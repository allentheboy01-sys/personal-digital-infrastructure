from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from pdi.query import format_resource_ref, parse_resource_ref
from pdi.repository.orm.asset import AssetORM
from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.observation import ResourceEnrichmentORM, ResourceStatementORM

from .errors import (
    ObservationLifecycleError,
    ObservationResourceNotFoundError,
)
from .models import (
    EnrichmentResource,
    EnrichmentSource,
    EnrichmentState,
    EnrichmentStatus,
    Evidence,
    EvidenceSourceKind,
    GeneratorIdentity,
    ObservationBatch,
    PublishResult,
    StatementDraft,
    StatementValueType,
    StatementView,
    TypedStatementValue,
)


class PostgreSQLObservationRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    @staticmethod
    def _identity_filters(asset_id: UUID, generator: GeneratorIdentity):
        return (
            ResourceEnrichmentORM.subject_asset_id == asset_id,
            ResourceEnrichmentORM.extractor_type == generator.generator_type,
            ResourceEnrichmentORM.extractor_name == generator.generator_name,
            ResourceEnrichmentORM.extractor_version == generator.generator_version,
        )

    @staticmethod
    def _statement_key(draft: StatementDraft) -> tuple:
        value = draft.value.value
        if isinstance(value, datetime):
            value = value.astimezone(UTC)
        return (
            draft.predicate,
            draft.value.value_type.value,
            value,
            draft.evidence.source_kind.value,
            draft.evidence.source_locator,
            draft.confidence,
        )

    @staticmethod
    def _orm_key(row: ResourceStatementORM) -> tuple:
        value = PostgreSQLObservationRepository._row_value(row)
        if isinstance(value, UUID):
            value = format_resource_ref(value)
        return (
            row.predicate,
            row.value_type,
            value,
            row.source_kind,
            row.source_locator,
            row.confidence,
        )

    @staticmethod
    def _row_value(row: ResourceStatementORM):
        return {
            "string": row.string_value,
            "integer": row.integer_value,
            "float": row.float_value,
            "boolean": row.boolean_value,
            "datetime": row.datetime_value,
            "resource_ref": row.resource_value_asset_id,
        }[row.value_type]

    @staticmethod
    def _draft_to_orm(asset_id: UUID, generator: GeneratorIdentity, draft: StatementDraft, now: datetime):
        kwargs = {
            "string_value": None,
            "integer_value": None,
            "float_value": None,
            "boolean_value": None,
            "datetime_value": None,
            "resource_value_asset_id": None,
        }
        column = {
            StatementValueType.STRING: "string_value",
            StatementValueType.INTEGER: "integer_value",
            StatementValueType.FLOAT: "float_value",
            StatementValueType.BOOLEAN: "boolean_value",
            StatementValueType.DATETIME: "datetime_value",
            StatementValueType.RESOURCE_REF: "resource_value_asset_id",
        }[draft.value.value_type]
        value = draft.value.value
        if draft.value.value_type is StatementValueType.RESOURCE_REF:
            value = UUID(parse_resource_ref(value))
        kwargs[column] = value
        return ResourceStatementORM(
            id=uuid4(), subject_asset_id=asset_id, predicate=draft.predicate,
            value_type=draft.value.value_type.value,
            generator_type=generator.generator_type,
            generator_name=generator.generator_name,
            generator_version=generator.generator_version,
            source_kind=draft.evidence.source_kind.value,
            source_locator=draft.evidence.source_locator,
            confidence=draft.confidence, created_at=now, is_current=True, **kwargs,
        )

    @staticmethod
    def _complete_state(row: ResourceEnrichmentORM, fingerprint: str, now: datetime) -> None:
        row.input_fingerprint = fingerprint
        row.status = EnrichmentStatus.COMPLETED.value
        row.completed_at = now
        row.updated_at = now
        row.error_code = None
        row.error_message = None

    def publish(
        self,
        batch: ObservationBatch,
        *,
        completed_at: datetime,
        exclusive_generator_family: tuple[str, ...] = (),
    ) -> PublishResult:
        asset_id = UUID(parse_resource_ref(batch.subject_resource_ref))
        now = completed_at.astimezone(UTC)
        with self._session_factory() as session:
            try:
                if session.get(AssetORM, asset_id) is None:
                    raise ObservationResourceNotFoundError("Resource does not exist")
                if exclusive_generator_family:
                    session.execute(
                        select(AssetORM)
                        .where(AssetORM.id == asset_id)
                        .with_for_update()
                    ).scalar_one()
                    conflicting = session.execute(
                        select(ResourceStatementORM.id).where(
                            ResourceStatementORM.subject_asset_id
                            == asset_id,
                            ResourceStatementORM.predicate.in_(
                                batch.covered_predicates
                            ),
                            ResourceStatementORM.generator_type
                            == batch.generator.generator_type,
                            ResourceStatementORM.generator_name.in_(
                                exclusive_generator_family
                            ),
                            ~(
                                (
                                    ResourceStatementORM.generator_name
                                    == batch.generator.generator_name
                                )
                                & (
                                    ResourceStatementORM.generator_version
                                    == batch.generator.generator_version
                                )
                            ),
                            ResourceStatementORM.is_current.is_(True),
                        )
                    ).first()
                    if conflicting is not None:
                        raise ObservationLifecycleError(
                            "Resource already has a current excerpt from "
                            "another Nextcloud document generator"
                        )
                state = session.execute(
                    select(ResourceEnrichmentORM)
                    .where(*self._identity_filters(asset_id, batch.generator))
                    .with_for_update()
                ).scalar_one_or_none()
                if state is None:
                    state = ResourceEnrichmentORM(
                        subject_asset_id=asset_id,
                        extractor_type=batch.generator.generator_type,
                        extractor_name=batch.generator.generator_name,
                        extractor_version=batch.generator.generator_version,
                        input_fingerprint=batch.input_fingerprint,
                        status=EnrichmentStatus.RUNNING.value,
                        started_at=now, completed_at=None, updated_at=now,
                        error_code=None, error_message=None,
                    )
                    session.add(state)
                    session.flush()
                current = list(session.execute(
                    select(ResourceStatementORM).where(
                        ResourceStatementORM.subject_asset_id == asset_id,
                        ResourceStatementORM.predicate.in_(batch.covered_predicates),
                        ResourceStatementORM.generator_type == batch.generator.generator_type,
                        ResourceStatementORM.generator_name == batch.generator.generator_name,
                        ResourceStatementORM.generator_version == batch.generator.generator_version,
                        ResourceStatementORM.is_current.is_(True),
                    ).with_for_update()
                ).scalars())
                old = sorted(self._orm_key(row) for row in current)
                new = sorted(self._statement_key(draft) for draft in batch.statements)
                if old == new:
                    self._complete_state(state, batch.input_fingerprint, now)
                    session.commit()
                    return PublishResult(0, 0)
                for row in current:
                    row.is_current = False
                for draft in sorted(batch.statements, key=self._statement_key):
                    session.add(self._draft_to_orm(asset_id, batch.generator, draft, now))
                self._complete_state(state, batch.input_fingerprint, now)
                session.commit()
                return PublishResult(len(batch.statements), len(current))
            except Exception:
                session.rollback()
                raise

    def get_enrichment_state(self, resource_ref: str, generator: GeneratorIdentity) -> EnrichmentState | None:
        asset_id = UUID(parse_resource_ref(resource_ref))
        with self._session_factory() as session:
            row = session.execute(select(ResourceEnrichmentORM).where(*self._identity_filters(asset_id, generator))).scalar_one_or_none()
            if row is None:
                return None
            return EnrichmentState(
                resource_ref, generator, row.input_fingerprint, EnrichmentStatus(row.status),
                row.started_at, row.completed_at, row.updated_at, row.error_code, row.error_message,
            )

    def mark_running(self, resource_ref: str, generator: GeneratorIdentity, input_fingerprint: str, *, now: datetime, stale_after: timedelta) -> bool:
        asset_id = UUID(parse_resource_ref(resource_ref))
        now = now.astimezone(UTC)
        with self._session_factory() as session:
            try:
                if session.get(AssetORM, asset_id) is None:
                    raise ObservationResourceNotFoundError("Resource does not exist")
                row = session.execute(select(ResourceEnrichmentORM).where(*self._identity_filters(asset_id, generator)).with_for_update()).scalar_one_or_none()
                if row is not None:
                    if row.status == "completed" and row.input_fingerprint == input_fingerprint:
                        session.rollback()
                        return False
                    if row.status == "running" and row.updated_at > now - stale_after:
                        session.rollback()
                        return False
                    row.input_fingerprint = input_fingerprint
                    row.status = "running"
                    row.started_at = now
                    row.completed_at = None
                    row.updated_at = now
                    row.error_code = row.error_message = None
                else:
                    session.add(ResourceEnrichmentORM(
                        subject_asset_id=asset_id, extractor_type=generator.generator_type,
                        extractor_name=generator.generator_name, extractor_version=generator.generator_version,
                        input_fingerprint=input_fingerprint, status="running", started_at=now,
                        completed_at=None, updated_at=now, error_code=None, error_message=None,
                    ))
                session.commit()
                return True
            except Exception:
                session.rollback()
                raise

    def mark_failed(self, resource_ref: str, generator: GeneratorIdentity, input_fingerprint: str, *, now: datetime, error_code: str, error_message: str) -> None:
        asset_id = UUID(parse_resource_ref(resource_ref))
        safe_message = error_message[:512]
        with self._session_factory() as session:
            row = session.execute(select(ResourceEnrichmentORM).where(*self._identity_filters(asset_id, generator)).with_for_update()).scalar_one()
            row.status = "failed"; row.input_fingerprint = input_fingerprint; row.updated_at = now.astimezone(UTC)
            row.completed_at = None; row.error_code = error_code[:64]; row.error_message = safe_message
            session.commit()

    def list_enrichment_resources(
        self,
        *,
        provider: str | tuple[str, ...],
        resource_type: str = "file",
    ) -> tuple[EnrichmentResource, ...]:
        if resource_type not in {"file", "message"}:
            raise ValueError("resource_type must be file or message")
        providers = (provider,) if isinstance(provider, str) else provider
        with self._session_factory() as session:
            rows = session.execute(
                select(
                    AssetORM.id,
                    AssetSourceORM.id,
                    AssetSourceORM.provider,
                    AssetSourceORM.metadata_,
                    AssetSourceORM.external_id,
                    BlobORM.hash,
                    BlobORM.size,
                    func.coalesce(
                        AssetSourceORM.provider_mime_type,
                        BlobORM.mime_type,
                    ),
                    AssetSourceORM.path,
                    AssetSourceORM.name,
                    AssetSourceORM.version_tag,
                    AssetSourceORM.observation_scope_id,
                )
                .join(BlobORM, BlobORM.asset_id == AssetORM.id)
                .join(AssetSourceORM, AssetSourceORM.blob_id == BlobORM.id)
                .where(
                    AssetORM.resource_type == resource_type,
                    AssetSourceORM.provider.in_(providers),
                    AssetSourceORM.is_active.is_(True),
                )
                .order_by(AssetORM.id, AssetSourceORM.id)
            ).all()
            grouped: dict[UUID, list[EnrichmentSource]] = {}
            for (
                asset_id,
                source_id,
                source_provider,
                metadata,
                provider_locator,
                blob_sha256,
                size,
                mime_type,
                path,
                name,
                version_tag,
                observation_scope_id,
            ) in rows:
                grouped.setdefault(asset_id, []).append(
                    EnrichmentSource(
                        str(source_id),
                        source_provider,
                        dict(metadata),
                        provider_locator,
                        blob_sha256,
                        size,
                        mime_type,
                        path,
                        name,
                        version_tag,
                        True,
                        (
                            None
                            if observation_scope_id is None
                            else str(observation_scope_id)
                        ),
                    )
                )
            return tuple(EnrichmentResource(format_resource_ref(asset_id), tuple(sources)) for asset_id, sources in grouped.items())

    def get_resource_statements(self, resource_ref: str, *, predicate: str | None, include_history: bool, limit: int) -> tuple[StatementView, ...] | None:
        asset_id = UUID(parse_resource_ref(resource_ref))
        with self._session_factory() as session:
            if session.get(AssetORM, asset_id) is None:
                return None
            query = select(ResourceStatementORM).where(ResourceStatementORM.subject_asset_id == asset_id)
            if predicate is not None:
                query = query.where(ResourceStatementORM.predicate == predicate)
            if not include_history:
                query = query.where(ResourceStatementORM.is_current.is_(True))
            rows = session.execute(query.order_by(
                ResourceStatementORM.predicate.asc(), ResourceStatementORM.generator_type.asc(),
                ResourceStatementORM.generator_name.asc(), ResourceStatementORM.generator_version.asc(),
                ResourceStatementORM.created_at.desc(), ResourceStatementORM.id.asc(),
            ).limit(limit)).scalars().all()
            result = []
            for row in rows:
                value = self._row_value(row)
                if row.value_type == "resource_ref":
                    value = format_resource_ref(value)
                result.append(StatementView(
                    resource_ref, row.predicate, StatementValueType(row.value_type), value,
                    GeneratorIdentity(row.generator_type, row.generator_name, row.generator_version),
                    Evidence(EvidenceSourceKind(row.source_kind), row.source_locator),
                    row.confidence, row.created_at, row.is_current,
                ))
            return tuple(result)
