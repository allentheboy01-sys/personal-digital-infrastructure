from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
import hashlib
import json
import re
from uuid import UUID, uuid4

from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from pdi.query import format_resource_ref, parse_resource_ref
from pdi.repository.orm.asset import AssetORM
from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.observation import ResourceEnrichmentORM, ResourceStatementORM
from pdi.repository.orm.pipeline_run_effect_receipt import (
    PipelineRunEffectReceiptORM,
)
from pdi.repository.orm.provider_identity import (
    ObservationScopeORM,
    ProviderAccountORM,
    ProviderInstanceORM,
)

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


_PIPELINE_KEY = re.compile(r"[a-z][a-z0-9_.-]{0,127}")
_EFFECT_PIPELINE_PROVIDERS = {
    "enrichment.nextcloud_text": frozenset({"nextcloud"}),
    "enrichment.nextcloud_documents": frozenset({"nextcloud"}),
    "enrichment.file_metadata": frozenset({"nextcloud", "immich"}),
    "enrichment.immich_geo": frozenset({"immich"}),
    "enrichment.immich_metadata": frozenset({"immich"}),
    "enrichment.immich_ocr": frozenset({"immich"}),
}


def _utc_text(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _receipt_fingerprint(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _enrichment_state_fingerprint(
    *,
    asset_id: UUID,
    generator: GeneratorIdentity,
    input_fingerprint: str,
    completed_at: datetime,
) -> str:
    return _receipt_fingerprint({
        "subject_asset_id": str(asset_id),
        "generator_type": generator.generator_type,
        "generator_name": generator.generator_name,
        "generator_version": generator.generator_version,
        "input_fingerprint": input_fingerprint,
        "status": EnrichmentStatus.COMPLETED.value,
        "completed_at": _utc_text(completed_at),
    })


def _statement_effect_fingerprint(
    rows: Sequence[ResourceStatementORM | Mapping[str, object]],
) -> str:
    """Commit to the exact semantic statement rows without persisting plaintext."""

    def field(row, name: str):
        return row[name] if isinstance(row, Mapping) else getattr(row, name)

    def normalized(value):
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return _utc_text(value)
        return value

    statements = []
    for row in sorted(rows, key=lambda item: str(field(item, "id"))):
        statements.append({
            name: normalized(field(row, name))
            for name in (
                "id",
                "subject_asset_id",
                "predicate",
                "value_type",
                "string_value",
                "integer_value",
                "float_value",
                "boolean_value",
                "datetime_value",
                "resource_value_asset_id",
                "generator_type",
                "generator_name",
                "generator_version",
                "source_kind",
                "source_locator",
                "confidence",
                "created_at",
                "is_current",
            )
        })
    return _receipt_fingerprint({"statements": statements})


def _source_binding_fingerprint(rows: Sequence[Mapping[str, object]]) -> str:
    """Commit to the exact enabled Source/Scope identity supplied to extraction."""

    sources = []
    for row in sorted(rows, key=lambda item: str(item["source_id"])):
        sources.append({
            "source_id": str(row["source_id"]),
            "provider": row["provider"],
            "observation_scope_id": str(row["observation_scope_id"]),
            "provider_instance_id": str(row["provider_instance_id"]),
            "provider_account_id": (
                None
                if row["provider_account_id"] is None
                else str(row["provider_account_id"])
            ),
        })
    return _receipt_fingerprint({"sources": sources})


def _receipt_fragment_payload(
    *,
    receipt_id: UUID,
    pipeline_run_id: UUID,
    pipeline_key: str,
    asset_id: UUID,
    generator: GeneratorIdentity,
    input_fingerprint: str,
    completed_at: datetime,
    created_statement_ids: tuple[UUID, ...],
    deactivated_statement_ids: tuple[UUID, ...],
    current_statement_ids: tuple[UUID, ...],
    source_ids: tuple[UUID, ...],
    source_binding_fingerprint: str,
    enrichment_state_fingerprint: str,
    statement_effect_fingerprint: str,
) -> dict[str, object]:
    return {
        "version": 1,
        "receipt_id": str(receipt_id),
        "pipeline_run_id": str(pipeline_run_id),
        "pipeline_key": pipeline_key,
        "subject_asset_id": str(asset_id),
        "generator_type": generator.generator_type,
        "generator_name": generator.generator_name,
        "generator_version": generator.generator_version,
        "input_fingerprint": input_fingerprint,
        "completed_at": _utc_text(completed_at),
        "created_statement_ids": [str(item) for item in created_statement_ids],
        "deactivated_statement_ids": [
            str(item) for item in deactivated_statement_ids
        ],
        "current_statement_ids": [str(item) for item in current_statement_ids],
        "source_ids": [str(item) for item in source_ids],
        "statement_write_count": len(created_statement_ids),
        "deactivated_statement_count": len(deactivated_statement_ids),
        "current_statement_count": len(current_statement_ids),
        "source_binding_fingerprint": source_binding_fingerprint,
        "enrichment_state_fingerprint": enrichment_state_fingerprint,
        "statement_effect_fingerprint": statement_effect_fingerprint,
    }


class PostgreSQLObservationRepository:
    def __init__(
        self,
        engine: Engine,
        *,
        effect_run_id: UUID | None = None,
        effect_pipeline_key: str | None = None,
    ) -> None:
        if (effect_run_id is None) != (effect_pipeline_key is None):
            raise ValueError("effect receipt context must be complete")
        if effect_pipeline_key is not None and (
            not isinstance(effect_pipeline_key, str)
            or _PIPELINE_KEY.fullmatch(effect_pipeline_key) is None
        ):
            raise ValueError("effect pipeline key is invalid")
        self._session_factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
        self._effect_run_id = effect_run_id
        self._effect_pipeline_key = effect_pipeline_key

    def _add_effect_receipt(
        self,
        session: Session,
        *,
        asset_id: UUID,
        batch: ObservationBatch,
        completed_at: datetime,
        created_statement_ids: tuple[UUID, ...],
        deactivated_statement_ids: tuple[UUID, ...],
        current_statement_ids: tuple[UUID, ...],
        effect_statements: tuple[ResourceStatementORM, ...],
        effect_sources: tuple[EnrichmentSource, ...],
    ) -> None:
        if self._effect_run_id is None or self._effect_pipeline_key is None:
            return
        created = tuple(sorted(created_statement_ids, key=str))
        deactivated = tuple(sorted(deactivated_statement_ids, key=str))
        current = tuple(sorted(current_statement_ids, key=str))
        if (
            len(set(created)) != len(created)
            or len(set(deactivated)) != len(deactivated)
            or len(set(current)) != len(current)
        ):
            raise ObservationLifecycleError("Effect receipt contains duplicate IDs")
        expected_ids = set((*created, *deactivated, *current))
        effect_by_id = {row.id: row for row in effect_statements}
        if set(effect_by_id) != expected_ids or len(effect_by_id) != len(effect_statements):
            raise ObservationLifecycleError("Effect receipt statement binding is incomplete")
        source_ids, source_fingerprint = self._verified_effect_sources(
            session,
            asset_id=asset_id,
            effect_sources=effect_sources,
        )
        receipt_id = uuid4()
        enrichment_fingerprint = _enrichment_state_fingerprint(
            asset_id=asset_id,
            generator=batch.generator,
            input_fingerprint=batch.input_fingerprint,
            completed_at=completed_at,
        )
        statement_fingerprint = _statement_effect_fingerprint(
            tuple(effect_by_id.values())
        )
        payload = _receipt_fragment_payload(
            receipt_id=receipt_id,
            pipeline_run_id=self._effect_run_id,
            pipeline_key=self._effect_pipeline_key,
            asset_id=asset_id,
            generator=batch.generator,
            input_fingerprint=batch.input_fingerprint,
            completed_at=completed_at,
            created_statement_ids=created,
            deactivated_statement_ids=deactivated,
            current_statement_ids=current,
            source_ids=source_ids,
            source_binding_fingerprint=source_fingerprint,
            enrichment_state_fingerprint=enrichment_fingerprint,
            statement_effect_fingerprint=statement_fingerprint,
        )
        session.add(PipelineRunEffectReceiptORM(
            id=receipt_id,
            version=1,
            pipeline_run_id=self._effect_run_id,
            pipeline_key=self._effect_pipeline_key,
            subject_asset_id=asset_id,
            generator_type=batch.generator.generator_type,
            generator_name=batch.generator.generator_name,
            generator_version=batch.generator.generator_version,
            input_fingerprint=batch.input_fingerprint,
            completed_at=completed_at,
            created_statement_ids=list(created),
            deactivated_statement_ids=list(deactivated),
            current_statement_ids=list(current),
            source_ids=list(source_ids),
            statement_write_count=len(created),
            deactivated_statement_count=len(deactivated),
            current_statement_count=len(current),
            source_binding_fingerprint=source_fingerprint,
            enrichment_state_fingerprint=enrichment_fingerprint,
            statement_effect_fingerprint=statement_fingerprint,
            fragment_fingerprint=_receipt_fingerprint(payload),
        ))

    def _verified_effect_sources(
        self,
        session: Session,
        *,
        asset_id: UUID,
        effect_sources: tuple[EnrichmentSource, ...],
    ) -> tuple[tuple[UUID, ...], str]:
        if self._effect_pipeline_key is None:
            raise ObservationLifecycleError("Effect source binding lacks pipeline")
        expected_providers = _EFFECT_PIPELINE_PROVIDERS.get(
            self._effect_pipeline_key
        )
        if expected_providers is None or not effect_sources:
            raise ObservationLifecycleError("Effect source binding is incomplete")
        supplied: dict[UUID, EnrichmentSource] = {}
        try:
            for source in effect_sources:
                source_id = UUID(source.source_id)
                scope_id = UUID(source.observation_scope_id or "")
                if (
                    source_id in supplied
                    or not source.is_active
                    or source.provider not in expected_providers
                    or str(scope_id) != source.observation_scope_id
                ):
                    raise ValueError
                supplied[source_id] = source
        except (TypeError, ValueError, AttributeError):
            raise ObservationLifecycleError(
                "Effect source binding is invalid"
            ) from None
        rows = list(session.execute(
            select(
                AssetSourceORM.id.label("source_id"),
                AssetSourceORM.provider,
                AssetSourceORM.observation_scope_id,
                ObservationScopeORM.provider_instance_id,
                ObservationScopeORM.provider_account_id,
                BlobORM.asset_id,
                AssetSourceORM.is_active,
                AssetSourceORM.deleted_at,
                ObservationScopeORM.enabled.label("scope_enabled"),
                ProviderInstanceORM.provider_type.label("instance_provider"),
                ProviderInstanceORM.enabled.label("instance_enabled"),
                ProviderAccountORM.enabled.label("account_enabled"),
            )
            .join(BlobORM, BlobORM.id == AssetSourceORM.blob_id)
            .join(
                ObservationScopeORM,
                ObservationScopeORM.id == AssetSourceORM.observation_scope_id,
            )
            .join(
                ProviderInstanceORM,
                ProviderInstanceORM.id == ObservationScopeORM.provider_instance_id,
            )
            .outerjoin(
                ProviderAccountORM,
                ProviderAccountORM.id == ObservationScopeORM.provider_account_id,
            )
            .where(AssetSourceORM.id.in_(tuple(supplied)))
            .with_for_update(of=AssetSourceORM)
        ).mappings())
        if {row["source_id"] for row in rows} != set(supplied):
            raise ObservationLifecycleError("Effect source binding is incomplete")
        fingerprint_rows = []
        for row in rows:
            source = supplied[row["source_id"]]
            if (
                row["asset_id"] != asset_id
                or row["provider"] != source.provider
                or str(row["observation_scope_id"])
                != source.observation_scope_id
                or row["provider"] not in expected_providers
                or row["instance_provider"] != row["provider"]
                or row["is_active"] is not True
                or row["deleted_at"] is not None
                or row["scope_enabled"] is not True
                or row["instance_enabled"] is not True
                or (
                    row["provider_account_id"] is not None
                    and row["account_enabled"] is not True
                )
            ):
                raise ObservationLifecycleError(
                    "Effect source authority is invalid"
                )
            fingerprint_rows.append(row)
        source_ids = tuple(sorted(supplied, key=str))
        return source_ids, _source_binding_fingerprint(fingerprint_rows)

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
        effect_sources: tuple[EnrichmentSource, ...] = (),
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
                    self._add_effect_receipt(
                        session,
                        asset_id=asset_id,
                        batch=batch,
                        completed_at=now,
                        created_statement_ids=(),
                        deactivated_statement_ids=(),
                        current_statement_ids=tuple(row.id for row in current),
                        effect_statements=tuple(current),
                        effect_sources=effect_sources,
                    )
                    session.commit()
                    return PublishResult(0, 0)
                for row in current:
                    row.is_current = False
                created = []
                for draft in sorted(batch.statements, key=self._statement_key):
                    created_row = self._draft_to_orm(
                        asset_id, batch.generator, draft, now
                    )
                    created.append(created_row)
                    session.add(created_row)
                self._complete_state(state, batch.input_fingerprint, now)
                self._add_effect_receipt(
                    session,
                    asset_id=asset_id,
                    batch=batch,
                    completed_at=now,
                    created_statement_ids=tuple(row.id for row in created),
                    deactivated_statement_ids=tuple(row.id for row in current),
                    current_statement_ids=tuple(row.id for row in created),
                    effect_statements=tuple((*current, *created)),
                    effect_sources=effect_sources,
                )
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
