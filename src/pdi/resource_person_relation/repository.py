from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import Engine, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.asset import AssetORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.person import (
    ObservationScopePersonSourceORM,
    PersonSourceORM,
)
from pdi.repository.orm.resource_person_relation import (
    ObservationScopeResourcePersonRelationORM,
    ResourcePersonRelationORM,
)

from .models import RelationSyncResult


class ResourcePersonRelationRepository:
    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

    @staticmethod
    def _instant(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("relation timestamp must be timezone-aware")
        return value.astimezone(UTC)

    def list_active_person_external_ids(self, provider: str) -> tuple[str, ...]:
        if not provider.strip():
            raise ValueError("provider must be non-empty")
        with self._session_factory() as session:
            return tuple(
                session.scalars(
                    select(PersonSourceORM.external_id)
                    .where(
                        PersonSourceORM.provider == provider,
                        PersonSourceORM.inactive_at.is_(None),
                    )
                    .order_by(PersonSourceORM.external_id)
                )
            )

    def reconcile_provider_relations(
        self,
        provider: str,
        observed_pairs: Iterable[tuple[str, str]],
        *,
        now: datetime | None = None,
    ) -> RelationSyncResult:
        if not provider.strip():
            raise ValueError("provider must be non-empty")
        external_pairs = set(observed_pairs)
        if any(not asset.strip() or not person.strip() for asset, person in external_pairs):
            raise ValueError("observed relation IDs must be non-empty")
        instant = self._instant(now or datetime.now(UTC))

        with self._session_factory.begin() as session:
            asset_map = {
                external_id: asset_id
                for external_id, asset_id in session.execute(
                    select(AssetSourceORM.external_id, BlobORM.asset_id)
                    .join(BlobORM, BlobORM.id == AssetSourceORM.blob_id)
                    .join(AssetORM, AssetORM.id == BlobORM.asset_id)
                    .where(
                        AssetORM.resource_type == "file",
                        AssetSourceORM.provider == provider,
                        AssetSourceORM.is_active.is_(True),
                    )
                )
            }
            person_map = {
                external_id: person_id
                for external_id, person_id in session.execute(
                    select(PersonSourceORM.external_id, PersonSourceORM.person_id)
                    .where(
                        PersonSourceORM.provider == provider,
                        PersonSourceORM.inactive_at.is_(None),
                    )
                )
            }
            mapped = {
                (asset_map[asset], person_map[person], provider)
                for asset, person in external_pairs
                if asset in asset_map and person in person_map
            }
            skipped = len(external_pairs) - len(mapped)
            existing = {
                (row.resource_id, row.person_id, row.provider): row.inactive_at
                for row in session.scalars(
                    select(ResourcePersonRelationORM).where(
                        ResourcePersonRelationORM.provider == provider
                    )
                )
            }
            created = len(mapped - existing.keys())
            reactivated = sum(
                identity in existing and existing[identity] is not None
                for identity in mapped
            )
            unchanged = len(mapped) - created - reactivated

            if mapped:
                rows = [
                    {
                        "resource_id": resource_id,
                        "person_id": person_id,
                        "provider": owner,
                        "inactive_at": None,
                    }
                    for resource_id, person_id, owner in mapped
                ]
                statement = insert(ResourcePersonRelationORM).values(rows)
                session.execute(
                    statement.on_conflict_do_update(
                        index_elements=[
                            ResourcePersonRelationORM.resource_id,
                            ResourcePersonRelationORM.person_id,
                            ResourcePersonRelationORM.provider,
                        ],
                        set_={"inactive_at": None},
                    )
                )

            missing = set(existing) - mapped
            active_missing = {
                identity for identity in missing if existing[identity] is None
            }
            inactivated = 0
            if active_missing:
                inactivated = session.execute(
                    update(ResourcePersonRelationORM)
                    .where(
                        ResourcePersonRelationORM.provider == provider,
                        ResourcePersonRelationORM.inactive_at.is_(None),
                        tuple_(
                            ResourcePersonRelationORM.resource_id,
                            ResourcePersonRelationORM.person_id,
                        ).in_(
                            {(identity[0], identity[1]) for identity in active_missing}
                        ),
                    )
                    .values(inactive_at=instant)
                ).rowcount

        return RelationSyncResult(
            observed=len(external_pairs),
            created=created,
            unchanged=unchanged,
            reactivated=reactivated,
            inactivated=inactivated,
            skipped_unmapped=skipped,
        )


class ScopedResourcePersonRelationRepository:
    """Relation observations permanently bound to one Observation Scope."""

    def __init__(self, engine: Engine, observation_scope_id) -> None:
        self.observation_scope_id = observation_scope_id
        self._session_factory = sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

    @staticmethod
    def _instant(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("relation timestamp must be timezone-aware")
        return value.astimezone(UTC)

    def list_active_person_external_ids(self) -> tuple[str, ...]:
        with self._session_factory() as session:
            return tuple(
                session.scalars(
                    select(ObservationScopePersonSourceORM.external_id)
                    .where(
                        ObservationScopePersonSourceORM.observation_scope_id
                        == self.observation_scope_id,
                        ObservationScopePersonSourceORM.inactive_at.is_(None),
                    )
                    .order_by(ObservationScopePersonSourceORM.external_id)
                )
            )

    def reconcile_relations(
        self,
        observed_pairs: Iterable[tuple[str, str]],
        *,
        now: datetime | None = None,
    ) -> RelationSyncResult:
        external_pairs = set(observed_pairs)
        if any(
            not asset.strip() or not person.strip()
            for asset, person in external_pairs
        ):
            raise ValueError("observed relation IDs must be non-empty")
        instant = self._instant(now or datetime.now(UTC))
        with self._session_factory.begin() as session:
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"scoped-relation-inventory:{self.observation_scope_id}"},
            )
            asset_map = {
                external_id: asset_id
                for external_id, asset_id in session.execute(
                    select(AssetSourceORM.external_id, BlobORM.asset_id)
                    .join(BlobORM, BlobORM.id == AssetSourceORM.blob_id)
                    .join(AssetORM, AssetORM.id == BlobORM.asset_id)
                    .where(
                        AssetORM.resource_type == "file",
                        AssetSourceORM.observation_scope_id
                        == self.observation_scope_id,
                        AssetSourceORM.is_active.is_(True),
                    )
                )
            }
            person_map = {
                external_id: person_id
                for external_id, person_id in session.execute(
                    select(
                        ObservationScopePersonSourceORM.external_id,
                        ObservationScopePersonSourceORM.person_id,
                    ).where(
                        ObservationScopePersonSourceORM.observation_scope_id
                        == self.observation_scope_id,
                        ObservationScopePersonSourceORM.inactive_at.is_(None),
                    )
                )
            }
            mapped = {
                (asset_map[asset], person_map[person])
                for asset, person in external_pairs
                if asset in asset_map and person in person_map
            }
            skipped = len(external_pairs) - len(mapped)
            existing = {
                (row.resource_id, row.person_id): row.inactive_at
                for row in session.scalars(
                    select(ObservationScopeResourcePersonRelationORM).where(
                        ObservationScopeResourcePersonRelationORM.observation_scope_id
                        == self.observation_scope_id
                    )
                )
            }
            created = len(mapped - existing.keys())
            reactivated = sum(
                identity in existing and existing[identity] is not None
                for identity in mapped
            )
            unchanged = len(mapped) - created - reactivated
            if mapped:
                rows = [
                    {
                        "observation_scope_id": self.observation_scope_id,
                        "resource_id": resource_id,
                        "person_id": person_id,
                        "inactive_at": None,
                    }
                    for resource_id, person_id in mapped
                ]
                statement = insert(
                    ObservationScopeResourcePersonRelationORM
                ).values(rows)
                session.execute(
                    statement.on_conflict_do_update(
                        index_elements=[
                            ObservationScopeResourcePersonRelationORM.observation_scope_id,
                            ObservationScopeResourcePersonRelationORM.resource_id,
                            ObservationScopeResourcePersonRelationORM.person_id,
                        ],
                        set_={"inactive_at": None},
                    )
                )
            active_missing = {
                identity
                for identity, inactive_at in existing.items()
                if identity not in mapped and inactive_at is None
            }
            inactivated = 0
            if active_missing:
                inactivated = session.execute(
                    update(ObservationScopeResourcePersonRelationORM)
                    .where(
                        ObservationScopeResourcePersonRelationORM.observation_scope_id
                        == self.observation_scope_id,
                        ObservationScopeResourcePersonRelationORM.inactive_at.is_(None),
                        tuple_(
                            ObservationScopeResourcePersonRelationORM.resource_id,
                            ObservationScopeResourcePersonRelationORM.person_id,
                        ).in_(active_missing),
                    )
                    .values(inactive_at=instant)
                ).rowcount
        return RelationSyncResult(
            observed=len(external_pairs),
            created=created,
            unchanged=unchanged,
            reactivated=reactivated,
            inactivated=inactivated,
            skipped_unmapped=skipped,
        )
