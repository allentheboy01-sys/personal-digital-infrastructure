"""Administrative, atomic transition of legacy Sources to stable Scopes."""

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.provider_identity import (
    ObservationScopeORM,
    ProviderInstanceORM,
)


class SourceProvenanceBackfillError(RuntimeError):
    """The complete provenance plan is unsafe; no rows were changed."""


@dataclass(frozen=True, slots=True)
class SourceProvenanceBackfillResult:
    examined: int
    updated: int


def backfill_source_observation_scopes(
    engine: Engine,
    provider_scope_ids: Mapping[str, UUID],
) -> SourceProvenanceBackfillResult:
    """Validate and atomically apply a complete provider-to-Scope mapping."""
    if not provider_scope_ids or any(
        not key.strip() for key in provider_scope_ids
    ):
        raise SourceProvenanceBackfillError(
            "A complete non-empty provider mapping is required"
        )

    with Session(engine) as session, session.begin():
        sources = list(
            session.execute(
                select(AssetSourceORM).with_for_update()
            ).scalars()
        )
        providers = {source.provider for source in sources}
        if providers - set(provider_scope_ids):
            raise SourceProvenanceBackfillError(
                "An existing Source provider has no Scope mapping"
            )

        scopes: dict[str, ObservationScopeORM] = {}
        for provider, scope_id in provider_scope_ids.items():
            scope = session.get(ObservationScopeORM, scope_id)
            if scope is None:
                raise SourceProvenanceBackfillError(
                    "Mapped Observation Scope does not exist for provider "
                    f"{provider}"
                )
            instance = session.get(ProviderInstanceORM, scope.provider_instance_id)
            if instance is None or instance.provider_type != provider:
                raise SourceProvenanceBackfillError(
                    "Scope Provider Instance mismatch for provider "
                    f"{provider}"
                )
            scopes[provider] = scope

        target_keys: set[tuple[UUID, str]] = set()
        updates: list[tuple[AssetSourceORM, UUID]] = []
        for source in sources:
            target = scopes[source.provider].id
            if source.observation_scope_id not in (None, target):
                raise SourceProvenanceBackfillError(
                    "Source already has different Scope provenance"
                )
            identity = (target, source.external_id)
            if identity in target_keys:
                raise SourceProvenanceBackfillError(
                    "Backfill would create a scoped Source identity conflict"
                )
            target_keys.add(identity)
            if source.observation_scope_id is None:
                updates.append((source, target))

        for source, target in updates:
            source.observation_scope_id = target
        session.flush()
        return SourceProvenanceBackfillResult(
            examined=len(sources),
            updated=len(updates),
        )
