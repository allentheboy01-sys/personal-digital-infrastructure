from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from pdi.repository.orm.provider_identity import ObservationScopeORM, ProviderInstanceORM
from pdi.repository.orm.provider_sync_state import ProviderSyncStateORM
from pdi.repository.orm.scope_sync_state import ObservationScopeSyncStateORM


class ScopeStateTransitionError(RuntimeError):
    """The complete legacy-to-Scope copy plan is unsafe."""


@dataclass(frozen=True, slots=True)
class ScopeStateTransitionResult:
    examined: int
    created: int


def copy_legacy_states_to_scopes(engine: Engine, plan: Mapping[tuple[str, str], UUID]) -> ScopeStateTransitionResult:
    """Atomically copy an exact legacy-state set without mutating legacy rows."""
    with Session(engine) as session, session.begin():
        legacy_rows = list(session.execute(select(ProviderSyncStateORM).with_for_update()).scalars())
        legacy_keys = {(row.provider, row.mechanism) for row in legacy_rows}
        if not plan or legacy_keys != set(plan):
            raise ScopeStateTransitionError("Transition plan must map every and only existing legacy state")

        prepared: list[tuple[ProviderSyncStateORM, UUID]] = []
        for row in legacy_rows:
            scope_id = plan[(row.provider, row.mechanism)]
            scope = session.get(ObservationScopeORM, scope_id)
            if scope is None:
                raise ScopeStateTransitionError("Mapped Observation Scope does not exist")
            instance = session.get(ProviderInstanceORM, scope.provider_instance_id)
            if instance is None or instance.provider_type != row.provider:
                raise ScopeStateTransitionError("Scope Provider Type does not match legacy state")
            existing = session.get(ObservationScopeSyncStateORM, (scope_id, row.mechanism))
            if existing is not None:
                equivalent = (
                    existing.checkpoint == row.checkpoint
                    and existing.version == row.version
                    and existing.reconciliation_required == row.reconciliation_required
                    and existing.created_at == row.created_at
                    and existing.updated_at == row.updated_at
                )
                if not equivalent:
                    raise ScopeStateTransitionError("Existing Scope state differs from legacy state")
            else:
                prepared.append((row, scope_id))

        for row, scope_id in prepared:
            session.add(ObservationScopeSyncStateORM(
                observation_scope_id=scope_id,
                mechanism=row.mechanism,
                checkpoint=row.checkpoint,
                version=row.version,
                reconciliation_required=row.reconciliation_required,
                created_at=row.created_at,
                updated_at=row.updated_at,
            ))
        session.flush()
        return ScopeStateTransitionResult(examined=len(legacy_rows), created=len(prepared))
