from pdi.scope_sync_state import ScopeSyncState, ScopeSyncStateRepository
from pdi.sync_state import ProviderSyncState, ProviderSyncStateRepository

from .context import ObservationContext
from .errors import ScopedProviderMismatchError


class ScopeBoundProviderSyncStateRepository(ProviderSyncStateRepository):
    """Legacy-shaped API backed exclusively by one Scope state namespace."""

    def __init__(
        self,
        repository: ScopeSyncStateRepository,
        context: ObservationContext,
    ) -> None:
        self._repository = repository
        self.context = context

    def _provider(self, provider: str) -> None:
        if provider != self.context.provider_type:
            raise ScopedProviderMismatchError(
                "State Provider does not match bound Observation Scope"
            )

    def _project(self, state: ScopeSyncState | None) -> ProviderSyncState | None:
        if state is None:
            return None
        return ProviderSyncState(
            provider=self.context.provider_type,
            mechanism=state.mechanism,
            checkpoint=state.checkpoint,
            version=state.version,
            reconciliation_required=state.reconciliation_required,
            created_at=state.created_at,
            updated_at=state.updated_at,
        )

    def read(self, provider: str, mechanism: str) -> ProviderSyncState | None:
        self._provider(provider)
        return self._project(
            self._repository.read(self.context.observation_scope_id, mechanism)
        )

    def get_or_create(
        self, provider: str, mechanism: str
    ) -> ProviderSyncState:
        self._provider(provider)
        state = self._repository.get_or_create(
            self.context.observation_scope_id, mechanism
        )
        projected = self._project(state)
        assert projected is not None
        return projected

    def compare_and_swap_checkpoint(
        self,
        provider: str,
        mechanism: str,
        *,
        expected_version: int,
        checkpoint: str,
    ) -> ProviderSyncState | None:
        self._provider(provider)
        return self._project(
            self._repository.compare_and_swap_checkpoint(
                self.context.observation_scope_id,
                mechanism,
                expected_version=expected_version,
                checkpoint=checkpoint,
            )
        )

    def mark_reconciliation_required(
        self,
        provider: str,
        mechanism: str,
        *,
        expected_version: int,
    ) -> ProviderSyncState | None:
        self._provider(provider)
        return self._project(
            self._repository.mark_reconciliation_required(
                self.context.observation_scope_id,
                mechanism,
                expected_version=expected_version,
            )
        )

    def recover_after_reconciliation(
        self,
        provider: str,
        mechanism: str,
        *,
        expected_version: int,
        trusted_checkpoint: str,
    ) -> ProviderSyncState | None:
        self._provider(provider)
        return self._project(
            self._repository.recover_after_reconciliation(
                self.context.observation_scope_id,
                mechanism,
                expected_version=expected_version,
                trusted_checkpoint=trusted_checkpoint,
            )
        )
