from dataclasses import replace

from pdi.decision import Action, ActionType, Decision
from pdi.models import Asset, AssetSource, Blob
from pdi.repository import Repository

from .context import ObservationContext
from .errors import CrossScopeSourceWriteError, ScopedProviderMismatchError


_SOURCE_ACTIONS = {
    ActionType.CREATE_SOURCE,
    ActionType.UPDATE_SOURCE,
    ActionType.DEACTIVATE_SOURCE,
}


class ScopeBoundRepository(Repository):
    """Repository firewall bound to one immutable Observation Context."""

    def __init__(self, repository: Repository, context: ObservationContext) -> None:
        self._repository = repository
        self.context = context

    def _validate_provider(self, provider: str) -> None:
        if provider != self.context.provider_type:
            raise ScopedProviderMismatchError(
                "Provider does not match bound Observation Scope"
            )

    def find_source(self, provider: str, external_id: str) -> AssetSource | None:
        self._validate_provider(provider)
        return self._repository.find_source_in_scope(
            str(self.context.observation_scope_id), external_id
        )

    def list_active_sources(self, provider: str) -> list[AssetSource]:
        self._validate_provider(provider)
        return self._repository.list_active_sources_in_scope(
            str(self.context.observation_scope_id)
        )

    def find_source_in_scope(
        self, observation_scope_id: str, external_id: str
    ) -> AssetSource | None:
        if observation_scope_id != str(self.context.observation_scope_id):
            raise CrossScopeSourceWriteError("Cross-Scope lookup is denied")
        return self._repository.find_source_in_scope(
            observation_scope_id, external_id
        )

    def list_active_sources_in_scope(
        self, observation_scope_id: str
    ) -> list[AssetSource]:
        if observation_scope_id != str(self.context.observation_scope_id):
            raise CrossScopeSourceWriteError("Cross-Scope listing is denied")
        return self._repository.list_active_sources_in_scope(
            observation_scope_id
        )

    def find_blob_by_hash(self, content_hash: str) -> Blob | None:
        return self._repository.find_blob_by_hash(content_hash)

    def find_blob_by_hash_in_asset(
        self, content_hash: str, asset_id: str
    ) -> Blob | None:
        return self._repository.find_blob_by_hash_in_asset(
            content_hash, asset_id
        )

    def get_blob(self, blob_id: str) -> Blob | None:
        return self._repository.get_blob(blob_id)

    def get_asset(self, asset_id: str) -> Asset | None:
        return self._repository.get_asset(asset_id)

    def _bind_action(self, action: Action) -> Action:
        if action.type not in _SOURCE_ACTIONS or action.source is None:
            return action
        source = action.source
        bound_scope = str(self.context.observation_scope_id)
        if source.provider != self.context.provider_type:
            raise ScopedProviderMismatchError(
                "Source Provider does not match bound Observation Scope"
            )
        if source.observation_scope_id not in (None, bound_scope):
            raise CrossScopeSourceWriteError(
                "Source belongs to a different Observation Scope"
            )
        return replace(
            action,
            source=replace(source, observation_scope_id=bound_scope),
        )

    def _bind_decision(self, decision: Decision) -> Decision:
        return replace(
            decision,
            actions=[self._bind_action(action) for action in decision.actions],
        )

    def execute(self, decision: Decision) -> None:
        self._repository.execute(self._bind_decision(decision))

    def execute_many(self, decisions: tuple[Decision, ...]) -> None:
        self._repository.execute_many(
            tuple(self._bind_decision(decision) for decision in decisions)
        )
