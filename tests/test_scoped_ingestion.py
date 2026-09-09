from datetime import UTC, datetime
from uuid import uuid4

import pytest

from pdi.decision import Action, ActionType, Decision
from pdi.models import AssetSource
from pdi.principal import PrincipalId
from pdi.repository import InMemoryRepository
from pdi.scoped_ingestion import (
    CrossScopeSourceWriteError,
    ObservationContext,
    ScopeBoundProviderSyncStateRepository,
    ScopeBoundRepository,
    ScopedProviderMismatchError,
)
from pdi.scope_sync_state import ScopeSyncState


def _context(provider: str = "nextcloud") -> ObservationContext:
    return ObservationContext(
        principal_id=PrincipalId("synthetic-principal"),
        observation_scope_id=uuid4(),
        provider_instance_id=uuid4(),
        provider_account_id=None,
        provider_type=provider,
    )


def test_context_is_immutable_and_has_no_credential() -> None:
    context = _context()
    assert "credential" not in context.__dataclass_fields__
    with pytest.raises(AttributeError):
        context.provider_type = "immich"  # type: ignore[misc]


def test_context_rejects_invalid_runtime_identity() -> None:
    with pytest.raises(ValueError, match="provider_type"):
        ObservationContext(
            principal_id=PrincipalId("synthetic-principal"),
            observation_scope_id=uuid4(),
            provider_instance_id=uuid4(),
            provider_account_id=None,
            provider_type="",
        )


def test_repository_binds_copy_without_mutating_caller() -> None:
    context = _context()
    underlying = InMemoryRepository()
    repository = ScopeBoundRepository(underlying, context)
    source = AssetSource(
        blob_id="blob",
        provider="nextcloud",
        external_id="x",
    )
    repository.execute(
        Decision(
            actions=[
                Action(ActionType.CREATE_SOURCE, source=source),
            ]
        )
    )
    assert source.observation_scope_id is None
    stored = repository.find_source("nextcloud", "x")
    assert stored is not None
    assert stored.observation_scope_id == str(context.observation_scope_id)
    assert underlying.find_source("nextcloud", "x") is None


def test_repository_rejects_provider_and_cross_scope_actions_atomically() -> None:
    context = _context()
    underlying = InMemoryRepository()
    repository = ScopeBoundRepository(underlying, context)
    valid = AssetSource(blob_id="blob", provider="nextcloud", external_id="ok")
    wrong = AssetSource(
        blob_id="blob",
        provider="nextcloud",
        external_id="wrong",
        observation_scope_id=str(uuid4()),
    )
    with pytest.raises(CrossScopeSourceWriteError):
        repository.execute_many(
            (
                Decision(actions=[Action(ActionType.CREATE_SOURCE, source=valid)]),
                Decision(actions=[Action(ActionType.CREATE_SOURCE, source=wrong)]),
            )
        )
    assert underlying.sources == {}
    with pytest.raises(ScopedProviderMismatchError):
        repository.find_source("immich", "x")


class _ScopeStateRepository:
    def __init__(self, scope_id):
        self.scope_id = scope_id
        self.state = None

    def read(self, scope_id, mechanism):
        assert scope_id == self.scope_id
        return self.state

    def get_or_create(self, scope_id, mechanism):
        assert scope_id == self.scope_id
        if self.state is None:
            now = datetime.now(UTC)
            self.state = ScopeSyncState(
                scope_id, mechanism, None, 0, False, now, now
            )
        return self.state

    def compare_and_swap_checkpoint(
        self, scope_id, mechanism, *, expected_version, checkpoint
    ):
        current = self.get_or_create(scope_id, mechanism)
        if current.version != expected_version:
            return None
        self.state = ScopeSyncState(
            scope_id,
            mechanism,
            checkpoint,
            current.version + 1,
            False,
            current.created_at,
            datetime.now(UTC),
        )
        return self.state

    def mark_reconciliation_required(
        self, scope_id, mechanism, *, expected_version
    ):
        raise NotImplementedError

    def recover_after_reconciliation(
        self, scope_id, mechanism, *, expected_version, trusted_checkpoint
    ):
        raise NotImplementedError


def test_state_bridge_projects_provider_and_rejects_mismatch() -> None:
    context = _context()
    underlying = _ScopeStateRepository(context.observation_scope_id)
    bridge = ScopeBoundProviderSyncStateRepository(underlying, context)  # type: ignore[arg-type]
    state = bridge.get_or_create("nextcloud", "activity_v2_hint_v1")
    assert state.provider == "nextcloud"
    assert state.version == 0
    with pytest.raises(ScopedProviderMismatchError):
        bridge.get_or_create("immich", "activity_v2_hint_v1")
