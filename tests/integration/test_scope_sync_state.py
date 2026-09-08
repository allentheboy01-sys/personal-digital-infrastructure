from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from pdi.database import create_postgres_engine
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scope_sync_state import (
    PostgreSQLScopeSyncStateRepository,
    ScopeStateTransitionError,
    ScopeSyncStateScopeNotFoundError,
    copy_legacy_states_to_scopes,
)
from pdi.sync_state import PostgreSQLProviderSyncStateRepository
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def context():
    engine = create_postgres_engine(require_safe_test_database_url())
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM observation_scope_sync_state"))
        connection.execute(text("DELETE FROM provider_sync_state"))
        connection.execute(text("DELETE FROM asset_sources"))
        connection.execute(text("DELETE FROM observation_scopes"))
        connection.execute(text("DELETE FROM provider_accounts"))
        connection.execute(text("DELETE FROM provider_instances"))
    try:
        yield (
            engine,
            PostgreSQLScopeSyncStateRepository(engine),
            PostgreSQLProviderSyncStateRepository(engine),
            PostgreSQLProviderIdentityRepository(engine),
        )
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM observation_scope_sync_state"))
            connection.execute(text("DELETE FROM provider_sync_state"))
            connection.execute(text("DELETE FROM observation_scopes"))
            connection.execute(text("DELETE FROM provider_accounts"))
            connection.execute(text("DELETE FROM provider_instances"))
        engine.dispose()


def _scope(identity, provider="nextcloud", *, enabled=True):
    token = uuid4().hex
    instance = identity.create_instance(
        provider_type=provider,
        instance_key=f"mu6-{token}",
    )
    return identity.create_scope(
        provider_instance_id=instance.id,
        scope_key=f"mu6-{token}",
        enabled=enabled,
    )


def test_new_scope_has_no_inherited_state_and_missing_scope_is_rejected(context):
    _, scoped, _, identity = context
    scope = _scope(identity)
    assert scoped.read(scope.id, "activity_v2_hint_v1") is None
    initial = scoped.get_or_create(scope.id, "activity_v2_hint_v1")
    assert (initial.checkpoint, initial.version, initial.reconciliation_required) == (None, 0, False)
    with pytest.raises(ScopeSyncStateScopeNotFoundError):
        scoped.get_or_create(uuid4(), "activity_v2_hint_v1")


def test_two_scopes_and_multiple_mechanisms_are_cas_isolated(context):
    _, scoped, _, identity = context
    scope_a, scope_b = _scope(identity), _scope(identity)
    mechanism = "activity_v2_hint_v1"
    scoped.get_or_create(scope_a.id, mechanism)
    scoped.get_or_create(scope_b.id, mechanism)
    scoped.get_or_create(scope_a.id, "secondary_v1")
    assert scoped.compare_and_swap_checkpoint(scope_a.id, mechanism, expected_version=4, checkpoint="synthetic-stale") is None
    advanced = scoped.compare_and_swap_checkpoint(scope_a.id, mechanism, expected_version=0, checkpoint="synthetic-a")
    assert advanced is not None and advanced.version == 1
    assert scoped.read(scope_b.id, mechanism).version == 0
    assert scoped.read(scope_b.id, mechanism).checkpoint is None
    assert scoped.read(scope_a.id, "secondary_v1").version == 0


def test_reconciliation_and_recovery_are_scope_local_and_explicit(context):
    _, scoped, _, identity = context
    scope_a, scope_b = _scope(identity), _scope(identity)
    mechanism = "metadata_updated_at_v1"
    scoped.get_or_create(scope_a.id, mechanism)
    scoped.get_or_create(scope_b.id, mechanism)
    marked = scoped.mark_reconciliation_required(scope_a.id, mechanism, expected_version=0)
    assert marked is not None and marked.reconciliation_required is True
    assert scoped.compare_and_swap_checkpoint(scope_a.id, mechanism, expected_version=1, checkpoint="synthetic-blocked") is None
    assert scoped.read(scope_b.id, mechanism).reconciliation_required is False
    recovered = scoped.recover_after_reconciliation(scope_a.id, mechanism, expected_version=1, trusted_checkpoint="synthetic-trusted")
    assert recovered is not None and recovered.reconciliation_required is False
    with pytest.raises(ValueError, match="trusted checkpoint"):
        scoped.recover_after_reconciliation(scope_a.id, mechanism, expected_version=2, trusted_checkpoint="")


def test_disabled_and_accountless_scope_state_remains_readable(context):
    _, scoped, _, identity = context
    scope = _scope(identity, "local_files", enabled=False)
    created = scoped.get_or_create(scope.id, "synthetic-local-v1")
    assert scoped.read(scope.id, "synthetic-local-v1") == created


def test_legacy_copy_preserves_state_and_is_idempotent(context):
    engine, scoped, legacy, identity = context
    scope_a = _scope(identity, "nextcloud")
    scope_b = _scope(identity, "immich")
    legacy_a = legacy.get_or_create("nextcloud", "activity_v2_hint_v1")
    advanced = legacy.compare_and_swap_checkpoint("nextcloud", "activity_v2_hint_v1", expected_version=legacy_a.version, checkpoint="synthetic-nextcloud")
    legacy_b = legacy.get_or_create("immich", "metadata_updated_at_v1")
    marked = legacy.mark_reconciliation_required("immich", "metadata_updated_at_v1", expected_version=legacy_b.version)
    plan = {
        ("nextcloud", "activity_v2_hint_v1"): scope_a.id,
        ("immich", "metadata_updated_at_v1"): scope_b.id,
    }
    before_a = legacy.read("nextcloud", "activity_v2_hint_v1")
    before_b = legacy.read("immich", "metadata_updated_at_v1")
    result = copy_legacy_states_to_scopes(engine, plan)
    assert (result.examined, result.created) == (2, 2)
    copied_a = scoped.read(scope_a.id, "activity_v2_hint_v1")
    copied_b = scoped.read(scope_b.id, "metadata_updated_at_v1")
    assert (copied_a.checkpoint, copied_a.version, copied_a.created_at, copied_a.updated_at) == (before_a.checkpoint, before_a.version, before_a.created_at, before_a.updated_at)
    assert copied_b.reconciliation_required is True
    assert legacy.read("nextcloud", "activity_v2_hint_v1") == before_a
    assert legacy.read("immich", "metadata_updated_at_v1") == before_b
    assert copy_legacy_states_to_scopes(engine, plan).created == 0

    changed = scoped.compare_and_swap_checkpoint(scope_a.id, "activity_v2_hint_v1", expected_version=advanced.version, checkpoint="synthetic-conflict")
    assert changed is not None
    with pytest.raises(ScopeStateTransitionError, match="differs"):
        copy_legacy_states_to_scopes(engine, plan)
    assert legacy.read("nextcloud", "activity_v2_hint_v1") == before_a


def test_copy_plan_is_complete_and_atomic(context):
    engine, scoped, legacy, identity = context
    scope = _scope(identity, "nextcloud")
    legacy.get_or_create("nextcloud", "one")
    legacy.get_or_create("immich", "two")
    with pytest.raises(ScopeStateTransitionError, match="every and only"):
        copy_legacy_states_to_scopes(engine, {("nextcloud", "one"): scope.id})
    assert scoped.read(scope.id, "one") is None
