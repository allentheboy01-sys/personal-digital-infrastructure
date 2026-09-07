from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from pdi.database import create_postgres_engine
from pdi.provider_identity import (
    PostgreSQLProviderIdentityRepository,
    ProviderIdentityConflictError,
    ProviderIdentityNotFoundError,
    ProviderIdentityRelationshipError,
)
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]


def _alembic_config(connection) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


@pytest.fixture
def identity_context():
    engine = create_postgres_engine(require_safe_test_database_url())
    with engine.connect() as connection:
        command.upgrade(_alembic_config(connection), "head")
    try:
        yield engine, PostgreSQLProviderIdentityRepository(engine)
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM observation_scopes"))
            connection.execute(text("DELETE FROM provider_accounts"))
            connection.execute(text("DELETE FROM provider_instances"))
        engine.dispose()


def test_multiple_instances_accounts_scopes_and_lifecycle(identity_context) -> None:
    _, repository = identity_context
    token = uuid4().hex
    first = repository.create_instance(
        provider_type="nextcloud", instance_key=f"instance-a-{token}"
    )
    second = repository.create_instance(
        provider_type="nextcloud", instance_key=f"instance-b-{token}"
    )
    first_account = repository.create_account(
        provider_instance_id=first.id, account_key="primary"
    )
    second_account = repository.create_account(
        provider_instance_id=first.id, account_key="secondary"
    )
    other_instance_account = repository.create_account(
        provider_instance_id=second.id, account_key="primary"
    )
    first_scope = repository.create_scope(
        provider_instance_id=first.id,
        provider_account_id=first_account.id,
        scope_key="files",
    )
    second_scope = repository.create_scope(
        provider_instance_id=first.id,
        provider_account_id=second_account.id,
        scope_key="shared-files",
    )
    other_scope = repository.create_scope(
        provider_instance_id=second.id,
        provider_account_id=other_instance_account.id,
        scope_key="files",
    )

    assert len(repository.list_instances()) == 2
    assert repository.list_accounts_for_instance(first.id) == (
        first_account,
        second_account,
    )
    assert repository.list_scopes_for_account(first_account.id) == (first_scope,)
    assert repository.get_scope_by_key(second.id, "files") == other_scope
    assert second_scope.provider_account_id == second_account.id

    changed_at = datetime.now(UTC) + timedelta(seconds=1)
    disabled_instance = repository.set_instance_enabled(
        first.id, False, now=changed_at
    )
    disabled_account = repository.set_account_enabled(
        first_account.id, False, now=changed_at
    )
    disabled_scope = repository.set_scope_enabled(
        first_scope.id, False, now=changed_at
    )
    assert not disabled_instance.enabled
    assert not disabled_account.enabled
    assert not disabled_scope.enabled
    assert repository.get_instance(first.id) == disabled_instance
    assert repository.get_account(first_account.id) == disabled_account
    assert repository.get_scope(first_scope.id) == disabled_scope


def test_accountless_provider_and_missing_relationships(identity_context) -> None:
    _, repository = identity_context
    local = repository.create_instance(
        provider_type="local_files",
        instance_key=f"local-{uuid4().hex}",
    )
    scope = repository.create_scope(
        provider_instance_id=local.id,
        provider_account_id=None,
        scope_key="documents",
    )
    assert scope.provider_account_id is None
    with pytest.raises(ProviderIdentityNotFoundError):
        repository.create_account(
            provider_instance_id=uuid4(), account_key="missing-instance"
        )
    with pytest.raises(ProviderIdentityNotFoundError):
        repository.create_scope(
            provider_instance_id=local.id,
            provider_account_id=uuid4(),
            scope_key="missing-account",
        )


def test_uniqueness_and_cross_instance_relationship(identity_context) -> None:
    engine, repository = identity_context
    token = uuid4().hex
    first = repository.create_instance(
        provider_type="immich", instance_key=f"first-{token}"
    )
    second = repository.create_instance(
        provider_type="immich", instance_key=f"second-{token}"
    )
    with pytest.raises(ProviderIdentityConflictError):
        repository.create_instance(
            provider_type="immich", instance_key=first.instance_key
        )
    account = repository.create_account(
        provider_instance_id=first.id, account_key="same-key"
    )
    with pytest.raises(ProviderIdentityConflictError):
        repository.create_account(
            provider_instance_id=first.id, account_key="same-key"
        )
    repository.create_account(
        provider_instance_id=second.id, account_key="same-key"
    )
    repository.create_scope(
        provider_instance_id=first.id, scope_key="same-scope"
    )
    with pytest.raises(ProviderIdentityConflictError):
        repository.create_scope(
            provider_instance_id=first.id, scope_key="same-scope"
        )
    repository.create_scope(
        provider_instance_id=second.id, scope_key="same-scope"
    )
    with pytest.raises(ProviderIdentityRelationshipError):
        repository.create_scope(
            provider_instance_id=second.id,
            provider_account_id=account.id,
            scope_key="wrong-instance",
        )

    # The relational composite FK independently enforces the same invariant.
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO observation_scopes "
                    "(id, provider_instance_id, provider_account_id, scope_key, "
                    "enabled, created_at, updated_at) "
                    "VALUES (:id, :instance, :account, 'raw-mismatch', true, "
                    "now(), now())"
                ),
                {"id": uuid4(), "instance": second.id, "account": account.id},
            )


def test_database_constraints_reject_empty_and_invalid_foreign_keys(
    identity_context,
) -> None:
    engine, _ = identity_context
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO provider_instances "
                    "(id, provider_type, instance_key, enabled, created_at, updated_at) "
                    "VALUES (:id, '', 'valid-key', true, now(), now())"
                ),
                {"id": uuid4()},
            )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO provider_accounts "
                    "(id, provider_instance_id, account_key, enabled, created_at, updated_at) "
                    "VALUES (:id, :instance, 'valid-key', true, now(), now())"
                ),
                {"id": uuid4(), "instance": uuid4()},
            )
