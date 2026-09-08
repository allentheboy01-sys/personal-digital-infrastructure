from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from pdi.database import create_postgres_engine
from pdi.decision import Action, ActionType, Decision
from pdi.models import Asset, AssetSource, Blob
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.repository import PostgreSQLRepository, SourceIdentityAmbiguityError
from pdi.source_provenance import SourceProvenanceBackfillError, backfill_source_observation_scopes
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def context():
    engine = create_postgres_engine(require_safe_test_database_url())
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini")); config.attributes["connection"] = connection
        command.upgrade(config, "head")
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM asset_sources"))
        connection.execute(text("DELETE FROM blobs"))
        connection.execute(text("DELETE FROM assets"))
        connection.execute(text("DELETE FROM observation_scopes"))
        connection.execute(text("DELETE FROM provider_accounts"))
        connection.execute(text("DELETE FROM provider_instances"))
    token = uuid4().hex
    try:
        yield engine, PostgreSQLRepository(engine), PostgreSQLProviderIdentityRepository(engine), token
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM asset_sources WHERE provider LIKE :p"), {"p": f"mu5-{token}%"})
            connection.execute(text("DELETE FROM blobs WHERE hash LIKE :p"), {"p": f"mu5-{token}%"})
            connection.execute(text("DELETE FROM assets WHERE title LIKE :p"), {"p": f"MU5-{token}%"})
            connection.execute(text("DELETE FROM observation_scopes WHERE scope_key LIKE :p"), {"p": f"mu5-{token}%"})
            connection.execute(text("DELETE FROM provider_accounts WHERE account_key LIKE :p"), {"p": f"mu5-{token}%"})
            connection.execute(text("DELETE FROM provider_instances WHERE instance_key LIKE :p"), {"p": f"mu5-{token}%"})
        engine.dispose()


def _identity(identity, token, provider="nextcloud"):
    instance = identity.create_instance(provider_type=provider, instance_key=f"mu5-{token}-{uuid4().hex}")
    return identity.create_scope(provider_instance_id=instance.id, scope_key=f"mu5-{token}-{uuid4().hex}")


def _create(repository, token, provider, external_id, scope_id=None):
    asset = Asset(title=f"MU5-{token}-{uuid4().hex}")
    blob = Blob(asset_id=asset.id, hash=f"mu5-{token}-{uuid4().hex}")
    source = AssetSource(blob_id=blob.id, provider=provider, external_id=external_id, observation_scope_id=None if scope_id is None else str(scope_id))
    repository.execute(Decision(actions=[Action(ActionType.CREATE_ASSET, asset=asset), Action(ActionType.CREATE_BLOB, blob=blob), Action(ActionType.CREATE_SOURCE, source=source)]))
    return asset, blob, source


def test_two_scopes_same_external_id_and_legacy_ambiguity(context):
    _, repository, identity, token = context
    provider = f"mu5-{token}"
    scope_a = _identity(identity, token, provider); scope_b = _identity(identity, token, provider)
    _, _, source_a = _create(repository, token, provider, "123", scope_a.id)
    _, _, source_b = _create(repository, token, provider, "123", scope_b.id)
    assert source_a.id != source_b.id
    assert repository.find_source_in_scope(str(scope_a.id), "123").id == source_a.id
    assert repository.find_source_in_scope(str(scope_b.id), "123").id == source_b.id
    with pytest.raises(SourceIdentityAmbiguityError):
        repository.find_source(provider, "123")


def test_legacy_unique_and_provider_scope_match(context):
    _, repository, identity, token = context
    provider = f"mu5-{token}"
    _create(repository, token, provider, "legacy")
    with pytest.raises(IntegrityError):
        _create(repository, token, provider, "legacy")
    immich_scope = _identity(identity, token, "immich")
    with pytest.raises(ValueError, match="does not match"):
        _create(repository, token, provider, "wrong", immich_scope.id)


def test_atomic_idempotent_backfill_preserves_world_rows(context):
    engine, repository, identity, token = context
    provider = f"mu5-{token}"
    scope = _identity(identity, token, provider)
    asset, blob, source = _create(repository, token, provider, "legacy-backfill")
    before = (asset.id, blob.id, source.id, source.blob_id)
    result = backfill_source_observation_scopes(engine, {provider: scope.id})
    assert (result.examined, result.updated) == (1, 1)
    stored = repository.find_source_in_scope(str(scope.id), "legacy-backfill")
    assert (asset.id, blob.id, stored.id, stored.blob_id) == before
    assert backfill_source_observation_scopes(engine, {provider: scope.id}).updated == 0

    other_scope = _identity(identity, token, provider)
    with pytest.raises(SourceProvenanceBackfillError, match="different Scope"):
        backfill_source_observation_scopes(engine, {provider: other_scope.id})
    assert repository.find_source_in_scope(str(scope.id), "legacy-backfill").id == source.id


def test_scoped_reactivation_is_local_to_scope(context):
    _, repository, identity, token = context
    provider = f"mu5-{token}"
    scope_a = _identity(identity, token, provider)
    scope_b = _identity(identity, token, provider)
    _, _, source_a = _create(repository, token, provider, "reactivate", scope_a.id)
    source_a.is_active = False
    repository.execute(Decision(actions=[Action(ActionType.DEACTIVATE_SOURCE, source=source_a)]))
    source_a.is_active = True
    repository.execute(Decision(actions=[Action(ActionType.UPDATE_SOURCE, source=source_a)]))
    assert repository.find_source_in_scope(str(scope_a.id), "reactivate").id == source_a.id
    _, _, source_b = _create(repository, token, provider, "reactivate", scope_b.id)
    assert source_b.id != source_a.id


def test_backfill_missing_mapping_is_atomic(context):
    engine, repository, identity, token = context
    first, second = f"mu5-{token}-a", f"mu5-{token}-b"
    scope = _identity(identity, token, first)
    _create(repository, token, first, "a"); _create(repository, token, second, "b")
    with pytest.raises(SourceProvenanceBackfillError, match="no Scope mapping"):
        backfill_source_observation_scopes(engine, {first: scope.id})
    assert repository.find_source(first, "a").observation_scope_id is None
    assert repository.find_source(second, "b").observation_scope_id is None
