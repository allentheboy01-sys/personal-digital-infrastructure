from pathlib import Path
import secrets
from uuid import UUID, uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from pdi.adapters.base import ProviderFact
from pdi.database import create_postgres_engine
from pdi.engine import DiscoveryBatch, DiscoveryMode
from pdi.principal import (
    DatabaseBindingRecord,
    DatabaseBindingRegistry,
    PersonalDatabaseProvisioner,
    PersonalDatabaseProvisioningSpec,
    PrincipalDatabaseRouter,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scoped_ingestion import (
    ScopedIdentityUnavailableError,
    ScopedIngestionRuntimeFactory,
    ScopedProviderMismatchError,
)
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]


class FakeAdapter:
    def __init__(self, provider_name="nextcloud", facts=()):
        self.provider_name = provider_name
        self.facts = tuple(facts)
        self.connect_count = 0

    def connect(self):
        self.connect_count += 1

    def scan(self):
        return iter(self.facts)

    def open(self, fact):
        yield b"synthetic"


def _fact(provider, external_id):
    return ProviderFact(
        provider=provider,
        kind="file",
        external_id=external_id,
        name=f"{external_id}.txt",
        attributes={
            "path": f"/{external_id}.txt",
            "size": 1,
            "mime_type": "text/plain",
            "version_tag": "v1",
            "content_hash": (external_id.encode().hex() + "0" * 64)[:64],
            "content_byte_length": 1,
        },
        raw={},
    )


def _router(database_url):
    return PrincipalDatabaseRouter(
        PrincipalRegistry((PrincipalRecord(PrincipalId("mu7-user"), "mu7-db"),)),
        DatabaseBindingRegistry(
            (DatabaseBindingRecord("mu7-db", "MU7_DATABASE_URL"),),
            {"MU7_DATABASE_URL": database_url},
        ),
    )


@pytest.fixture
def context():
    database_url = require_safe_test_database_url()
    engine = create_postgres_engine(database_url)
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    token = uuid4().hex
    try:
        yield engine, PostgreSQLProviderIdentityRepository(engine), _router(database_url), token
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM observation_scope_sync_state WHERE observation_scope_id IN (SELECT id FROM observation_scopes WHERE scope_key LIKE :p)"), {"p": f"mu7-{token}%"})
            connection.execute(text("DELETE FROM asset_sources WHERE provider=:provider"), {"provider": f"mu7-{token}"})
            connection.execute(text("DELETE FROM blobs WHERE hash LIKE :p"), {"p": f"mu7-{token}%"})
            connection.execute(text("DELETE FROM assets WHERE title LIKE :p"), {"p": f"%{token}%"})
            connection.execute(text("DELETE FROM observation_scopes WHERE scope_key LIKE :p"), {"p": f"mu7-{token}%"})
            connection.execute(text("DELETE FROM provider_accounts WHERE account_key LIKE :p"), {"p": f"mu7-{token}%"})
            connection.execute(text("DELETE FROM provider_instances WHERE instance_key LIKE :p"), {"p": f"mu7-{token}%"})
        engine.dispose()


def _identities(identity, token, *, account=True):
    provider = f"mu7-{token}"
    instance = identity.create_instance(provider_type=provider, instance_key=f"mu7-{token}-{uuid4().hex}")
    account_row = None
    if account:
        account_row = identity.create_account(provider_instance_id=instance.id, account_key=f"mu7-{token}-{uuid4().hex}")
    scope = identity.create_scope(provider_instance_id=instance.id, provider_account_id=None if account_row is None else account_row.id, scope_key=f"mu7-{token}-{uuid4().hex}")
    return provider, instance, account_row, scope


def test_end_to_end_full_reconciliation_and_reactivation_are_scope_isolated(context):
    _, identity, router, token = context
    provider, _, _, scope_a = _identities(identity, token)
    _, instance_b, _, scope_b = _identities(identity, token)
    # Both scopes must have the same Provider Type, even across Instances.
    assert instance_b.provider_type == provider
    adapter_a = FakeAdapter(provider, (_fact(provider, "a1"), _fact(provider, "a2")))
    adapter_b = FakeAdapter(provider, (_fact(provider, "b1"), _fact(provider, "b2")))
    factory = ScopedIngestionRuntimeFactory(router)
    with factory.build("mu7-user", scope_a.id, adapter_a) as runtime_a, factory.build("mu7-user", scope_b.id, adapter_b) as runtime_b:
        runtime_a.sync_engine.sync_once(); runtime_b.sync_engine.sync_once()
        a2_id = runtime_a.repository.find_source(provider, "a2").id
        adapter_a.facts = (_fact(provider, "a1"),)
        runtime_a.sync_engine.sync_once()
        assert runtime_a.repository.find_source(provider, "a2").is_active is False
        assert runtime_b.repository.find_source(provider, "b1").is_active is True
        assert runtime_b.repository.find_source(provider, "b2").is_active is True
        adapter_a.facts = (_fact(provider, "a1"), _fact(provider, "a2"))
        runtime_a.sync_engine.sync_once()
        assert runtime_a.repository.find_source(provider, "a2").id == a2_id
        assert runtime_a.repository.find_source(provider, "a2").is_active is True


def test_incremental_state_and_source_share_scope_without_legacy_write(context):
    engine, identity, router, token = context
    provider, _, _, scope_a = _identities(identity, token)
    _, _, _, scope_b = _identities(identity, token)
    factory = ScopedIngestionRuntimeFactory(router)
    mechanism = "synthetic_incremental_v1"
    with factory.build("mu7-user", scope_a.id, FakeAdapter(provider)) as runtime_a, factory.build("mu7-user", scope_b.id, FakeAdapter(provider)) as runtime_b:
        state_b = runtime_b.state_repository.get_or_create(provider, mechanism)
        runtime_b.state_repository.compare_and_swap_checkpoint(provider, mechanism, expected_version=state_b.version, checkpoint="synthetic-b")
        advanced = runtime_a.sync_engine.sync_incremental(
            mechanism,
            lambda state: DiscoveryBatch(
                provider=provider,
                mode=DiscoveryMode.INCREMENTAL_NON_AUTHORITATIVE,
                facts=(_fact(provider, "incremental-a"),),
                next_checkpoint="synthetic-a",
            ),
        )
        assert advanced.checkpoint == "synthetic-a"
        assert runtime_a.repository.find_source(provider, "incremental-a").observation_scope_id == str(scope_a.id)
        assert runtime_b.state_repository.read(provider, mechanism).checkpoint == "synthetic-b"
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM provider_sync_state WHERE provider=:provider"), {"provider": provider}).scalar_one() == 0


def test_factory_fails_before_scan_for_mismatch_and_disabled_identities(context):
    _, identity, router, token = context
    provider, instance, account, scope = _identities(identity, token)
    factory = ScopedIngestionRuntimeFactory(router)
    wrong = FakeAdapter("immich")
    with pytest.raises(ScopedProviderMismatchError):
        factory.build("mu7-user", scope.id, wrong)
    assert wrong.connect_count == 0
    identity.set_scope_enabled(scope.id, False)
    with pytest.raises(ScopedIdentityUnavailableError, match="Scope"):
        factory.build("mu7-user", scope.id, FakeAdapter(provider))
    identity.set_scope_enabled(scope.id, True)
    identity.set_account_enabled(account.id, False)
    with pytest.raises(ScopedIdentityUnavailableError, match="Account"):
        factory.build("mu7-user", scope.id, FakeAdapter(provider))
    identity.set_account_enabled(account.id, True)
    identity.set_instance_enabled(instance.id, False)
    with pytest.raises(ScopedIdentityUnavailableError, match="Instance"):
        factory.build("mu7-user", scope.id, FakeAdapter(provider))


def test_accountless_scope_runtime(context):
    _, identity, router, token = context
    provider, _, _, scope = _identities(identity, token, account=False)
    with ScopedIngestionRuntimeFactory(router).build("mu7-user", scope.id, FakeAdapter(provider, (_fact(provider, "local"),))) as runtime:
        runtime.sync_engine.sync_once()
        assert runtime.context.provider_account_id is None
        assert runtime.repository.find_source(provider, "local") is not None


def test_scope_resolution_is_personal_database_local_even_for_same_uuid():
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = (
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu7a_{token}_test",
            runtime_role=f"pdi_mu3_mu7a_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu7-a-db",
        ),
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu7b_{token}_test",
            runtime_role=f"pdi_mu3_mu7b_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu7-b-db",
        ),
    )
    results = []
    try:
        results = [provisioner.provision(spec) for spec in specs]
        engines = [
            create_engine(result.binding.database_url, poolclass=NullPool)
            for result in results
        ]
        mother_only = PostgreSQLProviderIdentityRepository(engines[1])
        mother_provider, _, _, mother_scope = _identities(
            mother_only, uuid4().hex
        )
        router = PrincipalDatabaseRouter(
            PrincipalRegistry(
                (
                    PrincipalRecord(PrincipalId("mu7-a"), "mu7-a-db"),
                    PrincipalRecord(PrincipalId("mu7-b"), "mu7-b-db"),
                )
            ),
            DatabaseBindingRegistry(
                (
                    DatabaseBindingRecord("mu7-a-db", "MU7_A_URL"),
                    DatabaseBindingRecord("mu7-b-db", "MU7_B_URL"),
                ),
                {
                    "MU7_A_URL": results[0].binding.database_url,
                    "MU7_B_URL": results[1].binding.database_url,
                },
            ),
        )
        factory = ScopedIngestionRuntimeFactory(router)
        with pytest.raises(ScopedIdentityUnavailableError):
            factory.build(
                "mu7-a", mother_scope.id, FakeAdapter(mother_provider)
            )

        shared_instance, shared_scope = uuid4(), uuid4()
        for engine in engines:
            with engine.begin() as connection:
                connection.execute(text("INSERT INTO provider_instances (id,provider_type,instance_key,enabled,created_at,updated_at) VALUES (:id,'nextcloud',:key,true,now(),now())"), {"id": shared_instance, "key": f"shared-{token}"})
                connection.execute(text("INSERT INTO observation_scopes (id,provider_instance_id,scope_key,enabled,created_at,updated_at) VALUES (:id,:instance,:key,true,now(),now())"), {"id": shared_scope, "instance": shared_instance, "key": f"shared-{token}"})
        with factory.build("mu7-a", shared_scope, FakeAdapter("nextcloud", (_fact("nextcloud", "a-only"),))) as runtime_a:
            runtime_a.sync_engine.sync_once()
        with factory.build("mu7-b", shared_scope, FakeAdapter("nextcloud", (_fact("nextcloud", "b-only"),))) as runtime_b:
            runtime_b.sync_engine.sync_once()
            assert runtime_b.repository.find_source("nextcloud", "a-only") is None
            assert runtime_b.repository.find_source("nextcloud", "b-only") is not None
    finally:
        for engine in locals().get("engines", []):
            engine.dispose()
        for spec in reversed(specs[: len(results)]):
            provisioner.drop(spec, missing_ok=True)
