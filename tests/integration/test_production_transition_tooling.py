from datetime import UTC, datetime
from pathlib import Path
import secrets
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from pdi.database import create_postgres_engine
from pdi.adapters.base import ProviderFact
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
from pdi.scoped_derived_transition import (
    DerivedTransitionError,
    plan_legacy_person_transition,
    plan_legacy_relation_transition,
    transition_legacy_person_sources,
    transition_legacy_resource_person_relations,
)
from pdi.scoped_operational import (
    PrincipalFormalPipelineRunner,
    SCOPED_FORMAL_PIPELINES,
    ScopedFormalPipelineError,
    build_executable_scoped_runner,
)
from pdi.data_status.models import PipelineKind
from pdi.scoped_operator_config import (
    ScopedOperatorConfiguration,
    ScopedProviderBinding,
)
from pdi.scope_sync_state import copy_legacy_states_to_scopes
from pdi.sync_state import PostgreSQLProviderSyncStateRepository
from pdi.scoped_ingestion import ScopedIngestionRuntimeFactory
from pdi.person_identity import ProviderPersonIdentity, ScopedPersonRepository
from pdi.resource_person_relation import ScopedResourcePersonRelationRepository
from pdi.source_provenance import (
    SourceProvenanceBackfillError,
    backfill_source_observation_scopes,
    plan_source_observation_scopes,
)
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def database():
    url = require_safe_test_database_url()
    engine = create_postgres_engine(url)
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    with engine.begin() as connection:
        for table in (
            "pipeline_runs", "observation_scope_resource_person_relations",
            "resource_person_relations", "observation_scope_person_sources",
            "person_sources", "persons", "asset_sources", "blobs", "assets",
            "observation_scope_sync_state", "provider_sync_state",
            "observation_scopes", "provider_accounts", "provider_instances",
        ):
            connection.execute(text(f"DELETE FROM {table}"))
    try:
        yield engine, url
    finally:
        with engine.begin() as connection:
            for table in (
                "pipeline_runs", "observation_scope_resource_person_relations",
                "resource_person_relations", "observation_scope_person_sources",
                "person_sources", "persons", "asset_sources", "blobs", "assets",
                "observation_scope_sync_state", "provider_sync_state",
                "observation_scopes", "provider_accounts", "provider_instances",
            ):
                connection.execute(text(f"DELETE FROM {table}"))
        engine.dispose()


def _scope(engine, provider):
    identities = PostgreSQLProviderIdentityRepository(engine)
    token = uuid4().hex
    instance = identities.create_instance(
        provider_type=provider, instance_key=f"mu13-{token}"
    )
    return identities.create_scope(
        provider_instance_id=instance.id, scope_key=f"mu13-{token}"
    )


def _legacy_world(engine, provider):
    scope = _scope(engine, provider)
    person_id, asset_id, blob_id, source_id = (uuid4() for _ in range(4))
    now = datetime(2026, 9, 10, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO persons(id, created_at) VALUES (:id, :now)"), {"id": person_id, "now": now})
        connection.execute(text("INSERT INTO person_sources(provider, external_id, person_id, display_name, inactive_at) VALUES (:p, 'person-x', :id, 'Synthetic', NULL)"), {"p": provider, "id": person_id})
        connection.execute(
            text("INSERT INTO assets(id, resource_type, title, created_at, updated_at) VALUES (:id, 'file', 'synthetic', :now, :now)"),
            {"id": asset_id, "now": now},
        )
        connection.execute(text("INSERT INTO blobs(id, asset_id, hash, size, mime_type) VALUES (:id, :asset, :hash, 1, 'text/plain')"), {"id": blob_id, "asset": asset_id, "hash": uuid4().hex})
        connection.execute(text("INSERT INTO asset_sources(id, blob_id, provider, external_id, observation_scope_id, metadata, is_active) VALUES (:id, :blob, :p, 'asset-x', :scope, '{}'::jsonb, true)"), {"id": source_id, "blob": blob_id, "p": provider, "scope": scope.id})
        connection.execute(text("INSERT INTO resource_person_relations(resource_id, person_id, provider, inactive_at) VALUES (:asset, :person, :p, NULL)"), {"asset": asset_id, "person": person_id, "p": provider})
    return scope, person_id, asset_id


def test_person_and_relation_transition_are_plannable_atomic_and_idempotent(database):
    engine, _ = database
    scope, person_id, asset_id = _legacy_world(engine, "immich")
    mapping = {"immich": scope.id}
    person_plan = plan_legacy_person_transition(engine, mapping)
    assert person_plan.ready and person_plan.would_create == 1
    applied = transition_legacy_person_sources(engine, mapping)
    assert applied.would_create == 1
    assert transition_legacy_person_sources(engine, mapping).already_equivalent == 1
    relation_plan = plan_legacy_relation_transition(engine, mapping)
    assert relation_plan.ready and relation_plan.would_create == 1
    transition_legacy_resource_person_relations(engine, mapping)
    assert transition_legacy_resource_person_relations(engine, mapping).already_equivalent == 1
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT person_id FROM observation_scope_person_sources WHERE observation_scope_id=:s"), {"s": scope.id}) == person_id
        assert connection.scalar(text("SELECT resource_id FROM observation_scope_resource_person_relations WHERE observation_scope_id=:s"), {"s": scope.id}) == asset_id
        assert connection.scalar(text("SELECT count(*) FROM person_sources")) == 1
        assert connection.scalar(text("SELECT count(*) FROM resource_person_relations")) == 1


def test_transition_failures_do_not_partially_write(database):
    engine, _ = database
    scope, _, _ = _legacy_world(engine, "immich")
    _legacy_world(engine, "integration-test")
    plan = plan_legacy_person_transition(engine, {"immich": scope.id})
    assert plan.providers_without_mapping == ("integration-test",)
    with pytest.raises(DerivedTransitionError):
        transition_legacy_person_sources(engine, {"immich": scope.id})
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM observation_scope_person_sources")) == 0

    # Existing Source transition also refuses the omitted production-audit type.
    with engine.begin() as connection:
        connection.execute(text("UPDATE asset_sources SET observation_scope_id=NULL"))
    with pytest.raises(SourceProvenanceBackfillError):
        plan_source_observation_scopes(engine, {"immich": scope.id})
    with pytest.raises(SourceProvenanceBackfillError):
        backfill_source_observation_scopes(engine, {"immich": scope.id})


def test_relation_requires_both_scoped_evidence(database):
    engine, _ = database
    scope, _, _ = _legacy_world(engine, "immich")
    plan = plan_legacy_relation_transition(engine, {"immich": scope.id})
    assert plan.missing_person_scope_evidence == 1
    with pytest.raises(DerivedTransitionError):
        transition_legacy_resource_person_relations(engine, {"immich": scope.id})
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM observation_scope_resource_person_relations")) == 0


def test_formal_runner_routes_all_enabled_scopes_and_ledger_to_personal_db(database, tmp_path):
    engine, url = database
    _scope(engine, "immich")
    _scope(engine, "immich")
    _scope(engine, "nextcloud")
    _scope(engine, "nextcloud")
    disabled = _scope(engine, "immich")
    PostgreSQLProviderIdentityRepository(engine).set_scope_enabled(disabled.id, False)
    engine.dispose()
    router = PrincipalDatabaseRouter.explicit_single_user(
        principal_id="synthetic-a", database_url=url
    )
    seen = []
    executors = {
        key: (lambda db, target, key=key: seen.append((key, target)))
        for key in SCOPED_FORMAL_PIPELINES
    }
    runner = PrincipalFormalPipelineRunner(
        router, executors, lock_path=tmp_path / "pdi-sync.lock"
    )
    for key in SCOPED_FORMAL_PIPELINES:
        assert runner.run("synthetic-a", key, lock_timeout=1) == 0
    assert all(target is not None for _, target in seen)
    # Provider/person/relation operations fan out by enabled Scope; enrichment
    # is one Principal-level run whose readers resolve each Source Scope.
    enabled_scope_counts = {"immich": 2, "nextcloud": 2}
    expected = sum(
        1 if spec.kind is PipelineKind.ENRICHMENT
        else enabled_scope_counts[spec.provider_type]
        for spec in SCOPED_FORMAL_PIPELINES.values()
    )
    assert len(seen) == expected
    verify = create_postgres_engine(url)
    with verify.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='completed'")) == len(SCOPED_FORMAL_PIPELINES)
    verify.dispose()


def test_multi_scope_failure_is_visible_after_all_scopes_are_attempted(database, tmp_path):
    engine, url = database
    scopes = (_scope(engine, "immich"), _scope(engine, "immich"))
    engine.dispose()
    attempted = []
    def fail_one(db, target):
        attempted.append(target.observation_scope_id)
        if target.observation_scope_id == scopes[0].id:
            raise RuntimeError("synthetic failure")
    runner = PrincipalFormalPipelineRunner(
        PrincipalDatabaseRouter.explicit_single_user(
            principal_id="synthetic-a", database_url=url
        ),
        {"provider.immich.sync": fail_one},
        lock_path=tmp_path / "failure.lock",
    )
    with pytest.raises(ScopedFormalPipelineError, match="1 scoped"):
        runner.run("synthetic-a", "provider.immich.sync", lock_timeout=1)
    assert set(attempted) == {scope.id for scope in scopes}
    verify = create_postgres_engine(url)
    with verify.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='failed'")) == 1
    verify.dispose()


def test_two_principal_executable_full_sync_isolation(monkeypatch, tmp_path):
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = tuple(
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_p1a_{name}_{token}_test",
            runtime_role=f"pdi_mu3_p1a_{name}_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref=f"{name}-db",
        )
        for name in ("a", "b")
    )
    results = []
    try:
        results = [provisioner.provision(spec) for spec in specs]
        scopes = []
        for result in results:
            db = create_postgres_engine(result.binding.database_url)
            scopes.append(_scope(db, "nextcloud"))
            db.dispose()
        principals = PrincipalRegistry(tuple(
            PrincipalRecord(PrincipalId(name), f"{name}-db")
            for name in ("a", "b")
        ))
        environment = {
            "A_DB_URL": results[0].binding.database_url,
            "B_DB_URL": results[1].binding.database_url,
            "A_SECRET": "synthetic-a",
            "B_SECRET": "synthetic-b",
        }
        databases = DatabaseBindingRegistry((
            DatabaseBindingRecord("a-db", "A_DB_URL"),
            DatabaseBindingRecord("b-db", "B_DB_URL"),
        ), environment)
        bindings = {
            (PrincipalId(name), scope.id): ScopedProviderBinding(
                PrincipalId(name), scope.id, "nextcloud",
                "https://provider.invalid", f"{name.upper()}_SECRET", name,
            )
            for name, scope in zip(("a", "b"), scopes, strict=True)
        }
        config = ScopedOperatorConfiguration(
            PrincipalDatabaseRouter(principals, databases), bindings, environment
        )

        class FakeNextcloudAdapter:
            provider_name = "nextcloud"
            def __init__(self, endpoint, username, secret):
                self.username = username
            def connect(self): pass
            def scan(self):
                payload = self.username.encode()
                yield ProviderFact(
                    provider="nextcloud", kind="file", external_id="same-id",
                    name=f"{self.username}.txt",
                    attributes={"size": len(payload), "mime_type": "text/plain"},
                    raw={},
                )
            def open(self, fact): yield self.username.encode()

        monkeypatch.setattr("pdi.scoped_operational.NextcloudAdapter", FakeNextcloudAdapter)
        runner = build_executable_scoped_runner(
            config, lock_path=tmp_path / "two-principal.lock"
        )
        assert runner.run("a", "provider.nextcloud.sync", lock_timeout=1) == 0
        assert runner.run("b", "provider.nextcloud.sync", lock_timeout=1) == 0
        for name, result, scope in zip(("a", "b"), results, scopes, strict=True):
            db = create_postgres_engine(result.binding.database_url)
            with db.connect() as connection:
                assert connection.scalar(text("SELECT count(*) FROM asset_sources WHERE observation_scope_id=:s"), {"s": scope.id}) == 1
                assert connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='completed'")) == 1
                assert connection.scalar(text("SELECT name FROM asset_sources")) == f"{name}.txt"
            db.dispose()
    finally:
        for spec in reversed(specs[:len(results)]):
            provisioner.drop(spec, missing_ok=True)


def test_complete_old_schema_transition_rehearsal(database):
    engine, url = database
    config = Config(str(ROOT / "alembic.ini"))
    try:
        with engine.connect() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "base")
            command.upgrade(config, "5e7a9c2d1f30")
        now = datetime(2026, 9, 10, tzinfo=UTC)
        person_id = uuid4()
        legacy = {}
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO persons(id,created_at) VALUES (:id,:now)"), {"id": person_id, "now": now})
            connection.execute(text("INSERT INTO person_sources(provider,external_id,person_id,display_name,inactive_at) VALUES ('immich','person-x',:id,'Synthetic',NULL)"), {"id": person_id})
            for provider in ("nextcloud", "immich", "gmail", "integration-test"):
                asset, blob, source = uuid4(), uuid4(), uuid4()
                payload = f"{provider}-synthetic".encode()
                import hashlib
                digest = hashlib.sha256(payload).hexdigest()
                legacy[provider] = (asset, blob, source, digest, payload)
                connection.execute(text("INSERT INTO assets(id,resource_type,title,created_at,updated_at) VALUES (:id,'file','Synthetic',:now,:now)"), {"id": asset, "now": now})
                connection.execute(text("INSERT INTO blobs(id,asset_id,hash,size,mime_type) VALUES (:id,:asset,:hash,:size,'text/plain')"), {"id": blob, "asset": asset, "hash": digest, "size": len(payload)})
                connection.execute(text("INSERT INTO asset_sources(id,blob_id,provider,external_id,name,version_tag,metadata,is_active) VALUES (:id,:blob,:provider,:external,:name,'v1','{}'::jsonb,true)"), {"id": source, "blob": blob, "provider": provider, "external": f"{provider}-x", "name": f"{provider}.txt"})
            connection.execute(text("INSERT INTO resource_person_relations(resource_id,person_id,provider,inactive_at) VALUES (:asset,:person,'immich',NULL)"), {"asset": legacy["immich"][0], "person": person_id})
        legacy_state = PostgreSQLProviderSyncStateRepository(engine)
        for provider, mechanism in (("nextcloud", "activity_v2_hint_v1"), ("immich", "metadata_updated_at_v1")):
            state = legacy_state.get_or_create(provider, mechanism)
            legacy_state.compare_and_swap_checkpoint(provider, mechanism, expected_version=state.version, checkpoint=f"synthetic-{provider}")

        with engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        identities = PostgreSQLProviderIdentityRepository(engine)
        scopes = {provider: _scope(engine, provider) for provider in legacy}
        incomplete = {key: value.id for key, value in scopes.items() if key != "integration-test"}
        with pytest.raises(SourceProvenanceBackfillError):
            plan_source_observation_scopes(engine, incomplete)
        mapping = {key: value.id for key, value in scopes.items()}
        assert plan_source_observation_scopes(engine, mapping).updated == 4
        assert backfill_source_observation_scopes(engine, mapping).updated == 4
        assert plan_legacy_person_transition(engine, {"immich": scopes["immich"].id}).ready
        transition_legacy_person_sources(engine, {"immich": scopes["immich"].id})
        assert plan_legacy_relation_transition(engine, {"immich": scopes["immich"].id}).ready
        transition_legacy_resource_person_relations(engine, {"immich": scopes["immich"].id})
        state_plan = {
            ("nextcloud", "activity_v2_hint_v1"): scopes["nextcloud"].id,
            ("immich", "metadata_updated_at_v1"): scopes["immich"].id,
        }
        assert copy_legacy_states_to_scopes(engine, state_plan).created == 2
        assert backfill_source_observation_scopes(engine, mapping).updated == 0
        assert transition_legacy_person_sources(engine, {"immich": scopes["immich"].id}).already_equivalent == 1
        assert transition_legacy_resource_person_relations(engine, {"immich": scopes["immich"].id}).already_equivalent == 1
        assert copy_legacy_states_to_scopes(engine, state_plan).created == 0
        class FakeImmichAdapter:
            provider_name = "immich"
            def connect(self): pass
            def scan(self):
                payload = legacy["immich"][4]
                yield ProviderFact(
                    provider="immich", kind="file", external_id="immich-x",
                    name="immich.txt",
                    attributes={
                        "size": len(payload), "mime_type": "text/plain",
                        "version_tag": "v1",
                    }, raw={},
                )
            def open(self, fact): yield legacy["immich"][4]
        router = PrincipalDatabaseRouter.explicit_single_user(
            principal_id="synthetic-transition", database_url=url
        )
        with ScopedIngestionRuntimeFactory(router).build(
            "synthetic-transition", scopes["immich"].id, FakeImmichAdapter()
        ) as runtime:
            runtime.sync_engine.sync_once()
        person_result = ScopedPersonRepository(
            engine, scopes["immich"].id
        ).reconcile_inventory((ProviderPersonIdentity("person-x", "Synthetic"),))
        assert person_result.existing == 1
        relation_result = ScopedResourcePersonRelationRepository(
            engine, scopes["immich"].id
        ).reconcile_relations((("immich-x", "person-x"),))
        assert relation_result.unchanged == 1
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM asset_sources WHERE observation_scope_id IS NOT NULL")) == 4
            assert connection.scalar(text("SELECT count(*) FROM person_sources")) == 1
            assert connection.scalar(text("SELECT count(*) FROM resource_person_relations")) == 1
            assert connection.scalar(text("SELECT count(*) FROM provider_sync_state")) == 2
            assert connection.scalar(text("SELECT count(*) FROM observation_scope_sync_state")) == 2
            assert connection.scalar(text("SELECT count(*) FROM asset_sources WHERE provider='immich'")) == 1
    finally:
        with engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
