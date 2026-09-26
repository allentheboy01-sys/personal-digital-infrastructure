"""Disposable PostgreSQL-16 proof of Principal/DB-local enrichment."""

from datetime import UTC, datetime
import secrets
from uuid import uuid4

from pdi.observation import EnrichmentWorker, FileMetadataExtractor, PostgreSQLObservationRepository
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
from pdi.scoped_operational import PrincipalFormalPipelineRunner
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from tests.integration.database_guard import require_safe_test_database_url


NOW = datetime(2026, 9, 20, tzinfo=UTC)


def _insert_asset(engine, scope_id, label):
    asset_id, blob_id, source_id = uuid4(), uuid4(), uuid4()
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO assets "
            "(id,resource_type,title,metadata,created_at,updated_at) "
            "VALUES (:id,'file',:title,'{}',:now,:now)"
        ), {"id": asset_id, "title": label, "now": NOW})
        connection.execute(text(
            "INSERT INTO blobs (id,asset_id,hash,size,mime_type) "
            "VALUES (:id,:asset,:hash,1,'image/jpeg')"
        ), {"id": blob_id, "asset": asset_id, "hash": str(blob_id)})
        connection.execute(text(
            "INSERT INTO asset_sources "
            "(id,blob_id,provider,external_id,path,name,version_tag,metadata,"
            "is_active,deleted_at,observation_scope_id) "
            "VALUES (:id,:blob,'immich',:external,NULL,:name,NULL,:metadata,"
            "TRUE,NULL,:scope)"
        ), {
            "id": source_id, "blob": blob_id, "external": label,
            "name": f"{label}.jpg", "metadata": '{"fileModifiedAt":"2026-09-20T00:00:00Z"}',
            "scope": scope_id,
        })


def test_scoped_local_enrichment_isolated_between_two_personal_databases(tmp_path):
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=".")
    specs = tuple(
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_p3d{label}_{token}_test",
            runtime_role=f"pdi_mu3_{label}_{token}_runtime",
            runtime_password=secrets.token_urlsafe(24),
            database_ref=f"p3d-{label}-db",
        )
        for label in ("a", "b")
    )
    results = []
    engines = []
    scopes = []
    try:
        results = [provisioner.provision(spec) for spec in specs]
        engines = [create_engine(r.binding.database_url, poolclass=NullPool) for r in results]
        for label, engine in zip(("a", "b"), engines, strict=True):
            identity = PostgreSQLProviderIdentityRepository(engine)
            instance = identity.create_instance(
                provider_type="immich", instance_key=f"p3d-{token}-{label}"
            )
            account = identity.create_account(
                provider_instance_id=instance.id, account_key=f"p3d-{token}-{label}"
            )
            scope = identity.create_scope(
                provider_instance_id=instance.id,
                provider_account_id=account.id,
                scope_key=f"p3d-{token}-{label}",
            )
            scopes.append(scope)
            _insert_asset(engine, scope.id, f"p3d-{token}-{label}-one")

        principals = PrincipalRegistry(tuple(
            PrincipalRecord(PrincipalId(label), f"p3d-{label}-db")
            for label in ("a", "b")
        ))
        environment = {
            "A_URL": results[0].binding.database_url,
            "B_URL": results[1].binding.database_url,
        }
        bindings = DatabaseBindingRegistry((
            DatabaseBindingRecord("p3d-a-db", "A_URL"),
            DatabaseBindingRecord("p3d-b-db", "B_URL"),
        ), environment)
        router = PrincipalDatabaseRouter(principals, bindings)

        def local_executor(engine, _target):
            result = EnrichmentWorker(
                PostgreSQLObservationRepository(engine),
                FileMetadataExtractor(),
                provider=FileMetadataExtractor.discovery_providers,
            ).run_once(batch_size=20000)
            assert result.failed == 0
            assert result.processed == 1

        runner = PrincipalFormalPipelineRunner(
            router, {"enrichment.file_metadata": local_executor},
            lock_path=tmp_path / "p3d.lock",
        )
        before = []
        for engine in engines:
            with engine.connect() as connection:
                before.append(connection.scalar(text("SELECT count(*) FROM resource_statements")))

        assert runner.run("a", "enrichment.file_metadata", lock_timeout=1) == 0
        with engines[0].connect() as connection:
            after_a = connection.scalar(text("SELECT count(*) FROM resource_statements"))
            ledger_a = connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='completed'"))
        with engines[1].connect() as connection:
            after_b = connection.scalar(text("SELECT count(*) FROM resource_statements"))
            ledger_b = connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='completed'"))
        assert after_a > before[0] and after_b == before[1]
        assert ledger_a == 1 and ledger_b == 0

        assert runner.run("b", "enrichment.file_metadata", lock_timeout=1) == 0
        with engines[0].connect() as connection:
            final_a = connection.scalar(text("SELECT count(*) FROM resource_statements"))
            ledger_a = connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='completed'"))
        with engines[1].connect() as connection:
            final_b = connection.scalar(text("SELECT count(*) FROM resource_statements"))
            ledger_b = connection.scalar(text("SELECT count(*) FROM pipeline_runs WHERE status='completed'"))
        assert final_a == after_a and final_b > after_b
        assert ledger_a == 1 and ledger_b == 1
    finally:
        for engine in engines:
            engine.dispose()
        for spec in reversed(specs[:len(results)]):
            provisioner.drop(spec, missing_ok=True)
