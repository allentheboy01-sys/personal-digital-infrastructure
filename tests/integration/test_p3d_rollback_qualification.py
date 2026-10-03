from __future__ import annotations

import os
from pathlib import Path
import shutil
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy.engine import make_url

from pdi.production_ops.p3d_rollback_qualification import (
    ExportedSnapshotCoordinator,
    Postgres16RestoreQualificationAdapter,
    PostgresBaselineCollector,
    PostgresCommandAdapter,
    PostgresTarget,
    QualificationContext,
    ResticBackupAdapter,
    RollbackQualificationOrchestrator,
    SourceRuntimeEvidenceV1,
    baseline_counts_fingerprint,
)
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    OperatorToolIdentity,
    ToolName,
    canonical_json_bytes,
)
from tests.integration.database_guard import require_safe_test_database_url


def _required_executable(name: str) -> Path:
    value = shutil.which(name)
    if value is None:
        if os.environ.get("CI"):
            pytest.fail(f"{name} is required by P3D rollback integration")
        pytest.skip(f"{name} is unavailable outside CI")
    return Path(value)


def _target_from_test_url(*, database: str | None = None) -> PostgresTarget:
    parsed = make_url(require_safe_test_database_url())
    target_database = database or str(parsed.database)
    return PostgresTarget(
        str(parsed.host),
        int(parsed.port or 5432),
        target_database,
        str(parsed.username),
        str(parsed.password),
    )


def _create_database(admin: PostgresTarget, name: str) -> None:
    with psycopg.connect(admin.conninfo(database="postgres"), autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))


def _drop_database(admin: PostgresTarget, name: str) -> None:
    with psycopg.connect(admin.conninfo(database="postgres"), autocommit=True) as connection:
        connection.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
        )


def _install_synthetic_production_shape(target: PostgresTarget) -> None:
    statements = (
        "CREATE TABLE alembic_version (version_num text PRIMARY KEY)",
        "INSERT INTO alembic_version VALUES ('e5a7b9d1f324')",
        "CREATE TABLE assets (id uuid PRIMARY KEY)",
        "CREATE TABLE blobs (id uuid PRIMARY KEY, asset_id uuid NOT NULL REFERENCES assets(id))",
        "CREATE TABLE persons (id uuid PRIMARY KEY)",
        "CREATE TABLE person_sources (id uuid PRIMARY KEY)",
        "CREATE TABLE resource_person_relations (id uuid PRIMARY KEY)",
        "CREATE TABLE resource_statements (id uuid PRIMARY KEY)",
        "CREATE TABLE resource_enrichments (id uuid PRIMARY KEY)",
        "CREATE TABLE pipeline_runs (id uuid PRIMARY KEY)",
        "CREATE TABLE provider_sync_state (provider text, mechanism text, PRIMARY KEY(provider, mechanism))",
        "CREATE TABLE provider_instances (id uuid CONSTRAINT pk_provider_instances PRIMARY KEY, provider_type text UNIQUE, enabled boolean NOT NULL)",
        "CREATE TABLE provider_accounts (id uuid CONSTRAINT pk_provider_accounts PRIMARY KEY, provider_instance_id uuid NOT NULL CONSTRAINT fk_provider_accounts_instance REFERENCES provider_instances(id), enabled boolean NOT NULL, UNIQUE(id, provider_instance_id))",
        "CREATE TABLE observation_scopes (id uuid CONSTRAINT pk_observation_scopes PRIMARY KEY, provider_instance_id uuid NOT NULL CONSTRAINT fk_observation_scopes_instance REFERENCES provider_instances(id), provider_account_id uuid, enabled boolean NOT NULL, CONSTRAINT fk_observation_scopes_account_instance FOREIGN KEY(provider_account_id, provider_instance_id) REFERENCES provider_accounts(id, provider_instance_id))",
        "CREATE TABLE asset_sources (id uuid PRIMARY KEY, blob_id uuid NOT NULL CONSTRAINT fk_asset_sources_blob REFERENCES blobs(id), provider text NOT NULL, external_id text NOT NULL, observation_scope_id uuid NOT NULL CONSTRAINT fk_asset_sources_observation_scope REFERENCES observation_scopes(id), UNIQUE(observation_scope_id, external_id))",
        "CREATE TABLE observation_scope_sync_state (observation_scope_id uuid, mechanism text NOT NULL, checkpoint jsonb, reconciliation_required boolean NOT NULL, CONSTRAINT pk_observation_scope_sync_state PRIMARY KEY(observation_scope_id, mechanism), CONSTRAINT fk_observation_scope_sync_state_scope FOREIGN KEY(observation_scope_id) REFERENCES observation_scopes(id))",
    )
    with psycopg.connect(target.conninfo()) as connection:
        for statement in statements:
            connection.execute(statement)
        asset_id = uuid4()
        blob_id = uuid4()
        connection.execute("INSERT INTO assets VALUES (%s)", (asset_id,))
        connection.execute("INSERT INTO blobs VALUES (%s,%s)", (blob_id, asset_id))
        instance_ids = {}
        scope_ids = {}
        for provider, enabled in (
            ("nextcloud", True),
            ("immich", True),
            ("gmail", False),
            ("integration-test", False),
        ):
            instance_id = uuid4()
            scope_id = uuid4()
            instance_ids[provider] = instance_id
            scope_ids[provider] = scope_id
            connection.execute(
                "INSERT INTO provider_instances VALUES (%s,%s,%s)",
                (instance_id, provider, enabled),
            )
            account_id = None
            if provider in {"nextcloud", "immich"}:
                account_id = uuid4()
                connection.execute(
                    "INSERT INTO provider_accounts VALUES (%s,%s,true)",
                    (account_id, instance_id),
                )
            connection.execute(
                "INSERT INTO observation_scopes VALUES (%s,%s,%s,%s)",
                (scope_id, instance_id, account_id, enabled),
            )
            connection.execute(
                "INSERT INTO asset_sources VALUES (%s,%s,%s,%s,%s)",
                (uuid4(), blob_id, provider, f"synthetic-{provider}", scope_id),
            )
        for provider in ("nextcloud", "immich"):
            connection.execute(
                "INSERT INTO observation_scope_sync_state VALUES (%s,%s,%s::jsonb,false)",
                (
                    scope_ids[provider],
                    "activity_v2_hint_v1" if provider == "nextcloud" else "metadata_updated_at_v1",
                    '{"synthetic":true}',
                ),
            )
        for table in (
            "persons", "person_sources",
            "resource_person_relations", "resource_statements",
            "resource_enrichments", "pipeline_runs",
        ):
            connection.execute(
                sql.SQL("INSERT INTO {} VALUES (%s)").format(sql.Identifier(table)),
                (uuid4(),),
            )
        connection.execute(
            "INSERT INTO provider_sync_state VALUES ('nextcloud','activity_v2_hint_v1')"
        )
        connection.execute(
            "INSERT INTO provider_sync_state VALUES ('immich','metadata_updated_at_v1')"
        )
        connection.commit()


def _source_runtime() -> SourceRuntimeEvidenceV1:
    return SourceRuntimeEvidenceV1(
        "b" * 40,
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "3.13.7",
        "cpython-313",
        "4" * 64,
        "e5a7b9d1f324",
    )


class _QualifiedSyntheticSource:
    def qualify(self, expected_source_sha: str) -> SourceRuntimeEvidenceV1:
        evidence = _source_runtime()
        assert expected_source_sha == evidence.source_sha
        return evidence


def _operator_tool(name: ToolName, source_sha: str) -> OperatorToolIdentity:
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": name.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": (
            "5" * 64 if name is ToolName.BACKUP_EXPORT else "6" * 64
        ),
        "TOOL_SOURCE_SHA": source_sha,
    })


def test_real_postgresql16_same_snapshot_dump_backup_restore_and_read_only_compatibility(
    tmp_path: Path,
) -> None:
    pg_dump = _required_executable("pg_dump")
    pg_restore = _required_executable("pg_restore")
    restic = _required_executable("restic")
    admin = _target_from_test_url()
    source_database = f"pdi_p3d_source_{uuid4().hex}_test"
    source = _target_from_test_url(database=source_database)
    _create_database(admin, source_database)
    try:
        _install_synthetic_production_shape(source)
        tool_adapter = PostgresCommandAdapter(
            source,
            disposable_root=tmp_path,
            pg_dump_path=pg_dump,
            pg_restore_path=pg_restore,
        )
        lifecycle = []
        coordinator = ExportedSnapshotCoordinator(
            connect=lambda: psycopg.connect(source.conninfo()),
            baseline_collector=PostgresBaselineCollector(),
            dump_adapter=tool_adapter,
            lifecycle=lifecycle.append,
        )

        def mutate_after_export() -> None:
            with psycopg.connect(source.conninfo()) as connection:
                connection.execute("INSERT INTO assets VALUES (%s)", (uuid4(),))
                connection.commit()

        dump_path = tmp_path / "payload" / "pdi-core.dump"
        dump_path.parent.mkdir(mode=0o700)
        export_result = coordinator.export(
            operation_id=str(uuid4()),
            output_path=dump_path,
            source_runtime=_source_runtime(),
            on_snapshot_exported=mutate_after_export,
            on_dump_completed=lambda: None,
        )
        baseline_assets = next(
            item.value for item in export_result.baseline.table_counts if item.name == "assets"
        )
        assert baseline_assets == 1
        with psycopg.connect(source.conninfo()) as connection:
            assert connection.execute("SELECT count(*) FROM assets").fetchone()[0] == 2
        assert lifecycle.index("EVIDENCE_HASHED") < lifecycle.index("EXPORTER_ROLLBACK")

        (dump_path.parent / "baseline.json").write_bytes(
            canonical_json_bytes(export_result.baseline.to_mapping()) + b"\n"
        )
        (dump_path.parent / "exported-snapshot-evidence.json").write_bytes(
            canonical_json_bytes(export_result.evidence.to_mapping()) + b"\n"
        )

        password_file = tmp_path / "restic-password"
        password_file.write_text("synthetic-disposable-password", encoding="utf-8")
        password_file.chmod(0o600)
        backup = ResticBackupAdapter(
            tmp_path / "restic-repository",
            password_file,
            disposable_root=tmp_path,
            backup_fs_uuid=str(UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")),
            restic_path=restic,
        )
        backup.initialize_disposable()
        snapshot = backup.create_snapshot(dump_path.parent)
        restored_root = backup.restore_snapshot(snapshot.snapshot_id, tmp_path / "restic-restore")
        recovered = tuple(restored_root.rglob("pdi-core.dump"))
        assert len(recovered) == 1
        assert recovered[0].read_bytes() == dump_path.read_bytes()
        assert len(tuple(restored_root.rglob("baseline.json"))) == 1
        assert len(tuple(restored_root.rglob("exported-snapshot-evidence.json"))) == 1

        restore_adapter = Postgres16RestoreQualificationAdapter(
            admin_target=admin,
            dump_adapter=tool_adapter,
            baseline_collector=PostgresBaselineCollector(),
        )
        with psycopg.connect(admin.conninfo(database="postgres")) as connection:
            disposable_before = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM pg_database WHERE datname LIKE 'pdi_p3d_restore_%_test'), "
                "(SELECT count(*) FROM pg_roles WHERE rolname LIKE "
                "'pdi_p3d_restore_owner_%_test')"
            ).fetchone()
        qualified = restore_adapter.qualify(
            recovered_dump=recovered[0],
            baseline=export_result.baseline,
            source_runtime=_source_runtime(),
        )
        with psycopg.connect(admin.conninfo(database="postgres")) as connection:
            disposable_after = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM pg_database WHERE datname LIKE 'pdi_p3d_restore_%_test'), "
                "(SELECT count(*) FROM pg_roles WHERE rolname LIKE "
                "'pdi_p3d_restore_owner_%_test')"
            ).fetchone()
        assert qualified.restored_invariants.counts_match is True
        assert qualified.restored_invariants.invariants_match is True
        assert disposable_after == disposable_before
        assert baseline_counts_fingerprint(export_result.baseline)

        candidate_sha = "a" * 40
        source_sha = "b" * 40
        export_tool_source_sha = "c" * 40
        restore_tool_source_sha = "d" * 40
        export_tool = _operator_tool(ToolName.BACKUP_EXPORT, export_tool_source_sha)
        restore_tool = _operator_tool(ToolName.RESTORE_QUALIFY, restore_tool_source_sha)
        orchestrated_backup = ResticBackupAdapter(
            tmp_path / "orchestrated-restic-repository",
            password_file,
            disposable_root=tmp_path,
            backup_fs_uuid=str(UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")),
            restic_path=restic,
        )
        orchestrated_backup.initialize_disposable()

        def coordinator_factory(_lifecycle):
            return ExportedSnapshotCoordinator(
                connect=lambda: psycopg.connect(source.conninfo()),
                baseline_collector=PostgresBaselineCollector(),
                dump_adapter=tool_adapter,
            )

        orchestrator = RollbackQualificationOrchestrator(
            disposable_root=tmp_path,
            source_qualifier=_QualifiedSyntheticSource(),
            snapshot_coordinator_factory=coordinator_factory,
            backup_adapter=orchestrated_backup,
            restore_adapter=restore_adapter,
            export_tool=export_tool,
            restore_tool=restore_tool,
            persistence_policy=AtomicCreatePolicyV1(
                owner_uid=os.getuid(), owner_gid=os.getgid(), mode=0o600,
                trust_root=tmp_path,
            ),
        )
        orchestrated = orchestrator.run(QualificationContext(
            candidate_sha,
            source_sha,
            "7" * 64,
            "8" * 64,
            str(UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")),
            "2026-09-25T00:00:00Z",
        ))
        assert orchestrated.final_state.phase == "COMPLETE"
        assert orchestrated.metadata.export_tool == export_tool
        assert orchestrated.metadata.restore_tool == restore_tool
        assert {
            candidate_sha,
            orchestrated.metadata.export_tool.tool_source_sha,
            orchestrated.metadata.restore_tool.tool_source_sha,
        } == {candidate_sha, export_tool_source_sha, restore_tool_source_sha}
        with psycopg.connect(admin.conninfo(database="postgres")) as connection:
            assert connection.execute(
                "SELECT "
                "(SELECT count(*) FROM pg_database WHERE datname LIKE "
                "'pdi_p3d_restore_%_test'), "
                "(SELECT count(*) FROM pg_roles WHERE rolname LIKE "
                "'pdi_p3d_restore_owner_%_test')"
            ).fetchone() == disposable_before
    finally:
        _drop_database(admin, source_database)
