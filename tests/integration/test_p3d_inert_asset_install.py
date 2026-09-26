from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from pdi.database import create_postgres_engine
from pdi.production_ops import p3d_inert_asset_install as module
from pdi.production_ops.p3d_preparation_contracts import (
    OperatorToolIdentity,
    P3DRollbackMetadataV1,
    ReleasePinState,
    RollbackReleasePinV1,
    ToolName,
    rollback_metadata_fingerprint,
)
from pdi.production_ops.p3d_release_bundle import (
    CANONICAL_SYSTEMD_ASSETS,
    SystemdAssetV1,
    systemd_asset_fingerprint,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scope_sync_state import PostgreSQLScopeSyncStateRepository
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = "a" * 40
SOURCE = "b" * 40
H1, H2, H3, H4, H5, H6 = (str(index) * 64 for index in range(1, 7))
WHEN = "2026-09-26T01:02:03Z"


def _tool(name: ToolName, source: str) -> OperatorToolIdentity:
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": name.value,
        "TOOL_VERSION": "0.1.0",
        "TOOL_ARTIFACT_SHA256": H1,
        "TOOL_SOURCE_SHA": source,
    })


def _metadata() -> P3DRollbackMetadataV1:
    mapping = {
        **P3DRollbackMetadataV1.FIXED,
        "SNAPSHOT_ID": H1,
        "SNAPSHOT_TAGS": ["final-quiesced", "p3d-pre-enrichment"],
        "DUMP_SHA256": H2,
        "BASELINE_COUNTS_SHA256": H3,
        "EXPORTED_SNAPSHOT_EVIDENCE_HASH": H4,
        "SOURCE_SHA": SOURCE,
        "SOURCE_RELEASE_SHA": SOURCE,
        "SOURCE_RELEASE_FINGERPRINT": H1,
        "SOURCE_RUNTIME_FINGERPRINT": H2,
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": H3,
        "TARGET_CANDIDATE_SHA": CANDIDATE,
        "SOURCE_DB_FINGERPRINT": H4,
        "P3C_CONTEXT_FINGERPRINT": H5,
        "P3C_SOAK_EVIDENCE_SHA256": H6,
        "RESTORED_INVARIANTS_SHA256": H1,
        "BACKUP_FS_UUID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "RESTIC_REPOSITORY": "/synthetic/repository",
        "QUALIFIED_AT_UTC": WHEN,
    }
    for prefix, identity in (
        ("EXPORT", _tool(ToolName.BACKUP_EXPORT, "c" * 40)),
        ("RESTORE", _tool(ToolName.RESTORE_QUALIFY, "d" * 40)),
    ):
        mapping.update({f"{prefix}_{key}": value for key, value in identity.to_mapping().items()})
    return P3DRollbackMetadataV1.from_mapping(mapping)


def _pin(metadata: P3DRollbackMetadataV1) -> RollbackReleasePinV1:
    return RollbackReleasePinV1(
        metadata.snapshot_id, metadata.source_release_sha,
        metadata.source_release_fingerprint, metadata.source_runtime_fingerprint,
        metadata.source_system_runtime_fingerprint,
        rollback_metadata_fingerprint(metadata), metadata.qualified_at_utc,
        ReleasePinState.ACTIVE,
    )


@dataclass
class FakePrerequisiteReader:
    policy: module.InertAssetPolicy
    inputs: module.InertAssetInputs
    systemd: object

    def collect(self, *, home: Path):
        metadata = _metadata()
        snapshot = self.systemd.snapshot()
        return module.PrerequisiteEvidence(
            metadata, rollback_metadata_fingerprint(metadata), _pin(metadata),
            H2, f"/opt/pdi/releases/{SOURCE}", H5, snapshot.p3c_fingerprint,
        )


def _clean(engine) -> None:
    with engine.begin() as connection:
        for table in (
            "pipeline_runs", "observation_scope_resource_person_relations",
            "resource_person_relations", "observation_scope_person_sources",
            "person_sources", "asset_sources", "blobs", "assets",
            "observation_scope_sync_state", "provider_sync_state",
            "observation_scopes", "provider_accounts", "provider_instances",
        ):
            connection.execute(text(f"DELETE FROM {table}"))


def _seed_database(url: str):
    engine = create_postgres_engine(url)
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    _clean(engine)
    identities = PostgreSQLProviderIdentityRepository(engine)
    scopes = {}
    for provider, enabled in (
        ("nextcloud", True), ("immich", True),
        ("gmail", False), ("integration-test", False),
    ):
        instance = identities.create_instance(
            provider_type=provider, instance_key=f"gate-c-{provider}", enabled=enabled,
        )
        account = None
        if enabled:
            account = identities.create_account(
                provider_instance_id=instance.id, account_key=f"gate-c-{provider}",
                provider_native_id=f"synthetic-{provider}", enabled=True,
            )
        scope = identities.create_scope(
            provider_instance_id=instance.id, provider_account_id=(None if account is None else account.id),
            scope_key=f"gate-c-{provider}", enabled=enabled,
        )
        scopes[provider] = scope
    with engine.begin() as connection:
        for provider, scope in scopes.items():
            asset, blob, source = uuid4(), uuid4(), uuid4()
            connection.execute(text(
                "INSERT INTO assets(id,resource_type,title,created_at,updated_at) "
                "VALUES (:id,'file','Synthetic',now(),now())"
            ), {"id": asset})
            connection.execute(text(
                "INSERT INTO blobs(id,asset_id,hash,size,mime_type) "
                "VALUES (:id,:asset,:hash,1,'text/plain')"
            ), {"id": blob, "asset": asset, "hash": uuid4().hex})
            connection.execute(text(
                "INSERT INTO asset_sources(id,blob_id,provider,external_id,observation_scope_id,metadata,is_active) "
                "VALUES (:id,:blob,:provider,:external,:scope,'{}'::jsonb,true)"
            ), {
                "id": source, "blob": blob, "provider": provider,
                "external": f"synthetic-{provider}", "scope": scope.id,
            })
    scoped = PostgreSQLScopeSyncStateRepository(engine)
    for provider, mechanism in (
        ("nextcloud", "activity_v2_hint_v1"),
        ("immich", "metadata_updated_at_v1"),
    ):
        initial = scoped.get_or_create(scopes[provider].id, mechanism)
        assert scoped.compare_and_swap_checkpoint(
            scopes[provider].id, mechanism, expected_version=initial.version,
            checkpoint=f"synthetic-{provider}",
        ) is not None
    return engine, scopes


def _write(path: Path, payload: str | bytes, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_bytes(payload)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


@pytest.mark.skipif(os.geteuid() != 0, reason="Gate C qualification requires disposable root ownership")
def test_real_postgres_profiles_systemd_analyze_and_no_replace_complete(tmp_path: Path) -> None:
    if shutil.which("systemd-analyze") is None:
        pytest.skip("systemd-analyze unavailable")
    url = require_safe_test_database_url()
    engine, scopes = _seed_database(url)
    root = tmp_path / "gate-c-root"
    root.mkdir(mode=0o700)
    os.chown(root, 0, 0)
    policy = module.InertAssetPolicy.qualification(
        root, owner_uid=0, owner_gid=0, runtime_uid=65534, runtime_gid=65534,
    )
    try:
        for logical, mode in (
            ("/etc/pdi/pdi.env", 0o600),
            ("/etc/pdi/scoped/registry.toml", 0o640),
        ):
            policy.physical(logical).parent.mkdir(parents=True, exist_ok=True)
        env = (
            f'DATABASE__URL="{url}"\n'
            'NEXTCLOUD__URL="https://nextcloud.invalid"\n'
            'NEXTCLOUD__USER="synthetic"\n'
            'NEXTCLOUD__PASSWORD="synthetic-nextcloud-secret"\n'
            'IMMICH__URL="https://immich.invalid"\n'
            'IMMICH__API_KEY="synthetic-immich-secret"\n'
        )
        _write(policy.environment, env, 0o600, 0, 0)
        principal = "33333333-3333-4333-8333-333333333333"
        registry = (
            '[[principals]]\n'
            f'id = "{principal}"\n'
            'database_ref = "primary-personal-db"\n'
            'enabled = true\n\n'
            '[[databases]]\nref = "primary-personal-db"\nurl_env = "DATABASE__URL"\n\n'
            '[[provider_bindings]]\n'
            f'principal_id = "{principal}"\n'
            f'scope_id = "{scopes["nextcloud"].id}"\n'
            'provider_type = "nextcloud"\nendpoint = "https://nextcloud.invalid"\n'
            'secret_env = "NEXTCLOUD__PASSWORD"\nusername = "synthetic"\n\n'
            '[[provider_bindings]]\n'
            f'principal_id = "{principal}"\n'
            f'scope_id = "{scopes["immich"].id}"\n'
            'provider_type = "immich"\nendpoint = "https://immich.invalid"\n'
            'secret_env = "IMMICH__API_KEY"\n'
        )
        _write(policy.registry, registry, 0o640, 0, 65534)
        release_systemd = policy.candidate_releases_root / CANDIDATE / "deployment/systemd"
        release_systemd.mkdir(parents=True)
        assets = []
        for name in CANONICAL_SYSTEMD_ASSETS:
            payload = (ROOT / "deployment/systemd" / name).read_bytes()
            path = release_systemd / name
            _write(path, payload, 0o644, 0, 0)
            assets.append(SystemdAssetV1(
                f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
                module._sha256(payload), "0644",
            ))
        policy.current.parent.mkdir(parents=True, exist_ok=True)
        policy.current.symlink_to(f"/opt/pdi/releases/{SOURCE}")
        (policy.preparation_root).mkdir(parents=True, mode=0o700)
        (policy.lock_path.parent).mkdir(parents=True, mode=0o700)
        for path in (root, *root.rglob("*")):
            if path.is_dir():
                os.chown(path, 0, 0)
                os.chmod(path, 0o700 if path.name in {"units", "preparation", "pdi"} else 0o755)
        # Restore exact protected directory modes after the general setup pass.
        policy.preparation_root.chmod(0o700)
        policy.lock_path.parent.chmod(0o700)
        (policy.registry.parent / "units").mkdir(mode=0o700)
        unit_dir = policy.physical("/etc/systemd/system")
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_dir.chmod(0o755)

        systemd = module.SyntheticSystemdStateProvider(
            module.SystemdSnapshot(H3, H4, True)
        )
        gate_inputs = module.InertAssetInputs(
            CANDIDATE, str(uuid4()), str(uuid4()), systemd_asset_fingerprint(assets),
            _tool(ToolName.INERT_ASSET_INSTALL, CANDIDATE),
        )
        result = module.InertAssetInstaller(
            inputs=gate_inputs, policy=policy, systemd=systemd,
            prerequisite_reader_factory=FakePrerequisiteReader,
        ).run()
        assert result.final_state.phase == "COMPLETE"
        assert len(result.marker.installed_file_manifest) == 13
        assert result.marker.db_identity_fingerprint
        assert result.marker.enabled_scope_fingerprint
        assert result.marker.p3d_timer_state == "DISABLED_INACTIVE"
        assert systemd.calls == 2
        assert policy.current.readlink() == Path(f"/opt/pdi/releases/{SOURCE}")
        assert not list(root.rglob("*.wants"))
        assert "synthetic-nextcloud-secret" not in (result.final_state.to_mapping().__repr__())
        assert "synthetic-immich-secret" not in (result.final_state.to_mapping().__repr__())
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM pipeline_runs")) == 0
            assert connection.scalar(text("SELECT count(*) FROM observation_scope_sync_state")) == 2
    finally:
        _clean(engine)
        engine.dispose()
