from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import os
import shutil
import stat
import subprocess
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from pdi.database import create_postgres_engine
from pdi.production_ops import p3d_inert_asset_install as module
from pdi.production_ops.contracts import QUALIFICATION
from pdi.production_ops.cutover import Host as FrozenP3CHost, Paths as FrozenP3CPaths
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    GateAPhase,
    OperatorToolIdentity,
    P3DRollbackMetadataV1,
    ReleasePinState,
    RollbackReleasePinV1,
    ToolName,
    atomic_create_no_replace,
    canonical_json_bytes,
    rollback_metadata_fingerprint,
)
from pdi.production_ops.p3d_release_bundle import (
    CANONICAL_SYSTEMD_ASSETS,
    SystemdAssetV1,
    systemd_asset_fingerprint,
)
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapInputs,
    BootstrapPolicy,
    QualificationHostRuntimeAuthorityProvider,
    ReleaseBootstrap,
    resolve_runtime_identity,
)
from pdi.production_ops.p3d_rollback_qualification import (
    GateAJournalStore,
    serialize_metadata,
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


def _metadata(
    *, candidate: str = CANDIDATE, source: str = SOURCE,
) -> P3DRollbackMetadataV1:
    mapping = {
        **P3DRollbackMetadataV1.FIXED,
        "SNAPSHOT_ID": H1,
        "SNAPSHOT_TAGS": ["final-quiesced", "p3d-pre-enrichment"],
        "DUMP_SHA256": H2,
        "BASELINE_COUNTS_SHA256": H3,
        "EXPORTED_SNAPSHOT_EVIDENCE_HASH": H4,
        "SOURCE_SHA": source,
        "SOURCE_RELEASE_SHA": source,
        "SOURCE_RELEASE_FINGERPRINT": H1,
        "SOURCE_RUNTIME_FINGERPRINT": H2,
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": H3,
        "TARGET_CANDIDATE_SHA": candidate,
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
            H2, f"/opt/pdi/releases/{SOURCE}", H5, H6, snapshot.p3c_fingerprint,
        )

    def verify_p3c_state_unchanged(self, evidence):
        assert evidence.p3c_state_sha256 == H6


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


def _create_complete_gate_a(
    preparation_root: Path, *, operation_id: str, candidate: str, source: str,
) -> tuple[P3DRollbackMetadataV1, Path]:
    """Write a synthetic but frozen-contract-valid Gate A authority."""
    operation_root = preparation_root / f"operation-{operation_id}"
    operation_root.mkdir(mode=0o700)
    authority = operation_root / "authority"
    policy = AtomicCreatePolicyV1(0, 0, 0o600, preparation_root)
    store = GateAJournalStore(authority, policy=policy)
    export_tool = _tool(ToolName.BACKUP_EXPORT, "c" * 40)
    restore_tool = _tool(ToolName.RESTORE_QUALIFY, "d" * 40)
    state = store.initialize(
        operation_id=operation_id,
        candidate_sha=candidate,
        started_at=WHEN,
        export_tool=export_tool,
        restore_tool=restore_tool,
    )
    events = ()
    metadata = _metadata(candidate=candidate, source=source)
    metadata_hash = rollback_metadata_fingerprint(metadata)
    pin = _pin(metadata)
    atomic_create_no_replace(
        authority / f"rollback-release-pin-{metadata.snapshot_id}.json",
        canonical_json_bytes(pin.to_mapping()) + b"\n",
        policy=policy,
    )
    atomic_create_no_replace(
        authority / "p3d-pre-enrichment.env",
        serialize_metadata(metadata),
        policy=policy,
    )
    export_phases = {
        GateAPhase.SOURCE_VERIFIED,
        GateAPhase.SNAPSHOT_EXPORTED,
        GateAPhase.DUMP_COMPLETED,
        GateAPhase.BACKUP_SNAPSHOT_CREATED,
    }
    for phase in GateAPhase:
        if phase in {GateAPhase.NEW, GateAPhase.FAILED}:
            continue
        state, events = store.advance(
            state,
            events,
            phase.value,
            timestamp=WHEN,
            tool=export_tool if phase in export_phases else restore_tool,
            evidence_fingerprints=(metadata_hash if phase is GateAPhase.COMPLETE else H1,),
        )
    assert state.phase == GateAPhase.COMPLETE.value
    return metadata, authority


def _cross_gate_environment() -> tuple[Path, Path, Path, Path, str]:
    names = (
        "PDI_P3D_GATE_C_BUNDLE",
        "PDI_P3D_GATE_C_DIGESTS",
        "PDI_P3D_GATE_C_QUALIFICATION_ROOT",
        "PDI_P3D_GATE_C_SYSTEM_PYTHON",
        "PDI_P3D_GATE_C_CANDIDATE_SHA",
    )
    if any(not os.environ.get(name) for name in names):
        pytest.skip("dedicated cross-gate Gate C qualification only")
    return (
        Path(os.environ[names[0]]),
        Path(os.environ[names[1]]),
        Path(os.environ[names[2]]),
        Path(os.environ[names[3]]),
        os.environ[names[4]],
    )


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


@pytest.mark.skipif(os.geteuid() != 0, reason="cross-gate qualification requires disposable root")
def test_exact_candidate_cli_consumes_real_gate_a_and_gate_b_authorities() -> None:
    """WP3 bundle -> real Gate B -> frozen Gate A layout -> staged Gate C CLI."""
    if shutil.which("systemd-analyze") is None:
        pytest.skip("systemd-analyze unavailable")
    bundle, digest_path, root, system_python, candidate = _cross_gate_environment()
    assert root != Path("/") and str(root).startswith("/tmp/pdi-p3d-gate-c-")
    assert bundle.is_file() and digest_path.is_file() and system_python.is_file()
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(mode=0o755)
    os.chown(root, 0, 0)
    os.chmod(root, 0o755)
    digests = json.loads(digest_path.read_text(encoding="utf-8"))
    assert digests["CANDIDATE_SHA"] == candidate
    assert len(candidate) == 40
    url = require_safe_test_database_url()
    engine, scopes = _seed_database(url)
    runtime_uid, runtime_gid = resolve_runtime_identity("nobody", "nogroup")
    releases_root = root / "opt/pdi/releases"
    preparation_root = root / "var/lib/pdi-p3d/preparation"
    lock_path = root / "run/lock/pdi/p3d-release-bootstrap.lock"
    current = root / "opt/pdi/current"
    for parent in (
        root / "opt", root / "opt/pdi", root / "var", root / "var/lib",
        root / "var/lib/pdi-p3d", root / "run", root / "run/lock",
    ):
        parent.mkdir(mode=0o755, exist_ok=True)
        os.chown(parent, 0, 0)
        os.chmod(parent, 0o755)
    bootstrap_source = Path(__import__(
        "pdi.production_ops.p3d_release_bootstrap", fromlist=["__file__"]
    ).__file__)
    bootstrap_tool = OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.RELEASE_BOOTSTRAP.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": hashlib.sha256(bootstrap_source.read_bytes()).hexdigest(),
        "TOOL_SOURCE_SHA": candidate,
    })
    bootstrap_inputs = BootstrapInputs(
        bundle.absolute(), candidate, digests["BUNDLE_SHA256"],
        digests["OS_RUNTIME_MANIFEST_SHA256"], "QUALIFICATION_ONLY",
        bootstrap_tool, releases_root, preparation_root, lock_path, current,
        "nobody", "nogroup",
    )
    bootstrap_policy = BootstrapPolicy.qualification(
        disposable_root=root, owner_uid=0, owner_gid=0,
        runtime_uid=runtime_uid, runtime_gid=runtime_gid,
    )
    runtime_provider = QualificationHostRuntimeAuthorityProvider(
        system_python, digests["OS_RUNTIME_MANIFEST_SHA256"],
    )
    try:
        bootstrap = ReleaseBootstrap(
            inputs=bootstrap_inputs, policy=bootstrap_policy,
            host_runtime_provider=runtime_provider,
        ).run()
        assert bootstrap.final_state.phase == "COMPLETE"
        assert bootstrap.release_fingerprint
        release = releases_root / candidate
        assert release == bootstrap.final_path
        assert not current.exists() and not current.is_symlink()

        source = "b" * 40
        gate_a_operation = str(uuid4())
        metadata, gate_a_authority = _create_complete_gate_a(
            preparation_root, operation_id=gate_a_operation,
            candidate=candidate, source=source,
        )
        assert gate_a_authority == (
            preparation_root / f"operation-{gate_a_operation}" / "authority"
        )
        assert not (preparation_root / gate_a_operation / "authority").exists()

        current.symlink_to(f"/opt/pdi/releases/{source}")
        current_before = os.readlink(current)
        p3c_state_root = root / "var/lib/pdi-p3c"
        frozen_paths = FrozenP3CPaths(
            staging=root / "p3c-unused/staging",
            env=root / "p3c-unused/pdi.env",
            recovery=root / "p3c-unused/recovery",
            config=root / "p3c-unused/config",
            units=root / "p3c-unused/units",
            current=root / "p3c-unused/current",
            releases=root / "p3c-unused/releases",
            state=p3c_state_root,
            control=root / "p3c-unused/control.lock",
            sync=root / "p3c-unused/sync.lock",
        )
        frozen_host = FrozenP3CHost(
            frozen_paths, root / "p3c-unused/release", source,
            "synthetic-host", H1, SOURCE,
        )
        frozen_host.save({
            "phase": "PASS",
            "sha": source,
            "old_target": "/opt/pdi/releases/" + "c" * 40,
            "context": metadata.p3c_context_fingerprint,
            "baseline": {"synthetic": "private-baseline-evidence"},
            "qualified": list(QUALIFICATION),
            "verified": {"synthetic": "private-verified-evidence"},
        })
        p3c_state = p3c_state_root / "state.json"
        assert p3c_state.is_file()
        p3c_state_info = p3c_state.lstat()
        assert p3c_state_info.st_uid == 0 and p3c_state_info.st_gid == 0
        assert stat.S_IMODE(p3c_state_info.st_mode) == 0o600
        assert not (p3c_state_root / "journal.jsonl").exists()

        environment = root / "etc/pdi/pdi.env"
        _write(
            environment,
            f'DATABASE__URL="{url}"\n'
            'NEXTCLOUD__URL="https://nextcloud.invalid"\n'
            'NEXTCLOUD__USER="synthetic"\n'
            'NEXTCLOUD__PASSWORD="synthetic-nextcloud-secret"\n'
            'IMMICH__URL="https://immich.invalid"\n'
            'IMMICH__API_KEY="synthetic-immich-secret"\n',
            0o600, 0, 0,
        )
        principal = "33333333-3333-4333-8333-333333333333"
        registry = root / "etc/pdi/scoped/registry.toml"
        _write(
            registry,
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
            'secret_env = "IMMICH__API_KEY"\n',
            0o640, 0, runtime_gid,
        )
        unit_profiles = root / "etc/pdi/scoped/units"
        unit_profiles.mkdir(mode=0o700)
        os.chown(unit_profiles, 0, 0)
        systemd_units = root / "etc/systemd/system"
        systemd_units.mkdir(parents=True, mode=0o755)
        os.chown(systemd_units, 0, 0)
        os.chmod(systemd_units, 0o755)
        for path in (root / "etc", root / "etc/pdi", root / "etc/pdi/scoped"):
            os.chown(path, 0, 0)
            os.chmod(path, 0o755)
        p3c_before = hashlib.sha256(p3c_state.read_bytes()).hexdigest()
        registry_before = hashlib.sha256(registry.read_bytes()).hexdigest()
        environment_before = hashlib.sha256(environment.read_bytes()).hexdigest()
        with engine.connect() as connection:
            db_before = tuple(connection.execute(text(
                "SELECT "
                "(SELECT count(*) FROM pipeline_runs), "
                "(SELECT count(*) FROM asset_sources), "
                "(SELECT count(*) FROM observation_scope_sync_state)"
            )).one())

        candidate_python = release / ".venv/bin/python"
        candidate_script = release / "scripts/pdi_p3d_inert_asset_install.py"
        assert candidate_python.is_file() and candidate_script.is_file()
        command_line = (
            str(candidate_python), str(candidate_script),
            "--mode", "QUALIFICATION",
            "--expected-candidate-sha", candidate,
            "--gate-a-operation-id", gate_a_operation,
            "--gate-b-operation-id", bootstrap.operation_id,
            "--expected-systemd-asset-fingerprint", digests["SYSTEMD_ASSET_FINGERPRINT"],
            "--qualification-root", str(root),
            "--qualification-runtime-user", "nobody",
            "--qualification-runtime-group", "nogroup",
        )
        process_environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        assert "PYTHONPATH" not in process_environment
        completed = subprocess.run(
            command_line, cwd=release, env=process_environment,
            capture_output=True, text=True, timeout=300, shell=False,
        )
        assert completed.returncode == 0, completed.stdout
        assert completed.stderr == ""
        assert "synthetic-nextcloud-secret" not in completed.stdout
        assert "synthetic-immich-secret" not in completed.stdout
        result = json.loads(completed.stdout)
        assert result["P3D_INERT_ASSET_INSTALL"] == "PASS"
        assert result["CANDIDATE_SHA"] == candidate
        assert result["PHASE"] == "COMPLETE"
        assert result["INSTALLED_FILE_COUNT"] == 13
        assert result["SYSTEMD_MUTATION"] == "NO"
        assert result["WORKLOAD_STARTED"] == "NO"
        assert os.readlink(current) == current_before
        assert hashlib.sha256(p3c_state.read_bytes()).hexdigest() == p3c_before
        assert not (p3c_state_root / "journal.jsonl").exists()
        assert hashlib.sha256(registry.read_bytes()).hexdigest() == registry_before
        assert hashlib.sha256(environment.read_bytes()).hexdigest() == environment_before
        assert not list(root.rglob("*.wants"))
        assert len([
            path for path in module.CANONICAL_P3D_INSTALL_PATHS
            if (root / path.removeprefix("/")).is_file()
        ]) == 13
        gate_c_root = preparation_root / "inert-assets" / result["OPERATION_ID"]
        assert (gate_c_root / "complete.json").is_file()
        gate_c_authority = b"".join(
            path.read_bytes() for path in gate_c_root.rglob("*") if path.is_file()
        )
        assert p3c_before.encode() in gate_c_authority
        assert b"private-baseline-evidence" not in gate_c_authority
        assert b"private-verified-evidence" not in gate_c_authority
        assert ("/opt/pdi/releases/" + "c" * 40).encode() not in gate_c_authority
        with engine.connect() as connection:
            db_after = tuple(connection.execute(text(
                "SELECT "
                "(SELECT count(*) FROM pipeline_runs), "
                "(SELECT count(*) FROM asset_sources), "
                "(SELECT count(*) FROM observation_scope_sync_state)"
            )).one())
        assert db_after == db_before
        assert db_after[0] == 0
    finally:
        _clean(engine)
        engine.dispose()
