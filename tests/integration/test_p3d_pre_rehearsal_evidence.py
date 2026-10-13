from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from pdi.database import create_postgres_engine
from pdi.production_ops.contracts import QUALIFICATION
from pdi.production_ops.cutover import Host as FrozenP3CHost, Paths as FrozenP3CPaths
from pdi.production_ops.p3d_inert_asset_install import (
    InertAssetPolicy,
    SyntheticSystemdStateProvider,
    SystemdSnapshot,
)
from pdi.production_ops.p3d_pre_rehearsal_evidence import (
    PreparationEvidenceInputs,
    PreRehearsalEvidenceCollector,
    PreRehearsalEvidenceError,
    verify_candidate_evidence_runtime,
)
from pdi.production_ops.p3d_preparation_contracts import (
    OperatorToolIdentity,
    ToolName,
    contract_fingerprint,
)
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapInputs,
    BootstrapPolicy,
    QualificationHostRuntimeAuthorityProvider,
    ReleaseBootstrap,
    resolve_runtime_identity,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scope_sync_state import PostgreSQLScopeSyncStateRepository
from tests.integration.database_guard import require_safe_test_database_url
from tests.integration.test_p3d_inert_asset_install import (
    _clean,
    _create_complete_gate_a,
    _write,
)


ROOT = Path(__file__).resolve().parents[2]
H1 = "1" * 64


def _environment() -> tuple[Path, Path, Path, Path, str]:
    names = (
        "PDI_P3D_WP6_BUNDLE",
        "PDI_P3D_WP6_DIGESTS",
        "PDI_P3D_WP6_QUALIFICATION_ROOT",
        "PDI_P3D_WP6_SYSTEM_PYTHON",
        "PDI_P3D_WP6_CANDIDATE_SHA",
    )
    if any(not os.environ.get(name) for name in names):
        pytest.skip("dedicated WP6 cross-gate qualification only")
    return (
        Path(os.environ[names[0]]),
        Path(os.environ[names[1]]),
        Path(os.environ[names[2]]),
        Path(os.environ[names[3]]),
        os.environ[names[4]],
    )


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
            provider_type=provider, instance_key=f"wp6-{provider}", enabled=enabled,
        )
        account = None
        if enabled:
            account = identities.create_account(
                provider_instance_id=instance.id,
                account_key=f"wp6-{provider}",
                provider_native_id=f"synthetic-{provider}",
                enabled=True,
            )
        scopes[provider] = identities.create_scope(
            provider_instance_id=instance.id,
            provider_account_id=(None if account is None else account.id),
            scope_key=f"wp6-{provider}",
            enabled=enabled,
        )
    with engine.begin() as connection:
        for provider, scope in scopes.items():
            asset_id = uuid4()
            connection.execute(text(
                "INSERT INTO assets(id,resource_type,title,created_at,updated_at) "
                "VALUES (:id,'file','Synthetic',now(),now())"
            ), {"id": asset_id})
            blob_id = uuid4()
            connection.execute(text(
                "INSERT INTO blobs(id,asset_id,hash,size,mime_type) "
                "VALUES (:id,:asset,:hash,1,'text/plain')"
            ), {"id": blob_id, "asset": asset_id, "hash": uuid4().hex})
            connection.execute(text(
                "INSERT INTO asset_sources(id,blob_id,provider,external_id,observation_scope_id,metadata,is_active) "
                "VALUES (:id,:blob,:provider,:external,:scope,'{}'::jsonb,true)"
            ), {
                "id": uuid4(), "blob": blob_id, "provider": provider,
                "external": f"synthetic-{provider}", "scope": scope.id,
            })
    sync = PostgreSQLScopeSyncStateRepository(engine)
    for provider, mechanism in (
        ("nextcloud", "activity_v2_hint_v1"),
        ("immich", "metadata_updated_at_v1"),
    ):
        row = sync.get_or_create(scopes[provider].id, mechanism)
        assert sync.compare_and_swap_checkpoint(
            scopes[provider].id, mechanism,
            expected_version=row.version,
            checkpoint=f"synthetic-{provider}",
        ) is not None
    return engine, scopes


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.skipif(os.geteuid() != 0, reason="WP6 qualification requires disposable root")
def test_real_a_b_c_live_read_only_pre_rehearsal_contract() -> None:
    bundle, digest_path, root, system_python, candidate = _environment()
    assert root != Path("/") and str(root).startswith("/tmp/pdi-p3d-wp6-disposable.")
    assert bundle.is_file() and digest_path.is_file() and system_python.is_file()
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(mode=0o755)
    os.chown(root, 0, 0)
    os.chmod(root, 0o755)
    digests = json.loads(digest_path.read_text(encoding="utf-8"))
    assert digests["CANDIDATE_SHA"] == candidate
    url = require_safe_test_database_url()
    engine, scopes = _seed_database(url)
    runtime_uid, runtime_gid = resolve_runtime_identity("nobody", "nogroup")
    releases_root = root / "opt/pdi/releases"
    preparation_root = root / "var/lib/pdi-p3d/preparation"
    bootstrap_lock = root / "run/lock/pdi/p3d-release-bootstrap.lock"
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
        bootstrap_tool, releases_root, preparation_root, bootstrap_lock, current,
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
            inputs=bootstrap_inputs,
            policy=bootstrap_policy,
            host_runtime_provider=runtime_provider,
        ).run()
        assert bootstrap.final_state.phase == "COMPLETE"
        release = releases_root / candidate

        source = "b" * 40
        gate_a_operation = str(uuid4())
        metadata, _ = _create_complete_gate_a(
            preparation_root,
            operation_id=gate_a_operation,
            candidate=candidate,
            source=source,
        )
        current.symlink_to(f"/opt/pdi/releases/{source}")

        p3c_state_root = root / "var/lib/pdi-p3c"
        frozen_host = FrozenP3CHost(
            FrozenP3CPaths(
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
            ),
            root / "p3c-unused/release", source,
            "synthetic-host", H1, source,
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
        registry_payload = (
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
        _write(registry, registry_payload, 0o640, 0, runtime_gid)
        profiles = root / "etc/pdi/scoped/units"
        profiles.mkdir(mode=0o700)
        os.chown(profiles, 0, 0)
        units = root / "etc/systemd/system"
        units.mkdir(parents=True, mode=0o755)
        os.chown(units, 0, 0)
        os.chmod(units, 0o755)
        for path in (root / "etc", root / "etc/pdi", root / "etc/pdi/scoped"):
            os.chown(path, 0, 0)
            os.chmod(path, 0o755)

        candidate_python = release / ".venv/bin/python"
        gate_c_script = release / "scripts/pdi_p3d_inert_asset_install.py"
        command_line = (
            str(candidate_python), str(gate_c_script),
            "--mode", "QUALIFICATION",
            "--expected-candidate-sha", candidate,
            "--gate-a-operation-id", gate_a_operation,
            "--gate-b-operation-id", bootstrap.operation_id,
            "--expected-systemd-asset-fingerprint", digests["SYSTEMD_ASSET_FINGERPRINT"],
            "--qualification-root", str(root),
            "--qualification-runtime-user", "nobody",
            "--qualification-runtime-group", "nogroup",
        )
        completed = subprocess.run(
            command_line,
            cwd=release,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
        )
        assert completed.returncode == 0, completed.stdout
        gate_c = json.loads(completed.stdout)
        assert gate_c["PHASE"] == "COMPLETE"

        p3c_fingerprint = contract_fingerprint({
            "qualification": "p3c-healthy", "candidate": candidate,
        })
        systemd = SyntheticSystemdStateProvider(SystemdSnapshot(
            p3c_fingerprint,
            contract_fingerprint({"qualification": "p3d-disabled-inactive"}),
            True,
        ))
        policy = InertAssetPolicy.qualification(
            root, owner_uid=0, owner_gid=0,
            runtime_uid=runtime_uid, runtime_gid=runtime_gid,
        )
        inputs = PreparationEvidenceInputs(
            candidate,
            gate_a_operation,
            bootstrap.operation_id,
            gate_c["OPERATION_ID"],
            source,
        )
        installed_module = next((release / ".venv").glob(
            "lib/python*/site-packages/pdi/production_ops/p3d_pre_rehearsal_evidence.py"
        ))

        def runtime_verifier(actual_policy, actual_candidate):
            return verify_candidate_evidence_runtime(
                actual_policy,
                actual_candidate,
                executable=candidate_python,
                module_file=installed_module,
                script_file=release / "scripts/mu13_p3d_cutover.py",
            )

        before_files = {
            logical: _hash(policy.physical(logical))
            for logical in gate_c_manifest_paths(gate_c, root)
        }
        protected_before = {
            "current": os.readlink(current),
            "p3c": _hash(p3c_state),
            "registry": _hash(registry),
            "environment": _hash(environment),
        }
        with engine.connect() as connection:
            db_before = tuple(connection.execute(text(
                "SELECT (SELECT count(*) FROM pipeline_runs), "
                "(SELECT count(*) FROM asset_sources), "
                "(SELECT count(*) FROM observation_scope_sync_state)"
            )).one())

        def collect(*, actual_systemd=systemd):
            return PreRehearsalEvidenceCollector(
                policy=policy,
                inputs=inputs,
                systemd=actual_systemd,
                runtime_verifier=runtime_verifier,
            ).collect()

        result = collect()
        sanitized = result.to_sanitized_mapping()
        assert sanitized["P3D_COLLECT_EVIDENCE"] == "PASS"
        assert sanitized["PRE_REHEARSAL_PREPARATION_CONTRACT"] == "PASS"
        assert sanitized["RUNTIME_PIPELINE_COVERAGE"] == "0/6"
        assert sanitized["CANONICAL_PIPELINE_COUNT"] == "6"
        assert sanitized["ENABLED_SCOPE_COUNT"] == "2"
        print(f"WP6_CONTEXT_FINGERPRINT={result.context_fingerprint}")
        print(f"WP6_MARKER_FINGERPRINT={result.marker_fingerprint}")
        print(f"WP6_ASSET_FINGERPRINT={result.asset_fingerprint}")

        # Each drift is introduced by the disposable test harness, rejected by
        # WP6, then restored before the next assertion.
        profile = policy.physical("/etc/pdi/scoped/units/enrichment.nextcloud_text.env")
        profile_bytes = profile.read_bytes()
        profile.write_bytes(profile_bytes + b"# drift\n")
        profile.chmod(0o600)
        with pytest.raises(PreRehearsalEvidenceError):
            collect()
        profile.write_bytes(profile_bytes)
        profile.chmod(0o600)

        registry_bytes = registry.read_bytes()
        registry.write_bytes(registry_bytes + b"\n")
        registry.chmod(0o640)
        with pytest.raises(PreRehearsalEvidenceError):
            collect()
        registry.write_bytes(registry_bytes)
        registry.chmod(0o640)

        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE observation_scopes SET enabled=false WHERE id=:id"
            ), {"id": scopes["nextcloud"].id})
        with pytest.raises(PreRehearsalEvidenceError):
            collect()
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE observation_scopes SET enabled=true WHERE id=:id"
            ), {"id": scopes["nextcloud"].id})

        current.unlink()
        current.symlink_to("/opt/pdi/releases/" + "c" * 40)
        with pytest.raises(PreRehearsalEvidenceError):
            collect()
        current.unlink()
        current.symlink_to(f"/opt/pdi/releases/{source}")

        p3c_bytes = p3c_state.read_bytes()
        p3c_value = json.loads(p3c_bytes)
        p3c_value["phase"] = "ABORTING"
        p3c_state.write_text(json.dumps(p3c_value), encoding="utf-8")
        p3c_state.chmod(0o600)
        with pytest.raises(PreRehearsalEvidenceError):
            collect()
        p3c_state.write_bytes(p3c_bytes)
        p3c_state.chmod(0o600)

        with pytest.raises(PreRehearsalEvidenceError):
            collect(actual_systemd=SyntheticSystemdStateProvider(SystemdSnapshot(
                "9" * 64, "8" * 64, True,
            )))

        assert os.readlink(current) == protected_before["current"]
        assert _hash(p3c_state) == protected_before["p3c"]
        assert _hash(registry) == protected_before["registry"]
        assert _hash(environment) == protected_before["environment"]
        assert {
            logical: _hash(policy.physical(logical))
            for logical in gate_c_manifest_paths(gate_c, root)
        } == before_files
        with engine.connect() as connection:
            db_after = tuple(connection.execute(text(
                "SELECT (SELECT count(*) FROM pipeline_runs), "
                "(SELECT count(*) FROM asset_sources), "
                "(SELECT count(*) FROM observation_scope_sync_state)"
            )).one())
        assert db_after == db_before
        assert db_after[0] == 0
    finally:
        _clean(engine)
        engine.dispose()


def gate_c_manifest_paths(_gate_c_result: dict[str, object], _root: Path) -> tuple[str, ...]:
    from pdi.production_ops.p3d_preparation_contracts import CANONICAL_P3D_INSTALL_PATHS

    return tuple(sorted(CANONICAL_P3D_INSTALL_PATHS))
