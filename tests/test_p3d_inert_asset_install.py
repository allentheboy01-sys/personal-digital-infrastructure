from __future__ import annotations

from pathlib import Path
import inspect
import os
from types import SimpleNamespace
from uuid import UUID

import pytest

from pdi.production_ops import p3d_inert_asset_install as module
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    CANONICAL_P3D_INSTALL_PATHS,
    CANONICAL_P3D_PIPELINE_KEYS,
    FailureCode,
    GateCPhase,
    OperatorToolIdentity,
    P3DRollbackMetadataV1,
    PreparationGate,
    ReleasePinState,
    RollbackReleasePinV1,
    ToolName,
    rollback_metadata_fingerprint,
)
from pdi.production_ops.p3d_evidence import PersonalDatabaseEvidence
from pdi.production_ops.p3d_release_bundle import (
    CANONICAL_SYSTEMD_ASSETS,
    SystemdAssetV1,
    systemd_asset_fingerprint,
)
from pdi.production_ops.p3d_release_bootstrap import GateBJournalStore
from pdi.scoped_enrichment_profiles import profile_keys
from pdi.scoped_operator_config import load_scoped_operator_configuration


CANDIDATE = "a" * 40
SOURCE = "b" * 40
H1 = "1" * 64
OPERATION = "11111111-2222-4333-8444-555555555555"
NC_SCOPE = UUID("11111111-1111-4111-8111-111111111111")
IM_SCOPE = UUID("22222222-2222-4222-8222-222222222222")
PRINCIPAL = "33333333-3333-4333-8333-333333333333"
WHEN = "2026-09-26T01:02:03Z"


def tool(source: str = CANDIDATE, name: ToolName = ToolName.INERT_ASSET_INSTALL):
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": name.value,
        "TOOL_VERSION": "0.1.0",
        "TOOL_ARTIFACT_SHA256": H1,
        "TOOL_SOURCE_SHA": source,
    })


def inputs(source: str = CANDIDATE):
    return module.InertAssetInputs(CANDIDATE, OPERATION, OPERATION, H1, tool(source))


def prepare_root(tmp_path: Path) -> module.InertAssetPolicy:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    return module.InertAssetPolicy.qualification(
        root, owner_uid=root.stat().st_uid, owner_gid=root.stat().st_gid,
        runtime_uid=65534, runtime_gid=(os.getegid() or 65534),
    )


def make_parents(policy: module.InertAssetPolicy) -> None:
    for logical in CANONICAL_P3D_INSTALL_PATHS:
        parent = policy.physical(logical).parent
        parent.mkdir(parents=True, exist_ok=True)
    for path in (policy.root, *policy.root.rglob("*")):
        if path.is_dir():
            path.chmod(0o700 if path.name == "units" else 0o755)


def asset_content() -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    source = Path("deployment/systemd")
    for name in CANONICAL_SYSTEMD_ASSETS:
        result[f"/etc/systemd/system/{name}"] = (source / name).read_bytes()
    for key in CANONICAL_P3D_PIPELINE_KEYS:
        values = {
            "PDI_PRINCIPAL_REF": PRINCIPAL,
            "PDI_SCOPED_PIPELINE_KEY": key,
            "DATABASE__URL": "postgresql://synthetic.invalid/pdi",
        }
        if key.startswith("enrichment.nextcloud_"):
            values["NEXTCLOUD__PASSWORD"] = "synthetic-nextcloud"
        if key == "enrichment.immich_ocr":
            values["IMMICH__API_KEY"] = "synthetic-immich"
        result[f"/etc/pdi/scoped/units/{key}.env"] = (
            module.render_environment_file(values).encode()
        )
    return result


def rendered() -> module.RenderedAssets:
    content = asset_content()
    manifest = module._manifest_from_content(content)
    assets = tuple(
        SystemdAssetV1(
            f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
            module._sha256(content[f"/etc/systemd/system/{name}"]), "0644",
        ) for name in CANONICAL_SYSTEMD_ASSETS
    )
    return module.RenderedAssets(
        content, manifest, module.asset_installation_fingerprint(manifest),
        systemd_asset_fingerprint(assets),
    )


def offline_state(policy: module.InertAssetPolicy):
    policy.gate_c_root.mkdir(parents=True, mode=0o700)
    store = module.GateCJournalStore(
        policy.gate_c_root / OPERATION,
        policy=AtomicCreatePolicyV1(
            policy.owner_uid, policy.owner_gid, 0o600, policy.gate_c_root,
        ),
    )
    state = store.initialize(operation_id=OPERATION, candidate_sha=CANDIDATE, tool=tool())
    events = ()
    for phase in (
        GateCPhase.PREREQUISITES_VERIFIED, GateCPhase.REGISTRY_VERIFIED,
        GateCPhase.DB_EVIDENCE_VERIFIED, GateCPhase.PROFILES_RENDERED,
        GateCPhase.OFFLINE_STATIC_VERIFIED,
    ):
        state, events = store.advance(state, events, phase, tool=tool(), evidence=(H1,))
    return store, state, events


def installer(policy: module.InertAssetPolicy, *, crash=None):
    snapshot = module.SystemdSnapshot(H1, "2" * 64, True)
    return module.InertAssetInstaller(
        inputs=inputs(), policy=policy,
        systemd=module.SyntheticSystemdStateProvider(snapshot),
        crash_after_new_files=crash,
    )


def test_gate_c_tool_authority_is_candidate_bound() -> None:
    inputs().validate()
    with pytest.raises(module.InertAssetInstallError) as error:
        inputs(SOURCE).validate()
    assert error.value.code is FailureCode.ASSET_PREREQUISITE_INVALID
    with pytest.raises(module.InertAssetInstallError):
        module.InertAssetInputs(
            CANDIDATE, OPERATION, OPERATION, H1,
            tool(CANDIDATE, ToolName.RELEASE_BOOTSTRAP),
        ).validate()


def test_canonical_rendered_set_and_secret_minimization() -> None:
    content = asset_content()
    assert set(content) == set(CANONICAL_P3D_INSTALL_PATHS)
    assert len(content) == 13
    module._validate_static_contract(content)
    for key in CANONICAL_P3D_PIPELINE_KEYS:
        text = content[f"/etc/pdi/scoped/units/{key}.env"].decode()
        names = {line.partition("=")[0] for line in text.splitlines()}
        assert names == set(profile_keys(key))
        if key in {"enrichment.file_metadata", "enrichment.immich_geo",
                   "enrichment.immich_metadata"}:
            assert "NEXTCLOUD__PASSWORD" not in names
            assert "IMMICH__API_KEY" not in names


def test_multiscope_profiles_include_only_enabled_exact_binding_refs(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    source = policy.candidate_releases_root / CANDIDATE / "deployment/systemd"
    source.mkdir(parents=True)
    systemd_assets = []
    for name in CANONICAL_SYSTEMD_ASSETS:
        payload = (Path("deployment/systemd") / name).read_bytes()
        (source / name).write_bytes(payload)
        systemd_assets.append(SystemdAssetV1(
            f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
            module._sha256(payload), "0644",
        ))
    nc_second = UUID("44444444-4444-4444-8444-444444444444")
    disabled = UUID("55555555-5555-4555-8555-555555555555")
    registry = tmp_path / "registry.toml"
    registry.write_text(
        f'[[principals]]\nid="{PRINCIPAL}"\ndatabase_ref="primary-personal-db"\n'
        '[[databases]]\nref="primary-personal-db"\nurl_env="DATABASE__URL"\n'
        f'[[provider_bindings]]\nprincipal_id="{PRINCIPAL}"\nscope_id="{NC_SCOPE}"\n'
        'provider_type="nextcloud"\nendpoint="https://a.invalid"\nsecret_env="NC_A"\nusername="a"\n'
        f'[[provider_bindings]]\nprincipal_id="{PRINCIPAL}"\nscope_id="{nc_second}"\n'
        'provider_type="nextcloud"\nendpoint="https://b.invalid"\nsecret_env="NC_B"\nusername="b"\n'
        f'[[provider_bindings]]\nprincipal_id="{PRINCIPAL}"\nscope_id="{disabled}"\n'
        'provider_type="nextcloud"\nendpoint="https://disabled.invalid"\nsecret_env="NC_DISABLED"\nusername="d"\n'
        f'[[provider_bindings]]\nprincipal_id="{PRINCIPAL}"\nscope_id="{IM_SCOPE}"\n'
        'provider_type="immich"\nendpoint="https://immich.invalid"\nsecret_env="IM_A"\n'
    )
    environment = {
        "DATABASE__URL": "postgresql://synthetic.invalid/pdi",
        "NC_A": "a-secret", "NC_B": "b-secret", "NC_DISABLED": "disabled-secret",
        "IM_A": "im-secret",
    }
    configuration = load_scoped_operator_configuration(registry, environment=environment)
    gate_inputs = module.InertAssetInputs(
        CANDIDATE, OPERATION, OPERATION, systemd_asset_fingerprint(systemd_assets), tool(),
    )
    renderer = module.InertAssetInstaller(
        inputs=gate_inputs, policy=policy,
        systemd=module.SyntheticSystemdStateProvider(
            module.SystemdSnapshot(H1, "2" * 64, True)
        ),
    )
    evidence = PersonalDatabaseEvidence(
        PRINCIPAL, "primary-personal-db", environment["DATABASE__URL"],
        frozenset(map(str, (NC_SCOPE, nc_second, IM_SCOPE))), "7" * 64, True,
    )
    assets = renderer._render_assets(configuration, PRINCIPAL, evidence)
    nextcloud = assets.content[
        "/etc/pdi/scoped/units/enrichment.nextcloud_text.env"
    ].decode()
    local = assets.content[
        "/etc/pdi/scoped/units/enrichment.immich_metadata.env"
    ].decode()
    ocr = assets.content["/etc/pdi/scoped/units/enrichment.immich_ocr.env"].decode()
    assert 'NC_A="a-secret"' in nextcloud and 'NC_B="b-secret"' in nextcloud
    assert "NC_DISABLED" not in nextcloud and "IM_A" not in nextcloud
    assert "NC_A" not in local and "NC_B" not in local and "IM_A" not in local
    assert 'IM_A="im-secret"' in ocr and "NC_A" not in ocr
    missing = PersonalDatabaseEvidence(
        PRINCIPAL, "primary-personal-db", environment["DATABASE__URL"],
        frozenset((*evidence.enabled_scope_ids, "66666666-6666-4666-8666-666666666666")),
        "7" * 64, True,
    )
    with pytest.raises(module.InertAssetInstallError) as error:
        renderer._render_assets(configuration, PRINCIPAL, missing)
    assert error.value.code is FailureCode.ASSET_PROFILE_INVALID


@pytest.mark.parametrize("missing", tuple(sorted(CANONICAL_P3D_INSTALL_PATHS)))
def test_manifest_rejects_missing_assets(missing: str) -> None:
    content = asset_content()
    del content[missing]
    with pytest.raises(module.InertAssetInstallError) as error:
        module._manifest_from_content(content)
    assert error.value.code is FailureCode.ASSET_FILE_CONFLICT


def test_manifest_rejects_extra_owned_asset() -> None:
    content = asset_content()
    content["/etc/systemd/system/pdi-scoped-enrichment-extra.timer"] = b"[Timer]\n"
    with pytest.raises(module.InertAssetInstallError) as error:
        module._manifest_from_content(content)
    assert error.value.code is FailureCode.ASSET_FILE_CONFLICT


def test_wrong_timer_binding_and_service_contract_fail_closed() -> None:
    content = asset_content()
    timer = "/etc/systemd/system/pdi-scoped-enrichment-nextcloud-text.timer"
    content[timer] = content[timer].replace(b"enrichment.nextcloud_text", b"enrichment.file_metadata")
    with pytest.raises(module.InertAssetInstallError):
        module._validate_static_contract(content)


@pytest.mark.parametrize("required", (
    b"EnvironmentFile=/etc/pdi/scoped/units/%i.env",
    b"WorkingDirectory=/opt/pdi/current",
    b"User=pdi",
    b"Group=pdi",
    b"NoNewPrivileges=true",
    b"ExecStart=/opt/pdi/current/.venv/bin/python -m pdi.production_ops.enrichment ",
))
def test_each_required_service_boundary_is_fail_closed(required: bytes) -> None:
    content = asset_content()
    service = "/etc/systemd/system/pdi-scoped-pipeline@.service"
    assert required in content[service]
    content[service] = content[service].replace(required, b"REMOVED", 1)
    with pytest.raises(module.InertAssetInstallError) as error:
        module._validate_static_contract(content)
    assert error.value.code is FailureCode.ASSET_STATIC_VERIFY_FAILED


def test_all_missing_create_exact_13_and_partial_transitions(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    store, state, events = offline_state(policy)
    next_state, next_events, manifest, disposition = installer(policy)._install(
        rendered(), store, state, events,
    )
    assert disposition == "CONVERGED"
    assert next_state.phase == GateCPhase.FILES_INSTALLED.value
    assert len(manifest) == 13
    assert any(event.to_state == GateCPhase.FILES_PARTIALLY_INSTALLED.value
               for event in next_events)


def test_all_exact_existing_is_direct_idempotent(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    data = rendered()
    for logical, payload in data.content.items():
        path = policy.physical(logical)
        path.write_bytes(payload)
        path.chmod(int(module.CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8))
    store, state, events = offline_state(policy)
    next_state, next_events, manifest, disposition = installer(policy)._install(
        data, store, state, events,
    )
    assert disposition == "IDEMPOTENT"
    assert len(next_events) == len(events) + 1
    assert next_state.phase == GateCPhase.FILES_INSTALLED.value
    assert len(manifest) == 13


@pytest.mark.parametrize("kind", ("bytes", "mode", "symlink"))
def test_foreign_target_never_replaced(tmp_path: Path, kind: str) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    data = rendered()
    logical = "/etc/systemd/system/pdi-scoped-pipeline@.service"
    path = policy.physical(logical)
    if kind == "symlink":
        path.symlink_to("/tmp/foreign")
    else:
        path.write_bytes(b"foreign" if kind == "bytes" else data.content[logical])
        path.chmod(0o600 if kind == "mode" else int(
            module.CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8
        ))
    store, state, events = offline_state(policy)
    with pytest.raises(module.InertAssetInstallError) as error:
        installer(policy)._install(data, store, state, events)
    assert error.value.code is FailureCode.ASSET_FILE_CONFLICT
    if kind == "bytes":
        assert path.read_bytes() == b"foreign"


@pytest.mark.parametrize("count", (1, 6, 12))
def test_crash_leaves_retryable_partial_and_files(count: int, tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    store, state, events = offline_state(policy)
    with pytest.raises(module.SimulatedGateCCrash):
        installer(policy, crash=count)._install(rendered(), store, state, events)
    persisted, _ = store.load_partial()
    assert persisted.phase == GateCPhase.FILES_PARTIALLY_INSTALLED.value
    assert sum(policy.physical(path).exists() for path in CANONICAL_P3D_INSTALL_PATHS) == count


def test_partial_same_candidate_converges_without_removing_existing_files(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    data = rendered()
    store, state, events = offline_state(policy)
    with pytest.raises(module.SimulatedGateCCrash):
        installer(policy, crash=6)._install(data, store, state, events)
    before = {
        path: policy.physical(path).read_bytes()
        for path in data.content if policy.physical(path).exists()
    }
    state, events = store.load_partial()
    final, _, manifest, disposition = installer(policy)._install(data, store, state, events)
    assert final.phase == GateCPhase.FILES_INSTALLED.value
    assert disposition == "CONVERGED"
    assert len(manifest) == 13
    assert all(policy.physical(path).read_bytes() == payload for path, payload in before.items())


@pytest.mark.parametrize("existing_count", (1, 6, 12))
def test_exact_prefix_plus_missing_files_converges(
    tmp_path: Path, existing_count: int,
) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    data = rendered()
    ordered = sorted(data.content)
    for logical in ordered[:existing_count]:
        path = policy.physical(logical)
        path.write_bytes(data.content[logical])
        path.chmod(int(module.CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8))
    store, state, events = offline_state(policy)
    final, _, manifest, disposition = installer(policy)._install(
        data, store, state, events,
    )
    assert final.phase == GateCPhase.FILES_INSTALLED.value
    assert disposition == "CONVERGED"
    assert len(manifest) == 13
    assert all(
        policy.physical(logical).read_bytes() == data.content[logical]
        for logical in ordered
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="owner-conflict assertion needs disposable root")
def test_foreign_owner_never_replaced(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    data = rendered()
    logical = "/etc/systemd/system/pdi-scoped-pipeline@.service"
    path = policy.physical(logical)
    path.write_bytes(data.content[logical])
    path.chmod(0o644)
    os.chown(path, 65534, policy.owner_gid)
    store, state, events = offline_state(policy)
    with pytest.raises(module.InertAssetInstallError) as error:
        installer(policy)._install(data, store, state, events)
    assert error.value.code is FailureCode.ASSET_FILE_CONFLICT
    assert path.read_bytes() == data.content[logical]


def test_other_candidate_cannot_resume_partial_operation(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    store, state, events = offline_state(policy)
    with pytest.raises(module.SimulatedGateCCrash):
        installer(policy, crash=1)._install(rendered(), store, state, events)
    before, before_events = store.load_partial()
    foreign = module.InertAssetInstaller(
        inputs=module.InertAssetInputs(
            SOURCE, OPERATION, OPERATION, H1, tool(SOURCE),
        ),
        policy=policy,
        systemd=module.SyntheticSystemdStateProvider(
            module.SystemdSnapshot(H1, "2" * 64, True)
        ),
    )
    with pytest.raises(module.InertAssetInstallError) as error:
        foreign._run_locked(operation_id=OPERATION, resume=True)
    assert error.value.code is FailureCode.ASSET_FILE_CONFLICT
    after, after_events = store.load_partial()
    assert after == before
    assert after_events == before_events


def test_production_systemd_provider_only_uses_read_commands() -> None:
    calls = []

    def runner(argv, **kwargs):
        calls.append(tuple(argv))
        action = argv[1]
        unit = argv[2]
        if action == "show":
            return SimpleNamespace(returncode=0, stdout="LoadState=loaded\n")
        if unit in module.P3C_TIMERS:
            return SimpleNamespace(returncode=0, stdout="enabled\n" if action == "is-enabled" else "active\n")
        if unit == module.P3C_SERVICE:
            return SimpleNamespace(returncode=1, stdout="static\n" if action == "is-enabled" else "inactive\n")
        return SimpleNamespace(returncode=1, stdout="disabled\n" if action == "is-enabled" else "inactive\n")

    snapshot = module.ProductionReadOnlySystemdStateProvider(runner).snapshot()
    assert snapshot.p3d_quiet
    assert {call[1] for call in calls} <= {"show", "is-enabled", "is-active"}
    assert all(call[0] == "/usr/bin/systemctl" for call in calls)
    before = len(calls)
    with pytest.raises(module.InertAssetInstallError):
        module.ProductionReadOnlySystemdStateProvider(runner)._read("start", "anything")
    assert len(calls) == before


def test_systemd_analyze_is_absolute_shell_false_and_failure_is_closed(tmp_path: Path) -> None:
    calls = []

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    verifier = module.SystemdStaticVerifier(runner)
    verifier.verify(
        root=tmp_path / "static", content=asset_content(), candidate_sha=CANDIDATE,
        owner_uid=os.geteuid(), owner_gid=os.getegid(),
        runtime_uid=65534, runtime_gid=65534,
    )
    assert calls[0][0][0] == "/usr/bin/systemd-analyze"
    assert calls[0][1]["shell"] is False
    assert "daemon-reload" not in calls[0][0]

    def failing_runner(argv, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="fixed synthetic failure")

    with pytest.raises(module.InertAssetInstallError) as error:
        module.SystemdStaticVerifier(failing_runner).verify(
            root=tmp_path / "static-fail", content=asset_content(),
            candidate_sha=CANDIDATE, owner_uid=os.geteuid(), owner_gid=os.getegid(),
            runtime_uid=65534, runtime_gid=65534,
        )
    assert error.value.code is FailureCode.ASSET_STATIC_VERIFY_FAILED


@pytest.mark.parametrize("kind", ("symlink", "mode", "parent"))
def test_protected_registry_reader_fails_closed(tmp_path: Path, kind: str) -> None:
    policy = prepare_root(tmp_path)
    parent = policy.registry.parent
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    target = tmp_path / "registry-target.toml"
    if kind == "symlink":
        target.write_text("synthetic", encoding="utf-8")
        policy.registry.symlink_to(target)
    else:
        policy.registry.write_text("synthetic", encoding="utf-8")
        policy.registry.chmod(0o600 if kind == "mode" else 0o640)
        if kind == "parent":
            parent.chmod(0o775)
    with pytest.raises(module.InertAssetInstallError) as error:
        module._secure_read_policy(
            policy.registry, policy=policy, mode=0o640, gid=policy.owner_gid,
        )
    assert error.value.code is FailureCode.ASSET_REGISTRY_INVALID


def test_production_module_has_no_systemd_mutation_or_workload_primitive() -> None:
    source = inspect.getsource(module.ProductionReadOnlySystemdStateProvider)
    assert 'action not in {"is-enabled", "is-active", "show"}' in source
    installer_source = inspect.getsource(module.InertAssetInstaller)
    for forbidden in (
        "daemon-reload", "systemctl start", "systemctl stop", "systemctl restart",
        "systemctl enable", "systemctl disable", "PipelineRun", "requests.", "httpx.",
    ):
        assert forbidden not in installer_source


def test_gate_c_journal_rejects_resume_from_non_partial(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    policy.gate_c_root.mkdir(parents=True)
    policy.gate_c_root.chmod(0o700)
    store = module.GateCJournalStore(
        policy.gate_c_root / OPERATION,
        policy=AtomicCreatePolicyV1(
            policy.owner_uid, policy.owner_gid, 0o600, policy.gate_c_root,
        ),
    )
    state = store.initialize(operation_id=OPERATION, candidate_sha=CANDIDATE, tool=tool())
    assert state.gate is PreparationGate.INERT_ASSET_INSTALL
    with pytest.raises(module.InertAssetInstallError):
        store.load_partial()


def test_gate_b_complete_reader_validates_every_persisted_prefix(tmp_path: Path) -> None:
    root = tmp_path / "gate-b"
    policy = AtomicCreatePolicyV1(os.geteuid(), os.getegid(), 0o600, tmp_path)
    store = GateBJournalStore(root, policy=policy)
    bootstrap_tool = tool("c" * 40, ToolName.RELEASE_BOOTSTRAP)
    state = store.initialize(
        operation_id=OPERATION, candidate_sha=CANDIDATE,
        started_at="2026-09-26T01:02:03Z", tool=bootstrap_tool,
    )
    events = ()
    for phase in module.GateBPhase:
        if phase.value in {"NEW", "FAILED"}:
            continue
        state, events = store.advance(
            state, events, phase, tool=bootstrap_tool, evidence_fingerprints=(H1,),
        )
    loaded, loaded_events = module._load_complete_gate(
        root, gate=PreparationGate.RELEASE_STAGING, candidate=CANDIDATE,
        owner_uid=os.geteuid(), owner_gid=os.getegid(),
    )
    assert loaded.phase == "COMPLETE"
    assert loaded_events == events
    intermediate = root / "state-000003.json"
    mapping = module.json.loads(intermediate.read_text())
    mapping["phase"] = "ARTIFACT_VERIFIED"
    intermediate.write_text(module.json.dumps(mapping))
    with pytest.raises(module.InertAssetInstallError):
        module._load_complete_gate(
            root, gate=PreparationGate.RELEASE_STAGING, candidate=CANDIDATE,
            owner_uid=os.geteuid(), owner_gid=os.getegid(),
        )


def rollback_metadata() -> P3DRollbackMetadataV1:
    mapping = {
        **P3DRollbackMetadataV1.FIXED,
        "SNAPSHOT_ID": H1, "SNAPSHOT_TAGS": ["final-quiesced"],
        "DUMP_SHA256": "2" * 64, "BASELINE_COUNTS_SHA256": "3" * 64,
        "EXPORTED_SNAPSHOT_EVIDENCE_HASH": "4" * 64,
        "SOURCE_SHA": SOURCE, "SOURCE_RELEASE_SHA": SOURCE,
        "SOURCE_RELEASE_FINGERPRINT": H1, "SOURCE_RUNTIME_FINGERPRINT": "2" * 64,
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": "3" * 64,
        "TARGET_CANDIDATE_SHA": CANDIDATE, "SOURCE_DB_FINGERPRINT": "4" * 64,
        "P3C_CONTEXT_FINGERPRINT": "5" * 64, "P3C_SOAK_EVIDENCE_SHA256": "6" * 64,
        "RESTORED_INVARIANTS_SHA256": H1,
        "BACKUP_FS_UUID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "RESTIC_REPOSITORY": "/synthetic/repository", "QUALIFIED_AT_UTC": WHEN,
    }
    for prefix, identity in (
        ("EXPORT", tool("c" * 40, ToolName.BACKUP_EXPORT)),
        ("RESTORE", tool("d" * 40, ToolName.RESTORE_QUALIFY)),
    ):
        mapping.update({f"{prefix}_{key}": value for key, value in identity.to_mapping().items()})
    return P3DRollbackMetadataV1.from_mapping(mapping)


class FakePrerequisites:
    def __init__(self, policy, gate_inputs, systemd):
        self.policy = policy
        self.systemd = systemd

    def collect(self, *, home):
        metadata = rollback_metadata()
        metadata_hash = rollback_metadata_fingerprint(metadata)
        pin = RollbackReleasePinV1(
            metadata.snapshot_id, SOURCE, metadata.source_release_fingerprint,
            metadata.source_runtime_fingerprint, metadata.source_system_runtime_fingerprint,
            metadata_hash, metadata.qualified_at_utc, ReleasePinState.ACTIVE,
        )
        snapshot = self.systemd.snapshot()
        return module.PrerequisiteEvidence(
            metadata, metadata_hash, pin, H1, f"/opt/pdi/releases/{SOURCE}",
            metadata.p3c_context_fingerprint, snapshot.p3c_fingerprint,
        )


class FakeStaticVerifier:
    def __init__(self):
        self.calls = 0

    def verify(self, **kwargs):
        self.calls += 1
        module._validate_static_contract(kwargs["content"])
        return H1


class FakeEngine:
    url = "postgresql+psycopg://synthetic.invalid/pdi"

    def dispose(self):
        pass


class FakeDatabaseReader:
    def __init__(self, router, engine, *, principal_ref):
        self.principal_ref = principal_ref

    def collect(self):
        return PersonalDatabaseEvidence(
            self.principal_ref, "primary-personal-db", FakeEngine.url,
            frozenset((str(NC_SCOPE), str(IM_SCOPE))), "7" * 64, True,
        )


def test_full_qualification_orchestration_completes_without_workload(tmp_path: Path) -> None:
    policy = prepare_root(tmp_path)
    make_parents(policy)
    policy.current.parent.mkdir(parents=True, exist_ok=True)
    policy.current.symlink_to(f"/opt/pdi/releases/{SOURCE}")
    env = (
        f'DATABASE__URL="{FakeEngine.url}"\n'
        'NEXTCLOUD__URL="https://nextcloud.invalid"\nNEXTCLOUD__USER="synthetic"\n'
        'NEXTCLOUD__PASSWORD="synthetic-nc"\nIMMICH__URL="https://immich.invalid"\n'
        'IMMICH__API_KEY="synthetic-im"\n'
    )
    policy.environment.parent.mkdir(parents=True, exist_ok=True)
    policy.environment.write_text(env)
    policy.environment.chmod(0o600)
    registry = (
        f'[[principals]]\nid="{PRINCIPAL}"\ndatabase_ref="primary-personal-db"\nenabled=true\n'
        '[[databases]]\nref="primary-personal-db"\nurl_env="DATABASE__URL"\n'
        f'[[provider_bindings]]\nprincipal_id="{PRINCIPAL}"\nscope_id="{NC_SCOPE}"\n'
        'provider_type="nextcloud"\nendpoint="https://nextcloud.invalid"\n'
        'secret_env="NEXTCLOUD__PASSWORD"\nusername="synthetic"\n'
        f'[[provider_bindings]]\nprincipal_id="{PRINCIPAL}"\nscope_id="{IM_SCOPE}"\n'
        'provider_type="immich"\nendpoint="https://immich.invalid"\n'
        'secret_env="IMMICH__API_KEY"\n'
    )
    policy.registry.parent.mkdir(parents=True, exist_ok=True)
    policy.registry.write_text(registry)
    os.chown(policy.registry, policy.owner_uid, policy.runtime_gid)
    policy.registry.chmod(0o640)
    source = policy.candidate_releases_root / CANDIDATE / "deployment/systemd"
    source.mkdir(parents=True)
    systemd_assets = []
    for name in CANONICAL_SYSTEMD_ASSETS:
        payload = (Path("deployment/systemd") / name).read_bytes()
        path = source / name
        path.write_bytes(payload)
        path.chmod(0o644)
        systemd_assets.append(SystemdAssetV1(
            f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
            module._sha256(payload), "0644",
        ))
    for path in (policy.root, *policy.root.rglob("*")):
        if path.is_dir():
            path.chmod(0o700 if path.name in {"units", "preparation", "pdi"} else 0o755)
    policy.registry.parent.chmod(0o755)
    static = FakeStaticVerifier()
    systemd = module.SyntheticSystemdStateProvider(
        module.SystemdSnapshot(H1, "8" * 64, True)
    )
    gate_inputs = module.InertAssetInputs(
        CANDIDATE, OPERATION, OPERATION,
        systemd_asset_fingerprint(systemd_assets), tool(),
    )
    result = module.InertAssetInstaller(
        inputs=gate_inputs, policy=policy, systemd=systemd,
        prerequisite_reader_factory=FakePrerequisites,
        static_verifier=static,
        db_evidence_reader_factory=FakeDatabaseReader,
        engine_factory=lambda _url: FakeEngine(),
    ).run()
    assert result.final_state.phase == "COMPLETE"
    assert len(result.marker.installed_file_manifest) == 13
    assert static.calls == 2
    assert systemd.calls == 2
    assert policy.current.readlink() == Path(f"/opt/pdi/releases/{SOURCE}")
    authority_bytes = b"".join(
        path.read_bytes() for path in (policy.gate_c_root / result.operation_id).rglob("*")
        if path.is_file()
    )
    assert b"synthetic-nc" not in authority_bytes
    assert b"synthetic-im" not in authority_bytes
    assert not list((policy.gate_c_root / result.operation_id).glob("static-*"))
