from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pdi.production_ops import p3d_pre_rehearsal_evidence as module
from pdi.production_ops.p3d_evidence import PersonalDatabaseEvidence
from pdi.production_ops.p3d_inert_asset_install import (
    GateCJournalStore,
    InertAssetPolicy,
    SyntheticSystemdStateProvider,
    SystemdSnapshot,
)
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    CANONICAL_P3D_INSTALL_PATH_MODES,
    GateCPhase,
    InstalledFileEntryV1,
    OperatorToolIdentity,
    P3DAssetInstallationCompleteV1,
    P3DRollbackMetadataV1,
    PreparationGate,
    ToolName,
    asset_installation_fingerprint,
    canonical_json_bytes,
    contract_fingerprint,
    rollback_metadata_fingerprint,
)
from tests.test_p3d_preparation_contracts import rollback_mapping


CANDIDATE = "a" * 40
SOURCE = "b" * 40
H1, H2, H3, H4, H5 = (str(index) * 64 for index in range(1, 6))
GATE_A = "11111111-1111-4111-8111-111111111111"
GATE_B = "22222222-2222-4222-8222-222222222222"
GATE_C = "33333333-3333-4333-8333-333333333333"
PRINCIPAL = "44444444-4444-4444-8444-444444444444"
SCOPES = (
    "55555555-5555-4555-8555-555555555555",
    "66666666-6666-4666-8666-666666666666",
)


def _tool() -> OperatorToolIdentity:
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.INERT_ASSET_INSTALL.value,
        "TOOL_VERSION": "0.1.0",
        "TOOL_ARTIFACT_SHA256": H1,
        "TOOL_SOURCE_SHA": CANDIDATE,
    })


def _metadata() -> P3DRollbackMetadataV1:
    mapping = rollback_mapping()
    mapping["TARGET_CANDIDATE_SHA"] = CANDIDATE
    mapping["SOURCE_SHA"] = SOURCE
    mapping["SOURCE_RELEASE_SHA"] = SOURCE
    return P3DRollbackMetadataV1.from_mapping(mapping)


def _files() -> tuple[InstalledFileEntryV1, ...]:
    return tuple(
        InstalledFileEntryV1.from_mapping({
            "path": path,
            "sha256": hashlib.sha256(path.encode()).hexdigest(),
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": mode,
        })
        for path, mode in sorted(CANONICAL_P3D_INSTALL_PATH_MODES.items())
    )


def _marker(metadata: P3DRollbackMetadataV1 | None = None) -> P3DAssetInstallationCompleteV1:
    metadata = _metadata() if metadata is None else metadata
    files = _files()
    scope_hash = contract_fingerprint({
        "principal_ref": PRINCIPAL,
        "enabled_scope_ids": sorted(SCOPES),
    })
    return P3DAssetInstallationCompleteV1.from_mapping({
        "marker_version": 1,
        "candidate_sha": CANDIDATE,
        "rollback_snapshot_id": metadata.snapshot_id,
        "rollback_metadata_sha256": rollback_metadata_fingerprint(metadata),
        "rollback_source_sha": metadata.source_release_sha,
        "registry_fingerprint": H3,
        "db_identity_fingerprint": H4,
        "enabled_scope_fingerprint": scope_hash,
        "unit_profile_asset_fingerprint": asset_installation_fingerprint(files),
        "installed_file_manifest": [entry.to_mapping() for entry in files],
        "current_symlink_before": f"/opt/pdi/releases/{SOURCE}",
        "current_symlink_after": f"/opt/pdi/releases/{SOURCE}",
        "p3c_systemd_state_before_fingerprint": H5,
        "p3c_systemd_state_after_fingerprint": H5,
        "p3d_timer_state": "DISABLED_INACTIVE",
        "preparation_operation_id": GATE_C,
        "completed_at_utc": "2026-09-26T01:02:03Z",
        "gate_c_tool_identity": _tool().to_mapping(),
    })


def _policy(tmp_path: Path, *, owner_uid: int | None = None) -> InertAssetPolicy:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    uid = os.getuid() if owner_uid is None else owner_uid
    return InertAssetPolicy.qualification(
        root, owner_uid=uid, owner_gid=os.getgid(),
        runtime_uid=65534, runtime_gid=(os.getgid() or 65534),
    )


def _protect_directories(policy: InertAssetPolicy, *, leaf_0700: Path | None = None) -> None:
    for path in (policy.root, *policy.root.rglob("*")):
        if path.is_dir():
            path.chmod(0o700 if path in {policy.root, leaf_0700} else 0o755)


def _inputs(**changes) -> module.PreparationEvidenceInputs:
    values = {
        "candidate_sha": CANDIDATE,
        "gate_a_operation_id": GATE_A,
        "gate_b_operation_id": GATE_B,
        "gate_c_operation_id": GATE_C,
        "rollback_source_cross_check": SOURCE,
    }
    values.update(changes)
    return module.PreparationEvidenceInputs(**values)


@pytest.mark.parametrize("field", (
    "gate_a_operation_id", "gate_b_operation_id", "gate_c_operation_id",
))
def test_explicit_gate_selectors_require_canonical_uuid(field: str) -> None:
    values = {field: "not-a-uuid"}
    with pytest.raises(module.PreRehearsalEvidenceError):
        _inputs(**values).validate()


@pytest.mark.parametrize(
    ("gate", "relative"),
    (
        (PreparationGate.ROLLBACK_QUALIFICATION, f"var/lib/pdi-p3d/preparation/operation-{GATE_A}/authority"),
        (PreparationGate.RELEASE_STAGING, f"var/lib/pdi-p3d/preparation/{GATE_B}"),
        (PreparationGate.INERT_ASSET_INSTALL, f"var/lib/pdi-p3d/preparation/inert-assets/{GATE_C}"),
    ),
)
def test_explicit_gate_uses_only_fixed_operation_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    gate: PreparationGate, relative: str,
) -> None:
    policy = _policy(tmp_path)
    root = policy.root / relative
    root.mkdir(parents=True, mode=0o700)
    _protect_directories(policy, leaf_0700=root)
    seen = []

    def load(actual_root, **kwargs):
        seen.append((actual_root, kwargs))
        return SimpleNamespace(operation_id=operation_id), ()

    monkeypatch.setattr(module, "_load_complete_gate", load)
    operation_id = {
        PreparationGate.ROLLBACK_QUALIFICATION: GATE_A,
        PreparationGate.RELEASE_STAGING: GATE_B,
        PreparationGate.INERT_ASSET_INSTALL: GATE_C,
    }[gate]
    state, _, actual = module._explicit_gate(
        policy, operation_id, gate=gate, candidate=CANDIDATE,
    )
    assert state.operation_id == operation_id
    assert actual == root
    assert seen == [(root, {
        "gate": gate,
        "candidate": CANDIDATE,
        "owner_uid": policy.owner_uid,
        "owner_gid": policy.owner_gid,
    })]


def test_explicit_gate_rejects_untrusted_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path)
    root = policy.preparation_root / GATE_B
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    root.parent.chmod(0o770)
    monkeypatch.setattr(
        module, "_load_complete_gate",
        lambda *_args, **_kwargs: (SimpleNamespace(operation_id=GATE_B), ()),
    )
    with pytest.raises(module.PreRehearsalEvidenceError):
        module._explicit_gate(
            policy, GATE_B, gate=PreparationGate.RELEASE_STAGING,
            candidate=CANDIDATE,
        )


def _candidate_runtime(tmp_path: Path):
    policy = _policy(tmp_path)
    release = policy.candidate_releases_root / CANDIDATE
    executable = release / ".venv/bin/python"
    imported = release / ".venv/lib/python3.13/site-packages/pdi/production_ops/p3d_pre_rehearsal_evidence.py"
    source = release / "src/pdi/production_ops/p3d_pre_rehearsal_evidence.py"
    script = release / "scripts/mu13_p3d_cutover.py"
    payload = b"# exact synthetic WP6 module\n"
    for path, content in (
        (executable, b"synthetic python\n"),
        (imported, payload),
        (source, payload),
        (script, b"# exact synthetic operator script\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return policy, executable, imported, script


def test_candidate_runtime_uses_fixed_read_only_git_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, executable, imported, script = _candidate_runtime(tmp_path)
    calls = []

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        output = CANDIDATE + "\n" if argv[-2:] == ("rev-parse", "HEAD") else ""
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "1")
    monkeypatch.setenv("GIT_DIR", "/tmp/foreign")
    module.verify_candidate_evidence_runtime(
        policy, CANDIDATE, executable=executable, module_file=imported,
        script_file=script, runner=runner,
    )
    assert len(calls) == 2
    assert all(call[1]["env"] == module.GIT_READ_ONLY_ENV for call in calls)
    assert all(call[1]["shell"] is False for call in calls)


def test_candidate_runtime_rejects_git_command_failure(tmp_path: Path) -> None:
    policy, executable, imported, script = _candidate_runtime(tmp_path)

    def runner(_argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    with pytest.raises(module.PreRehearsalEvidenceError):
        module.verify_candidate_evidence_runtime(
            policy, CANDIDATE, executable=executable, module_file=imported,
            script_file=script, runner=runner,
        )


@pytest.mark.parametrize("case", ("workspace", "old-module", "wrong-head", "dirty"))
def test_candidate_runtime_rejects_unbound_invocation(tmp_path: Path, case: str) -> None:
    policy, executable, imported, script = _candidate_runtime(tmp_path)
    module_file = imported
    if case == "workspace":
        module_file = tmp_path / "workspace/p3d_pre_rehearsal_evidence.py"
        module_file.parent.mkdir(parents=True)
        module_file.write_bytes(imported.read_bytes())
    elif case == "old-module":
        imported.write_bytes(b"# old bytes\n")

    def runner(argv, **_kwargs):
        if argv[-2:] == ("rev-parse", "HEAD"):
            output = (SOURCE if case == "wrong-head" else CANDIDATE) + "\n"
        else:
            output = "dirty\n" if case == "dirty" else ""
        return SimpleNamespace(returncode=0, stdout=output)

    with pytest.raises(module.PreRehearsalEvidenceError):
        module.verify_candidate_evidence_runtime(
            policy, CANDIDATE, executable=executable, module_file=module_file,
            script_file=script, runner=runner,
        )


def test_production_policy_rejects_synthetic_systemd_provider(monkeypatch) -> None:
    policy = SimpleNamespace(mode=module.InstallMode.PRODUCTION, owner_uid=0, owner_gid=0)
    with pytest.raises(module.PreRehearsalEvidenceError):
        module.PreRehearsalEvidenceCollector(
            policy=policy,
            inputs=_inputs(),
            systemd=SyntheticSystemdStateProvider(SystemdSnapshot(H5, H4, True)),
        )


def _wire_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    metadata = _metadata()
    marker = _marker(metadata)
    marker_hash = contract_fingerprint(marker)
    protected = module._ProtectedSnapshot(1, 1, 1, H3, b"protected")
    gate_root = tmp_path / "gate-c"
    gate_root.mkdir()
    (gate_root / "home").mkdir()
    state = SimpleNamespace(phase="COMPLETE")
    systemd = SyntheticSystemdStateProvider(SystemdSnapshot(H5, H2, True))
    policy = SimpleNamespace(
        mode=module.InstallMode.QUALIFICATION,
        owner_uid=0,
        owner_gid=0,
        runtime_uid=65534,
        runtime_gid=65534,
        environment=Path("/synthetic/pdi.env"),
        registry=Path("/synthetic/registry.toml"),
    )
    policy.physical = lambda value: Path(value)

    monkeypatch.setattr(module, "_explicit_gate", lambda *_args, **_kwargs: (state, (), Path("/gate")))
    marker_reads = []

    def read_marker(*_args, **_kwargs):
        marker_reads.append(True)
        return marker, marker_hash, protected, gate_root

    monkeypatch.setattr(module, "_read_gate_c_marker", read_marker)
    monkeypatch.setattr(module, "_trusted_directory", lambda *_args, **_kwargs: None)

    prerequisite = SimpleNamespace(
        rollback_metadata=metadata,
        rollback_metadata_sha256=rollback_metadata_fingerprint(metadata),
        p3c_state_sha256=H1,
    )

    class Prerequisites:
        verified = False

        def __init__(self, *_args, **_kwargs):
            pass

        def collect(self, *, home):
            assert home == gate_root / "home"
            return prerequisite

        def verify_p3c_state_unchanged(self, evidence):
            assert evidence is prerequisite
            self.verified = True

    monkeypatch.setattr(module, "ProtectedPrerequisiteReader", Prerequisites)
    configuration = SimpleNamespace(router=SimpleNamespace(
        resolve=lambda _principal: SimpleNamespace(
            database_url="postgresql://synthetic", database_ref="personal-db"
        )
    ))
    monkeypatch.setattr(
        module, "_load_protected_configuration",
        lambda *_args, **_kwargs: (configuration, PRINCIPAL, protected, protected),
    )
    evidence = PersonalDatabaseEvidence(
        PRINCIPAL, "personal-db", "postgresql://synthetic", frozenset(SCOPES), H4, True,
    )
    monkeypatch.setattr(module, "_collect_db_evidence", lambda *_args, **_kwargs: evidence)
    monkeypatch.setattr(module, "_fresh_installed_manifest", lambda _policy: marker.installed_file_manifest)
    monkeypatch.setattr(module, "_current_target", lambda *_args, **_kwargs: marker.current_symlink_after)
    monkeypatch.setattr(module, "_read_protected_bytes", lambda *_args, **_kwargs: protected)
    return policy, systemd, marker_reads, marker


def test_collector_calls_frozen_contract_without_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, systemd, marker_reads, marker = _wire_success(monkeypatch, tmp_path)
    calls = []

    def validator(actual_marker, live):
        calls.append((actual_marker, live))
        return True

    monkeypatch.setattr(module, "validate_pre_rehearsal_preparation_contract", validator)
    collector = module.PreRehearsalEvidenceCollector(
        policy=policy,
        inputs=_inputs(),
        systemd=systemd,
        runtime_verifier=lambda *_args, **_kwargs: H1,
    )
    result = collector.collect().to_sanitized_mapping()
    assert calls and calls[0][0] == marker
    assert result["PRE_REHEARSAL_PREPARATION_CONTRACT"] == "PASS"
    assert result["RUNTIME_PIPELINE_COVERAGE"] == "0/6"
    assert result["POST_REHEARSAL_RUNTIME_LEDGER_PROOF"] == "NOT_APPLICABLE_PRE_REHEARSAL"
    assert len(marker_reads) == 2


def test_collector_normalizes_dependency_failures_to_fixed_wp6_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, systemd, _, _ = _wire_success(monkeypatch, tmp_path)

    class BrokenPrerequisites:
        def __init__(self, *_args, **_kwargs):
            pass

        def collect(self, *, home):
            raise RuntimeError("sensitive backend detail must not cross boundary")

    monkeypatch.setattr(module, "ProtectedPrerequisiteReader", BrokenPrerequisites)
    with pytest.raises(
        module.PreRehearsalEvidenceError,
        match="^P3D_PRE_REHEARSAL_EVIDENCE_REJECTED$",
    ):
        module.PreRehearsalEvidenceCollector(
            policy=policy,
            inputs=_inputs(),
            systemd=systemd,
            runtime_verifier=lambda *_args, **_kwargs: H1,
        ).collect()


@pytest.mark.parametrize("drift", (
    "registry", "db", "scopes", "assets", "current", "p3c-systemd",
))
def test_each_live_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str,
) -> None:
    policy, systemd, _, marker = _wire_success(monkeypatch, tmp_path)
    if drift == "registry":
        other = module._ProtectedSnapshot(1, 1, 1, "9" * 64, b"protected")
        monkeypatch.setattr(
            module, "_load_protected_configuration",
            lambda *_args, **_kwargs: (SimpleNamespace(), PRINCIPAL, other, other),
        )
    elif drift == "db":
        monkeypatch.setattr(
            module, "_collect_db_evidence",
            lambda *_args, **_kwargs: PersonalDatabaseEvidence(
                PRINCIPAL, "personal-db", "postgresql://synthetic",
                frozenset(SCOPES), "9" * 64, True,
            ),
        )
    elif drift == "scopes":
        foreign = (*SCOPES, "77777777-7777-4777-8777-777777777777")
        monkeypatch.setattr(
            module, "_collect_db_evidence",
            lambda *_args, **_kwargs: PersonalDatabaseEvidence(
                PRINCIPAL, "personal-db", "postgresql://synthetic",
                frozenset(foreign), H4, True,
            ),
        )
    elif drift == "assets":
        changed = list(marker.installed_file_manifest)
        changed[0] = replace(changed[0], sha256="9" * 64)
        monkeypatch.setattr(module, "_fresh_installed_manifest", lambda _policy: tuple(changed))
    elif drift == "current":
        monkeypatch.setattr(module, "_current_target", lambda *_args, **_kwargs: "/opt/pdi/releases/" + "c" * 40)
    elif drift == "p3c-systemd":
        systemd.value = SystemdSnapshot("9" * 64, H2, True)
    with pytest.raises(module.PreRehearsalEvidenceError):
        module.PreRehearsalEvidenceCollector(
            policy=policy,
            inputs=_inputs(),
            systemd=systemd,
            runtime_verifier=lambda *_args, **_kwargs: H1,
        ).collect()


def test_marker_reader_requires_exact_operation_and_fingerprint_events(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path)
    policy.gate_c_root.mkdir(parents=True, mode=0o700)
    operation = policy.gate_c_root / GATE_C
    store = GateCJournalStore(
        operation,
        policy=AtomicCreatePolicyV1(policy.owner_uid, policy.owner_gid, 0o600, policy.gate_c_root),
    )
    state = store.initialize(operation_id=GATE_C, candidate_sha=CANDIDATE, tool=_tool())
    events = ()
    marker = _marker()
    marker_hash = contract_fingerprint(marker)
    for phase in GateCPhase:
        if phase in {GateCPhase.NEW, GateCPhase.FAILED}:
            continue
        evidence = (marker_hash,) if phase in {
            GateCPhase.COMPLETE_MARKER_COMMITTED, GateCPhase.COMPLETE,
        } else (H1,)
        state, events = store.advance(state, events, phase, tool=_tool(), evidence=evidence)
        if phase is GateCPhase.SYSTEMD_QUIET_VERIFIED:
            (operation / "complete.json").write_bytes(canonical_json_bytes(marker.to_mapping()) + b"\n")
            (operation / "complete.json").chmod(0o600)
    for path in (policy.root, *policy.root.rglob("*")):
        if path.is_dir():
            path.chmod(0o700 if path in {operation, policy.gate_c_root} else 0o755)
    actual, actual_hash, _, _ = module._read_gate_c_marker(policy, _inputs())
    assert actual == marker and actual_hash == marker_hash
    with pytest.raises(module.PreRehearsalEvidenceError):
        module._read_gate_c_marker(policy, _inputs(gate_c_operation_id=str(uuid4())))


@pytest.mark.parametrize("event", ("committed", "complete"))
def test_complete_marker_requires_fingerprint_in_both_final_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str,
) -> None:
    policy = _policy(tmp_path)
    root = policy.gate_c_root / GATE_C
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    marker = _marker()
    marker_hash = contract_fingerprint(marker)
    marker_path = root / "complete.json"
    marker_path.write_bytes(canonical_json_bytes(marker.to_mapping()) + b"\n")
    marker_path.chmod(0o600)
    committed_hash = H1 if event == "committed" else marker_hash
    complete_hash = H1 if event == "complete" else marker_hash
    events = (
        SimpleNamespace(
            to_state=GateCPhase.COMPLETE_MARKER_COMMITTED.value,
            evidence_fingerprints=(committed_hash,),
        ),
        SimpleNamespace(
            to_state=GateCPhase.COMPLETE.value,
            evidence_fingerprints=(complete_hash,),
        ),
    )
    monkeypatch.setattr(
        module, "_explicit_gate", lambda *_args, **_kwargs: (object(), events, root),
    )
    with pytest.raises(module.PreRehearsalEvidenceError):
        module._read_gate_c_marker(policy, _inputs())


@pytest.mark.parametrize("mutation", ("missing", "symlink", "mode", "owner", "group", "parent"))
def test_complete_marker_trust_fails_closed(
    tmp_path: Path, mutation: str,
) -> None:
    policy = _policy(tmp_path)
    marker_path = policy.gate_c_root / GATE_C / "complete.json"
    marker_path.parent.mkdir(parents=True, mode=0o700)
    if mutation == "symlink":
        target = tmp_path / "foreign"
        target.write_text("{}")
        marker_path.symlink_to(target)
    elif mutation == "mode":
        marker_path.write_text("{}")
        marker_path.chmod(0o644)
    elif mutation in {"owner", "group"}:
        marker_path.write_text("{}")
        marker_path.chmod(0o600)
        policy = replace(
            policy,
            owner_uid=(policy.owner_uid + 1 if mutation == "owner" else policy.owner_uid),
            owner_gid=(policy.owner_gid + 1 if mutation == "group" else policy.owner_gid),
        )
    elif mutation == "parent":
        marker_path.write_text("{}")
        marker_path.chmod(0o600)
        marker_path.parent.chmod(0o770)
    with pytest.raises(module.PreRehearsalEvidenceError):
        module._read_protected_bytes(
            marker_path, policy=policy, mode=0o600, gid=policy.owner_gid,
        )


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership boundary")
@pytest.mark.parametrize("mutation", ("missing", "mode", "owner", "group", "symlink"))
def test_fresh_installed_manifest_rejects_untrusted_physical_asset(
    tmp_path: Path, mutation: str,
) -> None:
    policy = InertAssetPolicy.qualification(
        tmp_path, owner_uid=0, owner_gid=0, runtime_uid=65534, runtime_gid=65534,
    )
    for logical, expected_mode in CANONICAL_P3D_INSTALL_PATH_MODES.items():
        path = policy.physical(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(logical.encode("utf-8"))
        path.chmod(int(expected_mode, 8))
    _protect_directories(policy)
    assert len(module._fresh_installed_manifest(policy)) == 13
    target = policy.physical(sorted(CANONICAL_P3D_INSTALL_PATH_MODES)[0])
    if mutation == "missing":
        target.unlink()
    elif mutation == "mode":
        target.chmod(0o666)
    elif mutation == "owner":
        os.chown(target, 65534, 0)
    elif mutation == "group":
        os.chown(target, 0, 65534)
    else:
        payload = target.read_bytes()
        target.unlink()
        foreign = tmp_path / "foreign-asset"
        foreign.write_bytes(payload)
        target.symlink_to(foreign)
    with pytest.raises(module.PreRehearsalEvidenceError):
        module._fresh_installed_manifest(policy)


def test_protected_environment_is_the_only_configuration_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path)
    environment = policy.environment
    registry = policy.registry
    environment.parent.mkdir(parents=True, exist_ok=True)
    registry.parent.mkdir(parents=True, exist_ok=True)
    environment.write_text(
        "DATABASE__URL=postgresql://protected\n"
        "NEXTCLOUD__URL=https://nextcloud.invalid\n"
        "NEXTCLOUD__USER=synthetic\n"
        "NEXTCLOUD__PASSWORD=protected-nextcloud\n"
        "IMMICH__URL=https://immich.invalid\n"
        "IMMICH__API_KEY=protected-immich\n",
        encoding="utf-8",
    )
    environment.chmod(0o600)
    os.chown(environment, policy.owner_uid, policy.owner_gid)
    registry.write_text("# protected registry\n", encoding="utf-8")
    registry.chmod(0o640)
    os.chown(registry, policy.owner_uid, policy.runtime_gid)
    _protect_directories(policy)
    monkeypatch.setenv("DATABASE__URL", "postgresql://process-environment-must-not-win")
    monkeypatch.setenv("NEXTCLOUD__PASSWORD", "process-environment-must-not-win")
    captured = []
    principal = SimpleNamespace(principal_id=PRINCIPAL)
    configuration = SimpleNamespace(
        router=SimpleNamespace(
            _principals=SimpleNamespace(list_enabled=lambda: [principal]),
        )
    )

    def loader(path, *, environment):
        captured.append((path, dict(environment)))
        return configuration

    actual, principal_ref, _, _ = module._load_protected_configuration(
        policy, configuration_loader=loader,
    )
    assert actual is configuration
    assert principal_ref == PRINCIPAL
    assert captured[0][0] == registry
    assert captured[0][1]["DATABASE__URL"] == "postgresql://protected"
    assert captured[0][1]["NEXTCLOUD__PASSWORD"] == "protected-nextcloud"


@pytest.mark.parametrize("field", ("snapshot_id", "source_release_sha"))
def test_marker_gate_a_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str,
) -> None:
    policy, systemd, _, _ = _wire_success(monkeypatch, tmp_path)
    mapping = rollback_mapping()
    mapping["TARGET_CANDIDATE_SHA"] = CANDIDATE
    mapping["SOURCE_SHA"] = SOURCE
    mapping["SOURCE_RELEASE_SHA"] = SOURCE
    if field == "snapshot_id":
        mapping["SNAPSHOT_ID"] = "9" * 64
    else:
        mapping["SOURCE_SHA"] = "c" * 40
        mapping["SOURCE_RELEASE_SHA"] = "c" * 40
    drifted = P3DRollbackMetadataV1.from_mapping(mapping)

    class Prerequisites:
        def __init__(self, *_args, **_kwargs):
            pass

        def collect(self, *, home):
            return SimpleNamespace(
                rollback_metadata=drifted,
                rollback_metadata_sha256=rollback_metadata_fingerprint(drifted),
                p3c_state_sha256=H1,
            )

        def verify_p3c_state_unchanged(self, _evidence):
            raise AssertionError("authority mismatch should fail first")

    monkeypatch.setattr(module, "ProtectedPrerequisiteReader", Prerequisites)
    with pytest.raises(
        module.PreRehearsalEvidenceError,
        match="P3D_PRE_REHEARSAL_ROLLBACK_AUTHORITY_MISMATCH",
    ):
        module.PreRehearsalEvidenceCollector(
            policy=policy,
            inputs=_inputs(rollback_source_cross_check=None),
            systemd=systemd,
            runtime_verifier=lambda *_args, **_kwargs: H1,
        ).collect()


def test_wp6_module_has_no_write_or_workload_primitives() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_calls = {
        "write_text", "write_bytes", "mkdir", "unlink", "replace", "rename",
        "symlink_to", "atomic_create_no_replace", "P3DControl", "PipelineRun",
    }
    used = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))
    }
    assert used.isdisjoint(forbidden_calls)
    assert "systemctl start" not in source
    assert "systemctl enable" not in source
    assert "shell=True" not in source
