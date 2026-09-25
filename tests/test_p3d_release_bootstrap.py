from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    FailureCode,
    GateBPhase,
    OperatorToolIdentity,
    OSRuntimeManifestV1,
    PreparationGate,
    ToolName,
    os_runtime_manifest_fingerprint,
    validate_preparation_journal_chain,
)
from pdi.production_ops import p3d_release_bootstrap as subject


CANDIDATE = "1" * 40
BOOTSTRAP_SOURCE = "2" * 40
BUNDLE_HASH = "3" * 64
OS_HASH = "4" * 64
ARTIFACT_HASH = "5" * 64


def tool(*, role: ToolName = ToolName.RELEASE_BOOTSTRAP) -> OperatorToolIdentity:
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": role.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": ARTIFACT_HASH,
        "TOOL_SOURCE_SHA": BOOTSTRAP_SOURCE,
    })


def manifest() -> OSRuntimeManifestV1:
    return OSRuntimeManifestV1.from_mapping({
        "MANIFEST_VERSION": "1",
        "OS_ID": "synthetic",
        "OS_VERSION_ID": "1",
        "ARCH": "x86_64",
        "APPROVED_PACKAGE_NAMES_AND_VERSIONS": [{"NAME": "python313", "VERSION": "3.13"}],
        "SYSTEM_PYTHON_PATH": "/usr/bin/python3.13",
        "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13",
        "PYTHON_ABI": "cp313",
        "SYSTEM_RUNTIME_FILE_SHA256": "6" * 64,
        "NATIVE_LIBRARY_PACKAGE_SET": ["python313"],
    })


def make_root(tmp_path: Path) -> Path:
    root = tmp_path / "qualification"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def make_inputs(root: Path, bundle: Path, *, authority: str = "QUALIFICATION_ONLY") -> subject.BootstrapInputs:
    return subject.BootstrapInputs(
        bundle.absolute(),
        CANDIDATE,
        subject.sha256_file(bundle),
        os_runtime_manifest_fingerprint(manifest()),
        authority,
        tool(),
        root / "releases",
        root / "state",
        root / "control/bootstrap.lock",
        root / "current",
        "qualification-user",
        "qualification-group",
    )


def make_policy(root: Path) -> subject.BootstrapPolicy:
    return subject.BootstrapPolicy.qualification(
        disposable_root=root,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        runtime_uid=os.geteuid(),
        runtime_gid=os.getegid(),
    )


class FakeProvider:
    def verify(self, value, *, policy):
        assert value == manifest()
        assert policy.mode is subject.BootstrapMode.QUALIFICATION
        return subject.HostRuntimeEvidence(Path("/usr/bin/python3.13"), "7" * 64)


def install_orchestration_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    def verify(bundle, **kwargs):
        assert bundle.name == "approved-bundle.tar"
        assert kwargs["perform_offline_install"] is False
        return {
            "CANDIDATE_SHA": CANDIDATE,
            "BUNDLE_SHA256": kwargs["expected_bundle_sha256"],
            "RELEASE_INPUT_MANIFEST_SHA256": "8" * 64,
            "PROVENANCE_SHA256": "9" * 64,
        }

    def extract(bundle: Path, target: Path):
        target.mkdir(mode=0o700)
        provenance = target / "provenance"
        provenance.mkdir()
        (provenance / "provenance.json").write_text(json.dumps({"AUTHORITY_CLASS": "QUALIFICATION_ONLY"}))
        (target / "source").mkdir()
        (target / "source/pdi.git.bundle").write_text("bundle")
        (target / "manifests").mkdir()
        (target / "manifests/os-runtime.json").write_text("{}")
        (target / "manifests/wheelhouse.json").write_text("wheels")
        (target / "requirements").mkdir()
        (target / "requirements/runtime.lock").write_text("lock")
        return ()

    def checkout(staging: Path, bundle: Path, *, candidate: str, home: Path):
        assert candidate == CANDIDATE
        (staging / "payload.txt").write_text("exact\n")

    def fingerprint(path: Path, **kwargs):
        return subject._sha256_bytes((path / "payload.txt").read_bytes())

    monkeypatch.setattr(subject, "verify_release_input_bundle", verify)
    monkeypatch.setattr(subject, "safe_extract_bundle", extract)
    monkeypatch.setattr(subject, "load_os_runtime_manifest", lambda path: manifest())
    monkeypatch.setattr(subject, "_checkout_source", checkout)
    monkeypatch.setattr(subject, "_verify_git", lambda *args, **kwargs: None)
    monkeypatch.setattr(subject, "_build_venv", lambda *args, **kwargs: None)
    monkeypatch.setattr(subject, "_rewrite_staging_references", lambda *args, **kwargs: None)
    monkeypatch.setattr(subject, "_canonicalize_tree", lambda *args, **kwargs: None)
    monkeypatch.setattr(subject, "_source_alembic_head", lambda path: "head123")
    monkeypatch.setattr(subject, "_runtime_verify", lambda *args, **kwargs: ("head123", "a" * 64))
    monkeypatch.setattr(subject, "_verify_release_tree", fingerprint)


def test_bootstrap_tool_sha_is_independent_from_candidate(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    bundle = tmp_path / "bundle.tar"
    bundle.write_bytes(b"bundle")
    inputs = make_inputs(root, bundle)
    inputs.validate()
    assert inputs.bootstrap_tool_identity.tool_source_sha == BOOTSTRAP_SOURCE
    assert inputs.expected_candidate_sha == CANDIDATE
    assert BOOTSTRAP_SOURCE != CANDIDATE


def test_wrong_tool_role_is_rejected_by_inputs(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    bundle = tmp_path / "bundle.tar"
    bundle.write_bytes(b"bundle")
    base = make_inputs(root, bundle)
    bad = subject.BootstrapInputs(
        base.bundle_path, base.expected_candidate_sha, base.expected_bundle_sha256,
        base.expected_os_runtime_manifest_sha256, base.expected_authority_class,
        tool(role=ToolName.BACKUP_EXPORT), base.releases_root,
        base.preparation_state_root, base.lock_path, base.current_path,
        base.runtime_user, base.runtime_group,
    )
    with pytest.raises(subject.BootstrapError) as raised:
        bad.validate()
    assert raised.value.code is FailureCode.RELEASE_ARTIFACT_INVALID


def test_qualification_authority_is_rejected_by_production_policy(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.tar"
    bundle.write_bytes(b"bundle")
    inputs = subject.BootstrapInputs(
        bundle.absolute(), CANDIDATE, subject.sha256_file(bundle), OS_HASH,
        "QUALIFICATION_ONLY", tool(), Path("/opt/pdi/releases"),
        Path("/var/lib/pdi-p3d/preparation"),
        Path("/run/lock/pdi/p3d-release-bootstrap.lock"), Path("/opt/pdi/current"),
        "pdi", "pdi",
    )
    policy = subject.BootstrapPolicy(
        subject.BootstrapMode.PRODUCTION, Path("/"), 0, 0, 1, 1,
        "QUALIFICATION_ONLY", (Path("/usr"),),
    )
    with pytest.raises(subject.BootstrapError) as raised:
        policy.validate_inputs(inputs)
    assert raised.value.code is FailureCode.RELEASE_ARTIFACT_INVALID


def test_wrong_bundle_hash_fails_before_verifier(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    source = tmp_path / "bundle.tar"
    source.write_bytes(b"actual")
    with pytest.raises(subject.BootstrapError) as raised:
        subject._seal_bundle(source, root / "sealed", expected_sha256=BUNDLE_HASH, policy=make_policy(root))
    assert raised.value.code is FailureCode.RELEASE_ARTIFACT_INVALID


def test_sealed_bundle_is_exact_protected_and_idempotent(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    source = tmp_path / "bundle.tar"
    source.write_bytes(b"exact")
    expected = subject.sha256_file(source)
    target = root / "sealed"
    assert subject._seal_bundle(source, target, expected_sha256=expected, policy=make_policy(root)) == target
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert subject._seal_bundle(source, target, expected_sha256=expected, policy=make_policy(root)) == target


def test_synthetic_provider_cannot_cross_into_production() -> None:
    value = manifest()
    provider = subject.QualificationHostRuntimeAuthorityProvider(
        Path("/usr/bin/python3.13"), os_runtime_manifest_fingerprint(value),
    )
    production = subject.BootstrapPolicy(
        subject.BootstrapMode.PRODUCTION, Path("/"), 0, 0, 1, 1,
        subject.PRODUCTION_AUTHORITY_CLASS, (Path("/usr"),),
    )
    with pytest.raises(subject.BootstrapError) as raised:
        provider.verify(value, policy=production)
    assert raised.value.code is FailureCode.RELEASE_OS_RUNTIME_MISMATCH


def test_offline_pip_argv_is_hash_locked_binary_only(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(argv, **kwargs):
        calls.append(tuple(map(os.fspath, argv)))
        if argv[1:4] == ("-m", "venv", "--copies"):
            (Path(argv[4]) / "bin").mkdir(parents=True)
        return ""

    monkeypatch.setattr(subject, "_run", runner)
    staging = tmp_path / "release"
    quarantine = tmp_path / "quarantine"
    staging.mkdir()
    (quarantine / "requirements").mkdir(parents=True)
    (quarantine / "wheelhouse").mkdir()
    subject._build_venv(staging, quarantine, Path("/usr/bin/python3.13"))
    install = calls[1]
    assert "--no-index" in install
    assert "--require-hashes" in install
    assert "--only-binary=:all:" in install
    assert not {"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PYTHONPATH"} & subject._python_env().keys()


def test_staging_rewrite_removes_bytecode_and_never_edits_binary(tmp_path: Path) -> None:
    staging = tmp_path / "staging-long-name"
    final = tmp_path / "final"
    cache = staging / "pkg/__pycache__"
    cache.mkdir(parents=True)
    (cache / "module.pyc").write_bytes(b"marshal" + os.fsencode(str(staging)))
    dist = staging / ".venv/lib/python3.13/site-packages/demo-1.0.dist-info"
    dist.mkdir(parents=True)
    installed_cache = staging / ".venv/lib/python3.13/site-packages/demo/__pycache__"
    installed_cache.mkdir(parents=True)
    (installed_cache / "module.cpython-313.pyc").write_bytes(b"installed-bytecode")
    (dist / "METADATA").write_text("Name: demo\n")
    (dist / "RECORD").write_text(
        "demo/__pycache__/module.cpython-313.pyc,,\n"
        "demo-1.0.dist-info/METADATA,sha256=stale,1\n"
        "demo-1.0.dist-info/RECORD,,\n"
    )
    script = staging / "script"
    script.write_text(f"#!{staging}/.venv/bin/python\n")
    subject._rewrite_staging_references(staging, final)
    assert not cache.exists()
    assert str(final) in script.read_text()
    record = (dist / "RECORD").read_text()
    assert "demo/__pycache__/module.cpython-313.pyc,," in record
    assert "sha256=stale" not in record
    assert "demo-1.0.dist-info/RECORD,," in record
    binary = staging / "binary.so"
    binary.write_bytes(b"\x00" + os.fsencode(str(staging)))
    with pytest.raises(subject.BootstrapError):
        subject._rewrite_staging_references(staging, final)


def test_root_runtime_always_uses_setpriv_and_clears_groups(monkeypatch) -> None:
    monkeypatch.setattr(subject.os, "geteuid", lambda: 0)
    monkeypatch.setattr(subject, "SETPRIV", Path("/usr/bin/true"))
    policy = subject.BootstrapPolicy(
        subject.BootstrapMode.QUALIFICATION, Path("/tmp/q"), 0, 0, 65534, 65534,
        "QUALIFICATION_ONLY", (Path("/usr"),),
    )
    argv = subject._unprivileged_argv((Path("/release/.venv/bin/python"), "-c", "pass"), policy=policy)
    assert argv[:5] == (str(subject.SETPRIV), "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs")
    assert "--" in argv


def test_nonroot_wrong_runtime_identity_fails(monkeypatch) -> None:
    monkeypatch.setattr(subject.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(subject.os, "getegid", lambda: 1000)
    policy = subject.BootstrapPolicy(
        subject.BootstrapMode.QUALIFICATION, Path("/tmp/q"), 1000, 1000, 1001, 1001,
        "QUALIFICATION_ONLY", (Path("/usr"),),
    )
    with pytest.raises(subject.BootstrapError):
        subject._unprivileged_argv((Path("/python"),), policy=policy)


def _minimal_release(tmp_path: Path) -> Path:
    release = tmp_path / "release"
    for relative in ("src", "scripts", "migrations/versions", "deployment", ".git", ".venv/bin"):
        (release / relative).mkdir(parents=True, exist_ok=True)
    for relative in ("pyproject.toml", "alembic.ini", "src/a.py", "scripts/a.py", "deployment/a"):
        (release / relative).write_text("safe\n")
    (release / ".venv/bin/python").write_bytes(b"python")
    for path in [release, *release.rglob("*")]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path == release / ".venv/bin/python" else 0o644)
    return release


def test_release_tree_trust_and_fingerprint(tmp_path: Path, monkeypatch) -> None:
    release = _minimal_release(tmp_path)
    monkeypatch.setattr(subject, "_verify_git", lambda *args, **kwargs: None)
    policy = subject.BootstrapPolicy(
        subject.BootstrapMode.QUALIFICATION, tmp_path, os.geteuid(), os.getegid(),
        os.geteuid(), os.getegid(), "QUALIFICATION_ONLY", (Path("/usr"),),
    )
    value = subject._verify_release_tree(
        release, candidate=CANDIDATE, policy=policy,
        approved_python=Path("/usr/bin/python3.13"), home=tmp_path,
    )
    assert len(value) == 64


@pytest.mark.parametrize("mutation", ["writable", "fifo", "external-symlink", "foreign-owner"])
def test_release_tree_rejects_mutable_special_or_untrusted_content(tmp_path: Path, monkeypatch, mutation: str) -> None:
    release = _minimal_release(tmp_path)
    policy = subject.BootstrapPolicy(
        subject.BootstrapMode.QUALIFICATION, tmp_path, os.geteuid(), os.getegid(),
        os.geteuid(), os.getegid(), "QUALIFICATION_ONLY", (Path("/usr"),),
    )
    monkeypatch.setattr(subject, "_verify_git", lambda *args, **kwargs: None)
    if mutation == "writable":
        (release / "src").chmod(0o775)
    elif mutation == "fifo":
        os.mkfifo(release / "pipe")
    elif mutation == "external-symlink":
        (release / "unsafe").symlink_to("/tmp")
    else:
        policy = subject.BootstrapPolicy(
            subject.BootstrapMode.QUALIFICATION, tmp_path, os.geteuid() + 1, os.getegid(),
            os.geteuid(), os.getegid(), "QUALIFICATION_ONLY", (Path("/usr"),),
        )
    with pytest.raises(subject.BootstrapError) as raised:
        subject._verify_release_tree(
            release, candidate=CANDIDATE, policy=policy,
            approved_python=Path("/usr/bin/python3.13"), home=tmp_path,
        )
    assert raised.value.code is FailureCode.RELEASE_IMMUTABILITY_FAILED


def test_exclusive_lock_refuses_second_holder(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    control = root / "control"
    control.mkdir(mode=0o700)
    policy = make_policy(root)
    lock = control / "bootstrap.lock"
    with subject.exclusive_bootstrap_lock(lock, policy=policy):
        with pytest.raises(subject.BootstrapError) as raised:
            with subject.exclusive_bootstrap_lock(lock, policy=policy):
                pass
    assert raised.value.code is FailureCode.RELEASE_FINAL_CONFLICT


def test_gate_b_journal_uses_frozen_chain_and_retry_policy(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    state_root = root / "state"
    state_root.mkdir(mode=0o700)
    operation = state_root / "00000000-0000-4000-8000-000000000001"
    policy = AtomicCreatePolicyV1(os.geteuid(), os.getegid(), 0o600, state_root)
    store = subject.GateBJournalStore(operation, policy=policy)
    state = store.initialize(
        operation_id=operation.name, candidate_sha=CANDIDATE,
        started_at="2026-01-01T00:00:00Z", tool=tool(),
    )
    state, events = store.advance(
        state, (), GateBPhase.ARTIFACT_VERIFIED, tool=tool(), evidence_fingerprints=(BUNDLE_HASH,),
    )
    assert state.gate is PreparationGate.RELEASE_STAGING
    assert validate_preparation_journal_chain(events, state)
    assert store.load_retryable() == (state, events)


def test_complete_orchestration_is_idempotent_and_conflict_safe(tmp_path: Path, monkeypatch) -> None:
    install_orchestration_fakes(monkeypatch)
    root = make_root(tmp_path)
    bundle = tmp_path / "bundle.tar"
    bundle.write_bytes(b"bundle")
    inputs = make_inputs(root, bundle)
    runner = lambda: subject.ReleaseBootstrap(inputs=inputs, policy=make_policy(root), host_runtime_provider=FakeProvider()).run()
    first = runner()
    assert first.disposition == "CREATED"
    assert first.final_state.phase == GateBPhase.COMPLETE.value
    assert len(first.events) == 10
    assert not inputs.current_path.exists()
    second = runner()
    assert second.disposition == "IDEMPOTENT"
    assert second.release_fingerprint == first.release_fingerprint
    (inputs.final_path / "payload.txt").write_text("tampered\n")
    with pytest.raises(subject.BootstrapError) as raised:
        runner()
    assert raised.value.code is FailureCode.RELEASE_FINAL_CONFLICT
    assert (inputs.final_path / "payload.txt").read_text() == "tampered\n"
    assert not inputs.current_path.exists()


def test_pre_rename_failure_cleans_staging_preserves_journal_and_current(tmp_path: Path, monkeypatch) -> None:
    install_orchestration_fakes(monkeypatch)
    root = make_root(tmp_path)
    bundle = tmp_path / "bundle.tar"
    bundle.write_bytes(b"bundle")
    inputs = make_inputs(root, bundle)
    monkeypatch.setattr(subject, "_checkout_source", lambda *args, **kwargs: subject._fail(FailureCode.RELEASE_SOURCE_CHECKOUT_FAILED))
    with pytest.raises(subject.BootstrapError):
        subject.ReleaseBootstrap(inputs=inputs, policy=make_policy(root), host_runtime_provider=FakeProvider()).run()
    assert list(inputs.preparation_state_root.glob("*/state-*.json"))
    assert not list(inputs.releases_root.glob(".p3d-staging-*"))
    assert not inputs.current_path.exists()


def test_resume_rejects_post_final_phase(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    state_root = root / "state"
    state_root.mkdir(mode=0o700)
    operation = state_root / "00000000-0000-4000-8000-000000000002"
    policy = AtomicCreatePolicyV1(os.geteuid(), os.getegid(), 0o600, state_root)
    store = subject.GateBJournalStore(operation, policy=policy)
    state = store.initialize(
        operation_id=operation.name, candidate_sha=CANDIDATE,
        started_at="2026-01-01T00:00:00Z", tool=tool(),
    )
    events = ()
    for phase in list(GateBPhase)[1:9]:
        state, events = store.advance(state, events, phase, tool=tool(), evidence_fingerprints=(BUNDLE_HASH,))
    assert state.phase == GateBPhase.FINAL_RENAME_COMMITTED.value
    with pytest.raises(subject.BootstrapError):
        store.load_retryable()


def test_security_forbidden_operations_absent_from_wp4_module() -> None:
    source = Path(subject.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "shell=True", "systemctl", "daemon-reload", "DATABASE_URL", "psycopg.connect",
        "git fetch https", "curl ", "wget ", "apt install", "apt upgrade", "current.symlink_to",
    ):
        assert forbidden not in source
    assert "perform_offline_install=False" in source
    assert "GIT_OPTIONAL_LOCKS\": \"0" in source


def test_bootstrap_artifact_design_is_independent_and_deferred() -> None:
    assert subject.bootstrap_artifact_design() == {
        "FORMAT": "stdlib-pyz-v1",
        "AUTHORITY": "INDEPENDENT_BOOTSTRAP",
        "SELF_UPDATE": "FORBIDDEN",
        "BUILD_STATUS": "DEFERRED",
    }
