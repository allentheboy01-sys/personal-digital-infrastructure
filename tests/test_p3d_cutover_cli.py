"""P3D CLI gate wiring tests; no test invokes systemctl or a pipeline."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[1]


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "mu13_p3d_cutover_under_test", ROOT / "scripts/mu13_p3d_cutover.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_pre_rehearsal_qualify_uses_static_proof_without_runtime_workload(tmp_path, monkeypatch):
    module = _load_module()
    candidate = "c" * 40
    rollback = "r" * 40
    (tmp_path / "registry.toml").write_text(
        '[[principals]]\nid="synthetic-principal"\nenabled=true\n'
    )
    routed = SimpleNamespace(database_url="postgresql://synthetic")
    router = SimpleNamespace(resolve=lambda _principal: routed)
    monkeypatch.setattr(
        module, "load_scoped_operator_configuration",
        lambda *_args, **_kwargs: SimpleNamespace(router=router),
    )
    monkeypatch.setattr(module, "create_postgres_engine", lambda _url: object())
    context = {"release_sha": candidate, "release_path": str(tmp_path / "release")}

    class Reader:
        def __init__(self, **_kwargs):
            pass

        def collect_preflight(self):
            return context

    events = []

    class Control:
        def __init__(self, *_args):
            pass

        def qualify(self, proof, *, context):
            events.append(("qualify", proof, context))

    class Backend:
        def __init__(self):
            events.append(("backend-created",))

        def run_rehearsal_services(self, _keys):
            raise AssertionError("pre-rehearsal qualify started a runtime service")

        def enable_scoped_enrichments(self, _keys):
            raise AssertionError("pre-rehearsal qualify enabled a timer")

    proof = {"proof_kind": "pre_rehearsal_static"}
    monkeypatch.setattr(module, "ProductionEvidenceReader", Reader)
    monkeypatch.setattr(module, "P3DControl", Control)
    monkeypatch.setattr(module, "SystemdScopedEnrichmentActions", Backend)
    monkeypatch.setattr(module, "build_pre_rehearsal_qualification_proof", lambda **_kwargs: proof)
    monkeypatch.setattr(
        module, "verify_qualification_ledger_batch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("pre-rehearsal qualify queried runtime ledger")
        ),
    )

    result = module.main([
        "qualify", "--release", str(tmp_path / "release"),
        "--expected-sha", candidate, "--rollback-source-sha", rollback,
        "--rehearsal-root", str(tmp_path),
    ])

    assert result == 0
    assert events[-1] == ("qualify", proof, context)


def test_post_rehearsal_ledger_path_requires_control_boundary(tmp_path, monkeypatch):
    module = _load_module()
    candidate = "c" * 40
    rollback = "r" * 40
    (tmp_path / "registry.toml").write_text(
        '[[principals]]\nid="synthetic-principal"\nenabled=true\n'
    )
    routed = SimpleNamespace(database_url="postgresql://synthetic")
    router = SimpleNamespace(resolve=lambda _principal: routed)
    monkeypatch.setattr(
        module, "load_scoped_operator_configuration",
        lambda *_args, **_kwargs: SimpleNamespace(router=router),
    )
    monkeypatch.setattr(module, "create_postgres_engine", lambda _url: object())

    class Reader:
        def __init__(self, **_kwargs):
            pass

        def collect_active_verify(self):
            return {"p3c_healthy": True, "p3d_healthy": True}

    class Control:
        def __init__(self, *_args):
            pass

        def runtime_ledger_boundary(self):
            raise module.P3DControlRefused("RUNTIME_LEDGER_PHASE_INVALID")

    monkeypatch.setattr(module, "ProductionEvidenceReader", Reader)
    monkeypatch.setattr(module, "P3DControl", Control)
    monkeypatch.setattr(module, "SystemdScopedEnrichmentActions", lambda: object())

    assert module.main([
        "post-rehearsal-ledger", "--release", str(tmp_path / "release"),
        "--expected-sha", candidate, "--rollback-source-sha", rollback,
        "--rehearsal-root", str(tmp_path),
    ]) == 1


def test_collect_evidence_cli_bypasses_all_stateful_control_paths(monkeypatch, capsys):
    module = _load_module()
    candidate = "c" * 40
    rollback = "a" * 40
    result = {
        "P3D_COLLECT_EVIDENCE": "PASS",
        "CANDIDATE_SHA": candidate,
        "CONTEXT_FINGERPRINT": "1" * 64,
        "P3C_EVIDENCE_REAL": "PASS",
        "GMAIL_EVIDENCE_REAL": "PASS",
        "ROUTED_DB_PREFLIGHT": "PASS",
        "READ_ONLY_DB_GUARANTEE": "PASS",
        "DB_IDENTITY_FINGERPRINT": "2" * 64,
        "ENABLED_SCOPE_COUNT": "2",
        "ENABLED_SCOPE_FINGERPRINT": "3" * 64,
        "CANONICAL_PIPELINE_COUNT": "6",
        "ASSET_FINGERPRINT": "4" * 64,
        "PRE_REHEARSAL_QUALIFICATION_PROOF": "PASS",
        "POST_REHEARSAL_RUNTIME_LEDGER_PROOF": "NOT_APPLICABLE_PRE_REHEARSAL",
        "RUNTIME_PIPELINE_COVERAGE": "0/6",
    }
    calls = []
    monkeypatch.setattr(
        module,
        "collect_read_only_evidence",
        lambda **kwargs: calls.append(kwargs) or result,
    )
    for name in (
        "P3DControl", "SystemdScopedEnrichmentActions", "promote_release_atomically",
        "verify_qualification_ledger_batch",
    ):
        monkeypatch.setattr(
            module,
            name,
            lambda *_args, _name=name, **_kwargs: (_ for _ in ()).throw(
                AssertionError(f"collect-evidence invoked {_name}")
            ),
        )

    assert module.main([
        "collect-evidence",
        "--release", f"/opt/pdi/releases/{candidate}",
        "--expected-sha", candidate,
        "--rollback-source-sha", rollback,
    ]) == 0

    assert len(calls) == 1
    assert "P3D_COLLECT_EVIDENCE=PASS" in capsys.readouterr().out


def test_collect_evidence_evaluates_static_proof_without_persistence(tmp_path, monkeypatch):
    module = _load_module()
    candidate = "c" * 40
    rollback = "a" * 40
    config = tmp_path / "registry.toml"
    config.write_text('[[principals]]\nid="synthetic-principal"\nenabled=true\n')
    rollback_metadata = tmp_path / "rollback.env"
    rollback_metadata.write_text("SYNTHETIC=YES\n")
    routed = SimpleNamespace(database_url="postgresql://synthetic")
    router = SimpleNamespace(resolve=lambda _principal: routed)
    disposed = []

    class Engine:
        def dispose(self):
            disposed.append(True)

    class PersonalReader:
        def __init__(self, *_args, **_kwargs):
            pass

    context = {
        "release_sha": candidate,
        "read_only_db_guarantee": True,
        "enabled_scope_ids": ["scope-a", "scope-b"],
        "db_identity_fingerprint": "d" * 64,
    }

    class EvidenceReader:
        def __init__(self, **_kwargs):
            pass

        def collect_preflight(self):
            return context

    proof = {
        "pipeline_keys": module.CANONICAL_SCOPED_ENRICHMENTS,
        "asset_fingerprint": "f" * 64,
    }
    proof_calls = []
    monkeypatch.setattr(module, "RoutedPersonalDatabaseEvidenceReader", PersonalReader)
    monkeypatch.setattr(
        module,
        "build_pre_rehearsal_qualification_proof",
        lambda **kwargs: proof_calls.append(kwargs) or proof,
    )

    result = module.collect_read_only_evidence(
        release=Path(f"/opt/pdi/releases/{candidate}"),
        expected_sha=candidate,
        rollback_source_sha=rollback,
        current=Path("/opt/pdi/current"),
        rollback=rollback_metadata,
        config=config,
        unit_dir=tmp_path / "units",
        profile_dir=tmp_path / "profiles",
        operator_config_loader=lambda *_args, **_kwargs: SimpleNamespace(router=router),
        engine_factory=lambda _url: Engine(),
        evidence_reader_factory=EvidenceReader,
        protected_file_reader=lambda path: path.read_text(),
    )

    assert result["P3D_COLLECT_EVIDENCE"] == "PASS"
    assert result["READ_ONLY_DB_GUARANTEE"] == "PASS"
    assert result["RUNTIME_PIPELINE_COVERAGE"] == "0/6"
    assert proof_calls[0]["context"] is context
    assert disposed == [True]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["registry.toml", "rollback.env"]


def test_collect_evidence_rejects_test_or_control_path_overrides(capsys):
    module = _load_module()
    candidate = "c" * 40
    rollback = "a" * 40
    for extra in (
        ("--rehearsal-root", "/tmp/not-authoritative"),
        ("--state", "/tmp/not-authoritative-state"),
        ("--journal", "/tmp/not-authoritative-journal"),
    ):
        assert module.main([
            "collect-evidence",
            "--release", f"/opt/pdi/releases/{candidate}",
            "--expected-sha", candidate,
            "--rollback-source-sha", rollback,
            *extra,
        ]) == 1
    output = capsys.readouterr().out
    assert output.count("FAILURE_CATEGORY=OPERATOR_PATH_OVERRIDE_REJECTED") == 3


def test_collect_evidence_failure_never_prints_exception_or_secret(monkeypatch, capsys):
    module = _load_module()
    candidate = "c" * 40
    rollback = "a" * 40
    monkeypatch.setattr(
        module,
        "collect_read_only_evidence",
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("postgresql://account:secret@example.invalid/personal")
        ),
    )

    assert module.main([
        "collect-evidence",
        "--release", f"/opt/pdi/releases/{candidate}",
        "--expected-sha", candidate,
        "--rollback-source-sha", rollback,
    ]) == 1

    output = capsys.readouterr().out
    assert output == (
        "P3D_COLLECT_EVIDENCE=FAIL\n"
        "FAILURE_CATEGORY=EVIDENCE_REJECTED\n"
    )
    assert "secret" not in output


def test_sanitized_evidence_schema_rejects_extra_values(capsys):
    module = _load_module()
    with pytest.raises(module.P3DControlRefused, match="SANITIZED_OUTPUT_SCHEMA_INVALID"):
        module.emit_sanitized_evidence({"DATABASE_URL": "postgresql://secret"})
    assert capsys.readouterr().out == ""


def test_sanitized_evidence_rejects_secret_in_allowlisted_value(capsys):
    module = _load_module()
    result = {
        "P3D_COLLECT_EVIDENCE": "PASS",
        "CANDIDATE_SHA": "c" * 40,
        "CONTEXT_FINGERPRINT": "1" * 64,
        "P3C_EVIDENCE_REAL": "PASS",
        "GMAIL_EVIDENCE_REAL": "PASS",
        "ROUTED_DB_PREFLIGHT": "PASS",
        "READ_ONLY_DB_GUARANTEE": "PASS",
        "DB_IDENTITY_FINGERPRINT": "postgresql://account:secret@example.invalid/db",
        "ENABLED_SCOPE_COUNT": "2",
        "ENABLED_SCOPE_FINGERPRINT": "3" * 64,
        "CANONICAL_PIPELINE_COUNT": "6",
        "ASSET_FINGERPRINT": "4" * 64,
        "PRE_REHEARSAL_QUALIFICATION_PROOF": "PASS",
        "POST_REHEARSAL_RUNTIME_LEDGER_PROOF": "NOT_APPLICABLE_PRE_REHEARSAL",
        "RUNTIME_PIPELINE_COVERAGE": "0/6",
    }
    with pytest.raises(module.P3DControlRefused, match="SANITIZED_OUTPUT_VALUE_INVALID"):
        module.emit_sanitized_evidence(result)
    assert capsys.readouterr().out == ""
