"""P3D CLI gate wiring tests; no test invokes systemctl or a pipeline."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace


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
