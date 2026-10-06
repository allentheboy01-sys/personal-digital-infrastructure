from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import inspect
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest

from pdi.production_ops import p3d_wp8_systemd as module
from pdi.production_ops.p3d_inert_asset_install import ProductionReadOnlySystemdStateProvider
from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint
from pdi.production_ops.p3d_wp8_contracts import (
    WP8_CANONICAL_PIPELINE_KEYS, WP8CleanupProofV1, WP8CleanupResult,
    WP8ContractError, WP8FailureCode, WP8PipelineRunProofV1,
)
from tests.test_p3d_wp8_contracts import phase_a, OPERATION


KEYS = WP8_CANONICAL_PIPELINE_KEYS
H = "1" * 64
CANARY = "synthetic-password-token@provider.invalid"
TEMPLATE = Path("deployment/systemd/pdi-scoped-pipeline@.service").read_bytes()
DEPENDENCY_DIRECTORIES = module._dependency_directories
PUBLIC = {"manager_identity", "daemon_reload", "snapshot_p3c", "verify_timers_quiet",
          "verify_service_contract", "start_service", "stop_all_services", "verify_all_services_inactive"}


def service_values(key):
    source = {name: value for section, name, value in module._template(TEMPLATE) if section == "Service"}
    values = {name: "" for name in module._SERVICE_PROPERTIES}
    values.update(Id=module._SERVICE_UNITS[key], Names=module._SERVICE_UNITS[key],
        LoadState="loaded", FragmentPath=module._TEMPLATE,
        Transient="no", NeedDaemonReload="no", User="pdi", Group="pdi", Type="oneshot",
        WorkingDirectory=source["WorkingDirectory"],
        EnvironmentFiles=f"/etc/pdi/scoped/units/{key}.env (ignore_errors=no)",
        ExecStart="{ path=/opt/pdi/current/.venv/bin/python ; argv[]=" + source["ExecStart"] +
            " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
        NoNewPrivileges="yes", PrivateTmp="yes", ProtectSystem="strict", ProtectHome="yes",
        ReadWritePaths="/run/lock", TimeoutStartUSec="infinity", TimeoutStopUSec="1min",
        KillMode="control-group", StandardOutput="null", StandardError="null",
        RemainAfterExit="no", Restart="no", FailureAction="none", SuccessAction="none",
        StartLimitAction="none", JobTimeoutAction="none", DefaultDependencies="yes", Slice=module._DEFAULT_SLICE,
        Wants="tmp.mount", Requires="sysinit.target " + module._DEFAULT_SLICE, Conflicts="shutdown.target",
        RequiresMountsFor="/opt/pdi/current /var/tmp", TriggeredBy=module._timer_units()[key],
        After="sysinit.target basic.target tmp.mount systemd-tmpfiles-setup.service network-online.target " +
              module._DEFAULT_SLICE, Before="shutdown.target", ConditionResult="yes", AssertResult="yes",
        ActiveState="inactive", SubState="dead", Job="0", Result="success", ExecMainCode="1",
        ExecMainStatus="0", ExecMainStartTimestampMonotonic="10", ExecMainExitTimestampMonotonic="20",
        InvocationID="1" * 32)
    return values


def timer_values(key):
    unit = module._timer_units()[key]
    return dict(Id=unit, LoadState="loaded", FragmentPath=f"/etc/systemd/system/{unit}",
        DropInPaths="", Transient="no", NeedDaemonReload="no", ActiveState="inactive",
        SubState="dead", Unit=module._SERVICE_UNITS[key], Job="0")


def show(values):
    return "".join(f"{name}={value}\n" for name, value in values.items())


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.services = {key: service_values(key) for key in KEYS}
        self.timers = {key: timer_values(key) for key in KEYS}
        self.enabled = {key: (1, "disabled\n") for key in KEYS}
        self.active = {key: (3, "inactive\n") for key in KEYS}
        self.manager = {"Version": "255", "Virtualization": "kvm", "SystemState": "running",
                        "UnitPath": " ".join(module._UNIT_LOAD_ROOTS)}
        self.failures = {}
        self.after_start = {}
        self.fresh = True
        self.clear_stale = True
        self.p3c_healthy = True
        self.p3c_revision = ""
        self.wait_on_start = None
        self.resume_start = None

    def __call__(self, argv, **kwargs):
        argv = tuple(argv)
        assert argv[0] == "/usr/bin/systemctl", "no real Git/systemd call is allowed in fake tests"
        self.calls.append((argv, kwargs))
        assert argv[1:4] == module._FLAGS
        verb = argv[4]
        unit = argv[5] if len(argv) > 5 and not argv[5].startswith("--") else None
        failure = self.failures.get((verb, unit))
        if isinstance(failure, BaseException):
            raise failure
        if failure is not None:
            return subprocess.CompletedProcess(argv, failure, "", CANARY)
        reverse_services = {unit: key for key, unit in module._SERVICE_UNITS.items()}
        reverse_timers = {unit: key for key, unit in module._timer_units().items()}
        code, stdout = 0, ""
        if verb == "daemon-reload":
            if self.clear_stale:
                for values in (*self.services.values(), *self.timers.values()):
                    values["NeedDaemonReload"] = "no"
        elif unit is None:
            assert verb == "show"
            stdout = show(self.manager)
        elif unit in reverse_services:
            key = reverse_services[unit]
            if verb == "start":
                if self.wait_on_start:
                    self.wait_on_start.set()
                    assert self.resume_start.wait(5)
                if self.fresh:
                    self.services[key].update(ExecMainStartTimestampMonotonic="1100",
                        ExecMainExitTimestampMonotonic="1200", InvocationID="2" * 32)
                self.services[key].update(self.after_start)
            elif verb == "stop":
                self.services[key].update(ActiveState="inactive", SubState="dead", Job="0")
            else:
                assert verb == "show"
                stdout = show(self.services[key])
        elif unit in reverse_timers:
            key = reverse_timers[unit]
            if verb == "is-enabled":
                code, stdout = self.enabled[key]
            elif verb == "is-active":
                code, stdout = self.active[key]
            else:
                assert verb == "show"
                stdout = show(self.timers[key])
        else:
            assert unit in module._p3c_units() and verb in {"show", "is-active", "is-enabled"}
            template = unit.endswith("@.service")
            if verb == "show":
                stdout = show(dict(Id=unit, LoadState="loaded", ActiveState="inactive" if template else "active",
                    SubState="dead" if template else "waiting", UnitFileState="static" if template else "enabled",
                    FragmentPath=f"/etc/systemd/system/{unit}" + self.p3c_revision))
            elif verb == "is-enabled":
                code, stdout = (0, "static\n") if template else ((0, "enabled\n") if self.p3c_healthy else (1, "disabled\n"))
            else:
                code, stdout = (3, "inactive\n") if template else ((0, "active\n") if self.p3c_healthy else (3, "inactive\n"))
        return subprocess.CompletedProcess(argv, code, stdout, CANARY)

    def mutations(self):
        return [argv for argv, _ in self.calls if argv[4] in {"start", "stop", "daemon-reload"}]


@pytest.fixture
def rig(monkeypatch):
    runner = FakeRunner()
    monkeypatch.setattr(module.subprocess, "run", runner)
    monkeypatch.setattr(module, "_trusted", lambda *_, **__: True)
    facts = {"boot": "11111111-2222-4333-8444-555555555555", "namespaces": {"pid": "pid:[1]"},
             "executable_sha256": H, "peer": (1, 0, 0)}
    monkeypatch.setattr(module, "_manager_os_facts", lambda: dict(facts))
    assets = module._Assets(H, module._template(TEMPLATE))
    monkeypatch.setattr(module, "_read_assets", lambda _: assets)
    monkeypatch.setattr(module, "_verify_candidate", lambda _: H)
    monkeypatch.setattr(module, "_current_candidate", lambda _: None)
    monkeypatch.setattr(module, "_dependency_directories", lambda _: None)
    # Run the actual frozen P3C algorithm over the same injected transport.
    frozen = ProductionReadOnlySystemdStateProvider(runner=module._p3c_read_adapter).snapshot(post_install=True)
    evidence = phase_a()
    baseline = replace(evidence.invariant_baseline, p3c_systemd_fingerprint=frozen.p3c_fingerprint)
    evidence = replace(evidence, invariant_baseline=baseline, p3c_systemd_fingerprint=frozen.p3c_fingerprint)
    # Rebuild through the frozen builder to avoid forging a self-hash.
    from pdi.production_ops.p3d_wp8_contracts import WP8PhaseAEvidenceV1
    evidence = WP8PhaseAEvidenceV1.build(**{
        name: getattr(evidence, name) for name in inspect.signature(WP8PhaseAEvidenceV1.build).parameters})
    runner.calls.clear()
    monkeypatch.setattr(module.time, "monotonic_ns", lambda: 1_000_000 if not any(
        argv[4] == "start" for argv, _ in runner.calls) else 2_000_000)
    backend = module.WP8ProductionSystemdBackend(evidence)
    return SimpleNamespace(backend=backend, runner=runner, evidence=evidence, facts=facts, assets=assets)


def test_exact_api_and_inert_construction(rig, monkeypatch):
    assert {name for name, member in inspect.getmembers(module.WP8ProductionSystemdBackend, inspect.isfunction)
            if not name.startswith("_")} == PUBLIC
    assert set(inspect.signature(module.WP8ProductionSystemdBackend).parameters) == {"phase_a_evidence"}
    module.WP8ProductionSystemdBackend(rig.evidence)
    assert rig.runner.calls == []
    assert module.__all__ == ["WP8ProductionSystemdBackend"]


def test_import_inert(monkeypatch):
    source = inspect.getsource(module)
    isolated = ModuleType(module.__package__ + ".isolated_import")
    isolated.__package__ = module.__package__
    monkeypatch.setitem(sys.modules, isolated.__name__, isolated)
    def forbidden(*_, **__):
        pytest.fail("import performed IO")
    monkeypatch.setattr(module.subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(module.os, "open", forbidden)
    exec(compile(source, "<isolated-inert-import>", "exec"), isolated.__dict__)
    assert isolated.__all__ == ["WP8ProductionSystemdBackend"]


def test_static_authority_surface():
    tree = ast.parse(inspect.getsource(module))
    forbidden_imports = {"sqlalchemy", "pdi.database", "requests", "httpx", "psycopg"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name not in forbidden_imports for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden_imports
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"write_text", "write_bytes", "mkdir", "unlink", "chmod", "chown",
                                          "commit", "create_engine", "flock", "Popen"}
    source = inspect.getsource(module.WP8ProductionSystemdBackend)
    for forbidden in ("enable_timer", "disable_timer", "activate", "apply", "cutover", "batch_start", "run_systemctl"):
        assert f"def {forbidden}" not in source


@pytest.mark.parametrize("key", ("gmail", "enrichment.gmail", "integration-test", "*", "", None,
                                   "pdi-scoped-pipeline@enrichment.local.service", "enrichment.local"))
@pytest.mark.parametrize("method", ("start_service", "verify_service_contract"))
def test_unknown_pipeline_refused_before_io(rig, key, method):
    with pytest.raises(WP8ContractError):
        getattr(rig.backend, method)(key)
    assert not rig.runner.calls


def test_exact_canonical_unit_generation():
    assert tuple(module._SERVICE_UNITS) == KEYS and len(KEYS) == 6
    for key in KEYS:
        assert module._SERVICE_UNITS[key] == f"pdi-scoped-pipeline@{key}.service"


@pytest.mark.parametrize("command_kind", ("enable", "disable", "restart", "mask", "unmask", "start", "show"))
def test_no_arbitrary_verb_algebra(command_kind):
    with pytest.raises(WP8ContractError):
        module._command(command_kind, KEYS[0])


@pytest.mark.parametrize("command_kind", tuple(module._Request))
def test_every_command_uses_fixed_transport(rig, monkeypatch, command_kind):
    for name, value in {"PATH": "/evil", "DATABASE__URL": CANARY, "NEXTCLOUD__PASSWORD": CANARY,
                        "IMMICH__API_KEY": CANARY, "SYSTEMD_BUS_ADDRESS": CANARY,
                        "DBUS_SYSTEM_BUS_ADDRESS": CANARY}.items():
        monkeypatch.setenv(name, value)
    key = (None if command_kind in {module._Request.MANAGER, module._Request.RELOAD} else
           module._p3c_units()[0] if command_kind.name.startswith("P3C") else KEYS[0])
    module._systemctl(command_kind, key)
    argv, kwargs = rig.runner.calls[-1]
    assert argv[:4] == ("/usr/bin/systemctl", "--system", "--no-pager", "--no-ask-password")
    assert argv[4] in {"show", "is-active", "is-enabled", "start", "stop", "daemon-reload"}
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["timeout"] == (1800 if argv[4] == "start" else 90 if argv[4] == "stop" else 30)
    assert not any(arg.startswith(("--machine", "--host", "--root", "--user")) for arg in argv)
    assert not any("Environment=" in arg or "Environment," in arg for arg in argv)


@pytest.mark.parametrize("command_kind", tuple(module._Request))
def test_arbitrary_unit_or_flags_not_accepted(rig, command_kind):
    with pytest.raises(WP8ContractError):
        module._systemctl(command_kind, "--machine=foreign")
    assert not rig.runner.calls


def test_untrusted_systemctl_binary_fails_before_exec(rig, monkeypatch):
    monkeypatch.setattr(module, "_trusted", lambda *_, **__: False)
    with pytest.raises(WP8ContractError):
        module._systemctl(module._Request.RELOAD)
    assert not rig.runner.calls


@pytest.mark.parametrize("virtualization", ("", "kvm", "vmware"))
def test_valid_host_manager_shape(rig, virtualization):
    rig.runner.manager["Virtualization"] = virtualization
    identity = rig.backend.manager_identity()
    assert len(identity.fingerprint) == len(identity.boot_fingerprint) == 64
    assert identity.host_class == ("FULL_VM" if virtualization else "BARE_METAL")
    assert CANARY not in repr(identity)


@pytest.mark.parametrize("field,value", (("Virtualization", "systemd-nspawn"), ("Virtualization", "docker"),
    ("Virtualization", "unknown"), ("Version", ""), ("SystemState", "starting")))
def test_manager_query_fail_closed(rig, field, value):
    rig.runner.manager[field] = value
    with pytest.raises(WP8ContractError) as exc:
        rig.backend.manager_identity()
    assert exc.value.code is WP8FailureCode.SYSTEMD_MANAGER_INVALID


def test_manager_query_error_not_proof(rig):
    rig.runner.failures[("show", None)] = 1
    with pytest.raises(WP8ContractError):
        rig.backend.manager_identity()


@pytest.mark.parametrize("field", ("boot", "executable_sha256", "namespaces"))
def test_manager_drift_rejected(rig, field):
    rig.backend.manager_identity()
    rig.facts[field] = "different"
    with pytest.raises(WP8ContractError):
        rig.backend.manager_identity()


def test_unrelated_running_degraded_transition_not_identity_change(rig):
    before = rig.backend.manager_identity()
    rig.runner.manager["SystemState"] = "degraded"
    assert rig.backend.manager_identity() == before


@pytest.mark.parametrize("field,value", (
    ("Id", "foreign.service"), ("LoadState", "masked"), ("LoadState", "not-found"),
    ("FragmentPath", "/run/systemd/system/foreign.service"), ("DropInPaths", "/run/evil.conf"),
    ("Transient", "yes"), ("NeedDaemonReload", "yes"), ("User", "root"), ("Group", "root"),
    ("Type", "simple"), ("WorkingDirectory", "/tmp"), ("EnvironmentFiles", "/tmp/fake.env (ignore_errors=no)"),
    ("ExecStartPre", "foreign"), ("ExecStartPost", "foreign"), ("ExecStop", "foreign"),
    ("ExecStopPost", "foreign"), ("ExecCondition", "foreign"), ("Restart", "always"),
    ("OnFailure", "pdi-p3c-writer@foreign.service"), ("OnSuccess", "foreign.service"),
    ("PartOf", "foreign.service"), ("BindsTo", "foreign.service"), ("ConsistsOf", "foreign.service"),
    ("PropagatesStopTo", "pdi-p3c-writer@foreign.service"), ("FailureAction", "reboot"),
    ("SuccessAction", "reboot"), ("NoNewPrivileges", "no"), ("PrivateTmp", "no"),
    ("ProtectSystem", "full"), ("ProtectHome", "no"), ("ReadWritePaths", "/"),
    ("TimeoutStartUSec", "1min"), ("TimeoutStopUSec", "infinity"), ("KillMode", "process"),
    ("StandardOutput", "journal"), ("StandardError", "journal"), ("RemainAfterExit", "yes"),
))
def test_service_contract_drift_rejected(rig, field, value):
    rig.runner.services[KEYS[0]][field] = value
    with pytest.raises(WP8ContractError):
        rig.backend.verify_service_contract(KEYS[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("key", KEYS)
def test_exact_service_contract(rig, key):
    assert len(rig.backend.verify_service_contract(key)) == 64
    assert not rig.runner.mutations()


@pytest.mark.parametrize("replacement", (" -m evil", " --extra", " ; arbitrary=evil", " } { path=/bin/evil"))
def test_execstart_not_substring_matching(rig, replacement):
    rig.runner.services[KEYS[0]]["ExecStart"] = rig.runner.services[KEYS[0]]["ExecStart"].replace(
        " ; ignore_errors=no", replacement + " ; ignore_errors=no")
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("helper,code", (("_read_assets", WP8FailureCode.SERVICE_CONTRACT_INVALID),
                                        ("_verify_candidate", WP8FailureCode.CURRENT_DRIFT)))
def test_authority_failure_never_starts(rig, monkeypatch, helper, code):
    def reject(*_):
        module._fail(code)
    monkeypatch.setattr(module, helper, reject)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


def test_context_drift_during_start_refused(rig, monkeypatch):
    seen = 0
    def runtime(_):
        nonlocal seen
        seen += 1
        return H if seen < 3 else "2" * 64
    monkeypatch.setattr(module, "_verify_candidate", runtime)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert len([argv for argv in rig.runner.mutations() if argv[4] == "start"]) == 1


@pytest.mark.parametrize("field,value,key_index", (("ActiveState", "active", 0), ("ActiveState", "active", 3),
    ("ActiveState", "failed", 0), ("SubState", "failed", 0), ("Job", "123", 0)))
def test_start_prerequisites_reject_overlap_or_pending_job(rig, field, value, key_index):
    rig.runner.services[KEYS[key_index]][field] = value
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("failure", (1, subprocess.TimeoutExpired("fixed", 1800, output=CANARY), OSError(CANARY)))
def test_start_failure_no_retry_and_safe_error(rig, failure):
    rig.runner.failures[("start", module._SERVICE_UNITS[KEYS[0]])] = failure
    with pytest.raises(WP8ContractError) as caught:
        rig.backend.start_service(KEYS[0])
    assert CANARY not in str(caught.value) and caught.value.__suppress_context__
    assert len(rig.runner.mutations()) == 1
    assert caught.value.outcome == (module._Outcome.TIMEOUT if isinstance(failure, subprocess.TimeoutExpired)
                                   else module._Outcome.COMMAND_FAILED)


@pytest.mark.parametrize("changes", (
    {"Result": "exit-code"}, {"ExecMainStatus": "7"}, {"ExecMainCode": "2"},
    {"ActiveState": "active"}, {"ActiveState": "failed"}, {"SubState": "exited"},
    {"Result": "skipped"}, {"Job": "123"}, {"ExecMainStartTimestampMonotonic": "0"},
    {"ExecMainExitTimestampMonotonic": "0"}, {"InvocationID": "1" * 32},
    {"ExecMainStartTimestampMonotonic": "999"}, {"ExecMainExitTimestampMonotonic": "3000"},
))
def test_start_rc_zero_is_not_sufficient(rig, changes):
    rig.runner.after_start = changes
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert len(rig.runner.mutations()) == 1


def test_stale_success_record_rejected(rig):
    rig.runner.fresh = False
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert len(rig.runner.mutations()) == 1


def test_valid_fresh_oneshot_service_result_is_frozen_proof_compatible(rig):
    result = rig.backend.start_service(KEYS[0])
    assert result.outcome is module._Outcome.SUCCESS and result.final_state == "INACTIVE"
    assert CANARY not in repr(result) and len(result.service_result_fingerprint) == 64
    proof = WP8PipelineRunProofV1.from_mapping(dict(pipeline_key=KEYS[0], pipeline_run_id=OPERATION,
        status="COMPLETED", service_result_fingerprint=result.service_result_fingerprint,
        business_effect_fingerprint=H, completed_enrichment_count=0, current_statement_count=0))
    assert proof.service_result_fingerprint == result.service_result_fingerprint
    assert rig.evidence.runtime_pipeline_coverage == "0/6"  # no runtime DB proof manufactured
    assert [argv[4] for argv in rig.runner.mutations()] == ["start"]


def test_single_flight_refuses_concurrent_start_without_second_command(rig):
    entered, resume = threading.Event(), threading.Event()
    rig.runner.wait_on_start, rig.runner.resume_start = entered, resume
    results = []
    worker = threading.Thread(target=lambda: results.append(rig.backend.start_service(KEYS[0])))
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(WP8ContractError) as caught:
            rig.backend.start_service(KEYS[1])
        assert caught.value.outcome is module._Outcome.BUSY
    finally:
        resume.set()
        worker.join(5)
    assert not worker.is_alive() and len(results) == 1
    assert len(rig.runner.mutations()) == 1


def test_timer_quiet_exact_and_read_only(rig):
    assert rig.backend.verify_timers_quiet().timer_state == "DISABLED_INACTIVE"
    assert not rig.runner.mutations()


@pytest.mark.parametrize("kind,code,value", (("enabled", 0, "enabled\n"), ("active", 0, "active\n"),
    ("enabled", 1, "not-found\n"), ("enabled", 1, "masked\n"), ("active", 4, "unknown\n"),
    ("enabled", 4, "disabled\n"), ("active", 1, "inactive\n"), ("active", 3, "inactive\nunknown\n")))
def test_timer_state_not_any_nonzero(rig, kind, code, value):
    getattr(rig.runner, kind)[KEYS[0]] = (code, value)
    with pytest.raises(WP8ContractError):
        rig.backend.verify_timers_quiet()
    assert not rig.runner.mutations()


@pytest.mark.parametrize("field,value", (("Id", "foreign.timer"), ("LoadState", "not-found"),
    ("LoadState", "masked"), ("FragmentPath", "/run/fake.timer"), ("Unit", "foreign.service"),
    ("NeedDaemonReload", "yes")))
def test_timer_loaded_authority_required(rig, field, value):
    rig.runner.timers[KEYS[0]][field] = value
    with pytest.raises(WP8ContractError):
        rig.backend.verify_timers_quiet()


def test_p3c_fingerprint_identical_to_frozen_algorithm(rig):
    actual = rig.backend.snapshot_p3c()
    frozen = ProductionReadOnlySystemdStateProvider(runner=module._p3c_read_adapter).snapshot(post_install=True)
    assert actual.fingerprint == frozen.p3c_fingerprint == rig.evidence.p3c_systemd_fingerprint
    assert actual.p3c_state == "UNCHANGED_HEALTHY" and not rig.runner.mutations()
    assert not {"ExecMainPID", "InvocationID", "ExecMainStartTimestamp"} & set(module._STABLE_PROPERTIES)


@pytest.mark.parametrize("case", ("unhealthy", "authority_changed"))
def test_p3c_wrong_health_or_stable_authority_rejected(rig, case):
    if case == "unhealthy":
        rig.runner.p3c_healthy = False
    else:
        rig.runner.p3c_revision = ".foreign"
    with pytest.raises(WP8ContractError):
        rig.backend.snapshot_p3c()
    assert not rig.runner.mutations()


@pytest.mark.parametrize("verb", ("start", "stop", "restart", "enable", "disable", "daemon-reload"))
def test_frozen_provider_adapter_cannot_be_mutation_passthrough(rig, verb):
    with pytest.raises(WP8ContractError):
        module._p3c_read_adapter((module._SYSTEMCTL, verb, module._p3c_units()[0]))
    assert not rig.runner.calls


@pytest.mark.parametrize("index", (0, 3, 5))
@pytest.mark.parametrize("failure", (1, subprocess.TimeoutExpired("fixed", 90, output=CANARY), RuntimeError(CANARY)))
def test_cleanup_attempts_every_service_after_first_middle_last_failure(rig, index, failure):
    rig.runner.failures[("stop", module._SERVICE_UNITS[KEYS[index]])] = failure
    result = rig.backend.stop_all_services()
    assert tuple(item.pipeline_key for item in result.attempts) == KEYS
    assert result.stop_failure_count == 1 and result.service_state == "INACTIVE"
    assert result.timer_state == "DISABLED_INACTIVE" and result.p3c_state == "UNCHANGED_HEALTHY"
    assert [argv[-1] for argv in rig.runner.mutations()] == list(module._SERVICE_UNITS.values())
    assert all(argv[4] == "stop" for argv in rig.runner.mutations())
    assert CANARY not in repr(result)
    last_stop = max(n for n, (argv, _) in enumerate(rig.runner.calls) if argv[4] == "stop")
    post_shows = {argv[5] for argv, _ in rig.runner.calls[last_stop + 1:] if argv[4] == "show" and len(argv) > 5}
    assert set(module._SERVICE_UNITS.values()) <= post_shows
    cleanup = WP8CleanupProofV1.build(rehearsal_operation_id=OPERATION, candidate_sha=rig.evidence.candidate_sha,
        phase_a_context_fingerprint=rig.evidence.phase_a_context_fingerprint,
        stop_failure_count=result.stop_failure_count, service_state=result.service_state,
        timer_state=result.timer_state, p3c_state=result.p3c_state, result=WP8CleanupResult.FAIL)
    assert cleanup.result is WP8CleanupResult.FAIL
    with pytest.raises(WP8ContractError):
        WP8CleanupProofV1.build(rehearsal_operation_id=OPERATION, candidate_sha=rig.evidence.candidate_sha,
            phase_a_context_fingerprint=rig.evidence.phase_a_context_fingerprint,
            stop_failure_count=result.stop_failure_count, service_state=result.service_state,
            timer_state=result.timer_state, p3c_state=result.p3c_state, result=WP8CleanupResult.PASS)


def test_cleanup_success_and_retry_facts(rig):
    rig.runner.failures[("stop", module._SERVICE_UNITS[KEYS[0]])] = 1
    assert rig.backend.stop_all_services().stop_failure_count == 1
    rig.runner.failures.clear()
    result = rig.backend.stop_all_services()
    assert result.stop_failure_count == 0
    proof = WP8CleanupProofV1.build(rehearsal_operation_id=OPERATION, candidate_sha=rig.evidence.candidate_sha,
        phase_a_context_fingerprint=rig.evidence.phase_a_context_fingerprint,
        stop_failure_count=0, service_state=result.service_state, timer_state=result.timer_state,
        p3c_state=result.p3c_state, result=WP8CleanupResult.PASS)
    assert proof.stop_attempted_pipeline_keys == KEYS


def test_cleanup_independent_query_error_is_not_inactive(rig, monkeypatch):
    # The failure is deliberately in the independent FINAL observation, not
    # the newly required pre-stop authority query (tested separately below).
    def transport(argv, **kwargs):
        if len([call for call in rig.runner.mutations() if call[4] == "stop"]) == 6:
            rig.runner.failures[("show", module._SERVICE_UNITS[KEYS[2]])] = 1
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(module.subprocess, "run", transport)
    result = rig.backend.stop_all_services()
    assert len(result.attempts) == 6 and result.stop_failure_count == 0
    assert result.service_state == "NOT_CONFIRMED" and result.attempts[2].final_state == "NOT_CONFIRMED"


def test_cleanup_does_not_disable_drifted_timer_or_mutate_unhealthy_p3c(rig):
    rig.runner.enabled[KEYS[0]] = (0, "enabled\n")
    rig.runner.p3c_healthy = False
    result = rig.backend.stop_all_services()
    assert result.timer_state == result.p3c_state == "NOT_CONFIRMED"
    assert all(argv[4] == "stop" and argv[5] in module._SERVICE_UNITS.values()
               for argv in rig.runner.mutations())


def test_cleanup_manager_drift_never_redirects(rig):
    rig.backend.manager_identity()
    rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
    result = rig.backend.stop_all_services()
    assert len(result.attempts) == result.stop_failure_count == 6
    assert result.service_state == "NOT_CONFIRMED" and not rig.runner.mutations()


@pytest.mark.parametrize("index", range(6))
def test_verify_inactive_does_not_accept_unknown_unit(rig, index):
    rig.runner.services[KEYS[index]]["LoadState"] = "not-found"
    with pytest.raises(WP8ContractError):
        rig.backend.verify_all_services_inactive()
    shows = {argv[5] for argv, _ in rig.runner.calls if argv[4] == "show" and len(argv) > 5}
    assert set(module._SERVICE_UNITS.values()) <= shows and not rig.runner.mutations()


def test_reload_rechecks_loaded_units_but_never_runs_workload(rig):
    for values in (*rig.runner.services.values(), *rig.runner.timers.values()):
        values["NeedDaemonReload"] = "yes"
    assert len(rig.backend.daemon_reload()) == 64
    assert [argv[4] for argv in rig.runner.mutations()] == ["daemon-reload"]


@pytest.mark.parametrize("case", ("nonzero", "timeout", "still_stale", "unit_drift"))
def test_reload_exit_zero_not_sufficient(rig, case):
    if case == "nonzero":
        rig.runner.failures[("daemon-reload", None)] = 1
    elif case == "timeout":
        rig.runner.failures[("daemon-reload", None)] = subprocess.TimeoutExpired("fixed", 30)
    elif case == "still_stale":
        rig.runner.services[KEYS[0]]["NeedDaemonReload"] = "yes"
        rig.runner.clear_stale = False
    else:
        rig.runner.services[KEYS[0]]["User"] = "root"
    with pytest.raises(WP8ContractError):
        rig.backend.daemon_reload()
    assert all(argv[4] == "daemon-reload" for argv in rig.runner.mutations())


def test_no_persistence_or_external_workload_calls(rig, monkeypatch, tmp_path):
    before = tuple(tmp_path.iterdir())
    def forbidden(*_, **__):
        pytest.fail("persistence or DB call")
    for method in ("write_bytes", "write_text", "mkdir", "unlink", "rename"):
        monkeypatch.setattr(Path, method, forbidden)
    monkeypatch.setattr(module.os, "open", forbidden)
    rig.backend.manager_identity()
    rig.backend.verify_service_contract(KEYS[0])
    rig.backend.verify_timers_quiet()
    rig.backend.snapshot_p3c()
    rig.backend.start_service(KEYS[0])
    rig.backend.stop_all_services()
    rig.backend.daemon_reload()
    assert tuple(tmp_path.iterdir()) == before
    assert all(argv[4] != "start" or argv[5].endswith(".service") for argv in rig.runner.mutations())
    assert rig.evidence.runtime_pipeline_coverage == "0/6"


@pytest.fixture
def manager_os(monkeypatch):
    # Execute the real OS verifier over injected proc/socket facts, never the host manager.
    state = dict(uid=0, comm="systemd", executable=Path("/usr/lib/systemd/systemd"), trusted=True,
                 root=True, boot="11111111-2222-4333-8444-555555555555", container=False,
                 peer=(1, 0, 0), socket_mode=stat.S_IFSOCK | 0o600, socket_uid=0, socket_gid=0,
                 namespace_mismatch=None, connected=[])
    original_exists, original_read = Path.exists, Path.read_bytes
    def read_text(path, *_, **__):
        return {"/proc/1/comm": state["comm"], "/proc/sys/kernel/random/boot_id": state["boot"]}[str(path)]
    def resolve(path, *_, **__):
        assert str(path) == "/proc/1/exe"
        return state["executable"]
    def readlink(path):
        name = str(path).rsplit("/", 1)[-1]
        return f"{name}:[2]" if state["namespace_mismatch"] == name and "/self/" in str(path) else f"{name}:[1]"
    class Peer:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def settimeout(self, timeout):
            assert timeout == 30
        def connect(self, path):
            state["connected"].append(path)
        def getsockopt(self, *args):
            assert args == (socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            return struct.pack("3i", *state["peer"])
    monkeypatch.setattr(module.os, "geteuid", lambda: state["uid"])
    monkeypatch.setattr(Path, "exists", lambda path: state["container"] if str(path) == "/run/systemd/container" else original_exists(path))
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"synthetic-systemd" if path == state["executable"] else original_read(path))
    monkeypatch.setattr(Path, "lstat", lambda _: SimpleNamespace(st_mode=state["socket_mode"],
                                                                st_uid=state["socket_uid"], st_gid=state["socket_gid"]))
    monkeypatch.setattr(module, "_trusted", lambda *_, **__: state["trusted"])
    monkeypatch.setattr(module.os, "readlink", readlink)
    monkeypatch.setattr(module.os.path, "samefile", lambda a, b: state["root"] and (a, b) == ("/proc/1/root", "/"))
    monkeypatch.setattr(module.socket, "socket", lambda *args: Peer())
    return state


def test_real_os_verifier_valid_injected_local_manager(manager_os):
    result = module._manager_os_facts()
    assert result["peer"] == (1, 0, 0) and len(result["executable_sha256"]) == 64
    assert manager_os["connected"] == ["/run/systemd/private"]


@pytest.mark.parametrize("field,value", (("uid", 1000), ("comm", "python"),
    ("executable", Path("/tmp/evil")), ("trusted", False), ("root", False), ("boot", "not-uuid"),
    ("container", True), ("peer", (100, 0, 0)), ("peer", (1, 1000, 1000)),
    ("socket_mode", stat.S_IFREG | 0o600), ("socket_mode", stat.S_IFLNK | 0o777),
    ("socket_uid", 1000), ("socket_gid", 1000),
    ("namespace_mismatch", "pid"), ("namespace_mismatch", "mnt"), ("namespace_mismatch", "user"),
    ("namespace_mismatch", "time")))
def test_actual_manager_os_verifier_fail_closed(manager_os, field, value):
    manager_os[field] = value
    with pytest.raises(WP8ContractError) as caught:
        module._manager_os_facts()
    assert caught.value.code is WP8FailureCode.SYSTEMD_MANAGER_INVALID


@pytest.fixture
def asset_tree(tmp_path, monkeypatch):
    from pdi.production_ops import p3d_pre_rehearsal_evidence as wp6
    from pdi.production_ops import p3d_wp8_preflight as phase_a_module
    from pdi.production_ops.p3d_inert_asset_install import InertAssetPolicy, InstallMode
    from pdi.production_ops.p3d_preparation_contracts import asset_installation_fingerprint
    from tests.test_p3d_inert_asset_install import asset_content
    from tests.test_p3d_pre_rehearsal_evidence import _marker
    root = tmp_path / "trusted"
    root.mkdir()
    policy = InertAssetPolicy(InstallMode.QUALIFICATION, root, 0, 0, 65534, 65534)
    for logical, payload in asset_content().items():
        path = policy.physical(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o600 if logical.endswith(".env") else 0o644)
    operation_root = policy.gate_c_root / phase_a().gate_c_operation_id
    operation_root.mkdir(parents=True)
    marker_path = operation_root / "complete.json"
    marker_path.write_bytes(b"synthetic protected complete marker")
    marker_path.chmod(0o600)
    root.chmod(0o755)
    for directory in root.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
    # Only stat identity is synthetic; no production-visible ownership bypass.
    original_lstat, original_fstat = Path.lstat, os.fstat
    overrides = {}
    def metadata(actual, path):
        fields = dict(st_mode=actual.st_mode, st_uid=0, st_gid=0, st_ino=actual.st_ino,
                      st_size=actual.st_size, st_mtime_ns=actual.st_mtime_ns)
        fields.update(overrides.get(path, {}))
        return SimpleNamespace(**fields)
    monkeypatch.setattr(Path, "lstat", lambda path: metadata(original_lstat(path), path)
                        if path == root or root in path.parents else original_lstat(path))
    def fstat(fd):
        path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        return metadata(original_fstat(fd), path) if root in path.parents else original_fstat(fd)
    monkeypatch.setattr(os, "fstat", fstat)
    manifest = wp6._fresh_installed_manifest(policy)
    fingerprint = asset_installation_fingerprint(manifest)
    marker = replace(_marker(), installed_file_manifest=manifest, unit_profile_asset_fingerprint=fingerprint,
                     preparation_operation_id=phase_a().gate_c_operation_id)
    marker_hash = contract_fingerprint(marker)
    a = phase_a()
    values = {name: getattr(a, name) for name in inspect.signature(type(a).build).parameters}
    values.update(gate_c_marker_fingerprint=marker_hash, unit_profile_asset_fingerprint=fingerprint,
        registry_fingerprint=marker.registry_fingerprint, db_identity_fingerprint=marker.db_identity_fingerprint,
        enabled_scope_fingerprint=marker.enabled_scope_fingerprint,
        p3c_systemd_fingerprint=marker.p3c_systemd_state_after_fingerprint,
        invariant_baseline=replace(a.invariant_baseline, unit_profile_asset_fingerprint=fingerprint,
            registry_fingerprint=marker.registry_fingerprint, db_identity_fingerprint=marker.db_identity_fingerprint,
            enabled_scope_fingerprint=marker.enabled_scope_fingerprint,
            p3c_systemd_fingerprint=marker.p3c_systemd_state_after_fingerprint))
    a = type(a).build(**values)
    seen = []
    monkeypatch.setattr(InertAssetPolicy, "production", classmethod(lambda _: policy))
    def explicit(actual_policy, operation, **kwargs):
        seen.append((actual_policy, operation, kwargs))
        assert actual_policy is policy and operation == a.gate_c_operation_id
        assert kwargs["candidate"] == a.candidate_sha
        return object(), (), operation_root
    monkeypatch.setattr(wp6, "_explicit_gate", explicit)
    monkeypatch.setattr(wp6, "_read_gate_c_marker", lambda p, i: (marker, marker_hash,
        wp6._read_protected_bytes(marker_path, policy=p, mode=0o600, gid=0), operation_root))
    monkeypatch.setattr(phase_a_module, "_gate_binding", lambda *args: a.gate_c_authority_binding_fingerprint)
    return SimpleNamespace(policy=policy, evidence=a, marker=marker, overrides=overrides, seen=seen)


def test_actual_asset_reader_consumes_frozen_marker_and_manifest(asset_tree):
    result = module._read_assets(asset_tree.evidence)
    assert result.fingerprint == asset_tree.evidence.unit_profile_asset_fingerprint
    assert result.template == module._template(TEMPLATE)
    assert len(asset_tree.seen) == 1


@pytest.mark.parametrize("logical", (module._TEMPLATE, f"/etc/pdi/scoped/units/{KEYS[0]}.env"))
@pytest.mark.parametrize("kind", ("owner", "group", "mode", "parent", "symlink"))
def test_asset_reader_refuses_untrusted_owner_mode_parent_or_symlink(asset_tree, logical, kind):
    path = asset_tree.policy.physical(logical)
    if kind == "owner":
        asset_tree.overrides[path] = {"st_uid": 1000}
    elif kind == "group":
        asset_tree.overrides[path] = {"st_gid": 1000}
    elif kind == "mode":
        asset_tree.overrides[path] = {"st_mode": stat.S_IFREG | 0o666}
    elif kind == "parent":
        asset_tree.overrides[path.parent] = {"st_mode": stat.S_IFDIR | 0o775}
    else:
        asset_tree.overrides[path] = {"st_mode": stat.S_IFLNK | 0o777}
    with pytest.raises(WP8ContractError) as caught:
        module._read_assets(asset_tree.evidence)
    assert caught.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID


@pytest.mark.parametrize("logical", (module._TEMPLATE, f"/etc/pdi/scoped/units/{KEYS[3]}.env"))
def test_changed_installed_bytes_not_repaired(asset_tree, logical):
    path = asset_tree.policy.physical(logical)
    path.write_bytes(path.read_bytes() + b"# tampered\n")
    with pytest.raises(WP8ContractError):
        module._read_assets(asset_tree.evidence)
    assert path.read_bytes().endswith(b"# tampered\n")


@pytest.mark.parametrize("field", ("gate_c_marker_fingerprint", "gate_c_authority_binding_fingerprint",
                                   "unit_profile_asset_fingerprint", "registry_fingerprint", "enabled_scope_fingerprint"))
def test_asset_binding_not_caller_boolean(asset_tree, field):
    a = replace(asset_tree.evidence, **{field: "f" * 64})
    with pytest.raises(WP8ContractError):
        module._read_assets(a)


def test_actual_candidate_verifier_current_and_git_binding(tmp_path, monkeypatch):
    from pdi.production_ops import p3d_pre_rehearsal_evidence as wp6
    from pdi.production_ops import p3d_wp8_preflight as phase_a_module
    from pdi.production_ops import enrichment_cutover
    from pdi.production_ops.p3d_inert_asset_install import InertAssetPolicy, InstallMode, GIT_READ_ONLY_ENV
    from pdi.production_ops.p3d_preparation_contracts import SourceFileFingerprintEntryV1, source_release_fingerprint
    a = phase_a()
    policy = InertAssetPolicy(InstallMode.QUALIFICATION, tmp_path, 0, 0, 65534, 65534)
    release = policy.candidate_releases_root / a.candidate_sha
    release.mkdir(parents=True)
    path = release / "runtime.py"
    path.write_bytes(b"# exact synthetic runtime\n")
    path.chmod(0o644)
    fingerprint = source_release_fingerprint(a.candidate_sha, (
        SourceFileFingerprintEntryV1("runtime.py", "file", "0644", 0, 0, hashlib.sha256(path.read_bytes()).hexdigest()),))
    current_checks, git_calls = [], []
    monkeypatch.setattr(InertAssetPolicy, "production", classmethod(lambda _: policy))
    monkeypatch.setattr(wp6, "_current_target", lambda p, **kw: current_checks.append((p, kw)))
    monkeypatch.setattr(enrichment_cutover, "verify_release_immutability", lambda *args: True)
    monkeypatch.setattr(wp6, "_explicit_gate", lambda *args, **kw: (
        object(), (SimpleNamespace(evidence_fingerprints=(fingerprint,)),), tmp_path))
    monkeypatch.setattr(phase_a_module, "_gate_binding", lambda *args: a.gate_b_authority_binding_fingerprint)
    dirty = [False]
    def git(argv, **kwargs):
        git_calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, a.candidate_sha + "\n" if argv[-2:] == ("rev-parse", "HEAD")
                                           else " M runtime.py\n" if dirty[0] else "", CANARY)
    monkeypatch.setattr(module.subprocess, "run", git)
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "1")
    monkeypatch.setenv("GIT_DIR", "/foreign")
    assert module._verify_candidate(a) == fingerprint
    assert all(kw == {"expected_source": a.candidate_sha} for _, kw in current_checks)
    assert len(git_calls) == len(current_checks) == 2
    for argv, kwargs in git_calls:
        assert argv[0] == "/usr/bin/git" and argv[2] == str(release)
        assert kwargs["env"] == GIT_READ_ONLY_ENV and kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"
        assert kwargs["shell"] is False and kwargs["timeout"] == 30 and kwargs["stdin"] == subprocess.DEVNULL
    dirty[0] = True
    with pytest.raises(WP8ContractError) as caught:
        module._verify_candidate(a)
    assert caught.value.code is WP8FailureCode.CANDIDATE_RUNTIME_DRIFT
    def wrong_current(*_, **__):
        raise ValueError(CANARY)
    monkeypatch.setattr(wp6, "_current_target", wrong_current)
    with pytest.raises(WP8ContractError) as caught:
        module._verify_candidate(a)
    assert caught.value.code is WP8FailureCode.CURRENT_DRIFT and CANARY not in str(caught.value)


@pytest.mark.parametrize("relation", module._GRAPH_PROPERTIES)
@pytest.mark.parametrize("action", ("verify_service_contract", "start_service", "stop_all_services"))
def test_r3_extra_loaded_relationship_never_grants_mutation(rig, relation, action):
    key = KEYS[2]
    values = rig.runner.services[key]
    extra = "/unreviewed" if relation == "RequiresMountsFor" else "synthetic-unreviewed.service"
    values[relation] = (values[relation] + " " + extra).strip()
    if action == "stop_all_services":
        result = rig.backend.stop_all_services()
        assert result.stop_failure_count == 1 and result.service_state == "NOT_CONFIRMED"
        assert result.attempts[2].outcome is module._Outcome.EVIDENCE_REJECTED
        assert result.attempts[2].final_state == "NOT_CONFIRMED"
        assert [call[5] for call in rig.runner.mutations()] == [
            unit for other, unit in module._SERVICE_UNITS.items() if other != key]
        with pytest.raises(WP8ContractError):
            WP8CleanupProofV1.build(rehearsal_operation_id=OPERATION, candidate_sha=rig.evidence.candidate_sha,
                phase_a_context_fingerprint=rig.evidence.phase_a_context_fingerprint,
                stop_failure_count=result.stop_failure_count, service_state=result.service_state,
                timer_state=result.timer_state, p3c_state=result.p3c_state, result=WP8CleanupResult.PASS)
    else:
        with pytest.raises(WP8ContractError) as error:
            getattr(rig.backend, action)(key)
        assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID
        assert not rig.runner.mutations()
    assert CANARY not in repr(rig.runner.services[key])


@pytest.mark.parametrize("relation", ("PropagatesStopTo", "ConsistsOf", "RequiredBy", "RequisiteOf", "BoundBy"))
@pytest.mark.parametrize("target", (*module._p3c_units(), module._timer_units()[KEYS[0]], "synthetic-other.service"))
def test_r1_indirect_p3c_timer_stop_propagation_is_not_attempted(rig, relation, target):
    key = KEYS[0]
    rig.runner.services[key].update({relation: target, "ActiveState": "active", "SubState": "running"})
    result = rig.backend.stop_all_services()
    assert result.stop_failure_count == 1 and result.attempts[0].final_state == "NOT_CONFIRMED"
    assert [call[5] for call in rig.runner.mutations()] == list(module._SERVICE_UNITS.values())[1:]
    assert all(call[4] == "stop" and call[5] in module._SERVICE_UNITS.values() for call in rig.runner.mutations())
    assert not any(call[5] == module._SERVICE_UNITS[key] for call in rig.runner.mutations())
    assert not any(call[5] == target for call in rig.runner.mutations())


def test_r1_rechecks_each_target_instead_of_one_batch_authority(rig, monkeypatch):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4:6] == ("stop", module._SERVICE_UNITS[KEYS[0]]):
            rig.runner.services[KEYS[3]]["PropagatesStopTo"] = module._p3c_units()[0]
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    result = rig.backend.stop_all_services()
    assert result.stop_failure_count == 1 and result.attempts[3].final_state == "NOT_CONFIRMED"
    assert [call[5] for call in rig.runner.mutations()] == [
        unit for key, unit in module._SERVICE_UNITS.items() if key != KEYS[3]]


def test_r1_every_stop_is_preceded_by_its_own_current_authority(rig, monkeypatch):
    events = []
    def assets(_):
        events.append("assets")
        return rig.assets
    monkeypatch.setattr(module, "_read_assets", assets)
    monkeypatch.setattr(module, "_dependency_directories", lambda key: events.append(("directories", key)))
    def transport(argv, **kwargs):
        if argv[4] == "show" and argv[5] in module._SERVICE_UNITS.values():
            events.append(("show", argv[5]))
        elif argv[4] == "stop":
            events.append(("stop", argv[5]))
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(module.subprocess, "run", transport)
    result = rig.backend.stop_all_services()
    assert result.stop_failure_count == 0
    previous = 0
    for key in KEYS:
        index = events.index(("stop", module._SERVICE_UNITS[key]))
        assert "assets" in events[previous:index]
        assert ("directories", key) in events[previous:index]
        assert events[index - 1] == ("show", module._SERVICE_UNITS[key])
        previous = index + 1


@pytest.mark.parametrize("kind", ("asset_rejected", "show_failure", "manager_drift"))
def test_r1_authority_failure_is_not_a_stop_failure_after_mutation(rig, monkeypatch, kind):
    if kind == "asset_rejected":
        monkeypatch.setattr(module, "_read_assets", lambda _: module._fail(WP8FailureCode.SERVICE_CONTRACT_INVALID))
        unsafe = set(KEYS)
    elif kind == "show_failure":
        rig.runner.failures[("show", module._SERVICE_UNITS[KEYS[0]])] = 1
        unsafe = {KEYS[0]}
    else:
        def assets(_):
            rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
            return rig.assets
        monkeypatch.setattr(module, "_read_assets", assets)
        unsafe = set(KEYS)
    result = rig.backend.stop_all_services()
    assert result.stop_failure_count == len(unsafe) and result.service_state == "NOT_CONFIRMED"
    assert not any(call[5] == module._SERVICE_UNITS[key] for call in rig.runner.mutations() for key in unsafe)
    assert all(item.outcome is module._Outcome.EVIDENCE_REJECTED for item in result.attempts
               if item.pipeline_key in unsafe)


def test_r1_interrupted_stop_continues_without_claiming_clean_success(rig):
    rig.runner.failures[("stop", module._SERVICE_UNITS[KEYS[0]])] = KeyboardInterrupt(CANARY)
    result = rig.backend.stop_all_services()
    assert len(rig.runner.mutations()) == 6 and result.stop_failure_count == 1
    assert CANARY not in repr(result)


@pytest.mark.parametrize("timeline", ((1000, 1100, 1200, 1500, 2000), (20000, 24000, 28000, 32000, 40000)))
@pytest.mark.parametrize("fresh", (False, True))
def test_r2_final_fence_not_early_validation_fence(rig, monkeypatch, timeline, fresh):
    early, intervening_start, intervening_end, command_time, finish = timeline
    clock, verifications, events = [early], [0], []
    rig.runner.fresh = False
    def runtime(_):
        verifications[0] += 1
        events.append("slow_runtime")
        if verifications[0] == 2:
            rig.runner.services[KEYS[0]].update(ExecMainStartTimestampMonotonic=str(intervening_start),
                ExecMainExitTimestampMonotonic=str(intervening_end), InvocationID="2" * 32)
            clock[0] = command_time
        return H
    def monotonic():
        events.append(("fence", clock[0]))
        return clock[0] * 1000
    def assets(_):
        events.append("slow_assets")
        return rig.assets
    def directories(_):
        events.append("directory_scan")
    def transport(argv, **kwargs):
        if argv[4] == "start":
            events.append(("start", clock[0]))
            if fresh:
                rig.runner.after_start = dict(ExecMainStartTimestampMonotonic=str(command_time + 1),
                    ExecMainExitTimestampMonotonic=str(command_time + 2), InvocationID="3" * 32)
        result = rig.runner(argv, **kwargs)
        if argv[4] == "start":
            clock[0] = finish
        return result
    monkeypatch.setattr(module, "_verify_candidate", runtime)
    monkeypatch.setattr(module, "_read_assets", assets)
    monkeypatch.setattr(module, "_dependency_directories", directories)
    monkeypatch.setattr(module.time, "monotonic_ns", monotonic)
    monkeypatch.setattr(module.subprocess, "run", transport)
    if fresh:
        assert rig.backend.start_service(KEYS[0]).outcome is module._Outcome.SUCCESS
    else:
        with pytest.raises(WP8ContractError) as error:
            rig.backend.start_service(KEYS[0])
        assert error.value.code is WP8FailureCode.SERVICE_EXECUTION_FAILED
    index = events.index(("start", command_time))
    assert events[index - 1] == ("fence", command_time)
    assert len(rig.runner.mutations()) == 1  # no retry of a rejected/no-op request


@pytest.mark.parametrize("drift", ("overlap", "target_job", "other_job", "timer", "timer_job", "manager"))
def test_r2_drift_during_last_slow_validation_refused_before_start(rig, monkeypatch, drift):
    verifications = 0
    def runtime(_):
        nonlocal verifications
        verifications += 1
        if verifications == 2:
            if drift == "overlap":
                rig.runner.services[KEYS[3]].update(ActiveState="active", SubState="running")
            elif drift in {"target_job", "other_job"}:
                rig.runner.services[KEYS[0 if drift == "target_job" else 3]]["Job"] = "123"
            elif drift == "timer":
                rig.runner.enabled[KEYS[3]] = (0, "enabled\n")
            elif drift == "timer_job":
                rig.runner.timers[KEYS[3]]["Job"] = "123"
            else:
                rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
        return H
    monkeypatch.setattr(module, "_verify_candidate", runtime)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert verifications == 2 and not rig.runner.mutations()


def test_r2_final_current_drift_refused_before_start(rig, monkeypatch):
    monkeypatch.setattr(module, "_current_candidate", lambda _: module._fail(WP8FailureCode.CURRENT_DRIFT))
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service(KEYS[0])
    assert error.value.code is WP8FailureCode.CURRENT_DRIFT and not rig.runner.mutations()


@pytest.mark.parametrize("result_property", ("ConditionResult", "AssertResult"))
@pytest.mark.parametrize("value", ("no", "", "unknown"))
def test_r2_condition_assert_skip_even_with_fresh_success_is_failure(rig, result_property, value):
    rig.runner.after_start = {result_property: value}
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert len(rig.runner.mutations()) == 1


def test_r2_manager_drift_after_start_never_retries_or_accepts_fresh_result(rig, monkeypatch):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4] == "start":
            rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert len(rig.runner.mutations()) == 1


def test_r3_actual_systemctl_requested_projection_contains_all_closure_properties(rig, monkeypatch):
    rig.runner.services[KEYS[0]]["Wants"] += " synthetic-extra.service"
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4] == "show" and argv[5] == module._SERVICE_UNITS[KEYS[0]]:
            requested = next(arg for arg in argv if arg.startswith("--property=")).split("=", 1)[1].split(",")
            assert set(module._GRAPH_PROPERTIES) | set(module._ORDERING_PROPERTIES) <= set(requested)
            result.stdout = show({name: rig.runner.services[KEYS[0]][name] for name in requested})
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.verify_service_contract(KEYS[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("change", ("default_requires_missing", "tmp_want_missing", "shutdown_missing",
    "mount_path_extra", "wrong_slice", "defaults_disabled", "alias", "following"))
def test_r3_loaded_default_authority_does_not_accept_arbitrary_approximations(rig, change):
    values = rig.runner.services[KEYS[0]]
    changes = dict(default_requires_missing={"Requires": ""}, tmp_want_missing={"Wants": ""},
        shutdown_missing={"Conflicts": ""}, mount_path_extra={"RequiresMountsFor": "/opt/pdi/current /var/tmp /home"},
        wrong_slice={"Slice": "foreign.slice"}, defaults_disabled={"DefaultDependencies": "no"},
        alias={"Names": values["Names"] + " foreign.service"}, following={"Following": "foreign.service"})
    values.update(changes[change])
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


def test_r3_frozen_v255_defaults_and_ordering_only_edges_are_not_workload_authority(rig):
    for values in rig.runner.services.values():
        values["Requires"] += " opt.mount var.mount var-tmp.mount"
        values["After"] += " opt.mount var.mount var-tmp.mount synthetic-order-only.service"
        values["Before"] += " synthetic-order-only.target"
    assert rig.backend.start_service(KEYS[0]).outcome is module._Outcome.SUCCESS
    assert rig.backend.stop_all_services().stop_failure_count == 0
    assert all(call[5] in module._SERVICE_UNITS.values() for call in rig.runner.mutations())


@pytest.mark.parametrize("value", ("/tmp/unreviewed-units", "", "/etc/systemd/system /etc/systemd/system"))
def test_r3_unknown_manager_load_search_path_cannot_escape_directory_authority(rig, value):
    rig.runner.manager["UnitPath"] = value
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("version", ("254", "256", "255malformed"))
def test_r3_dependency_semantics_cannot_silently_use_unqualified_version(rig, version):
    rig.runner.manager["Version"] = version
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("unit", (Path(module._TEMPLATE).name, module._SERVICE_UNITS[KEYS[0]]))
@pytest.mark.parametrize("suffix", ("wants", "requires"))
@pytest.mark.parametrize("kind", ("absent", "empty", "entry", "symlink", "file", "owner", "gid", "group", "parent", "unreadable"))
def test_r3_dependency_directory_authority_is_bounded_trusted_and_non_mutating(monkeypatch, unit, suffix, kind):
    # Test-only virtual metadata; no production path is read or changed. The
    # actual production helper and frozen trusted_path algorithm execute here.
    root = Path("/etc/systemd/system")
    leaf = root / f"{unit}.{suffix}"
    metadata = {path: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
                for path in (root, *root.parents)}
    if kind != "absent":
        metadata[leaf] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    if kind == "symlink":
        metadata[leaf].st_mode = stat.S_IFLNK | 0o777
    elif kind == "file":
        metadata[leaf].st_mode = stat.S_IFREG | 0o644
    elif kind == "owner":
        metadata[leaf].st_uid = 1000
    elif kind == "gid":
        metadata[leaf].st_gid = 1000
    elif kind == "group":
        metadata[leaf].st_mode = stat.S_IFDIR | 0o775
    elif kind == "parent":
        metadata[root].st_uid = 1000
    def lstat(path):
        if path == leaf and kind == "unreadable":
            raise PermissionError(CANARY)
        if path not in metadata:
            raise FileNotFoundError
        return metadata[path]
    def iterdir(path):
        assert path == leaf
        # Even a link to an allowed default is unreviewed filesystem authority.
        return iter((leaf / "sysinit.target",) if kind == "entry" else ())
    monkeypatch.setattr(module, "_UNIT_LOAD_ROOTS", (str(root),))
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "iterdir", iterdir)
    if kind in {"absent", "empty"}:
        DEPENDENCY_DIRECTORIES(KEYS[0])
    else:
        with pytest.raises(WP8ContractError) as error:
            DEPENDENCY_DIRECTORIES(KEYS[0])
        assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID
        assert CANARY not in str(error.value)


@pytest.mark.parametrize("action", ("verify_service_contract", "start_service", "stop_all_services"))
def test_r3_dependency_directory_rejection_is_wired_into_mutation_guard(rig, monkeypatch, action):
    def directories(key):
        if key == KEYS[0]:
            module._fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    monkeypatch.setattr(module, "_dependency_directories", directories)
    if action == "stop_all_services":
        result = rig.backend.stop_all_services()
        assert result.stop_failure_count == 1 and result.service_state == "NOT_CONFIRMED"
        assert len(rig.runner.mutations()) == 5
        assert not any(call[5] == module._SERVICE_UNITS[KEYS[0]] for call in rig.runner.mutations())
        last_stop = max(index for index, (call, _) in enumerate(rig.runner.calls) if call[4] == "stop")
        final_shows = {call[5] for call, _ in rig.runner.calls[last_stop + 1:] if call[4] == "show"}
        assert set(module._SERVICE_UNITS.values()) <= final_shows
    else:
        with pytest.raises(WP8ContractError):
            getattr(rig.backend, action)(KEYS[0])
        assert not rig.runner.mutations()


def test_r3_untrusted_dependency_never_appears_in_public_safe_error(rig):
    rig.runner.services[KEYS[0]]["Wants"] += " " + CANARY + ".service"
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service(KEYS[0])
    assert CANARY not in str(error.value) and error.value.__suppress_context__
    assert not rig.runner.mutations()
