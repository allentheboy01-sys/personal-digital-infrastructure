from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import inspect
import json
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
DEFAULT_DEPENDENCY_DIRECTORIES = module._default_dependency_directories
DEFAULT_FRAGMENT = module._default_fragment
PUBLIC = {"manager_identity", "daemon_reload", "snapshot_p3c", "verify_timers_quiet",
          "verify_service_contract", "start_service", "stop_all_services", "verify_all_services_inactive"}
# Reviewed manager policy, independently enumerated rather than taken from the
# backend allowlist. Missing members are NOT optional compatibility variants.
REVIEWED_UNITPATH = (
    "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
    "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late",
)


def service_values(key):
    # Independent literal show projection: production parser/property constants
    # do not manufacture the evidence that their own validation will accept.
    values = dict(DropInPaths="", Following="", Requisite="", BindsTo="", PartOf="", ConsistsOf="",
        Upholds="", RequiredBy="", RequisiteOf="", WantedBy="", BoundBy="", UpheldBy="", ConflictedBy="",
        OnFailure="", OnSuccess="", OnFailureOf="", OnSuccessOf="", Triggers="", PropagatesStopTo="",
        StopPropagatedFrom="", PropagatesReloadTo="", ReloadPropagatedFrom="", JoinsNamespaceOf="", SliceOf="")
    exec_start = ("/opt/pdi/current/.venv/bin/python -m pdi.production_ops.enrichment "
        "--config /etc/pdi/scoped/registry.toml --principal-ref ${PDI_PRINCIPAL_REF} "
        "--pipeline-key ${PDI_SCOPED_PIPELINE_KEY} --lock-timeout 300")
    values.update(Id=f"pdi-scoped-pipeline@{key}.service", Names=f"pdi-scoped-pipeline@{key}.service",
        LoadState="loaded", FragmentPath="/etc/systemd/system/pdi-scoped-pipeline@.service",
        Transient="no", NeedDaemonReload="no", User="pdi", Group="pdi", Type="oneshot",
        WorkingDirectory="/opt/pdi/current",
        EnvironmentFiles=f"/etc/pdi/scoped/units/{key}.env (ignore_errors=no)",
        ExecStart="{ path=/opt/pdi/current/.venv/bin/python ; argv[]=" + exec_start +
            " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
        NoNewPrivileges="yes", PrivateTmp="yes", PrivateTmpEx="connected", ProtectSystem="strict", ProtectHome="yes",
        ReadWritePaths="/run/lock", TimeoutStartUSec="infinity", TimeoutStopUSec="1min",
        KillMode="control-group", StandardOutput="null", StandardError="null",
        RemainAfterExit="no", Restart="no", FailureAction="none", SuccessAction="none",
        StartLimitAction="none", JobTimeoutAction="none", DefaultDependencies="yes", Slice=module._DEFAULT_SLICE,
        Wants="tmp.mount", Requires="sysinit.target " + module._DEFAULT_SLICE, Conflicts="shutdown.target",
        RequiresMountsFor="/opt/pdi/current", WantsMountsFor="/tmp /var/tmp", TriggeredBy=module._timer_units()[key],
        After="sysinit.target basic.target tmp.mount systemd-tmpfiles-setup.service network-online.target " +
              module._DEFAULT_SLICE, Before="shutdown.target", ConditionResult="yes", AssertResult="yes",
        ActiveState="inactive", SubState="dead", Job="", Result="success", ExecMainCode="1",
        ExecMainStatus="0", ExecMainStartTimestampMonotonic="10", ExecMainExitTimestampMonotonic="20",
        InvocationID="1" * 32)
    # Literal v257 D-Bus fixtures, independent of production signatures/names.
    for name in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition"):
        values[name] = {"type": "a(sasbttttuii)", "data": []}
    for name in ("Conditions", "Asserts"):
        values[name] = {"type": "a(sbbsi)", "data": []}
    return values


def timer_values(key):
    unit = module._timer_units()[key]
    return dict(Id=unit, LoadState="loaded", FragmentPath=f"/etc/systemd/system/{unit}",
        DropInPaths="", Transient="no", NeedDaemonReload="no", ActiveState="inactive",
        SubState="dead", Unit=module._SERVICE_UNITS[key], Job="")


def raw_default_units():
    # Independent literal v257 Unit projection. NOT generated from production
    # property/default/edge constants. Unknown requested properties are omitted
    # by the fake transport, as real systemctl show does.
    def unit(name, active="active", sub="active", **changes):
        values = dict(Id=name, Names=name, Following="", LoadState="loaded",
            FragmentPath="/usr/lib/systemd/system/" + name, DropInPaths="", Transient="no",
            NeedDaemonReload="no", Wants="", Requires="", Requisite="", BindsTo="", PartOf="",
            ConsistsOf="", Upholds="", RequiredBy="", RequisiteOf="", WantedBy="", BoundBy="",
            UpheldBy="", Conflicts="", ConflictedBy="", OnFailure="", OnSuccess="", OnFailureOf="",
            OnSuccessOf="", Triggers="", TriggeredBy="", PropagatesStopTo="", StopPropagatedFrom="",
            PropagatesReloadTo="", ReloadPropagatedFrom="", JoinsNamespaceOf="", SliceOf="",
            RequiresMountsFor="", WantsMountsFor="", Before="", After="", ActiveState=active, SubState=sub, Job="",
            FailureAction="none", SuccessAction="none", StartLimitAction="none", JobTimeoutAction="none",
            StopWhenUnneeded="no")
        values.update(changes)
        return values
    units = {
        "sysinit.target": unit("sysinit.target", Wants="local-fs.target swap.target",
            Conflicts="emergency.service emergency.target"),
        "local-fs.target": unit("local-fs.target"), "swap.target": unit("swap.target"),
        r"system-pdi\x2dscoped\x2dpipeline.slice": unit(r"system-pdi\x2dscoped\x2dpipeline.slice",
            active="inactive", sub="dead", FragmentPath="", Requires="system.slice", Conflicts="shutdown.target"),
        "system.slice": unit("system.slice", Requires="-.slice", Conflicts="shutdown.target"),
        "-.slice": unit("-.slice", FragmentPath=""),
        "shutdown.target": unit("shutdown.target", "inactive", "dead"),
        "umount.target": unit("umount.target", "inactive", "dead"),
        "emergency.target": unit("emergency.target", "inactive", "dead"),
        "emergency.service": unit("emergency.service", "inactive", "dead",
            ExecStop={"type": "a(sasbttttuii)", "data": []},
            ExecStopPost={"type": "a(sasbttttuii)", "data": []}),
    }
    for name in ("-.mount", "tmp.mount", "opt.mount", "opt-pdi.mount", "opt-pdi-current.mount", "var.mount", "var-tmp.mount"):
        units[name] = unit(name, sub="mounted", Conflicts="umount.target",
                           FragmentPath="" if name == "-.mount" else "/usr/lib/systemd/system/" + name)
    return units


def show(values):
    return "".join(f"{name}={value}\n" for name, value in values.items())


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.services = {key: service_values(key) for key in KEYS}
        self.defaults = raw_default_units()
        self.timers = {key: timer_values(key) for key in KEYS}
        self.enabled = {key: (1, "disabled\n") for key in KEYS}
        self.active = {key: (3, "inactive\n") for key in KEYS}
        self.manager = {"Version": "257.13-1~deb13u1", "Virtualization": "kvm", "SystemState": "running",
                        "UnitPath": " ".join(REVIEWED_UNITPATH)}
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
        assert argv[0] in {"/usr/bin/systemctl", "/usr/bin/busctl"}, "no real call is allowed in fake tests"
        self.calls.append((argv, kwargs))
        if argv[0] == "/usr/bin/busctl":
            assert argv[:6] == ("/usr/bin/busctl", "--system", "--no-pager", "--json=short",
                               "get-property", "org.freedesktop.systemd1")
            names = argv[8:]
            objects = {"/org/freedesktop/systemd1/unit/" + "".join(
                c if c.isascii() and c.isalnum() else f"_{ord(c):02x}" for c in name): values
                for name, values in ((f"pdi-scoped-pipeline@{key}.service", self.services[key]) for key in KEYS)}
            objects["/org/freedesktop/systemd1/unit/emergency_2eservice"] = self.defaults["emergency.service"]
            values = objects[argv[6]]
            assert argv[7] in {"org.freedesktop.systemd1.Service", "org.freedesktop.systemd1.Unit"}
            stdout = "".join(json.dumps(values[name]) + "\n" for name in names if name in values)
            return subprocess.CompletedProcess(argv, 0, stdout, CANARY)
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
                self.services[key].update(ActiveState="inactive", SubState="dead", Job="")
            else:
                assert verb == "show"
                requested = next(arg for arg in argv if arg.startswith("--property=")).split("=", 1)[1].split(",")
                stdout = show({name: self.services[key][name] for name in requested if name in self.services[key]})
        elif unit in reverse_timers:
            key = reverse_timers[unit]
            if verb == "is-enabled":
                code, stdout = self.enabled[key]
            elif verb == "is-active":
                code, stdout = self.active[key]
            else:
                assert verb == "show"
                stdout = show(self.timers[key])
        elif unit in self.defaults:
            assert verb == "show"
            requested = next(arg for arg in argv if arg.startswith("--property=")).split("=", 1)[1].split(",")
            stdout = show({name: self.defaults[unit][name] for name in requested if name in self.defaults[unit]})
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
    monkeypatch.setattr(module, "_manager_continuity_facts", lambda: {k: v for k, v in facts.items() if k != "executable_sha256"})
    assets = module._Assets(H, module._template(TEMPLATE))
    monkeypatch.setattr(module, "_read_assets", lambda _: assets)
    monkeypatch.setattr(module, "_verify_candidate", lambda _: H)
    monkeypatch.setattr(module, "_current_candidate", lambda _: None)
    monkeypatch.setattr(module, "_dependency_directories", lambda _: None)
    monkeypatch.setattr(module, "_default_dependency_directories", lambda *_: None)
    monkeypatch.setattr(module, "_default_fragment", lambda _: H)
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
                        "DBUS_SYSTEM_BUS_ADDRESS": CANARY, "SYSTEMD_UNIT_PATH": CANARY}.items():
        monkeypatch.setenv(name, value)
    key = (None if command_kind in {module._Request.MANAGER, module._Request.RELOAD} else
           "sysinit.target" if command_kind is module._Request.DEFAULT_SHOW else
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
                 namespace_mismatch=None, connected=[], executable_inode=2, socket_inode=2)
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
            assert timeout == 1
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
    monkeypatch.setattr(Path, "lstat", lambda path: SimpleNamespace(
        st_mode=state["socket_mode"], st_uid=state["socket_uid"], st_gid=state["socket_gid"],
        st_dev=1, st_ino=state["executable_inode" if path == state["executable"] else "socket_inode"],
        st_size=17, st_mtime_ns=1, st_ctime_ns=1))
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
    extra = "/unreviewed" if relation in {"RequiresMountsFor", "WantsMountsFor"} else "synthetic-unreviewed.service"
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


@pytest.mark.parametrize("change", ("default_requires_missing", "tmp_path_missing", "shutdown_missing",
    "mount_path_extra", "wrong_slice", "defaults_disabled", "alias", "following"))
def test_r3_loaded_default_authority_does_not_accept_arbitrary_approximations(rig, change):
    values = rig.runner.services[KEYS[0]]
    changes = dict(default_requires_missing={"Requires": ""}, tmp_path_missing={"WantsMountsFor": "/var/tmp"},
        shutdown_missing={"Conflicts": ""}, mount_path_extra={"RequiresMountsFor": "/opt/pdi/current /var/tmp /home"},
        wrong_slice={"Slice": "foreign.slice"}, defaults_disabled={"DefaultDependencies": "no"},
        alias={"Names": values["Names"] + " foreign.service"}, following={"Following": "foreign.service"})
    values.update(changes[change])
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(KEYS[0])
    assert not rig.runner.mutations()


def test_r3_frozen_v257_defaults_and_ordering_only_edges_are_not_workload_authority(rig):
    for values in rig.runner.services.values():
        values["Requires"] += " opt.mount"
        values["Wants"] += " var.mount var-tmp.mount"
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


@pytest.mark.parametrize("drift", ("other_active", "other_job", "timer_enabled", "timer_active",
    "current", "candidate", "target_active", "target_job", "target_graph", "default_graph", "manager"))
def test_b1_last_full_manager_window_cannot_emit_start(rig, monkeypatch, drift):
    # Discover the last full OS proof preceding start using the injected trace,
    # then replay an attack at that precise boundary. No production helper's
    # manager-call count/order is copied into this test oracle.
    real_facts, count, last = module._manager_os_facts, [0], []
    def counted():
        count[0] += 1
        return real_facts()
    def trace(argv, **kwargs):
        if argv[4] == "start":
            last.append(count[0])
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(module, "_manager_os_facts", counted)
    monkeypatch.setattr(module.subprocess, "run", trace)
    rig.backend.start_service("enrichment.nextcloud_text")
    assert len(last) == 1 and last[0] > 0
    rig.runner.calls.clear()
    rig.runner.services = {key: service_values(key) for key in KEYS}
    rig.runner.defaults = raw_default_units()
    backend = module.WP8ProductionSystemdBackend(rig.evidence)
    count[0], injected = 0, []
    def attack():
        count[0] += 1
        if count[0] == last[0]:
            injected.append(drift)
            if drift == "other_active":
                rig.runner.services["enrichment.immich_geo"].update(ActiveState="active", SubState="running")
            elif drift == "other_job":
                rig.runner.services["enrichment.immich_geo"]["Job"] = "123"
            elif drift == "timer_enabled":
                rig.runner.enabled["enrichment.immich_geo"] = (0, "enabled\n")
            elif drift == "timer_active":
                rig.runner.active["enrichment.immich_geo"] = (0, "active\n")
            elif drift == "target_active":
                rig.runner.services["enrichment.nextcloud_text"].update(ActiveState="active", SubState="running")
            elif drift == "target_job":
                rig.runner.services["enrichment.nextcloud_text"]["Job"] = "123"
            elif drift == "target_graph":
                rig.runner.services["enrichment.nextcloud_text"]["Wants"] += " synthetic-unreviewed.service"
            elif drift == "default_graph":
                rig.runner.defaults[r"system-pdi\x2dscoped\x2dpipeline.slice"]["Requires"] = "synthetic-unreviewed.service"
            elif drift == "manager":
                rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
        return real_facts()
    monkeypatch.setattr(module, "_manager_os_facts", attack)
    monkeypatch.setattr(module.subprocess, "run", rig.runner)
    def runtime(_):
        return "2" * 64 if injected and drift == "candidate" else H
    def current(_):
        if injected and drift == "current":
            module._fail(WP8FailureCode.CURRENT_DRIFT)
    monkeypatch.setattr(module, "_verify_candidate", runtime)
    monkeypatch.setattr(module, "_current_candidate", current)
    with pytest.raises(WP8ContractError):
        backend.start_service("enrichment.nextcloud_text")
    assert injected == [drift] and not rig.runner.mutations()


def test_b1_final_bundle_has_no_full_manager_or_slow_validation_after_current(rig, monkeypatch):
    current_seen, started, events = [False], [False], []
    def current(_):
        current_seen[0] = True
        events.append("current")
    # Only the final runtime gate has the no-slow-IO fence. Each complete A/B
    # snapshot independently verifies current too, before this final gate.
    original_final = rig.backend._final_runtime_prerequisites
    def final(*args, **kwargs):
        monkeypatch.setattr(module, "_current_candidate", current)
        return original_final(*args, **kwargs)
    monkeypatch.setattr(rig.backend, "_final_runtime_prerequisites", final)
    for name in ("_manager_os_facts", "_verify_candidate", "_read_assets", "_dependency_directories",
                 "_default_dependency_directories", "_default_fragment"):
        original = getattr(module, name)
        def checked(*args, _original=original, _name=name, **kwargs):
            assert not current_seen[0] or started[0], _name + " after final current before start"
            events.append(_name)
            return _original(*args, **kwargs)
        monkeypatch.setattr(module, name, checked)
    def transport(argv, **kwargs):
        if argv[4] == "start":
            assert current_seen[0]
            started[0] = True
            events.append("start")
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(module.subprocess, "run", transport)
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    assert events.index("current") < events.index("start")


def test_b1_cheap_manager_token_never_reads_executable_content_or_queries(manager_os, monkeypatch):
    full = module._manager_os_facts()
    identity = module._ManagerIdentity(H, H, "BARE_METAL",
        contract_fingerprint({k: v for k, v in full.items() if k != "executable_sha256"}))
    def forbidden(*_, **__):
        pytest.fail("cheap continuity proof performed slow IO")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(module.subprocess, "run", forbidden)
    module._manager_token(identity)
    manager_os["boot"] = "21111111-2222-4333-8444-555555555555"
    with pytest.raises(WP8ContractError):
        module._manager_token(identity)


@pytest.mark.parametrize("source,relation,target", (
    (r"system-pdi\x2dscoped\x2dpipeline.slice", "Requires", "synthetic-second-hop.service"),
    (r"system-pdi\x2dscoped\x2dpipeline.slice", "Wants", "synthetic-second-hop.service"),
    ("system.slice", "Conflicts", "pdi-p3c-nextcloud-incremental.timer"),
    ("system.slice", "ConflictedBy", "pdi-p3c-nextcloud-incremental.timer"),
    ("system.slice", "OnFailure", "synthetic-handler.service"),
    ("system.slice", "OnSuccess", "synthetic-handler.service"),
    ("system.slice", "Upholds", "synthetic-second-hop.service"),
    ("system.slice", "BindsTo", "synthetic-second-hop.service"),
    ("system.slice", "Requisite", "synthetic-second-hop.service"),
    ("shutdown.target", "PropagatesStopTo", "pdi-p3c-nextcloud-incremental.timer"),
    ("shutdown.target", "RequiredBy", "pdi-p3c-nextcloud-incremental.timer"),
    (r"system-pdi\x2dscoped\x2dpipeline.slice", "RequiredBy", "pdi-p3c-nextcloud-incremental.timer"),
))
@pytest.mark.parametrize("action", ("verify_service_contract", "start_service"))
def test_b2_raw_transitive_mutation_graph_rejected(rig, source, relation, target, action):
    rig.runner.defaults[source][relation] = target
    # Even if the foreign second hop has a P3C conflict, its identity is itself
    # unauthorized. Do NOT query an arbitrary unit to decide whether to trust it.
    rig.runner.defaults["synthetic-second-hop.service"] = {
        "Id": "synthetic-second-hop.service", "Conflicts": "pdi-p3c-nextcloud-incremental.timer"}
    with pytest.raises(WP8ContractError) as error:
        getattr(rig.backend, action)("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID
    assert not rig.runner.mutations()
    assert not any(call[4:6] == ("show", "synthetic-second-hop.service") for call, _ in rig.runner.calls)


@pytest.mark.parametrize("relation", ("Before", "After", "PartOf", "StopPropagatedFrom", "WantedBy", "SliceOf"))
def test_b2_non_start_edges_are_not_walked_as_an_undirected_graph(rig, relation):
    rig.runner.defaults["system.slice"][relation] = "synthetic-order-or-inverse.service"
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    assert not any(call[5] == "synthetic-order-or-inverse.service" for call, _ in rig.runner.calls if len(call) > 5)


def test_b2_requisite_checks_active_authority_without_starting_its_dependencies(rig):
    rig.runner.defaults["system.slice"]["Requisite"] = "swap.target"
    # VERIFY_ACTIVE does not pull swap.target's Wants into the transaction. It
    # remains separately reached/checked as START through sysinit.target, so
    # removing that actual start edge isolates this directional test.
    rig.runner.defaults["sysinit.target"]["Wants"] = "local-fs.target"
    rig.runner.defaults["swap.target"]["Wants"] = "synthetic-not-started.service"
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    rig.runner.services["enrichment.nextcloud_text"] = service_values("enrichment.nextcloud_text")
    rig.runner.calls.clear()
    rig.runner.defaults["swap.target"]["ActiveState"] = "inactive"
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_b2_reviewed_cycle_terminates_with_deterministic_complete_fingerprint(rig):
    rig.runner.defaults["swap.target"]["Requires"] = "sysinit.target"
    first = rig.backend.verify_service_contract("enrichment.nextcloud_text")
    second = rig.backend.verify_service_contract("enrichment.nextcloud_text")
    assert first == second and not rig.runner.mutations()
    assert len(rig.runner.calls) < 200


@pytest.mark.parametrize("limit,value", (("_MAX_CLOSURE_NODES", 2), ("_MAX_CLOSURE_EDGES", 2), ("_MAX_CLOSURE_DEPTH", 1)))
def test_b2_each_graph_limit_fails_closed_not_truncated(rig, monkeypatch, limit, value):
    monkeypatch.setattr(module, limit, value)  # internal test API, never operator-configurable
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_b2_real_fixed_edge_limit_rejects_large_authorized_graph(rig):
    names = ("sysinit.target", "local-fs.target", "swap.target", r"system-pdi\x2dscoped\x2dpipeline.slice",
             "system.slice", "-.slice", "tmp.mount", "-.mount", "opt.mount", "opt-pdi.mount",
             "opt-pdi-current.mount", "var.mount", "var-tmp.mount")
    for name in names:
        rig.runner.defaults[name]["Wants"] = " ".join(names)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("field,value", (("Id", "synthetic-other.target"), ("Names", "sysinit.target alias.target"),
    ("LoadState", "not-found"), ("NeedDaemonReload", "yes"), ("DropInPaths", "/run/foreign.conf"),
    ("Transient", "yes"), ("Following", "alias.target"), ("Job", "123"),
    ("ActiveState", "inactive"), ("SubState", "failed"), ("FailureAction", "reboot"),
    ("StopWhenUnneeded", "yes"), ("RequiresMountsFor", "/foreign")))
def test_b2_default_name_alone_is_not_authority(rig, field, value):
    rig.runner.defaults["sysinit.target"][field] = value
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_b2_missing_raw_default_property_is_not_filled_by_the_fake(rig):
    del rig.runner.defaults["sysinit.target"]["Conflicts"]
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_b2_final_loaded_closure_drift_refused_without_new_graph_traversal(rig, monkeypatch):
    calls = []
    def changed():
        calls.append(True)
        rig.runner.defaults["system.slice"]["Requires"] = "synthetic-second-hop.service"
    _attack_after_snapshot_a(rig, monkeypatch, changed)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert len(calls) == 1 and not rig.runner.mutations()


@pytest.mark.parametrize("value", ("", None, "00000000000000000000000000000000", "abc", "2" * 31,
    "2" * 33, "g" * 32, "ABCDEF0123456789ABCDEF0123456789", " 22222222222222222222222222222222",
    "22222222222222222222222222222222 ", "11111111111111111111111111111111"))
def test_b3_raw_post_invocation_requires_new_canonical_nonzero_id(rig, value):
    rig.runner.after_start["InvocationID"] = value
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SERVICE_EXECUTION_FAILED
    assert len(rig.runner.mutations()) == 1  # never retry after ambiguous execution


@pytest.mark.parametrize("prior", ("", "00000000000000000000000000000000", "11111111111111111111111111111111"))
def test_b3_no_prior_invocation_still_requires_valid_new_nonzero_id(rig, prior):
    rig.runner.services["enrichment.nextcloud_text"]["InvocationID"] = prior
    rig.runner.after_start["InvocationID"] = "abcdef0123456789abcdef0123456789"
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS


def test_b3_missing_invocation_property_is_rejected_not_defaulted(rig, monkeypatch):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4] == "start":
            del rig.runner.services["enrichment.nextcloud_text"]["InvocationID"]
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert len(rig.runner.mutations()) == 1


@pytest.mark.parametrize("version", ("257.13-1~deb13u1",))
def test_b4_raw_known_supported_version_representations(rig, version):
    rig.runner.manager["Version"] = version
    assert len(rig.backend.manager_identity().fingerprint) == 64


@pytest.mark.parametrize("version", ("255 future-version-256-unreviewed", "255malformed", "254", "256",
    "255\n256", "255 arbitrary free text", " 255", "255 ", "255\t", "255\x00", "255 256",
    "255.4-1ubuntu8.14 future 256", "255.4-1ubuntu8.014", "255.4-1ubuntu8.0", "255.4-1ubuntu8.14.256",
    "255.5", "255.4-2ubuntu8", "255.4-1ubuntu9", "255.4-1ubuntu8~256", "255.4-1ubuntu8+256"))
def test_b4_raw_malformed_or_unreviewed_version_never_authorizes_start(rig, version):
    rig.runner.manager["Version"] = version
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SYSTEMD_MANAGER_INVALID
    assert not rig.runner.mutations()


@pytest.mark.parametrize("field,value", (("boot", "21111111-2222-4333-8444-555555555555"),
    ("peer", (123, 0, 0)), ("comm", "python"), ("namespace_mismatch", "pid"),
    ("namespace_mismatch", "mnt"), ("namespace_mismatch", "user"), ("namespace_mismatch", "time"),
    ("executable_inode", 3), ("socket_inode", 3)))
def test_b1_cheap_continuity_binds_original_boot_peer_namespaces_and_inodes(manager_os, monkeypatch, field, value):
    full = module._manager_os_facts()
    identity = module._ManagerIdentity(H, H, "BARE_METAL",
        contract_fingerprint({k: v for k, v in full.items() if k != "executable_sha256"}))
    def forbidden(*_, **__):
        pytest.fail("cheap token performed full proof or systemctl query")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(module.subprocess, "run", forbidden)
    manager_os[field] = value
    with pytest.raises(WP8ContractError) as error:
        module._manager_token(identity)
    assert error.value.code is WP8FailureCode.SYSTEMD_MANAGER_INVALID


@pytest.mark.parametrize("suffix", ("wants", "requires"))
@pytest.mark.parametrize("case", ("absent", "empty", "trusted_link", "relative_link", "missing_loaded_edge",
    "foreign_name", "file", "link_owner", "link_gid", "directory_owner", "directory_group", "directory_link",
    "parent_group", "target_owner", "target_group", "target_link", "target_parent_owner", "target_escape",
    "intermediate_user_alias", "limit"))
def test_b2_actual_default_directory_reconciles_root_trust_links_and_loaded_graph(monkeypatch, suffix, case):
    # All stat/link/directory observations are virtual. Execute the actual WP8
    # helper AND frozen trusted_path logic, never read a host unit directory.
    root = Path("/etc/systemd/system")
    packaged = Path("/usr/lib/systemd/system")
    directory = root / ("sysinit.target." + suffix)
    entry, target = directory / "swap.target", packaged / "swap.target"
    metadata = {p: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        for p in {root, *root.parents, packaged, *packaged.parents}}
    if case != "absent":
        metadata[directory] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    metadata[entry] = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
    metadata[target] = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)
    text_target = str(target)
    entries = [entry] if case not in {"absent", "empty"} else []
    values = raw_default_units()["sysinit.target"]
    values["Wants" if suffix == "wants" else "Requires"] = "swap.target"
    if case == "relative_link":
        target = root / "swap.target"
        metadata[target] = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)
        text_target = "../swap.target"
        metadata[directory / ".."] = metadata[root]
        metadata[directory / ".." / "swap.target"] = metadata[target]
    elif case == "missing_loaded_edge":
        values["Wants" if suffix == "wants" else "Requires"] = ""
    elif case == "foreign_name":
        entries = [directory / "synthetic-unreviewed.service"]
    elif case == "file":
        metadata[entry].st_mode = stat.S_IFREG | 0o644
    elif case == "link_owner":
        metadata[entry].st_uid = 1000
    elif case == "link_gid":
        metadata[entry].st_gid = 1000
    elif case == "directory_owner":
        metadata[directory].st_uid = 1000
    elif case == "directory_group":
        metadata[directory].st_mode |= 0o020
    elif case == "directory_link":
        metadata[directory].st_mode = stat.S_IFLNK | 0o777
    elif case == "parent_group":
        metadata[root].st_mode |= 0o020
    elif case == "target_owner":
        metadata[target].st_uid = 1000
    elif case == "target_group":
        metadata[target].st_mode |= 0o020
    elif case == "target_link":
        metadata[target].st_mode = stat.S_IFLNK | 0o777
    elif case == "target_parent_owner":
        metadata[packaged].st_uid = 1000
    elif case == "target_escape":
        text_target = "/synthetic-outside/swap.target"
        metadata[Path(text_target)] = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)
        metadata[Path("/synthetic-outside")] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    elif case == "intermediate_user_alias":
        text_target = "/synthetic-user/alias.target"
        metadata[Path(text_target)] = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=1000, st_gid=1000)
        metadata[Path("/synthetic-user")] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)
    elif case == "limit":
        # Repeated entries test the independent total entry budget without
        # materializing an arbitrary host directory or expanding authority.
        entries *= 129
    def lstat(path):
        if path not in metadata:
            raise FileNotFoundError
        return metadata[path]
    def iterdir(path):
        assert path == directory
        return iter(entries)
    def readlink(path):
        assert path == entry
        return text_target
    def resolve(path, *, strict):
        assert strict and path == (Path(text_target) if text_target.startswith("/") else directory / text_target)
        return target if case != "target_escape" else Path(text_target)
    monkeypatch.setattr(module, "_UNIT_LOAD_ROOTS", (str(root), str(packaged)))
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "iterdir", iterdir)
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(module.os, "readlink", readlink)
    if case in {"absent", "empty", "trusted_link", "relative_link"}:
        DEFAULT_DEPENDENCY_DIRECTORIES("sysinit.target", values)
    else:
        with pytest.raises(WP8ContractError) as error:
            DEFAULT_DEPENDENCY_DIRECTORIES("sysinit.target", values)
        assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID


@pytest.mark.parametrize("case", ("trusted", "foreign_path", "wrong_name", "file_owner", "file_group",
    "file_link", "parent_owner", "parent_group"))
def test_b2_actual_default_fragment_authority_is_exact_and_root_controlled(monkeypatch, case):
    values = raw_default_units()["sysinit.target"]
    target = Path("/usr/lib/systemd/system/sysinit.target")
    metadata = {p: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0) for p in target.parents}
    metadata[target] = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)
    if case == "foreign_path":
        values["FragmentPath"] = "/tmp/sysinit.target"
    elif case == "wrong_name":
        values["FragmentPath"] = "/usr/lib/systemd/system/swap.target"
    elif case == "file_owner":
        metadata[target].st_uid = 1000
    elif case == "file_group":
        metadata[target].st_mode |= 0o020
    elif case == "file_link":
        metadata[target].st_mode = stat.S_IFLNK | 0o777
    elif case == "parent_owner":
        metadata[target.parent].st_uid = 1000
    elif case == "parent_group":
        metadata[target.parent].st_mode |= 0o020
    reads = []
    def lstat(path):
        if path not in metadata:
            raise FileNotFoundError
        return metadata[path]
    def read(path):
        reads.append(path)
        assert path == target
        return b"synthetic root-controlled default unit"
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "read_bytes", read)
    if case == "trusted":
        assert DEFAULT_FRAGMENT(values) == hashlib.sha256(read(target)).hexdigest()
    else:
        with pytest.raises(WP8ContractError):
            DEFAULT_FRAGMENT(values)
        assert reads == []


@pytest.mark.parametrize("unit", (r"system-pdi\x2dscoped\x2dpipeline.slice", "system.slice", "-.slice", "-.mount"))
def test_b2_only_explicit_v257_implicit_units_have_no_fragment(unit):
    assert DEFAULT_FRAGMENT(dict(Id=unit, FragmentPath="")) == "IMPLICIT_V257_UNIT"


@pytest.mark.parametrize("action", ("verify_service_contract", "start_service"))
@pytest.mark.parametrize("helper", ("_default_fragment", "_default_dependency_directories"))
def test_b2_transitive_filesystem_failure_is_wired_and_sanitized(rig, monkeypatch, action, helper):
    def rejected(*_):
        raise PermissionError(CANARY)
    monkeypatch.setattr(module, helper, rejected)
    with pytest.raises(WP8ContractError) as error:
        getattr(rig.backend, action)("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID and error.value.__suppress_context__
    assert CANARY not in str(error.value) and not rig.runner.mutations()


@pytest.mark.parametrize("unit", ("synthetic-second-hop.service", "pdi-p3c-nextcloud-incremental.timer"))
def test_b2_default_read_transport_never_accepts_foreign_unit_arguments(rig, unit):
    with pytest.raises(WP8ContractError):
        module._systemctl(module._Request.DEFAULT_SHOW, unit)
    assert not rig.runner.calls


def test_b2_stop_direction_does_not_start_stop_targets_outgoing_wants(rig):
    rig.runner.defaults["shutdown.target"]["Wants"] = "synthetic-not-started.service"
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    assert not any(call[4:6] == ("show", "synthetic-not-started.service") for call, _ in rig.runner.calls)


def test_b1_complete_final_bundle_follows_every_slow_proof_and_fence_immediately_precedes_start(rig, monkeypatch):
    events = []
    for name in ("_manager_os_facts", "_verify_candidate", "_read_assets", "_dependency_directories",
                 "_default_dependency_directories", "_default_fragment"):
        original = getattr(module, name)
        def slow(*args, _original=original, **kwargs):
            result = _original(*args, **kwargs)
            events.append(("slow",))
            return result
        monkeypatch.setattr(module, name, slow)
    token, clock = module._manager_token, module.time.monotonic_ns
    def continuity(identity):
        token(identity)
        events.append(("token",))
    def current(_):
        events.append(("current",))
    def fence():
        events.append(("fence",))
        return clock()
    def transport(argv, **kwargs):
        events.append((argv[4], argv[5] if len(argv) > 5 and not argv[5].startswith("--") else None))
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(module, "_manager_token", continuity)
    monkeypatch.setattr(module, "_current_candidate", current)
    monkeypatch.setattr(module.time, "monotonic_ns", fence)
    monkeypatch.setattr(module.subprocess, "run", transport)
    rig.backend.start_service("enrichment.nextcloud_text")
    start = next(i for i, event in enumerate(events) if event[0] == "start")
    last_slow = max(i for i, event in enumerate(events[:start]) if event == ("slow",))
    final = events[last_slow + 1:start]
    assert ("token",) in final and ("current",) in final
    for key in ("enrichment.nextcloud_text", "enrichment.nextcloud_documents", "enrichment.file_metadata",
                "enrichment.immich_geo", "enrichment.immich_metadata", "enrichment.immich_ocr"):
        assert ("show", f"pdi-scoped-pipeline@{key}.service") in final
        timer = module._timer_units()[key]
        assert ("show", timer) in final
        assert ("is-enabled", timer) in final and ("is-active", timer) in final
    assert final[-4:] == [("show", "pdi-scoped-pipeline@enrichment.nextcloud_text.service"),
                         ("current",), ("token",), ("fence",)]
    calls = [argv for argv, _ in rig.runner.calls]
    command = next(i for i, argv in enumerate(calls) if argv[4] == "start")
    # Typed authority belongs to COMPLETE B, not a detached last-property seal.
    typed = [argv for argv in calls[:command] if argv[0] == "/usr/bin/busctl" and
             "enrichment_2enextcloud_5ftext" in argv[6]]
    service, unit = typed[-2:]
    assert service[7:] == ("org.freedesktop.systemd1.Service", "ExecStartPre", "ExecStartPost",
                           "ExecStop", "ExecStopPost", "ExecCondition")
    assert unit[7:] == ("org.freedesktop.systemd1.Unit", "Conditions", "Asserts")
    assert service[6] == unit[6] == "/org/freedesktop/systemd1/unit/pdi_2dscoped_2dpipeline_40enrichment_2enextcloud_5ftext_2eservice"
    assert len(rig.runner.mutations()) == 1


@pytest.mark.parametrize("prior", (None, "bad", "ABCDEF0123456789ABCDEF0123456789", " 11111111111111111111111111111111"))
def test_b3_malformed_prior_identity_rejected_before_mutation(rig, prior):
    rig.runner.services["enrichment.nextcloud_text"]["InvocationID"] = prior
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_b2_authorized_slice_activation_is_not_a_post_start_authority_drift(rig, monkeypatch):
    # Semantic fake models the actual v257 slice start side effect, rather than
    # claiming that all default activity remains byte-identical across start.
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4] == "start":
            rig.runner.defaults[r"system-pdi\x2dscoped\x2dpipeline.slice"].update(ActiveState="active", SubState="active")
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    assert len(rig.runner.mutations()) == 1


def test_b2_activity_is_still_sealed_before_start_even_when_slice_transition_is_authorized(rig, monkeypatch):
    def changed():
        rig.runner.defaults[r"system-pdi\x2dscoped\x2dpipeline.slice"].update(ActiveState="active", SubState="active")
    # Volatile activity is not stable authority. Inject after B, before its
    # bounded activity check, preserving the original pre-start rejection.
    original = rig.backend._final_runtime_prerequisites
    def final(*args, **kwargs):
        changed()
        return original(*args, **kwargs)
    monkeypatch.setattr(rig.backend, "_final_runtime_prerequisites", final)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


# v257 B1-B6 / T1-T8 authority repairs. Literal raw fixtures above plus
# independently enumerated signatures/paths/versions here; all IO is injected.
@pytest.mark.parametrize("version", ("255", "255.4-1ubuntu8.17", "257", "257.13", "257.13-1",
    "257.13-1~deb13u2", "257.14-1~deb13u1", "258.1-1", "257.13-1~deb13u1+local",
    "257.13-1~deb13u1 future", " 257.13-1~deb13u1", "257.13-1~deb13u1 "))
def test_v257_t1_exact_package_not_major_or_future_update(rig, version):
    rig.runner.manager["Version"] = version
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SYSTEMD_MANAGER_INVALID
    assert not rig.runner.mutations()


@pytest.mark.parametrize("mode", (None, "", "disconnected", "yes", "true", "CONNECTED", "future", "[unprintable]"))
def test_v257_t2_connected_cannot_be_inferred_from_legacy_boolean(rig, mode):
    values = rig.runner.services["enrichment.nextcloud_text"]
    if mode is None:
        del values["PrivateTmpEx"]
    else:
        values["PrivateTmpEx"] = mode
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("property,value", (
    ("WantsMountsFor", ""), ("WantsMountsFor", "/tmp"), ("WantsMountsFor", "/var/tmp"),
    ("WantsMountsFor", "/tmp /var/tmp /tmp"), ("WantsMountsFor", "tmp /var/tmp"),
    ("WantsMountsFor", "/tmp /var/../var/tmp"), ("WantsMountsFor", "/tmp /var/tmp /home"),
    ("WantsMountsFor", "/tmp/ /var/tmp"), ("WantsMountsFor", "/tmp /var/tmp /etc/pdi/scoped"),
    ("RequiresMountsFor", ""), ("RequiresMountsFor", "opt/pdi/current"),
    ("RequiresMountsFor", "/opt/pdi/current /opt/pdi/current"),
    ("RequiresMountsFor", "/opt/pdi/../pdi/current"), ("RequiresMountsFor", "/opt/pdi/current /run/lock"),
    ("RequiresMountsFor", "/opt/pdi/current /var/tmp")))
def test_v257_t3_exact_path_authority_fail_closed(rig, property, value):
    rig.runner.services["enrichment.nextcloud_text"][property] = value
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_t3_real_connected_paths_and_relation_specific_mount_prefixes(rig):
    values = rig.runner.services["enrichment.nextcloud_text"]
    values.update(Requires=r"sysinit.target system-pdi\x2dscoped\x2dpipeline.slice -.mount opt.mount opt-pdi.mount opt-pdi-current.mount",
        Wants="-.mount tmp.mount var.mount var-tmp.mount",
        After=r"sysinit.target system-pdi\x2dscoped\x2dpipeline.slice basic.target network-online.target systemd-tmpfiles-setup.service -.mount tmp.mount var.mount var-tmp.mount opt.mount opt-pdi.mount opt-pdi-current.mount")
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    default_reads = {argv[5] for argv, _ in rig.runner.calls if argv[4] == "show"}
    assert {"opt-pdi-current.mount", "tmp.mount", "var-tmp.mount", "-.mount"} <= default_reads


@pytest.mark.parametrize("relation,target", (("Requires", "var-tmp.mount"), ("Wants", "opt.mount"),
    ("Requires", "etc-pdi.mount"), ("Wants", "synthetic.mount")))
def test_v257_t3_no_generic_or_wrong_relation_mount_authority(rig, relation, target):
    rig.runner.services["enrichment.nextcloud_text"][relation] += " " + target
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("relation,target", (("Requires", "synthetic.service"),
    ("Wants", "synthetic.service"), ("Conflicts", "pdi-p3c-nextcloud-incremental.timer"),
    ("OnFailure", "synthetic.service"), ("OnSuccess", "synthetic.service")))
def test_v257_t3_mount_authority_is_not_trust_terminal(rig, relation, target):
    rig.runner.defaults["tmp.mount"][relation] = target
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("property,value", (("WantsMountsFor", "/tmp /var/tmp /home"),
    ("RequiresMountsFor", "/opt/pdi/current /run/lock"), ("PrivateTmpEx", "disconnected"),
    ("Wants", "tmp.mount var.mount")))
def test_v257_t4_final_path_mode_or_derived_authority_drift_refused(rig, monkeypatch, property, value):
    def drift():
        rig.runner.services["enrichment.nextcloud_text"][property] = value
    _attack_after_snapshot_a(rig, monkeypatch, drift)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_t4_post_full_proof_mount_edge_drift_refused(rig, monkeypatch):
    def drift():
        rig.runner.defaults["tmp.mount"]["Conflicts"] += " pdi-p3c-nextcloud-incremental.timer"
    _attack_after_snapshot_a(rig, monkeypatch, drift)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_t4_surface_seal_binds_paths_mode_and_typed_proof(rig):
    values = rig.backend._show("enrichment.nextcloud_text")
    captured = []
    # The expected seal fields are literal, not manufactured by a parser.
    original = module.contract_fingerprint
    def capture(value):
        captured.append(value)
        return original(value)
    from unittest.mock import patch
    with patch.object(module, "contract_fingerprint", capture):
        module._check_service(values, "enrichment.nextcloud_text", rig.assets)
    seal = captured[-1]
    assert seal["private_tmp"] == "yes" and seal["private_tmp_ex"] == "connected"
    assert seal["mount_paths"] == {"RequiresMountsFor": ["/opt/pdi/current"], "WantsMountsFor": ["/tmp", "/var/tmp"]}
    assert set(seal["typed_empty"]) == {"ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition", "Conditions", "Asserts"}
    assert seal["no_job_representation"] == "EMPTY_V257"


@pytest.mark.parametrize("target", ("selected", "other", "timer", "default"))
@pytest.mark.parametrize("job", (None, "0", "123", "123 /org/freedesktop/systemd1/job/123", " ", "\t", "\r", "[unprintable]", "no"))
def test_v257_t5_only_present_empty_job_is_no_job(rig, target, job):
    values = (rig.runner.services["enrichment.nextcloud_text"] if target == "selected" else
              rig.runner.services["enrichment.file_metadata"] if target == "other" else
              rig.runner.timers["enrichment.nextcloud_text"] if target == "timer" else
              rig.runner.defaults["sysinit.target"])
    if job is None:
        del values["Job"]
    else:
        values["Job"] = job
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_t5_duplicate_empty_job_rejected(rig, monkeypatch):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4:6] == ("show", "pdi-scoped-pipeline@enrichment.nextcloud_text.service"):
            result.stdout += "Job=\n"
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("action", ("daemon_reload", "verify_all_services_inactive", "stop_all_services"))
def test_v257_t5_reload_and_cleanup_use_same_job_rule(rig, monkeypatch, action):
    rig.runner.services["enrichment.nextcloud_text"]["Job"] = "0"
    if action == "stop_all_services":
        # Cleanup may stop an outstanding job. Its FINAL no-job proof must not
        # accept legacy 0 even when the stop command returned success.
        def transport(argv, **kwargs):
            result = rig.runner(argv, **kwargs)
            if argv[4:6] == ("stop", "pdi-scoped-pipeline@enrichment.nextcloud_text.service"):
                rig.runner.services["enrichment.nextcloud_text"]["Job"] = "0"
            return result
        monkeypatch.setattr(module.subprocess, "run", transport)
        result = rig.backend.stop_all_services()
        assert result.service_state == "NOT_CONFIRMED"
        assert len(rig.runner.mutations()) == 6
    else:
        with pytest.raises(WP8ContractError):
            getattr(rig.backend, action)()
        assert not rig.runner.mutations()


@pytest.mark.parametrize("property", ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition", "Conditions", "Asserts"))
@pytest.mark.parametrize("invalid", ("missing", "signature", "nonempty", "text", "unprintable", "null", "wrong_container"))
def test_v257_t6_each_property_requires_present_typed_empty_array(rig, property, invalid):
    values = rig.runner.services["enrichment.nextcloud_text"]
    if invalid == "missing":
        del values[property]
    elif invalid == "signature":
        values[property] = {"type": "as", "data": []}
    elif invalid == "nonempty":
        values[property] = {"type": "a(sbbsi)" if property in {"Conditions", "Asserts"} else "a(sasbttttuii)", "data": [["foreign"]]}
    else:
        values[property] = {"text": "", "unprintable": "[unprintable]", "null": None,
                            "wrong_container": {"type": "a(sasbttttuii)", "data": {}}}[invalid]
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID
    assert not rig.runner.mutations()


@pytest.mark.parametrize("stdout", ("", "[unprintable]\n", "bad json\n", "null\n",
    '{"type":"a(sasbttttuii)","type":"as","data":[]}\n',
    '{"type":"a(sasbttttuii)","data":[],"extra":true}\n', "x" * 65537))
def test_v257_t6_raw_typed_transport_failure_safe_and_never_empty_fallback(rig, monkeypatch, stdout):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[0] == "/usr/bin/busctl":
            result.stdout = stdout
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert CANARY not in str(error.value) and error.value.__suppress_context__
    assert not rig.runner.mutations()


@pytest.mark.parametrize("failure", (OSError(CANARY), subprocess.TimeoutExpired("fixed", 30, output=CANARY), KeyboardInterrupt(CANARY), 1))
def test_v257_t6_typed_failures_have_fixed_safe_code(rig, monkeypatch, failure):
    def transport(argv, **kwargs):
        if argv[0] == "/usr/bin/busctl":
            if isinstance(failure, BaseException):
                raise failure
            return subprocess.CompletedProcess(argv, failure, CANARY, CANARY)
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert error.value.code is WP8FailureCode.SERVICE_CONTRACT_INVALID
    assert CANARY not in str(error.value) and error.value.__suppress_context__
    assert not rig.runner.mutations()


def test_v257_t6_fixed_typed_transport_and_environment_no_mutation(rig, monkeypatch):
    for name in ("SYSTEMD_UNIT_PATH", "SYSTEMD_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS", "PATH", "NEXTCLOUD__PASSWORD"):
        monkeypatch.setenv(name, CANARY)
    rig.backend.verify_service_contract("enrichment.nextcloud_text")
    typed = [(argv, kwargs) for argv, kwargs in rig.runner.calls if argv[0] == "/usr/bin/busctl"]
    assert typed
    for argv, kwargs in typed:
        assert argv[:6] == ("/usr/bin/busctl", "--system", "--no-pager", "--json=short", "get-property", "org.freedesktop.systemd1")
        assert argv[6] in {"/org/freedesktop/systemd1/unit/pdi_2dscoped_2dpipeline_40enrichment_2enextcloud_5ftext_2eservice", "/org/freedesktop/systemd1/unit/emergency_2eservice"}
        expected = (("ExecStop", "ExecStopPost") if argv[6].endswith("emergency_2eservice") else
            ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition") if argv[7].endswith(".Service") else ("Conditions", "Asserts"))
        assert argv[8:] == expected
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL and kwargs["timeout"] == 30
    assert not rig.runner.mutations()


@pytest.mark.parametrize("authority,key", (("canonical_service", "enrichment.nextcloud_text"),
    ("emergency_stop", None), (module._TypedAuthority.CANONICAL_SERVICE, "synthetic.service"),
    (module._TypedAuthority.CANONICAL_SERVICE, "sysinit.target"), (module._TypedAuthority.EMERGENCY_STOP, "emergency.service"),
    (module._TypedAuthority.EMERGENCY_STOP, "shutdown.target"), (module._TypedAuthority.EMERGENCY_STOP, "ExecStart"),
    (module._TypedAuthority.EMERGENCY_STOP, "Environment")))
def test_v257_t6_typed_reader_not_an_arbitrary_capability(rig, authority, key):
    with pytest.raises(WP8ContractError):
        module._typed_empty(authority, key)
    assert not rig.runner.calls


@pytest.mark.parametrize("unit,property", (("emergency.service", "ExecStart"), ("emergency.service", "Environment"),
    ("sysinit.target", "ExecStop"), ("shutdown.target", "ExecStop"), ("synthetic.service", "ExecStop")))
def test_v257_emergency_allowlist_has_no_property_or_unit_selector(rig, unit, property):
    # Production API cannot encode these pairs at all, even as keyword input.
    with pytest.raises(TypeError):
        module._typed_empty(module._TypedAuthority.EMERGENCY_STOP, unit=unit, property=property)
    assert not rig.runner.calls


@pytest.mark.parametrize("property", ("ExecStop", "ExecStopPost"))
@pytest.mark.parametrize("invalid", ("missing", "wrong_signature", "nonempty", "text"))
def test_v257_emergency_empty_stop_guard_is_typed_not_weakened(rig, property, invalid):
    values = rig.runner.defaults["emergency.service"]
    if invalid == "missing":
        del values[property]
    else:
        values[property] = {"wrong_signature": {"type": "as", "data": []},
            "nonempty": {"type": "a(sasbttttuii)", "data": [["foreign"]]}, "text": ""}[invalid]
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("property,value", (("Id", "synthetic.service"), ("Names", "emergency.service alias.service"),
    ("Following", "synthetic.service"), ("Transient", "yes"), ("LoadState", "not-found"),
    ("FragmentPath", "/run/systemd/generator/emergency.service"), ("FragmentPath", "/etc/systemd/system/emergency@.service"),
    ("DropInPaths", "/etc/systemd/system/emergency.service.d/override.conf")))
def test_v257_emergency_identity_required_before_typed_query(rig, property, value):
    rig.runner.defaults["emergency.service"][property] = value
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not any(argv[0] == "/usr/bin/busctl" and argv[6].endswith("emergency_2eservice") for argv, _ in rig.runner.calls)
    assert not rig.runner.mutations()


def test_v257_emergency_only_reached_through_reviewed_sysinit_conflict(rig):
    rig.runner.defaults["sysinit.target"]["Conflicts"] = "emergency.target"
    rig.runner.defaults["system.slice"]["Conflicts"] += " emergency.service"
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not any(argv[0] == "/usr/bin/busctl" and argv[6].endswith("emergency_2eservice") for argv, _ in rig.runner.calls)
    assert not rig.runner.mutations()


def test_v257_emergency_typed_authority_drift_after_full_closure_refused(rig, monkeypatch):
    def drift():
        rig.runner.defaults["emergency.service"]["ExecStopPost"] = {"type": "a(sasbttttuii)", "data": [["foreign"]]}
    _attack_after_snapshot_a(rig, monkeypatch, drift)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("roots", ("", "/etc/systemd/system /etc/systemd/system", "/usr/lib/systemd/system /etc/systemd/system",
    "/etc/systemd/system /lib/systemd/system", "/etc/systemd/system /synthetic/unreviewed"))
def test_v257_t1_unitpath_exact_order_and_membership(rig, roots):
    rig.runner.manager["UnitPath"] = roots
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_t1_ordered_actual_unitpath_fingerprinted(rig, monkeypatch):
    captured = []
    original = module.contract_fingerprint
    def capture(value):
        if isinstance(value, dict) and "unit_path" in value:
            captured.append(value["unit_path"])
        return original(value)
    monkeypatch.setattr(module, "contract_fingerprint", capture)
    assert len(rig.backend.manager_identity().fingerprint) == 64
    assert captured == [list(REVIEWED_UNITPATH)]


@pytest.mark.parametrize("line", ('{"type":"a(sasbttttuii)","type":"a(sasbttttuii)","data":[]}',
    '{"type":"a(sasbttttuii)","data":[],"extra":true}',
    '{"type":"a(sasbttttuii)","data":null}',
    '{"type":"a(sasbttttuii)","data":[[]]}'))
def test_v257_t6_correct_response_count_still_requires_exact_schema(rig, monkeypatch, line):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[0] == "/usr/bin/busctl":
            lines = result.stdout.splitlines()
            lines[0] = line
            result.stdout = "\n".join(lines) + "\n"
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_emergency_exact_empty_stop_proof_is_bound_in_closure_seal(rig, monkeypatch):
    captured = []
    original = module.contract_fingerprint
    def capture(value):
        captured.append(value)
        return original(value)
    monkeypatch.setattr(module, "contract_fingerprint", capture)
    assert len(rig.backend.verify_service_contract("enrichment.nextcloud_text")) == 64
    sealed = [value["defaults"]["emergency.service:STOP"]["properties"] for value in captured
              if isinstance(value, dict) and "emergency.service:STOP" in value.get("defaults", {})]
    assert sealed
    for value in sealed:
        assert value["ExecStop"] == {"type": "a(sasbttttuii)", "data": []}
        assert value["ExecStopPost"] == {"type": "a(sasbttttuii)", "data": []}
    typed = [argv for argv, _ in rig.runner.calls if argv[0] == "/usr/bin/busctl" and argv[6].endswith("emergency_2eservice")]
    assert typed and all(argv[8:] == ("ExecStop", "ExecStopPost") for argv in typed)
    assert not rig.runner.mutations()


@pytest.mark.parametrize("unit", ("canonical", "emergency"))
def test_v257_typed_query_identity_rebound_before_consumption(rig, monkeypatch, unit):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[0] == "/usr/bin/busctl":
            if unit == "canonical" and "enrichment_2enextcloud_5ftext" in argv[6]:
                rig.runner.services["enrichment.nextcloud_text"]["Names"] += " alias.service"
            if unit == "emergency" and argv[6].endswith("emergency_2eservice"):
                rig.runner.defaults["emergency.service"]["Transient"] = "yes"
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


def test_v257_typed_untrusted_transport_binary_refused(rig, monkeypatch):
    monkeypatch.setattr(module, "_trusted", lambda path, **_: path != Path("/usr/bin/busctl"))
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not any(argv[0] == "/usr/bin/busctl" for argv, _ in rig.runner.calls)
    assert not rig.runner.mutations()


# Final continuity attacks change LIVE authority AFTER the fake transport has
# rendered an old valid response, reproducing the independent review's window.
# Literal property names/signatures/paths are not taken from backend constants.
def _nonempty_authority(name):
    if name == "PrivateTmpEx":
        return "disconnected"
    signature = "a(sbbsi)" if name in {"Conditions", "Asserts"} else "a(sasbttttuii)"
    return {"type": signature, "data": [["synthetic-unreviewed-authority"]]}


def _attack_after_snapshot_a(rig, monkeypatch, attack):
    """CATEGORY_A: old full-proof attacks now sit between complete A and B.

    They still require zero mutations; none are reclassified as residual races.
    """
    original = rig.backend._collect_complete_start_authority_snapshot
    observed = []
    def collect(key):
        snapshot = original(key)
        if not observed:
            observed.append(snapshot)
            attack()
        return snapshot
    monkeypatch.setattr(rig.backend, "_collect_complete_start_authority_snapshot", collect)


@pytest.mark.parametrize("property", ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
                                      "ExecCondition", "Conditions", "Asserts", "PrivateTmpEx"))
def test_v257_continuity_start_rejects_drift_after_final_typed_response(rig, monkeypatch, property):
    armed, injected = [], []
    monkeypatch.setattr(module, "_current_candidate", lambda _: armed.append(True))
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (armed and not injected and argv[0] == "/usr/bin/busctl" and
                "enrichment_2enextcloud_5ftext" in argv[6] and
                (property == "PrivateTmpEx" or property in argv[8:])):
            rig.runner.services["enrichment.nextcloud_text"][property] = _nonempty_authority(property)
            injected.append(property)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as error:
        rig.backend.start_service("enrichment.nextcloud_text")
    assert injected == [property]
    assert not rig.runner.mutations(), "must reject BEFORE start, not in post-start verification"
    assert CANARY not in str(error.value) and error.value.__suppress_context__


@pytest.mark.parametrize("key", ("enrichment.nextcloud_text", "enrichment.nextcloud_documents",
                                  "enrichment.file_metadata", "enrichment.immich_geo",
                                  "enrichment.immich_metadata", "enrichment.immich_ocr"))
@pytest.mark.parametrize("property", ("ExecStop", "ExecStopPost"))
def test_v257_continuity_stop_rejects_drift_per_unit_after_final_typed_response(rig, monkeypatch, key, property):
    shows, armed, injected = [], [], []
    original = rig.backend._show
    def observed(selected):
        if selected == key:
            shows.append(selected)
            if len(shows) == 2:  # fresh per-unit observation after its full proof
                armed.append(True)
        return original(selected)
    monkeypatch.setattr(rig.backend, "_show", observed)
    # Use independent literal unit identity, not the production unit map.
    object_label = "".join(c if c.isascii() and c.isalnum() else f"_{ord(c):02x}"
                           for c in f"pdi-scoped-pipeline@{key}.service")
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (armed and not injected and argv[0] == "/usr/bin/busctl" and
                argv[6].endswith("/" + object_label) and property in argv[8:]):
            rig.runner.services[key][property] = _nonempty_authority(property)
            injected.append(property)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    cleanup = rig.backend.stop_all_services()
    assert injected == [property]
    stops = rig.runner.mutations()
    assert len(stops) == 5 and all(argv[4] == "stop" for argv in stops)
    assert {argv[5] for argv in stops} == {f"pdi-scoped-pipeline@{other}.service" for other in KEYS if other != key}
    assert cleanup.stop_failure_count == 1 and cleanup.service_state == "NOT_CONFIRMED"
    unsafe = next(attempt for attempt in cleanup.attempts if attempt.pipeline_key == key)
    assert unsafe.outcome is module._Outcome.EVIDENCE_REJECTED and unsafe.final_state == "NOT_CONFIRMED"
    assert cleanup.timer_state == "DISABLED_INACTIVE" and cleanup.p3c_state == "UNCHANGED_HEALTHY"


@pytest.mark.parametrize("property", ("ExecStop", "ExecStopPost"))
def test_v257_continuity_emergency_drift_after_final_typed_response_blocks_start(rig, monkeypatch, property):
    armed, injected = [], []
    # A completes before B's independently recollected emergency authority.
    monkeypatch.setattr(module, "_current_candidate", lambda _: armed.append(True))
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (armed and not injected and argv[0] == "/usr/bin/busctl" and
                argv[6].endswith("/emergency_2eservice")):
            rig.runner.defaults["emergency.service"][property] = _nonempty_authority(property)
            injected.append(property)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert injected == [property] and not rig.runner.mutations()


@pytest.mark.parametrize("stage,interface", (
    ("start", "Service"), ("start", "Unit"), ("stop", "Service"), ("stop", "Unit"), ("emergency", "Service"),
))
@pytest.mark.parametrize("failure", ("timeout", "command", "malformed", "signature", "missing"))
def test_v257_continuity_final_typed_recollection_failure_never_uses_old_proof(rig, monkeypatch, stage, interface, failure):
    armed, reads, injected = [], [], []
    if stage == "start":
        monkeypatch.setattr(module, "_current_candidate", lambda _: armed.append(True))
    elif stage == "emergency":
        monkeypatch.setattr(module, "_current_candidate", lambda _: armed.append(True))
    else:
        original = rig.backend._show
        shows = []
        def observed(key):
            if key == "enrichment.nextcloud_text":
                shows.append(key)
                if len(shows) == 2:
                    armed.append(True)
            return original(key)
        monkeypatch.setattr(rig.backend, "_show", observed)
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        target = "emergency_2eservice" if stage == "emergency" else "enrichment_2enextcloud_5ftext_2eservice"
        if (armed and argv[0] == "/usr/bin/busctl" and argv[6].endswith(target) and
                argv[7] == "org.freedesktop.systemd1." + interface):
            reads.append(True)
            if len(reads) == 2:  # first valid typed read cannot substitute for this one
                injected.append(failure)
                if failure == "timeout":
                    raise subprocess.TimeoutExpired(argv, 30, output=CANARY, stderr=CANARY)
                if failure == "command":
                    result.returncode = 1
                elif failure == "malformed":
                    result.stdout = "not-json " + CANARY
                elif failure == "signature":
                    result.stdout = result.stdout.replace("a(sasbttttuii)", "s").replace("a(sbbsi)", "s")
                elif failure == "missing":
                    result.stdout = "\n".join(result.stdout.splitlines()[1:]) + "\n"
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    if stage == "stop":
        cleanup = rig.backend.stop_all_services()
        assert cleanup.stop_failure_count == 1
        assert not any(argv[5] == "pdi-scoped-pipeline@enrichment.nextcloud_text.service" for argv in rig.runner.mutations())
        assert len(rig.runner.mutations()) == 5
    else:
        with pytest.raises(WP8ContractError) as error:
            rig.backend.start_service("enrichment.nextcloud_text")
        assert not rig.runner.mutations()
        assert CANARY not in str(error.value)
    assert injected == [failure]


@pytest.mark.parametrize("missing", REVIEWED_UNITPATH)
def test_v257_continuity_each_reviewed_unitpath_root_is_required(rig, missing):
    rig.runner.manager["UnitPath"] = " ".join(root for root in REVIEWED_UNITPATH if root != missing)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("roots", (
    ("/etc/systemd/system",), (),
    (*REVIEWED_UNITPATH, "/synthetic/unreviewed"),
    (*REVIEWED_UNITPATH, "/etc/systemd/system"),
    (REVIEWED_UNITPATH[1], REVIEWED_UNITPATH[0], *REVIEWED_UNITPATH[2:]),
    (*REVIEWED_UNITPATH[:-1], "/run/systemd/generator.late/"),
))
def test_v257_continuity_unitpath_subset_extra_duplicate_reordered_malformed_refused(rig, roots):
    rig.runner.manager["UnitPath"] = " ".join(roots)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert not rig.runner.mutations()


@pytest.mark.parametrize("stage", ("start", "stop"))
def test_v257_continuity_stable_text_drift_must_match_full_authority_seal(rig, monkeypatch, stage):
    injected = []
    if stage == "start":
        def current(_):
            # Valid ordering-only text is NOT an extra activation authority,
            # but changing it must invalidate the earlier full authority seal.
            if not injected:
                rig.runner.services["enrichment.nextcloud_text"]["After"] += " synthetic-order-only.target"
                injected.append(True)
        monkeypatch.setattr(module, "_current_candidate", current)
        with pytest.raises(WP8ContractError):
            rig.backend.start_service("enrichment.nextcloud_text")
        assert not rig.runner.mutations()
    else:
        original = rig.backend._show
        shows = []
        def observed(key):
            if key == "enrichment.nextcloud_text":
                shows.append(key)
                if len(shows) == 2:
                    rig.runner.services[key]["After"] += " synthetic-order-only.target"
                    injected.append(True)
            return original(key)
        monkeypatch.setattr(rig.backend, "_show", observed)
        cleanup = rig.backend.stop_all_services()
        assert cleanup.stop_failure_count == 1
        assert len(rig.runner.mutations()) == 5
        assert not any(argv[5] == "pdi-scoped-pipeline@enrichment.nextcloud_text.service" for argv in rig.runner.mutations())
    assert injected == [True]


@pytest.mark.parametrize("property", ("PrivateTmpEx", "After", "RequiresMountsFor"))
def test_v257_continuity_no_stable_text_drift_hidden_inside_collection(rig, monkeypatch, property):
    armed, injected = [], []
    monkeypatch.setattr(module, "_current_candidate", lambda _: armed.append(True))
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (armed and not injected and argv[0] == "/usr/bin/busctl" and
                "enrichment_2enextcloud_5ftext" in argv[6]):
            rig.runner.services["enrichment.nextcloud_text"][property] += " synthetic-drift"
            injected.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service("enrichment.nextcloud_text")
    assert injected == [True] and not rig.runner.mutations()


def test_v257_continuity_authority_seal_excludes_separate_volatile_prerequisite_facts(rig, monkeypatch):
    values = rig.backend._show("enrichment.nextcloud_text")
    expected = module._check_service(values, "enrichment.nextcloud_text", rig.assets)
    changed = dict(values, ActiveState="active", SubState="running", Job="123", Result="exit-code",
                   ExecMainCode="2", ExecMainStatus="1", ExecMainStartTimestampMonotonic="1100",
                   ExecMainExitTimestampMonotonic="1200", InvocationID="2" * 32,
                   ConditionResult="no", AssertResult="no")
    changed["ExecStart"] = values["ExecStart"].replace("start_time=[n/a]", "start_time=[synthetic-start]").replace(
        "stop_time=[n/a]", "stop_time=[synthetic-exit]").replace("pid=0", "pid=123").replace(
        "code=(null) ; status=0/0", "code=exited ; status=0/SUCCESS")
    assert module._check_service(changed, "enrichment.nextcloud_text", rig.assets) == expected
    with pytest.raises(WP8ContractError):
        module._require_inactive(changed)


def test_v257_continuity_completed_invocation_execstart_runtime_is_not_contract_drift(rig, monkeypatch):
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[4] == "start":
            values = rig.runner.services["enrichment.nextcloud_text"]
            values["ExecStart"] = values["ExecStart"].replace("start_time=[n/a]", "start_time=[synthetic-start]").replace(
                "stop_time=[n/a]", "stop_time=[synthetic-exit]").replace("pid=0", "pid=123").replace(
                "code=(null) ; status=0/0", "code=exited ; status=0/SUCCESS")
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    assert rig.backend.start_service("enrichment.nextcloud_text").outcome is module._Outcome.SUCCESS
    assert len(rig.runner.mutations()) == 1


def test_v257_continuity_every_service_mutation_follows_fresh_sealed_typed_observation(rig):
    rig.backend.start_service("enrichment.nextcloud_text")
    assert rig.backend.stop_all_services().stop_failure_count == 0
    calls = [argv for argv, _ in rig.runner.calls]
    commands = [i for i, argv in enumerate(calls) if argv[4] in {"start", "stop"}]
    assert len(commands) == 7
    previous = 0
    for i in commands:
        unit_name = calls[i][5]
        expected_object = "/org/freedesktop/systemd1/unit/" + "".join(
            c if c.isascii() and c.isalnum() else f"_{ord(c):02x}" for c in unit_name)
        typed = [argv for argv in calls[previous:i] if argv[0] == "/usr/bin/busctl" and
                 argv[6] == expected_object]
        # Each target has fresh Service + Unit typed reads in both complete
        # snapshots, before bounded runtime projections (not after them).
        assert len(typed) >= 8
        service, unit = typed[-2:]
        assert service[:6] == unit[:6] == ("/usr/bin/busctl", "--system", "--no-pager", "--json=short",
                                           "get-property", "org.freedesktop.systemd1")
        assert service[6] == unit[6] == expected_object
        assert service[7:] == ("org.freedesktop.systemd1.Service", "ExecStartPre", "ExecStartPost",
                               "ExecStop", "ExecStopPost", "ExecCondition")
        assert unit[7:] == ("org.freedesktop.systemd1.Unit", "Conditions", "Asserts")
        assert calls[i - 1][4:6] == ("show", unit_name)
        previous = i + 1
