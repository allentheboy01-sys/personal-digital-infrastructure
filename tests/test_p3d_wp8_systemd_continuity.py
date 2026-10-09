"""Independent complete-snapshot and residual-race protocol tests (no real IO)."""

from dataclasses import replace
import json
import subprocess

import pytest

from tests.test_p3d_wp8_systemd import rig, module, KEYS, H, CANARY, _nonempty_authority
from pdi.production_ops.p3d_wp8_contracts import WP8ContractError

PIPELINES = (
    "enrichment.nextcloud_text", "enrichment.nextcloud_documents", "enrichment.file_metadata",
    "enrichment.immich_geo", "enrichment.immich_metadata", "enrichment.immich_ocr",
)
TYPED = ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition", "Conditions", "Asserts")
RELATIONS = ("Wants", "Requires", "Requisite", "BindsTo", "PartOf", "ConsistsOf", "Upholds",
    "RequiredBy", "RequisiteOf", "WantedBy", "BoundBy", "UpheldBy", "Conflicts", "ConflictedBy",
    "OnFailure", "OnSuccess", "OnFailureOf", "OnSuccessOf", "Triggers", "TriggeredBy",
    "PropagatesStopTo", "StopPropagatedFrom", "PropagatesReloadTo", "ReloadPropagatedFrom",
    "JoinsNamespaceOf", "SliceOf", "RequiresMountsFor", "WantsMountsFor", "Before", "After")
SERVICE_TEXT = ("Id", "LoadState", "FragmentPath", "DropInPaths", "Transient", "NeedDaemonReload",
    "Names", "Following", "User", "Group", "Type", "WorkingDirectory", "EnvironmentFiles", "ExecStart",
    "NoNewPrivileges", "PrivateTmp", "PrivateTmpEx", "ProtectSystem", "ProtectHome", "ReadWritePaths",
    "TimeoutStartUSec", "TimeoutStopUSec", "KillMode", "StandardOutput", "StandardError", "RemainAfterExit",
    "Restart", "FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction", "DefaultDependencies", "Slice")
DEFAULTS = {"sysinit.target:START", "local-fs.target:START", "swap.target:START",
    r"system-pdi\x2dscoped\x2dpipeline.slice:START", "system.slice:START", "-.slice:START",
    "tmp.mount:START", "shutdown.target:STOP", "umount.target:STOP", "emergency.target:STOP", "emergency.service:STOP"}
VOLATILE = {"ActiveState", "SubState", "Job", "Result", "ExecMainCode", "ExecMainStatus",
            "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic", "InvocationID",
            "ConditionResult", "AssertResult"}


def test_complete_snapshot_collection(rig):
    # Exercise the implementation below its safe exception boundary as well:
    # malformed implementation must not be mistaken for an expected rejection.
    snapshot = module.WP8ProductionSystemdBackend._collect_complete_authority_snapshot.__wrapped__(
        rig.backend, KEYS[0], module._JobAuthority.START)
    assert len(snapshot.fingerprint) == 64
    assert not rig.runner.mutations()


@pytest.mark.parametrize("direction", ("start", "stop"))
def test_snapshot_domain_independently_enumerated_not_production_projection(rig, monkeypatch, direction):
    payloads = []
    fingerprint = module.contract_fingerprint
    def capture(value):
        if isinstance(value, dict) and set(value) == {"direction", "pipeline", "manager", "context",
                "runtime", "assets", "services", "timers", "p3c", "closure"}:
            payloads.append(value)
        return fingerprint(value)
    monkeypatch.setattr(module, "contract_fingerprint", capture)
    collector = getattr(rig.backend, f"_collect_complete_{direction}_authority_snapshot")
    a, b = collector(PIPELINES[0]), collector(PIPELINES[0])
    assert len(payloads) == 2
    assert a.domain == b.domain and a.fingerprint == b.fingerprint
    for payload in payloads:
        assert set(payload["manager"]) == {"fingerprint", "boot", "host_class", "domain", "continuity"}
        assert set(payload["context"]) == {"candidate", "phase_a", "current_candidate", "gate_b", "gate_c"}
        assert set(payload["services"]) == (set(PIPELINES) if direction == "start" else {PIPELINES[0]})
        for service in payload["services"].values():
            assert set(service) == {"text", "typed", "members"}
            assert set(service["text"]) == set(SERVICE_TEXT) | set(RELATIONS)
            assert set(service["typed"]) == set(TYPED)
            assert set(service["members"]) == set(RELATIONS)
            assert not VOLATILE & set(service["text"])
            for name in TYPED:
                assert service["typed"][name] == {"type": "a(sbbsi)" if name in {"Conditions", "Asserts"}
                                                 else "a(sasbttttuii)", "data": []}
        assert set(payload["timers"]) == set(PIPELINES)
        for timer in payload["timers"].values():
            assert set(timer) == {"Id", "LoadState", "FragmentPath", "DropInPaths", "Transient", "NeedDaemonReload", "Unit"}
        assert set(payload["p3c"]) == {"pdi-p3c-nextcloud-incremental.timer", "pdi-p3c-nextcloud-full.timer",
            "pdi-p3c-immich-incremental.timer", "pdi-p3c-immich-daily.timer", "pdi-p3c-writer@.service"}
        for p3c in payload["p3c"].values():
            assert set(p3c) == {"Id", "LoadState", "UnitFileState", "FragmentPath"}
        assert set(payload["closure"]["defaults"]) == (DEFAULTS if direction == "start" else set())
        for unit, values in payload["closure"]["defaults"].items():
            assert not VOLATILE & set(values["properties"])
            assert set(values["members"]) == set(RELATIONS)
            if unit == "emergency.service:STOP":
                assert {"ExecStop", "ExecStopPost"} <= set(values["properties"])
    # Even byte-identical snapshots use distinct newly parsed objects.
    assert payloads[0] is not payloads[1]
    assert payloads[0]["services"][PIPELINES[0]]["typed"] is not payloads[1]["services"][PIPELINES[0]]["typed"]


@pytest.mark.parametrize("direction", ("start", "stop"))
def test_b_independently_recollects_all_io_even_when_identical(rig, monkeypatch, direction):
    facts = []
    monkeypatch.setattr(module, "_verify_candidate", lambda _: facts.append("runtime") or H)
    monkeypatch.setattr(module, "_read_assets", lambda _: facts.append("assets") or rig.assets)
    collector = getattr(rig.backend, f"_collect_complete_{direction}_authority_snapshot")
    traces = []
    for _ in range(2):
        boundary = len(rig.runner.calls)
        collector(PIPELINES[0])
        traces.append([argv for argv, _ in rig.runner.calls[boundary:]])
    assert facts == ["runtime", "assets", "runtime", "assets"]
    assert traces[0] == traces[1]
    for calls in traces:
        assert sum(argv[4] == "show" and argv[5] == "--all" for argv in calls) == 1
        for pipeline in PIPELINES if direction == "start" else (PIPELINES[0],):
            label = "".join(c if c.isascii() and c.isalnum() else f"_{ord(c):02x}"
                            for c in f"pdi-scoped-pipeline@{pipeline}.service")
            typed = [argv for argv in calls if argv[0] == "/usr/bin/busctl" and argv[6].endswith("/" + label)]
            assert len(typed) == 4  # two fresh Service/Unit pairs within each collection
            assert set(typed[0][8:]) | set(typed[1][8:]) == set(TYPED)
        emergency = [argv for argv in calls if argv[0] == "/usr/bin/busctl" and argv[6].endswith("/emergency_2eservice")]
        assert len(emergency) == (2 if direction == "start" else 0)


@pytest.mark.parametrize("attack", ("text", "typed", "emergency", "graph", "mount", "manager",
                                    "current", "timer", "p3c", "runtime", "assets"))
def test_category_a_observable_snapshot_drift_zero_start(rig, monkeypatch, attack):
    original = rig.backend._collect_complete_start_authority_snapshot
    snapshots = []
    def collect(key):
        value = original(key)
        snapshots.append(value)
        if len(snapshots) == 1:
            if attack == "text":
                rig.runner.services[PIPELINES[2]]["After"] += " synthetic-order.target"
            elif attack == "typed":
                rig.runner.services[PIPELINES[2]]["ExecCondition"] = _nonempty_authority("ExecCondition")
            elif attack == "emergency":
                rig.runner.defaults["emergency.service"]["ExecStopPost"] = _nonempty_authority("ExecStopPost")
            elif attack == "graph":
                rig.runner.defaults["local-fs.target"]["Wants"] = "var.mount"
            elif attack == "mount":
                rig.runner.services[PIPELINES[0]]["Requires"] += " opt.mount"
                rig.runner.services[PIPELINES[0]]["After"] += " opt.mount"
            elif attack == "manager":
                rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
            elif attack == "current":
                monkeypatch.setattr(module, "_current_candidate", lambda _: module._fail(module.WP8FailureCode.CURRENT_DRIFT))
            elif attack == "timer":
                rig.runner.timers[PIPELINES[3]]["FragmentPath"] += ".foreign"
            elif attack == "p3c":
                rig.runner.p3c_revision = ".foreign"
            elif attack == "runtime":
                monkeypatch.setattr(module, "_verify_candidate", lambda _: "2" * 64)
            else:
                monkeypatch.setattr(module, "_read_assets", lambda _: replace(rig.assets, fingerprint="2" * 64))
        return value
    monkeypatch.setattr(rig.backend, "_collect_complete_start_authority_snapshot", collect)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(PIPELINES[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("direction", ("start", "stop"))
@pytest.mark.parametrize("change", ("addition", "removal", "digest"))
def test_domain_checked_even_if_aggregate_hash_is_identical(rig, monkeypatch, direction, change):
    original = getattr(rig.backend, f"_collect_complete_{direction}_authority_snapshot")
    samples = []
    def collect(key):
        value = original(key)
        if key == PIPELINES[0]:
            samples.append(value)
            if len(samples) == 2:
                if change == "addition":
                    value = replace(value, domain=(*value.domain, "/synthetic_extra"))
                elif change == "removal":
                    value = replace(value, domain=value.domain[:-1])
                else:
                    value = replace(value, fingerprint="2" * 64)
        return value
    monkeypatch.setattr(rig.backend, f"_collect_complete_{direction}_authority_snapshot", collect)
    if direction == "start":
        with pytest.raises(WP8ContractError):
            rig.backend.start_service(PIPELINES[0])
        assert not rig.runner.mutations()
    else:
        result = rig.backend.stop_all_services()
        assert result.stop_failure_count == 1 and result.service_state == "NOT_CONFIRMED"
        assert len(rig.runner.mutations()) == 5
        assert all(argv[5] != f"pdi-scoped-pipeline@{PIPELINES[0]}.service" for argv in rig.runner.mutations())


@pytest.mark.parametrize("change", ("default_add", "default_remove", "emergency_remove", "mount_add"))
def test_real_reachable_domain_changes_rejected(rig, change):
    a = rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    if change == "default_add":
        rig.runner.defaults["local-fs.target"]["Requires"] = "var.mount"
    elif change == "default_remove":
        rig.runner.defaults["sysinit.target"]["Wants"] = "local-fs.target"
    elif change == "emergency_remove":
        rig.runner.defaults["sysinit.target"]["Conflicts"] = "emergency.target"
    else:
        rig.runner.services[PIPELINES[0]]["Requires"] += " opt.mount"
        rig.runner.services[PIPELINES[0]]["After"] += " opt.mount"
    b = rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    assert a.domain != b.domain
    with pytest.raises(WP8ContractError):
        module._same_snapshot(a, b)
    assert not rig.runner.mutations()


@pytest.mark.parametrize("pipeline", PIPELINES)
@pytest.mark.parametrize("property", ("After", "ExecStopPost"))
def test_category_a_stop_snapshots_per_target_unsafe_target_only(rig, monkeypatch, pipeline, property):
    original = rig.backend._collect_complete_stop_authority_snapshot
    samples = {}
    def collect(key):
        value = original(key)
        samples[key] = samples.get(key, 0) + 1
        if key == pipeline and samples[key] == 1:
            if property == "After":
                rig.runner.services[key][property] += " synthetic-order.target"
            else:
                rig.runner.services[key][property] = _nonempty_authority(property)
        return value
    monkeypatch.setattr(rig.backend, "_collect_complete_stop_authority_snapshot", collect)
    result = rig.backend.stop_all_services()
    assert result.stop_failure_count == 1 and result.service_state == "NOT_CONFIRMED"
    assert len(rig.runner.mutations()) == 5
    assert all(argv[5] != f"pdi-scoped-pipeline@{pipeline}.service" for argv in rig.runner.mutations())
    for key in PIPELINES:
        if key != pipeline:
            assert samples[key] == 3  # A, B and independent post-stop snapshot


@pytest.mark.parametrize("direction", ("start", "stop"))
@pytest.mark.parametrize("attack", ("typed", "text", "current", "manager"))
def test_category_b_privileged_external_race_observable_post_failure_not_atomic_claim(rig, monkeypatch, direction, attack):
    # Inject AFTER B and the final runtime gate, immediately before the fixed
    # command is processed. API has no atomic CAS: command may already issue.
    original = rig.backend._final_runtime_prerequisites
    injected = []
    def final(key, snapshot, **kwargs):
        values = original(key, snapshot, **kwargs)
        if key == PIPELINES[0] and not injected:
            injected.append(attack)
            if attack == "typed":
                rig.runner.services[key]["ExecStopPost"] = _nonempty_authority("ExecStopPost")
            elif attack == "text":
                rig.runner.services[key]["After"] += " synthetic-order.target"
            elif attack == "current":
                monkeypatch.setattr(module, "_current_candidate", lambda _: module._fail(module.WP8FailureCode.CURRENT_DRIFT))
            else:
                rig.facts["boot"] = "21111111-2222-4333-8444-555555555555"
        return values
    monkeypatch.setattr(rig.backend, "_final_runtime_prerequisites", final)
    if direction == "start":
        with pytest.raises(WP8ContractError) as caught:
            rig.backend.start_service(PIPELINES[0])
        assert len(rig.runner.mutations()) == 1
        assert CANARY not in str(caught.value)
    else:
        result = rig.backend.stop_all_services()
        assert result.stop_failure_count >= 1 and result.service_state == "NOT_CONFIRMED"
        assert result.attempts[0].final_state == "NOT_CONFIRMED"
        assert sum(argv[5] == f"pdi-scoped-pipeline@{PIPELINES[0]}.service" for argv in rig.runner.mutations()) == 1
        assert CANARY not in repr(result)


def test_complete_protocol_no_persistent_lock_or_extra_public_api(rig, monkeypatch):
    events = []
    collect = rig.backend._collect_complete_start_authority_snapshot
    final = rig.backend._final_runtime_prerequisites
    equal = module._same_snapshot
    def sample(key):
        value = collect(key)
        events.append("snapshot")
        return value
    def equality(a, b):
        equal(a, b)
        events.append("equal_domain_digest")
    def runtime(*args, **kwargs):
        assert events == ["snapshot", "snapshot", "equal_domain_digest"]
        value = final(*args, **kwargs)
        events.append("runtime")
        return value
    def transport(argv, **kwargs):
        if argv[4] == "start":
            assert events[-1] == "runtime"
            events.append("start")
        return rig.runner(argv, **kwargs)
    monkeypatch.setattr(rig.backend, "_collect_complete_start_authority_snapshot", sample)
    monkeypatch.setattr(rig.backend, "_final_runtime_prerequisites", runtime)
    monkeypatch.setattr(module, "_same_snapshot", equality)
    monkeypatch.setattr(module.subprocess, "run", transport)
    assert rig.backend.start_service(PIPELINES[0]).outcome is module._Outcome.SUCCESS
    assert events == ["snapshot", "snapshot", "equal_domain_digest", "runtime", "start", "snapshot", "equal_domain_digest"]
    assert {name for name in dir(type(rig.backend)) if not name.startswith("_")} == {
        "manager_identity", "daemon_reload", "snapshot_p3c", "verify_timers_quiet", "verify_service_contract",
        "start_service", "stop_all_services", "verify_all_services_inactive"}


@pytest.mark.parametrize("pipeline", PIPELINES)
@pytest.mark.parametrize("property", TYPED)
def test_complete_start_includes_fresh_typed_authority_of_every_service(rig, monkeypatch, pipeline, property):
    original = rig.backend._collect_complete_start_authority_snapshot
    seen = []
    def collect(key):
        value = original(key)
        if not seen:
            seen.append(value)
            rig.runner.services[pipeline][property] = _nonempty_authority(property)
        return value
    monkeypatch.setattr(rig.backend, "_collect_complete_start_authority_snapshot", collect)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(PIPELINES[0])
    assert not rig.runner.mutations()


@pytest.mark.parametrize("attack", ("timer_enabled", "timer_active", "timer_job", "other_active",
                                    "other_job", "target_job", "default_job", "p3c_health"))
def test_final_runtime_gate_rechecks_volatile_prerequisites_after_equal_snapshots(rig, monkeypatch, attack):
    original = rig.backend._final_runtime_prerequisites
    seen = []
    def final(*args, **kwargs):
        seen.append(True)
        if attack == "timer_enabled":
            rig.runner.enabled[PIPELINES[1]] = (0, "enabled\n")
        elif attack == "timer_active":
            rig.runner.active[PIPELINES[1]] = (0, "active\n")
        elif attack == "timer_job":
            rig.runner.timers[PIPELINES[1]]["Job"] = "123"
        elif attack == "other_active":
            rig.runner.services[PIPELINES[4]].update(ActiveState="active", SubState="running")
        elif attack == "other_job":
            rig.runner.services[PIPELINES[4]]["Job"] = "123"
        elif attack == "target_job":
            rig.runner.services[PIPELINES[0]]["Job"] = "123"
        elif attack == "default_job":
            rig.runner.defaults["sysinit.target"]["Job"] = "123"
        else:
            rig.runner.p3c_healthy = False
        return original(*args, **kwargs)
    monkeypatch.setattr(rig.backend, "_final_runtime_prerequisites", final)
    with pytest.raises(WP8ContractError):
        rig.backend.start_service(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()


def test_snapshot_excludes_runtime_volatility_and_normalizes_relation_order(rig):
    a = rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    for service in rig.runner.services.values():
        service.update(Result="exit-code", ExecMainCode="2", ExecMainStatus="1",
            ExecMainStartTimestampMonotonic="1110", ExecMainExitTimestampMonotonic="1120",
            InvocationID="2" * 32, ConditionResult="no", AssertResult="no")
        for relation in RELATIONS:
            service[relation] = " ".join(reversed(service[relation].split()))
    rig.runner.defaults["sysinit.target"]["Wants"] = "swap.target local-fs.target"
    rig.runner.defaults[r"system-pdi\x2dscoped\x2dpipeline.slice"].update(ActiveState="active", SubState="active")
    b = rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    assert a.domain == b.domain and a.fingerprint == b.fingerprint


def test_stop_walks_stop_direction_not_start_dependencies(rig):
    # A START would reject this default. STOP's source has no outgoing STOP
    # propagation under the reviewed contract, so this is outside STOP domain.
    rig.runner.defaults["sysinit.target"]["Requires"] = "synthetic-foreign.service"
    snapshot = rig.backend._collect_complete_stop_authority_snapshot(PIPELINES[0])
    assert snapshot.closure.authority["direction"] == "STOP"
    assert snapshot.closure.authority["defaults"] == snapshot.closure.authority["edges"] == {}
    assert not any(argv[4:6] == ("show", "sysinit.target") for argv, _ in rig.runner.calls)
    assert not any(argv[0] == "/usr/bin/busctl" and argv[6].endswith("/emergency_2eservice") for argv, _ in rig.runner.calls)
    assert not rig.runner.mutations()


P3C_TIMER = "pdi-p3c-nextcloud-incremental.timer"


def _arm_final_gate(rig, monkeypatch):
    """Observe only final-gate reads, after the actual independent A/B pair."""
    original = rig.backend._final_runtime_prerequisites
    stage = {"key": None, "p3c_shows": 0}
    def final(key, snapshot, **kwargs):
        stage.update(key=key, p3c_shows=0)
        try:
            return original(key, snapshot, **kwargs)
        finally:
            stage["key"] = None
    monkeypatch.setattr(rig.backend, "_final_runtime_prerequisites", final)
    return stage


def _inject_fresh_p3c_health(rig, monkeypatch, stage=None):
    """Literal unhealthy transport reply, not a production-derived mapping."""
    seen = []
    local = {"p3c_shows": 0}
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (argv[0] == "/usr/bin/systemctl" and argv[4:6] == ("show", P3C_TIMER)
                and (stage is None or stage["key"] == PIPELINES[0])):
            counter = local if stage is None else stage
            counter["p3c_shows"] += 1
            if counter["p3c_shows"] == 2:
                result.stdout = result.stdout.replace("ActiveState=active\n", "ActiveState=inactive\n").replace(
                    "SubState=waiting\n", "SubState=dead\n")
                assert "ActiveState=inactive\n" in result.stdout and "SubState=dead\n" in result.stdout
                seen.append(True)  # This exact unsafe reply is returned to the backend.
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    return seen


def test_p1_a_final_default_conflict_rejected_before_start(rig, monkeypatch):
    stage = _arm_final_gate(rig, monkeypatch)
    seen = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (stage["key"] == PIPELINES[0] and argv[0] == "/usr/bin/systemctl"
                and argv[4:6] == ("show", "tmp.mount")):
            result.stdout = result.stdout.replace("Conflicts=umount.target\n",
                "Conflicts=umount.target pdi-p3c-nextcloud-incremental.timer\n")
            assert f"Conflicts=umount.target {P3C_TIMER}\n" in result.stdout
            seen.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as caught:
        rig.backend.start_service(PIPELINES[0])
    assert seen and not rig.runner.mutations()
    assert caught.value.code is module.WP8FailureCode.SERVICE_CONTRACT_INVALID
    assert CANARY not in str(caught.value)


def test_p1_b_intra_snapshot_fresh_p3c_health_rejected(rig, monkeypatch):
    seen = _inject_fresh_p3c_health(rig, monkeypatch)
    with pytest.raises(WP8ContractError) as caught:
        rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert CANARY not in str(caught.value)


def test_p1_c_final_start_fresh_p3c_health_rejected(rig, monkeypatch):
    seen = _inject_fresh_p3c_health(rig, monkeypatch, _arm_final_gate(rig, monkeypatch))
    with pytest.raises(WP8ContractError) as caught:
        rig.backend.start_service(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert CANARY not in str(caught.value)


def test_p1_d_final_stop_fresh_p3c_health_rejected_per_target(rig, monkeypatch):
    seen = _inject_fresh_p3c_health(rig, monkeypatch, _arm_final_gate(rig, monkeypatch))
    result = rig.backend.stop_all_services()
    assert seen == [True]
    mutations = rig.runner.mutations()
    assert not any(argv[5] == f"pdi-scoped-pipeline@{PIPELINES[0]}.service" for argv in mutations)
    assert {argv[5] for argv in mutations} == {
        f"pdi-scoped-pipeline@{key}.service" for key in PIPELINES[1:]}
    assert result.attempts[0].outcome is module._Outcome.EVIDENCE_REJECTED
    assert result.attempts[0].final_state == result.service_state == "NOT_CONFIRMED"
    assert result.stop_failure_count == 1 and CANARY not in repr(result)


@pytest.mark.parametrize("field,value", (
    ("Requires", "synthetic-unreviewed.service"),
    ("Wants", "synthetic-unreviewed.service"),
    ("Requires", "var.mount"),  # Even a newly reachable reviewed unit is drift.
    ("PropagatesStopTo", "pdi-p3c-nextcloud-incremental.timer"),
    ("RequiredBy", "pdi-p3c-nextcloud-incremental.timer"),
    ("Id", "var.mount"),
    ("Names", "tmp.mount synthetic-alias.mount"),
    ("Following", "var.mount"),
    ("LoadState", "not-found"),
    ("FragmentPath", "/run/systemd/system/tmp.mount"),
    ("DropInPaths", "/run/systemd/system/tmp.mount.d/foreign.conf"),
    ("Transient", "yes"),
    ("NeedDaemonReload", "yes"),
    ("FailureAction", "reboot"),
    ("OnFailure", "synthetic-unreviewed.service"),
    ("RequiresMountsFor", "/unreviewed"),
    ("After", "var.mount"),
    ("Requires", "not/a/unit"),
    ("Requires", "var.mount var.mount"),
    ("Conflicts", None),
    ("Conflicts", "umount.target\x00"),
    ("__duplicate", "Conflicts=umount.target"),
    ("__unknown", "UnknownAuthority=synthetic"),
))
def test_p1_final_default_all_returned_authority_validated(rig, monkeypatch, field, value):
    stage = _arm_final_gate(rig, monkeypatch)
    seen = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (stage["key"] == PIPELINES[0] and argv[0] == "/usr/bin/systemctl"
                and argv[4:6] == ("show", "tmp.mount")):
            if field.startswith("__"):
                result.stdout += value + "\n"
            else:
                old = next(line for line in result.stdout.splitlines() if line.startswith(field + "="))
                result.stdout = result.stdout.replace(old + "\n", "" if value is None else f"{field}={value}\n")
            seen.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as caught:
        rig.backend.start_service(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert caught.value.code is module.WP8FailureCode.SERVICE_CONTRACT_INVALID
    assert caught.value.__suppress_context__ and CANARY not in str(caught.value)


@pytest.mark.parametrize("failure", ("timeout", "command"))
def test_p1_final_default_read_failure_has_no_mutation(rig, monkeypatch, failure):
    stage = _arm_final_gate(rig, monkeypatch)
    seen = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (stage["key"] == PIPELINES[0] and argv[0] == "/usr/bin/systemctl"
                and argv[4:6] == ("show", "tmp.mount")):
            seen.append(True)
            if failure == "timeout":
                raise subprocess.TimeoutExpired(argv, 30, output=CANARY, stderr=CANARY)
            result.returncode, result.stderr = 1, CANARY
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as caught:
        rig.backend.start_service(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert CANARY not in str(caught.value) and caught.value.__suppress_context__


@pytest.mark.parametrize("field", ("ExecStop", "ExecStopPost"))
def test_p1_final_emergency_reuses_strict_typed_authority(rig, monkeypatch, field):
    stage = _arm_final_gate(rig, monkeypatch)
    seen = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (stage["key"] == PIPELINES[0] and argv[0] == "/usr/bin/busctl"
                and argv[6].endswith("/emergency_2eservice") and field in argv[8:]):
            lines = result.stdout.splitlines()
            lines[argv[8:].index(field)] = json.dumps({"type": "a(sasbttttuii)",
                "data": [["synthetic-unreviewed-authority"]]})
            result.stdout = "\n".join(lines) + "\n"
            seen.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as caught:
        rig.backend.start_service(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("failure", (
    "inactive", "dead", "disabled", "ambiguous_enabled", "identity", "fragment",
    "missing", "duplicate", "unknown", "control", "timeout", "command", "malformed",
))
@pytest.mark.parametrize("stage_name", ("snapshot", "final"))
def test_p1_fresh_p3c_each_observation_fail_closed(rig, monkeypatch, failure, stage_name):
    stage = _arm_final_gate(rig, monkeypatch) if stage_name == "final" else None
    counter, seen = [], []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (argv[0] == "/usr/bin/systemctl" and argv[4:6] == ("show", P3C_TIMER)
                and (stage is None or stage["key"] == PIPELINES[0])):
            counter.append(True)
            if len(counter) == 2:
                if failure == "timeout":
                    seen.append(True)
                    raise subprocess.TimeoutExpired(argv, 30, output=CANARY, stderr=CANARY)
                replacements = {
                    "inactive": ("ActiveState=active\n", "ActiveState=inactive\n"),
                    "dead": ("SubState=waiting\n", "SubState=dead\n"),
                    "disabled": ("UnitFileState=enabled\n", "UnitFileState=disabled\n"),
                    "ambiguous_enabled": ("UnitFileState=enabled\n", "UnitFileState=enabled disabled\n"),
                    "identity": (f"Id={P3C_TIMER}\n", "Id=synthetic-foreign.timer\n"),
                    "fragment": (f"FragmentPath=/etc/systemd/system/{P3C_TIMER}\n",
                                 f"FragmentPath=/run/systemd/system/{P3C_TIMER}\n"),
                    "missing": ("ActiveState=active\n", ""),
                    "control": ("ActiveState=active\n", "ActiveState=active\x00\n"),
                }
                if failure in replacements:
                    old, new = replacements[failure]
                    assert old in result.stdout
                    result.stdout = result.stdout.replace(old, new)
                    assert new in result.stdout if new else old not in result.stdout
                elif failure == "duplicate":
                    result.stdout += "ActiveState=inactive\n"
                elif failure == "unknown":
                    result.stdout += "UnknownAuthority=synthetic\n"
                elif failure == "command":
                    result.returncode, result.stderr = 1, CANARY
                else:
                    result.stdout = "not-properties " + CANARY
                seen.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as caught:
        if stage is None:
            rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
        else:
            rig.backend.start_service(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert caught.value.__suppress_context__ and CANARY not in str(caught.value)


@pytest.mark.parametrize("field,value", (("ActiveState", "inactive"), ("UnitFileState", "disabled")))
def test_p1_p3c_provider_show_must_match_same_stage_state_reads(rig, monkeypatch, field, value):
    seen = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if argv[0] == "/usr/bin/systemctl" and argv[4:6] == ("show", P3C_TIMER) and not seen:
            result.stdout = result.stdout.replace(f"{field}={'active' if field == 'ActiveState' else 'enabled'}\n",
                                                 f"{field}={value}\n")
            seen.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    with pytest.raises(WP8ContractError) as caught:
        rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    assert seen == [True] and not rig.runner.mutations()
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("stage_name", ("snapshot_b", "post_start", "post_stop"))
def test_p1_p3c_health_applies_to_b_and_independent_post_verification(rig, monkeypatch, stage_name):
    direction = "stop" if stage_name == "post_stop" else "start"
    number = 2 if stage_name == "snapshot_b" else 3
    name = f"_collect_complete_{direction}_authority_snapshot"
    collect = getattr(rig.backend, name)
    stage = {"key": None, "p3c_shows": 0}
    samples = []
    def sample(key):
        if key == PIPELINES[0]:
            samples.append(key)
            if len(samples) == number:
                stage.update(key=key, p3c_shows=0)
        try:
            return collect(key)
        finally:
            stage["key"] = None
    monkeypatch.setattr(rig.backend, name, sample)
    seen = _inject_fresh_p3c_health(rig, monkeypatch, stage)
    if direction == "start":
        with pytest.raises(WP8ContractError) as caught:
            rig.backend.start_service(PIPELINES[0])
        assert len(rig.runner.mutations()) == (0 if stage_name == "snapshot_b" else 1)
        assert CANARY not in str(caught.value)
    else:
        result = rig.backend.stop_all_services()
        assert len(rig.runner.mutations()) == 6  # Unhealthy evidence first appears AFTER the target STOP.
        assert result.stop_failure_count == 1 and result.service_state == "NOT_CONFIRMED"
        assert result.attempts[0].final_state == "NOT_CONFIRMED" and CANARY not in repr(result)
    assert seen == [True]


def test_p1_healthy_final_authority_uses_same_canonical_graph_projection(rig, monkeypatch):
    stage = _arm_final_gate(rig, monkeypatch)
    seen = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (stage["key"] == PIPELINES[0] and argv[0] == "/usr/bin/systemctl"
                and argv[4:6] == ("show", "sysinit.target")):
            result.stdout = result.stdout.replace("Wants=local-fs.target swap.target\n",
                                                 "Wants=swap.target local-fs.target\n")
            seen.append(True)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    assert rig.backend.start_service(PIPELINES[0]).outcome is module._Outcome.SUCCESS
    assert seen == [True] and len(rig.runner.mutations()) == 1


def test_p1_normal_p3c_execution_counters_are_not_health_authority(rig, monkeypatch):
    progress = []
    def transport(argv, **kwargs):
        result = rig.runner(argv, **kwargs)
        if (argv[0] == "/usr/bin/systemctl" and argv[4] == "show"
                and argv[5].startswith("pdi-p3c-")):
            # Literal runtime facts change on every read. Fixed projection must
            # never request them or make them part of the stable health seal.
            fields = next(arg.split("=", 1)[1].split(",") for arg in argv if arg.startswith("--property="))
            assert set(fields) == {"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath"}
            facts = dict(line.split("=", 1) for line in result.stdout.splitlines())
            facts.update(InvocationID=f"{len(progress) + 1:032x}", ExecMainPID=str(100 + len(progress)),
                         ExecMainStartTimestampMonotonic=str(200 + len(progress)))
            progress.append((facts["InvocationID"], facts["ExecMainPID"]))
            result.stdout = "".join(f"{name}={facts[name]}\n" for name in fields)
        return result
    monkeypatch.setattr(module.subprocess, "run", transport)
    a = rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    b = rig.backend._collect_complete_start_authority_snapshot(PIPELINES[0])
    assert a.domain == b.domain and a.fingerprint == b.fingerprint
    assert len(progress) == 20 and len(set(progress)) == 20
    assert rig.backend.start_service(PIPELINES[0]).outcome is module._Outcome.SUCCESS
    assert len(rig.runner.mutations()) == 1
