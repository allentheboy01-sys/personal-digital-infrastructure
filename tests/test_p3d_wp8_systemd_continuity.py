"""Independent complete-snapshot and residual-race protocol tests (no real IO)."""

from dataclasses import replace

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
