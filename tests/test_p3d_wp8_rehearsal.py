from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from pdi.production_ops import p3d_wp8_contracts as c
from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint
from pdi.production_ops.p3d_wp8_operation_store import OperationStore
from pdi.production_ops.p3d_wp8_postflight import _BusinessBoundary
from pdi.production_ops.p3d_wp8_rehearsal import _Adapters, _Coordinator
from pdi.production_ops.p3d_wp8_systemd import (
    _ExecutionAttestationV1, _ServiceResult, _CleanupFacts, _StopFact, _Outcome, _SERVICE_UNITS,
    _ManagerIdentity, _ServiceStates, _ServiceState,
)
from tests.test_p3d_wp8_contracts import phase_a, timestamp, OPERATION, H1, H2, pipeline_records
from tests.test_p3d_wp8_operation_store import install_inputs, write


def result(key, evidence, *, manager=H1, invocation=None):
    values = dict(version=1, pipeline_key=key, unit=_SERVICE_UNITS[key], candidate_sha=evidence.candidate_sha,
        phase_a_context_fingerprint=evidence.phase_a_context_fingerprint, manager_fingerprint=manager,
        unit_contract_fingerprint=H2, start_monotonic_usec=10, exit_monotonic_usec=20,
        invocation_fingerprint=invocation or hashlib.sha256(key.encode()).hexdigest(), result="success", exit_status=0)
    values["service_result_fingerprint"] = contract_fingerprint({"candidate": values["candidate_sha"],
        "context": values["phase_a_context_fingerprint"], "pipeline": key, "manager": manager, "contract": H2,
        "start": 10, "exit": 20, "invocation_hash": values["invocation_fingerprint"], "result": "success", "exit_status": 0})
    attestation = _ExecutionAttestationV1(**values)
    return _ServiceResult(key, _SERVICE_UNITS[key], _Outcome.SUCCESS, manager, H2,
                          values["service_result_fingerprint"], "INACTIVE", attestation)


class SyntheticBackend:
    def __init__(self, evidence):
        self.evidence, self.starts, self.stops, self.reloads = evidence, [], 0, 0
        self.results = []
        self.manager = _ManagerIdentity(H1, H2, "SYNTHETIC", H2)
        self.cleanup_bad = False

    def manager_identity(self):
        return self.manager

    def daemon_reload(self):
        self.reloads += 1
        return H2

    def verify_timers_quiet(self):
        return SimpleNamespace(timer_state="DISABLED_INACTIVE")

    def verify_all_services_inactive(self):
        return _ServiceStates(tuple(_ServiceState(key, "INACTIVE") for key in c.WP8_CANONICAL_PIPELINE_KEYS), "INACTIVE")

    def verify_service_contract(self, key):
        assert key in c.WP8_CANONICAL_PIPELINE_KEYS
        return H2

    def start_service(self, key):
        self.starts.append(key)
        value = result(key, self.evidence)
        self.results.append(value)
        return value

    def stop_all_services(self):
        self.stops += 1
        return _CleanupFacts(tuple(_StopFact(key, _Outcome.COMMAND_FAILED if self.cleanup_bad else _Outcome.SUCCESS,
                                            "NOT_CONFIRMED" if self.cleanup_bad else "INACTIVE") for key in c.WP8_CANONICAL_PIPELINE_KEYS),
            6 if self.cleanup_bad else 0, "NOT_CONFIRMED" if self.cleanup_bad else "INACTIVE",
            "DISABLED_INACTIVE", "UNCHANGED_HEALTHY")


class SyntheticRuntime:
    def __init__(self, evidence, backend):
        self.evidence, self.backend, self.calls = evidence, backend, 0

    def collect(self, objects, *, rehearsal_operation_id, runtime_boundary_fingerprint):
        self.calls += 1
        assert all(obj is original for obj, original in zip(objects, self.backend.results, strict=True))
        records = tuple(replace(record, service_result_fingerprint=obj.service_result_fingerprint)
                        for record, obj in zip(pipeline_records(), objects, strict=True))
        return c.WP8RuntimeLedgerProofV1.build(candidate_sha=self.evidence.candidate_sha,
            phase_a_context_fingerprint=self.evidence.phase_a_context_fingerprint,
            rehearsal_operation_id=rehearsal_operation_id, runtime_boundary_fingerprint=runtime_boundary_fingerprint,
            pipeline_records=records)


class SyntheticPostflight:
    def __init__(self, evidence):
        self.evidence = evidence
        self.calls = 0

    def capture_business(self):
        return _BusinessBoundary(())

    def verify(self, *, operation_id, **kwargs):
        self.calls += 1
        return c.WP8InvariantProofV1.build(self.evidence, rehearsal_operation_id=operation_id,
            before=self.evidence.invariant_baseline,
            after=c.WP8InvariantSnapshotV1.from_mapping(self.evidence.invariant_baseline.to_mapping()))


def fixture(tmp_path, *, evidence=None):
    root = tmp_path / "protected"
    evidence, _, _ = install_inputs(root, evidence=evidence)
    store = OperationStore._for_tests(root)
    backend = SyntheticBackend(evidence)
    runtime, post = SyntheticRuntime(evidence, backend), SyntheticPostflight(evidence)
    promotions = []
    def promote():
        promotions.append(True)
        return "EXACT_CANDIDATE"
    adapters = _Adapters(backend, lambda: evidence, promote, runtime, post)
    return _Coordinator(store, adapters, clock=lambda: timestamp(4)), backend, runtime, post, promotions


def test_full_synthetic_closure_is_not_real_qualification(tmp_path):
    coordinator, backend, runtime, post, promotions = fixture(tmp_path)
    value = coordinator.run(OPERATION)
    assert value.status == "REVIEWABLE_COMPLETE"
    assert backend.starts == list(c.WP8_CANONICAL_PIPELINE_KEYS)
    assert backend.stops == backend.reloads == runtime.calls == len(promotions) == 1
    assert post.calls == 2
    assert value.completion.to_mapping()["independent_b_review_state"] == "PENDING"
    assert not value.completion.to_mapping()["wp8_final_end_boundary_reached"]
    state, events, refs = coordinator.store.load(OPERATION)
    assert state.phase is c.WP8RehearsalPhase.REHEARSAL_COMPLETE
    assert len(events) == len(c.NORMAL_PHASES) - 1
    assert set(refs) == {"runtime", "invariant", "cleanup"}
    assert coordinator.store.proof(OPERATION, "runtime", refs["runtime"]).runtime_boundary_fingerprint == coordinator.store.boundary(OPERATION)[1]
    with pytest.raises(c.WP8ContractError):
        coordinator.run(OPERATION)
    assert len(backend.starts) == 6


@pytest.mark.parametrize("failure", ("preflight", "manager", "promote", "reload", "start", "runtime", "postflight", "cleanup"))
def test_failed_phase_never_completes_or_retries_workload(tmp_path, monkeypatch, failure):
    coordinator, backend, runtime, post, promotions = fixture(tmp_path)
    def reject(*args, **kwargs):
        raise c.WP8ContractError(c.WP8FailureCode.PREREQUISITE_DRIFT)
    if failure == "preflight":
        coordinator.adapters = replace(coordinator.adapters, preflight=reject)
    elif failure == "manager":
        monkeypatch.setattr(backend, "manager_identity", reject)
    elif failure == "promote":
        coordinator.adapters = replace(coordinator.adapters, promote=reject)
    elif failure == "reload":
        monkeypatch.setattr(backend, "daemon_reload", reject)
    elif failure == "start":
        monkeypatch.setattr(backend, "start_service", reject)
    elif failure == "runtime":
        monkeypatch.setattr(runtime, "collect", reject)
    elif failure == "postflight":
        monkeypatch.setattr(post, "verify", reject)
    else:
        backend.cleanup_bad = True
    value = coordinator.run(OPERATION)
    assert value.status != "REVIEWABLE_COMPLETE"
    assert not (coordinator.store._operation(OPERATION) / "complete.json").exists()
    assert backend.stops <= 1
    with pytest.raises(c.WP8ContractError):
        coordinator.run(OPERATION)


@pytest.mark.parametrize("attack", ("foreign_context", "manager", "duplicate", "mapping", "inactive", "service_hash"))
def test_same_call_handoff_rejects_foreign_or_incomplete_results(tmp_path, monkeypatch, attack):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    original = backend.start_service
    def tamper(key):
        obj = original(key)
        if attack == "foreign_context":
            foreign = replace(backend.evidence, candidate_sha="f" * 40)
            return result(key, foreign)
        if attack == "manager":
            return result(key, backend.evidence, manager="f" * 64)
        if attack == "duplicate":
            return result(key, backend.evidence, invocation="f" * 64)
        if attack == "mapping":
            return obj.execution_attestation.to_mapping()
        if attack == "inactive":
            return replace(obj, final_state="RUNNING")
        return replace(obj, service_result_fingerprint="f" * 64)
    monkeypatch.setattr(backend, "start_service", tamper)
    assert coordinator.run(OPERATION).status != "REVIEWABLE_COMPLETE"


def test_projection_failure_is_not_business_failure(tmp_path, monkeypatch):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    original = coordinator.store._put
    def failure(path, value):
        if path.name.startswith("state-"):
            raise OSError("synthetic projection unavailable")
        return original(path, value)
    monkeypatch.setattr(coordinator.store, "_put", failure)
    assert coordinator.run(OPERATION).status == "REVIEWABLE_COMPLETE"
    monkeypatch.setattr(coordinator.store, "_put", original)
    with coordinator.store.serialized():
        state, _, _ = coordinator.store.load(OPERATION, rebuild=True)
    assert state.phase is c.WP8RehearsalPhase.REHEARSAL_COMPLETE
    assert len(backend.starts) == 6


def test_promotion_crash_does_not_falsely_record_pre_mutation_failed(tmp_path):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    side_effect = []
    def uncertain():
        side_effect.append(True)
        raise OSError("write happened; reply unavailable")
    coordinator.adapters = replace(coordinator.adapters, promote=uncertain)
    value = coordinator.run(OPERATION)
    assert value.status == "UNCERTAIN_NO_REPLAY" and side_effect == [True]
    assert coordinator.store.load(OPERATION)[0].phase is c.WP8RehearsalPhase.PRE_MUTATION_REVALIDATED
    assert backend.starts == []


def test_safe_records_have_no_exception_payload(tmp_path):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    def error(*_):
        raise RuntimeError("postgresql://secret:password@example/hidden TOKEN=bad")
    coordinator.adapters = replace(coordinator.adapters, promote=error)
    coordinator.run(OPERATION)
    for path in coordinator.store._operation(OPERATION).rglob("*.json"):
        body = path.read_text()
        assert "postgresql://" not in body and "password" not in body and "TOKEN=" not in body


def test_completed_closure_read_is_non_persisting(tmp_path):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    completed = coordinator.run(OPERATION).completion
    root = coordinator.store._operation(OPERATION)
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in root.rglob("*.json")}
    assert coordinator.store.load_completion(OPERATION) == completed
    assert before == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in root.rglob("*.json")}
    assert backend.stops == 1 and len(backend.starts) == 6


@pytest.mark.parametrize("attack", ("missing_marker", "marker_context", "marker_operation", "baseline", "boundary", "manager_anchor", "attestation", "result_missing", "runtime_proof"))
def test_persisted_closure_rejects_missing_or_tampered_references(tmp_path, attack):
    coordinator, _, _, _, _ = fixture(tmp_path)
    assert coordinator.run(OPERATION).status == "REVIEWABLE_COMPLETE"
    root = coordinator.store._operation(OPERATION)
    if attack == "missing_marker":
        (root / "complete.json").unlink()
    elif attack.startswith("marker_"):
        value = json.loads((root / "complete.json").read_bytes())
        value["phase_a_context_fingerprint" if attack == "marker_context" else "rehearsal_operation_id"] = "f" * 64 if attack == "marker_context" else "00000000-0000-0000-0000-000000000099"
        value["completion_fingerprint"] = contract_fingerprint({key: item for key, item in value.items() if key != "completion_fingerprint"})
        write(root / "complete.json", value)
    elif attack == "baseline":
        write(root / "business-before.json", _BusinessBoundary((("assets", H1, H1, H1),)).to_mapping())
    elif attack in {"boundary", "manager_anchor"}:
        path = root / ("boundary.json" if attack == "boundary" else "manager-anchor.json")
        value = json.loads(path.read_bytes())
        value["business_fingerprint" if attack == "boundary" else "manager_fingerprint"] = "f" * 64
        write(path, value)
    elif attack == "runtime_proof":
        refs = coordinator.store.load(OPERATION)[2]
        (root / "proofs" / (refs["runtime"] + ".json")).unlink()
    else:
        path = sorted((root / "results").glob("*-START.json"))[0]
        if attack == "result_missing":
            path.unlink()
        else:
            value = json.loads(path.read_bytes())
            value["payload"]["invocation_fingerprint"] = "f" * 64
            write(path, value)
    with pytest.raises(c.WP8ContractError):
        coordinator.store.load_completion(OPERATION)


def test_confirmed_cleanup_failure_allows_explicit_same_epoch_cleanup_only(tmp_path):
    coordinator, backend, _, _, promotions = fixture(tmp_path)
    backend.cleanup_bad = True
    failed = coordinator.run(OPERATION)
    assert failed.phase is c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED and backend.stops == 1
    primary = coordinator.store.load(OPERATION)[0].primary_failure_code
    backend.cleanup_bad = False
    state = coordinator.recover_cleanup(OPERATION)
    assert state.phase is c.WP8RehearsalPhase.ABORTED
    assert state.primary_failure_code == primary
    assert backend.stops == 2 and len(backend.starts) == 6 and len(promotions) == 1
    assert not (coordinator.store._operation(OPERATION) / "complete.json").exists()
    with pytest.raises(c.WP8ContractError):
        coordinator.recover_cleanup(OPERATION)


@pytest.mark.parametrize("field", ("fingerprint", "boot_fingerprint", "continuity_token"))
def test_cleanup_recovery_rejects_new_manager_epoch_without_stop(tmp_path, field):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    backend.cleanup_bad = True
    assert coordinator.run(OPERATION).phase is c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED
    original = coordinator.store.load(OPERATION)[0]
    backend.manager = replace(backend.manager, **{field: "f" * 64})
    backend.cleanup_bad = False
    with pytest.raises(c.WP8ContractError):
        coordinator.recover_cleanup(OPERATION)
    assert backend.stops == 1 and coordinator.store.load(OPERATION)[0] == original


@pytest.mark.parametrize("action", ("start_service", "stop_all_services"))
def test_uncertain_commands_are_not_automatically_reissued(tmp_path, monkeypatch, action):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    calls = []
    def uncertain(*args):
        calls.append(args)
        raise OSError("synthetic command issued; terminal unavailable")
    monkeypatch.setattr(backend, action, uncertain)
    outcome = coordinator.run(OPERATION)
    assert outcome.status != "REVIEWABLE_COMPLETE" and len(calls) == 1
    with pytest.raises(c.WP8ContractError):
        coordinator.run(OPERATION)
    assert len(calls) == 1
    if action == "stop_all_services":
        assert outcome.status == "UNCERTAIN_NO_REPLAY"
        with pytest.raises(c.WP8ContractError):
            coordinator.recover_cleanup(OPERATION)


def test_mid_execution_expiry_prevents_new_start_but_permits_cleanup(tmp_path, monkeypatch):
    coordinator, backend, _, _, _ = fixture(tmp_path)
    start = backend.start_service
    def expire(key):
        returned = start(key)
        coordinator.clock = lambda: timestamp(59)
        return returned
    monkeypatch.setattr(backend, "start_service", expire)
    outcome = coordinator.run(OPERATION)
    assert outcome.phase is c.WP8RehearsalPhase.ABORTED
    assert len(backend.starts) == 1 and backend.stops == 1
