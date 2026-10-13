"""Internal WP8 protected orchestration; no CLI, approval issuer or activation.

Dependency injection is an internal qualification-test API. Production
composition always derives dependencies from fixed protected configuration.
Imports have no effects. Real-systemd qualification/production authority are
separate gates; this module's presence is not either authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path
import sys

from . import p3d_wp8_contracts as c
from .p3d_preparation_contracts import contract_fingerprint
from .p3d_wp8_operation_store import OperationStore, _fail
from .p3d_wp8_systemd import (WP8ProductionSystemdBackend, _ServiceResult,
    _ExecutionAttestationV1, _CleanupFacts, _Outcome, _SERVICE_UNITS)


def _now():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class _Adapters:
    backend: object
    preflight: object
    promote: object
    runtime: object
    postflight: object


@dataclass(frozen=True)
class _Result:
    status: str
    code: c.WP8FailureCode | None
    phase: c.WP8RehearsalPhase | None
    completion: c.WP8RehearsalCompleteV1 | None = None


def _cleanup_proof(facts, evidence, operation_id):
    if type(facts) is not _CleanupFacts or tuple(item.pipeline_key for item in facts.attempts) != c.WP8_CANONICAL_PIPELINE_KEYS:
        _fail(c.WP8FailureCode.CLEANUP_FAILED)
    failures = sum(item.outcome is not _Outcome.SUCCESS for item in facts.attempts)
    if (type(facts.stop_failure_count) is not int or facts.stop_failure_count != failures
            or any(item.final_state != "INACTIVE" for item in facts.attempts) and facts.service_state == "INACTIVE"):
        _fail(c.WP8FailureCode.CLEANUP_FAILED)
    passed = failures == 0 and facts.service_state == "INACTIVE" and facts.timer_state == "DISABLED_INACTIVE" and facts.p3c_state == "UNCHANGED_HEALTHY"
    return c.WP8CleanupProofV1.build(rehearsal_operation_id=operation_id, candidate_sha=evidence.candidate_sha,
        phase_a_context_fingerprint=evidence.phase_a_context_fingerprint, stop_failure_count=failures,
        service_state=facts.service_state, timer_state=facts.timer_state, p3c_state=facts.p3c_state,
        result=c.WP8CleanupResult.PASS if passed else c.WP8CleanupResult.FAIL)


def _verified_result(result, evidence, key, manager, prior):
    if type(result) is not _ServiceResult or type(result.execution_attestation) is not _ExecutionAttestationV1:
        _fail(c.WP8FailureCode.SERVICE_EXECUTION_FAILED)
    attestation = result.execution_attestation
    attestation.validate_binding(evidence, pipeline_key=key)
    if (result.pipeline_key != key or result.unit != _SERVICE_UNITS[key] or result.outcome is not _Outcome.SUCCESS
            or result.final_state != "INACTIVE" or result.manager_fingerprint != manager
            or attestation.manager_fingerprint != manager or result.unit_contract_fingerprint != attestation.unit_contract_fingerprint
            or result.service_result_fingerprint != attestation.recompute_service_result_fingerprint()
            or attestation.invocation_fingerprint in prior):
        _fail(c.WP8FailureCode.SERVICE_EXECUTION_FAILED)
    return attestation.to_mapping()


class _Coordinator:
    def __init__(self, store, adapters, *, clock=_now):
        self.store, self.adapters, self.clock = store, adapters, clock

    def _eligible(self, operation_id):
        evidence, review, authorization = self.store.inputs(operation_id)
        # Eligibility recheck for this already-consumed operation, not issuance.
        state, _, _ = self.store.load(operation_id)
        if state.authorization_fingerprint != authorization.authorization_fingerprint:
            _fail(c.WP8FailureCode.AUTHORIZATION_INVALID)
        c.validate_rehearsal_authorization(authorization, evidence, review, at_utc=self.clock(), consumed=False)
        return evidence

    def _mutation(self, operation_id, action, perform, serialize, *, pipeline=None):
        self._same_manager(operation_id)
        if action != "STOP":
            self._eligible(operation_id)
        state, events, _ = self.store.load(operation_id)
        name = f"{len(events) + 1:06d}-{action}"
        intent = {"version": 1, "operation_id": operation_id, "action": action,
            "pipeline_key": pipeline, "sequence": len(events) + 1, "state_fingerprint": state.state_fingerprint,
            "candidate_sha": state.candidate_sha, "phase_a_context_fingerprint": state.phase_a_context_fingerprint,
            "authorization_fingerprint": state.authorization_fingerprint}
        self.store.record(operation_id, "intents", name, intent)
        result = perform()  # exactly one call; no retry or post-hoc reconstruction
        payload = serialize(result)
        receipt = {"version": 1, "operation_id": operation_id,
                   "intent_fingerprint": contract_fingerprint(intent), "payload": payload}
        self.store.record(operation_id, "results", name, receipt)
        return result, contract_fingerprint(receipt)

    def _same_manager(self, operation_id):
        from .p3d_wp8_systemd import _ManagerIdentity
        expected = self.store.manager_anchor(operation_id)
        actual = self.adapters.backend.manager_identity()
        if (type(actual) is not _ManagerIdentity or actual.fingerprint != expected["manager_fingerprint"]
                or actual.boot_fingerprint != expected["boot_fingerprint"]
                or actual.continuity_token != expected["continuity_fingerprint"]):
            _fail(c.WP8FailureCode.SYSTEMD_MANAGER_INVALID)

    def _advance(self, operation_id, target, **kwargs):
        return self.store.advance(operation_id, target, at_utc=self.clock(), **kwargs)

    def run(self, operation_id):
        # A used/incomplete operation is never automatically dispatched again.
        with self.store.serialized():
            self.store.begin(operation_id, at_utc=self.clock())
            evidence, _, _ = self.store.inputs(operation_id)
            try:
                self._advance(operation_id, c.WP8RehearsalPhase.AUTHORIZATION_VERIFIED)
                if self.adapters.preflight() != evidence:
                    _fail(c.WP8FailureCode.PREREQUISITE_DRIFT)
                manager = self.adapters.backend.manager_identity()
                before = self.adapters.postflight.capture_business()
                self.store._put(self.store._operation(operation_id) / "business-before.json", before.to_mapping())
                self._advance(operation_id, c.WP8RehearsalPhase.PREREQUISITES_VERIFIED)
                if self.adapters.preflight() != evidence or self.adapters.backend.manager_identity() != manager:
                    _fail(c.WP8FailureCode.PREREQUISITE_DRIFT)
                self._advance(operation_id, c.WP8RehearsalPhase.PRE_MUTATION_REVALIDATED)
                self.store.write_manager_anchor(operation_id, manager)
                _, ref = self._mutation(operation_id, "PROMOTE", self.adapters.promote,
                    lambda value: {"current": value} if value == "EXACT_CANDIDATE" else _fail(c.WP8FailureCode.CURRENT_DRIFT))
                self._advance(operation_id, c.WP8RehearsalPhase.CURRENT_PROMOTED, evidence_fingerprints=(ref,))
                _, ref = self._mutation(operation_id, "RELOAD", self.adapters.backend.daemon_reload,
                    lambda value: {"reload_fingerprint": value})
                self._advance(operation_id, c.WP8RehearsalPhase.SYSTEMD_RELOADED, evidence_fingerprints=(ref,))
                self.adapters.backend.verify_timers_quiet()
                self.adapters.backend.verify_all_services_inactive()
                for key in c.WP8_CANONICAL_PIPELINE_KEYS:
                    self.adapters.backend.verify_service_contract(key)
                if self.adapters.backend.manager_identity() != manager:
                    _fail(c.WP8FailureCode.SYSTEMD_MANAGER_INVALID)
                self._advance(operation_id, c.WP8RehearsalPhase.SERVICES_VERIFIED)
                boundary = self.store.write_boundary(operation_id, manager_fingerprint=manager.fingerprint,
                                                      business_fingerprint=before.fingerprint)
                results, invocations = [], set()
                for number, key in enumerate(c.WP8_CANONICAL_PIPELINE_KEYS, 1):
                    self._advance(operation_id, c.WP8RehearsalPhase[f"SERVICE_{number}_EXECUTING"])
                    result, ref = self._mutation(operation_id, "START", lambda: self.adapters.backend.start_service(key),
                        lambda value: _verified_result(value, evidence, key, manager.fingerprint, invocations), pipeline=key)
                    results.append(result)  # preserve actual same-call object
                    invocations.add(result.execution_attestation.invocation_fingerprint)
                    self._advance(operation_id, c.WP8RehearsalPhase[f"SERVICE_{number}_VERIFIED"], evidence_fingerprints=(ref,))
                self._advance(operation_id, c.WP8RehearsalPhase.SERVICES_EXECUTED)
                runtime = self.adapters.runtime.collect(tuple(results), rehearsal_operation_id=operation_id,
                                                        runtime_boundary_fingerprint=boundary)
                if runtime.runtime_boundary_fingerprint != boundary:
                    _fail(c.WP8FailureCode.RUNTIME_LEDGER_INVALID)
                self._advance(operation_id, c.WP8RehearsalPhase.RUNTIME_LEDGER_VERIFIED, proofs={"runtime": runtime})
                invariant = self.adapters.postflight.verify(operation_id=operation_id, boundary=before,
                                                            service_results=tuple(results), runtime=runtime)
                self._advance(operation_id, c.WP8RehearsalPhase.INVARIANTS_VERIFIED, proofs={"invariant": invariant})
                facts, ref = self._mutation(operation_id, "STOP", self.adapters.backend.stop_all_services,
                    lambda value: _cleanup_proof(value, evidence, operation_id).to_mapping())
                cleanup = _cleanup_proof(facts, evidence, operation_id)
                if cleanup.result is not c.WP8CleanupResult.PASS:
                    _fail(c.WP8FailureCode.CLEANUP_FAILED)
                self._advance(operation_id, c.WP8RehearsalPhase.SERVICES_STOPPED,
                              proofs={"cleanup": cleanup}, evidence_fingerprints=(ref,))
                if self.adapters.postflight.verify(operation_id=operation_id, boundary=before,
                        service_results=tuple(results), runtime=runtime) != invariant:
                    _fail(c.WP8FailureCode.INVARIANT_FAILED)
                self._eligible(operation_id)
                self._advance(operation_id, c.WP8RehearsalPhase.REHEARSAL_COMPLETE)
                complete = self.store.complete(operation_id, at_utc=self.clock())
                return _Result("REVIEWABLE_COMPLETE", None, c.WP8RehearsalPhase.REHEARSAL_COMPLETE, complete)
            except Exception as exc:
                code = getattr(exc, "code", c.WP8FailureCode.PROTECTED_STATE_TAMPER)
                if code not in c.OPERATION_FAILURE_CODES:
                    code = c.WP8FailureCode.PROTECTED_STATE_TAMPER
                return self._pause(operation_id, evidence, code)

    def _pause(self, operation_id, evidence, code):
        # A command and a file commit cannot be one transaction. Never invent
        # CURRENT_PROMOTED or claim pre-mutation failure after an issued intent.
        try:
            state, events, _ = self.store.load(operation_id)
            if state.phase in c.TERMINAL_PHASES:
                return _Result("PAUSED", code, state.phase)
            if state.phase in c.PRE_MUTATION_PHASES:
                intent = self.store._operation(operation_id) / "intents" / f"{len(events) + 1:06d}-PROMOTE.json"
                if intent.exists() or intent.is_symlink():
                    self.store._put(self.store._operation(operation_id) / "uncertain.json",
                        {"version": 1, "operation_id": operation_id, "failure_code": code.value,
                         "state_fingerprint": state.state_fingerprint, "workload_replay": "PROHIBITED"})
                    return _Result("UNCERTAIN_NO_REPLAY", code, state.phase)
                self._advance(operation_id, c.WP8RehearsalPhase.FAILED, primary_failure_code=code)
            else:
                # No automatic second STOP after a stop command became uncertain.
                already_stop = any(self.store._json(path).get("action") == "STOP"
                    for path in (self.store._operation(operation_id) / "intents").glob("*.json"))
                receipt_path = self.store._operation(operation_id) / "results" / f"{len(events) + 1:06d}-STOP.json"
                if already_stop:
                    if not receipt_path.exists():
                        return _Result("UNCERTAIN_NO_REPLAY", code, state.phase)
                    ref = contract_fingerprint(self.store._json(receipt_path))
                else:
                    _, ref = self._mutation(operation_id, "STOP", self.adapters.backend.stop_all_services,
                        lambda value: _cleanup_proof(value, evidence, operation_id).to_mapping())
                receipt = self.store._json(receipt_path)
                cleanup = c.WP8CleanupProofV1.from_mapping(receipt["payload"])
                target = c.WP8RehearsalPhase.ABORTED if cleanup.result is c.WP8CleanupResult.PASS else c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED
                self._advance(operation_id, target, proofs={"cleanup": cleanup}, primary_failure_code=code,
                    cleanup_failure_code=None if cleanup.result is c.WP8CleanupResult.PASS else c.WP8FailureCode.CLEANUP_FAILED,
                    evidence_fingerprints=(ref,))
            return _Result("PAUSED", code, self.store.load(operation_id)[0].phase)
        except Exception:
            return _Result("UNCERTAIN_NO_REPLAY", code, None)

    def recover_cleanup(self, operation_id):
        """Explicit cleanup-only recovery, never dispatch run() or reconstruct results."""
        with self.store.serialized():
            state, _, _ = self.store.load(operation_id, rebuild=True)
            if state.phase is not c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED:
                _fail(c.WP8FailureCode.AUTHORIZATION_REPLAY)
            evidence, _, _ = self.store.inputs(operation_id)
            self._same_manager(operation_id)
            # Expired execution grants may not start workload. Recovery is only
            # the frozen cleanup transition of the already-consumed operation.
            facts, _ = self._mutation(operation_id, "STOP", self.adapters.backend.stop_all_services,
                lambda value: _cleanup_proof(value, evidence, operation_id).to_mapping())
            proof = _cleanup_proof(facts, evidence, operation_id)
            target = c.WP8RehearsalPhase.ABORTED if proof.result is c.WP8CleanupResult.PASS else c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED
            self._advance(operation_id, target, proofs={"cleanup": proof},
                cleanup_failure_code=None if proof.result is c.WP8CleanupResult.PASS else c.WP8FailureCode.CLEANUP_FAILED)
            return self.store.load(operation_id)[0]


def _production_coordinator(operation_id):
    """Fixed composition for a future separately authorized operator/VM harness."""
    from . import p3d_wp8_preflight as preflight
    from . import p3d_pre_rehearsal_evidence as wp6
    from .p3d_inert_asset_install import InertAssetPolicy, ProductionReadOnlySystemdStateProvider
    from .p3d_wp8_runtime_proof import WP8RuntimeProofReader
    from .p3d_wp8_postflight import PostflightReader, _final_projection
    from .cutover import trusted_path
    from .enrichment_cutover import promote_release_atomically
    from pdi.database import create_postgres_engine

    store = OperationStore.production()
    evidence, _, _ = store.inputs(operation_id)
    policy = InertAssetPolicy.production()
    inputs = wp6.PreparationEvidenceInputs(evidence.candidate_sha, evidence.gate_a_operation_id,
        evidence.gate_b_operation_id, evidence.gate_c_operation_id, evidence.rollback_source_sha)
    preflight._verify_runtime(policy, evidence.candidate_sha)
    release = policy.candidate_releases_root / evidence.candidate_sha
    for name in ("p3d_wp8_rehearsal.py", "p3d_wp8_operation_store.py", "p3d_wp8_postflight.py", "p3d_wp8_runtime_proof.py", "p3d_wp8_systemd.py"):
        imported = Path(sys.modules["pdi.production_ops." + name[:-3]].__file__).absolute()
        source = release / "src/pdi/production_ops" / name
        if (release / ".venv" not in imported.resolve(strict=True).parents
                or not trusted_path(imported, expected_kind="file", require_root_group=True)
                or not trusted_path(source, expected_kind="file", require_root_group=True)
                or imported.read_bytes() != source.read_bytes()):
            _fail(c.WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)
    configuration, principal, _, _ = wp6._load_protected_configuration(policy)
    engine = create_postgres_engine(configuration.router.resolve(principal).database_url)
    backend = WP8ProductionSystemdBackend(evidence)
    def collect():
        return preflight.collect_phase_a_evidence(candidate_sha=evidence.candidate_sha,
            gate_a_operation_id=evidence.gate_a_operation_id, gate_b_operation_id=evidence.gate_b_operation_id,
            gate_c_operation_id=evidence.gate_c_operation_id, rollback_source_sha=evidence.rollback_source_sha)
    def promote():
        # Reuse the exact frozen promotion primitive, never P3DControl.apply().
        promote_release_atomically(policy.current, release, evidence.candidate_sha)
        wp6._current_target(policy, expected_source=evidence.candidate_sha)
        return "EXACT_CANDIDATE"
    runtime = WP8RuntimeProofReader(router=configuration.router, engine=engine, principal_ref=principal, phase_a_evidence=evidence)
    postflight = PostflightReader(evidence=evidence, router=configuration.router, engine=engine, principal=principal,
        observe_final=lambda: _final_projection(policy, inputs, ProductionReadOnlySystemdStateProvider()), backend=backend)
    return _Coordinator(store, _Adapters(backend, collect, promote, runtime, postflight)), engine


__all__ = []  # No production CLI or caller-supplied authorization escape hatch.
