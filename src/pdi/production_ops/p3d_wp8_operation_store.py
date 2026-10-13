"""Protected WP8 storage. No imports, constructors or reads authorize workload.

Immutable commit frames are authoritative; numbered state files are projections.
Human-installed approval inputs are never issued by this module. Test roots are
an internal filesystem fixture API, not an operator path override.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID

from .p3d_preparation_contracts import (
    AtomicCreatePolicyV1, AtomicCreateResult, atomic_create_no_replace,
    PreparationContractError, canonical_json_bytes, contract_fingerprint,
)
from . import p3d_wp8_contracts as c


_ROOT = Path("/var/lib/pdi-p3d-wp8")
_LOCKS = tuple(map(Path, (
    "/run/lock/pdi-mu13-p3c-cutover.lock",
    "/run/lock/pdi-mu13-p3d-cutover.lock",
    "/run/lock/pdi/p3d-inert-asset-install.lock",
    "/run/lock/pdi/p3d-release-bootstrap.lock",
)))
_PROOFS = {
    "runtime": (c.WP8RuntimeLedgerProofV1, "runtime_ledger_fingerprint"),
    "invariant": (c.WP8InvariantProofV1, "invariant_proof_fingerprint"),
    "cleanup": (c.WP8CleanupProofV1, "cleanup_proof_fingerprint"),
}


def _fail(code=c.WP8FailureCode.PROTECTED_STATE_TAMPER):
    raise c.WP8ContractError(code) from None


def _uuid(value):
    try:
        if type(value) is not str or str(UUID(value)) != value:
            _fail()
        return value
    except (ValueError, TypeError, AttributeError):
        _fail()


def _hash(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        _fail()
    return value


@dataclass(frozen=True)
class _Policy:
    root: Path
    trust_root: Path
    uid: int
    gid: int
    locks: tuple[Path, ...]


class OperationStore:
    def __init__(self, policy: _Policy):
        self._policy = policy
        self.root = policy.root
        self._held = False
        self._check(self.root, directory=True, mode=0o700)
        self._atomic = AtomicCreatePolicyV1(policy.uid, policy.gid, 0o600, policy.trust_root)

    @classmethod
    def production(cls):
        # No directory, account, approval, or lock installation here.
        return cls(_Policy(_ROOT, Path("/"), 0, 0, _LOCKS))

    @classmethod
    def _for_tests(cls, root: Path, *, locks=()):
        return cls(_Policy(root, root, os.geteuid(), os.getegid(), tuple(locks)))

    def _check(self, path, *, directory=False, mode=None):
        p = self._policy
        if not path.is_absolute() or (path != p.trust_root and p.trust_root not in path.parents):
            _fail()
        current = path
        while True:
            info = current.lstat()
            leaf = current == path
            kind = stat.S_ISDIR if (not leaf or directory) else stat.S_ISREG
            if (not kind(info.st_mode) or info.st_uid != p.uid or info.st_gid != p.gid
                    or info.st_mode & 0o022 or (leaf and mode is not None
                    and stat.S_IMODE(info.st_mode) != mode)):
                _fail()
            if current == p.trust_root:
                return
            current = current.parent

    def _read(self, path):
        self._check(path, mode=0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != self._policy.uid or before.st_gid != self._policy.gid or stat.S_IMODE(before.st_mode) != 0o600:
                _fail()
            with os.fdopen(fd, "rb", closefd=False) as handle:
                payload = handle.read(16 * 1024 * 1024 + 1)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(payload) > 16 * 1024 * 1024 or identity(before) != identity(os.fstat(fd)):
                _fail()
            if (before.st_dev, before.st_ino) != (path.lstat().st_dev, path.lstat().st_ino):
                _fail()
            return payload
        finally:
            os.close(fd)

    def _json(self, path):
        payload = self._read(path)
        try:
            value = json.loads(payload)
            canonical = canonical_json_bytes(value) + b"\n"
        except (ValueError, TypeError, PreparationContractError):
            _fail()
        if canonical != payload:
            _fail()
        return value

    def _put(self, path, value):
        if not self._held:
            _fail()
        return atomic_create_no_replace(path, canonical_json_bytes(value) + b"\n", policy=self._atomic)

    def _mkdir(self, path):
        if not self._held:
            _fail()
        self._check(path.parent, directory=True)
        path.mkdir(mode=0o700)
        self._check(path, directory=True, mode=0o700)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def serialized(self):
        """Coordinate the real legacy locks too; never take a worker sync lock."""
        if self._held:
            _fail()
        descriptors = []
        try:
            self._check(self.root, directory=True, mode=0o700)
            own = self.root / "operation.lock"
            # Installed root must already exist. This is the only lock created.
            if not own.exists() and not own.is_symlink():
                fd = os.open(own, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            for path in (own, *self._policy.locks):
                # Unknown or missing legacy locks fail closed, not installed here.
                self._check(path, mode=0o600)
                fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                descriptors.append(fd)
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) != (path.lstat().st_dev, path.lstat().st_ino):
                    _fail()
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._held = True
            yield
        except (OSError, ValueError):
            _fail()
        finally:
            self._held = False
            for fd in reversed(descriptors):
                os.close(fd)

    def inputs(self, operation_id):
        root = self.root / "approvals" / _uuid(operation_id)
        self._check(root, directory=True, mode=0o700)
        evidence = c.WP8PhaseAEvidenceV1.from_mapping(self._json(root / "phase-a.json"))
        review = c.WP8AReviewResultV1.from_mapping(self._json(root / "a-review.json"))
        authorization = c.WP8RehearsalAuthorizationV1.from_mapping(self._json(root / "b-authorization.json"))
        if (authorization.rehearsal_operation_id != operation_id or
                hashlib.sha256(self._read(root / "review-record")).hexdigest() != review.review_record_sha256):
            _fail(c.WP8FailureCode.AUTHORIZATION_INVALID)
        c.validate_review_result(review, evidence)
        return evidence, review, authorization

    def _operation(self, operation_id):
        return self.root / "operations" / _uuid(operation_id)

    def begin(self, operation_id, *, at_utc):
        evidence, review, authorization = self.inputs(operation_id)
        consumption = self.root / "consumptions" / authorization.authorization_fingerprint
        c.validate_rehearsal_authorization(authorization, evidence, review, at_utc=at_utc,
                                           consumed=consumption.exists() or consumption.is_symlink())
        root = self._operation(operation_id)
        if root.exists() or root.is_symlink():
            _fail(c.WP8FailureCode.AUTHORIZATION_REPLAY)
        for path in (self.root / "consumptions", self.root / "operations"):
            if not path.exists():
                self._mkdir(path)
            self._check(path, directory=True, mode=0o700)
        # A crash from this point burns this grant, even without an initial frame.
        self._put(consumption, {"version": 1, "operation_id": operation_id,
            "authorization_fingerprint": authorization.authorization_fingerprint, "at_utc": at_utc})
        self._mkdir(root)
        for name in ("proofs", "intents", "results"):
            self._mkdir(root / name)
        state = c.WP8RehearsalStateV1.new(operation_id=operation_id,
            candidate_sha=evidence.candidate_sha, phase_a_context_fingerprint=evidence.phase_a_context_fingerprint,
            authorization_fingerprint=authorization.authorization_fingerprint, started_at_utc=at_utc)
        self._commit(root, state, None, {})
        return state

    def _commit(self, root, state, event, refs):
        sequence = 0 if event is None else event.sequence
        # This one immutable frame is the durable commit point. Proofs precede it.
        self._put(root / f"commit-{sequence:06d}.json", {"version": 1, "sequence": sequence,
            "state": state.to_mapping(), "event": None if event is None else event.to_mapping(), "proofs": refs})
        # Projection failure cannot undo a committed event; missing projections rebuild on load.
        try:
            self._put(root / f"state-{sequence:06d}.json", state.to_mapping())
        except (OSError, PreparationContractError):
            if (root / f"state-{sequence:06d}.json").exists():
                _fail()

    def load(self, operation_id, *, rebuild=False):
        root = self._operation(operation_id)
        self._check(root, directory=True, mode=0o700)
        evidence, review, authorization = self.inputs(operation_id)
        consumed = self._json(self.root / "consumptions" / authorization.authorization_fingerprint)
        if type(consumed.get("version")) is not int or set(consumed) != {"version", "operation_id", "authorization_fingerprint", "at_utc"} or consumed != {
                "version": 1, "operation_id": operation_id,
                "authorization_fingerprint": authorization.authorization_fingerprint,
                "at_utc": consumed.get("at_utc")}:
            _fail()
        c.validate_rehearsal_authorization(authorization, evidence, review,
            at_utc=consumed["at_utc"], consumed=False)
        paths = sorted(root.glob("commit-*.json"))
        if not paths or len(paths) > 4096 or [p.name for p in paths] != [f"commit-{i:06d}.json" for i in range(len(paths))]:
            _fail()
        events, previous, refs = [], None, {}
        for i, path in enumerate(paths):
            frame = self._json(path)
            if set(frame) != {"version", "sequence", "state", "event", "proofs"} or type(frame["version"]) is not int or frame["version"] != 1 or type(frame["sequence"]) is not int or frame["sequence"] != i:
                _fail()
            state = c.WP8RehearsalStateV1.from_mapping(frame["state"])
            if i == 0:
                expected = c.WP8RehearsalStateV1.new(operation_id=operation_id, candidate_sha=evidence.candidate_sha,
                    phase_a_context_fingerprint=evidence.phase_a_context_fingerprint,
                    authorization_fingerprint=authorization.authorization_fingerprint, started_at_utc=consumed["at_utc"])
                if frame["event"] is not None or state != expected or frame["proofs"]:
                    _fail()
            else:
                event = c.WP8RehearsalJournalEventV1.from_mapping(frame["event"])
                expected, computed = c.transition_rehearsal_state(previous, event.to_state,
                    sequence=i, timestamp_utc=event.timestamp_utc,
                    runtime_ledger_fingerprint=(state.runtime_ledger_fingerprint if event.to_state is c.WP8RehearsalPhase.RUNTIME_LEDGER_VERIFIED else None),
                    invariant_proof_fingerprint=(state.invariant_proof_fingerprint if event.to_state is c.WP8RehearsalPhase.INVARIANTS_VERIFIED else None),
                    cleanup_proof=(event.cleanup_proof if event.to_state in {c.WP8RehearsalPhase.SERVICES_STOPPED, c.WP8RehearsalPhase.ABORTED, c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED} else None),
                    primary_failure_code=event.primary_failure_code,
                    cleanup_failure_code=event.cleanup_failure_code,
                    failed_pipeline_key=event.failed_pipeline_key,
                    evidence_fingerprints=(() if previous.phase is c.WP8RehearsalPhase.ABORT_NOT_CONFIRMED else event.evidence_fingerprints))
                if expected != state or computed != event:
                    _fail()
                events.append(event)
            if events:
                c.validate_rehearsal_journal_chain(events, state)
            if not isinstance(frame["proofs"], dict) or set(frame["proofs"]) - _PROOFS.keys():
                _fail()
            for key, ref in refs.items():
                if key != "cleanup" and frame["proofs"].get(key) != ref:
                    _fail()
            refs = frame["proofs"]
            for key, ref in refs.items():
                proof = self.proof(operation_id, key, ref)
                if (getattr(state, _PROOFS[key][1]) != ref or proof.rehearsal_operation_id != operation_id
                        or proof.candidate_sha != evidence.candidate_sha or proof.phase_a_context_fingerprint != evidence.phase_a_context_fingerprint):
                    _fail()
            for key, (_, field) in _PROOFS.items():
                if getattr(state, field) != refs.get(key):
                    _fail()
            projection = root / f"state-{i:06d}.json"
            if projection.exists() or projection.is_symlink():
                if self._json(projection) != state.to_mapping():
                    _fail()
            elif rebuild:
                self._put(projection, state.to_mapping())
            previous = state
        return previous, tuple(events), refs

    def proof(self, operation_id, key, fingerprint):
        kind, field = _PROOFS[key]
        obj = kind.from_mapping(self._json(self._operation(operation_id) / "proofs" / (_hash(fingerprint) + ".json")))
        if getattr(obj, field) != fingerprint:
            _fail()
        return obj

    def advance(self, operation_id, target, *, at_utc, proofs=None, **kwargs):
        state, events, refs = self.load(operation_id)
        refs = dict(refs)
        root = self._operation(operation_id)
        for key, proof in (proofs or {}).items():
            kind, field = _PROOFS[key]
            if type(proof) is not kind or proof.rehearsal_operation_id != operation_id or proof.candidate_sha != state.candidate_sha or proof.phase_a_context_fingerprint != state.phase_a_context_fingerprint:
                _fail()
            c.wp8_contract_bytes(proof)
            ref = getattr(proof, field)
            self._put(root / "proofs" / (ref + ".json"), proof.to_mapping())
            refs[key] = ref
            kwargs[{"runtime": "runtime_ledger_fingerprint", "invariant": "invariant_proof_fingerprint", "cleanup": "cleanup_proof"}[key]] = proof if key == "cleanup" else ref
        state, event = c.transition_rehearsal_state(state, target, sequence=len(events) + 1,
                                                  timestamp_utc=at_utc, **kwargs)
        c.validate_rehearsal_journal_chain((*events, event), state)
        self._commit(root, state, event, refs)
        return state

    def record(self, operation_id, area, name, value):
        if area not in {"intents", "results"} or re.fullmatch(r"[0-9]{6}-(PROMOTE|RELOAD|START|STOP)", name) is None:
            _fail()
        if value.get("operation_id") != operation_id or value.get("version") != 1:
            _fail()
        result = self._put(self._operation(operation_id) / area / (name + ".json"), value)
        if result is not AtomicCreateResult.CREATED:
            _fail(c.WP8FailureCode.AUTHORIZATION_REPLAY)

    def write_boundary(self, operation_id, *, manager_fingerprint, business_fingerprint):
        state, events, _ = self.load(operation_id)
        if state.phase is not c.WP8RehearsalPhase.SERVICES_VERIFIED:
            _fail()
        value = {"version": 1, "domain": "WP8_RUNTIME_BOUNDARY", "operation_id": operation_id,
            "candidate_sha": state.candidate_sha, "phase_a_context_fingerprint": state.phase_a_context_fingerprint,
            "authorization_fingerprint": state.authorization_fingerprint,
            "journal_head_fingerprint": state.journal_head_fingerprint, "sequence": len(events),
            "manager_fingerprint": _hash(manager_fingerprint), "business_fingerprint": _hash(business_fingerprint)}
        self._put(self._operation(operation_id) / "boundary.json", value)
        return contract_fingerprint(value)

    def write_manager_anchor(self, operation_id, manager):
        from .p3d_wp8_systemd import _ManagerIdentity
        state, events, _ = self.load(operation_id)
        if type(manager) is not _ManagerIdentity or state.phase is not c.WP8RehearsalPhase.PRE_MUTATION_REVALIDATED:
            _fail(c.WP8FailureCode.SYSTEMD_MANAGER_INVALID)
        self._put(self._operation(operation_id) / "manager-anchor.json", {
            "version": 1, "domain": "WP8_MANAGER_ANCHOR", "operation_id": operation_id,
            "candidate_sha": state.candidate_sha, "phase_a_context_fingerprint": state.phase_a_context_fingerprint,
            "authorization_fingerprint": state.authorization_fingerprint,
            "sequence": len(events), "state_fingerprint": state.state_fingerprint,
            "manager_fingerprint": _hash(manager.fingerprint), "boot_fingerprint": _hash(manager.boot_fingerprint),
            "continuity_fingerprint": _hash(manager.continuity_token)})

    def manager_anchor(self, operation_id):
        state, events, _ = self.load(operation_id)
        value = self._json(self._operation(operation_id) / "manager-anchor.json")
        sequence = value.get("sequence")
        if type(sequence) is not int or not 1 <= sequence <= len(events) or events[sequence - 1].to_state is not c.WP8RehearsalPhase.PRE_MUTATION_REVALIDATED:
            _fail()
        prior = self._json(self._operation(operation_id) / f"commit-{sequence:06d}.json")["state"]
        expected = {"version": 1, "domain": "WP8_MANAGER_ANCHOR", "operation_id": operation_id,
            "candidate_sha": state.candidate_sha, "phase_a_context_fingerprint": state.phase_a_context_fingerprint,
            "authorization_fingerprint": state.authorization_fingerprint,
            "sequence": sequence, "state_fingerprint": prior["state_fingerprint"],
            **{key: _hash(value.get(key)) for key in ("manager_fingerprint", "boot_fingerprint", "continuity_fingerprint")}}
        if type(value.get("version")) is not int or value != expected:
            _fail()
        return value

    def boundary(self, operation_id):
        value = self._json(self._operation(operation_id) / "boundary.json")
        state, events, _ = self.load(operation_id)
        if set(value) != {"version", "domain", "operation_id", "candidate_sha", "phase_a_context_fingerprint",
                "authorization_fingerprint", "journal_head_fingerprint", "sequence", "manager_fingerprint", "business_fingerprint"}:
            _fail()
        if type(value["version"]) is not int or value["version"] != 1 or value["domain"] != "WP8_RUNTIME_BOUNDARY" or value["operation_id"] != operation_id or value["candidate_sha"] != state.candidate_sha or value["phase_a_context_fingerprint"] != state.phase_a_context_fingerprint or value["authorization_fingerprint"] != state.authorization_fingerprint:
            _fail()
        index = value["sequence"]
        if type(index) is not int or not 1 <= index <= len(events) or events[index - 1].to_state is not c.WP8RehearsalPhase.SERVICES_VERIFIED or events[index - 1].event_fingerprint != value["journal_head_fingerprint"]:
            _fail()
        _hash(value["manager_fingerprint"])
        _hash(value["business_fingerprint"])
        if value["manager_fingerprint"] != self.manager_anchor(operation_id)["manager_fingerprint"]:
            _fail()
        return value, contract_fingerprint(value)

    def complete(self, operation_id, *, at_utc):
        evidence, review, authorization = self.inputs(operation_id)
        state, events, refs = self.load(operation_id)
        runtime = self.proof(operation_id, "runtime", refs["runtime"])
        if runtime.runtime_boundary_fingerprint != self.boundary(operation_id)[1]:
            _fail()
        self._verify_handoffs(operation_id, events, runtime)
        complete = c.WP8RehearsalCompleteV1.build(evidence=evidence, review=review, authorization=authorization,
            runtime_ledger=runtime, invariant_proof=self.proof(operation_id, "invariant", refs["invariant"]),
            cleanup_proof=self.proof(operation_id, "cleanup", refs["cleanup"]), state=state,
            completed_at_utc=at_utc, journal_events=events)
        self._put(self._operation(operation_id) / "complete.json", complete.to_mapping())
        return self.load_completion(operation_id)

    def load_completion(self, operation_id):
        """Read-only full closure validation, never replays or changes timestamps."""
        from .p3d_wp8_postflight import _BusinessBoundary
        try:
            evidence, review, authorization = self.inputs(operation_id)
            state, events, refs = self.load(operation_id)
            complete = c.WP8RehearsalCompleteV1.from_mapping(self._json(self._operation(operation_id) / "complete.json"))
            boundary, fingerprint = self.boundary(operation_id)
            before = _BusinessBoundary.from_mapping(self._json(self._operation(operation_id) / "business-before.json"))
            runtime = self.proof(operation_id, "runtime", refs["runtime"])
            if runtime.runtime_boundary_fingerprint != fingerprint or before.fingerprint != boundary["business_fingerprint"]:
                _fail()
            self._verify_handoffs(operation_id, events, runtime)
            expected = c.WP8RehearsalCompleteV1.build(evidence=evidence, review=review, authorization=authorization,
                runtime_ledger=runtime, invariant_proof=self.proof(operation_id, "invariant", refs["invariant"]),
                cleanup_proof=self.proof(operation_id, "cleanup", refs["cleanup"]), state=state,
                completed_at_utc=complete.completed_at_utc, journal_events=events)
            if complete != expected:
                _fail()
            return complete
        except Exception:
            _fail()

    def _verify_handoffs(self, operation_id, events, runtime):
        from .p3d_wp8_systemd import _ExecutionAttestationV1
        evidence, _, authorization = self.inputs(operation_id)
        manager = self.boundary(operation_id)[0]["manager_fingerprint"]
        records = {record.pipeline_key: record for record in runtime.pipeline_records}
        invocations = set()
        for event in events:
            target = event.to_state
            action = {c.WP8RehearsalPhase.CURRENT_PROMOTED: "PROMOTE", c.WP8RehearsalPhase.SYSTEMD_RELOADED: "RELOAD",
                      c.WP8RehearsalPhase.SERVICES_STOPPED: "STOP"}.get(target)
            if target.value.startswith("SERVICE_") and target.value.endswith("_VERIFIED"):
                action = "START"
            if action is None:
                continue
            name = f"{event.sequence:06d}-{action}.json"
            root = self._operation(operation_id)
            intent = self._json(root / "intents" / name)
            result = self._json(root / "results" / name)
            prior = self._json(root / f"commit-{event.sequence - 1:06d}.json")["state"]
            expected = {"version": 1, "operation_id": operation_id, "action": action,
                "pipeline_key": event.pipeline_key if action == "START" else None,
                "sequence": event.sequence, "state_fingerprint": prior["state_fingerprint"],
                "candidate_sha": evidence.candidate_sha, "phase_a_context_fingerprint": evidence.phase_a_context_fingerprint,
                "authorization_fingerprint": authorization.authorization_fingerprint}
            if intent != expected or set(result) != {"version", "operation_id", "intent_fingerprint", "payload"} or result["version"] != 1 or result["operation_id"] != operation_id or result["intent_fingerprint"] != contract_fingerprint(intent) or contract_fingerprint(result) not in event.evidence_fingerprints:
                _fail()
            if action == "START":
                # Revalidate persisted commitment only. NEVER turn it back into
                # a live _ServiceResult or resume service execution from it.
                attestation = _ExecutionAttestationV1(**result["payload"])
                attestation.validate_binding(evidence, pipeline_key=event.pipeline_key)
                if attestation.manager_fingerprint != manager or attestation.invocation_fingerprint in invocations or records[event.pipeline_key].service_result_fingerprint != attestation.service_result_fingerprint:
                    _fail()
                invocations.add(attestation.invocation_fingerprint)
            elif action == "PROMOTE" and result["payload"] != {"current": "EXACT_CANDIDATE"}:
                _fail()
            elif action == "RELOAD":
                if set(result["payload"]) != {"reload_fingerprint"}:
                    _fail()
                _hash(result["payload"]["reload_fingerprint"])
            elif action == "STOP":
                cleanup = c.WP8CleanupProofV1.from_mapping(result["payload"])
                if cleanup != event.cleanup_proof or cleanup.result is not c.WP8CleanupResult.PASS:
                    _fail()
        if len(invocations) != 6:
            _fail()


__all__ = []  # No production operator entrypoint or approval issuance API.
