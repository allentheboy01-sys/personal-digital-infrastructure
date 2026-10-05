"""Pure contracts for the governed MU13-P3D WP8 production rehearsal.

The module is deliberately inert.  It defines strict schemas, canonical
fingerprints, and state transitions, but performs no filesystem, database,
subprocess, systemd, Provider, network, or persistence operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
import re
import unicodedata
from typing import Any, Mapping, Sequence
from uuid import UUID

from pdi.production_ops.contracts import HEAD as EXPECTED_ALEMBIC_REVISION
from pdi.production_ops.p3d_preparation_contracts import (
    CANONICAL_P3D_PIPELINE_KEYS,
    canonical_json_bytes,
    contract_fingerprint,
    reject_secret_material,
)


GIT_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")

WP8_CANONICAL_PIPELINE_KEYS = tuple(CANONICAL_P3D_PIPELINE_KEYS)
WP8_CANONICAL_PIPELINE_SET_FINGERPRINT = contract_fingerprint({
    "pipeline_keys": list(WP8_CANONICAL_PIPELINE_KEYS),
})


class WP8FailureCode(str, Enum):
    """Fixed, non-sensitive WP8 contract and operation classifications."""

    CONTRACT_FIELD_SET_INVALID = "P3D_WP8_CONTRACT_FIELD_SET_INVALID"
    CONTRACT_VALUE_INVALID = "P3D_WP8_CONTRACT_VALUE_INVALID"
    CONTRACT_VERSION_UNSUPPORTED = "P3D_WP8_CONTRACT_VERSION_UNSUPPORTED"
    CONTRACT_SECRET_MATERIAL = "P3D_WP8_CONTRACT_SECRET_MATERIAL"
    CONTRACT_FINGERPRINT_MISMATCH = "P3D_WP8_CONTRACT_FINGERPRINT_MISMATCH"
    CONTRACT_TRANSITION_INVALID = "P3D_WP8_CONTRACT_TRANSITION_INVALID"
    CONTRACT_PIPELINE_SET_INVALID = "P3D_WP8_CONTRACT_PIPELINE_SET_INVALID"
    AUTHORIZATION_INVALID = "P3D_WP8_AUTHORIZATION_INVALID"
    AUTHORIZATION_EXPIRED = "P3D_WP8_AUTHORIZATION_EXPIRED"
    AUTHORIZATION_NOT_YET_VALID = "P3D_WP8_AUTHORIZATION_NOT_YET_VALID"
    AUTHORIZATION_REPLAY = "P3D_WP8_AUTHORIZATION_REPLAY"
    PREREQUISITE_DRIFT = "P3D_WP8_PREREQUISITE_DRIFT"
    CURRENT_DRIFT = "P3D_WP8_CURRENT_DRIFT"
    CANDIDATE_RUNTIME_DRIFT = "P3D_WP8_CANDIDATE_RUNTIME_DRIFT"
    SYSTEMD_MANAGER_INVALID = "P3D_WP8_SYSTEMD_MANAGER_INVALID"
    DAEMON_RELOAD_FAILED = "P3D_WP8_DAEMON_RELOAD_FAILED"
    SERVICE_CONTRACT_INVALID = "P3D_WP8_SERVICE_CONTRACT_INVALID"
    SERVICE_EXECUTION_FAILED = "P3D_WP8_SERVICE_EXECUTION_FAILED"
    RUNTIME_LEDGER_INVALID = "P3D_WP8_RUNTIME_LEDGER_INVALID"
    INVARIANT_FAILED = "P3D_WP8_INVARIANT_FAILED"
    CLEANUP_FAILED = "P3D_WP8_CLEANUP_FAILED"
    PROTECTED_STATE_TAMPER = "P3D_WP8_PROTECTED_STATE_TAMPER"


OPERATION_FAILURE_CODES = frozenset({
    WP8FailureCode.AUTHORIZATION_INVALID,
    WP8FailureCode.AUTHORIZATION_EXPIRED,
    WP8FailureCode.AUTHORIZATION_NOT_YET_VALID,
    WP8FailureCode.AUTHORIZATION_REPLAY,
    WP8FailureCode.PREREQUISITE_DRIFT,
    WP8FailureCode.CURRENT_DRIFT,
    WP8FailureCode.CANDIDATE_RUNTIME_DRIFT,
    WP8FailureCode.SYSTEMD_MANAGER_INVALID,
    WP8FailureCode.DAEMON_RELOAD_FAILED,
    WP8FailureCode.SERVICE_CONTRACT_INVALID,
    WP8FailureCode.SERVICE_EXECUTION_FAILED,
    WP8FailureCode.RUNTIME_LEDGER_INVALID,
    WP8FailureCode.INVARIANT_FAILED,
    WP8FailureCode.CLEANUP_FAILED,
    WP8FailureCode.PROTECTED_STATE_TAMPER,
})


class WP8ContractError(ValueError):
    """A fail-closed rejection containing only a fixed safe code."""

    def __init__(self, code: WP8FailureCode) -> None:
        self.code = code
        super().__init__(code.value)


def _fail(code: WP8FailureCode = WP8FailureCode.CONTRACT_VALUE_INVALID) -> None:
    raise WP8ContractError(code)


def _exact(value: Mapping[str, Any], fields: frozenset[str]) -> None:
    if not isinstance(value, Mapping) or frozenset(value) != fields:
        _fail(WP8FailureCode.CONTRACT_FIELD_SET_INVALID)


def _reject_secret_material(value: Any) -> None:
    try:
        reject_secret_material(value)
    except Exception:
        _fail(WP8FailureCode.CONTRACT_SECRET_MATERIAL)


def _safe_text(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "://" in value
        or any(unicodedata.category(char) == "Cc" for char in value)
    ):
        _fail()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()
    return value


def _git_sha(value: Any) -> str:
    value = _safe_text(value)
    if GIT_SHA.fullmatch(value) is None:
        _fail()
    return value


def _sha256(value: Any) -> str:
    value = _safe_text(value)
    if SHA256.fullmatch(value) is None:
        _fail()
    return value


def _canonical_uuid(value: Any) -> str:
    value = _safe_text(value)
    try:
        parsed = UUID(value)
    except ValueError:
        _fail()
    if str(parsed) != value:
        _fail()
    return value


def _timestamp(value: Any) -> str:
    value = _safe_text(value)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        _fail()
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail()
    return value


def _integer(value: Any, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail()
    return value


def _enum(enum_type, value: Any):
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        _fail()


def _pipelines(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
    normalized = tuple(_safe_text(item) for item in value)
    if normalized != WP8_CANONICAL_PIPELINE_KEYS:
        _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
    return normalized


def _fingerprint_without(value: Mapping[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return contract_fingerprint(payload)


def _version(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != 1:
        _fail(WP8FailureCode.CONTRACT_VERSION_UNSUPPORTED)


@dataclass(frozen=True, slots=True)
class WP8InvariantSnapshotV1:
    """Unchanged authority facts, observed independently before and after B.

    P3C fingerprints describe stable authority/health, not moving writer
    counters or timestamps. Business observations are intentionally excluded.
    This schema does not collect facts or grant migration authority.
    """

    schema_fingerprint: str
    migration_tree_fingerprint: str
    alembic_revision: str
    principal_route_fingerprint: str
    db_identity_fingerprint: str
    provider_identity_fingerprint: str
    enabled_scope_fingerprint: str
    source_identity_fingerprint: str
    sync_state_fingerprint: str
    protected_environment_fingerprint: str
    registry_fingerprint: str
    unit_profile_asset_fingerprint: str
    gate_a_authority_binding_fingerprint: str
    gate_b_authority_binding_fingerprint: str
    gate_c_authority_binding_fingerprint: str
    p3c_state_fingerprint: str
    p3c_systemd_fingerprint: str
    p3d_timer_state: str
    legacy_writer_state: str
    legacy_enrichment_state: str
    gmail_state: str
    integration_test_state: str

    HASH_FIELDS = (
        "schema_fingerprint", "migration_tree_fingerprint",
        "principal_route_fingerprint", "db_identity_fingerprint",
        "provider_identity_fingerprint", "enabled_scope_fingerprint",
        "source_identity_fingerprint", "sync_state_fingerprint",
        "protected_environment_fingerprint", "registry_fingerprint",
        "unit_profile_asset_fingerprint", "gate_a_authority_binding_fingerprint",
        "gate_b_authority_binding_fingerprint", "gate_c_authority_binding_fingerprint",
        "p3c_state_fingerprint", "p3c_systemd_fingerprint",
    )
    FIXED = {
        "alembic_revision": EXPECTED_ALEMBIC_REVISION,
        "p3d_timer_state": "DISABLED_INACTIVE",
        "legacy_writer_state": "DISABLED_INACTIVE",
        "legacy_enrichment_state": "DISABLED_INACTIVE",
        "gmail_state": "DISABLED",
        "integration_test_state": "DISABLED",
    }
    FIELDS = frozenset({"version", *HASH_FIELDS, *FIXED})

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8InvariantSnapshotV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        if any(value[name] != expected for name, expected in cls.FIXED.items()):
            _fail(WP8FailureCode.INVARIANT_FAILED)
        return cls(**{
            **{name: _sha256(value[name]) for name in cls.HASH_FIELDS},
            **{name: value[name] for name in cls.FIXED},
        })

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            **{name: getattr(self, name) for name in (*self.HASH_FIELDS, *self.FIXED)},
        }


PHASE_A_CONTEXT_FIELDS = (
    "candidate_sha",
    "rollback_source_sha",
    "gate_a_operation_id",
    "gate_a_authority_binding_fingerprint",
    "gate_b_operation_id",
    "gate_b_authority_binding_fingerprint",
    "gate_c_operation_id",
    "gate_c_marker_fingerprint",
    "gate_c_authority_binding_fingerprint",
    "wp6_context_fingerprint",
    "db_identity_fingerprint",
    "enabled_scope_count",
    "enabled_scope_fingerprint",
    "unit_profile_asset_fingerprint",
    "canonical_pipeline_keys",
    "canonical_pipeline_set_fingerprint",
    "p3c_state_fingerprint",
    "p3c_systemd_fingerprint",
    "protected_environment_fingerprint",
    "registry_fingerprint",
    "current_state",
    "p3d_timer_state",
    "read_only_db_guarantee",
    "invariant_baseline",
)


@dataclass(frozen=True, slots=True)
class WP8PhaseAEvidenceV1:
    candidate_sha: str
    rollback_source_sha: str
    gate_a_operation_id: str
    gate_a_authority_binding_fingerprint: str
    gate_b_operation_id: str
    gate_b_authority_binding_fingerprint: str
    gate_c_operation_id: str
    gate_c_marker_fingerprint: str
    gate_c_authority_binding_fingerprint: str
    wp6_context_fingerprint: str
    db_identity_fingerprint: str
    enabled_scope_count: int
    enabled_scope_fingerprint: str
    unit_profile_asset_fingerprint: str
    canonical_pipeline_keys: tuple[str, ...]
    canonical_pipeline_set_fingerprint: str
    p3c_state_fingerprint: str
    p3c_systemd_fingerprint: str
    protected_environment_fingerprint: str
    registry_fingerprint: str
    current_state: str
    p3d_timer_state: str
    read_only_db_guarantee: str
    runtime_pipeline_coverage: str
    post_rehearsal_runtime_ledger_proof: str
    invariant_baseline: WP8InvariantSnapshotV1
    phase_a_context_fingerprint: str
    phase_a_evidence_fingerprint: str

    FIELDS = frozenset({
        "version", "evidence_class", "candidate_sha", "rollback_source_sha",
        "gate_a_operation_id", "gate_a_authority_binding_fingerprint",
        "gate_b_operation_id", "gate_b_authority_binding_fingerprint",
        "gate_c_operation_id", "gate_c_marker_fingerprint",
        "gate_c_authority_binding_fingerprint", "wp6_context_fingerprint",
        "db_identity_fingerprint", "enabled_scope_count",
        "enabled_scope_fingerprint", "unit_profile_asset_fingerprint",
        "canonical_pipeline_keys", "canonical_pipeline_set_fingerprint",
        "p3c_state_fingerprint", "p3c_systemd_fingerprint",
        "protected_environment_fingerprint", "registry_fingerprint",
        "current_state", "p3d_timer_state", "read_only_db_guarantee",
        "runtime_pipeline_coverage", "post_rehearsal_runtime_ledger_proof",
        "invariant_baseline",
        "phase_a_context_fingerprint", "phase_a_evidence_fingerprint",
    })

    @classmethod
    def build(
        cls,
        *,
        candidate_sha: str,
        rollback_source_sha: str,
        gate_a_operation_id: str,
        gate_a_authority_binding_fingerprint: str,
        gate_b_operation_id: str,
        gate_b_authority_binding_fingerprint: str,
        gate_c_operation_id: str,
        gate_c_marker_fingerprint: str,
        gate_c_authority_binding_fingerprint: str,
        wp6_context_fingerprint: str,
        db_identity_fingerprint: str,
        enabled_scope_count: int,
        enabled_scope_fingerprint: str,
        unit_profile_asset_fingerprint: str,
        p3c_state_fingerprint: str,
        p3c_systemd_fingerprint: str,
        protected_environment_fingerprint: str,
        registry_fingerprint: str,
        invariant_baseline: WP8InvariantSnapshotV1,
    ) -> "WP8PhaseAEvidenceV1":
        value: dict[str, Any] = {
            "version": 1,
            "evidence_class": "A_READ_ONLY_PRODUCTION_PREFLIGHT",
            "candidate_sha": candidate_sha,
            "rollback_source_sha": rollback_source_sha,
            "gate_a_operation_id": gate_a_operation_id,
            "gate_a_authority_binding_fingerprint": gate_a_authority_binding_fingerprint,
            "gate_b_operation_id": gate_b_operation_id,
            "gate_b_authority_binding_fingerprint": gate_b_authority_binding_fingerprint,
            "gate_c_operation_id": gate_c_operation_id,
            "gate_c_marker_fingerprint": gate_c_marker_fingerprint,
            "gate_c_authority_binding_fingerprint": gate_c_authority_binding_fingerprint,
            "wp6_context_fingerprint": wp6_context_fingerprint,
            "db_identity_fingerprint": db_identity_fingerprint,
            "enabled_scope_count": enabled_scope_count,
            "enabled_scope_fingerprint": enabled_scope_fingerprint,
            "unit_profile_asset_fingerprint": unit_profile_asset_fingerprint,
            "canonical_pipeline_keys": list(WP8_CANONICAL_PIPELINE_KEYS),
            "canonical_pipeline_set_fingerprint": WP8_CANONICAL_PIPELINE_SET_FINGERPRINT,
            "p3c_state_fingerprint": p3c_state_fingerprint,
            "p3c_systemd_fingerprint": p3c_systemd_fingerprint,
            "protected_environment_fingerprint": protected_environment_fingerprint,
            "registry_fingerprint": registry_fingerprint,
            "current_state": "ROLLBACK_SOURCE",
            "p3d_timer_state": "DISABLED_INACTIVE",
            "read_only_db_guarantee": "PASS",
            "runtime_pipeline_coverage": "0/6",
            "post_rehearsal_runtime_ledger_proof": "NOT_APPLICABLE_PRE_REHEARSAL",
            "invariant_baseline": WP8InvariantSnapshotV1.from_mapping(
                invariant_baseline.to_mapping()
            ).to_mapping(),
        }
        value["phase_a_context_fingerprint"] = contract_fingerprint({
            field: value[field] for field in PHASE_A_CONTEXT_FIELDS
        })
        value["phase_a_evidence_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8PhaseAEvidenceV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        if value["evidence_class"] != "A_READ_ONLY_PRODUCTION_PREFLIGHT":
            _fail()
        candidate = _git_sha(value["candidate_sha"])
        rollback = _git_sha(value["rollback_source_sha"])
        if candidate == rollback:
            _fail()
        gate_ids = (
            _canonical_uuid(value["gate_a_operation_id"]),
            _canonical_uuid(value["gate_b_operation_id"]),
            _canonical_uuid(value["gate_c_operation_id"]),
        )
        if len(set(gate_ids)) != 3:
            _fail()
        hashes = {
            name: _sha256(value[name])
            for name in (
                "gate_a_authority_binding_fingerprint",
                "gate_b_authority_binding_fingerprint",
                "gate_c_marker_fingerprint",
                "gate_c_authority_binding_fingerprint",
                "wp6_context_fingerprint",
                "db_identity_fingerprint",
                "enabled_scope_fingerprint",
                "unit_profile_asset_fingerprint",
                "p3c_state_fingerprint",
                "p3c_systemd_fingerprint",
                "protected_environment_fingerprint",
                "registry_fingerprint",
                "phase_a_context_fingerprint",
                "phase_a_evidence_fingerprint",
            )
        }
        pipelines = _pipelines(value["canonical_pipeline_keys"])
        if (
            _sha256(value["canonical_pipeline_set_fingerprint"])
            != WP8_CANONICAL_PIPELINE_SET_FINGERPRINT
            or value["current_state"] != "ROLLBACK_SOURCE"
            or value["p3d_timer_state"] != "DISABLED_INACTIVE"
            or value["read_only_db_guarantee"] != "PASS"
            or value["runtime_pipeline_coverage"] != "0/6"
            or value["post_rehearsal_runtime_ledger_proof"]
            != "NOT_APPLICABLE_PRE_REHEARSAL"
        ):
            _fail()
        scope_count = _integer(value["enabled_scope_count"], minimum=1)
        baseline = WP8InvariantSnapshotV1.from_mapping(value["invariant_baseline"])
        for name in (
            "db_identity_fingerprint", "enabled_scope_fingerprint",
            "protected_environment_fingerprint", "registry_fingerprint",
            "unit_profile_asset_fingerprint", "gate_a_authority_binding_fingerprint",
            "gate_b_authority_binding_fingerprint", "gate_c_authority_binding_fingerprint",
            "p3c_state_fingerprint", "p3c_systemd_fingerprint",
        ):
            if getattr(baseline, name) != hashes[name]:
                _fail(WP8FailureCode.INVARIANT_FAILED)
        expected_context = contract_fingerprint({
            field: value[field] for field in PHASE_A_CONTEXT_FIELDS
        })
        if hashes["phase_a_context_fingerprint"] != expected_context:
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        if (
            hashes["phase_a_evidence_fingerprint"]
            != _fingerprint_without(value, "phase_a_evidence_fingerprint")
        ):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            candidate,
            rollback,
            gate_ids[0],
            hashes["gate_a_authority_binding_fingerprint"],
            gate_ids[1],
            hashes["gate_b_authority_binding_fingerprint"],
            gate_ids[2],
            hashes["gate_c_marker_fingerprint"],
            hashes["gate_c_authority_binding_fingerprint"],
            hashes["wp6_context_fingerprint"],
            hashes["db_identity_fingerprint"],
            scope_count,
            hashes["enabled_scope_fingerprint"],
            hashes["unit_profile_asset_fingerprint"],
            pipelines,
            WP8_CANONICAL_PIPELINE_SET_FINGERPRINT,
            hashes["p3c_state_fingerprint"],
            hashes["p3c_systemd_fingerprint"],
            hashes["protected_environment_fingerprint"],
            hashes["registry_fingerprint"],
            "ROLLBACK_SOURCE",
            "DISABLED_INACTIVE",
            "PASS",
            "0/6",
            "NOT_APPLICABLE_PRE_REHEARSAL",
            baseline,
            hashes["phase_a_context_fingerprint"],
            hashes["phase_a_evidence_fingerprint"],
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "evidence_class": "A_READ_ONLY_PRODUCTION_PREFLIGHT",
            "candidate_sha": self.candidate_sha,
            "rollback_source_sha": self.rollback_source_sha,
            "gate_a_operation_id": self.gate_a_operation_id,
            "gate_a_authority_binding_fingerprint": self.gate_a_authority_binding_fingerprint,
            "gate_b_operation_id": self.gate_b_operation_id,
            "gate_b_authority_binding_fingerprint": self.gate_b_authority_binding_fingerprint,
            "gate_c_operation_id": self.gate_c_operation_id,
            "gate_c_marker_fingerprint": self.gate_c_marker_fingerprint,
            "gate_c_authority_binding_fingerprint": self.gate_c_authority_binding_fingerprint,
            "wp6_context_fingerprint": self.wp6_context_fingerprint,
            "db_identity_fingerprint": self.db_identity_fingerprint,
            "enabled_scope_count": self.enabled_scope_count,
            "enabled_scope_fingerprint": self.enabled_scope_fingerprint,
            "unit_profile_asset_fingerprint": self.unit_profile_asset_fingerprint,
            "canonical_pipeline_keys": list(self.canonical_pipeline_keys),
            "canonical_pipeline_set_fingerprint": self.canonical_pipeline_set_fingerprint,
            "p3c_state_fingerprint": self.p3c_state_fingerprint,
            "p3c_systemd_fingerprint": self.p3c_systemd_fingerprint,
            "protected_environment_fingerprint": self.protected_environment_fingerprint,
            "registry_fingerprint": self.registry_fingerprint,
            "current_state": self.current_state,
            "p3d_timer_state": self.p3d_timer_state,
            "read_only_db_guarantee": self.read_only_db_guarantee,
            "runtime_pipeline_coverage": self.runtime_pipeline_coverage,
            "post_rehearsal_runtime_ledger_proof": self.post_rehearsal_runtime_ledger_proof,
            "invariant_baseline": self.invariant_baseline.to_mapping(),
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "phase_a_evidence_fingerprint": self.phase_a_evidence_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class WP8AReviewResultV1:
    candidate_sha: str
    phase_a_evidence_fingerprint: str
    phase_a_context_fingerprint: str
    gate_a_operation_id: str
    gate_a_authority_binding_fingerprint: str
    gate_b_operation_id: str
    gate_b_authority_binding_fingerprint: str
    gate_c_operation_id: str
    gate_c_authority_binding_fingerprint: str
    reviewed_at_utc: str
    review_record_sha256: str
    review_result_fingerprint: str

    FIELDS = frozenset({
        "version", "review_class", "result", "candidate_sha",
        "phase_a_evidence_fingerprint", "phase_a_context_fingerprint",
        "gate_a_operation_id", "gate_a_authority_binding_fingerprint",
        "gate_b_operation_id", "gate_b_authority_binding_fingerprint",
        "gate_c_operation_id", "gate_c_authority_binding_fingerprint",
        "reviewed_at_utc", "review_record_sha256", "review_result_fingerprint",
    })

    @classmethod
    def build(
        cls,
        evidence: WP8PhaseAEvidenceV1,
        *,
        reviewed_at_utc: str,
        review_record_sha256: str,
    ) -> "WP8AReviewResultV1":
        evidence = WP8PhaseAEvidenceV1.from_mapping(evidence.to_mapping())
        value: dict[str, Any] = {
            "version": 1,
            "review_class": "INDEPENDENT_PHASE_A_REVIEW",
            "result": "PASS",
            "candidate_sha": evidence.candidate_sha,
            "phase_a_evidence_fingerprint": evidence.phase_a_evidence_fingerprint,
            "phase_a_context_fingerprint": evidence.phase_a_context_fingerprint,
            "gate_a_operation_id": evidence.gate_a_operation_id,
            "gate_a_authority_binding_fingerprint": evidence.gate_a_authority_binding_fingerprint,
            "gate_b_operation_id": evidence.gate_b_operation_id,
            "gate_b_authority_binding_fingerprint": evidence.gate_b_authority_binding_fingerprint,
            "gate_c_operation_id": evidence.gate_c_operation_id,
            "gate_c_authority_binding_fingerprint": evidence.gate_c_authority_binding_fingerprint,
            "reviewed_at_utc": reviewed_at_utc,
            "review_record_sha256": review_record_sha256,
        }
        value["review_result_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8AReviewResultV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        if (
            value["review_class"] != "INDEPENDENT_PHASE_A_REVIEW"
            or value["result"] != "PASS"
        ):
            _fail()
        parsed = cls(
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_evidence_fingerprint"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _canonical_uuid(value["gate_a_operation_id"]),
            _sha256(value["gate_a_authority_binding_fingerprint"]),
            _canonical_uuid(value["gate_b_operation_id"]),
            _sha256(value["gate_b_authority_binding_fingerprint"]),
            _canonical_uuid(value["gate_c_operation_id"]),
            _sha256(value["gate_c_authority_binding_fingerprint"]),
            _timestamp(value["reviewed_at_utc"]),
            _sha256(value["review_record_sha256"]),
            _sha256(value["review_result_fingerprint"]),
        )
        if parsed.review_result_fingerprint != _fingerprint_without(
            value, "review_result_fingerprint"
        ):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return parsed

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "review_class": "INDEPENDENT_PHASE_A_REVIEW",
            "result": "PASS",
            "candidate_sha": self.candidate_sha,
            "phase_a_evidence_fingerprint": self.phase_a_evidence_fingerprint,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "gate_a_operation_id": self.gate_a_operation_id,
            "gate_a_authority_binding_fingerprint": self.gate_a_authority_binding_fingerprint,
            "gate_b_operation_id": self.gate_b_operation_id,
            "gate_b_authority_binding_fingerprint": self.gate_b_authority_binding_fingerprint,
            "gate_c_operation_id": self.gate_c_operation_id,
            "gate_c_authority_binding_fingerprint": self.gate_c_authority_binding_fingerprint,
            "reviewed_at_utc": self.reviewed_at_utc,
            "review_record_sha256": self.review_record_sha256,
            "review_result_fingerprint": self.review_result_fingerprint,
        }


def validate_review_result(
    review: WP8AReviewResultV1,
    evidence: WP8PhaseAEvidenceV1,
) -> bool:
    review = WP8AReviewResultV1.from_mapping(review.to_mapping())
    evidence = WP8PhaseAEvidenceV1.from_mapping(evidence.to_mapping())
    expected = (
        evidence.candidate_sha,
        evidence.phase_a_evidence_fingerprint,
        evidence.phase_a_context_fingerprint,
        evidence.gate_a_operation_id,
        evidence.gate_a_authority_binding_fingerprint,
        evidence.gate_b_operation_id,
        evidence.gate_b_authority_binding_fingerprint,
        evidence.gate_c_operation_id,
        evidence.gate_c_authority_binding_fingerprint,
    )
    actual = (
        review.candidate_sha,
        review.phase_a_evidence_fingerprint,
        review.phase_a_context_fingerprint,
        review.gate_a_operation_id,
        review.gate_a_authority_binding_fingerprint,
        review.gate_b_operation_id,
        review.gate_b_authority_binding_fingerprint,
        review.gate_c_operation_id,
        review.gate_c_authority_binding_fingerprint,
    )
    if actual != expected:
        _fail(WP8FailureCode.AUTHORIZATION_INVALID)
    return True


@dataclass(frozen=True, slots=True)
class WP8RehearsalAuthorizationV1:
    rehearsal_operation_id: str
    candidate_sha: str
    rollback_source_sha: str
    phase_a_evidence_fingerprint: str
    phase_a_context_fingerprint: str
    phase_a_review_result_fingerprint: str
    review_record_sha256: str
    gate_a_operation_id: str
    gate_a_authority_binding_fingerprint: str
    gate_b_operation_id: str
    gate_b_authority_binding_fingerprint: str
    gate_c_operation_id: str
    gate_c_authority_binding_fingerprint: str
    canonical_pipeline_keys: tuple[str, ...]
    canonical_pipeline_set_fingerprint: str
    issued_at_utc: str
    not_before_utc: str
    expires_at_utc: str
    single_use: bool
    authorization_fingerprint: str

    FIELDS = frozenset({
        "version", "authorization_class", "rehearsal_operation_id",
        "candidate_sha", "rollback_source_sha", "phase_a_evidence_fingerprint",
        "phase_a_context_fingerprint", "phase_a_review_result_fingerprint",
        "review_result", "review_record_sha256", "gate_a_operation_id",
        "gate_a_authority_binding_fingerprint", "gate_b_operation_id",
        "gate_b_authority_binding_fingerprint", "gate_c_operation_id",
        "gate_c_authority_binding_fingerprint", "canonical_pipeline_keys",
        "canonical_pipeline_set_fingerprint", "issued_at_utc", "not_before_utc",
        "expires_at_utc", "single_use", "authorization_fingerprint",
    })

    @classmethod
    def build(
        cls,
        evidence: WP8PhaseAEvidenceV1,
        review: WP8AReviewResultV1,
        *,
        rehearsal_operation_id: str,
        issued_at_utc: str,
        not_before_utc: str,
        expires_at_utc: str,
    ) -> "WP8RehearsalAuthorizationV1":
        evidence = WP8PhaseAEvidenceV1.from_mapping(evidence.to_mapping())
        review = WP8AReviewResultV1.from_mapping(review.to_mapping())
        validate_review_result(review, evidence)
        if _timestamp(issued_at_utc) < review.reviewed_at_utc:
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        value: dict[str, Any] = {
            "version": 1,
            "authorization_class": "PRODUCTION_REHEARSAL_EXECUTION",
            "rehearsal_operation_id": rehearsal_operation_id,
            "candidate_sha": evidence.candidate_sha,
            "rollback_source_sha": evidence.rollback_source_sha,
            "phase_a_evidence_fingerprint": evidence.phase_a_evidence_fingerprint,
            "phase_a_context_fingerprint": evidence.phase_a_context_fingerprint,
            "phase_a_review_result_fingerprint": review.review_result_fingerprint,
            "review_result": "PASS",
            "review_record_sha256": review.review_record_sha256,
            "gate_a_operation_id": evidence.gate_a_operation_id,
            "gate_a_authority_binding_fingerprint": evidence.gate_a_authority_binding_fingerprint,
            "gate_b_operation_id": evidence.gate_b_operation_id,
            "gate_b_authority_binding_fingerprint": evidence.gate_b_authority_binding_fingerprint,
            "gate_c_operation_id": evidence.gate_c_operation_id,
            "gate_c_authority_binding_fingerprint": evidence.gate_c_authority_binding_fingerprint,
            "canonical_pipeline_keys": list(WP8_CANONICAL_PIPELINE_KEYS),
            "canonical_pipeline_set_fingerprint": WP8_CANONICAL_PIPELINE_SET_FINGERPRINT,
            "issued_at_utc": issued_at_utc,
            "not_before_utc": not_before_utc,
            "expires_at_utc": expires_at_utc,
            "single_use": True,
        }
        value["authorization_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8RehearsalAuthorizationV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        if (
            value["authorization_class"] != "PRODUCTION_REHEARSAL_EXECUTION"
            or value["review_result"] != "PASS"
            or value["single_use"] is not True
        ):
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        candidate = _git_sha(value["candidate_sha"])
        rollback = _git_sha(value["rollback_source_sha"])
        if candidate == rollback:
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        pipelines = _pipelines(value["canonical_pipeline_keys"])
        pipeline_fingerprint = _sha256(value["canonical_pipeline_set_fingerprint"])
        if pipeline_fingerprint != WP8_CANONICAL_PIPELINE_SET_FINGERPRINT:
            _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
        issued = _timestamp(value["issued_at_utc"])
        not_before = _timestamp(value["not_before_utc"])
        expires = _timestamp(value["expires_at_utc"])
        if not (issued <= not_before < expires):
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        operation_id = _canonical_uuid(value["rehearsal_operation_id"])
        gate_a_operation_id = _canonical_uuid(value["gate_a_operation_id"])
        gate_b_operation_id = _canonical_uuid(value["gate_b_operation_id"])
        gate_c_operation_id = _canonical_uuid(value["gate_c_operation_id"])
        if len({
            operation_id, gate_a_operation_id, gate_b_operation_id,
            gate_c_operation_id,
        }) != 4:
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        parsed = cls(
            operation_id,
            candidate,
            rollback,
            _sha256(value["phase_a_evidence_fingerprint"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _sha256(value["phase_a_review_result_fingerprint"]),
            _sha256(value["review_record_sha256"]),
            gate_a_operation_id,
            _sha256(value["gate_a_authority_binding_fingerprint"]),
            gate_b_operation_id,
            _sha256(value["gate_b_authority_binding_fingerprint"]),
            gate_c_operation_id,
            _sha256(value["gate_c_authority_binding_fingerprint"]),
            pipelines,
            pipeline_fingerprint,
            issued,
            not_before,
            expires,
            True,
            _sha256(value["authorization_fingerprint"]),
        )
        if parsed.authorization_fingerprint != _fingerprint_without(
            value, "authorization_fingerprint"
        ):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return parsed

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "authorization_class": "PRODUCTION_REHEARSAL_EXECUTION",
            "rehearsal_operation_id": self.rehearsal_operation_id,
            "candidate_sha": self.candidate_sha,
            "rollback_source_sha": self.rollback_source_sha,
            "phase_a_evidence_fingerprint": self.phase_a_evidence_fingerprint,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "phase_a_review_result_fingerprint": self.phase_a_review_result_fingerprint,
            "review_result": "PASS",
            "review_record_sha256": self.review_record_sha256,
            "gate_a_operation_id": self.gate_a_operation_id,
            "gate_a_authority_binding_fingerprint": self.gate_a_authority_binding_fingerprint,
            "gate_b_operation_id": self.gate_b_operation_id,
            "gate_b_authority_binding_fingerprint": self.gate_b_authority_binding_fingerprint,
            "gate_c_operation_id": self.gate_c_operation_id,
            "gate_c_authority_binding_fingerprint": self.gate_c_authority_binding_fingerprint,
            "canonical_pipeline_keys": list(self.canonical_pipeline_keys),
            "canonical_pipeline_set_fingerprint": self.canonical_pipeline_set_fingerprint,
            "issued_at_utc": self.issued_at_utc,
            "not_before_utc": self.not_before_utc,
            "expires_at_utc": self.expires_at_utc,
            "single_use": self.single_use,
            "authorization_fingerprint": self.authorization_fingerprint,
        }


def validate_rehearsal_authorization(
    authorization: WP8RehearsalAuthorizationV1,
    evidence: WP8PhaseAEvidenceV1,
    review: WP8AReviewResultV1,
    *,
    at_utc: str,
    consumed: bool,
) -> bool:
    authorization = WP8RehearsalAuthorizationV1.from_mapping(
        authorization.to_mapping()
    )
    evidence = WP8PhaseAEvidenceV1.from_mapping(evidence.to_mapping())
    review = WP8AReviewResultV1.from_mapping(review.to_mapping())
    validate_review_result(review, evidence)
    if type(consumed) is not bool:
        _fail(WP8FailureCode.AUTHORIZATION_INVALID)
    if consumed:
        _fail(WP8FailureCode.AUTHORIZATION_REPLAY)
    instant = _timestamp(at_utc)
    if instant < authorization.not_before_utc:
        _fail(WP8FailureCode.AUTHORIZATION_NOT_YET_VALID)
    if instant >= authorization.expires_at_utc:
        _fail(WP8FailureCode.AUTHORIZATION_EXPIRED)
    if authorization.issued_at_utc < review.reviewed_at_utc:
        _fail(WP8FailureCode.AUTHORIZATION_INVALID)
    expected = (
        evidence.candidate_sha,
        evidence.rollback_source_sha,
        evidence.phase_a_evidence_fingerprint,
        evidence.phase_a_context_fingerprint,
        review.review_result_fingerprint,
        review.review_record_sha256,
        evidence.gate_a_operation_id,
        evidence.gate_a_authority_binding_fingerprint,
        evidence.gate_b_operation_id,
        evidence.gate_b_authority_binding_fingerprint,
        evidence.gate_c_operation_id,
        evidence.gate_c_authority_binding_fingerprint,
    )
    actual = (
        authorization.candidate_sha,
        authorization.rollback_source_sha,
        authorization.phase_a_evidence_fingerprint,
        authorization.phase_a_context_fingerprint,
        authorization.phase_a_review_result_fingerprint,
        authorization.review_record_sha256,
        authorization.gate_a_operation_id,
        authorization.gate_a_authority_binding_fingerprint,
        authorization.gate_b_operation_id,
        authorization.gate_b_authority_binding_fingerprint,
        authorization.gate_c_operation_id,
        authorization.gate_c_authority_binding_fingerprint,
    )
    if actual != expected:
        _fail(WP8FailureCode.AUTHORIZATION_INVALID)
    return True


class WP8RehearsalPhase(str, Enum):
    NEW = "NEW"
    AUTHORIZATION_VERIFIED = "AUTHORIZATION_VERIFIED"
    PREREQUISITES_VERIFIED = "PREREQUISITES_VERIFIED"
    PRE_MUTATION_REVALIDATED = "PRE_MUTATION_REVALIDATED"
    CURRENT_PROMOTED = "CURRENT_PROMOTED"
    SYSTEMD_RELOADED = "SYSTEMD_RELOADED"
    SERVICES_VERIFIED = "SERVICES_VERIFIED"
    SERVICE_1_EXECUTING = "SERVICE_1_EXECUTING"
    SERVICE_1_VERIFIED = "SERVICE_1_VERIFIED"
    SERVICE_2_EXECUTING = "SERVICE_2_EXECUTING"
    SERVICE_2_VERIFIED = "SERVICE_2_VERIFIED"
    SERVICE_3_EXECUTING = "SERVICE_3_EXECUTING"
    SERVICE_3_VERIFIED = "SERVICE_3_VERIFIED"
    SERVICE_4_EXECUTING = "SERVICE_4_EXECUTING"
    SERVICE_4_VERIFIED = "SERVICE_4_VERIFIED"
    SERVICE_5_EXECUTING = "SERVICE_5_EXECUTING"
    SERVICE_5_VERIFIED = "SERVICE_5_VERIFIED"
    SERVICE_6_EXECUTING = "SERVICE_6_EXECUTING"
    SERVICE_6_VERIFIED = "SERVICE_6_VERIFIED"
    SERVICES_EXECUTED = "SERVICES_EXECUTED"
    RUNTIME_LEDGER_VERIFIED = "RUNTIME_LEDGER_VERIFIED"
    INVARIANTS_VERIFIED = "INVARIANTS_VERIFIED"
    SERVICES_STOPPED = "SERVICES_STOPPED"
    REHEARSAL_COMPLETE = "REHEARSAL_COMPLETE"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
    ABORT_NOT_CONFIRMED = "ABORT_NOT_CONFIRMED"


NORMAL_PHASES = (
    WP8RehearsalPhase.NEW,
    WP8RehearsalPhase.AUTHORIZATION_VERIFIED,
    WP8RehearsalPhase.PREREQUISITES_VERIFIED,
    WP8RehearsalPhase.PRE_MUTATION_REVALIDATED,
    WP8RehearsalPhase.CURRENT_PROMOTED,
    WP8RehearsalPhase.SYSTEMD_RELOADED,
    WP8RehearsalPhase.SERVICES_VERIFIED,
    WP8RehearsalPhase.SERVICE_1_EXECUTING,
    WP8RehearsalPhase.SERVICE_1_VERIFIED,
    WP8RehearsalPhase.SERVICE_2_EXECUTING,
    WP8RehearsalPhase.SERVICE_2_VERIFIED,
    WP8RehearsalPhase.SERVICE_3_EXECUTING,
    WP8RehearsalPhase.SERVICE_3_VERIFIED,
    WP8RehearsalPhase.SERVICE_4_EXECUTING,
    WP8RehearsalPhase.SERVICE_4_VERIFIED,
    WP8RehearsalPhase.SERVICE_5_EXECUTING,
    WP8RehearsalPhase.SERVICE_5_VERIFIED,
    WP8RehearsalPhase.SERVICE_6_EXECUTING,
    WP8RehearsalPhase.SERVICE_6_VERIFIED,
    WP8RehearsalPhase.SERVICES_EXECUTED,
    WP8RehearsalPhase.RUNTIME_LEDGER_VERIFIED,
    WP8RehearsalPhase.INVARIANTS_VERIFIED,
    WP8RehearsalPhase.SERVICES_STOPPED,
    WP8RehearsalPhase.REHEARSAL_COMPLETE,
)
PRE_MUTATION_PHASES = frozenset(NORMAL_PHASES[:4])
POST_MUTATION_PHASES = frozenset(NORMAL_PHASES[4:-1])
TERMINAL_PHASES = frozenset({
    WP8RehearsalPhase.REHEARSAL_COMPLETE,
    WP8RehearsalPhase.FAILED,
    WP8RehearsalPhase.ABORTED,
})


ALLOWED_TRANSITIONS: dict[WP8RehearsalPhase, frozenset[WP8RehearsalPhase]] = {
    phase: frozenset({NORMAL_PHASES[index + 1]})
    for index, phase in enumerate(NORMAL_PHASES[:-1])
}
for phase in PRE_MUTATION_PHASES:
    ALLOWED_TRANSITIONS[phase] = ALLOWED_TRANSITIONS[phase] | frozenset({
        WP8RehearsalPhase.FAILED,
    })
for phase in POST_MUTATION_PHASES:
    ALLOWED_TRANSITIONS[phase] = ALLOWED_TRANSITIONS[phase] | frozenset({
        WP8RehearsalPhase.ABORTED,
        WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
    })
ALLOWED_TRANSITIONS[WP8RehearsalPhase.ABORT_NOT_CONFIRMED] = frozenset({
    WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
    WP8RehearsalPhase.ABORTED,
})
for phase in TERMINAL_PHASES:
    ALLOWED_TRANSITIONS[phase] = frozenset()


def validate_wp8_transition(
    source: WP8RehearsalPhase | str,
    target: WP8RehearsalPhase | str,
) -> bool:
    source_phase = _enum(WP8RehearsalPhase, source)
    target_phase = _enum(WP8RehearsalPhase, target)
    if target_phase not in ALLOWED_TRANSITIONS[source_phase]:
        _fail(WP8FailureCode.CONTRACT_TRANSITION_INVALID)
    return True


def _service_pipeline_for_transition(
    source: WP8RehearsalPhase,
    target: WP8RehearsalPhase,
) -> str | None:
    for index, pipeline_key in enumerate(WP8_CANONICAL_PIPELINE_KEYS, start=1):
        executing = WP8RehearsalPhase[f"SERVICE_{index}_EXECUTING"]
        verified = WP8RehearsalPhase[f"SERVICE_{index}_VERIFIED"]
        if target in {executing, verified}:
            return pipeline_key
    return None


FAILURE_PHASES = frozenset({
    WP8RehearsalPhase.FAILED, WP8RehearsalPhase.ABORTED,
    WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
})


def _failure_provenance(
    primary: WP8FailureCode | None,
    phase: Any,
    pipeline: Any,
    boundary: Any,
) -> tuple[WP8RehearsalPhase | None, str | None, str | None]:
    if primary is None:
        if any(item is not None for item in (phase, pipeline, boundary)):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        return None, None, None
    failed_phase = _enum(WP8RehearsalPhase, phase)
    if failed_phase not in PRE_MUTATION_PHASES | POST_MUTATION_PHASES:
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    expected_boundary = (
        "PRE_MUTATION" if failed_phase in PRE_MUTATION_PHASES else "POST_MUTATION"
    )
    expected_pipeline = _service_pipeline_for_transition(failed_phase, failed_phase)
    if boundary != expected_boundary:
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    if expected_pipeline is not None:
        if pipeline != expected_pipeline:
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    elif pipeline is not None and (
        pipeline not in WP8_CANONICAL_PIPELINE_KEYS
        or primary not in {
            WP8FailureCode.SERVICE_CONTRACT_INVALID,
            WP8FailureCode.RUNTIME_LEDGER_INVALID,
        }
    ):
        # Aggregate unit/ledger validation may identify a particular canonical
        # pipeline outside a service pair. Other authority failures cannot.
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    if primary is WP8FailureCode.SERVICE_EXECUTION_FAILED and expected_pipeline is None:
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    return failed_phase, pipeline, boundary


def _bound_cleanup(
    value: Any, fingerprint: str | None, operation_id: str,
    candidate_sha: str, context: str,
) -> "WP8CleanupProofV1 | None":
    if value is None:
        if fingerprint is not None:
            _fail(WP8FailureCode.CLEANUP_FAILED)
        return None
    proof = WP8CleanupProofV1.from_mapping(value)
    if (
        proof.cleanup_proof_fingerprint != fingerprint
        or (proof.rehearsal_operation_id, proof.candidate_sha,
            proof.phase_a_context_fingerprint) != (operation_id, candidate_sha, context)
    ):
        _fail(WP8FailureCode.CLEANUP_FAILED)
    return proof


@dataclass(frozen=True, slots=True)
class WP8RehearsalStateV1:
    operation_id: str
    candidate_sha: str
    phase_a_context_fingerprint: str
    authorization_fingerprint: str
    phase: WP8RehearsalPhase
    started_at_utc: str
    updated_at_utc: str
    runtime_ledger_fingerprint: str | None
    invariant_proof_fingerprint: str | None
    cleanup_proof_fingerprint: str | None
    cleanup_proof: WP8CleanupProofV1 | None
    primary_failure_code: WP8FailureCode | None
    cleanup_failure_code: WP8FailureCode | None
    failed_pipeline_key: str | None
    failed_phase: WP8RehearsalPhase | None
    failure_mutation_boundary: str | None
    journal_head_fingerprint: str | None
    state_fingerprint: str

    FIELDS = frozenset({
        "version", "operation_id", "candidate_sha", "phase_a_context_fingerprint",
        "authorization_fingerprint", "phase", "started_at_utc", "updated_at_utc",
        "runtime_ledger_fingerprint", "invariant_proof_fingerprint",
        "cleanup_proof_fingerprint", "primary_failure_code",
        "cleanup_proof", "failed_phase", "failure_mutation_boundary",
        "cleanup_failure_code", "failed_pipeline_key", "journal_head_fingerprint",
        "state_fingerprint",
    })

    @classmethod
    def new(
        cls,
        *,
        operation_id: str,
        candidate_sha: str,
        phase_a_context_fingerprint: str,
        authorization_fingerprint: str,
        started_at_utc: str,
    ) -> "WP8RehearsalStateV1":
        value: dict[str, Any] = {
            "version": 1,
            "operation_id": operation_id,
            "candidate_sha": candidate_sha,
            "phase_a_context_fingerprint": phase_a_context_fingerprint,
            "authorization_fingerprint": authorization_fingerprint,
            "phase": "NEW",
            "started_at_utc": started_at_utc,
            "updated_at_utc": started_at_utc,
            "runtime_ledger_fingerprint": None,
            "invariant_proof_fingerprint": None,
            "cleanup_proof_fingerprint": None,
            "cleanup_proof": None,
            "primary_failure_code": None,
            "cleanup_failure_code": None,
            "failed_pipeline_key": None,
            "failed_phase": None,
            "failure_mutation_boundary": None,
            "journal_head_fingerprint": None,
        }
        value["state_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8RehearsalStateV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        phase = _enum(WP8RehearsalPhase, value["phase"])
        started = _timestamp(value["started_at_utc"])
        updated = _timestamp(value["updated_at_utc"])
        if updated < started:
            _fail()
        runtime = None if value["runtime_ledger_fingerprint"] is None else _sha256(
            value["runtime_ledger_fingerprint"]
        )
        invariant = None if value["invariant_proof_fingerprint"] is None else _sha256(
            value["invariant_proof_fingerprint"]
        )
        cleanup = None if value["cleanup_proof_fingerprint"] is None else _sha256(
            value["cleanup_proof_fingerprint"]
        )
        primary = None if value["primary_failure_code"] is None else _enum(
            WP8FailureCode, value["primary_failure_code"]
        )
        cleanup_failure = None if value["cleanup_failure_code"] is None else _enum(
            WP8FailureCode, value["cleanup_failure_code"]
        )
        failed_pipeline = value["failed_pipeline_key"]
        if failed_pipeline is not None and failed_pipeline not in WP8_CANONICAL_PIPELINE_KEYS:
            _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
        failed_phase, failed_pipeline, boundary = _failure_provenance(
            primary, value["failed_phase"], failed_pipeline,
            value["failure_mutation_boundary"],
        )
        cleanup_proof = _bound_cleanup(
            value["cleanup_proof"], cleanup, value["operation_id"],
            value["candidate_sha"], value["phase_a_context_fingerprint"],
        )
        journal_head = None if value["journal_head_fingerprint"] is None else _sha256(
            value["journal_head_fingerprint"]
        )
        if phase is WP8RehearsalPhase.NEW:
            if any(item is not None for item in (
                runtime, invariant, cleanup, primary, cleanup_failure,
                failed_pipeline, journal_head,
            )) or updated != started:
                _fail()
        elif journal_head is None:
            _fail()
        normal_runtime_phases = frozenset({
            WP8RehearsalPhase.RUNTIME_LEDGER_VERIFIED,
            WP8RehearsalPhase.INVARIANTS_VERIFIED,
            WP8RehearsalPhase.SERVICES_STOPPED,
            WP8RehearsalPhase.REHEARSAL_COMPLETE,
        })
        normal_invariant_phases = frozenset({
            WP8RehearsalPhase.INVARIANTS_VERIFIED,
            WP8RehearsalPhase.SERVICES_STOPPED,
            WP8RehearsalPhase.REHEARSAL_COMPLETE,
        })
        normal_cleanup_phases = frozenset({
            WP8RehearsalPhase.SERVICES_STOPPED,
            WP8RehearsalPhase.REHEARSAL_COMPLETE,
        })
        if phase in normal_runtime_phases and runtime is None:
            _fail()
        if phase in normal_invariant_phases and invariant is None:
            _fail()
        if phase in normal_cleanup_phases and cleanup is None:
            _fail()
        normal_phase = phase in NORMAL_PHASES
        if normal_phase and phase not in normal_runtime_phases and runtime is not None:
            _fail()
        if normal_phase and phase not in normal_invariant_phases and invariant is not None:
            _fail()
        if normal_phase and phase not in normal_cleanup_phases and cleanup is not None:
            _fail()
        failure_phase = phase in {
            WP8RehearsalPhase.FAILED,
            WP8RehearsalPhase.ABORTED,
            WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
        }
        if failure_phase != (primary is not None):
            _fail()
        if primary is not None and primary not in OPERATION_FAILURE_CODES:
            _fail()
        if phase is WP8RehearsalPhase.FAILED and any(item is not None for item in (
            runtime, invariant, cleanup, cleanup_failure,
        )):
            _fail()
        if phase is WP8RehearsalPhase.ABORTED and (
            cleanup_proof is None or cleanup_proof.result is not WP8CleanupResult.PASS
            or cleanup_failure is not None
        ):
            _fail()
        if phase is WP8RehearsalPhase.ABORT_NOT_CONFIRMED and (
            cleanup_proof is None or cleanup_proof.result is not WP8CleanupResult.FAIL
            or cleanup_failure is not WP8FailureCode.CLEANUP_FAILED
        ):
            _fail()
        if phase in normal_cleanup_phases and (
            cleanup_proof is None or cleanup_proof.result is not WP8CleanupResult.PASS
        ):
            _fail(WP8FailureCode.CLEANUP_FAILED)
        if failure_phase and (
            (phase is WP8RehearsalPhase.FAILED) != (boundary == "PRE_MUTATION")
        ):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        if not failure_phase and any(item is not None for item in (
            primary, cleanup_failure, failed_pipeline,
        )):
            _fail()
        state_fingerprint = _sha256(value["state_fingerprint"])
        if state_fingerprint != _fingerprint_without(value, "state_fingerprint"):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            _canonical_uuid(value["operation_id"]),
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _sha256(value["authorization_fingerprint"]),
            phase,
            started,
            updated,
            runtime,
            invariant,
            cleanup,
            cleanup_proof,
            primary,
            cleanup_failure,
            failed_pipeline,
            failed_phase,
            boundary,
            journal_head,
            state_fingerprint,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "operation_id": self.operation_id,
            "candidate_sha": self.candidate_sha,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "authorization_fingerprint": self.authorization_fingerprint,
            "phase": self.phase.value,
            "started_at_utc": self.started_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "runtime_ledger_fingerprint": self.runtime_ledger_fingerprint,
            "invariant_proof_fingerprint": self.invariant_proof_fingerprint,
            "cleanup_proof_fingerprint": self.cleanup_proof_fingerprint,
            "cleanup_proof": (
                None if self.cleanup_proof is None else self.cleanup_proof.to_mapping()
            ),
            "primary_failure_code": (
                None if self.primary_failure_code is None
                else self.primary_failure_code.value
            ),
            "cleanup_failure_code": (
                None if self.cleanup_failure_code is None
                else self.cleanup_failure_code.value
            ),
            "failed_pipeline_key": self.failed_pipeline_key,
            "failed_phase": None if self.failed_phase is None else self.failed_phase.value,
            "failure_mutation_boundary": self.failure_mutation_boundary,
            "journal_head_fingerprint": self.journal_head_fingerprint,
            "state_fingerprint": self.state_fingerprint,
        }


class WP8EventClass(str, Enum):
    STATE_TRANSITION = "STATE_TRANSITION"
    PIPELINE_TRANSITION = "PIPELINE_TRANSITION"
    FAILURE = "FAILURE"
    CLEANUP_RECOVERY = "CLEANUP_RECOVERY"


def _event_class(
    source: WP8RehearsalPhase,
    target: WP8RehearsalPhase,
) -> WP8EventClass:
    if source is WP8RehearsalPhase.ABORT_NOT_CONFIRMED:
        return WP8EventClass.CLEANUP_RECOVERY
    if target in {
        WP8RehearsalPhase.FAILED,
        WP8RehearsalPhase.ABORTED,
        WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
    }:
        return WP8EventClass.FAILURE
    if _service_pipeline_for_transition(source, target) is not None:
        return WP8EventClass.PIPELINE_TRANSITION
    return WP8EventClass.STATE_TRANSITION


@dataclass(frozen=True, slots=True)
class WP8RehearsalJournalEventV1:
    sequence: int
    operation_id: str
    candidate_sha: str
    phase_a_context_fingerprint: str
    authorization_fingerprint: str
    from_state: WP8RehearsalPhase
    to_state: WP8RehearsalPhase
    event_class: WP8EventClass
    previous_event_fingerprint: str | None
    timestamp_utc: str
    pipeline_key: str | None
    failed_pipeline_key: str | None
    failed_phase: WP8RehearsalPhase | None
    failure_mutation_boundary: str | None
    cleanup_proof: WP8CleanupProofV1 | None
    evidence_fingerprints: tuple[str, ...]
    primary_failure_code: WP8FailureCode | None
    cleanup_failure_code: WP8FailureCode | None
    event_fingerprint: str

    FIELDS = frozenset({
        "version", "sequence", "operation_id", "candidate_sha",
        "phase_a_context_fingerprint", "authorization_fingerprint",
        "from_state", "to_state", "event_class",
        "previous_event_fingerprint", "timestamp_utc", "pipeline_key",
        "failed_pipeline_key", "failed_phase", "failure_mutation_boundary", "cleanup_proof",
        "evidence_fingerprints", "primary_failure_code",
        "cleanup_failure_code", "event_fingerprint",
    })

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        state: WP8RehearsalStateV1,
        target: WP8RehearsalPhase,
        timestamp_utc: str,
        evidence_fingerprints: Sequence[str] = (),
        primary_failure_code: WP8FailureCode | None = None,
        cleanup_failure_code: WP8FailureCode | None = None,
        failed_pipeline_key: str | None = None,
        cleanup_proof: WP8CleanupProofV1 | None = None,
    ) -> "WP8RehearsalJournalEventV1":
        state = WP8RehearsalStateV1.from_mapping(state.to_mapping())
        target = _enum(WP8RehearsalPhase, target)
        validate_wp8_transition(state.phase, target)
        pipeline_key = _service_pipeline_for_transition(state.phase, target)
        failed_phase = state.failed_phase
        boundary = state.failure_mutation_boundary
        if target in FAILURE_PHASES and state.primary_failure_code is None:
            failed_phase = state.phase
            boundary = "PRE_MUTATION" if state.phase in PRE_MUTATION_PHASES else "POST_MUTATION"
        if primary_failure_code is not None:
            primary_failure_code = _enum(WP8FailureCode, primary_failure_code)
            if primary_failure_code not in OPERATION_FAILURE_CODES:
                _fail()
        if cleanup_failure_code is not None:
            cleanup_failure_code = _enum(WP8FailureCode, cleanup_failure_code)
        if state.phase is WP8RehearsalPhase.ABORT_NOT_CONFIRMED and (
            primary_failure_code is not state.primary_failure_code
            or failed_pipeline_key != state.failed_pipeline_key
        ):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        if _timestamp(timestamp_utc) < state.updated_at_utc:
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        fingerprints = tuple(sorted(_sha256(item) for item in evidence_fingerprints))
        if len(set(fingerprints)) != len(fingerprints):
            _fail()
        value: dict[str, Any] = {
            "version": 1,
            "sequence": sequence,
            "operation_id": state.operation_id,
            "candidate_sha": state.candidate_sha,
            "phase_a_context_fingerprint": state.phase_a_context_fingerprint,
            "authorization_fingerprint": state.authorization_fingerprint,
            "from_state": state.phase.value,
            "to_state": target.value,
            "event_class": _event_class(state.phase, target).value,
            "previous_event_fingerprint": state.journal_head_fingerprint,
            "timestamp_utc": timestamp_utc,
            "pipeline_key": pipeline_key,
            "failed_pipeline_key": failed_pipeline_key,
            "failed_phase": None if failed_phase is None else failed_phase.value,
            "failure_mutation_boundary": boundary,
            "cleanup_proof": None if cleanup_proof is None else cleanup_proof.to_mapping(),
            "evidence_fingerprints": list(fingerprints),
            "primary_failure_code": (
                None if primary_failure_code is None else primary_failure_code.value
            ),
            "cleanup_failure_code": (
                None if cleanup_failure_code is None else cleanup_failure_code.value
            ),
        }
        value["event_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8RehearsalJournalEventV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        sequence = _integer(value["sequence"], minimum=1)
        source = _enum(WP8RehearsalPhase, value["from_state"])
        target = _enum(WP8RehearsalPhase, value["to_state"])
        validate_wp8_transition(source, target)
        event_class = _enum(WP8EventClass, value["event_class"])
        if event_class is not _event_class(source, target):
            _fail()
        previous = None if value["previous_event_fingerprint"] is None else _sha256(
            value["previous_event_fingerprint"]
        )
        if (sequence == 1) != (previous is None):
            _fail()
        pipeline = value["pipeline_key"]
        expected_pipeline = _service_pipeline_for_transition(source, target)
        if pipeline is not None and pipeline not in WP8_CANONICAL_PIPELINE_KEYS:
            _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
        if pipeline != expected_pipeline:
            _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
        raw_fingerprints = value["evidence_fingerprints"]
        if not isinstance(raw_fingerprints, (list, tuple)):
            _fail()
        fingerprints = tuple(sorted(_sha256(item) for item in raw_fingerprints))
        if len(fingerprints) != len(set(fingerprints)) or tuple(raw_fingerprints) != fingerprints:
            _fail()
        primary = None if value["primary_failure_code"] is None else _enum(
            WP8FailureCode, value["primary_failure_code"]
        )
        cleanup = None if value["cleanup_failure_code"] is None else _enum(
            WP8FailureCode, value["cleanup_failure_code"]
        )
        failure_target = target in {
            WP8RehearsalPhase.FAILED,
            WP8RehearsalPhase.ABORTED,
            WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
        }
        if failure_target != (primary is not None):
            _fail()
        if primary is not None and primary not in OPERATION_FAILURE_CODES:
            _fail()
        if (target is WP8RehearsalPhase.ABORT_NOT_CONFIRMED) != (
            cleanup is WP8FailureCode.CLEANUP_FAILED
        ):
            _fail()
        if target is not WP8RehearsalPhase.ABORT_NOT_CONFIRMED and cleanup is not None:
            _fail()
        failed_phase, failed_pipeline, boundary = _failure_provenance(
            primary, value["failed_phase"], value["failed_pipeline_key"],
            value["failure_mutation_boundary"],
        )
        if failure_target and source is not WP8RehearsalPhase.ABORT_NOT_CONFIRMED:
            if failed_phase is not source:
                _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        if failure_target and (target is WP8RehearsalPhase.FAILED) != (boundary == "PRE_MUTATION"):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        cleanup_proof = None if value["cleanup_proof"] is None else WP8CleanupProofV1.from_mapping(
            value["cleanup_proof"]
        )
        requires_cleanup = target in {
            WP8RehearsalPhase.ABORTED, WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
            WP8RehearsalPhase.SERVICES_STOPPED, WP8RehearsalPhase.REHEARSAL_COMPLETE,
        }
        if requires_cleanup != (cleanup_proof is not None):
            _fail(WP8FailureCode.CLEANUP_FAILED)
        if cleanup_proof is not None:
            if (
                (cleanup_proof.rehearsal_operation_id, cleanup_proof.candidate_sha,
                 cleanup_proof.phase_a_context_fingerprint)
                != (value["operation_id"], value["candidate_sha"], value["phase_a_context_fingerprint"])
                or cleanup_proof.cleanup_proof_fingerprint not in fingerprints
                or (cleanup_proof.result is WP8CleanupResult.FAIL)
                != (target is WP8RehearsalPhase.ABORT_NOT_CONFIRMED)
            ):
                _fail(WP8FailureCode.CLEANUP_FAILED)
        event_fingerprint = _sha256(value["event_fingerprint"])
        if event_fingerprint != _fingerprint_without(value, "event_fingerprint"):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            sequence,
            _canonical_uuid(value["operation_id"]),
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _sha256(value["authorization_fingerprint"]),
            source,
            target,
            event_class,
            previous,
            _timestamp(value["timestamp_utc"]),
            pipeline,
            failed_pipeline,
            failed_phase,
            boundary,
            cleanup_proof,
            fingerprints,
            primary,
            cleanup,
            event_fingerprint,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "sequence": self.sequence,
            "operation_id": self.operation_id,
            "candidate_sha": self.candidate_sha,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "authorization_fingerprint": self.authorization_fingerprint,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "event_class": self.event_class.value,
            "previous_event_fingerprint": self.previous_event_fingerprint,
            "timestamp_utc": self.timestamp_utc,
            "pipeline_key": self.pipeline_key,
            "failed_pipeline_key": self.failed_pipeline_key,
            "failed_phase": None if self.failed_phase is None else self.failed_phase.value,
            "failure_mutation_boundary": self.failure_mutation_boundary,
            "cleanup_proof": None if self.cleanup_proof is None else self.cleanup_proof.to_mapping(),
            "evidence_fingerprints": list(self.evidence_fingerprints),
            "primary_failure_code": (
                None if self.primary_failure_code is None
                else self.primary_failure_code.value
            ),
            "cleanup_failure_code": (
                None if self.cleanup_failure_code is None
                else self.cleanup_failure_code.value
            ),
            "event_fingerprint": self.event_fingerprint,
        }


def transition_rehearsal_state(
    state: WP8RehearsalStateV1,
    target: WP8RehearsalPhase,
    *,
    sequence: int,
    timestamp_utc: str,
    runtime_ledger_fingerprint: str | None = None,
    invariant_proof_fingerprint: str | None = None,
    cleanup_proof: WP8CleanupProofV1 | None = None,
    primary_failure_code: WP8FailureCode | None = None,
    cleanup_failure_code: WP8FailureCode | None = None,
    failed_pipeline_key: str | None = None,
    evidence_fingerprints: Sequence[str] = (),
) -> tuple[WP8RehearsalStateV1, WP8RehearsalJournalEventV1]:
    state = WP8RehearsalStateV1.from_mapping(state.to_mapping())
    target = _enum(WP8RehearsalPhase, target)
    validate_wp8_transition(state.phase, target)
    timestamp = _timestamp(timestamp_utc)
    if timestamp < state.updated_at_utc:
        _fail()
    primary = None if primary_failure_code is None else _enum(WP8FailureCode, primary_failure_code)
    cleanup_failure = None if cleanup_failure_code is None else _enum(WP8FailureCode, cleanup_failure_code)
    retry = state.phase is WP8RehearsalPhase.ABORT_NOT_CONFIRMED
    if retry:
        # A retry can change cleanup evidence, never original failure or
        # previously verified runtime/invariant proof, and cannot replay B.
        if (
            primary is not None and primary is not state.primary_failure_code
            or failed_pipeline_key is not None and failed_pipeline_key != state.failed_pipeline_key
            or runtime_ledger_fingerprint is not None
            or invariant_proof_fingerprint is not None
            or evidence_fingerprints
        ):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        primary = state.primary_failure_code
        failed_pipeline_key = state.failed_pipeline_key
    failed_phase = state.failed_phase
    boundary = state.failure_mutation_boundary
    if target in FAILURE_PHASES and not retry:
        failed_phase = state.phase
        boundary = "PRE_MUTATION" if state.phase in PRE_MUTATION_PHASES else "POST_MUTATION"
        expected_pipeline = _service_pipeline_for_transition(state.phase, state.phase)
        if failed_pipeline_key is None:
            failed_pipeline_key = expected_pipeline
    if target not in FAILURE_PHASES and any(
        item is not None for item in (primary, cleanup_failure, failed_pipeline_key)
    ):
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    runtime = state.runtime_ledger_fingerprint
    invariant = state.invariant_proof_fingerprint
    if runtime_ledger_fingerprint is not None:
        runtime = _sha256(runtime_ledger_fingerprint)
    if invariant_proof_fingerprint is not None:
        invariant = _sha256(invariant_proof_fingerprint)
    if cleanup_proof is not None:
        cleanup_proof = WP8CleanupProofV1.from_mapping(cleanup_proof.to_mapping())
    elif target is WP8RehearsalPhase.REHEARSAL_COMPLETE:
        cleanup_proof = state.cleanup_proof
    # Aborts and cleanup retries require a newly supplied exact proof, never
    # infer success from a stale hash or from clearing a failure code.
    cleanup = None if cleanup_proof is None else cleanup_proof.cleanup_proof_fingerprint
    combined_evidence = tuple(sorted(set(
        tuple(evidence_fingerprints) + tuple(
            item for item in (runtime, invariant, cleanup) if item is not None
        )
    )))
    event = WP8RehearsalJournalEventV1.build(
        sequence=sequence,
        state=state,
        target=target,
        timestamp_utc=timestamp,
        evidence_fingerprints=combined_evidence,
        primary_failure_code=primary,
        cleanup_failure_code=cleanup_failure,
        failed_pipeline_key=failed_pipeline_key,
        cleanup_proof=cleanup_proof,
    )
    value = {
        **state.to_mapping(),
        "phase": target.value,
        "updated_at_utc": timestamp,
        "runtime_ledger_fingerprint": runtime,
        "invariant_proof_fingerprint": invariant,
        "cleanup_proof_fingerprint": cleanup,
        "cleanup_proof": None if cleanup_proof is None else cleanup_proof.to_mapping(),
        "primary_failure_code": None if primary is None else primary.value,
        "cleanup_failure_code": None if cleanup_failure is None else cleanup_failure.value,
        "failed_pipeline_key": failed_pipeline_key,
        "failed_phase": None if failed_phase is None else failed_phase.value,
        "failure_mutation_boundary": boundary,
        "journal_head_fingerprint": event.event_fingerprint,
    }
    value["state_fingerprint"] = _fingerprint_without(value, "state_fingerprint")
    return WP8RehearsalStateV1.from_mapping(value), event


def validate_rehearsal_journal_chain(
    events: Sequence[WP8RehearsalJournalEventV1],
    state: WP8RehearsalStateV1,
) -> bool:
    if not isinstance(events, (list, tuple)) or not events:
        _fail()
    normalized = tuple(
        WP8RehearsalJournalEventV1.from_mapping(event.to_mapping())
        for event in events
    )
    state = WP8RehearsalStateV1.from_mapping(state.to_mapping())
    first = normalized[0]
    if first.sequence != 1 or first.from_state is not WP8RehearsalPhase.NEW:
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    previous: WP8RehearsalJournalEventV1 | None = None
    first_failure: tuple[Any, ...] | None = None
    cumulative_evidence: set[str] = set()
    for expected_sequence, event in enumerate(normalized, start=1):
        if (
            event.sequence != expected_sequence
            or event.operation_id != state.operation_id
            or event.candidate_sha != state.candidate_sha
            or event.phase_a_context_fingerprint != state.phase_a_context_fingerprint
            or event.authorization_fingerprint != state.authorization_fingerprint
        ):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        if event.timestamp_utc < state.started_at_utc:
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        if event.primary_failure_code is not None:
            provenance = (
                event.primary_failure_code, event.failed_phase,
                event.failed_pipeline_key, event.failure_mutation_boundary,
            )
            if first_failure is None:
                first_failure = provenance
            elif provenance != first_failure:
                _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        if previous is not None and (
            event.previous_event_fingerprint != previous.event_fingerprint
            or event.from_state is not previous.to_state
            or event.timestamp_utc < previous.timestamp_utc
        ):
            _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
        cumulative_evidence.update(event.evidence_fingerprints)
        previous = event
    final = normalized[-1]
    if (
        final.to_state is not state.phase
        or final.timestamp_utc != state.updated_at_utc
        or final.event_fingerprint != state.journal_head_fingerprint
        or final.primary_failure_code is not state.primary_failure_code
        or final.cleanup_failure_code is not state.cleanup_failure_code
        or final.failed_pipeline_key != state.failed_pipeline_key
        or final.failed_phase is not state.failed_phase
        or final.failure_mutation_boundary != state.failure_mutation_boundary
        or final.cleanup_proof != state.cleanup_proof
        or any(
            fingerprint is not None and fingerprint not in cumulative_evidence
            for fingerprint in (
                state.runtime_ledger_fingerprint,
                state.invariant_proof_fingerprint,
                state.cleanup_proof_fingerprint,
            )
        )
    ):
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    return True


@dataclass(frozen=True, slots=True, order=True)
class WP8PipelineRunProofV1:
    pipeline_key: str
    pipeline_run_id: str
    status: str
    service_result_fingerprint: str
    business_effect_fingerprint: str
    completed_enrichment_count: int
    current_statement_count: int

    FIELDS = frozenset({
        "pipeline_key", "pipeline_run_id", "status",
        "service_result_fingerprint", "business_effect_fingerprint",
        "completed_enrichment_count", "current_statement_count",
    })

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8PipelineRunProofV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        pipeline = _safe_text(value["pipeline_key"])
        if pipeline not in WP8_CANONICAL_PIPELINE_KEYS:
            _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
        if value["status"] != "COMPLETED":
            _fail(WP8FailureCode.RUNTIME_LEDGER_INVALID)
        return cls(
            pipeline,
            _canonical_uuid(value["pipeline_run_id"]),
            "COMPLETED",
            _sha256(value["service_result_fingerprint"]),
            _sha256(value["business_effect_fingerprint"]),
            _integer(value["completed_enrichment_count"]),
            _integer(value["current_statement_count"]),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "pipeline_key": self.pipeline_key,
            "pipeline_run_id": self.pipeline_run_id,
            "status": self.status,
            "service_result_fingerprint": self.service_result_fingerprint,
            "business_effect_fingerprint": self.business_effect_fingerprint,
            "completed_enrichment_count": self.completed_enrichment_count,
            "current_statement_count": self.current_statement_count,
        }


@dataclass(frozen=True, slots=True)
class WP8RuntimeLedgerProofV1:
    candidate_sha: str
    phase_a_context_fingerprint: str
    rehearsal_operation_id: str
    runtime_boundary_fingerprint: str
    pipeline_records: tuple[WP8PipelineRunProofV1, ...]
    new_pipeline_run_count: int
    unique_run_count: int
    pipeline_set_fingerprint: str
    runtime_pipeline_coverage: str
    failed_new_run_count: int
    running_new_run_count: int
    unknown_new_run_count: int
    runtime_ledger_fingerprint: str

    FIELDS = frozenset({
        "version", "candidate_sha", "phase_a_context_fingerprint",
        "rehearsal_operation_id", "runtime_boundary_fingerprint",
        "pipeline_records", "new_pipeline_run_count", "unique_run_count",
        "pipeline_set_fingerprint", "runtime_pipeline_coverage",
        "failed_new_run_count", "running_new_run_count",
        "unknown_new_run_count", "runtime_ledger_fingerprint",
    })

    @classmethod
    def build(
        cls,
        *,
        candidate_sha: str,
        phase_a_context_fingerprint: str,
        rehearsal_operation_id: str,
        runtime_boundary_fingerprint: str,
        pipeline_records: Sequence[WP8PipelineRunProofV1],
    ) -> "WP8RuntimeLedgerProofV1":
        records = tuple(pipeline_records)
        value: dict[str, Any] = {
            "version": 1,
            "candidate_sha": candidate_sha,
            "phase_a_context_fingerprint": phase_a_context_fingerprint,
            "rehearsal_operation_id": rehearsal_operation_id,
            "runtime_boundary_fingerprint": runtime_boundary_fingerprint,
            "pipeline_records": [record.to_mapping() for record in records],
            "new_pipeline_run_count": 6,
            "unique_run_count": 6,
            "pipeline_set_fingerprint": WP8_CANONICAL_PIPELINE_SET_FINGERPRINT,
            "runtime_pipeline_coverage": "6/6",
            "failed_new_run_count": 0,
            "running_new_run_count": 0,
            "unknown_new_run_count": 0,
        }
        value["runtime_ledger_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8RuntimeLedgerProofV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        raw_records = value["pipeline_records"]
        if not isinstance(raw_records, (list, tuple)):
            _fail()
        records = tuple(WP8PipelineRunProofV1.from_mapping(item) for item in raw_records)
        if (
            tuple(record.pipeline_key for record in records)
            != WP8_CANONICAL_PIPELINE_KEYS
            or len({record.pipeline_run_id for record in records}) != 6
            or _integer(value["new_pipeline_run_count"]) != 6
            or _integer(value["unique_run_count"]) != 6
            or _sha256(value["pipeline_set_fingerprint"])
            != WP8_CANONICAL_PIPELINE_SET_FINGERPRINT
            or value["runtime_pipeline_coverage"] != "6/6"
            or any(_integer(value[field]) != 0 for field in (
                "failed_new_run_count", "running_new_run_count",
                "unknown_new_run_count",
            ))
        ):
            _fail(WP8FailureCode.RUNTIME_LEDGER_INVALID)
        fingerprint = _sha256(value["runtime_ledger_fingerprint"])
        if fingerprint != _fingerprint_without(value, "runtime_ledger_fingerprint"):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _canonical_uuid(value["rehearsal_operation_id"]),
            _sha256(value["runtime_boundary_fingerprint"]),
            records,
            6,
            6,
            WP8_CANONICAL_PIPELINE_SET_FINGERPRINT,
            "6/6",
            0,
            0,
            0,
            fingerprint,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "candidate_sha": self.candidate_sha,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "rehearsal_operation_id": self.rehearsal_operation_id,
            "runtime_boundary_fingerprint": self.runtime_boundary_fingerprint,
            "pipeline_records": [record.to_mapping() for record in self.pipeline_records],
            "new_pipeline_run_count": self.new_pipeline_run_count,
            "unique_run_count": self.unique_run_count,
            "pipeline_set_fingerprint": self.pipeline_set_fingerprint,
            "runtime_pipeline_coverage": self.runtime_pipeline_coverage,
            "failed_new_run_count": self.failed_new_run_count,
            "running_new_run_count": self.running_new_run_count,
            "unknown_new_run_count": self.unknown_new_run_count,
            "runtime_ledger_fingerprint": self.runtime_ledger_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class WP8InvariantProofV1:
    candidate_sha: str
    phase_a_context_fingerprint: str
    phase_a_evidence_fingerprint: str
    rehearsal_operation_id: str
    before: WP8InvariantSnapshotV1
    after: WP8InvariantSnapshotV1
    invariant_proof_fingerprint: str

    FIELDS = frozenset({
        "version", "candidate_sha", "phase_a_context_fingerprint",
        "phase_a_evidence_fingerprint", "rehearsal_operation_id", "before", "after",
        "p3d_service_state", "current_state", "candidate_release_state",
        "approved_business_write_classification", "invariant_result",
        "invariant_proof_fingerprint",
    })

    @classmethod
    def build(
        cls,
        evidence: WP8PhaseAEvidenceV1,
        *,
        rehearsal_operation_id: str,
        before: WP8InvariantSnapshotV1,
        after: WP8InvariantSnapshotV1,
    ) -> "WP8InvariantProofV1":
        evidence = WP8PhaseAEvidenceV1.from_mapping(evidence.to_mapping())
        before = WP8InvariantSnapshotV1.from_mapping(before.to_mapping())
        after = WP8InvariantSnapshotV1.from_mapping(after.to_mapping())
        # Do not manufacture final observations by copying A fields. Both
        # independently observed snapshots must be supplied and baseline must
        # equal the exact reviewed, authorized Phase A snapshot.
        if before != evidence.invariant_baseline:
            _fail(WP8FailureCode.INVARIANT_FAILED)
        value: dict[str, Any] = {
            "version": 1,
            "candidate_sha": evidence.candidate_sha,
            "phase_a_context_fingerprint": evidence.phase_a_context_fingerprint,
            "phase_a_evidence_fingerprint": evidence.phase_a_evidence_fingerprint,
            "rehearsal_operation_id": rehearsal_operation_id,
            "before": before.to_mapping(),
            "after": after.to_mapping(),
            "p3d_service_state": "INACTIVE",
            "current_state": "EXACT_CANDIDATE",
            "candidate_release_state": "EXACT_IMMUTABLE",
            "approved_business_write_classification": "EXPECTED_ENRICHMENT_ONLY",
            "invariant_result": "PASS",
        }
        value["invariant_proof_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8InvariantProofV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        fixed = {
            "p3d_service_state": "INACTIVE",
            "current_state": "EXACT_CANDIDATE",
            "candidate_release_state": "EXACT_IMMUTABLE",
            "approved_business_write_classification": "EXPECTED_ENRICHMENT_ONLY",
            "invariant_result": "PASS",
        }
        if any(value[name] != expected for name, expected in fixed.items()):
            _fail(WP8FailureCode.INVARIANT_FAILED)
        before = WP8InvariantSnapshotV1.from_mapping(value["before"])
        after = WP8InvariantSnapshotV1.from_mapping(value["after"])
        if before != after:
            _fail(WP8FailureCode.INVARIANT_FAILED)
        fingerprint = _sha256(value["invariant_proof_fingerprint"])
        if fingerprint != _fingerprint_without(value, "invariant_proof_fingerprint"):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _sha256(value["phase_a_evidence_fingerprint"]),
            _canonical_uuid(value["rehearsal_operation_id"]),
            before, after, fingerprint,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "candidate_sha": self.candidate_sha,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "phase_a_evidence_fingerprint": self.phase_a_evidence_fingerprint,
            "rehearsal_operation_id": self.rehearsal_operation_id,
            "before": self.before.to_mapping(),
            "after": self.after.to_mapping(),
            "p3d_service_state": "INACTIVE",
            "current_state": "EXACT_CANDIDATE",
            "candidate_release_state": "EXACT_IMMUTABLE",
            "approved_business_write_classification": "EXPECTED_ENRICHMENT_ONLY",
            "invariant_result": "PASS",
            "invariant_proof_fingerprint": self.invariant_proof_fingerprint,
        }


class WP8CleanupResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class WP8CleanupProofV1:
    rehearsal_operation_id: str
    candidate_sha: str
    phase_a_context_fingerprint: str
    stop_attempted_pipeline_keys: tuple[str, ...]
    stop_failure_count: int
    service_state: str
    timer_state: str
    p3c_state: str
    result: WP8CleanupResult
    cleanup_proof_fingerprint: str

    FIELDS = frozenset({
        "version", "rehearsal_operation_id", "candidate_sha",
        "phase_a_context_fingerprint", "stop_attempted_pipeline_keys",
        "stop_failure_count", "service_state", "timer_state", "p3c_state",
        "result", "cleanup_proof_fingerprint",
    })

    @classmethod
    def build(
        cls,
        *,
        rehearsal_operation_id: str,
        candidate_sha: str,
        phase_a_context_fingerprint: str,
        stop_failure_count: int,
        service_state: str,
        timer_state: str,
        p3c_state: str,
        result: WP8CleanupResult,
    ) -> "WP8CleanupProofV1":
        result = _enum(WP8CleanupResult, result)
        value: dict[str, Any] = {
            "version": 1,
            "rehearsal_operation_id": rehearsal_operation_id,
            "candidate_sha": candidate_sha,
            "phase_a_context_fingerprint": phase_a_context_fingerprint,
            "stop_attempted_pipeline_keys": list(WP8_CANONICAL_PIPELINE_KEYS),
            "stop_failure_count": stop_failure_count,
            "service_state": service_state,
            "timer_state": timer_state,
            "p3c_state": p3c_state,
            "result": result.value,
        }
        value["cleanup_proof_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8CleanupProofV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        result = _enum(WP8CleanupResult, value["result"])
        stop_failures = _integer(value["stop_failure_count"])
        service_state = _safe_text(value["service_state"])
        timer_state = _safe_text(value["timer_state"])
        p3c_state = _safe_text(value["p3c_state"])
        if (
            service_state not in {"INACTIVE", "NOT_CONFIRMED"}
            or timer_state not in {"DISABLED_INACTIVE", "NOT_CONFIRMED"}
            or p3c_state not in {"UNCHANGED_HEALTHY", "NOT_CONFIRMED"}
        ):
            _fail(WP8FailureCode.CLEANUP_FAILED)
        is_pass = (
            stop_failures == 0
            and service_state == "INACTIVE"
            and timer_state == "DISABLED_INACTIVE"
            and p3c_state == "UNCHANGED_HEALTHY"
        )
        if (result is WP8CleanupResult.PASS) != is_pass:
            _fail(WP8FailureCode.CLEANUP_FAILED)
        fingerprint = _sha256(value["cleanup_proof_fingerprint"])
        if fingerprint != _fingerprint_without(value, "cleanup_proof_fingerprint"):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            _canonical_uuid(value["rehearsal_operation_id"]),
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _pipelines(value["stop_attempted_pipeline_keys"]),
            stop_failures,
            service_state,
            timer_state,
            p3c_state,
            result,
            fingerprint,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "rehearsal_operation_id": self.rehearsal_operation_id,
            "candidate_sha": self.candidate_sha,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "stop_attempted_pipeline_keys": list(self.stop_attempted_pipeline_keys),
            "stop_failure_count": self.stop_failure_count,
            "service_state": self.service_state,
            "timer_state": self.timer_state,
            "p3c_state": self.p3c_state,
            "result": self.result.value,
            "cleanup_proof_fingerprint": self.cleanup_proof_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class WP8RehearsalCompleteV1:
    """B execution evidence is reviewable; independent B review is pending.

    Never denotes final WP8 lifecycle completion or mutation authorization.
    """
    rehearsal_operation_id: str
    candidate_sha: str
    phase_a_evidence_fingerprint: str
    phase_a_context_fingerprint: str
    phase_a_review_result_fingerprint: str
    authorization_fingerprint: str
    runtime_ledger_fingerprint: str
    invariant_proof_fingerprint: str
    cleanup_proof_fingerprint: str
    rehearsal_state_fingerprint: str
    journal_head_fingerprint: str
    completed_at_utc: str
    completion_fingerprint: str

    FIELDS = frozenset({
        "version", "completion_class", "rehearsal_operation_id",
        "candidate_sha", "phase_a_evidence_fingerprint",
        "phase_a_context_fingerprint", "phase_a_review_result_fingerprint",
        "authorization_fingerprint", "runtime_ledger_fingerprint",
        "invariant_proof_fingerprint", "cleanup_proof_fingerprint",
        "rehearsal_state_fingerprint", "journal_head_fingerprint",
        "runtime_pipeline_coverage", "p3d_service_state", "p3d_timer_state",
        "p3c_state", "execution_end_boundary", "wp8_final_end_boundary",
        "wp8_final_end_boundary_reached", "independent_b_review_state", "completed_at_utc",
        "completion_fingerprint",
    })

    @classmethod
    def build(
        cls,
        *,
        evidence: WP8PhaseAEvidenceV1,
        review: WP8AReviewResultV1,
        authorization: WP8RehearsalAuthorizationV1,
        runtime_ledger: WP8RuntimeLedgerProofV1,
        invariant_proof: WP8InvariantProofV1,
        cleanup_proof: WP8CleanupProofV1,
        state: WP8RehearsalStateV1,
        completed_at_utc: str,
        journal_events: Sequence[WP8RehearsalJournalEventV1],
    ) -> "WP8RehearsalCompleteV1":
        evidence = WP8PhaseAEvidenceV1.from_mapping(evidence.to_mapping())
        review = WP8AReviewResultV1.from_mapping(review.to_mapping())
        authorization = WP8RehearsalAuthorizationV1.from_mapping(
            authorization.to_mapping()
        )
        runtime_ledger = WP8RuntimeLedgerProofV1.from_mapping(
            runtime_ledger.to_mapping()
        )
        invariant_proof = WP8InvariantProofV1.from_mapping(
            invariant_proof.to_mapping()
        )
        cleanup_proof = WP8CleanupProofV1.from_mapping(cleanup_proof.to_mapping())
        state = WP8RehearsalStateV1.from_mapping(state.to_mapping())
        validate_rehearsal_journal_chain(journal_events, state)
        validate_review_result(review, evidence)
        if cleanup_proof.result is not WP8CleanupResult.PASS:
            _fail(WP8FailureCode.CLEANUP_FAILED)
        if (
            state.phase is not WP8RehearsalPhase.REHEARSAL_COMPLETE
            or state.runtime_ledger_fingerprint
            != runtime_ledger.runtime_ledger_fingerprint
            or state.invariant_proof_fingerprint
            != invariant_proof.invariant_proof_fingerprint
            or state.cleanup_proof_fingerprint
            != cleanup_proof.cleanup_proof_fingerprint
            or state.journal_head_fingerprint is None
        ):
            _fail(WP8FailureCode.CONTRACT_TRANSITION_INVALID)
        completed = _timestamp(completed_at_utc)
        if completed < state.updated_at_utc:
            _fail(WP8FailureCode.CONTRACT_TRANSITION_INVALID)
        # Revalidate the exact execution authority, not just its hash shape.
        # consumed=False here only re-evaluates the bound authorization's
        # original eligibility; it neither consumes nor reissues authority.
        validate_rehearsal_authorization(
            authorization, evidence, review, at_utc=state.started_at_utc, consumed=False
        )
        validate_rehearsal_authorization(
            authorization, evidence, review, at_utc=completed, consumed=False
        )
        if state.authorization_fingerprint != authorization.authorization_fingerprint:
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        if (
            invariant_proof.before != evidence.invariant_baseline
            or invariant_proof.phase_a_evidence_fingerprint != evidence.phase_a_evidence_fingerprint
        ):
            _fail(WP8FailureCode.INVARIANT_FAILED)
        bindings = {
            (authorization.candidate_sha, authorization.phase_a_context_fingerprint,
             authorization.rehearsal_operation_id),
            (runtime_ledger.candidate_sha, runtime_ledger.phase_a_context_fingerprint,
             runtime_ledger.rehearsal_operation_id),
            (invariant_proof.candidate_sha, invariant_proof.phase_a_context_fingerprint,
             invariant_proof.rehearsal_operation_id),
            (cleanup_proof.candidate_sha, cleanup_proof.phase_a_context_fingerprint,
             cleanup_proof.rehearsal_operation_id),
            (state.candidate_sha, state.phase_a_context_fingerprint,
             state.operation_id),
            (evidence.candidate_sha, evidence.phase_a_context_fingerprint,
             authorization.rehearsal_operation_id),
        }
        if len(bindings) != 1 or (
            authorization.phase_a_evidence_fingerprint
            != evidence.phase_a_evidence_fingerprint
            or authorization.phase_a_review_result_fingerprint
            != review.review_result_fingerprint
        ):
            _fail(WP8FailureCode.AUTHORIZATION_INVALID)
        value: dict[str, Any] = {
            "version": 1,
            "completion_class": "WP8_REHEARSAL_REVIEWABLE_COMPLETE",
            "rehearsal_operation_id": authorization.rehearsal_operation_id,
            "candidate_sha": evidence.candidate_sha,
            "phase_a_evidence_fingerprint": evidence.phase_a_evidence_fingerprint,
            "phase_a_context_fingerprint": evidence.phase_a_context_fingerprint,
            "phase_a_review_result_fingerprint": review.review_result_fingerprint,
            "authorization_fingerprint": authorization.authorization_fingerprint,
            "runtime_ledger_fingerprint": runtime_ledger.runtime_ledger_fingerprint,
            "invariant_proof_fingerprint": invariant_proof.invariant_proof_fingerprint,
            "cleanup_proof_fingerprint": cleanup_proof.cleanup_proof_fingerprint,
            "rehearsal_state_fingerprint": state.state_fingerprint,
            "journal_head_fingerprint": state.journal_head_fingerprint,
            "runtime_pipeline_coverage": "6/6",
            "p3d_service_state": "INACTIVE",
            "p3d_timer_state": "DISABLED_INACTIVE",
            "p3c_state": "UNCHANGED_HEALTHY",
            "execution_end_boundary": "B_RUNTIME_LEDGER_INVARIANT_PROOF_REVIEWABLE",
            "wp8_final_end_boundary": "AFTER_B_RUNTIME_LEDGER_INVARIANT_PROOF_AND_INDEPENDENT_REVIEW",
            "wp8_final_end_boundary_reached": False,
            "independent_b_review_state": "PENDING",
            "completed_at_utc": completed,
        }
        value["completion_fingerprint"] = contract_fingerprint(value)
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WP8RehearsalCompleteV1":
        _exact(value, cls.FIELDS)
        _reject_secret_material(value)
        _version(value["version"])
        fixed = {
            "completion_class": "WP8_REHEARSAL_REVIEWABLE_COMPLETE",
            "runtime_pipeline_coverage": "6/6",
            "p3d_service_state": "INACTIVE",
            "p3d_timer_state": "DISABLED_INACTIVE",
            "p3c_state": "UNCHANGED_HEALTHY",
            "execution_end_boundary": "B_RUNTIME_LEDGER_INVARIANT_PROOF_REVIEWABLE",
            "wp8_final_end_boundary": "AFTER_B_RUNTIME_LEDGER_INVARIANT_PROOF_AND_INDEPENDENT_REVIEW",
            "independent_b_review_state": "PENDING",
        }
        if any(value[name] != expected for name, expected in fixed.items()):
            _fail()
        if value["wp8_final_end_boundary_reached"] is not False:
            _fail()
        fingerprint = _sha256(value["completion_fingerprint"])
        if fingerprint != _fingerprint_without(value, "completion_fingerprint"):
            _fail(WP8FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            _canonical_uuid(value["rehearsal_operation_id"]),
            _git_sha(value["candidate_sha"]),
            _sha256(value["phase_a_evidence_fingerprint"]),
            _sha256(value["phase_a_context_fingerprint"]),
            _sha256(value["phase_a_review_result_fingerprint"]),
            _sha256(value["authorization_fingerprint"]),
            _sha256(value["runtime_ledger_fingerprint"]),
            _sha256(value["invariant_proof_fingerprint"]),
            _sha256(value["cleanup_proof_fingerprint"]),
            _sha256(value["rehearsal_state_fingerprint"]),
            _sha256(value["journal_head_fingerprint"]),
            _timestamp(value["completed_at_utc"]),
            fingerprint,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "completion_class": "WP8_REHEARSAL_REVIEWABLE_COMPLETE",
            "rehearsal_operation_id": self.rehearsal_operation_id,
            "candidate_sha": self.candidate_sha,
            "phase_a_evidence_fingerprint": self.phase_a_evidence_fingerprint,
            "phase_a_context_fingerprint": self.phase_a_context_fingerprint,
            "phase_a_review_result_fingerprint": self.phase_a_review_result_fingerprint,
            "authorization_fingerprint": self.authorization_fingerprint,
            "runtime_ledger_fingerprint": self.runtime_ledger_fingerprint,
            "invariant_proof_fingerprint": self.invariant_proof_fingerprint,
            "cleanup_proof_fingerprint": self.cleanup_proof_fingerprint,
            "rehearsal_state_fingerprint": self.rehearsal_state_fingerprint,
            "journal_head_fingerprint": self.journal_head_fingerprint,
            "runtime_pipeline_coverage": "6/6",
            "p3d_service_state": "INACTIVE",
            "p3d_timer_state": "DISABLED_INACTIVE",
            "p3c_state": "UNCHANGED_HEALTHY",
            "execution_end_boundary": "B_RUNTIME_LEDGER_INVARIANT_PROOF_REVIEWABLE",
            "wp8_final_end_boundary": "AFTER_B_RUNTIME_LEDGER_INVARIANT_PROOF_AND_INDEPENDENT_REVIEW",
            "wp8_final_end_boundary_reached": False,
            "independent_b_review_state": "PENDING",
            "completed_at_utc": self.completed_at_utc,
            "completion_fingerprint": self.completion_fingerprint,
        }


def validate_rehearsal_completion(
    marker: WP8RehearsalCompleteV1,
    *,
    evidence: WP8PhaseAEvidenceV1,
    review: WP8AReviewResultV1,
    authorization: WP8RehearsalAuthorizationV1,
    runtime_ledger: WP8RuntimeLedgerProofV1,
    invariant_proof: WP8InvariantProofV1,
    cleanup_proof: WP8CleanupProofV1,
    state: WP8RehearsalStateV1,
    journal_events: Sequence[WP8RehearsalJournalEventV1],
) -> bool:
    """A parsed marker's references are not independent authority.

    Consumers must resolve its protected proof objects and revalidate these
    bindings; parsing alone proves schema/hash, not observed production facts.
    """
    marker = WP8RehearsalCompleteV1.from_mapping(marker.to_mapping())
    expected = WP8RehearsalCompleteV1.build(
        evidence=evidence, review=review, authorization=authorization,
        runtime_ledger=runtime_ledger, invariant_proof=invariant_proof,
        cleanup_proof=cleanup_proof, state=state, journal_events=journal_events,
        completed_at_utc=marker.completed_at_utc,
    )
    if marker != expected:
        _fail(WP8FailureCode.PROTECTED_STATE_TAMPER)
    return True


def wp8_contract_bytes(value: Any) -> bytes:
    """Serialize only an exact WP8 type after its strict schema parser.

    Mappings must first pass the desired explicit ``Type.from_mapping``.
    No duck typing, inferred schema, subclass, or caller-defined serializer.
    """

    allowed = (
        WP8InvariantSnapshotV1, WP8PhaseAEvidenceV1, WP8AReviewResultV1,
        WP8RehearsalAuthorizationV1, WP8RehearsalStateV1,
        WP8RehearsalJournalEventV1, WP8PipelineRunProofV1,
        WP8RuntimeLedgerProofV1, WP8InvariantProofV1, WP8CleanupProofV1,
        WP8RehearsalCompleteV1,
    )
    if type(value) not in allowed:
        _fail()
    try:
        # Check nested typed boundaries before invoking their to_mapping;
        # an unknown nested duck type is not an authorized serializer either.
        nested = {
            WP8PhaseAEvidenceV1: (("invariant_baseline", WP8InvariantSnapshotV1),),
            WP8InvariantProofV1: (("before", WP8InvariantSnapshotV1), ("after", WP8InvariantSnapshotV1)),
            WP8RehearsalStateV1: (("cleanup_proof", WP8CleanupProofV1),),
            WP8RehearsalJournalEventV1: (("cleanup_proof", WP8CleanupProofV1),),
        }
        for name, expected_type in nested.get(type(value), ()):
            item = getattr(value, name)
            nullable = name == "cleanup_proof"
            if not (nullable and item is None) and type(item) is not expected_type:
                _fail()
        if type(value) is WP8RuntimeLedgerProofV1 and (
            type(value.pipeline_records) is not tuple
            or any(type(item) is not WP8PipelineRunProofV1 for item in value.pipeline_records)
        ):
            _fail()
        parsed = type(value).from_mapping(value.to_mapping())
        return canonical_json_bytes(parsed.to_mapping())
    except WP8ContractError:
        raise
    except (AttributeError, TypeError, ValueError):
        _fail()
