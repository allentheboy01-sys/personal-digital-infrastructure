from __future__ import annotations

import ast
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint
from pdi.production_ops.contracts import HEAD as EXPECTED_ALEMBIC_REVISION
from pdi.production_ops.p3d_wp8_contracts import (
    ALLOWED_TRANSITIONS,
    NORMAL_PHASES,
    WP8_CANONICAL_PIPELINE_KEYS,
    WP8AReviewResultV1,
    WP8CleanupProofV1,
    WP8CleanupResult,
    WP8ContractError,
    WP8FailureCode,
    WP8InvariantProofV1,
    WP8InvariantSnapshotV1,
    WP8PhaseAEvidenceV1,
    WP8PipelineRunProofV1,
    WP8RehearsalAuthorizationV1,
    WP8RehearsalCompleteV1,
    WP8RehearsalJournalEventV1,
    WP8RehearsalPhase,
    WP8RehearsalStateV1,
    WP8RuntimeLedgerProofV1,
    transition_rehearsal_state,
    validate_rehearsal_authorization,
    validate_rehearsal_completion,
    validate_rehearsal_journal_chain,
    validate_review_result,
    validate_wp8_transition,
    wp8_contract_bytes,
)


CANDIDATE = "a" * 40
ROLLBACK = "b" * 40
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
H8 = "8" * 64
H9 = "9" * 64
HA = "a" * 64
HB = "b" * 64
HC = "c" * 64
OPERATION = "11111111-2222-4333-8444-555555555555"
GATE_A = "21111111-2222-4333-8444-555555555555"
GATE_B = "31111111-2222-4333-8444-555555555555"
GATE_C = "41111111-2222-4333-8444-555555555555"


def timestamp(index: int) -> str:
    return f"2026-10-05T00:{index:02d}:00Z"


def phase_a() -> WP8PhaseAEvidenceV1:
    return WP8PhaseAEvidenceV1.build(
        candidate_sha=CANDIDATE,
        rollback_source_sha=ROLLBACK,
        gate_a_operation_id=GATE_A,
        gate_a_authority_binding_fingerprint=H1,
        gate_b_operation_id=GATE_B,
        gate_b_authority_binding_fingerprint=H2,
        gate_c_operation_id=GATE_C,
        gate_c_marker_fingerprint=H3,
        gate_c_authority_binding_fingerprint=H4,
        wp6_context_fingerprint=H5,
        db_identity_fingerprint=H6,
        enabled_scope_count=2,
        enabled_scope_fingerprint=H7,
        unit_profile_asset_fingerprint=H8,
        p3c_state_fingerprint=H9,
        p3c_systemd_fingerprint=HA,
        protected_environment_fingerprint=HB,
        registry_fingerprint=HC,
        invariant_baseline=snapshot(),
    )


def review(evidence: WP8PhaseAEvidenceV1 | None = None) -> WP8AReviewResultV1:
    return WP8AReviewResultV1.build(
        evidence or phase_a(),
        reviewed_at_utc=timestamp(1),
        review_record_sha256=H5,
    )


def authorization(
    evidence: WP8PhaseAEvidenceV1 | None = None,
    reviewed: WP8AReviewResultV1 | None = None,
) -> WP8RehearsalAuthorizationV1:
    evidence = evidence or phase_a()
    reviewed = reviewed or review(evidence)
    return WP8RehearsalAuthorizationV1.build(
        evidence,
        reviewed,
        rehearsal_operation_id=OPERATION,
        issued_at_utc=timestamp(2),
        not_before_utc=timestamp(3),
        expires_at_utc=timestamp(59),
    )


def initial_state(
    evidence: WP8PhaseAEvidenceV1 | None = None,
    authorized: WP8RehearsalAuthorizationV1 | None = None,
) -> WP8RehearsalStateV1:
    evidence = evidence or phase_a()
    authorized = authorized or authorization(evidence)
    return WP8RehearsalStateV1.new(
        operation_id=authorized.rehearsal_operation_id,
        candidate_sha=evidence.candidate_sha,
        phase_a_context_fingerprint=evidence.phase_a_context_fingerprint,
        authorization_fingerprint=authorized.authorization_fingerprint,
        started_at_utc=timestamp(4),
    )


def pipeline_records() -> tuple[WP8PipelineRunProofV1, ...]:
    return tuple(
        WP8PipelineRunProofV1.from_mapping({
            "pipeline_key": key,
            "pipeline_run_id": f"{index}1111111-2222-4333-8444-555555555555",
            "status": "COMPLETED",
            "service_result_fingerprint": H1,
            "business_effect_fingerprint": H2,
            "completed_enrichment_count": index,
            "current_statement_count": index,
        })
        for index, key in enumerate(WP8_CANONICAL_PIPELINE_KEYS, start=1)
    )


def runtime(evidence: WP8PhaseAEvidenceV1 | None = None) -> WP8RuntimeLedgerProofV1:
    evidence = evidence or phase_a()
    return WP8RuntimeLedgerProofV1.build(
        candidate_sha=evidence.candidate_sha,
        phase_a_context_fingerprint=evidence.phase_a_context_fingerprint,
        rehearsal_operation_id=OPERATION,
        runtime_boundary_fingerprint=H3,
        pipeline_records=pipeline_records(),
    )


def snapshot() -> WP8InvariantSnapshotV1:
    return WP8InvariantSnapshotV1.from_mapping({
        "version": 1,
        "schema_fingerprint": H1,
        "migration_tree_fingerprint": H2,
        "alembic_revision": EXPECTED_ALEMBIC_REVISION,
        "principal_route_fingerprint": H5,
        "db_identity_fingerprint": H6,
        "provider_identity_fingerprint": H2,
        "enabled_scope_fingerprint": H7,
        "source_identity_fingerprint": H3,
        "sync_state_fingerprint": H4,
        "protected_environment_fingerprint": HB,
        "registry_fingerprint": HC,
        "unit_profile_asset_fingerprint": H8,
        "gate_a_authority_binding_fingerprint": H1,
        "gate_b_authority_binding_fingerprint": H2,
        "gate_c_authority_binding_fingerprint": H4,
        "p3c_state_fingerprint": H9,
        "p3c_systemd_fingerprint": HA,
        "p3d_timer_state": "DISABLED_INACTIVE",
        "legacy_writer_state": "DISABLED_INACTIVE",
        "legacy_enrichment_state": "DISABLED_INACTIVE",
        "gmail_state": "DISABLED",
        "integration_test_state": "DISABLED",
    })


def invariant(evidence: WP8PhaseAEvidenceV1 | None = None) -> WP8InvariantProofV1:
    evidence = evidence or phase_a()
    return WP8InvariantProofV1.build(
        evidence,
        rehearsal_operation_id=OPERATION,
        before=evidence.invariant_baseline,
        after=WP8InvariantSnapshotV1.from_mapping(evidence.invariant_baseline.to_mapping()),
    )


def cleanup(
    evidence: WP8PhaseAEvidenceV1 | None = None,
    *,
    result: WP8CleanupResult = WP8CleanupResult.PASS,
) -> WP8CleanupProofV1:
    evidence = evidence or phase_a()
    return WP8CleanupProofV1.build(
        rehearsal_operation_id=OPERATION,
        candidate_sha=evidence.candidate_sha,
        phase_a_context_fingerprint=evidence.phase_a_context_fingerprint,
        stop_failure_count=0 if result is WP8CleanupResult.PASS else 1,
        service_state="INACTIVE" if result is WP8CleanupResult.PASS else "NOT_CONFIRMED",
        timer_state=(
            "DISABLED_INACTIVE"
            if result is WP8CleanupResult.PASS
            else "NOT_CONFIRMED"
        ),
        p3c_state="UNCHANGED_HEALTHY",
        result=result,
    )


def refingerprint(mapping: dict[str, object], field: str) -> None:
    mapping[field] = contract_fingerprint({
        key: value for key, value in mapping.items() if key != field
    })


def stopped_state(
    evidence: WP8PhaseAEvidenceV1 | None = None,
) -> tuple[WP8RehearsalStateV1, tuple[WP8RehearsalJournalEventV1, ...]]:
    evidence = evidence or phase_a()
    state = initial_state(evidence)
    runtime_proof = runtime(evidence)
    invariant_proof = invariant(evidence)
    cleanup_proof = cleanup(evidence)
    events: list[WP8RehearsalJournalEventV1] = []
    for sequence, target in enumerate(NORMAL_PHASES[1:-1], start=1):
        kwargs: dict[str, object] = {}
        if target is WP8RehearsalPhase.RUNTIME_LEDGER_VERIFIED:
            kwargs["runtime_ledger_fingerprint"] = runtime_proof.runtime_ledger_fingerprint
        if target is WP8RehearsalPhase.INVARIANTS_VERIFIED:
            kwargs["invariant_proof_fingerprint"] = invariant_proof.invariant_proof_fingerprint
        if target is WP8RehearsalPhase.SERVICES_STOPPED:
            kwargs["cleanup_proof"] = cleanup_proof
        state, event = transition_rehearsal_state(
            state,
            target,
            sequence=sequence,
            timestamp_utc=timestamp(sequence + 4),
            **kwargs,
        )
        events.append(event)
    return state, tuple(events)


def complete_state(
    evidence: WP8PhaseAEvidenceV1 | None = None,
) -> tuple[WP8RehearsalStateV1, tuple[WP8RehearsalJournalEventV1, ...]]:
    state, events = stopped_state(evidence)
    state, event = transition_rehearsal_state(
        state,
        WP8RehearsalPhase.REHEARSAL_COMPLETE,
        sequence=len(events) + 1,
        timestamp_utc=timestamp(len(events) + 5),
    )
    return state, (*events, event)


def test_phase_a_contract_is_deterministic_and_exact() -> None:
    first = phase_a()
    second = phase_a()
    assert first == second
    assert wp8_contract_bytes(first) == wp8_contract_bytes(second)
    assert first.runtime_pipeline_coverage == "0/6"
    assert first.canonical_pipeline_keys == WP8_CANONICAL_PIPELINE_KEYS


@pytest.mark.parametrize("mutation", ["missing", "extra", "version"])
def test_phase_a_rejects_field_and_version_drift(mutation: str) -> None:
    mapping = phase_a().to_mapping()
    if mutation == "missing":
        mapping.pop("registry_fingerprint")
    elif mutation == "extra":
        mapping["unexpected"] = "PASS"
    else:
        mapping["version"] = 2
    with pytest.raises(WP8ContractError):
        WP8PhaseAEvidenceV1.from_mapping(mapping)


@pytest.mark.parametrize("candidate", ["A" * 40, "a" * 39, "a" * 64])
def test_phase_a_rejects_noncanonical_git_sha(candidate: str) -> None:
    mapping = phase_a().to_mapping()
    mapping["candidate_sha"] = candidate
    with pytest.raises(WP8ContractError):
        WP8PhaseAEvidenceV1.from_mapping(mapping)


def test_phase_a_rejects_malformed_hash_uuid_and_self_fingerprint() -> None:
    for field, value in (
        ("registry_fingerprint", "F" * 64),
        ("gate_a_operation_id", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"),
        ("phase_a_evidence_fingerprint", H1),
    ):
        mapping = phase_a().to_mapping()
        mapping[field] = value
        with pytest.raises(WP8ContractError):
            WP8PhaseAEvidenceV1.from_mapping(mapping)


@pytest.mark.parametrize(
    "pipelines",
    [
        WP8_CANONICAL_PIPELINE_KEYS[:-1],
        WP8_CANONICAL_PIPELINE_KEYS + (WP8_CANONICAL_PIPELINE_KEYS[-1],),
        tuple(reversed(WP8_CANONICAL_PIPELINE_KEYS)),
        WP8_CANONICAL_PIPELINE_KEYS + ("enrichment.gmail_metadata",),
        WP8_CANONICAL_PIPELINE_KEYS + ("integration-test",),
    ],
)
def test_exact_pipeline_authority_rejects_drift(pipelines: tuple[str, ...]) -> None:
    mapping = phase_a().to_mapping()
    mapping["canonical_pipeline_keys"] = list(pipelines)
    refingerprint(mapping, "phase_a_context_fingerprint")
    refingerprint(mapping, "phase_a_evidence_fingerprint")
    with pytest.raises(WP8ContractError) as caught:
        WP8PhaseAEvidenceV1.from_mapping(mapping)
    assert caught.value.code is WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID


def test_secret_and_url_values_are_rejected_without_echo() -> None:
    mapping = phase_a().to_mapping()
    mapping["current_state"] = "contains-OAUTH-secret"
    with pytest.raises(WP8ContractError) as caught:
        WP8PhaseAEvidenceV1.from_mapping(mapping)
    assert caught.value.code is WP8FailureCode.CONTRACT_SECRET_MATERIAL
    assert "OAUTH" not in str(caught.value)
    mapping = phase_a().to_mapping()
    mapping["current_state"] = "postgresql://example"
    with pytest.raises(WP8ContractError):
        WP8PhaseAEvidenceV1.from_mapping(mapping)


def test_review_and_authorization_bind_exact_phase_a() -> None:
    evidence = phase_a()
    reviewed = review(evidence)
    authorized = authorization(evidence, reviewed)
    assert validate_review_result(reviewed, evidence)
    assert validate_rehearsal_authorization(
        authorized, evidence, reviewed, at_utc=timestamp(4), consumed=False
    )
    assert authorized.single_use is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_sha", "c" * 40),
        ("phase_a_evidence_fingerprint", H1),
        ("phase_a_context_fingerprint", H2),
        ("gate_b_authority_binding_fingerprint", H3),
    ],
)
def test_authorization_rejects_wrong_phase_a_or_gate_binding(
    field: str, value: str
) -> None:
    evidence = phase_a()
    reviewed = review(evidence)
    mapping = authorization(evidence, reviewed).to_mapping()
    mapping[field] = value
    refingerprint(mapping, "authorization_fingerprint")
    parsed = WP8RehearsalAuthorizationV1.from_mapping(mapping)
    with pytest.raises(WP8ContractError) as caught:
        validate_rehearsal_authorization(
            parsed, evidence, reviewed, at_utc=timestamp(4), consumed=False
        )
    assert caught.value.code is WP8FailureCode.AUTHORIZATION_INVALID


def test_authorization_time_window_and_replay_fail_closed() -> None:
    evidence = phase_a()
    reviewed = review(evidence)
    authorized = authorization(evidence, reviewed)
    cases = (
        (timestamp(2), False, WP8FailureCode.AUTHORIZATION_NOT_YET_VALID),
        (timestamp(59), False, WP8FailureCode.AUTHORIZATION_EXPIRED),
        (timestamp(4), True, WP8FailureCode.AUTHORIZATION_REPLAY),
    )
    for at_utc, consumed, code in cases:
        with pytest.raises(WP8ContractError) as caught:
            validate_rehearsal_authorization(
                authorized, evidence, reviewed, at_utc=at_utc, consumed=consumed
            )
        assert caught.value.code is code


def test_authorization_cannot_predate_independent_review() -> None:
    evidence = phase_a()
    reviewed = review(evidence)
    with pytest.raises(WP8ContractError) as caught:
        WP8RehearsalAuthorizationV1.build(
            evidence,
            reviewed,
            rehearsal_operation_id=OPERATION,
            issued_at_utc=timestamp(0),
            not_before_utc=timestamp(2),
            expires_at_utc=timestamp(59),
        )
    assert caught.value.code is WP8FailureCode.AUTHORIZATION_INVALID


def test_non_single_use_authorization_is_rejected() -> None:
    mapping = authorization().to_mapping()
    mapping["single_use"] = False
    refingerprint(mapping, "authorization_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalAuthorizationV1.from_mapping(mapping)


def test_state_graph_allows_only_exact_normal_order() -> None:
    for source, target in zip(NORMAL_PHASES, NORMAL_PHASES[1:]):
        assert validate_wp8_transition(source, target)
    assert "ACTIVE" not in WP8RehearsalPhase.__members__
    assert "CUTOVER" not in WP8RehearsalPhase.__members__
    with pytest.raises(WP8ContractError):
        validate_wp8_transition(
            WP8RehearsalPhase.SERVICE_1_VERIFIED,
            WP8RehearsalPhase.SERVICE_3_EXECUTING,
        )
    with pytest.raises(WP8ContractError):
        validate_wp8_transition(
            WP8RehearsalPhase.REHEARSAL_COMPLETE,
            WP8RehearsalPhase.NEW,
        )


def test_pre_and_post_mutation_failure_terminals_are_distinct() -> None:
    assert WP8RehearsalPhase.FAILED in ALLOWED_TRANSITIONS[
        WP8RehearsalPhase.PRE_MUTATION_REVALIDATED
    ]
    assert WP8RehearsalPhase.FAILED not in ALLOWED_TRANSITIONS[
        WP8RehearsalPhase.CURRENT_PROMOTED
    ]
    assert WP8RehearsalPhase.ABORTED in ALLOWED_TRANSITIONS[
        WP8RehearsalPhase.CURRENT_PROMOTED
    ]


def test_abort_not_confirmed_allows_only_cleanup_recovery() -> None:
    state = initial_state()
    events: list[WP8RehearsalJournalEventV1] = []
    for sequence, target in enumerate(NORMAL_PHASES[1:5], start=1):
        state, event = transition_rehearsal_state(
            state,
            target,
            sequence=sequence,
            timestamp_utc=timestamp(sequence + 4),
        )
        events.append(event)
    failed_cleanup = cleanup(result=WP8CleanupResult.FAIL)
    state, event = transition_rehearsal_state(
        state,
        WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
        sequence=5,
        timestamp_utc=timestamp(9),
        cleanup_proof=failed_cleanup,
        primary_failure_code=WP8FailureCode.CURRENT_DRIFT,
        cleanup_failure_code=WP8FailureCode.CLEANUP_FAILED,
    )
    events.append(event)
    with pytest.raises(WP8ContractError):
        validate_wp8_transition(
            state.phase, WP8RehearsalPhase.REHEARSAL_COMPLETE
        )
    successful_cleanup = cleanup()
    state, event = transition_rehearsal_state(
        state,
        WP8RehearsalPhase.ABORTED,
        sequence=6,
        timestamp_utc=timestamp(10),
        cleanup_proof=successful_cleanup,
    )
    events.append(event)
    assert validate_rehearsal_journal_chain(tuple(events), state)
    assert state.primary_failure_code is WP8FailureCode.CURRENT_DRIFT


def test_state_rejects_proofs_before_corresponding_phase() -> None:
    state = initial_state()
    mapping = state.to_mapping()
    mapping["runtime_ledger_fingerprint"] = H1
    refingerprint(mapping, "state_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalStateV1.from_mapping(mapping)


def test_full_state_and_journal_chain_is_exact() -> None:
    state, events = stopped_state()
    assert state.phase is WP8RehearsalPhase.SERVICES_STOPPED
    assert validate_rehearsal_journal_chain(events, state)
    service_events = [event for event in events if event.pipeline_key]
    assert tuple(event.pipeline_key for event in service_events) == tuple(
        pipeline for pipeline in WP8_CANONICAL_PIPELINE_KEYS for _ in range(2)
    )


def test_journal_rejects_sequence_chain_context_and_timestamp_drift() -> None:
    state, events = stopped_state()
    with pytest.raises(WP8ContractError):
        validate_rehearsal_journal_chain(events[1:], state)
    wrong = list(events)
    mapping = wrong[3].to_mapping()
    mapping["phase_a_context_fingerprint"] = H1
    refingerprint(mapping, "event_fingerprint")
    wrong[3] = WP8RehearsalJournalEventV1.from_mapping(mapping)
    with pytest.raises(WP8ContractError):
        validate_rehearsal_journal_chain(tuple(wrong), state)
    mapping = events[1].to_mapping()
    mapping["timestamp_utc"] = timestamp(1)
    refingerprint(mapping, "event_fingerprint")
    wrong = [events[0], WP8RehearsalJournalEventV1.from_mapping(mapping), *events[2:]]
    with pytest.raises(WP8ContractError):
        validate_rehearsal_journal_chain(tuple(wrong), state)


def test_raw_failure_text_never_enters_journal() -> None:
    state = initial_state()
    with pytest.raises(WP8ContractError) as caught:
        transition_rehearsal_state(
            state,
            WP8RehearsalPhase.FAILED,
            sequence=1,
            timestamp_utc=timestamp(5),
            primary_failure_code="provider password was bad",  # type: ignore[arg-type]
        )
    assert str(caught.value) == WP8FailureCode.CONTRACT_VALUE_INVALID.value


def test_runtime_ledger_requires_exact_unique_six() -> None:
    proof = runtime()
    assert proof.runtime_pipeline_coverage == "6/6"
    assert tuple(record.pipeline_key for record in proof.pipeline_records) == (
        WP8_CANONICAL_PIPELINE_KEYS
    )
    for records in (
        pipeline_records()[:-1],
        (*pipeline_records()[:-1], pipeline_records()[0]),
        tuple(reversed(pipeline_records())),
    ):
        with pytest.raises(WP8ContractError):
            WP8RuntimeLedgerProofV1.build(
                candidate_sha=CANDIDATE,
                phase_a_context_fingerprint=phase_a().phase_a_context_fingerprint,
                rehearsal_operation_id=OPERATION,
                runtime_boundary_fingerprint=H3,
                pipeline_records=records,
            )


def test_invariant_proof_binds_phase_a_authorities() -> None:
    evidence = phase_a()
    proof = invariant(evidence)
    assert proof.before.db_identity_fingerprint == evidence.db_identity_fingerprint
    assert proof.after.protected_environment_fingerprint == evidence.protected_environment_fingerprint
    mapping = proof.to_mapping()
    mapping["after"]["gmail_state"] = "ENABLED"
    refingerprint(mapping, "invariant_proof_fingerprint")
    with pytest.raises(WP8ContractError) as caught:
        WP8InvariantProofV1.from_mapping(mapping)
    assert caught.value.code is WP8FailureCode.INVARIANT_FAILED


def test_cleanup_proof_is_exact_and_fail_closed() -> None:
    assert cleanup().result is WP8CleanupResult.PASS
    assert cleanup(result=WP8CleanupResult.FAIL).result is WP8CleanupResult.FAIL
    mapping = cleanup(result=WP8CleanupResult.FAIL).to_mapping()
    mapping["service_state"] = "raw exception text"
    refingerprint(mapping, "cleanup_proof_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8CleanupProofV1.from_mapping(mapping)


def test_completion_requires_state_runtime_invariants_and_cleanup() -> None:
    evidence = phase_a()
    reviewed = review(evidence)
    authorized = authorization(evidence, reviewed)
    runtime_proof = runtime(evidence)
    invariant_proof = invariant(evidence)
    cleanup_proof = cleanup(evidence)
    state, events = complete_state(evidence)
    marker = WP8RehearsalCompleteV1.build(
        evidence=evidence,
        review=reviewed,
        authorization=authorized,
        runtime_ledger=runtime_proof,
        invariant_proof=invariant_proof,
        cleanup_proof=cleanup_proof,
        state=state,
        completed_at_utc=timestamp(40),
        journal_events=events,
    )
    assert marker.rehearsal_state_fingerprint == state.state_fingerprint
    with pytest.raises(WP8ContractError):
        WP8RehearsalCompleteV1.build(
            evidence=evidence,
            review=reviewed,
            authorization=authorized,
            runtime_ledger=runtime_proof,
            invariant_proof=invariant_proof,
            cleanup_proof=cleanup_proof,
            state=initial_state(evidence, authorized),
            completed_at_utc=timestamp(40),
            journal_events=events,
        )


def test_completion_rejects_wrong_cleanup_and_invariant_binding() -> None:
    evidence = phase_a()
    reviewed = review(evidence)
    authorized = authorization(evidence, reviewed)
    runtime_proof = runtime(evidence)
    state, events = complete_state(evidence)
    with pytest.raises(WP8ContractError):
        WP8RehearsalCompleteV1.build(
            evidence=evidence,
            review=reviewed,
            authorization=authorized,
            runtime_ledger=runtime_proof,
            invariant_proof=invariant(evidence),
            cleanup_proof=cleanup(evidence, result=WP8CleanupResult.FAIL),
            state=state,
            completed_at_utc=timestamp(40),
            journal_events=events,
        )
    wrong_invariant = replace(
        invariant(evidence), after=replace(snapshot(), db_identity_fingerprint=H1)
    )
    with pytest.raises(WP8ContractError):
        WP8RehearsalCompleteV1.build(
            evidence=evidence,
            review=reviewed,
            authorization=authorized,
            runtime_ledger=runtime_proof,
            invariant_proof=wrong_invariant,
            cleanup_proof=cleanup(evidence),
            state=state,
            completed_at_utc=timestamp(40),
            journal_events=events,
        )


def completion_inputs() -> dict[str, object]:
    evidence = phase_a()
    state, events = complete_state(evidence)
    return {
        "evidence": evidence,
        "review": review(evidence),
        "authorization": authorization(evidence),
        "runtime_ledger": runtime(evidence),
        "invariant_proof": invariant(evidence),
        "cleanup_proof": cleanup(evidence),
        "state": state,
        "journal_events": events,
        "completed_at_utc": timestamp(40),
    }


@pytest.mark.parametrize(("field", "value"), [
    ("rollback_source_sha", "c" * 40),
    ("gate_a_authority_binding_fingerprint", HC),
    ("gate_b_authority_binding_fingerprint", HC),
    ("gate_c_authority_binding_fingerprint", HC),
    ("gate_a_operation_id", "51111111-2222-4333-8444-555555555555"),
    ("gate_b_operation_id", "51111111-2222-4333-8444-555555555555"),
    ("gate_c_operation_id", "51111111-2222-4333-8444-555555555555"),
    ("review_record_sha256", HC),
    ("phase_a_review_result_fingerprint", HC),
    ("phase_a_evidence_fingerprint", HC),
    ("candidate_sha", "c" * 40),
    ("phase_a_context_fingerprint", HC),
    ("rehearsal_operation_id", "51111111-2222-4333-8444-555555555555"),
])
def test_completion_rejects_altered_rehashed_authorization(field, value) -> None:
    inputs = completion_inputs()
    mapping = inputs["authorization"].to_mapping()
    mapping[field] = value
    refingerprint(mapping, "authorization_fingerprint")
    inputs["authorization"] = WP8RehearsalAuthorizationV1.from_mapping(mapping)
    with pytest.raises(WP8ContractError):
        WP8RehearsalCompleteV1.build(**inputs)


def test_completion_revalidates_authorization_even_after_state_journal_rehash() -> None:
    inputs = completion_inputs()
    mapping = inputs["authorization"].to_mapping()
    mapping["rollback_source_sha"] = "c" * 40
    mapping["gate_b_authority_binding_fingerprint"] = HC
    refingerprint(mapping, "authorization_fingerprint")
    authorized = WP8RehearsalAuthorizationV1.from_mapping(mapping)
    events = []
    previous = None
    for event in inputs["journal_events"]:
        changed = event.to_mapping()
        changed["authorization_fingerprint"] = authorized.authorization_fingerprint
        changed["previous_event_fingerprint"] = previous
        refingerprint(changed, "event_fingerprint")
        parsed = WP8RehearsalJournalEventV1.from_mapping(changed)
        previous = parsed.event_fingerprint
        events.append(parsed)
    state = inputs["state"].to_mapping()
    state["authorization_fingerprint"] = authorized.authorization_fingerprint
    state["journal_head_fingerprint"] = previous
    refingerprint(state, "state_fingerprint")
    parsed_state = WP8RehearsalStateV1.from_mapping(state)
    assert validate_rehearsal_journal_chain(tuple(events), parsed_state)
    inputs.update(authorization=authorized, state=parsed_state, journal_events=tuple(events))
    with pytest.raises(WP8ContractError) as caught:
        WP8RehearsalCompleteV1.build(**inputs)
    assert caught.value.code is WP8FailureCode.AUTHORIZATION_INVALID


def test_completion_state_must_bind_the_exact_otherwise_valid_authorization() -> None:
    inputs = completion_inputs()
    evidence = inputs["evidence"]
    another = WP8RehearsalAuthorizationV1.build(
        evidence, inputs["review"], rehearsal_operation_id=OPERATION,
        issued_at_utc=timestamp(3), not_before_utc=timestamp(3),
        expires_at_utc=timestamp(58),
    )
    assert validate_rehearsal_authorization(
        another, evidence, inputs["review"], at_utc=timestamp(40), consumed=False,
    )
    inputs["authorization"] = another
    with pytest.raises(WP8ContractError) as caught:
        WP8RehearsalCompleteV1.build(**inputs)
    assert caught.value.code is WP8FailureCode.AUTHORIZATION_INVALID


def test_completion_rejects_expired_execution_authority() -> None:
    inputs = completion_inputs()
    inputs["completed_at_utc"] = timestamp(59)
    with pytest.raises(WP8ContractError) as caught:
        WP8RehearsalCompleteV1.build(**inputs)
    assert caught.value.code is WP8FailureCode.AUTHORIZATION_EXPIRED


def state_prefix(target: WP8RehearsalPhase):
    state = initial_state()
    events = []
    for sequence, phase in enumerate(NORMAL_PHASES[1:], start=1):
        state, event = transition_rehearsal_state(
            state, phase, sequence=sequence, timestamp_utc=timestamp(sequence + 4),
        )
        events.append(event)
        if phase is target:
            return state, tuple(events)
    raise AssertionError("unsupported test prefix")


@pytest.mark.parametrize("phase", [
    WP8RehearsalPhase[f"SERVICE_{index}_{suffix}"]
    for index in range(1, 7) for suffix in ("EXECUTING", "VERIFIED")
])
def test_every_normal_service_prefix_roundtrips_and_validates(phase) -> None:
    state, events = state_prefix(phase)
    assert state.failed_pipeline_key is None
    assert state.failed_phase is None
    assert events[-1].failed_pipeline_key is None
    assert events[-1].pipeline_key == WP8_CANONICAL_PIPELINE_KEYS[int(phase.value[8]) - 1]
    parsed_state = WP8RehearsalStateV1.from_mapping(json.loads(wp8_contract_bytes(state)))
    parsed_events = tuple(
        WP8RehearsalJournalEventV1.from_mapping(json.loads(wp8_contract_bytes(event)))
        for event in events
    )
    assert validate_rehearsal_journal_chain(parsed_events, parsed_state)
    mapping = events[-1].to_mapping()
    mapping["pipeline_key"] = WP8_CANONICAL_PIPELINE_KEYS[int(phase.value[8]) % 6]
    refingerprint(mapping, "event_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalJournalEventV1.from_mapping(mapping)
    mapping = state.to_mapping()
    mapping["failed_pipeline_key"] = events[-1].pipeline_key
    refingerprint(mapping, "state_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalStateV1.from_mapping(mapping)


def unconfirmed_cleanup():
    state, events = state_prefix(WP8RehearsalPhase.SERVICE_1_EXECUTING)
    state, event = transition_rehearsal_state(
        state, WP8RehearsalPhase.ABORT_NOT_CONFIRMED,
        sequence=len(events) + 1, timestamp_utc=timestamp(30),
        primary_failure_code=WP8FailureCode.SERVICE_EXECUTION_FAILED,
        cleanup_failure_code=WP8FailureCode.CLEANUP_FAILED,
        cleanup_proof=cleanup(result=WP8CleanupResult.FAIL),
    )
    return state, (*events, event)


def test_failed_cleanup_cannot_be_aborted_by_transition_or_rehashed_state() -> None:
    state, events = unconfirmed_cleanup()
    assert validate_rehearsal_journal_chain(events, state)
    assert events[-1].pipeline_key is None
    assert events[-1].failed_pipeline_key == WP8_CANONICAL_PIPELINE_KEYS[0]
    with pytest.raises(WP8ContractError):
        transition_rehearsal_state(
            state, WP8RehearsalPhase.ABORTED, sequence=len(events) + 1,
            timestamp_utc=timestamp(31), cleanup_proof=state.cleanup_proof,
        )
    mapping = state.to_mapping()
    mapping.update(phase="ABORTED", cleanup_failure_code=None)
    refingerprint(mapping, "state_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalStateV1.from_mapping(mapping)
    with pytest.raises(WP8ContractError):
        transition_rehearsal_state(
            state, WP8RehearsalPhase.ABORTED, sequence=len(events) + 1,
            timestamp_utc=timestamp(31),
        )


def test_cleanup_retry_requires_pass_proof_and_preserves_first_failure() -> None:
    state, events = unconfirmed_cleanup()
    failed_again, event = transition_rehearsal_state(
        state, WP8RehearsalPhase.ABORT_NOT_CONFIRMED, sequence=len(events) + 1,
        timestamp_utc=timestamp(31), cleanup_proof=cleanup(result=WP8CleanupResult.FAIL),
        cleanup_failure_code=WP8FailureCode.CLEANUP_FAILED,
    )
    assert validate_rehearsal_journal_chain((*events, event), failed_again)
    aborted, recovered = transition_rehearsal_state(
        failed_again, WP8RehearsalPhase.ABORTED, sequence=len(events) + 2,
        timestamp_utc=timestamp(32), cleanup_proof=cleanup(),
    )
    assert validate_rehearsal_journal_chain((*events, event, recovered), aborted)
    for name in (
        "primary_failure_code", "failed_phase", "failed_pipeline_key",
        "failure_mutation_boundary", "runtime_ledger_fingerprint", "invariant_proof_fingerprint",
    ):
        assert getattr(aborted, name) == getattr(state, name)
    assert aborted.cleanup_proof.result is WP8CleanupResult.PASS
    assert aborted.failed_phase is WP8RehearsalPhase.SERVICE_1_EXECUTING
    assert aborted.failure_mutation_boundary == "POST_MUTATION"
    for target in NORMAL_PHASES:
        with pytest.raises(WP8ContractError):
            validate_wp8_transition(state.phase, target)


@pytest.mark.parametrize("changes", [
    {"primary_failure_code": WP8FailureCode.INVARIANT_FAILED},
    {"failed_pipeline_key": WP8_CANONICAL_PIPELINE_KEYS[1]},
    {"runtime_ledger_fingerprint": H1},
    {"invariant_proof_fingerprint": H1},
    {"evidence_fingerprints": (H1,)},
])
def test_cleanup_retry_cannot_replace_non_cleanup_authority(changes) -> None:
    state, events = unconfirmed_cleanup()
    with pytest.raises(WP8ContractError) as caught:
        transition_rehearsal_state(
            state, WP8RehearsalPhase.ABORTED, sequence=len(events) + 1,
            timestamp_utc=timestamp(31), cleanup_proof=cleanup(), **changes,
        )
    assert caught.value.code is WP8FailureCode.PROTECTED_STATE_TAMPER


@pytest.mark.parametrize("provenance", [
    {"primary_failure_code": WP8FailureCode.INVARIANT_FAILED.value},
    {"failed_phase": "SERVICE_2_EXECUTING", "failed_pipeline_key": WP8_CANONICAL_PIPELINE_KEYS[1]},
])
def test_journal_rejects_rehashed_original_failure_replacement(provenance) -> None:
    state, events = unconfirmed_cleanup()
    state, event = transition_rehearsal_state(
        state, WP8RehearsalPhase.ABORTED, sequence=len(events) + 1,
        timestamp_utc=timestamp(31), cleanup_proof=cleanup(),
    )
    event_mapping = event.to_mapping()
    event_mapping.update(provenance)
    refingerprint(event_mapping, "event_fingerprint")
    altered = WP8RehearsalJournalEventV1.from_mapping(event_mapping)
    state_mapping = state.to_mapping()
    state_mapping.update(provenance, journal_head_fingerprint=altered.event_fingerprint)
    refingerprint(state_mapping, "state_fingerprint")
    altered_state = WP8RehearsalStateV1.from_mapping(state_mapping)
    with pytest.raises(WP8ContractError) as caught:
        validate_rehearsal_journal_chain((*events, altered), altered_state)
    assert caught.value.code is WP8FailureCode.PROTECTED_STATE_TAMPER


def test_failure_boundary_cannot_be_reclassified_after_mutation() -> None:
    state, _ = unconfirmed_cleanup()
    mapping = state.to_mapping()
    mapping["failure_mutation_boundary"] = "PRE_MUTATION"
    refingerprint(mapping, "state_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalStateV1.from_mapping(mapping)


def test_pre_mutation_failure_records_exact_original_phase() -> None:
    state = initial_state()
    failed, event = transition_rehearsal_state(
        state, WP8RehearsalPhase.FAILED, sequence=1, timestamp_utc=timestamp(5),
        primary_failure_code=WP8FailureCode.PREREQUISITE_DRIFT,
    )
    assert failed.failed_phase is WP8RehearsalPhase.NEW
    assert failed.failure_mutation_boundary == "PRE_MUTATION"
    assert validate_rehearsal_journal_chain((event,), failed)


def test_failure_pipeline_binding_is_separate_for_unit_contract_validation() -> None:
    state = initial_state()
    failed, event = transition_rehearsal_state(
        state, WP8RehearsalPhase.FAILED, sequence=1, timestamp_utc=timestamp(5),
        primary_failure_code=WP8FailureCode.SERVICE_CONTRACT_INVALID,
        failed_pipeline_key=WP8_CANONICAL_PIPELINE_KEYS[2],
    )
    assert event.pipeline_key is None
    assert event.failed_pipeline_key == failed.failed_pipeline_key
    assert validate_rehearsal_journal_chain((event,), failed)
    with pytest.raises(WP8ContractError):
        transition_rehearsal_state(
            state, WP8RehearsalPhase.FAILED, sequence=1, timestamp_utc=timestamp(5),
            primary_failure_code=WP8FailureCode.AUTHORIZATION_INVALID,
            failed_pipeline_key=WP8_CANONICAL_PIPELINE_KEYS[2],
        )


def test_direct_journal_builder_cannot_replace_failure_during_cleanup_retry() -> None:
    state, events = unconfirmed_cleanup()
    successful = cleanup()
    with pytest.raises(WP8ContractError):
        WP8RehearsalJournalEventV1.build(
            sequence=len(events) + 1, state=state, target=WP8RehearsalPhase.ABORTED,
            timestamp_utc=timestamp(31),
            primary_failure_code=WP8FailureCode.INVARIANT_FAILED,
            failed_pipeline_key=state.failed_pipeline_key, cleanup_proof=successful,
            evidence_fingerprints=(successful.cleanup_proof_fingerprint,),
        )


@pytest.mark.parametrize("field", WP8InvariantSnapshotV1.HASH_FIELDS)
def test_invariant_rehashed_after_drift_is_rejected(field) -> None:
    mapping = invariant().to_mapping()
    mapping["after"][field] = "d" * 64
    refingerprint(mapping, "invariant_proof_fingerprint")
    with pytest.raises(WP8ContractError) as caught:
        WP8InvariantProofV1.from_mapping(mapping)
    assert caught.value.code is WP8FailureCode.INVARIANT_FAILED


def test_equal_but_foreign_baseline_is_not_reviewed_authority() -> None:
    inputs = completion_inputs()
    mapping = inputs["invariant_proof"].to_mapping()
    for boundary in ("before", "after"):
        mapping[boundary]["schema_fingerprint"] = HC
        mapping[boundary]["source_identity_fingerprint"] = HC
    refingerprint(mapping, "invariant_proof_fingerprint")
    foreign = WP8InvariantProofV1.from_mapping(mapping)
    with pytest.raises(WP8ContractError):
        WP8InvariantProofV1.build(
            phase_a(), rehearsal_operation_id=OPERATION,
            before=foreign.before, after=foreign.after,
        )
    # Even updating protected proof references and journal hashes cannot bind
    # the foreign baseline to the exact reviewed A evidence.
    state, events = complete_state()
    revised = []
    previous = None
    old_hash = inputs["invariant_proof"].invariant_proof_fingerprint
    for event in events:
        changed = event.to_mapping()
        changed["evidence_fingerprints"] = sorted(
            foreign.invariant_proof_fingerprint if item == old_hash else item
            for item in changed["evidence_fingerprints"]
        )
        changed["previous_event_fingerprint"] = previous
        refingerprint(changed, "event_fingerprint")
        parsed = WP8RehearsalJournalEventV1.from_mapping(changed)
        revised.append(parsed)
        previous = parsed.event_fingerprint
    changed_state = state.to_mapping()
    changed_state.update(invariant_proof_fingerprint=foreign.invariant_proof_fingerprint,
                         journal_head_fingerprint=previous)
    refingerprint(changed_state, "state_fingerprint")
    inputs.update(invariant_proof=foreign,
                  state=WP8RehearsalStateV1.from_mapping(changed_state),
                  journal_events=tuple(revised))
    with pytest.raises(WP8ContractError) as caught:
        WP8RehearsalCompleteV1.build(**inputs)
    assert caught.value.code is WP8FailureCode.INVARIANT_FAILED


@pytest.mark.parametrize("field", tuple(WP8InvariantSnapshotV1.FIXED))
def test_invariant_rejects_rehashed_fixed_authority_changes(field) -> None:
    mapping = invariant().to_mapping()
    for boundary in ("before", "after"):
        mapping[boundary][field] = "000000000000" if field == "alembic_revision" else "ENABLED"
    refingerprint(mapping, "invariant_proof_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8InvariantProofV1.from_mapping(mapping)


@pytest.mark.parametrize("field", [
    "db_identity_fingerprint", "enabled_scope_fingerprint", "protected_environment_fingerprint",
    "registry_fingerprint", "unit_profile_asset_fingerprint", "p3c_state_fingerprint",
    "p3c_systemd_fingerprint", "gate_a_authority_binding_fingerprint",
    "gate_b_authority_binding_fingerprint", "gate_c_authority_binding_fingerprint",
])
def test_phase_a_snapshot_cannot_conflict_with_outer_authority(field) -> None:
    mapping = phase_a().to_mapping()
    mapping["invariant_baseline"][field] = "d" * 64
    refingerprint(mapping, "phase_a_evidence_fingerprint")
    with pytest.raises(WP8ContractError) as caught:
        WP8PhaseAEvidenceV1.from_mapping(mapping)
    assert caught.value.code is WP8FailureCode.INVARIANT_FAILED


@pytest.mark.parametrize("consumed", [None, 0, 1, "False", "True", [], {}])
def test_authorization_unknown_or_pseudo_boolean_consumption_rejected(consumed) -> None:
    with pytest.raises(WP8ContractError) as caught:
        validate_rehearsal_authorization(
            authorization(), phase_a(), review(), at_utc=timestamp(4), consumed=consumed,
        )
    assert caught.value.code is WP8FailureCode.AUTHORIZATION_INVALID


def test_authorization_missing_consumption_is_not_defaulted() -> None:
    with pytest.raises(TypeError):
        validate_rehearsal_authorization(authorization(), phase_a(), review(), at_utc=timestamp(4))


def test_serializer_rejects_unknown_duck_types_mappings_and_malformed_objects() -> None:
    class Unknown:
        def to_mapping(self):
            raise AssertionError("unknown serializers must not be invoked")

    for obj in (
        Unknown(), phase_a().to_mapping(), replace(phase_a(), candidate_sha="malformed"),
        replace(authorization(), authorization_fingerprint=H1),
        replace(initial_state(), phase="foreign"),
        replace(invariant(), after=replace(snapshot(), schema_fingerprint=HC)),
        replace(snapshot(), alembic_revision="000000000000"),
        replace(phase_a(), invariant_baseline=Unknown()),
        replace(invariant(), after=Unknown()),
        replace(initial_state(), cleanup_proof=Unknown()),
        replace(runtime(), pipeline_records=(Unknown(),)),
    ):
        with pytest.raises(WP8ContractError):
            wp8_contract_bytes(obj)


def test_all_serializers_revalidate_self_hash_and_schema() -> None:
    inputs = completion_inputs()
    marker = WP8RehearsalCompleteV1.build(**inputs)
    malformed = (
        replace(snapshot(), db_identity_fingerprint="invalid"),
        replace(phase_a(), phase_a_evidence_fingerprint=H1),
        replace(review(), review_result_fingerprint=H1),
        replace(authorization(), authorization_fingerprint=H1),
        replace(initial_state(), state_fingerprint=H1),
        replace(inputs["journal_events"][0], event_fingerprint=H1),
        replace(pipeline_records()[0], completed_enrichment_count=True),
        replace(runtime(), runtime_ledger_fingerprint=H1),
        replace(invariant(), invariant_proof_fingerprint=H1),
        replace(cleanup(), cleanup_proof_fingerprint=H1),
        replace(marker, completion_fingerprint=H1),
    )
    for obj in malformed:
        with pytest.raises(WP8ContractError):
            wp8_contract_bytes(obj)


def test_journal_unsorted_evidence_input_is_rejected_not_silently_rewritten() -> None:
    state = initial_state()
    event = WP8RehearsalJournalEventV1.build(
        sequence=1, state=state, target=WP8RehearsalPhase.AUTHORIZATION_VERIFIED,
        timestamp_utc=timestamp(5), evidence_fingerprints=(H2, H1),
    )
    assert event.evidence_fingerprints == (H1, H2)
    mapping = event.to_mapping()
    mapping["evidence_fingerprints"] = [H2, H1]
    refingerprint(mapping, "event_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalJournalEventV1.from_mapping(mapping)
    mapping["evidence_fingerprints"] = [H1, H1]
    refingerprint(mapping, "event_fingerprint")
    with pytest.raises(WP8ContractError):
        WP8RehearsalJournalEventV1.from_mapping(mapping)


def test_all_contract_types_roundtrip_stably_under_key_order_permutations() -> None:
    inputs = completion_inputs()
    marker = WP8RehearsalCompleteV1.build(**inputs)
    values = (
        snapshot(), phase_a(), review(), authorization(), initial_state(),
        *inputs["journal_events"], *pipeline_records(), runtime(), invariant(),
        cleanup(), cleanup(result=WP8CleanupResult.FAIL), inputs["state"], marker,
        *unconfirmed_cleanup(),
    )
    # Expand the event tuple produced by unconfirmed_cleanup separately.
    for obj in values:
        if isinstance(obj, tuple):
            objects = obj
        else:
            objects = (obj,)
        for value in objects:
            canonical = wp8_contract_bytes(value)
            mapping = json.loads(canonical)
            orders = (list(mapping), list(reversed(mapping)), sorted(mapping, reverse=True))
            for order in orders:
                parsed = type(value).from_mapping({key: mapping[key] for key in order})
                assert parsed == value
                assert wp8_contract_bytes(parsed) == canonical
                assert type(value).from_mapping(json.loads(wp8_contract_bytes(parsed))) == parsed


def test_completion_is_reviewable_only_and_requires_separate_b_review() -> None:
    inputs = completion_inputs()
    marker = WP8RehearsalCompleteV1.build(**inputs)
    mapping = marker.to_mapping()
    assert mapping["completion_class"] == "WP8_REHEARSAL_REVIEWABLE_COMPLETE"
    assert mapping["wp8_final_end_boundary"] == (
        "AFTER_B_RUNTIME_LEDGER_INVARIANT_PROOF_AND_INDEPENDENT_REVIEW"
    )
    assert mapping["wp8_final_end_boundary_reached"] is False
    assert mapping["independent_b_review_state"] == "PENDING"
    validation = {key: value for key, value in inputs.items() if key != "completed_at_utc"}
    assert validate_rehearsal_completion(marker, **validation)
    for key, value in (
        ("wp8_final_end_boundary_reached", True),
        ("wp8_final_end_boundary_reached", 0),
        ("independent_b_review_state", "PASS"),
        ("completion_class", "WP8_FULLY_COMPLETE"),
    ):
        changed = dict(mapping)
        changed[key] = value
        refingerprint(changed, "completion_fingerprint")
        with pytest.raises(WP8ContractError):
            WP8RehearsalCompleteV1.from_mapping(changed)
    changed = dict(mapping)
    changed["authorization_fingerprint"] = HC
    refingerprint(changed, "completion_fingerprint")
    rehashed = WP8RehearsalCompleteV1.from_mapping(changed)
    with pytest.raises(WP8ContractError):
        validate_rehearsal_completion(rehashed, **validation)


def test_contract_module_has_no_operational_import_or_activation_surface() -> None:
    path = Path("src/pdi/production_ops/p3d_wp8_contracts.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_imports = {
        "os", "pathlib", "subprocess", "sqlalchemy", "requests", "socket",
    }
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert forbidden_imports.isdisjoint(imported)
    assert "ACTIVE" not in WP8RehearsalPhase.__members__
    assert "ACTIVATED" not in source
    assert "READY_FOR_CUTOVER" not in source


def test_contract_import_has_no_write_process_network_or_operational_side_effects() -> None:
    program = """
import sys
events = []
def audit(name, args):
    if name == 'open':
        mode, flags = args[1], args[2]
        if (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & 3:
            events.append('WRITE_OPEN')
            raise RuntimeError('WRITE_OPEN')
    if name in {'subprocess.Popen', 'os.system', 'socket.connect', 'socket.bind'}:
        events.append(name)
        raise RuntimeError('OPERATIONAL_IMPORT')
sys.addaudithook(audit)
import pdi.production_ops.p3d_wp8_contracts
assert events == []
assert not any(name.startswith(('sqlalchemy', 'requests', 'psycopg')) for name in sys.modules)
print('WP8_IMPORT_SIDE_EFFECTS=NONE')
"""
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "WP8_IMPORT_SIDE_EFFECTS=NONE"


def test_only_frozen_pure_contract_authority_is_imported() -> None:
    path = Path("src/pdi/production_ops/p3d_wp8_contracts.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    pdi_imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("pdi.")
    }
    assert pdi_imports == {
        "pdi.production_ops.p3d_preparation_contracts", "pdi.production_ops.contracts",
    }
