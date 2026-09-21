from __future__ import annotations

import ast
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
import os
from pathlib import Path

import pytest

from pdi.production_ops.p3d_preparation_contracts import (
    ALLOWED_TRANSITIONS,
    AtomicCreatePolicyV1,
    AtomicCreateResult,
    FailureCode,
    GateAPhase,
    GateBPhase,
    GateCPhase,
    InstalledFileEntryV1,
    OperatorToolIdentity,
    OSRuntimeManifestV1,
    P3DAssetInstallationCompleteV1,
    P3DRollbackMetadataV1,
    PreparationContractError,
    PreparationGate,
    PreparationJournalEventV1,
    PreparationOperationStateV1,
    PreparationPrerequisiteEvidenceV1,
    ReleaseInputBundleManifestV1,
    RollbackReleasePinV1,
    RuntimeDistributionEntryV1,
    SourceFileFingerprintEntryV1,
    ToolName,
    WheelEntryV1,
    WheelhouseManifestV1,
    asset_installation_fingerprint,
    atomic_create_no_replace,
    canonical_json_bytes,
    contract_fingerprint,
    os_runtime_manifest_fingerprint,
    release_bundle_fingerprint,
    release_pin_fingerprint,
    rollback_metadata_fingerprint,
    source_release_fingerprint,
    source_runtime_fingerprint,
    transition_preparation_state,
    validate_complete_marker_authorities,
    validate_pre_rehearsal_preparation_contract,
    validate_rollback_release_pin,
    wheel_inventory_fingerprint,
    wheelhouse_manifest_fingerprint,
)


CANDIDATE = "a" * 40
ROLLBACK_SOURCE = "b" * 40
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
WHEN = "2026-09-21T01:02:03Z"
OPERATION_ID = "11111111-2222-4333-8444-555555555555"


def tool_mapping(name: ToolName, source_sha: str = CANDIDATE) -> dict[str, str]:
    return {
        "TOOL_NAME": name.value,
        "TOOL_VERSION": "1.2.3",
        "TOOL_ARTIFACT_SHA256": H1,
        "TOOL_SOURCE_SHA": source_sha,
    }


def rollback_mapping() -> dict[str, object]:
    value: dict[str, object] = {
        **P3DRollbackMetadataV1.FIXED,
        "SNAPSHOT_ID": H1,
        "SNAPSHOT_TAGS": ["final-quiesced", "p3d-pre-enrichment"],
        "DUMP_SHA256": H2,
        "BASELINE_COUNTS_SHA256": H3,
        "EXPORTED_SNAPSHOT_EVIDENCE_HASH": H4,
        "SOURCE_SHA": ROLLBACK_SOURCE,
        "SOURCE_RELEASE_SHA": ROLLBACK_SOURCE,
        "SOURCE_RELEASE_FINGERPRINT": H1,
        "SOURCE_RUNTIME_FINGERPRINT": H2,
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": H3,
        "TARGET_CANDIDATE_SHA": CANDIDATE,
        "SOURCE_DB_FINGERPRINT": H4,
        "P3C_CONTEXT_FINGERPRINT": H5,
        "P3C_SOAK_EVIDENCE_SHA256": H6,
        "RESTORED_INVARIANTS_SHA256": H1,
        "BACKUP_FS_UUID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "RESTIC_REPOSITORY": "/srv/operator-backup/repository",
        "QUALIFIED_AT_UTC": WHEN,
    }
    for prefix, identity in (
        ("EXPORT", tool_mapping(ToolName.BACKUP_EXPORT)),
        ("RESTORE", tool_mapping(ToolName.RESTORE_QUALIFY)),
    ):
        value.update({f"{prefix}_{key}": item for key, item in identity.items()})
    return value


def os_manifest_mapping() -> dict[str, object]:
    return {
        "MANIFEST_VERSION": "1",
        "OS_ID": "synthetic-linux",
        "OS_VERSION_ID": "1.0",
        "ARCH": "x86_64",
        "APPROVED_PACKAGE_NAMES_AND_VERSIONS": [
            {"NAME": "libalpha", "VERSION": "1.2.3-1"},
            {"NAME": "libbeta", "VERSION": "4.5.6-2"},
        ],
        "SYSTEM_PYTHON_PATH": "/usr/bin/python3.13",
        "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13.7",
        "PYTHON_ABI": "cp313",
        "SYSTEM_RUNTIME_FILE_SHA256": H1,
        "NATIVE_LIBRARY_PACKAGE_SET": ["libalpha", "libbeta"],
    }


def wheel_mappings() -> list[dict[str, object]]:
    return [
        {
            "PACKAGE": "alpha",
            "VERSION": "1.2.3",
            "FILENAME": "alpha-1.2.3-py3-none-any.whl",
            "SHA256": H1,
            "TAGS": ["py3-none-any"],
        },
        {
            "PACKAGE": "beta",
            "VERSION": "4.5.6",
            "FILENAME": "beta-4.5.6-cp313-cp313-manylinux.whl",
            "SHA256": H2,
            "TAGS": ["cp313-cp313-manylinux"],
        },
    ]


def wheelhouse_mapping() -> dict[str, object]:
    wheels = tuple(WheelEntryV1.from_mapping(item) for item in wheel_mappings())
    return {
        "MANIFEST_VERSION": "1",
        "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13.7",
        "PYTHON_ABI": "cp313",
        "PLATFORM_TAG": "manylinux-x86_64",
        "ARCH": "x86_64",
        "OS_RUNTIME_MANIFEST_SHA256": H3,
        "WHEELHOUSE_MANIFEST_SHA256": wheel_inventory_fingerprint(wheels),
        "WHEELS": wheel_mappings(),
    }


def release_bundle_mapping() -> dict[str, object]:
    return {
        "MANIFEST_VERSION": "1",
        "CANDIDATE_SHA": CANDIDATE,
        "GIT_BUNDLE_SHA256": H1,
        "GIT_BUNDLE_SOURCE_SHA": CANDIDATE,
        "PDI_WHEEL_SHA256": H2,
        "PDI_WHEEL_SOURCE_SHA": CANDIDATE,
        "PDI_SDIST_SHA256": H3,
        "PDI_SDIST_SOURCE_SHA": CANDIDATE,
        "WHEELHOUSE_MANIFEST_SHA256": H4,
        "OS_RUNTIME_MANIFEST_SHA256": H5,
        "SYSTEMD_ASSET_FINGERPRINT": H6,
        "BUILD_WORKFLOW_IDENTITY": "reviewed-build-v1",
        "BUILD_ARTIFACT_IDENTITY": "artifact-001",
        "PROVENANCE_SHA256": H1,
        "BUILDER_TOOL": tool_mapping(ToolName.RELEASE_BUNDLE_BUILD),
    }


def release_pin_mapping() -> dict[str, str]:
    return {
        "PIN_VERSION": "1",
        "SNAPSHOT_ID": H1,
        "SOURCE_RELEASE_SHA": ROLLBACK_SOURCE,
        "SOURCE_RELEASE_FINGERPRINT": H2,
        "SOURCE_RUNTIME_FINGERPRINT": H3,
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": H4,
        "ROLLBACK_METADATA_SHA256": H5,
        "QUALIFIED_AT_UTC": WHEN,
        "STATE": "ACTIVE",
    }


def tool_for_gate(gate: PreparationGate) -> ToolName:
    return {
        PreparationGate.ROLLBACK_QUALIFICATION: ToolName.BACKUP_EXPORT,
        PreparationGate.RELEASE_STAGING: ToolName.RELEASE_BOOTSTRAP,
        PreparationGate.INERT_ASSET_INSTALL: ToolName.INERT_ASSET_INSTALL,
    }[gate]


def state_for(gate: PreparationGate, phase: str = "NEW") -> PreparationOperationStateV1:
    return PreparationOperationStateV1.from_mapping({
        "version": 1,
        "operation_id": OPERATION_ID,
        "gate": gate.value,
        "candidate_sha": CANDIDATE,
        "phase": phase,
        "started_at": WHEN,
        "updated_at": WHEN,
        "tool_identity": tool_mapping(tool_for_gate(gate)),
        "evidence_fingerprint": None,
        "failure_code": None,
    })


def installed_files() -> tuple[InstalledFileEntryV1, ...]:
    return (
        InstalledFileEntryV1.from_mapping({
            "path": "/etc/pdi/scoped/units/enrichment.file-metadata.env",
            "sha256": H1,
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": "0600",
        }),
        InstalledFileEntryV1.from_mapping({
            "path": "/etc/systemd/system/pdi-enrichment-file-metadata.timer",
            "sha256": H2,
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": "0644",
        }),
    )


def complete_marker_mapping() -> dict[str, object]:
    files = installed_files()
    return {
        "marker_version": 1,
        "candidate_sha": CANDIDATE,
        "rollback_snapshot_id": H1,
        "rollback_metadata_sha256": H2,
        "rollback_source_sha": ROLLBACK_SOURCE,
        "registry_fingerprint": H3,
        "db_identity_fingerprint": H4,
        "enabled_scope_fingerprint": H5,
        "unit_profile_asset_fingerprint": asset_installation_fingerprint(files),
        "installed_file_manifest": [item.to_mapping() for item in files],
        "current_symlink_before": "/opt/pdi/releases/previous-release",
        "current_symlink_after": "/opt/pdi/releases/previous-release",
        "p3c_systemd_state_before_fingerprint": H5,
        "p3c_systemd_state_after_fingerprint": H5,
        "p3d_timer_state": "DISABLED_INACTIVE",
        "preparation_operation_id": OPERATION_ID,
        "completed_at_utc": WHEN,
        "gate_c_tool_identity": tool_mapping(ToolName.INERT_ASSET_INSTALL),
    }


def live_prerequisite(marker: P3DAssetInstallationCompleteV1) -> PreparationPrerequisiteEvidenceV1:
    return PreparationPrerequisiteEvidenceV1(
        candidate_sha=marker.candidate_sha,
        rollback_snapshot_id=marker.rollback_snapshot_id,
        rollback_metadata_sha256=marker.rollback_metadata_sha256,
        rollback_source_sha=marker.rollback_source_sha,
        registry_fingerprint=marker.registry_fingerprint,
        db_identity_fingerprint=marker.db_identity_fingerprint,
        enabled_scope_fingerprint=marker.enabled_scope_fingerprint,
        unit_profile_asset_fingerprint=marker.unit_profile_asset_fingerprint,
        current_symlink=marker.current_symlink_after,
        p3c_systemd_state_fingerprint=marker.p3c_systemd_state_after_fingerprint,
        p3d_timer_state=marker.p3d_timer_state,
    )


def test_rollback_metadata_contract_roundtrip_and_fingerprint() -> None:
    contract = P3DRollbackMetadataV1.from_mapping(rollback_mapping())
    assert contract.to_mapping() == rollback_mapping()
    assert rollback_metadata_fingerprint(contract) == contract_fingerprint(contract.to_mapping())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("SOURCE_SHA", "A" * 40),
        ("DUMP_SHA256", "x" * 64),
        ("QUALIFIED_AT_UTC", "2026-09-21T01:02:03+00:00"),
        ("TARGET_CANDIDATE_SHA", ROLLBACK_SOURCE),
        ("RESTORE_TESTED", "NO"),
    ],
)
def test_rollback_metadata_rejects_invalid_authority(field: str, value: str) -> None:
    mapping = rollback_mapping()
    mapping[field] = value
    with pytest.raises(PreparationContractError):
        P3DRollbackMetadataV1.from_mapping(mapping)


def test_operator_tool_identity_is_allowlisted_and_separates_hashes() -> None:
    identity = OperatorToolIdentity.from_mapping(tool_mapping(ToolName.RELEASE_BOOTSTRAP))
    assert identity.tool_source_sha == CANDIDATE
    assert identity.tool_artifact_sha256 == H1
    invalid = tool_mapping(ToolName.RELEASE_BOOTSTRAP)
    invalid["TOOL_NAME"] = "arbitrary.tool"
    with pytest.raises(PreparationContractError):
        OperatorToolIdentity.from_mapping(invalid)


def test_os_runtime_manifest_is_deterministic_and_strict() -> None:
    first = OSRuntimeManifestV1.from_mapping(os_manifest_mapping())
    reordered = os_manifest_mapping()
    reordered["APPROVED_PACKAGE_NAMES_AND_VERSIONS"] = list(reversed(
        reordered["APPROVED_PACKAGE_NAMES_AND_VERSIONS"],
    ))
    second = OSRuntimeManifestV1.from_mapping(reordered)
    assert os_runtime_manifest_fingerprint(first) == os_runtime_manifest_fingerprint(second)
    invalid = os_manifest_mapping()
    invalid["MANIFEST_VERSION"] = "2"
    with pytest.raises(PreparationContractError):
        OSRuntimeManifestV1.from_mapping(invalid)


def test_wheelhouse_manifest_roundtrip_and_fingerprint() -> None:
    manifest = WheelhouseManifestV1.from_mapping(wheelhouse_mapping())
    assert manifest.to_mapping() == wheelhouse_mapping()
    assert wheelhouse_manifest_fingerprint(manifest) == contract_fingerprint(manifest)


@pytest.mark.parametrize("duplicate_key", ["PACKAGE_VERSION", "FILENAME"])
def test_wheelhouse_rejects_duplicates(duplicate_key: str) -> None:
    mapping = wheelhouse_mapping()
    wheels = mapping["WHEELS"]
    assert isinstance(wheels, list)
    if duplicate_key == "PACKAGE_VERSION":
        wheels[1]["PACKAGE"] = wheels[0]["PACKAGE"]
        wheels[1]["VERSION"] = wheels[0]["VERSION"]
    else:
        wheels[1]["FILENAME"] = wheels[0]["FILENAME"]
    parsed = tuple(WheelEntryV1.from_mapping(item) for item in wheels)
    mapping["WHEELHOUSE_MANIFEST_SHA256"] = wheel_inventory_fingerprint(parsed)
    with pytest.raises(PreparationContractError):
        WheelhouseManifestV1.from_mapping(mapping)


def test_wheelhouse_rejects_unpinned_or_missing_hash() -> None:
    for field, value in (("VERSION", ">=1.2"), ("SHA256", "")):
        mapping = wheelhouse_mapping()
        mapping["WHEELS"][0][field] = value
        with pytest.raises(PreparationContractError):
            WheelhouseManifestV1.from_mapping(mapping)


def test_release_bundle_binds_every_input_to_exact_candidate() -> None:
    manifest = ReleaseInputBundleManifestV1.from_mapping(release_bundle_mapping())
    assert release_bundle_fingerprint(manifest) == contract_fingerprint(manifest)
    mixed = release_bundle_mapping()
    mixed["PDI_WHEEL_SOURCE_SHA"] = ROLLBACK_SOURCE
    with pytest.raises(PreparationContractError, match=FailureCode.CONTRACT_CANDIDATE_MISMATCH.value):
        ReleaseInputBundleManifestV1.from_mapping(mixed)


def test_release_bundle_rejects_wrong_builder_role() -> None:
    mapping = release_bundle_mapping()
    mapping["BUILDER_TOOL"] = tool_mapping(ToolName.RELEASE_BOOTSTRAP)
    with pytest.raises(PreparationContractError):
        ReleaseInputBundleManifestV1.from_mapping(mapping)


def test_release_pin_has_only_explicit_active_or_retired_states() -> None:
    pin = RollbackReleasePinV1.from_mapping(release_pin_mapping())
    assert release_pin_fingerprint(pin) == contract_fingerprint(pin)
    invalid = release_pin_mapping()
    invalid["STATE"] = "AUTO_DELETED"
    with pytest.raises(PreparationContractError):
        RollbackReleasePinV1.from_mapping(invalid)


def test_active_release_pin_must_match_exact_rollback_metadata() -> None:
    metadata = P3DRollbackMetadataV1.from_mapping(rollback_mapping())
    mapping = release_pin_mapping()
    mapping.update({
        "SNAPSHOT_ID": metadata.snapshot_id,
        "SOURCE_RELEASE_SHA": metadata.source_release_sha,
        "SOURCE_RELEASE_FINGERPRINT": metadata.source_release_fingerprint,
        "SOURCE_RUNTIME_FINGERPRINT": metadata.source_runtime_fingerprint,
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": metadata.source_system_runtime_fingerprint,
        "ROLLBACK_METADATA_SHA256": rollback_metadata_fingerprint(metadata),
        "QUALIFIED_AT_UTC": metadata.qualified_at_utc,
    })
    pin = RollbackReleasePinV1.from_mapping(mapping)
    assert validate_rollback_release_pin(metadata, pin)
    with pytest.raises(PreparationContractError, match=FailureCode.ROLLBACK_PIN_FAILED.value):
        validate_rollback_release_pin(metadata, replace(pin, source_runtime_fingerprint=H6))


@pytest.mark.parametrize(
    ("factory", "parser", "version_field", "invalid_version"),
    [
        (rollback_mapping, P3DRollbackMetadataV1.from_mapping, "METADATA_VERSION", "2"),
        (os_manifest_mapping, OSRuntimeManifestV1.from_mapping, "MANIFEST_VERSION", "2"),
        (wheelhouse_mapping, WheelhouseManifestV1.from_mapping, "MANIFEST_VERSION", "2"),
        (release_bundle_mapping, ReleaseInputBundleManifestV1.from_mapping, "MANIFEST_VERSION", "2"),
        (release_pin_mapping, RollbackReleasePinV1.from_mapping, "PIN_VERSION", "2"),
        (complete_marker_mapping, P3DAssetInstallationCompleteV1.from_mapping, "marker_version", 2),
    ],
)
def test_v1_contracts_reject_unknown_major_versions(
    factory, parser, version_field: str, invalid_version,
) -> None:
    mapping = factory()
    mapping[version_field] = invalid_version
    with pytest.raises(PreparationContractError):
        parser(mapping)


@pytest.mark.parametrize(
    ("factory", "parser"),
    [
        (rollback_mapping, P3DRollbackMetadataV1.from_mapping),
        (os_manifest_mapping, OSRuntimeManifestV1.from_mapping),
        (wheelhouse_mapping, WheelhouseManifestV1.from_mapping),
        (release_bundle_mapping, ReleaseInputBundleManifestV1.from_mapping),
        (release_pin_mapping, RollbackReleasePinV1.from_mapping),
        (complete_marker_mapping, P3DAssetInstallationCompleteV1.from_mapping),
    ],
)
def test_v1_contracts_reject_schema_widening(factory, parser) -> None:
    mapping = factory()
    mapping["UNREVIEWED_FIELD"] = "x"
    with pytest.raises(PreparationContractError, match=FailureCode.CONTRACT_FIELD_SET_INVALID.value):
        parser(mapping)


def test_canonical_serialization_is_stable_and_semantic() -> None:
    left = {"set": {"b", "a"}, "flag": True, "count": 2}
    right = {"count": 2, "flag": True, "set": {"a", "b"}}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert contract_fingerprint(left) == contract_fingerprint(right)
    assert contract_fingerprint(left) != contract_fingerprint({**right, "count": 3})
    with pytest.raises(PreparationContractError):
        canonical_json_bytes({"float": 1.0})


def test_canonical_timestamps_normalize_timezone_but_reject_precision_loss() -> None:
    utc_value = datetime(2026, 9, 21, 1, 2, 3, tzinfo=UTC)
    offset_value = datetime(2026, 9, 21, 9, 2, 3, tzinfo=timezone(timedelta(hours=8)))
    assert canonical_json_bytes({"at": utc_value}) == canonical_json_bytes({"at": offset_value})
    with pytest.raises(PreparationContractError):
        canonical_json_bytes({"at": utc_value.replace(microsecond=1)})


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"EXTRA": "x"}),
        lambda value: value.pop("SNAPSHOT_ID"),
        lambda value: value.update({"PASSWORD": "x"}),
        lambda value: value.update({"RESTIC_REPOSITORY": "line\nbreak"}),
    ],
)
def test_strict_field_set_and_no_secret_contract(mutator) -> None:
    mapping = rollback_mapping()
    mutator(mapping)
    with pytest.raises(PreparationContractError):
        P3DRollbackMetadataV1.from_mapping(mapping)


@pytest.mark.parametrize(
    ("gate", "phases"),
    [
        (PreparationGate.ROLLBACK_QUALIFICATION, [item.value for item in GateAPhase if item.value != "FAILED"]),
        (PreparationGate.RELEASE_STAGING, [item.value for item in GateBPhase if item.value != "FAILED"]),
        (PreparationGate.INERT_ASSET_INSTALL, [item.value for item in GateCPhase if item.value != "FAILED"]),
    ],
)
def test_gate_state_machine_happy_paths(gate: PreparationGate, phases: list[str]) -> None:
    state = state_for(gate)
    for phase in phases[1:]:
        state = transition_preparation_state(state, phase, updated_at=WHEN, candidate_sha=CANDIDATE)
    assert state.phase == "COMPLETE"
    with pytest.raises(PreparationContractError):
        transition_preparation_state(state, "NEW", updated_at=WHEN)


def test_gate_a_metadata_cannot_commit_early_or_without_pin() -> None:
    state = state_for(PreparationGate.ROLLBACK_QUALIFICATION)
    with pytest.raises(PreparationContractError):
        transition_preparation_state(state, "METADATA_COMMITTED", updated_at=WHEN)
    assert "METADATA_COMMITTED" not in ALLOWED_TRANSITIONS[
        PreparationGate.ROLLBACK_QUALIFICATION
    ]["DB_RUNTIME_COMPATIBLE"]


@pytest.mark.parametrize(
    ("phase", "code"),
    [
        ("RESTORE_STARTED", FailureCode.ROLLBACK_RESTORE_FAILED),
        ("RESTORE_QUALIFIED", FailureCode.ROLLBACK_RUNTIME_INVALID),
    ],
)
def test_gate_a_failures_are_terminal(phase: str, code: FailureCode) -> None:
    state = state_for(PreparationGate.ROLLBACK_QUALIFICATION)
    phases = [item.value for item in GateAPhase if item.value not in {"FAILED", "COMPLETE"}]
    for target in phases[1:phases.index(phase) + 1]:
        state = transition_preparation_state(state, target, updated_at=WHEN)
    state = transition_preparation_state(state, "FAILED", updated_at=WHEN, failure_code=code)
    with pytest.raises(PreparationContractError):
        transition_preparation_state(state, "RESTORE_STARTED", updated_at=WHEN)


def test_gate_failure_codes_are_namespace_bound() -> None:
    state = state_for(PreparationGate.RELEASE_STAGING)
    with pytest.raises(PreparationContractError):
        transition_preparation_state(
            state,
            "FAILED",
            updated_at=WHEN,
            failure_code=FailureCode.ROLLBACK_DUMP_FAILED,
        )


def test_state_rejects_time_regression_and_foreign_tool_source() -> None:
    state = state_for(PreparationGate.RELEASE_STAGING).to_mapping()
    state["updated_at"] = "2026-09-21T01:02:02Z"
    with pytest.raises(PreparationContractError):
        PreparationOperationStateV1.from_mapping(state)
    state = state_for(PreparationGate.RELEASE_STAGING).to_mapping()
    state["tool_identity"] = tool_mapping(ToolName.RELEASE_BOOTSTRAP, ROLLBACK_SOURCE)
    with pytest.raises(PreparationContractError):
        PreparationOperationStateV1.from_mapping(state)


def test_gate_b_final_rename_requires_immutability_and_has_no_promotion() -> None:
    state = state_for(PreparationGate.RELEASE_STAGING)
    with pytest.raises(PreparationContractError):
        transition_preparation_state(state, "FINAL_RENAME_COMMITTED", updated_at=WHEN)
    assert not {"PROMOTED", "ACTIVE"} & {item.value for item in GateBPhase}
    assert "FINAL_RENAME_COMMITTED" in ALLOWED_TRANSITIONS[
        PreparationGate.RELEASE_STAGING
    ]["IMMUTABILITY_VERIFIED"]


def test_gate_b_conflict_fails_and_crash_before_final_remains_incomplete() -> None:
    state = state_for(PreparationGate.RELEASE_STAGING)
    for target in (
        "ARTIFACT_VERIFIED", "OS_RUNTIME_VERIFIED", "STAGING_CREATED",
        "SOURCE_CHECKED_OUT", "VENV_BUILT", "RUNTIME_VERIFIED", "IMMUTABILITY_VERIFIED",
    ):
        state = transition_preparation_state(state, target, updated_at=WHEN)
    assert state.phase == "IMMUTABILITY_VERIFIED"
    assert state.phase != "COMPLETE"
    state = transition_preparation_state(
        state,
        "FAILED",
        updated_at=WHEN,
        failure_code=FailureCode.RELEASE_FINAL_CONFLICT,
    )
    assert state.phase == "FAILED"


def test_gate_c_partial_install_same_sha_retry_and_takeover_refusal() -> None:
    state = state_for(PreparationGate.INERT_ASSET_INSTALL)
    for target in (
        "PREREQUISITES_VERIFIED", "REGISTRY_VERIFIED", "DB_EVIDENCE_VERIFIED",
        "PROFILES_RENDERED", "OFFLINE_STATIC_VERIFIED", "FILES_PARTIALLY_INSTALLED",
    ):
        state = transition_preparation_state(state, target, updated_at=WHEN)
    state = transition_preparation_state(
        state, "FILES_PARTIALLY_INSTALLED", updated_at=WHEN, candidate_sha=CANDIDATE,
    )
    assert state.phase == "FILES_PARTIALLY_INSTALLED"
    with pytest.raises(PreparationContractError, match=FailureCode.CONTRACT_CANDIDATE_MISMATCH.value):
        transition_preparation_state(
            state, "FILES_PARTIALLY_INSTALLED", updated_at=WHEN,
            candidate_sha=ROLLBACK_SOURCE,
        )


def test_gate_c_complete_marker_requires_static_and_quiet_phases() -> None:
    assert "COMPLETE_MARKER_COMMITTED" not in ALLOWED_TRANSITIONS[
        PreparationGate.INERT_ASSET_INSTALL
    ]["FILES_INSTALLED"]
    assert "COMPLETE_MARKER_COMMITTED" in ALLOWED_TRANSITIONS[
        PreparationGate.INERT_ASSET_INSTALL
    ]["SYSTEMD_QUIET_VERIFIED"]
    assert "FILES_INSTALLED" not in ALLOWED_TRANSITIONS[
        PreparationGate.INERT_ASSET_INSTALL
    ]["REGISTRY_VERIFIED"]


def test_preparation_state_and_journal_envelopes_are_candidate_bound() -> None:
    state = state_for(PreparationGate.RELEASE_STAGING)
    assert PreparationOperationStateV1.from_mapping(state.to_mapping()) == state
    event = PreparationJournalEventV1.from_mapping({
        "version": 1,
        "sequence": 1,
        "operation_id": OPERATION_ID,
        "gate": PreparationGate.RELEASE_STAGING.value,
        "candidate_sha": CANDIDATE,
        "from_state": "NEW",
        "to_state": "ARTIFACT_VERIFIED",
        "timestamp": WHEN,
        "tool_identity": tool_mapping(ToolName.RELEASE_BOOTSTRAP),
        "evidence_fingerprints": [H2, H1],
        "failure_code": None,
    })
    assert event.evidence_fingerprints == (H1, H2)
    foreign = event.to_mapping()
    foreign["tool_identity"] = tool_mapping(ToolName.RELEASE_BOOTSTRAP, ROLLBACK_SOURCE)
    with pytest.raises(PreparationContractError):
        PreparationJournalEventV1.from_mapping(foreign)


def test_complete_marker_and_live_prerequisite_contract() -> None:
    marker = P3DAssetInstallationCompleteV1.from_mapping(complete_marker_mapping())
    assert validate_pre_rehearsal_preparation_contract(marker, live_prerequisite(marker))


def test_complete_marker_must_match_exact_rollback_metadata() -> None:
    metadata = P3DRollbackMetadataV1.from_mapping(rollback_mapping())
    mapping = complete_marker_mapping()
    mapping.update({
        "rollback_snapshot_id": metadata.snapshot_id,
        "rollback_metadata_sha256": rollback_metadata_fingerprint(metadata),
        "rollback_source_sha": metadata.source_release_sha,
        "candidate_sha": metadata.target_candidate_sha,
    })
    marker = P3DAssetInstallationCompleteV1.from_mapping(mapping)
    assert validate_complete_marker_authorities(marker, metadata)
    with pytest.raises(PreparationContractError):
        validate_complete_marker_authorities(replace(marker, rollback_metadata_sha256=H6), metadata)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("current_symlink_after", "/opt/pdi/releases/unexpected"),
        ("p3c_systemd_state_after_fingerprint", H6),
        ("p3d_timer_state", "ACTIVE"),
        ("rollback_source_sha", CANDIDATE),
    ],
)
def test_complete_marker_rejects_forged_invariants(field: str, value: str) -> None:
    mapping = complete_marker_mapping()
    mapping[field] = value
    with pytest.raises(PreparationContractError):
        P3DAssetInstallationCompleteV1.from_mapping(mapping)


@pytest.mark.parametrize(
    "field",
    [
        "candidate_sha", "rollback_metadata_sha256", "registry_fingerprint",
        "db_identity_fingerprint", "enabled_scope_fingerprint",
        "unit_profile_asset_fingerprint", "current_symlink",
        "p3c_systemd_state_fingerprint", "p3d_timer_state",
    ],
)
def test_live_prerequisite_mismatch_fails_closed(field: str) -> None:
    marker = P3DAssetInstallationCompleteV1.from_mapping(complete_marker_mapping())
    live = live_prerequisite(marker)
    replacement = ROLLBACK_SOURCE if field == "candidate_sha" else (
        "ACTIVE" if field == "p3d_timer_state" else (
            "/opt/pdi/releases/other" if field == "current_symlink" else H6
        )
    )
    with pytest.raises(PreparationContractError):
        validate_pre_rehearsal_preparation_contract(marker, replace(live, **{field: replacement}))


def test_source_release_and_runtime_fingerprints_are_order_independent() -> None:
    entries = (
        SourceFileFingerprintEntryV1("src/pdi/a.py", "file", "0644", 0, 0, H1),
        SourceFileFingerprintEntryV1("src/pdi", "directory", "0755", 0, 0),
    )
    assert source_release_fingerprint(CANDIDATE, entries) == source_release_fingerprint(
        CANDIDATE, tuple(reversed(entries)),
    )
    distributions = (
        RuntimeDistributionEntryV1("alpha", "1.0.0", H2),
        RuntimeDistributionEntryV1("beta", "2.0.0", H3),
    )
    left = source_runtime_fingerprint(
        source_release_sha256=H1,
        system_runtime_sha256=H4,
        python_version="3.13.7",
        python_abi="cp313",
        distributions=distributions,
    )
    right = source_runtime_fingerprint(
        source_release_sha256=H1,
        system_runtime_sha256=H4,
        python_version="3.13.7",
        python_abi="cp313",
        distributions=tuple(reversed(distributions)),
    )
    assert left == right
    assert left != source_runtime_fingerprint(
        source_release_sha256=H1,
        system_runtime_sha256=H5,
        python_version="3.13.7",
        python_abi="cp313",
        distributions=distributions,
    )


def test_failure_code_registry_is_fixed_and_namespaced() -> None:
    values = [item.value for item in FailureCode]
    assert len(values) == len(set(values))
    assert all(value.startswith((
        "P3D_PREP_CONTRACT_", "P3D_ROLLBACK_", "P3D_RELEASE_STAGE_",
        "P3D_ASSET_INSTALL_",
    )) for value in values)
    assert all(" " not in value and "\n" not in value for value in values)


def test_atomic_create_no_replace_is_durable_idempotent_and_conflict_safe(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    policy = AtomicCreatePolicyV1(
        owner_uid=os.getuid(), owner_gid=os.getgid(), mode=0o600, trust_root=trusted,
    )
    target = trusted / "authority.json"
    assert atomic_create_no_replace(target, b'{"version":1}', policy=policy) is AtomicCreateResult.CREATED
    assert atomic_create_no_replace(target, b'{"version":1}', policy=policy) is AtomicCreateResult.IDEMPOTENT
    assert target.read_bytes() == b'{"version":1}'
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(PreparationContractError, match=FailureCode.CONTRACT_PERSISTENCE_CONFLICT.value):
        atomic_create_no_replace(target, b'{"version":2}', policy=policy)


def test_atomic_create_rejects_untrusted_parent_and_symlink(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    policy = AtomicCreatePolicyV1(
        owner_uid=os.getuid(), owner_gid=os.getgid(), mode=0o600, trust_root=trusted,
    )
    weak = trusted / "weak"
    weak.mkdir(mode=0o770)
    weak.chmod(0o770)
    with pytest.raises(PreparationContractError, match=FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED.value):
        atomic_create_no_replace(weak / "authority.json", b"{}", policy=policy)
    real = trusted / "real"
    real.mkdir(mode=0o700)
    link = trusted / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(PreparationContractError, match=FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED.value):
        atomic_create_no_replace(link / "authority.json", b"{}", policy=policy)


def test_contract_module_has_no_operational_import_or_import_time_entrypoint() -> None:
    path = Path("src/pdi/production_ops/p3d_preparation_contracts.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not imported & {"subprocess", "sqlalchemy", "psycopg", "requests", "httpx", "pdi"}
    assert not any(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and any(isinstance(item, ast.Constant) and item.value == "__main__" for item in ast.walk(node.test))
        for node in tree.body
    )
