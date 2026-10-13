"""P3D operator cutover; production facts come from protected backends."""
import argparse
import os
import re
import tomllib
from pathlib import Path

from pdi.production_ops.enrichment_cutover import (
    P3DControl, P3DControlRefused, ProductionEvidenceReader,
    SystemdScopedEnrichmentActions, build_pre_rehearsal_qualification_proof,
    promote_release_atomically,
)
from pdi.database import create_postgres_engine
from pdi.scoped_operator_config import load_scoped_operator_configuration
from pdi.production_ops.p3d_evidence import RoutedPersonalDatabaseEvidenceReader
from pdi.production_ops.p3d_evidence import verify_qualification_ledger_batch
from pdi.production_ops.p3d_inert_asset_install import (
    ProductionReadOnlySystemdStateProvider,
)
from pdi.production_ops.p3d_pre_rehearsal_evidence import (
    PreparationEvidenceInputs,
    PreparationEvidencePolicy,
    collect_pre_rehearsal_evidence,
)
from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS


PRODUCTION_STATE = Path("/var/lib/pdi-p3d/state.json")
PRODUCTION_JOURNAL = Path("/var/lib/pdi-p3d/journal.jsonl")


def collect_read_only_evidence(
    *,
    release: Path,
    expected_sha: str,
    gate_a_operation_id: str,
    gate_b_operation_id: str,
    gate_c_operation_id: str,
    rollback_source_sha: str | None = None,
    policy: PreparationEvidencePolicy | None = None,
    systemd=None,
    collector=collect_pre_rehearsal_evidence,
    **dependencies,
) -> dict[str, str]:
    """Collect frozen A/B/C plus fresh evidence without control persistence."""

    policy = PreparationEvidencePolicy.production() if policy is None else policy
    expected_release = policy.candidate_releases_root / expected_sha
    if (not release.is_absolute() or release != expected_release or
            re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None):
        raise P3DControlRefused("OPERATOR_ARGUMENT_INVALID")
    inputs = PreparationEvidenceInputs(
        expected_sha,
        gate_a_operation_id,
        gate_b_operation_id,
        gate_c_operation_id,
        rollback_source_sha,
    )
    systemd = ProductionReadOnlySystemdStateProvider() if systemd is None else systemd
    return collector(
        policy=policy,
        inputs=inputs,
        systemd=systemd,
        **dependencies,
    ).to_sanitized_mapping()


def emit_sanitized_evidence(result: dict[str, str]) -> None:
    """Emit only the fixed, non-secret collect-evidence result schema."""
    allowed = (
        "P3D_COLLECT_EVIDENCE", "CANDIDATE_SHA", "CONTEXT_FINGERPRINT",
        "PREPARATION_MARKER_FINGERPRINT",
        "GATE_A_AUTHORITY", "GATE_B_AUTHORITY", "GATE_C_AUTHORITY",
        "P3C_EVIDENCE_REAL", "GMAIL_EVIDENCE_REAL", "ROUTED_DB_PREFLIGHT",
        "READ_ONLY_DB_GUARANTEE", "DB_IDENTITY_FINGERPRINT",
        "ENABLED_SCOPE_COUNT", "ENABLED_SCOPE_FINGERPRINT",
        "CANONICAL_PIPELINE_COUNT", "ASSET_FINGERPRINT",
        "PRE_REHEARSAL_PREPARATION_CONTRACT",
        "PRE_REHEARSAL_QUALIFICATION_PROOF",
        "POST_REHEARSAL_RUNTIME_LEDGER_PROOF", "RUNTIME_PIPELINE_COVERAGE",
    )
    if set(result) != set(allowed):
        raise P3DControlRefused("SANITIZED_OUTPUT_SCHEMA_INVALID")
    exact_values = {
        "P3D_COLLECT_EVIDENCE": "PASS",
        "GATE_A_AUTHORITY": "PASS",
        "GATE_B_AUTHORITY": "PASS",
        "GATE_C_AUTHORITY": "PASS",
        "P3C_EVIDENCE_REAL": "PASS",
        "GMAIL_EVIDENCE_REAL": "PASS",
        "ROUTED_DB_PREFLIGHT": "PASS",
        "READ_ONLY_DB_GUARANTEE": "PASS",
        "CANONICAL_PIPELINE_COUNT": "6",
        "PRE_REHEARSAL_PREPARATION_CONTRACT": "PASS",
        "PRE_REHEARSAL_QUALIFICATION_PROOF": "PASS",
        "POST_REHEARSAL_RUNTIME_LEDGER_PROOF": "NOT_APPLICABLE_PRE_REHEARSAL",
        "RUNTIME_PIPELINE_COVERAGE": "0/6",
    }
    hash_values = {
        "CONTEXT_FINGERPRINT", "PREPARATION_MARKER_FINGERPRINT",
        "DB_IDENTITY_FINGERPRINT",
        "ENABLED_SCOPE_FINGERPRINT", "ASSET_FINGERPRINT",
    }
    for key in allowed:
        value = result[key]
        if (not isinstance(value, str) or "\n" in value or "\r" in value or
                (key in exact_values and value != exact_values[key]) or
                (key == "CANDIDATE_SHA" and re.fullmatch(r"[0-9a-f]{40}", value) is None) or
                (key in hash_values and re.fullmatch(r"[0-9a-f]{64}", value) is None) or
                (key == "ENABLED_SCOPE_COUNT" and re.fullmatch(r"[0-9]+", value) is None)):
            raise P3DControlRefused("SANITIZED_OUTPUT_VALUE_INVALID")
    for key in allowed:
        value = result[key]
        print(f"{key}={value}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="P3D operator cutover and read-only pre-rehearsal evidence collection."
    )
    parser.add_argument(
        "action",
        choices=("preflight", "apply", "qualify", "activate", "verify", "abort",
                 "post-rehearsal-ledger", "collect-evidence"),
        help=("collect-evidence is read-only and non-persisting; all other actions "
              "belong to the stateful cutover control plane"),
    )
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--rollback-source-sha")
    parser.add_argument("--gate-a-operation-id")
    parser.add_argument("--gate-b-operation-id")
    parser.add_argument("--gate-c-operation-id")
    parser.add_argument("--state", type=Path, default=PRODUCTION_STATE)
    parser.add_argument("--journal", type=Path, default=PRODUCTION_JOURNAL)
    parser.add_argument("--rehearsal-root", type=Path)
    args = parser.parse_args(argv)
    if args.action == "collect-evidence":
        if (args.rehearsal_root is not None or args.state != PRODUCTION_STATE or
                args.journal != PRODUCTION_JOURNAL):
            print("P3D_COLLECT_EVIDENCE=FAIL")
            print("FAILURE_CATEGORY=OPERATOR_PATH_OVERRIDE_REJECTED")
            return 1
        if any(operation_id is None for operation_id in (
                args.gate_a_operation_id,
                args.gate_b_operation_id,
                args.gate_c_operation_id,
        )):
            print("P3D_COLLECT_EVIDENCE=FAIL")
            print("FAILURE_CATEGORY=EVIDENCE_REJECTED")
            return 1
        try:
            result = collect_read_only_evidence(
                release=args.release,
                expected_sha=args.expected_sha,
                rollback_source_sha=args.rollback_source_sha,
                gate_a_operation_id=args.gate_a_operation_id,
                gate_b_operation_id=args.gate_b_operation_id,
                gate_c_operation_id=args.gate_c_operation_id,
            )
            emit_sanitized_evidence(result)
            return 0
        except BaseException:
            print("P3D_COLLECT_EVIDENCE=FAIL")
            print("FAILURE_CATEGORY=EVIDENCE_REJECTED")
            return 1
    try:
        if args.rollback_source_sha is None:
            raise P3DControlRefused("ROLLBACK_SOURCE_REQUIRED")
        if args.rehearsal_root:
            root = args.rehearsal_root
            state = root / "state.json"
            journal = root / "journal.jsonl"
            lock = root / "cutover.lock"
            current = root / "current"
            rollback = root / "rollback.env"
            config = root / "registry.toml"
            unit_dir = root / "etc/systemd/system"
            profile_dir = root / "etc/pdi/scoped/units"
        else:
            state, journal, lock = args.state, args.journal, Path("/run/lock/pdi-mu13-p3d-cutover.lock")
            current = Path("/opt/pdi/current")
            rollback = Path("/etc/pdi-backup-recovery/pdi-core/p3d-pre-enrichment.env")
            config = Path("/etc/pdi/scoped/registry.toml")
            unit_dir = Path("/etc/systemd/system")
            profile_dir = Path("/etc/pdi/scoped/units")
        raw_config = tomllib.loads(config.read_text())
        principals = raw_config.get("principals", [])
        if len(principals) != 1 or not principals[0].get("enabled", False):
            raise P3DControlRefused("PRINCIPAL_INVARIANT_FAILED")
        principal_ref = principals[0]["id"]
        operator_config = load_scoped_operator_configuration(config, environment=os.environ)
        routed = operator_config.router.resolve(principal_ref)
        db_engine = create_postgres_engine(routed.database_url)
        personal_db_reader = RoutedPersonalDatabaseEvidenceReader(
            operator_config.router, db_engine, principal_ref=principal_ref
        )
        control = P3DControl(state, journal, args.expected_sha, args.release, lock)
        reader = ProductionEvidenceReader(
            release=args.release, expected_sha=args.expected_sha, current=current,
            rollback_metadata=rollback, config=config, previous_sha=args.rollback_source_sha,
            rollback_source_sha=args.rollback_source_sha, personal_db_reader=personal_db_reader,
        )
        backend = SystemdScopedEnrichmentActions()
        if args.action == "preflight":
            control.preflight(reader.collect_preflight())
        elif args.action == "qualify":
            context = reader.collect_preflight()
            proof = build_pre_rehearsal_qualification_proof(
                candidate_sha=args.expected_sha,
                rollback_source_sha=args.rollback_source_sha,
                context=context,
                unit_dir=unit_dir,
                profile_dir=profile_dir,
            )
            control.qualify(proof, context=context)
        elif args.action == "activate":
            context = reader.collect_preflight()
            if not current.is_symlink() or current.resolve() != args.release:
                raise P3DControlRefused("CANDIDATE_NOT_PROMOTED")
            try:
                backend.enable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
            except BaseException:
                confirmed = backend.disable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
                control.activation_result(enabled=False, all_disabled=confirmed, context=context)
            else:
                control.activation_result(enabled=True, all_disabled=False, context=context)
        elif args.action == "verify":
            evidence = reader.collect_active_verify()
            control.verify(evidence)
        elif args.action == "post-rehearsal-ledger":
            reader.collect_active_verify()
            started_after, context = control.runtime_ledger_boundary()
            ledger = verify_qualification_ledger_batch(
                db_engine, started_after=started_after,
                pipeline_keys=CANONICAL_SCOPED_ENRICHMENTS,
                candidate_sha=args.expected_sha, context=context,
            )
            control.record_runtime_ledger(ledger)
        elif args.action == "apply":
            context = reader.collect_preflight()
            control.preflight(context)
            proof = build_pre_rehearsal_qualification_proof(
                candidate_sha=args.expected_sha,
                rollback_source_sha=args.rollback_source_sha,
                context=context,
                unit_dir=unit_dir,
                profile_dir=profile_dir,
            )
            promote_release_atomically(current, args.release, args.expected_sha)
            promoted_context = reader.collect_preflight()
            control.qualify(proof, context=promoted_context)
            backend.enable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
            control.activation_result(enabled=True, all_disabled=False, context=promoted_context)
        else:
            control.abort(all_disabled=backend.disable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS))
        print("P3D_CONTROL=PASS")
        return 0
    except (OSError, ValueError, P3DControlRefused):
        print("P3D_CONTROL=FAIL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
