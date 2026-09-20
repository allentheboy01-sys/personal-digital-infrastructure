"""P3D operator cutover; production facts come from protected backends."""
import argparse
import os
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from pdi.production_ops.enrichment_cutover import (
    P3DControl, P3DControlRefused, ProductionEvidenceReader,
    SystemdScopedEnrichmentActions, promote_release_atomically,
)
from pdi.database import create_postgres_engine
from pdi.scoped_operator_config import load_scoped_operator_configuration
from pdi.production_ops.p3d_evidence import RoutedPersonalDatabaseEvidenceReader
from pdi.production_ops.p3d_evidence import verify_qualification_ledger_batch
from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "apply", "qualify", "activate", "verify", "abort"))
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--rollback-source-sha", required=True)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/pdi-p3d/state.json"))
    parser.add_argument("--journal", type=Path, default=Path("/var/lib/pdi-p3d/journal.jsonl"))
    parser.add_argument("--rehearsal-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.rehearsal_root:
            root = args.rehearsal_root
            state = root / "state.json"
            journal = root / "journal.jsonl"
            lock = root / "cutover.lock"
            current = root / "current"
            rollback = root / "rollback.env"
            config = root / "registry.toml"
        else:
            state, journal, lock = args.state, args.journal, Path("/run/lock/pdi-mu13-p3d-cutover.lock")
            current = Path("/opt/pdi/current")
            rollback = Path("/etc/pdi-backup-recovery/pdi-core/p3d-pre-enrichment.env")
            config = Path("/etc/pdi/scoped/registry.toml")
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
            qualification_started = datetime.now(UTC)
            if not backend.qualify(tuple(CANONICAL_SCOPED_ENRICHMENTS)):
                raise P3DControlRefused("QUALIFICATION_FAILED")
            ledger = verify_qualification_ledger_batch(
                db_engine, started_after=qualification_started,
                pipeline_keys=CANONICAL_SCOPED_ENRICHMENTS,
                candidate_sha=args.expected_sha, context=context,
            )
            control.qualify({key: True for key in CANONICAL_SCOPED_ENRICHMENTS},
                            context=context, ledger=ledger)
        elif args.action == "activate":
            context = reader.collect_preflight()
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
        elif args.action == "apply":
            context = reader.collect_preflight()
            control.preflight(context)
            promote_release_atomically(current, args.release, args.expected_sha)
            qualification_started = datetime.now(UTC)
            if not backend.qualify(tuple(CANONICAL_SCOPED_ENRICHMENTS)):
                raise P3DControlRefused("QUALIFICATION_FAILED")
            ledger = verify_qualification_ledger_batch(
                db_engine, started_after=qualification_started,
                pipeline_keys=CANONICAL_SCOPED_ENRICHMENTS,
                candidate_sha=args.expected_sha, context=context,
            )
            control.qualify({key: True for key in CANONICAL_SCOPED_ENRICHMENTS},
                            context=context, ledger=ledger)
            backend.enable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
            control.activation_result(enabled=True, all_disabled=False, context=context)
        else:
            control.abort(all_disabled=backend.disable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS))
        print("P3D_CONTROL=PASS")
        return 0
    except (OSError, ValueError, P3DControlRefused):
        print("P3D_CONTROL=FAIL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
