"""P3D control-plane contract entrypoint; no production defaults are embedded."""
import argparse
import json
from pathlib import Path

from pdi.production_ops.enrichment_cutover import P3DControl, P3DControlRefused
from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "qualify", "activate", "verify", "abort"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        control = P3DControl(args.state, args.journal, args.expected_sha, args.release)
        evidence = json.loads(args.evidence.read_text())
        if args.action == "preflight":
            control.preflight(evidence)
        elif args.action == "qualify":
            control.qualify(evidence)
        elif args.action == "activate":
            control.activation_result(enabled=bool(evidence.get("enabled")), all_disabled=bool(evidence.get("all_disabled")))
        elif args.action == "verify":
            control.verify(evidence)
        else:
            control.abort(all_disabled=bool(evidence.get("all_disabled")))
        print("P3D_CONTROL=PASS")
        return 0
    except (OSError, ValueError, P3DControlRefused):
        print("P3D_CONTROL=FAIL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
