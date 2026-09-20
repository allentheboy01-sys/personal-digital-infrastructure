"""Safe production boundary for one allow-listed scoped enrichment run."""

import argparse
import logging
import os

from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS
from pdi.scoped_operational import build_executable_scoped_runner
from pdi.scoped_operator_config import load_scoped_operator_configuration


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--principal-ref", required=True)
    parser.add_argument("--pipeline-key", required=True)
    parser.add_argument("--lock-timeout", type=float, default=300)
    args = parser.parse_args(argv)
    if args.pipeline_key not in CANONICAL_SCOPED_ENRICHMENTS:
        print("PDI_SCOPED_ENRICHMENT=PIPELINE_NOT_ALLOWED")
        return 1
    logging.disable(logging.CRITICAL)
    try:
        configuration = load_scoped_operator_configuration(args.config)
        runner = build_executable_scoped_runner(configuration)
        return runner.run(args.principal_ref, args.pipeline_key, lock_timeout=args.lock_timeout)
    except BaseException:
        # Provider/library exceptions are deliberately not exposed to journald.
        print("PDI_SCOPED_ENRICHMENT=FAIL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
