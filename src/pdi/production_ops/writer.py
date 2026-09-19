"""P3C systemd writer entrypoint, including the deterministic daily chain."""

import argparse
import logging
import os

from pdi.scoped_operational import build_executable_scoped_runner
from pdi.scoped_operator_config import load_scoped_operator_configuration
from .contracts import PIPELINES, require


DAILY = ("provider.immich.sync", "person.immich.sync", "relation.immich.sync")


def execute(runner, principal, pipeline, lock_timeout):
    require(pipeline in PIPELINES.values(), "PIPELINE_NOT_ALLOWED")
    for key in DAILY if pipeline == 'immich.daily' else (pipeline,):
        result = runner.run(principal, key, lock_timeout=lock_timeout)
        require(result == 0, "WRITER_FAILED")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--lock-timeout', type=float, default=300)
    args = parser.parse_args(argv)
    # Provider/library exception messages may contain URLs: emit fixed codes only.
    logging.disable(logging.CRITICAL)
    try:
        config = load_scoped_operator_configuration(args.config)
        return execute(build_executable_scoped_runner(config), os.environ['PDI_PRINCIPAL_REF'],
                       os.environ['PDI_SCOPED_PIPELINE_KEY'], args.lock_timeout)
    except BaseException:
        print('PDI_SCOPED_WRITER=FAIL')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
