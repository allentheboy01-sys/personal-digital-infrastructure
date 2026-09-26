#!/usr/bin/env python3
"""Single-purpose MU13-P3D disposable real-systemd rehearsal CLI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from pdi.production_ops.p3d_disposable_rehearsal import (
    DisposableRehearsal,
    DisposableRehearsalError,
    MachineSystemdBackend,
    RehearsalInputs,
    RehearsalPolicy,
    rootfs_pdi_identity,
    verify_rehearsal_runtime,
)
from pdi.production_ops.p3d_inert_asset_install import (
    SyntheticSystemdStateProvider,
    SystemdSnapshot,
)
from pdi.production_ops.p3d_pre_rehearsal_evidence import (
    PreparationEvidenceInputs,
    collect_pre_rehearsal_evidence,
)
from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact six P3D enrichment services against one isolated "
            "disposable systemd manager; no production mode and no timer "
            "activation are available"
        ),
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    run = subparsers.add_parser("run", help="run one disposable rehearsal")
    run.add_argument("--expected-candidate-sha", required=True)
    run.add_argument("--gate-a-operation-id", required=True)
    run.add_argument("--gate-b-operation-id", required=True)
    run.add_argument("--gate-c-operation-id", required=True)
    run.add_argument("--rehearsal-operation-id", required=True)
    run.add_argument("--rehearsal-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.action != "run" or os.geteuid() != 0 or os.getegid() != 0:
            raise DisposableRehearsalError("P3D_REHEARSAL_OPERATOR_INVALID")
        runtime_uid, runtime_gid = rootfs_pdi_identity(args.rehearsal_root)
        inputs = RehearsalInputs(
            args.expected_candidate_sha,
            args.gate_a_operation_id,
            args.gate_b_operation_id,
            args.gate_c_operation_id,
            args.rehearsal_operation_id,
        )
        policy = RehearsalPolicy.qualification(
            args.rehearsal_root,
            owner_uid=0,
            owner_gid=0,
            runtime_uid=runtime_uid,
            runtime_gid=runtime_gid,
            operation_id=args.rehearsal_operation_id,
        )
        verify_rehearsal_runtime(
            policy,
            args.expected_candidate_sha,
            script_file=Path(__file__),
        )
        preparation_inputs = PreparationEvidenceInputs(
            args.expected_candidate_sha,
            args.gate_a_operation_id,
            args.gate_b_operation_id,
            args.gate_c_operation_id,
        )
        p3c_fingerprint = contract_fingerprint({
            "qualification": "p3c-healthy",
            "candidate": args.expected_candidate_sha,
        })
        preparation_systemd = SyntheticSystemdStateProvider(SystemdSnapshot(
            p3c_fingerprint,
            contract_fingerprint({"qualification": "p3d-disabled-inactive"}),
            True,
        ))

        def collect_preparation():
            return collect_pre_rehearsal_evidence(
                policy=policy.preparation_policy,
                inputs=preparation_inputs,
                systemd=preparation_systemd,
            )

        result = DisposableRehearsal(
            inputs=inputs,
            policy=policy,
            preparation_collector=collect_preparation,
            systemd=MachineSystemdBackend(policy.machine_name),
        ).run()
        print(json.dumps(result.to_sanitized_mapping(), sort_keys=True))
        return 0
    except DisposableRehearsalError as error:
        print(
            "P3D_DISPOSABLE_REHEARSAL=FAIL\n"
            f"FAILURE_CODE={error.code}"
        )
        return 1
    except BaseException:
        print(
            "P3D_DISPOSABLE_REHEARSAL=FAIL\n"
            "FAILURE_CODE=P3D_DISPOSABLE_REHEARSAL_REJECTED"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
