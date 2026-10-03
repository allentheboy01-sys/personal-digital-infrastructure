#!/usr/bin/env python3
"""Thin, fixed-path CLI for MU13-P3D Gate C."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import grp
from typing import Sequence

from pdi.production_ops.p3d_inert_asset_install import (
    InertAssetInputs,
    InertAssetInstallError,
    InertAssetInstaller,
    InertAssetPolicy,
    InstallMode,
    ProductionReadOnlySystemdStateProvider,
    SyntheticSystemdStateProvider,
    SystemdSnapshot,
    verify_candidate_installer_runtime,
)
from pdi.production_ops.p3d_preparation_contracts import (
    OperatorToolIdentity,
    ToolName,
    contract_fingerprint,
)


TOOL_VERSION = "0.1.0"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Install the exact inert P3D Gate C unit/profile set; never reload, "
            "enable, start, stop, or invoke a workload"
        ),
    )
    parser.add_argument("--mode", choices=[item.value for item in InstallMode], required=True)
    parser.add_argument("--expected-candidate-sha", required=True)
    parser.add_argument("--gate-a-operation-id", required=True)
    parser.add_argument("--gate-b-operation-id", required=True)
    parser.add_argument("--expected-systemd-asset-fingerprint", required=True)
    parser.add_argument("--resume-operation-id")
    parser.add_argument(
        "--qualification-root", type=Path,
        help="Required disposable root in QUALIFICATION mode; forbidden in PRODUCTION",
    )
    parser.add_argument("--qualification-runtime-user", default="nobody")
    parser.add_argument("--qualification-runtime-group", default="nogroup")
    return parser


def _tool(candidate: str, policy: InertAssetPolicy) -> OperatorToolIdentity:
    module = Path(__import__(
        "pdi.production_ops.p3d_inert_asset_install", fromlist=["__file__"]
    ).__file__)
    artifact_sha256 = verify_candidate_installer_runtime(
        policy,
        candidate,
        module_file=module,
        script_file=Path(__file__),
    )
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.INERT_ASSET_INSTALL.value,
        "TOOL_VERSION": TOOL_VERSION,
        "TOOL_ARTIFACT_SHA256": artifact_sha256,
        "TOOL_SOURCE_SHA": candidate,
    })


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        mode = InstallMode(args.mode)
        if mode is InstallMode.PRODUCTION:
            if args.qualification_root is not None:
                raise ValueError
            policy = InertAssetPolicy.production()
            systemd = ProductionReadOnlySystemdStateProvider()
        else:
            if args.qualification_root is None:
                raise ValueError
            runtime_uid = pwd.getpwnam(args.qualification_runtime_user).pw_uid
            runtime_gid = grp.getgrnam(args.qualification_runtime_group).gr_gid
            policy = InertAssetPolicy.qualification(
                args.qualification_root, owner_uid=os.geteuid(), owner_gid=os.getegid(),
                runtime_uid=runtime_uid, runtime_gid=runtime_gid,
            )
            p3c_hash = contract_fingerprint({
                "qualification": "p3c-healthy", "candidate": args.expected_candidate_sha,
            })
            systemd = SyntheticSystemdStateProvider(SystemdSnapshot(
                p3c_hash,
                contract_fingerprint({"qualification": "p3d-disabled-inactive"}),
                True,
            ))
        inputs = InertAssetInputs(
            args.expected_candidate_sha,
            args.gate_a_operation_id,
            args.gate_b_operation_id,
            args.expected_systemd_asset_fingerprint,
            _tool(args.expected_candidate_sha, policy),
        )
        result = InertAssetInstaller(
            inputs=inputs, policy=policy, systemd=systemd,
        ).run(resume_operation_id=args.resume_operation_id)
        print(json.dumps({
            "P3D_INERT_ASSET_INSTALL": "PASS",
            "CANDIDATE_SHA": args.expected_candidate_sha,
            "GATE": result.final_state.gate.value,
            "PHASE": result.final_state.phase,
            "OPERATION_ID": result.operation_id,
            "DISPOSITION": result.disposition,
            "INSTALLED_FILE_COUNT": len(result.marker.installed_file_manifest),
            "INSTALLED_ASSET_FINGERPRINT": result.marker.unit_profile_asset_fingerprint,
            "CURRENT_CHANGED": "NO",
            "SYSTEMD_MUTATION": "NO",
            "WORKLOAD_STARTED": "NO",
        }, sort_keys=True))
        return 0
    except InertAssetInstallError as error:
        print(f"P3D_INERT_ASSET_INSTALL=FAIL\nFAILURE_CODE={error.code.value}")
        return 1
    except Exception:
        print("P3D_INERT_ASSET_INSTALL=FAIL\nFAILURE_CODE=P3D_ASSET_INSTALL_PREREQUISITE_INVALID")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
