#!/usr/bin/python3
"""Thin CLI for the independently pinned MU13-P3D Gate B bootstrap."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from pdi.production_ops.p3d_preparation_contracts import OperatorToolIdentity, ToolName
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapError,
    BootstrapInputs,
    BootstrapMode,
    BootstrapPolicy,
    DebianHostRuntimeAuthorityProvider,
    QualificationHostRuntimeAuthorityProvider,
    ReleaseBootstrap,
    resolve_runtime_identity,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline, no-current-mutation P3D Gate B release bootstrap",
    )
    parser.add_argument("--mode", choices=[item.value for item in BootstrapMode], required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-candidate-sha", required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--expected-os-runtime-manifest-sha256", required=True)
    parser.add_argument("--expected-authority-class", required=True)
    parser.add_argument("--bootstrap-tool-version", required=True)
    parser.add_argument("--bootstrap-tool-artifact-sha256", required=True)
    parser.add_argument("--bootstrap-tool-source-sha", required=True)
    parser.add_argument("--releases-root", type=Path, required=True)
    parser.add_argument("--preparation-state-root", type=Path, required=True)
    parser.add_argument("--lock-path", type=Path, required=True)
    parser.add_argument("--current-path", type=Path, required=True)
    parser.add_argument("--runtime-user", required=True)
    parser.add_argument("--runtime-group", required=True)
    parser.add_argument("--resume-operation-id")
    parser.add_argument(
        "--qualification-root",
        type=Path,
        help="Required disposable trust root in QUALIFICATION mode only",
    )
    parser.add_argument(
        "--qualification-system-python",
        type=Path,
        help="Explicit host Python in QUALIFICATION mode only",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        runtime_uid, runtime_gid = resolve_runtime_identity(args.runtime_user, args.runtime_group)
        tool = OperatorToolIdentity.from_mapping({
            "TOOL_NAME": ToolName.RELEASE_BOOTSTRAP.value,
            "TOOL_VERSION": args.bootstrap_tool_version,
            "TOOL_ARTIFACT_SHA256": args.bootstrap_tool_artifact_sha256,
            "TOOL_SOURCE_SHA": args.bootstrap_tool_source_sha,
        })
        mode = BootstrapMode(args.mode)
        if mode is BootstrapMode.PRODUCTION:
            if args.qualification_root is not None or args.qualification_system_python is not None:
                raise ValueError("qualification override forbidden")
            policy = BootstrapPolicy.production(runtime_uid=runtime_uid, runtime_gid=runtime_gid)
            provider = DebianHostRuntimeAuthorityProvider()
        else:
            if args.qualification_root is None or args.qualification_system_python is None:
                raise ValueError("qualification authority required")
            policy = BootstrapPolicy.qualification(
                disposable_root=args.qualification_root,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
                runtime_uid=runtime_uid,
                runtime_gid=runtime_gid,
            )
            provider = QualificationHostRuntimeAuthorityProvider(
                args.qualification_system_python,
                args.expected_os_runtime_manifest_sha256,
            )
        inputs = BootstrapInputs(
            args.bundle,
            args.expected_candidate_sha,
            args.expected_bundle_sha256,
            args.expected_os_runtime_manifest_sha256,
            args.expected_authority_class,
            tool,
            args.releases_root,
            args.preparation_state_root,
            args.lock_path,
            args.current_path,
            args.runtime_user,
            args.runtime_group,
        )
        result = ReleaseBootstrap(
            inputs=inputs,
            policy=policy,
            host_runtime_provider=provider,
        ).run(resume_operation_id=args.resume_operation_id)
        print(json.dumps({
            "P3D_RELEASE_BOOTSTRAP": "PASS",
            "CANDIDATE_SHA": args.expected_candidate_sha,
            "DISPOSITION": result.disposition,
            "FINAL_RELEASE_FINGERPRINT": result.release_fingerprint,
            "GATE": result.final_state.gate.value,
            "PHASE": result.final_state.phase,
            "OPERATION_ID": result.operation_id,
            "CURRENT_CHANGED": "NO",
        }, sort_keys=True))
        return 0
    except BootstrapError as error:
        print(f"P3D_RELEASE_BOOTSTRAP=FAIL\nFAILURE_CODE={error.code.value}")
        return 1
    except Exception:
        print("P3D_RELEASE_BOOTSTRAP=FAIL\nFAILURE_CODE=P3D_RELEASE_STAGE_ARTIFACT_INVALID")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
