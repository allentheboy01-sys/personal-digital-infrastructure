"""Disposable end-to-end Gate B qualification; never targets production paths."""

from __future__ import annotations

import json
import os
from pathlib import Path
import grp
import pwd
import shutil

import pytest

from pdi.production_ops.p3d_preparation_contracts import OperatorToolIdentity, ToolName
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapError,
    BootstrapInputs,
    BootstrapPolicy,
    QualificationHostRuntimeAuthorityProvider,
    ReleaseBootstrap,
    resolve_runtime_identity,
)


def _required_environment() -> tuple[Path, Path, Path, str]:
    names = (
        "PDI_P3D_BOOTSTRAP_BUNDLE",
        "PDI_P3D_BOOTSTRAP_DIGESTS",
        "PDI_P3D_BOOTSTRAP_QUALIFICATION_ROOT",
        "PDI_P3D_BOOTSTRAP_CANDIDATE_SHA",
    )
    if any(not os.environ.get(name) for name in names):
        pytest.skip("dedicated P3D root bootstrap qualification only")
    return (
        Path(os.environ[names[0]]),
        Path(os.environ[names[1]]),
        Path(os.environ[names[2]]),
        os.environ[names[3]],
    )


def test_real_offline_root_bootstrap_is_idempotent_and_conflict_safe() -> None:
    bundle, digest_path, root, candidate = _required_environment()
    assert root != Path("/")
    assert str(root).startswith(("/tmp/", "/home/runner/work/_temp/"))
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    digests = json.loads(digest_path.read_text(encoding="utf-8"))
    default_user = "nobody" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
    default_group = "nogroup" if os.geteuid() == 0 else grp.getgrgid(os.getegid()).gr_name
    runtime_user = os.environ.get("PDI_P3D_BOOTSTRAP_RUNTIME_USER", default_user)
    runtime_group = os.environ.get("PDI_P3D_BOOTSTRAP_RUNTIME_GROUP", default_group)
    runtime_uid, runtime_gid = resolve_runtime_identity(runtime_user, runtime_group)
    tool_source = os.environ.get("PDI_P3D_BOOTSTRAP_TOOL_SOURCE_SHA", candidate)
    bootstrap_source = Path(__import__("pdi.production_ops.p3d_release_bootstrap", fromlist=["x"]).__file__)
    tool = OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.RELEASE_BOOTSTRAP.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": __import__("hashlib").sha256(bootstrap_source.read_bytes()).hexdigest(),
        "TOOL_SOURCE_SHA": tool_source,
    })
    inputs = BootstrapInputs(
        bundle.absolute(),
        candidate,
        digests["BUNDLE_SHA256"],
        digests["OS_RUNTIME_MANIFEST_SHA256"],
        "QUALIFICATION_ONLY",
        tool,
        root / "releases",
        root / "state",
        root / "control/bootstrap.lock",
        root / "current",
        runtime_user,
        runtime_group,
    )
    policy = BootstrapPolicy.qualification(
        disposable_root=root,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        runtime_uid=runtime_uid,
        runtime_gid=runtime_gid,
    )
    python = Path(os.environ["PDI_P3D_BOOTSTRAP_SYSTEM_PYTHON"])
    provider = QualificationHostRuntimeAuthorityProvider(
        python, digests["OS_RUNTIME_MANIFEST_SHA256"],
    )

    before_current = inputs.current_path.exists() or inputs.current_path.is_symlink()
    first = ReleaseBootstrap(inputs=inputs, policy=policy, host_runtime_provider=provider).run()
    assert first.disposition == "CREATED"
    assert first.final_state.phase == "COMPLETE"
    assert inputs.final_path.is_dir() and not inputs.final_path.is_symlink()
    assert not before_current and not inputs.current_path.exists()

    second = ReleaseBootstrap(inputs=inputs, policy=policy, host_runtime_provider=provider).run()
    assert second.disposition == "IDEMPOTENT"
    assert second.release_fingerprint == first.release_fingerprint
    assert not inputs.current_path.exists()

    marker = inputs.final_path / "README.md"
    marker.chmod(0o644)
    marker.write_bytes(marker.read_bytes() + b"\nqualification tamper\n")
    marker.chmod(0o644)
    with pytest.raises(BootstrapError) as raised:
        ReleaseBootstrap(inputs=inputs, policy=policy, host_runtime_provider=provider).run()
    assert raised.value.code.value == "P3D_RELEASE_STAGE_FINAL_CONFLICT"
    assert not inputs.current_path.exists()
