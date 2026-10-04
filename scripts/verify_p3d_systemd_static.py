#!/usr/bin/env python3
"""Install and statically verify exact P3D units in a disposable offline root."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_SOURCE = ROOT / "deployment/systemd"
PIPELINES = (
    "enrichment.nextcloud_text",
    "enrichment.nextcloud_documents",
    "enrichment.file_metadata",
    "enrichment.immich_geo",
    "enrichment.immich_metadata",
    "enrichment.immich_ocr",
)
TIMERS = tuple(f"pdi-scoped-enrichment-{key.removeprefix('enrichment.').replace('_', '-')}.timer"
               for key in PIPELINES)
UNITS = ("pdi-scoped-pipeline@.service", *TIMERS)


def _write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    args = parser.parse_args(argv)
    target_root = args.root.resolve()
    if target_root == Path("/") or len(args.release_sha) != 40:
        raise SystemExit("P3D_SYSTEMD_STATIC=INVALID_ARGUMENT")
    if target_root.exists() and any(target_root.iterdir()):
        raise SystemExit("P3D_SYSTEMD_STATIC=ROOT_NOT_EMPTY")

    unit_dir = target_root / "etc/systemd/system"
    profile_dir = target_root / "etc/pdi/scoped/units"
    unit_dir.mkdir(parents=True, exist_ok=True)
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_dir.chmod(0o700)
    for name in UNITS:
        source = SYSTEMD_SOURCE / name
        if not source.is_file() or source.is_symlink():
            raise SystemExit("P3D_SYSTEMD_STATIC=ASSET_MISSING")
        shutil.copyfile(source, unit_dir / name)
        (unit_dir / name).chmod(0o644)

    for key in PIPELINES:
        profile = profile_dir / f"{key}.env"
        _write(
            profile,
            'PDI_PRINCIPAL_REF="synthetic-principal"\n'
            f'PDI_SCOPED_PIPELINE_KEY="{key}"\n'
            'PDI_SYNTHETIC_DATABASE_URL="postgresql://synthetic.invalid/pdi"\n',
            0o600,
        )
    _write(target_root / "etc/pdi/scoped/registry.toml", "# synthetic static-verification registry\n", 0o600)
    _write(target_root / "etc/passwd", "root:x:0:0:root:/root:/bin/sh\npdi:x:990:990:pdi:/nonexistent:/usr/sbin/nologin\n", 0o644)
    _write(target_root / "etc/group", "root:x:0:\npdi:x:990:\n", 0o644)
    for target in ("sysinit", "basic", "shutdown", "timers", "network-online"):
        _write(unit_dir / f"{target}.target", "[Unit]\nDescription=Synthetic static target\n", 0o644)

    release = target_root / "opt/pdi/releases" / args.release_sha
    executable = release / ".venv/bin/python"
    _write(executable, "#!/bin/sh\nexit 125\n", 0o755)
    (release / "src/pdi/production_ops").mkdir(parents=True)
    current = target_root / "opt/pdi/current"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.symlink_to(Path("/opt/pdi/releases") / args.release_sha)

    analyzer = shutil.which("systemd-analyze")
    if analyzer is None:
        raise SystemExit("P3D_SYSTEMD_STATIC=ANALYZER_MISSING")
    command = (
        analyzer, f"--root={target_root}", "--generators=no", "--man=no",
        "verify", *UNITS,
    )
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0:
        print("P3D_SYSTEMD_STATIC=FAIL")
        print(result.stderr, end="")
        return 1
    for name in UNITS:
        installed = unit_dir / name
        if installed.read_bytes() != (SYSTEMD_SOURCE / name).read_bytes():
            raise SystemExit("P3D_SYSTEMD_STATIC=BYTE_MISMATCH")
    if any(path.stat().st_mode & 0o077 for path in profile_dir.glob("*.env")):
        raise SystemExit("P3D_SYSTEMD_STATIC=PROFILE_MODE_INVALID")
    print("P3D_SYSTEMD_STATIC=PASS")
    print("P3D_SYSTEMD_STATIC_WORKLOAD_STARTED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
