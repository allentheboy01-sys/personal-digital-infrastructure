"""Disposable integration proofs for Gate B; no production configuration."""

from __future__ import annotations

from pathlib import Path
import subprocess
import zipfile

from pdi.production_ops.p3d_preparation_contracts import (
    OSRuntimeManifestV1,
    WheelhouseManifestV1,
    wheel_inventory_fingerprint,
)
from pdi.production_ops import p3d_release_bundle as subject


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(cwd), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(cwd),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        },
    )
    return result.stdout.strip()


def _wheel(
    path: Path, distribution: str, package: str, version: str,
    requires: tuple[str, ...] = (),
) -> Path:
    dist = distribution.replace("-", "_")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(f"{package}/__init__.py", "QUALIFICATION_ONLY = True\n")
        requirement_lines = "".join(f"Requires-Dist: {item}\n" for item in requires)
        archive.writestr(
            f"{dist}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n{requirement_lines}\n",
        )
        archive.writestr(
            f"{dist}-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: pdi-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
        )
        archive.writestr(f"{dist}-{version}.dist-info/RECORD", "")
    return path


def test_real_git_bundle_has_no_local_object_store_dependency(tmp_path: Path):
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "candidate.txt").write_text("exact candidate\n")
    _git(repo, "add", "candidate.txt")
    subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "-c", "user.name=PDI Test",
         "-c", "user.email=pdi-test@example.invalid", "commit", "--quiet", "-m", "candidate"],
        check=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(repo),
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0"},
    )
    candidate = _git(repo, "rev-parse", "HEAD")
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    bundle = tmp_path / "artifact/source/pdi.git.bundle"
    subject.create_and_verify_git_bundle(
        repo, candidate, bundle, work_root=work, home=home,
    )
    moved = tmp_path / "detached.bundle"
    bundle.replace(moved)
    source_objects = repo / ".git/objects"
    hidden_objects = tmp_path / "hidden-objects"
    source_objects.replace(hidden_objects)
    verify_root = tmp_path / "detached-verification"
    verify_root.mkdir()
    subject._verify_git_bundle_from_payload(moved, candidate, verify_root)


def test_real_fresh_venv_installs_only_hash_locked_disposable_wheelhouse(tmp_path: Path):
    root = tmp_path / "bundle"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    paths = (
        _wheel(
            wheelhouse / "pdi-0.6.0-py3-none-any.whl", "pdi", "pdi", "0.6.0",
            requires=("psycopg==3.3.4", "SQLAlchemy==2.0.52"),
        ),
        _wheel(wheelhouse / "psycopg-3.3.4-py3-none-any.whl", "psycopg", "psycopg", "3.3.4"),
        _wheel(wheelhouse / "sqlalchemy-2.0.52-py3-none-any.whl", "SQLAlchemy", "sqlalchemy", "2.0.52"),
    )
    os_manifest = OSRuntimeManifestV1.from_mapping({
        "MANIFEST_VERSION": "1", "OS_ID": "ubuntu", "OS_VERSION_ID": "24.04",
        "ARCH": "x86_64",
        "APPROVED_PACKAGE_NAMES_AND_VERSIONS": [
                {"NAME": "python313", "VERSION": "3.13.15"},
        ],
        "SYSTEM_PYTHON_PATH": "/usr/bin/python3.13", "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13.15", "PYTHON_ABI": "cp313",
        "SYSTEM_RUNTIME_FILE_SHA256": "1" * 64,
            "NATIVE_LIBRARY_PACKAGE_SET": ["python313"],
    })
    entries = tuple(subject.inspect_wheel(path).entry for path in paths)
    manifest = WheelhouseManifestV1.from_mapping({
        "MANIFEST_VERSION": "1", "PYTHON_IMPLEMENTATION": "CPython",
        "PYTHON_VERSION": "3.13.15", "PYTHON_ABI": "cp313",
        "PLATFORM_TAG": "manylinux_2_34_x86_64", "ARCH": "x86_64",
        "OS_RUNTIME_MANIFEST_SHA256": subject.os_runtime_manifest_fingerprint(os_manifest),
        "WHEELHOUSE_MANIFEST_SHA256": wheel_inventory_fingerprint(entries),
        "WHEELS": [entry.to_mapping() for entry in entries],
    })
    lock = root / "requirements/runtime.lock"
    lock.parent.mkdir()
    lock.write_bytes(subject.runtime_lock_bytes(manifest))
    manifest_path = root / "manifests/wheelhouse.json"
    manifest_path.parent.mkdir()
    manifest_path.write_bytes(subject.canonical_json_bytes(manifest.to_mapping()) + b"\n")
    subject.offline_install_proof(root)
