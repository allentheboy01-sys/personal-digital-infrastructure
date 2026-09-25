"""MU13-P3D Gate B release-input artifact authority.

The builder operates only in caller supplied build/output directories.  The
verifier is non-root, network-independent (apart from the separately executed
GitHub attestation check), and extracts archives only after validating every
member.  This module deliberately has no production installation capability.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable, Mapping, Sequence
import venv
import zipfile

from pdi.production_ops.p3d_preparation_contracts import (
    OSRuntimeManifestV1,
    OperatorToolIdentity,
    ReleaseInputBundleManifestV1,
    ToolName,
    WheelEntryV1,
    WheelhouseManifestV1,
    canonical_json_bytes,
    contract_fingerprint,
    os_runtime_manifest_fingerprint,
    release_bundle_fingerprint,
    wheel_inventory_fingerprint,
    wheelhouse_manifest_fingerprint,
)


GIT = Path("/usr/bin/git")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PACKAGE_NORMALIZER = re.compile(r"[-_.]+")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BUILDER_VERSION = "1.0.0"
BUNDLE_VERSION = "1"
AUTHORITY_CLASS = "QUALIFICATION_ONLY"
BUNDLE_PREFIX = "pdi-p3d-release-input"
CANONICAL_PIPELINES = (
    "enrichment.nextcloud_text",
    "enrichment.nextcloud_documents",
    "enrichment.file_metadata",
    "enrichment.immich_geo",
    "enrichment.immich_metadata",
    "enrichment.immich_ocr",
)
CANONICAL_SYSTEMD_ASSETS = (
    "pdi-scoped-pipeline@.service",
    "pdi-scoped-enrichment-nextcloud-text.timer",
    "pdi-scoped-enrichment-nextcloud-documents.timer",
    "pdi-scoped-enrichment-file-metadata.timer",
    "pdi-scoped-enrichment-immich-geo.timer",
    "pdi-scoped-enrichment-immich-metadata.timer",
    "pdi-scoped-enrichment-immich-ocr.timer",
)
FIXED_MEMBERS = frozenset({
    "manifests/release-input.json",
    "manifests/os-runtime.json",
    "manifests/wheelhouse.json",
    "manifests/files.json",
    "provenance/provenance.json",
    "source/pdi.git.bundle",
    "requirements/runtime.lock",
})
FILE_CLASSES = frozenset({
    "GIT_BUNDLE", "PDI_SDIST", "RUNTIME_WHEEL", "RUNTIME_LOCK", "SYSTEMD_UNIT",
})


class ReleaseBundleError(RuntimeError):
    """Fixed public failure code; sensitive subprocess details stay suppressed."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str = "P3D_RELEASE_BUNDLE_INVALID") -> None:
    raise ReleaseBundleError(code)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_text(value: Any, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or CONTROL.search(value):
        _fail("P3D_RELEASE_BUNDLE_SCHEMA_INVALID")
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail("P3D_RELEASE_BUNDLE_SCHEMA_INVALID")
    return value


def _exact(mapping: Mapping[str, Any], fields: set[str]) -> None:
    if not isinstance(mapping, Mapping) or set(mapping) != fields:
        _fail("P3D_RELEASE_BUNDLE_SCHEMA_INVALID")


def _relative_path(value: Any) -> str:
    text = _strict_text(value)
    path = PurePosixPath(text)
    if path.is_absolute() or text != path.as_posix() or ".." in path.parts or "." in path.parts:
        _fail("P3D_RELEASE_BUNDLE_PATH_INVALID")
    if not path.parts or any(not part for part in path.parts):
        _fail("P3D_RELEASE_BUNDLE_PATH_INVALID")
    return text


def _canonical_json_file(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    path.chmod(0o644)


def _parse_json(data: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("P3D_RELEASE_BUNDLE_JSON_INVALID")
    if not isinstance(value, Mapping):
        _fail("P3D_RELEASE_BUNDLE_JSON_INVALID")
    return value


def _fixed_git_env(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _fixed_python_env(*, network: bool) -> dict[str, str]:
    value = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
    }
    if not network:
        value["PIP_NO_INDEX"] = "1"
    else:
        # Transport-only allowlist. Pip indexes/configuration remain fixed by
        # argv and PIP_CONFIG_FILE; offline verification inherits none of this.
        for name in (
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
            "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
        ):
            item = os.environ.get(name)
            if item and not CONTROL.search(item):
                value[name] = item
    return value


def _run(
    argv: Sequence[str | os.PathLike[str]],
    *,
    env: Mapping[str, str],
    cwd: Path | None = None,
    capture: bool = True,
    failure_code: str = "P3D_RELEASE_BUNDLE_COMMAND_FAILED",
) -> subprocess.CompletedProcess[str]:
    if not argv or not Path(argv[0]).is_absolute():
        _fail("P3D_RELEASE_BUNDLE_EXECUTABLE_INVALID")
    try:
        return subprocess.run(
            [os.fspath(item) for item in argv],
            cwd=cwd,
            env=dict(env),
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except subprocess.CalledProcessError as error:
        fixed = re.search(r"(?:^|\n)FAILURE_CODE=(P3D_RELEASE_BUNDLE_[A-Z0-9_]+)(?:\n|$)", error.stderr or "")
        if fixed:
            _fail(fixed.group(1))
        _fail(failure_code)
    except OSError:
        _fail(failure_code)


def verify_clean_candidate_checkout(source: Path, candidate_sha: str, *, home: Path) -> None:
    source = source.resolve()
    _strict_text(candidate_sha, pattern=GIT_SHA)
    if not GIT.is_file() or not source.is_dir() or source.is_symlink():
        _fail("P3D_RELEASE_BUNDLE_SOURCE_INVALID")
    env = _fixed_git_env(home)
    head = _run((GIT, "-C", source, "rev-parse", "HEAD"), env=env).stdout.strip()
    if head != candidate_sha:
        _fail("P3D_RELEASE_BUNDLE_CANDIDATE_MISMATCH")
    status = _run(
        (GIT, "-C", source, "status", "--porcelain", "--untracked-files=all"), env=env,
    ).stdout
    if status:
        _fail("P3D_RELEASE_BUNDLE_SOURCE_DIRTY")


def create_and_verify_git_bundle(
    source: Path, candidate_sha: str, output: Path, *, work_root: Path, home: Path,
) -> None:
    env = _fixed_git_env(home)
    output.parent.mkdir(parents=True, exist_ok=True)
    _run((GIT, "-C", source, "bundle", "create", output, "HEAD"), env=env)
    empty = work_root / "empty-git-verification"
    empty.mkdir(mode=0o700)
    _run((GIT, "init", "--quiet", empty), env=env)
    _run((GIT, "-C", empty, "bundle", "verify", output), env=env)
    _run((GIT, "-C", empty, "fetch", "--quiet", output, "HEAD"), env=env)
    fetched = _run((GIT, "-C", empty, "rev-parse", "FETCH_HEAD"), env=env).stdout.strip()
    if fetched != candidate_sha:
        _fail("P3D_RELEASE_BUNDLE_GIT_INCOMPLETE")
    _run((GIT, "-C", empty, "cat-file", "-e", f"{candidate_sha}^{{commit}}"), env=env)
    _run((GIT, "-C", empty, "cat-file", "-e", f"{candidate_sha}^{{tree}}"), env=env)


def _safe_extract_source_archive(archive: Path, target: Path) -> None:
    target.mkdir(mode=0o700)
    with tarfile.open(archive, "r:") as stream:
        members = stream.getmembers()
        seen: set[str] = set()
        for member in members:
            name = _relative_path(member.name)
            if name in seen or not (member.isfile() or member.isdir()):
                _fail("P3D_RELEASE_BUNDLE_SOURCE_ARCHIVE_INVALID")
            seen.add(name)
        for member in members:
            destination = target / member.name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = stream.extractfile(member)
            if source is None:
                _fail("P3D_RELEASE_BUNDLE_SOURCE_ARCHIVE_INVALID")
            with destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(member.mode & 0o777)


def archive_exact_source(
    source: Path, candidate_sha: str, target: Path, *, work_root: Path, home: Path,
) -> None:
    archive = work_root / "candidate-source.tar"
    _run(
        (GIT, "-C", source, "archive", "--format=tar", f"--output={archive}", candidate_sha),
        env=_fixed_git_env(home),
    )
    _safe_extract_source_archive(archive, target)


def _tree_inventory(root: Path) -> dict[str, tuple[str, int]]:
    inventory: dict[str, tuple[str, int]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            _fail("P3D_RELEASE_BUNDLE_SOURCE_INVALID")
        if path.is_file():
            inventory[relative] = (sha256_file(path), path.stat().st_mode & 0o111)
    return inventory


def verify_source_tree_from_git_bundle(
    source_root: Path, git_bundle: Path, candidate_sha: str,
) -> None:
    """Prove that the build input tree is exactly the bundle candidate tree."""

    with tempfile.TemporaryDirectory(prefix="pdi-p3d-source-proof-") as raw:
        work = Path(raw)
        home = work / "home"
        home.mkdir(mode=0o700)
        repo = work / "repo"
        repo.mkdir()
        env = _fixed_git_env(home)
        failure = "P3D_RELEASE_BUNDLE_SOURCE_PROOF_FAILED"
        _run((GIT, "init", "--quiet", repo), env=env, failure_code=failure)
        _run(
            (GIT, "-C", repo, "bundle", "verify", git_bundle),
            env=env,
            failure_code=failure,
        )
        _run(
            (GIT, "-C", repo, "fetch", "--quiet", git_bundle, "HEAD"),
            env=env,
            failure_code=failure,
        )
        if _run(
            (GIT, "-C", repo, "rev-parse", "FETCH_HEAD"),
            env=env,
            failure_code=failure,
        ).stdout.strip() != candidate_sha:
            _fail("P3D_RELEASE_BUNDLE_CANDIDATE_MISMATCH")
        archive = work / "source.tar"
        _run(
            (GIT, "-C", repo, "archive", "--format=tar", f"--output={archive}", candidate_sha),
            env=env,
            failure_code=failure,
        )
        expected = work / "expected"
        _safe_extract_source_archive(archive, expected)
        if _tree_inventory(source_root) != _tree_inventory(expected):
            _fail("P3D_RELEASE_BUNDLE_SOURCE_INVALID")


def normalize_package_name(value: str) -> str:
    normalized = PACKAGE_NORMALIZER.sub("-", value).lower()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", normalized):
        _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
    return normalized


@dataclass(frozen=True)
class InspectedWheel:
    entry: WheelEntryV1
    metadata_name: str


def inspect_wheel(path: Path) -> InspectedWheel:
    if not path.is_file() or path.is_symlink() or path.suffix != ".whl":
        _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or archive.testzip() is not None:
                _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
            for info in infos:
                normalized = info.filename.rstrip("/")
                _relative_path(normalized)
                unix_mode = info.external_attr >> 16
                if stat.S_ISLNK(unix_mode) or info.flag_bits & 0x1:
                    _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
            metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
            wheel = [name for name in names if name.endswith(".dist-info/WHEEL")]
            if len(metadata) != 1 or len(wheel) != 1:
                _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
            parsed_metadata = BytesParser().parsebytes(archive.read(metadata[0]))
            parsed_wheel = BytesParser().parsebytes(archive.read(wheel[0]))
    except (OSError, zipfile.BadZipFile, KeyError):
        _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
    raw_name = parsed_metadata.get("Name")
    version = parsed_metadata.get("Version")
    tags = tuple(sorted(set(parsed_wheel.get_all("Tag", []))))
    if not raw_name or not version or not tags:
        _fail("P3D_RELEASE_BUNDLE_WHEEL_INVALID")
    package = normalize_package_name(raw_name)
    mapping = {
        "PACKAGE": package,
        "VERSION": version,
        "FILENAME": path.name,
        "SHA256": sha256_file(path),
        "TAGS": list(tags),
    }
    return InspectedWheel(WheelEntryV1.from_mapping(mapping), raw_name)


def _parse_manylinux(value: str) -> tuple[int, int, str] | None:
    aliases = {
        "manylinux1": (2, 5),
        "manylinux2010": (2, 12),
        "manylinux2014": (2, 17),
    }
    for prefix, version in aliases.items():
        marker = f"{prefix}_"
        if value.startswith(marker):
            return (*version, value.removeprefix(marker))
    match = re.fullmatch(r"manylinux_(\d+)_(\d+)_(.+)", value)
    if match:
        return int(match.group(1)), int(match.group(2)), match.group(3)
    return None


def _platform_compatible(wheel_platform: str, target_platform: str, arch: str) -> bool:
    if wheel_platform == "any":
        return True
    target = _parse_manylinux(target_platform)
    wheel = _parse_manylinux(wheel_platform)
    if target and wheel:
        return wheel[2] == target[2] == arch and wheel[:2] <= target[:2]
    return wheel_platform == target_platform and wheel_platform.endswith(f"_{arch}")


def compatible_pip_platforms(target_platform: str, arch: str) -> tuple[str, ...]:
    target = _parse_manylinux(target_platform)
    if target is None or target[0] != 2 or target[2] != arch:
        _fail("P3D_RELEASE_BUNDLE_OS_TARGET_INVALID")
    values = [f"manylinux_2_{minor}_{arch}" for minor in range(target[1], 4, -1)]
    aliases = ((17, "manylinux2014"), (12, "manylinux2010"), (5, "manylinux1"))
    values.extend(f"{name}_{arch}" for minor, name in aliases if minor <= target[1])
    return tuple(values)


def wheel_is_target_compatible(entry: WheelEntryV1, manifest: OSRuntimeManifestV1, platform_tag: str) -> bool:
    expected_python = "".join(manifest.python_version.split(".")[:2])
    expected_cp = f"cp{expected_python}"
    for compressed in entry.tags:
        parts = compressed.split("-")
        if len(parts) != 3:
            return False
        python_tags, abi_tags, platforms = (part.split(".") for part in parts)
        python_ok = any(tag in {"py3", f"py{expected_python}", expected_cp} for tag in python_tags)
        if "abi3" in abi_tags:
            for tag in python_tags:
                match = re.fullmatch(r"cp3(\d+)", tag)
                if match and int(match.group(1)) <= int(manifest.python_version.split(".")[1]):
                    python_ok = True
        abi_ok = any(tag in {"none", "abi3", expected_cp} for tag in abi_tags)
        platform_ok = any(
            _platform_compatible(item, platform_tag, manifest.arch) for item in platforms
        )
        if python_ok and abi_ok and platform_ok:
            return True
    return False


def load_os_runtime_manifest(path: Path) -> OSRuntimeManifestV1:
    if not path.is_file() or path.is_symlink():
        _fail("P3D_RELEASE_BUNDLE_OS_MANIFEST_INVALID")
    return OSRuntimeManifestV1.from_mapping(_parse_json(path.read_bytes()))


def build_wheelhouse_manifest(
    wheelhouse: Path, os_manifest: OSRuntimeManifestV1, platform_tag: str,
) -> WheelhouseManifestV1:
    paths = sorted(wheelhouse.glob("*.whl"), key=lambda item: item.name)
    if not paths or any(path.is_symlink() for path in paths):
        _fail("P3D_RELEASE_BUNDLE_WHEELHOUSE_INVALID")
    if set(wheelhouse.iterdir()) != set(paths):
        _fail("P3D_RELEASE_BUNDLE_WHEELHOUSE_INVALID")
    entries = tuple(sorted(inspect_wheel(path).entry for path in paths))
    if len({(entry.package, entry.version) for entry in entries}) != len(entries):
        _fail("P3D_RELEASE_BUNDLE_WHEELHOUSE_INVALID")
    if any(not wheel_is_target_compatible(entry, os_manifest, platform_tag) for entry in entries):
        _fail("P3D_RELEASE_BUNDLE_WHEEL_TARGET_INVALID")
    mapping = {
        "MANIFEST_VERSION": "1",
        "PYTHON_IMPLEMENTATION": os_manifest.python_implementation,
        "PYTHON_VERSION": os_manifest.python_version,
        "PYTHON_ABI": os_manifest.python_abi,
        "PLATFORM_TAG": platform_tag,
        "ARCH": os_manifest.arch,
        "OS_RUNTIME_MANIFEST_SHA256": os_runtime_manifest_fingerprint(os_manifest),
        "WHEELHOUSE_MANIFEST_SHA256": wheel_inventory_fingerprint(entries),
        "WHEELS": [entry.to_mapping() for entry in entries],
    }
    return WheelhouseManifestV1.from_mapping(mapping)


def runtime_lock_bytes(manifest: WheelhouseManifestV1) -> bytes:
    lines = [
        f"{entry.package}=={entry.version} --hash=sha256:{entry.sha256}"
        for entry in sorted(manifest.wheels)
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def verify_runtime_lock(data: bytes, manifest: WheelhouseManifestV1) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        _fail("P3D_RELEASE_BUNDLE_LOCK_INVALID")
    if data != runtime_lock_bytes(manifest) or not text.endswith("\n"):
        _fail("P3D_RELEASE_BUNDLE_LOCK_INVALID")
    for line in text.splitlines():
        if " @ " in line or line.startswith("-e ") or "http:" in line or "https:" in line:
            _fail("P3D_RELEASE_BUNDLE_LOCK_INVALID")


@dataclass(frozen=True, order=True)
class ReleaseBundleFileEntryV1:
    relative_path: str
    sha256: str
    size: int
    mode: str
    file_class: str

    FIELDS = {"RELATIVE_PATH", "SHA256", "SIZE", "MODE", "FILE_CLASS"}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReleaseBundleFileEntryV1":
        _exact(value, cls.FIELDS)
        path = _relative_path(value["RELATIVE_PATH"])
        sha = _strict_text(value["SHA256"], pattern=SHA256)
        size = value["SIZE"]
        mode = value["MODE"]
        file_class = value["FILE_CLASS"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            _fail("P3D_RELEASE_BUNDLE_FILE_MANIFEST_INVALID")
        if mode != "0644" or file_class not in FILE_CLASSES:
            _fail("P3D_RELEASE_BUNDLE_FILE_MANIFEST_INVALID")
        return cls(path, sha, size, mode, file_class)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "RELATIVE_PATH": self.relative_path,
            "SHA256": self.sha256,
            "SIZE": self.size,
            "MODE": self.mode,
            "FILE_CLASS": self.file_class,
        }


@dataclass(frozen=True)
class ReleaseBundleFileManifestV1:
    entries: tuple[ReleaseBundleFileEntryV1, ...]

    FIELDS = {"MANIFEST_VERSION", "SCOPE", "ENTRIES"}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReleaseBundleFileManifestV1":
        _exact(value, cls.FIELDS)
        if value["MANIFEST_VERSION"] != "1" or value["SCOPE"] != "PAYLOAD_ONLY":
            _fail("P3D_RELEASE_BUNDLE_FILE_MANIFEST_INVALID")
        raw = value["ENTRIES"]
        if not isinstance(raw, list) or not raw:
            _fail("P3D_RELEASE_BUNDLE_FILE_MANIFEST_INVALID")
        entries = tuple(sorted(ReleaseBundleFileEntryV1.from_mapping(item) for item in raw))
        if len({entry.relative_path for entry in entries}) != len(entries):
            _fail("P3D_RELEASE_BUNDLE_FILE_MANIFEST_INVALID")
        return cls(entries)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "MANIFEST_VERSION": "1",
            "SCOPE": "PAYLOAD_ONLY",
            "ENTRIES": [entry.to_mapping() for entry in self.entries],
        }


@dataclass(frozen=True)
class SystemdAssetV1:
    source_path: str
    target_path: str
    sha256: str
    mode: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "SOURCE_PATH": self.source_path,
            "TARGET_PATH": self.target_path,
            "SHA256": self.sha256,
            "MODE": self.mode,
        }


def collect_systemd_assets(source_root: Path, payload_root: Path) -> tuple[SystemdAssetV1, ...]:
    systemd = source_root / "deployment/systemd"
    actual = {path.name for path in systemd.glob("pdi-scoped-enrichment-*.timer")}
    if actual != set(CANONICAL_SYSTEMD_ASSETS[1:]):
        _fail("P3D_RELEASE_BUNDLE_SYSTEMD_SET_INVALID")
    assets: list[SystemdAssetV1] = []
    for name in CANONICAL_SYSTEMD_ASSETS:
        source = systemd / name
        if not source.is_file() or source.is_symlink():
            _fail("P3D_RELEASE_BUNDLE_SYSTEMD_SET_INVALID")
        destination = payload_root / "systemd" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
        assets.append(SystemdAssetV1(
            f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
            sha256_file(destination), "0644",
        ))
    return tuple(assets)


def systemd_asset_fingerprint(assets: Sequence[SystemdAssetV1]) -> str:
    ordered = sorted(assets, key=lambda item: item.source_path)
    if len(ordered) != 7 or {PurePosixPath(item.source_path).name for item in ordered} != set(CANONICAL_SYSTEMD_ASSETS):
        _fail("P3D_RELEASE_BUNDLE_SYSTEMD_SET_INVALID")
    return contract_fingerprint({"SYSTEMD_ASSETS": [item.to_mapping() for item in ordered]})


@dataclass(frozen=True)
class P3DReleaseBundleProvenanceV1:
    repository_identity: str
    candidate_sha: str
    workflow_identity: str
    workflow_source_sha: str
    run_identity: str
    run_attempt: str
    artifact_identity: str
    builder_tool: OperatorToolIdentity
    git_bundle_sha256: str
    pdi_wheel_sha256: str
    pdi_sdist_sha256: str
    wheelhouse_manifest_sha256: str
    os_runtime_manifest_sha256: str
    systemd_asset_fingerprint: str
    runtime_lock_sha256: str
    file_manifest_sha256: str

    FIELDS = {
        "PROVENANCE_VERSION", "AUTHORITY_CLASS", "REPOSITORY_IDENTITY",
        "CANDIDATE_SHA", "WORKFLOW_IDENTITY", "WORKFLOW_SOURCE_SHA",
        "RUN_IDENTITY", "RUN_ATTEMPT", "ARTIFACT_IDENTITY", "BUILDER_TOOL",
        "GIT_BUNDLE_SHA256", "PDI_WHEEL_SHA256", "PDI_SDIST_SHA256",
        "WHEELHOUSE_MANIFEST_SHA256", "OS_RUNTIME_MANIFEST_SHA256",
        "SYSTEMD_ASSET_FINGERPRINT", "RUNTIME_LOCK_SHA256", "FILE_MANIFEST_SHA256",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "P3DReleaseBundleProvenanceV1":
        _exact(value, cls.FIELDS)
        if value["PROVENANCE_VERSION"] != "1" or value["AUTHORITY_CLASS"] != AUTHORITY_CLASS:
            _fail("P3D_RELEASE_BUNDLE_PROVENANCE_INVALID")
        candidate = _strict_text(value["CANDIDATE_SHA"], pattern=GIT_SHA)
        workflow_source = _strict_text(value["WORKFLOW_SOURCE_SHA"], pattern=GIT_SHA)
        builder = OperatorToolIdentity.from_mapping(value["BUILDER_TOOL"])
        if (workflow_source != candidate or builder.tool_source_sha != candidate or
                builder.tool_name is not ToolName.RELEASE_BUNDLE_BUILD or
                builder.tool_artifact_sha256 != value["PDI_WHEEL_SHA256"]):
            _fail("P3D_RELEASE_BUNDLE_PROVENANCE_INVALID")
        return cls(
            _strict_text(value["REPOSITORY_IDENTITY"]), candidate,
            _strict_text(value["WORKFLOW_IDENTITY"]), workflow_source,
            _strict_text(value["RUN_IDENTITY"]), _strict_text(value["RUN_ATTEMPT"]),
            _strict_text(value["ARTIFACT_IDENTITY"]), builder,
            *(_strict_text(value[key], pattern=SHA256) for key in (
                "GIT_BUNDLE_SHA256", "PDI_WHEEL_SHA256", "PDI_SDIST_SHA256",
                "WHEELHOUSE_MANIFEST_SHA256", "OS_RUNTIME_MANIFEST_SHA256",
                "SYSTEMD_ASSET_FINGERPRINT", "RUNTIME_LOCK_SHA256",
                "FILE_MANIFEST_SHA256",
            )),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "PROVENANCE_VERSION": "1",
            "AUTHORITY_CLASS": AUTHORITY_CLASS,
            "REPOSITORY_IDENTITY": self.repository_identity,
            "CANDIDATE_SHA": self.candidate_sha,
            "WORKFLOW_IDENTITY": self.workflow_identity,
            "WORKFLOW_SOURCE_SHA": self.workflow_source_sha,
            "RUN_IDENTITY": self.run_identity,
            "RUN_ATTEMPT": self.run_attempt,
            "ARTIFACT_IDENTITY": self.artifact_identity,
            "BUILDER_TOOL": self.builder_tool.to_mapping(),
            "GIT_BUNDLE_SHA256": self.git_bundle_sha256,
            "PDI_WHEEL_SHA256": self.pdi_wheel_sha256,
            "PDI_SDIST_SHA256": self.pdi_sdist_sha256,
            "WHEELHOUSE_MANIFEST_SHA256": self.wheelhouse_manifest_sha256,
            "OS_RUNTIME_MANIFEST_SHA256": self.os_runtime_manifest_sha256,
            "SYSTEMD_ASSET_FINGERPRINT": self.systemd_asset_fingerprint,
            "RUNTIME_LOCK_SHA256": self.runtime_lock_sha256,
            "FILE_MANIFEST_SHA256": self.file_manifest_sha256,
        }


def _payload_entry(path: Path, root: Path, file_class: str, mode: str = "0644") -> ReleaseBundleFileEntryV1:
    relative = path.relative_to(root).as_posix()
    return ReleaseBundleFileEntryV1(relative, sha256_file(path), path.stat().st_size, mode, file_class)


def _write_canonical_tar(root: Path, members: Sequence[str], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for relative in sorted(members):
                relative = _relative_path(relative)
                source = root / relative
                if not source.is_file() or source.is_symlink():
                    _fail("P3D_RELEASE_BUNDLE_ARCHIVE_INVALID")
                info = tarfile.TarInfo(relative)
                info.size = source.stat().st_size
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.pax_headers = {}
                with source.open("rb") as stream:
                    archive.addfile(info, stream)


def _canonical_pax_headers(name: str) -> dict[str, str]:
    return {"path": name} if len(name.encode("utf-8")) > tarfile.LENGTH_NAME else {}


def _validate_archive_member(member: tarfile.TarInfo, seen: set[str]) -> str:
    name = _relative_path(member.name)
    if name in seen or not member.isfile() or member.islnk() or member.issym():
        _fail("P3D_RELEASE_BUNDLE_ARCHIVE_INVALID")
    if (member.uid, member.gid, member.uname, member.gname, member.mtime, member.mode) != (0, 0, "", "", 0, 0o644):
        _fail("P3D_RELEASE_BUNDLE_ARCHIVE_METADATA_INVALID")
    expected_pax_headers = _canonical_pax_headers(name)
    if member.pax_headers != expected_pax_headers:
        _fail("P3D_RELEASE_BUNDLE_ARCHIVE_METADATA_INVALID")
    seen.add(name)
    return name


def safe_extract_bundle(bundle: Path, target: Path) -> tuple[str, ...]:
    target.mkdir(mode=0o700)
    try:
        with tarfile.open(bundle, "r:") as archive:
            members = archive.getmembers()
            seen: set[str] = set()
            names = tuple(_validate_archive_member(member, seen) for member in members)
            for member in members:
                destination = target / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    _fail("P3D_RELEASE_BUNDLE_ARCHIVE_INVALID")
                with destination.open("xb") as output:
                    shutil.copyfileobj(source, output)
                destination.chmod(0o644)
    except (OSError, tarfile.TarError, FileExistsError):
        _fail("P3D_RELEASE_BUNDLE_ARCHIVE_INVALID")
    return names


def _verify_file_manifest(root: Path, value: ReleaseBundleFileManifestV1) -> None:
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*") if path.is_file()
    } - {
        "manifests/files.json", "manifests/release-input.json",
        "manifests/os-runtime.json", "manifests/wheelhouse.json",
        "provenance/provenance.json",
    }
    expected = {entry.relative_path for entry in value.entries}
    if actual != expected:
        _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")
    by_class: dict[str, set[str]] = {name: set() for name in FILE_CLASSES}
    for entry in value.entries:
        path = root / entry.relative_path
        if not path.is_file() or path.is_symlink():
            _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")
        if path.stat().st_size != entry.size or sha256_file(path) != entry.sha256:
            _fail("P3D_RELEASE_BUNDLE_FILE_HASH_INVALID")
        by_class[entry.file_class].add(entry.relative_path)
    if by_class["GIT_BUNDLE"] != {"source/pdi.git.bundle"}:
        _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")
    if len(by_class["PDI_SDIST"]) != 1 or not next(iter(by_class["PDI_SDIST"])).startswith("dist/pdi-"):
        _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")
    if by_class["RUNTIME_LOCK"] != {"requirements/runtime.lock"}:
        _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")
    if by_class["RUNTIME_WHEEL"] != {
            f"wheelhouse/{path.name}" for path in (root / "wheelhouse").iterdir()}:
        _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")
    if by_class["SYSTEMD_UNIT"] != {f"systemd/{name}" for name in CANONICAL_SYSTEMD_ASSETS}:
        _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")


def verify_builder_runtime(candidate_wheel: Path) -> None:
    expected = Path(__file__).read_bytes()
    member = "pdi/production_ops/p3d_release_bundle.py"
    try:
        with zipfile.ZipFile(candidate_wheel) as archive:
            wheel_bytes = archive.read(member)
    except (OSError, KeyError, zipfile.BadZipFile):
        _fail("P3D_RELEASE_BUNDLE_BUILDER_INVALID")
    if wheel_bytes != expected:
        _fail("P3D_RELEASE_BUNDLE_BUILDER_INVALID")


def _python_version_parts(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?", value)
    if not match:
        _fail("P3D_RELEASE_BUNDLE_OS_MANIFEST_INVALID")
    return int(match.group(1)), int(match.group(2))


def _validate_builder_target(os_manifest: OSRuntimeManifestV1) -> None:
    if os_manifest.python_implementation.lower() != platform.python_implementation().lower():
        _fail("P3D_RELEASE_BUNDLE_OS_TARGET_INVALID")
    if _python_version_parts(os_manifest.python_version) != sys.version_info[:2]:
        _fail("P3D_RELEASE_BUNDLE_OS_TARGET_INVALID")
    if os_manifest.python_abi != f"cp{sys.version_info.major}{sys.version_info.minor}":
        _fail("P3D_RELEASE_BUNDLE_OS_TARGET_INVALID")
    arch_aliases = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
    if arch_aliases.get(platform.machine().lower()) != arch_aliases.get(os_manifest.arch.lower()):
        _fail("P3D_RELEASE_BUNDLE_OS_TARGET_INVALID")


@dataclass(frozen=True)
class AssembleInputs:
    candidate_sha: str
    source_root: Path
    git_bundle: Path
    pdi_wheel: Path
    pdi_sdist: Path
    os_manifest_path: Path
    platform_tag: str
    repository_identity: str
    workflow_path: str
    run_identity: str
    run_attempt: str
    output_dir: Path


def assemble_release_input_bundle(inputs: AssembleInputs) -> tuple[Path, dict[str, str]]:
    candidate = _strict_text(inputs.candidate_sha, pattern=GIT_SHA)
    verify_builder_runtime(inputs.pdi_wheel)
    verify_source_tree_from_git_bundle(inputs.source_root, inputs.git_bundle, candidate)
    os_manifest = load_os_runtime_manifest(inputs.os_manifest_path)
    _validate_builder_target(os_manifest)
    target_platform = _parse_manylinux(inputs.platform_tag)
    if target_platform is None or target_platform[2] != os_manifest.arch:
        _fail("P3D_RELEASE_BUNDLE_OS_TARGET_INVALID")
    inputs.output_dir.mkdir(parents=True, exist_ok=True)
    if any(inputs.output_dir.iterdir()):
        _fail("P3D_RELEASE_BUNDLE_OUTPUT_NOT_EMPTY")
    with tempfile.TemporaryDirectory(prefix="pdi-p3d-assemble-") as raw:
        work = Path(raw)
        payload = work / "payload"
        payload.mkdir()
        source_bundle = payload / "source/pdi.git.bundle"
        source_bundle.parent.mkdir(parents=True)
        shutil.copyfile(inputs.git_bundle, source_bundle)
        source_bundle.chmod(0o644)

        dist = payload / "dist"
        dist.mkdir()
        sdist = dist / inputs.pdi_sdist.name
        shutil.copyfile(inputs.pdi_sdist, sdist)
        sdist.chmod(0o644)

        wheelhouse = payload / "wheelhouse"
        wheelhouse.mkdir()
        constraints = inputs.source_root / "constraints/python3.13.txt"
        if not constraints.is_file() or constraints.is_symlink():
            _fail("P3D_RELEASE_BUNDLE_CONSTRAINTS_INVALID")
        python = _current_python_executable()
        platform_arguments = tuple(
            item
            for value in compatible_pip_platforms(inputs.platform_tag, os_manifest.arch)
            for item in ("--platform", value)
        )
        download_command = (
            python, "-m", "pip", "download", "--dest", wheelhouse,
            "--only-binary=:all:", *platform_arguments,
            "--python-version", ".".join(map(str, sys.version_info[:2])),
            "--implementation", "cp", "--abi", f"cp{sys.version_info.major}{sys.version_info.minor}",
            "--constraint", constraints, "--index-url", "https://pypi.org/simple",
            inputs.pdi_wheel,
        )
        _run(
            download_command,
            env=_fixed_python_env(network=True),
            capture=False,
            failure_code="P3D_RELEASE_BUNDLE_WHEELHOUSE_RESOLUTION_FAILED",
        )
        wheel_manifest = build_wheelhouse_manifest(wheelhouse, os_manifest, inputs.platform_tag)
        pdi_entries = [entry for entry in wheel_manifest.wheels if entry.package == "pdi"]
        if len(pdi_entries) != 1 or pdi_entries[0].sha256 != sha256_file(inputs.pdi_wheel):
            _fail("P3D_RELEASE_BUNDLE_PDI_WHEEL_INVALID")

        lock = payload / "requirements/runtime.lock"
        lock.parent.mkdir(parents=True)
        lock.write_bytes(runtime_lock_bytes(wheel_manifest))
        lock.chmod(0o644)
        systemd_assets = collect_systemd_assets(inputs.source_root, payload)
        systemd_fingerprint = systemd_asset_fingerprint(systemd_assets)

        entries = [
            _payload_entry(source_bundle, payload, "GIT_BUNDLE"),
            _payload_entry(sdist, payload, "PDI_SDIST"),
            _payload_entry(lock, payload, "RUNTIME_LOCK"),
        ]
        entries.extend(_payload_entry(path, payload, "RUNTIME_WHEEL") for path in sorted(wheelhouse.iterdir()))
        entries.extend(
            _payload_entry(payload / "systemd" / name, payload, "SYSTEMD_UNIT")
            for name in CANONICAL_SYSTEMD_ASSETS
        )
        file_manifest = ReleaseBundleFileManifestV1(tuple(sorted(entries)))
        files_canonical = canonical_json_bytes(file_manifest.to_mapping())
        files_bytes = files_canonical + b"\n"
        (payload / "manifests").mkdir()
        (payload / "manifests/files.json").write_bytes(files_bytes)
        (payload / "manifests/files.json").chmod(0o644)

        os_hash = os_runtime_manifest_fingerprint(os_manifest)
        wheelhouse_hash = wheelhouse_manifest_fingerprint(wheel_manifest)
        workflow_identity = f"github:{inputs.repository_identity}@{candidate}:{inputs.workflow_path}"
        artifact_name = f"{BUNDLE_PREFIX}-{candidate}"
        artifact_identity = f"github-run:{inputs.run_identity}:{inputs.run_attempt}:{artifact_name}"
        wheel_hash = sha256_file(inputs.pdi_wheel)
        builder = OperatorToolIdentity.from_mapping({
            "TOOL_NAME": ToolName.RELEASE_BUNDLE_BUILD.value,
            "TOOL_VERSION": BUILDER_VERSION,
            "TOOL_ARTIFACT_SHA256": wheel_hash,
            "TOOL_SOURCE_SHA": candidate,
        })
        provenance = P3DReleaseBundleProvenanceV1(
            inputs.repository_identity, candidate, workflow_identity, candidate,
            inputs.run_identity, inputs.run_attempt, artifact_identity, builder,
            sha256_file(inputs.git_bundle), wheel_hash, sha256_file(inputs.pdi_sdist),
            wheelhouse_hash, os_hash, systemd_fingerprint, sha256_file(lock),
            _sha256_bytes(files_canonical),
        )
        provenance_canonical = canonical_json_bytes(provenance.to_mapping())
        provenance_bytes = provenance_canonical + b"\n"
        release_manifest = ReleaseInputBundleManifestV1.from_mapping({
            "MANIFEST_VERSION": "1",
            "CANDIDATE_SHA": candidate,
            "GIT_BUNDLE_SHA256": sha256_file(inputs.git_bundle),
            "GIT_BUNDLE_SOURCE_SHA": candidate,
            "PDI_WHEEL_SHA256": wheel_hash,
            "PDI_WHEEL_SOURCE_SHA": candidate,
            "PDI_SDIST_SHA256": sha256_file(inputs.pdi_sdist),
            "PDI_SDIST_SOURCE_SHA": candidate,
            "WHEELHOUSE_MANIFEST_SHA256": wheelhouse_hash,
            "OS_RUNTIME_MANIFEST_SHA256": os_hash,
            "SYSTEMD_ASSET_FINGERPRINT": systemd_fingerprint,
            "BUILD_WORKFLOW_IDENTITY": workflow_identity,
            "BUILD_ARTIFACT_IDENTITY": artifact_identity,
            "PROVENANCE_SHA256": _sha256_bytes(provenance_canonical),
            "BUILDER_TOOL": builder.to_mapping(),
        })
        _canonical_json_file(payload / "manifests/os-runtime.json", os_manifest.to_mapping())
        _canonical_json_file(payload / "manifests/wheelhouse.json", wheel_manifest.to_mapping())
        (payload / "provenance").mkdir()
        (payload / "provenance/provenance.json").write_bytes(provenance_bytes)
        (payload / "provenance/provenance.json").chmod(0o644)
        _canonical_json_file(payload / "manifests/release-input.json", release_manifest.to_mapping())

        member_names = tuple(
            path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file()
        )
        bundle = inputs.output_dir / f"{artifact_name}.tar"
        _write_canonical_tar(payload, member_names, bundle)
        bundle_hash = sha256_file(bundle)
        digests = {
            "CANDIDATE_SHA": candidate,
            "BUNDLE_SHA256": bundle_hash,
            "RELEASE_INPUT_MANIFEST_SHA256": release_bundle_fingerprint(release_manifest),
            "PROVENANCE_SHA256": _sha256_bytes(provenance_canonical),
            "OS_RUNTIME_MANIFEST_SHA256": os_hash,
            "WHEELHOUSE_MANIFEST_SHA256": wheelhouse_hash,
            "SYSTEMD_ASSET_FINGERPRINT": systemd_fingerprint,
        }
        _canonical_json_file(inputs.output_dir / f"{artifact_name}.digests.json", digests)
        return bundle, digests


def _verify_git_bundle_from_payload(path: Path, candidate: str, root: Path) -> None:
    home = root / "git-home"
    home.mkdir(mode=0o700)
    env = _fixed_git_env(home)
    empty = root / "empty-repo"
    empty.mkdir()
    _run((GIT, "init", "--quiet", empty), env=env)
    _run((GIT, "-C", empty, "bundle", "verify", path), env=env)
    _run((GIT, "-C", empty, "fetch", "--quiet", path, "HEAD"), env=env)
    if _run((GIT, "-C", empty, "rev-parse", "FETCH_HEAD"), env=env).stdout.strip() != candidate:
        _fail("P3D_RELEASE_BUNDLE_GIT_INCOMPLETE")
    _run((GIT, "-C", empty, "cat-file", "-e", f"{candidate}^{{tree}}"), env=env)


def inspect_sdist(path: Path) -> tuple[str, str]:
    if (not path.is_file() or path.is_symlink() or
            not path.name.startswith("pdi-") or not path.name.endswith(".tar.gz")):
        _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            seen: set[str] = set()
            roots: set[str] = set()
            for member in members:
                name = _relative_path(member.name)
                if name in seen or not (member.isfile() or member.isdir()):
                    _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
                seen.add(name)
                roots.add(PurePosixPath(name).parts[0])
            if len(roots) != 1:
                _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
            root = next(iter(roots))
            package_info = next(
                (member for member in members if member.name == f"{root}/PKG-INFO"), None,
            )
            if package_info is None or not package_info.isfile():
                _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
            stream = archive.extractfile(package_info)
            if stream is None:
                _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
            metadata = BytesParser().parsebytes(stream.read())
    except (OSError, tarfile.TarError):
        _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or normalize_package_name(name) != "pdi" or not version:
        _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
    if root != f"pdi-{version}" or path.name != f"pdi-{version}.tar.gz":
        _fail("P3D_RELEASE_BUNDLE_SDIST_INVALID")
    return "pdi", version


def _verify_systemd_payload(root: Path, expected_fingerprint: str) -> None:
    systemd = root / "systemd"
    actual = {path.name for path in systemd.iterdir()} if systemd.is_dir() else set()
    if actual != set(CANONICAL_SYSTEMD_ASSETS):
        _fail("P3D_RELEASE_BUNDLE_SYSTEMD_SET_INVALID")
    assets = tuple(
        SystemdAssetV1(
            f"deployment/systemd/{name}", f"/etc/systemd/system/{name}",
            sha256_file(systemd / name), "0644",
        )
        for name in CANONICAL_SYSTEMD_ASSETS
    )
    if systemd_asset_fingerprint(assets) != expected_fingerprint:
        _fail("P3D_RELEASE_BUNDLE_SYSTEMD_HASH_INVALID")


def offline_install_proof(root: Path, *, python: Path | None = None) -> None:
    python = (python or Path(sys.executable)).resolve()
    environment = root.parent / "offline-venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    venv_python = environment / "bin/python"
    wheel_manifest = WheelhouseManifestV1.from_mapping(
        _parse_json((root / "manifests/wheelhouse.json").read_bytes())
    )
    pdi_entries = [entry for entry in wheel_manifest.wheels if entry.package == "pdi"]
    if len(pdi_entries) != 1:
        _fail("P3D_RELEASE_BUNDLE_DEPENDENCY_CLOSURE_INVALID")
    report = root.parent / "offline-resolution-report.json"
    _run(
        (
            venv_python, "-m", "pip", "install", "--dry-run", "--ignore-installed",
            "--no-index", "--find-links", root / "wheelhouse", "--report", report,
            f"pdi=={pdi_entries[0].version}",
        ),
        env=_fixed_python_env(network=False), capture=False,
    )
    try:
        report_value = json.loads(report.read_text(encoding="utf-8"))
        installs = report_value["install"]
        resolved = {
            (
                normalize_package_name(item["metadata"]["name"]),
                item["metadata"]["version"],
                item["download_info"]["archive_info"]["hashes"]["sha256"],
            )
            for item in installs
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        _fail("P3D_RELEASE_BUNDLE_DEPENDENCY_CLOSURE_INVALID")
    expected = {(entry.package, entry.version, entry.sha256) for entry in wheel_manifest.wheels}
    if resolved != expected or len(resolved) != len(installs):
        _fail("P3D_RELEASE_BUNDLE_DEPENDENCY_CLOSURE_INVALID")
    _run(
        (
            venv_python, "-m", "pip", "install", "--no-index",
            "--find-links", root / "wheelhouse", "--require-hashes",
            "-r", root / "requirements/runtime.lock",
        ),
        env=_fixed_python_env(network=False), capture=False,
    )
    _run((venv_python, "-m", "pip", "check"), env=_fixed_python_env(network=False))
    _run(
        (venv_python, "-c", "import pdi, psycopg, sqlalchemy"),
        env=_fixed_python_env(network=False),
    )


def verify_release_input_bundle(
    bundle: Path,
    *,
    expected_candidate_sha: str,
    expected_bundle_sha256: str,
    expected_os_manifest_sha256: str | None = None,
    perform_offline_install: bool = True,
) -> dict[str, str]:
    candidate = _strict_text(expected_candidate_sha, pattern=GIT_SHA)
    expected_hash = _strict_text(expected_bundle_sha256, pattern=SHA256)
    if not bundle.is_file() or bundle.is_symlink() or sha256_file(bundle) != expected_hash:
        _fail("P3D_RELEASE_BUNDLE_OUTER_HASH_INVALID")
    with tempfile.TemporaryDirectory(prefix="pdi-p3d-verify-") as raw:
        work = Path(raw)
        root = work / "bundle"
        names = safe_extract_bundle(bundle, root)
        name_set = set(names)
        if not FIXED_MEMBERS.issubset(name_set):
            _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")

        file_manifest_bytes = (root / "manifests/files.json").read_bytes()
        file_manifest = ReleaseBundleFileManifestV1.from_mapping(_parse_json(file_manifest_bytes))
        _verify_file_manifest(root, file_manifest)
        expected_all = {entry.relative_path for entry in file_manifest.entries} | {
            "manifests/files.json", "manifests/release-input.json", "manifests/os-runtime.json",
            "manifests/wheelhouse.json", "provenance/provenance.json",
        }
        if name_set != expected_all:
            _fail("P3D_RELEASE_BUNDLE_FILE_SET_INVALID")

        os_bytes = (root / "manifests/os-runtime.json").read_bytes()
        os_manifest = OSRuntimeManifestV1.from_mapping(_parse_json(os_bytes))
        os_hash = os_runtime_manifest_fingerprint(os_manifest)
        if expected_os_manifest_sha256 is not None and os_hash != expected_os_manifest_sha256:
            _fail("P3D_RELEASE_BUNDLE_OS_MANIFEST_INVALID")

        wheel_bytes = (root / "manifests/wheelhouse.json").read_bytes()
        wheel_manifest = WheelhouseManifestV1.from_mapping(_parse_json(wheel_bytes))
        if wheel_manifest.os_runtime_manifest_sha256 != os_hash:
            _fail("P3D_RELEASE_BUNDLE_OS_MANIFEST_INVALID")
        actual_wheels = {path.name for path in (root / "wheelhouse").iterdir()}
        expected_wheels = {entry.filename for entry in wheel_manifest.wheels}
        if actual_wheels != expected_wheels:
            _fail("P3D_RELEASE_BUNDLE_WHEELHOUSE_INVALID")
        for entry in wheel_manifest.wheels:
            path = root / "wheelhouse" / entry.filename
            inspected = inspect_wheel(path).entry
            if inspected != entry or not wheel_is_target_compatible(entry, os_manifest, wheel_manifest.platform_tag):
                _fail("P3D_RELEASE_BUNDLE_WHEELHOUSE_INVALID")
        verify_runtime_lock((root / "requirements/runtime.lock").read_bytes(), wheel_manifest)

        provenance_bytes = (root / "provenance/provenance.json").read_bytes()
        provenance = P3DReleaseBundleProvenanceV1.from_mapping(_parse_json(provenance_bytes))
        release = ReleaseInputBundleManifestV1.from_mapping(
            _parse_json((root / "manifests/release-input.json").read_bytes())
        )
        pdi_wheels = [entry for entry in wheel_manifest.wheels if entry.package == "pdi"]
        sdists = list((root / "dist").iterdir()) if (root / "dist").is_dir() else []
        if len(pdi_wheels) != 1 or len(sdists) != 1:
            _fail("P3D_RELEASE_BUNDLE_DISTRIBUTION_INVALID")
        sdist_name, sdist_version = inspect_sdist(sdists[0])
        if sdist_name != pdi_wheels[0].package or sdist_version != pdi_wheels[0].version:
            _fail("P3D_RELEASE_BUNDLE_DISTRIBUTION_INVALID")
        cross = (
            release.candidate_sha == candidate == provenance.candidate_sha,
            release.git_bundle_sha256 == provenance.git_bundle_sha256 == sha256_file(root / "source/pdi.git.bundle"),
            release.pdi_wheel_sha256 == provenance.pdi_wheel_sha256 == pdi_wheels[0].sha256,
            release.pdi_sdist_sha256 == provenance.pdi_sdist_sha256 == sha256_file(sdists[0]),
            release.wheelhouse_manifest_sha256 == provenance.wheelhouse_manifest_sha256 == wheelhouse_manifest_fingerprint(wheel_manifest),
            release.os_runtime_manifest_sha256 == provenance.os_runtime_manifest_sha256 == os_hash,
            release.provenance_sha256 == contract_fingerprint(provenance.to_mapping()),
            provenance.runtime_lock_sha256 == sha256_file(root / "requirements/runtime.lock"),
            provenance.file_manifest_sha256 == contract_fingerprint(file_manifest.to_mapping()),
            release.builder_tool.tool_artifact_sha256 == release.pdi_wheel_sha256,
            release.builder_tool == provenance.builder_tool,
        )
        if not all(cross):
            _fail("P3D_RELEASE_BUNDLE_CROSS_BINDING_INVALID")
        _verify_git_bundle_from_payload(root / "source/pdi.git.bundle", candidate, work)
        _verify_systemd_payload(root, release.systemd_asset_fingerprint)
        if perform_offline_install:
            offline_install_proof(root)
        return {
            "CANDIDATE_SHA": candidate,
            "BUNDLE_SHA256": expected_hash,
            "RELEASE_INPUT_MANIFEST_SHA256": release_bundle_fingerprint(release),
            "PROVENANCE_SHA256": release.provenance_sha256,
            "OS_RUNTIME_MANIFEST_SHA256": os_hash,
            "WHEELHOUSE_MANIFEST_SHA256": wheelhouse_manifest_fingerprint(wheel_manifest),
            "SYSTEMD_ASSET_FINGERPRINT": release.systemd_asset_fingerprint,
        }


def _build_distributions(source_tree: Path, output: Path, python: Path) -> tuple[Path, Path]:
    output.mkdir()
    _run(
        (python, "-m", "build", "--no-isolation", "--wheel", "--sdist", "--outdir", output),
        cwd=source_tree, env=_fixed_python_env(network=False), capture=False,
        failure_code="P3D_RELEASE_BUNDLE_DISTRIBUTION_BUILD_FAILED",
    )
    wheels = list(output.glob("*.whl"))
    sdists = list(output.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        _fail("P3D_RELEASE_BUNDLE_DISTRIBUTION_INVALID")
    inspected_wheel = inspect_wheel(wheels[0]).entry
    sdist_name, sdist_version = inspect_sdist(sdists[0])
    if inspected_wheel.package != sdist_name or inspected_wheel.version != sdist_version:
        _fail("P3D_RELEASE_BUNDLE_DISTRIBUTION_INVALID")
    return wheels[0], sdists[0]


def _current_python_executable() -> Path:
    """Keep the active environment boundary; do not dereference venv Python."""

    python = Path(sys.executable)
    if not python.is_absolute() or not python.is_file():
        _fail("P3D_RELEASE_BUNDLE_PYTHON_INVALID")
    return python


def build_release_input_bundle(
    *,
    source: Path,
    candidate_sha: str,
    os_manifest: Path,
    platform_tag: str,
    repository_identity: str,
    workflow_path: str,
    run_identity: str,
    run_attempt: str,
    output_dir: Path,
) -> tuple[Path, dict[str, str]]:
    candidate = _strict_text(candidate_sha, pattern=GIT_SHA)
    source = source.resolve()
    repository_identity = _strict_text(repository_identity)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository_identity):
        _fail("P3D_RELEASE_BUNDLE_REPOSITORY_INVALID")
    workflow_path = _relative_path(workflow_path)
    if not workflow_path.startswith(".github/workflows/"):
        _fail("P3D_RELEASE_BUNDLE_WORKFLOW_INVALID")
    _strict_text(platform_tag)
    _strict_text(run_identity)
    _strict_text(run_attempt)
    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        _fail("P3D_RELEASE_BUNDLE_OUTPUT_NOT_EMPTY")
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pdi-p3d-build-") as raw:
        work = Path(raw)
        home = work / "home"
        home.mkdir(mode=0o700)
        verify_clean_candidate_checkout(source, candidate, home=home)
        candidate_source = work / "source"
        archive_exact_source(source, candidate, candidate_source, work_root=work, home=home)
        build_source = work / "build-source"
        shutil.copytree(candidate_source, build_source)
        git_bundle = work / "pdi.git.bundle"
        create_and_verify_git_bundle(source, candidate, git_bundle, work_root=work, home=home)
        dist = work / "dist"
        python = _current_python_executable()
        wheel, sdist = _build_distributions(build_source, dist, python)
        builder_venv = work / "builder-venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(builder_venv)
        builder_python = builder_venv / "bin/python"
        _run(
            (builder_python, "-m", "pip", "install", "--no-index", "--no-deps", wheel),
            env=_fixed_python_env(network=False), capture=False,
            failure_code="P3D_RELEASE_BUNDLE_BUILDER_INSTALL_FAILED",
        )
        command = (
            builder_python, "-m", "pdi.production_ops.p3d_release_bundle", "_assemble",
            "--candidate", candidate, "--source-root", candidate_source,
            "--git-bundle", git_bundle, "--pdi-wheel", wheel, "--pdi-sdist", sdist,
            "--os-manifest", os_manifest.resolve(), "--platform-tag", platform_tag,
            "--repository", repository_identity, "--workflow-path", workflow_path,
            "--run-identity", run_identity, "--run-attempt", run_attempt,
            "--output-dir", output_dir,
        )
        completed = _run(
            command, env=_fixed_python_env(network=True), cwd=work,
            failure_code="P3D_RELEASE_BUNDLE_ASSEMBLY_FAILED",
        )
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            _fail("P3D_RELEASE_BUNDLE_BUILDER_INVALID")
        bundle = output_dir / result["BUNDLE_FILENAME"]
        digests = result["DIGESTS"]
        if not bundle.is_file() or not isinstance(digests, dict):
            _fail("P3D_RELEASE_BUNDLE_BUILDER_INVALID")
        return bundle, digests


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify MU13-P3D Gate B release-input bundles")
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser("build", help="build a qualification-only release-input bundle")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--candidate", required=True)
    build.add_argument("--os-manifest", type=Path, required=True)
    build.add_argument("--platform-tag", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--workflow-path", required=True)
    build.add_argument("--run-identity", required=True)
    build.add_argument("--run-attempt", required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    verify = sub.add_parser("verify", help="offline verify an existing release-input bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-candidate", required=True)
    verify.add_argument("--expected-bundle-sha256", required=True)
    verify.add_argument("--expected-os-manifest-sha256")
    assemble = sub.add_parser("_assemble", help=argparse.SUPPRESS)
    assemble.add_argument("--candidate", required=True)
    assemble.add_argument("--source-root", type=Path, required=True)
    assemble.add_argument("--git-bundle", type=Path, required=True)
    assemble.add_argument("--pdi-wheel", type=Path, required=True)
    assemble.add_argument("--pdi-sdist", type=Path, required=True)
    assemble.add_argument("--os-manifest", type=Path, required=True)
    assemble.add_argument("--platform-tag", required=True)
    assemble.add_argument("--repository", required=True)
    assemble.add_argument("--workflow-path", required=True)
    assemble.add_argument("--run-identity", required=True)
    assemble.add_argument("--run-attempt", required=True)
    assemble.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.action == "build":
            bundle, digests = build_release_input_bundle(
                source=args.source, candidate_sha=args.candidate,
                os_manifest=args.os_manifest, platform_tag=args.platform_tag,
                repository_identity=args.repository, workflow_path=args.workflow_path,
                run_identity=args.run_identity, run_attempt=args.run_attempt,
                output_dir=args.output_dir,
            )
            print(json.dumps({"BUNDLE_FILENAME": bundle.name, "DIGESTS": digests}, sort_keys=True))
        elif args.action == "_assemble":
            bundle, digests = assemble_release_input_bundle(AssembleInputs(
                args.candidate, args.source_root, args.git_bundle, args.pdi_wheel,
                args.pdi_sdist, args.os_manifest, args.platform_tag, args.repository,
                args.workflow_path, args.run_identity, args.run_attempt, args.output_dir,
            ))
            print(json.dumps({"BUNDLE_FILENAME": bundle.name, "DIGESTS": digests}, sort_keys=True))
        else:
            digests = verify_release_input_bundle(
                args.bundle, expected_candidate_sha=args.expected_candidate,
                expected_bundle_sha256=args.expected_bundle_sha256,
                expected_os_manifest_sha256=args.expected_os_manifest_sha256,
                perform_offline_install=True,
            )
            print(json.dumps({"P3D_RELEASE_BUNDLE_VERIFY": "PASS", "DIGESTS": digests}, sort_keys=True))
    except ReleaseBundleError as error:
        print(f"P3D_RELEASE_BUNDLE=FAIL\nFAILURE_CODE={error.code}", file=sys.stderr)
        return 1
    except Exception:
        print("P3D_RELEASE_BUNDLE=FAIL\nFAILURE_CODE=P3D_RELEASE_BUNDLE_UNEXPECTED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
