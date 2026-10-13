"""Offline MU13-P3D Gate B release bootstrap.

This module is the independently reviewed bootstrap authority.  It never loads
bootstrap code from the candidate bundle, never changes ``current``, and has no
systemd, database, Provider, or network integration.  Production and
qualification policies are deliberately separate types of authority.
"""

from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
import ctypes
import csv
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
import errno
import fcntl
import grp
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sysconfig
from typing import Any, Iterator, Mapping, Protocol, Sequence
from uuid import uuid4

from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    FailureCode,
    GateBPhase,
    OperatorToolIdentity,
    OSRuntimeManifestV1,
    PreparationGate,
    PreparationJournalEventV1,
    PreparationOperationStateV1,
    SourceFileFingerprintEntryV1,
    ToolName,
    atomic_create_no_replace,
    canonical_json_bytes,
    contract_fingerprint,
    os_runtime_manifest_fingerprint,
    preparation_journal_fingerprint,
    source_release_fingerprint,
    transition_preparation_state,
    utc_timestamp,
    validate_preparation_journal_chain,
)
from pdi.production_ops.p3d_release_bundle import (
    AUTHORITY_CLASS as QUALIFICATION_AUTHORITY_CLASS,
    ReleaseBundleError,
    load_os_runtime_manifest,
    safe_extract_bundle,
    sha256_file,
    verify_release_input_bundle,
)


GIT = Path("/usr/bin/git")
SETPRIV = Path("/usr/bin/setpriv")
DPKG = Path("/usr/bin/dpkg")
DPKG_QUERY = Path("/usr/bin/dpkg-query")
PRODUCTION_AUTHORITY_CLASS = "PRODUCTION_RELEASE"
PRODUCTION_RUNTIME_USER = "pdi"
PRODUCTION_RUNTIME_GROUP = "pdi"
GIT_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SAFE_AUTHORITY_CLASS = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
CANONICAL_REQUIRED_PATHS = (
    "pyproject.toml",
    "alembic.ini",
    "src",
    "scripts",
    "migrations",
    "deployment",
    ".git",
    ".venv",
    ".venv/bin/python",
)
RUNTIME_IMPORTS = ("pdi", "psycopg", "sqlalchemy")


class BootstrapError(RuntimeError):
    """A fixed, non-sensitive Gate B failure."""

    def __init__(self, code: FailureCode):
        self.code = code
        super().__init__(code.value)


def _fail(code: FailureCode) -> None:
    raise BootstrapError(code)


def _require_sha(value: str, *, code: FailureCode) -> str:
    if not isinstance(value, str) or GIT_SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _require_hash(value: str, *, code: FailureCode) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _fail(code)
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> str:
    return utc_timestamp(datetime.now(UTC).replace(microsecond=0))


def _run(
    argv: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path,
    env: Mapping[str, str],
    code: FailureCode,
    stdout: bool = True,
) -> str:
    if not argv or not Path(argv[0]).is_absolute():
        _fail(code)
    try:
        result = subprocess.run(
            [os.fspath(item) for item in argv],
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True,
            shell=False,
        )
    except (OSError, subprocess.CalledProcessError):
        _fail(code)
    return result.stdout if stdout else ""


def _git_env(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _python_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
    }


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _trusted_directory(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    exact_mode: int | None = None,
) -> None:
    try:
        info = path.lstat()
    except OSError:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or info.st_mode & 0o022
        or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)
    ):
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)


def _trusted_chain(
    path: Path,
    *,
    stop: Path,
    owner_uid: int,
    owner_gid: int,
) -> None:
    current = path.absolute()
    boundary = stop.absolute()
    if current != boundary and boundary not in current.parents:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    while True:
        _trusted_directory(current, owner_uid=owner_uid, owner_gid=owner_gid)
        if current == boundary:
            return
        current = current.parent


class BootstrapMode(str, Enum):
    QUALIFICATION = "QUALIFICATION"
    PRODUCTION = "PRODUCTION"


@dataclass(frozen=True)
class BootstrapPolicy:
    mode: BootstrapMode
    trust_root: Path
    filesystem_owner_uid: int
    filesystem_owner_gid: int
    runtime_uid: int
    runtime_gid: int
    expected_authority_class: str
    approved_external_runtime_roots: tuple[Path, ...]

    @classmethod
    def qualification(
        cls,
        *,
        disposable_root: Path,
        owner_uid: int,
        owner_gid: int,
        runtime_uid: int,
        runtime_gid: int,
    ) -> "BootstrapPolicy":
        root = disposable_root.absolute()
        if root == Path("/") or runtime_uid == 0 or runtime_gid == 0:
            _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
        return cls(
            BootstrapMode.QUALIFICATION,
            root,
            owner_uid,
            owner_gid,
            runtime_uid,
            runtime_gid,
            QUALIFICATION_AUTHORITY_CLASS,
            (Path("/usr"),),
        )

    @classmethod
    def production(cls) -> "BootstrapPolicy":
        if os.geteuid() != 0:
            _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
        runtime_uid, runtime_gid = resolve_runtime_identity(
            PRODUCTION_RUNTIME_USER,
            PRODUCTION_RUNTIME_GROUP,
        )
        return cls(
            BootstrapMode.PRODUCTION,
            Path("/"),
            0,
            0,
            runtime_uid,
            runtime_gid,
            PRODUCTION_AUTHORITY_CLASS,
            (Path("/usr"),),
        )

    def validate_inputs(self, inputs: "BootstrapInputs") -> None:
        if self.expected_authority_class != inputs.expected_authority_class:
            _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        if self.mode is BootstrapMode.PRODUCTION:
            if inputs.expected_authority_class == QUALIFICATION_AUTHORITY_CLASS:
                _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
            if (
                inputs.runtime_user != PRODUCTION_RUNTIME_USER
                or inputs.runtime_group != PRODUCTION_RUNTIME_GROUP
            ):
                _fail(FailureCode.RELEASE_RUNTIME_INVALID)
            expected_runtime_uid, expected_runtime_gid = resolve_runtime_identity(
                PRODUCTION_RUNTIME_USER,
                PRODUCTION_RUNTIME_GROUP,
            )
            if (
                self.runtime_uid != expected_runtime_uid
                or self.runtime_gid != expected_runtime_gid
            ):
                _fail(FailureCode.RELEASE_RUNTIME_INVALID)
            expected = (
                Path("/opt/pdi/releases"),
                Path("/var/lib/pdi-p3d/preparation"),
                Path("/run/lock/pdi/p3d-release-bootstrap.lock"),
                Path("/opt/pdi/current"),
            )
            actual = (
                inputs.releases_root,
                inputs.preparation_state_root,
                inputs.lock_path,
                inputs.current_path,
            )
            if actual != expected:
                _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        else:
            for path in (
                inputs.releases_root,
                inputs.preparation_state_root,
                inputs.lock_path,
                inputs.current_path,
            ):
                absolute = path.absolute()
                if absolute != self.trust_root and self.trust_root not in absolute.parents:
                    _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)


@dataclass(frozen=True)
class BootstrapInputs:
    bundle_path: Path
    expected_candidate_sha: str
    expected_bundle_sha256: str
    expected_os_runtime_manifest_sha256: str
    expected_authority_class: str
    bootstrap_tool_identity: OperatorToolIdentity
    releases_root: Path
    preparation_state_root: Path
    lock_path: Path
    current_path: Path
    runtime_user: str
    runtime_group: str

    def validate(self) -> None:
        _require_sha(self.expected_candidate_sha, code=FailureCode.RELEASE_ARTIFACT_INVALID)
        _require_hash(self.expected_bundle_sha256, code=FailureCode.RELEASE_ARTIFACT_INVALID)
        _require_hash(
            self.expected_os_runtime_manifest_sha256,
            code=FailureCode.RELEASE_ARTIFACT_INVALID,
        )
        if (
            SAFE_AUTHORITY_CLASS.fullmatch(self.expected_authority_class) is None
            or self.bootstrap_tool_identity.tool_name is not ToolName.RELEASE_BOOTSTRAP
            or not self.runtime_user
            or not self.runtime_group
        ):
            _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        for path in (
            self.bundle_path,
            self.releases_root,
            self.preparation_state_root,
            self.lock_path,
            self.current_path,
        ):
            if not path.is_absolute():
                _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        if self.releases_root / self.expected_candidate_sha != self.final_path:
            _fail(FailureCode.RELEASE_ARTIFACT_INVALID)

    @property
    def final_path(self) -> Path:
        return self.releases_root / self.expected_candidate_sha


@dataclass(frozen=True)
class HostRuntimeEvidence:
    system_python_path: Path
    authority_fingerprint: str


class HostRuntimeAuthorityProvider(Protocol):
    def verify(
        self,
        manifest: OSRuntimeManifestV1,
        *,
        policy: BootstrapPolicy,
    ) -> HostRuntimeEvidence: ...


@dataclass(frozen=True)
class QualificationHostRuntimeAuthorityProvider:
    """Explicit synthetic authority accepted only by qualification policy."""

    system_python_path: Path
    os_manifest_fingerprint: str

    def verify(
        self,
        manifest: OSRuntimeManifestV1,
        *,
        policy: BootstrapPolicy,
    ) -> HostRuntimeEvidence:
        if (
            policy.mode is not BootstrapMode.QUALIFICATION
            or os_runtime_manifest_fingerprint(manifest) != self.os_manifest_fingerprint
        ):
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        path = self.system_python_path.absolute()
        try:
            resolved = path.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        evidence = {
            "kind": "qualification-host-runtime-v1",
            "manifest": self.os_manifest_fingerprint,
            "python_file": sha256_file(resolved),
            "python_version": platform.python_version(),
            "python_abi": sysconfig.get_config_var("SOABI") or "unknown",
        }
        return HostRuntimeEvidence(path, contract_fingerprint(evidence))


@dataclass(frozen=True)
class DebianHostRuntimeAuthorityProvider:
    os_release_path: Path = Path("/etc/os-release")
    dpkg_path: Path = DPKG
    dpkg_query_path: Path = DPKG_QUERY

    @staticmethod
    def _os_release(path: Path) -> dict[str, str]:
        try:
            result: dict[str, str] = {}
            for raw in path.read_text(encoding="utf-8").splitlines():
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                if key in {"ID", "VERSION_ID"}:
                    result[key] = value.strip().strip('"')
            return result
        except OSError:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)

    @staticmethod
    def _arch(value: str) -> str:
        return {"amd64": "x86_64", "arm64": "aarch64"}.get(value, value)

    def verify(
        self,
        manifest: OSRuntimeManifestV1,
        *,
        policy: BootstrapPolicy,
    ) -> HostRuntimeEvidence:
        if policy.mode is not BootstrapMode.PRODUCTION:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        os_release = self._os_release(self.os_release_path)
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        architecture = self._arch(_run(
            (self.dpkg_path, "--print-architecture"),
            cwd=Path("/"), env=env, code=FailureCode.RELEASE_OS_RUNTIME_MISMATCH,
        ).strip())
        python = Path(manifest.system_python_path)
        try:
            python_resolved = python.resolve(strict=True)
            python_info = python_resolved.stat()
        except OSError:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        _trusted_chain(
            python_resolved.parent,
            stop=Path("/"),
            owner_uid=0,
            owner_gid=0,
        )
        if (
            not stat.S_ISREG(python_info.st_mode)
            or python_info.st_uid != 0
            or python_info.st_gid != 0
            or python_info.st_mode & 0o022
        ):
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        runtime_json = _run(
            (
                python,
                "-c",
                "import json,platform,sys,sysconfig;print(json.dumps({"
                "'implementation':platform.python_implementation(),"
                "'version':'.'.join(map(str,sys.version_info[:2])),"
                "'abi':'cp%d%d'%sys.version_info[:2]}))",
            ),
            cwd=Path("/"), env=_python_env(), code=FailureCode.RELEASE_OS_RUNTIME_MISMATCH,
        )
        try:
            runtime = json.loads(runtime_json)
        except (TypeError, json.JSONDecodeError):
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        installed: dict[str, str] = {}
        for package in manifest.approved_packages:
            value = _run(
                (self.dpkg_query_path, "-W", "-f=${Version}", package.name),
                cwd=Path("/"), env=env, code=FailureCode.RELEASE_OS_RUNTIME_MISMATCH,
            ).strip()
            installed[package.name] = value
            if value != package.version:
                _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        expected = {
            "os_id": manifest.os_id,
            "os_version": manifest.os_version_id,
            "arch": manifest.arch,
            "implementation": manifest.python_implementation,
            "version": manifest.python_version,
            "abi": manifest.python_abi,
            "python_hash": manifest.system_runtime_file_sha256,
        }
        actual = {
            "os_id": os_release.get("ID"),
            "os_version": os_release.get("VERSION_ID"),
            "arch": architecture,
            "implementation": runtime.get("implementation"),
            "version": runtime.get("version"),
            "abi": runtime.get("abi"),
            "python_hash": sha256_file(python_resolved),
        }
        if actual != expected or not set(manifest.native_library_package_set).issubset(installed):
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        return HostRuntimeEvidence(
            python,
            contract_fingerprint({"runtime": actual, "packages": installed}),
        )


class GateBJournalStore:
    """Immutable Gate B sequence files backed by the frozen WP1 contracts."""

    def __init__(self, root: Path, *, policy: AtomicCreatePolicyV1) -> None:
        self.root = root
        self.policy = policy

    def initialize(
        self,
        *,
        operation_id: str,
        candidate_sha: str,
        started_at: str,
        tool: OperatorToolIdentity,
    ) -> PreparationOperationStateV1:
        try:
            self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
            os.chown(self.root, self.policy.owner_uid, self.policy.owner_gid)
            os.chmod(self.root, 0o700)
        except OSError:
            _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
        state = PreparationOperationStateV1.from_mapping({
            "version": 1,
            "operation_id": operation_id,
            "gate": PreparationGate.RELEASE_STAGING.value,
            "candidate_sha": candidate_sha,
            "phase": GateBPhase.NEW.value,
            "started_at": started_at,
            "updated_at": started_at,
            "operator_tool_identities": [tool.to_mapping()],
            "evidence_fingerprint": None,
            "failure_code": None,
        })
        atomic_create_no_replace(
            self.root / "state-000000.json",
            canonical_json_bytes(state.to_mapping()) + b"\n",
            policy=self.policy,
        )
        return state

    def advance(
        self,
        state: PreparationOperationStateV1,
        events: tuple[PreparationJournalEventV1, ...],
        target: GateBPhase,
        *,
        tool: OperatorToolIdentity,
        evidence_fingerprints: Sequence[str],
        failure_code: FailureCode | None = None,
    ) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        timestamp = _now()
        event = PreparationJournalEventV1.from_mapping({
            "version": 1,
            "sequence": len(events) + 1,
            "operation_id": state.operation_id,
            "gate": state.gate.value,
            "candidate_sha": state.candidate_sha,
            "from_state": state.phase,
            "to_state": target.value,
            "timestamp": timestamp,
            "tool_identity": tool.to_mapping(),
            "evidence_fingerprints": sorted(set(evidence_fingerprints)),
            "failure_code": None if failure_code is None else failure_code.value,
        })
        next_events = (*events, event)
        next_state = transition_preparation_state(
            state,
            target.value,
            updated_at=timestamp,
            evidence_fingerprint=preparation_journal_fingerprint(next_events),
            failure_code=failure_code,
        )
        validate_preparation_journal_chain(next_events, next_state)
        sequence = event.sequence
        atomic_create_no_replace(
            self.root / f"journal-{sequence:06d}.json",
            canonical_json_bytes(event.to_mapping()) + b"\n",
            policy=self.policy,
        )
        atomic_create_no_replace(
            self.root / f"state-{sequence:06d}.json",
            canonical_json_bytes(next_state.to_mapping()) + b"\n",
            policy=self.policy,
        )
        return next_state, next_events

    def load_retryable(
        self,
    ) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        try:
            _trusted_directory(
                self.root,
                owner_uid=self.policy.owner_uid,
                owner_gid=self.policy.owner_gid,
                exact_mode=0o700,
            )
            state_paths = sorted(self.root.glob("state-*.json"))
            event_paths = sorted(self.root.glob("journal-*.json"))
            if not state_paths or len(state_paths) != len(event_paths) + 1:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            expected_names = [f"state-{index:06d}.json" for index in range(len(state_paths))]
            expected_events = [f"journal-{index:06d}.json" for index in range(1, len(state_paths))]
            if [path.name for path in state_paths] != expected_names or [path.name for path in event_paths] != expected_events:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            states = tuple(
                PreparationOperationStateV1.from_mapping(json.loads(path.read_text()))
                for path in state_paths
            )
            events = tuple(
                PreparationJournalEventV1.from_mapping(json.loads(path.read_text()))
                for path in event_paths
            )
            state = states[-1]
            if events:
                validate_preparation_journal_chain(events, state)
            retryable = {
                GateBPhase.ARTIFACT_VERIFIED.value,
                GateBPhase.OS_RUNTIME_VERIFIED.value,
                GateBPhase.STAGING_CREATED.value,
                GateBPhase.SOURCE_CHECKED_OUT.value,
                GateBPhase.VENV_BUILT.value,
                GateBPhase.RUNTIME_VERIFIED.value,
                GateBPhase.IMMUTABILITY_VERIFIED.value,
            }
            if state.phase not in retryable:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            return state, events
        except BootstrapError:
            raise
        except Exception:
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)


@contextmanager
def exclusive_bootstrap_lock(path: Path, *, policy: BootstrapPolicy) -> Iterator[None]:
    try:
        _trusted_chain(
            path.parent,
            stop=policy.trust_root,
            owner_uid=policy.filesystem_owner_uid,
            owner_gid=policy.filesystem_owner_gid,
        )
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.fchown(descriptor, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        except OSError:
            pass


@dataclass(frozen=True)
class ReleaseFacts:
    fingerprint: str
    head: str
    alembic_head: str
    runtime_fingerprint: str


@dataclass(frozen=True)
class BootstrapResult:
    operation_id: str
    disposition: str
    final_path: Path
    release_fingerprint: str
    final_state: PreparationOperationStateV1
    events: tuple[PreparationJournalEventV1, ...]


def _current_snapshot(path: Path) -> tuple[str, str]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ("ABSENT", "")
    except OSError:
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)
    if not stat.S_ISLNK(info.st_mode):
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)
    try:
        return ("SYMLINK", os.readlink(path))
    except OSError:
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)


def _ensure_root(path: Path, *, policy: BootstrapPolicy, mode: int = 0o700) -> None:
    if path.exists() or path.is_symlink():
        _trusted_directory(
            path,
            owner_uid=policy.filesystem_owner_uid,
            owner_gid=policy.filesystem_owner_gid,
            exact_mode=mode,
        )
        return
    parent = path.parent
    _trusted_chain(
        parent,
        stop=policy.trust_root,
        owner_uid=policy.filesystem_owner_uid,
        owner_gid=policy.filesystem_owner_gid,
    )
    try:
        path.mkdir(mode=mode)
        os.chown(path, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
        os.chmod(path, mode)
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)


def _secure_remove(path: Path, *, allowed_parent: Path) -> None:
    if path.parent != allowed_parent or path.is_symlink():
        return
    try:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    except OSError:
        pass


def _seal_bundle(
    source: Path,
    target: Path,
    *,
    expected_sha256: str,
    policy: BootstrapPolicy,
) -> Path:
    """Copy caller bytes once into the protected operation root and fsync them."""

    try:
        source_info = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(source_info.st_mode):
            _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        if target.exists() or target.is_symlink():
            info = target.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != policy.filesystem_owner_uid
                or info.st_gid != policy.filesystem_owner_gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or sha256_file(target) != expected_sha256
            ):
                _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
            return target
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchown(target_fd, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
                os.fchmod(target_fd, 0o600)
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        view = view[written:]
                os.fsync(target_fd)
            finally:
                os.close(target_fd)
        finally:
            os.close(source_fd)
        if digest.hexdigest() != expected_sha256:
            try:
                target.unlink()
            except OSError:
                pass
            _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        _fsync_directory(target.parent)
        return target
    except BootstrapError:
        raise
    except OSError:
        _fail(FailureCode.RELEASE_ARTIFACT_INVALID)


def _parse_authority_class(root: Path) -> str:
    try:
        value = json.loads((root / "provenance/provenance.json").read_text(encoding="utf-8"))
        authority = value["AUTHORITY_CLASS"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
    if not isinstance(authority, str) or SAFE_AUTHORITY_CLASS.fullmatch(authority) is None:
        _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
    return authority


def _artifact_fingerprint(digests: Mapping[str, str], authority_class: str) -> str:
    return contract_fingerprint({
        "authority_class": authority_class,
        "bundle": digests["BUNDLE_SHA256"],
        "candidate": digests["CANDIDATE_SHA"],
        "release_manifest": digests["RELEASE_INPUT_MANIFEST_SHA256"],
        "provenance": digests["PROVENANCE_SHA256"],
    })


def _checkout_source(staging: Path, bundle: Path, *, candidate: str, home: Path) -> None:
    env = _git_env(home)
    code = FailureCode.RELEASE_SOURCE_CHECKOUT_FAILED
    _run((GIT, "init", "--quiet", staging), cwd=staging, env=env, code=code)
    _run((GIT, "-C", staging, "bundle", "verify", bundle), cwd=staging, env=env, code=code)
    _run((GIT, "-C", staging, "fetch", "--quiet", bundle, "HEAD"), cwd=staging, env=env, code=code)
    fetched = _run((GIT, "-C", staging, "rev-parse", "FETCH_HEAD"), cwd=staging, env=env, code=code).strip()
    if fetched != candidate:
        _fail(code)
    _run((GIT, "-C", staging, "checkout", "--quiet", "--detach", candidate), cwd=staging, env=env, code=code)
    _verify_git(staging, candidate=candidate, home=home, code=code)


def _verify_git(release: Path, *, candidate: str, home: Path, code: FailureCode) -> None:
    env = _git_env(home)
    head = _run((GIT, "-C", release, "rev-parse", "HEAD"), cwd=release, env=env, code=code).strip()
    status = _run(
        (GIT, "-C", release, "status", "--porcelain", "--untracked-files=all"),
        cwd=release, env=env, code=code,
    )
    if head != candidate or status:
        _fail(code)


def _build_venv(staging: Path, quarantine: Path, python: Path) -> None:
    code = FailureCode.RELEASE_VENV_FAILED
    env = _python_env()
    _run((python, "-m", "venv", "--copies", staging / ".venv"), cwd=staging, env=env, code=code, stdout=False)
    venv_python = staging / ".venv/bin/python"
    argv = (
        venv_python,
        "-m", "pip", "install",
        "--no-index",
        "--find-links", quarantine / "wheelhouse",
        "--require-hashes",
        "--only-binary=:all:",
        "-r", quarantine / "requirements/runtime.lock",
    )
    _run(argv, cwd=staging, env=env, code=FailureCode.RELEASE_WHEELHOUSE_INVALID, stdout=False)


def _rewrite_staging_references(staging: Path, final: Path) -> None:
    old = os.fsencode(str(staging))
    new = os.fsencode(str(final))
    try:
        for path in sorted(staging.rglob("*.pyc")):
            if not path.is_symlink():
                path.unlink()
        for path in sorted(staging.rglob("__pycache__"), key=lambda item: len(item.parts), reverse=True):
            if path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
                path.rmdir()
        for path in staging.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
            if old in data:
                if b"\x00" in data:
                    _fail(FailureCode.RELEASE_RUNTIME_INVALID)
                data.decode("utf-8", errors="strict")
                path.write_bytes(data.replace(old, new))
        for path in staging.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            if old in path.read_bytes():
                _fail(FailureCode.RELEASE_RUNTIME_INVALID)
        _normalize_wheel_records(staging)
    except OSError:
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)


def _normalize_wheel_records(release: Path) -> None:
    """Rebind wheel RECORD hashes after deterministic script relocation."""

    try:
        release_root = release.resolve(strict=True)
        records = sorted((release / ".venv").glob("lib/python*/site-packages/*.dist-info/RECORD"))
        if not records:
            _fail(FailureCode.RELEASE_RUNTIME_INVALID)
        for record in records:
            site_packages = record.parent.parent
            rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
            if not rows or any(len(row) != 3 or not row[0] for row in rows):
                _fail(FailureCode.RELEASE_RUNTIME_INVALID)
            normalized: list[tuple[str, str, str]] = []
            record_relative = record.relative_to(site_packages).as_posix()
            for relative, prior_digest, prior_size in rows:
                target = (site_packages / relative).resolve(strict=False)
                if not _inside(target, release_root):
                    _fail(FailureCode.RELEASE_RUNTIME_INVALID)
                if relative == record_relative:
                    normalized.append((relative, "", ""))
                    continue
                relative_parts = PurePosixPath(relative).parts
                if (
                    not target.exists()
                    and not prior_digest
                    and not prior_size
                    and target.suffix == ".pyc"
                    and "__pycache__" in relative_parts
                ):
                    # pip records generated bytecode without a digest.  The
                    # bootstrap removes bytecode before fingerprinting so the
                    # release remains independent of staging-path pyc bytes.
                    normalized.append((relative, "", ""))
                    continue
                if not target.is_file() or target.is_symlink():
                    _fail(FailureCode.RELEASE_RUNTIME_INVALID)
                content = target.read_bytes()
                digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
                normalized.append((relative, f"sha256={digest}", str(len(content))))
            output = io.StringIO(newline="")
            writer = csv.writer(output, lineterminator="\n")
            writer.writerows(sorted(normalized))
            record.write_text(output.getvalue(), encoding="utf-8", newline="")
    except BootstrapError:
        raise
    except (OSError, UnicodeError, csv.Error, ValueError):
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)


def _tracked_executables(release: Path, home: Path) -> frozenset[str]:
    output = _run(
        (GIT, "-C", release, "ls-files", "-s", "-z"),
        cwd=release,
        env=_git_env(home),
        code=FailureCode.RELEASE_IMMUTABILITY_FAILED,
    )
    executable: set[str] = set()
    for raw in output.split("\0"):
        if not raw:
            continue
        prefix, relative = raw.split("\t", 1)
        if prefix.split(" ", 1)[0] == "100755":
            executable.add(relative)
    return frozenset(executable)


def _canonicalize_tree(release: Path, *, policy: BootstrapPolicy, home: Path) -> None:
    tracked_exec = _tracked_executables(release, home)
    try:
        paths = sorted(release.rglob("*"), key=lambda item: len(item.parts), reverse=True)
        for path in paths:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                os.lchown(path, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
            elif stat.S_ISDIR(info.st_mode):
                os.chown(path, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
                os.chmod(path, 0o755)
            elif stat.S_ISREG(info.st_mode):
                relative = path.relative_to(release).as_posix()
                executable = relative in tracked_exec or (
                    relative.startswith(".venv/bin/") and bool(info.st_mode & 0o111)
                ) or path.suffix in {".so"}
                os.chown(path, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
                os.chmod(path, 0o755 if executable else 0o644)
            else:
                _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
        os.chown(release, policy.filesystem_owner_uid, policy.filesystem_owner_gid)
        os.chmod(release, 0o755)
    except OSError:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)


def _source_alembic_head(release: Path) -> str:
    revisions: dict[str, str | tuple[str, ...] | None] = {}
    try:
        for path in sorted((release / "migrations/versions").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
            values: dict[str, Any] = {}
            for node in tree.body:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    names = [target.id for target in node.targets if isinstance(target, ast.Name)] if isinstance(node, ast.Assign) else ([node.target.id] if isinstance(node.target, ast.Name) else [])
                    if any(name in {"revision", "down_revision"} for name in names):
                        value_node = node.value
                        if value_node is not None:
                            parsed = ast.literal_eval(value_node)
                            for name in names:
                                values[name] = parsed
            revision = values.get("revision")
            down = values.get("down_revision")
            if not isinstance(revision, str) or revision in revisions:
                _fail(FailureCode.RELEASE_RUNTIME_INVALID)
            if down is not None and not isinstance(down, (str, tuple)):
                _fail(FailureCode.RELEASE_RUNTIME_INVALID)
            revisions[revision] = down
        parents = {
            item
            for down in revisions.values()
            for item in ((down,) if isinstance(down, str) else (down or ()))
        }
        heads = sorted(set(revisions) - parents)
        if len(heads) != 1:
            _fail(FailureCode.RELEASE_RUNTIME_INVALID)
        return heads[0]
    except (OSError, SyntaxError, ValueError):
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)


def _unprivileged_argv(argv: Sequence[Path | str], *, policy: BootstrapPolicy) -> tuple[str, ...]:
    command = tuple(os.fspath(item) for item in argv)
    if os.geteuid() == 0:
        if policy.runtime_uid == 0 or policy.runtime_gid == 0 or not SETPRIV.is_file():
            _fail(FailureCode.RELEASE_RUNTIME_INVALID)
        return (
            str(SETPRIV),
            f"--reuid={policy.runtime_uid}",
            f"--regid={policy.runtime_gid}",
            "--clear-groups",
            "--no-new-privs",
            "--",
            *command,
        )
    if os.geteuid() != policy.runtime_uid or os.getegid() != policy.runtime_gid:
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)
    return command


def _runtime_verify(
    release: Path,
    *,
    candidate: str,
    expected_alembic_head: str,
    policy: BootstrapPolicy,
    home: Path,
) -> tuple[str, str]:
    _verify_git(release, candidate=candidate, home=home, code=FailureCode.RELEASE_RUNTIME_INVALID)
    python = release / ".venv/bin/python"
    env = _python_env()
    _run(
        _unprivileged_argv((python, "-m", "pip", "check"), policy=policy),
        cwd=release, env=env, code=FailureCode.RELEASE_RUNTIME_INVALID,
    )
    code = (
        "import json,pathlib,sys; import pdi,psycopg,sqlalchemy;"
        "from alembic.config import Config; from alembic.script import ScriptDirectory;"
        "mods=[pdi,psycopg,sqlalchemy];"
        "print(json.dumps({'uid':__import__('os').geteuid(),"
        "'modules':[str(pathlib.Path(m.__file__).resolve()) for m in mods],"
        "'heads':sorted(ScriptDirectory.from_config(Config('alembic.ini')).get_heads()),"
        "'python':sys.version.split()[0]}))"
    )
    raw = _run(
        _unprivileged_argv((python, "-c", code), policy=policy),
        cwd=release, env=env, code=FailureCode.RELEASE_RUNTIME_INVALID,
    )
    try:
        value = json.loads(raw)
        modules = tuple(Path(item) for item in value["modules"])
        heads = value["heads"]
        uid = value["uid"]
    except (KeyError, TypeError, json.JSONDecodeError):
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)
    site_root = (release / ".venv").resolve()
    if (
        uid == 0
        or uid != policy.runtime_uid
        or heads != [expected_alembic_head]
        or any(not _inside(path, site_root) for path in modules)
    ):
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)
    return expected_alembic_head, contract_fingerprint({
        "candidate": candidate,
        "alembic_head": expected_alembic_head,
        "runtime_uid": policy.runtime_uid,
        "python": value["python"],
        "module_count": len(modules),
    })


def _verify_release_tree(
    release: Path,
    *,
    candidate: str,
    policy: BootstrapPolicy,
    approved_python: Path,
    home: Path,
) -> str:
    try:
        root_info = release.lstat()
    except OSError:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != policy.filesystem_owner_uid
        or root_info.st_gid != policy.filesystem_owner_gid
        or root_info.st_mode & 0o022
    ):
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    if any(not (release / item).exists() for item in CANONICAL_REQUIRED_PATHS):
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    approved_resolved = approved_python.resolve(strict=True)
    entries: list[SourceFileFingerprintEntryV1] = []
    try:
        for path in sorted(release.rglob("*")):
            relative = path.relative_to(release).as_posix()
            info = path.lstat()
            if info.st_uid != policy.filesystem_owner_uid or info.st_gid != policy.filesystem_owner_gid:
                _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                resolved = path.resolve(strict=True)
                if _inside(resolved, release.resolve()):
                    target = resolved.relative_to(release.resolve()).as_posix()
                elif resolved == approved_resolved and any(
                    _inside(resolved, root.resolve(strict=True))
                    for root in policy.approved_external_runtime_roots
                ):
                    target = str(resolved)
                else:
                    _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
                if not relative.startswith(".git/"):
                    entries.append(SourceFileFingerprintEntryV1(relative, "symlink", f"0{mode:03o}", 0, 0, symlink_target=target))
            elif stat.S_ISDIR(info.st_mode):
                if mode & 0o022 or mode != 0o755:
                    _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
                if not relative.startswith(".git/") and relative != ".git":
                    entries.append(SourceFileFingerprintEntryV1(relative, "directory", "0755", 0, 0))
            elif stat.S_ISREG(info.st_mode):
                if mode & 0o022 or mode not in {0o644, 0o755}:
                    _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
                if not relative.startswith(".git/"):
                    entries.append(SourceFileFingerprintEntryV1(relative, "file", f"0{mode:03o}", 0, 0, sha256_file(path)))
            else:
                _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    except OSError:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)
    _verify_git(release, candidate=candidate, home=home, code=FailureCode.RELEASE_IMMUTABILITY_FAILED)
    return source_release_fingerprint(candidate, entries)


def _fsync_tree(root: Path) -> None:
    try:
        directories: list[Path] = [root]
        for path in root.rglob("*"):
            if path.is_symlink():
                continue
            if path.is_file():
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            elif path.is_dir():
                directories.append(path)
        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError:
        _fail(FailureCode.RELEASE_IMMUTABILITY_FAILED)


def _atomic_rename_no_replace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd, os.fsencode(source), at_fdcwd, os.fsencode(target), rename_noreplace,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(target)
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        _fail(FailureCode.RELEASE_FINAL_CONFLICT)


class ReleaseBootstrap:
    """Fail-closed Gate B orchestrator with explicit policy and authority."""

    def __init__(
        self,
        *,
        inputs: BootstrapInputs,
        policy: BootstrapPolicy,
        host_runtime_provider: HostRuntimeAuthorityProvider,
    ) -> None:
        self.inputs = inputs
        self.policy = policy
        self.host_runtime_provider = host_runtime_provider
        self._active_state: PreparationOperationStateV1 | None = None
        self._active_events: tuple[PreparationJournalEventV1, ...] = ()

    def _advance(
        self,
        store: GateBJournalStore,
        target: GateBPhase,
        *,
        evidence_fingerprints: Sequence[str],
        failure_code: FailureCode | None = None,
    ) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        if self._active_state is None:
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        state, events = store.advance(
            self._active_state,
            self._active_events,
            target,
            tool=self.inputs.bootstrap_tool_identity,
            evidence_fingerprints=evidence_fingerprints,
            failure_code=failure_code,
        )
        self._active_state = state
        self._active_events = events
        return state, events

    def _prepare_roots(self) -> None:
        self.inputs.validate()
        self.policy.validate_inputs(self.inputs)
        if self.policy.mode is BootstrapMode.QUALIFICATION:
            _trusted_directory(
                self.policy.trust_root,
                owner_uid=self.policy.filesystem_owner_uid,
                owner_gid=self.policy.filesystem_owner_gid,
            )
        _ensure_root(self.inputs.releases_root, policy=self.policy, mode=0o755)
        _ensure_root(self.inputs.preparation_state_root, policy=self.policy, mode=0o700)
        _ensure_root(self.inputs.lock_path.parent, policy=self.policy, mode=0o700)
        if self.inputs.final_path.is_symlink():
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)

    def run(self, *, resume_operation_id: str | None = None) -> BootstrapResult:
        self._prepare_roots()
        initial_current = _current_snapshot(self.inputs.current_path)
        with exclusive_bootstrap_lock(self.inputs.lock_path, policy=self.policy):
            result = self._run_locked(initial_current, resume_operation_id=resume_operation_id)
        if _current_snapshot(self.inputs.current_path) != initial_current:
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        return result

    def _run_locked(
        self,
        initial_current: tuple[str, str],
        *,
        resume_operation_id: str | None,
    ) -> BootstrapResult:
        operation_id = resume_operation_id or str(uuid4())
        operation_root = self.inputs.preparation_state_root / operation_id
        atomic_policy = AtomicCreatePolicyV1(
            owner_uid=self.policy.filesystem_owner_uid,
            owner_gid=self.policy.filesystem_owner_gid,
            mode=0o600,
            trust_root=self.inputs.preparation_state_root,
        )
        store = GateBJournalStore(operation_root, policy=atomic_policy)
        if resume_operation_id is None:
            state = store.initialize(
                operation_id=operation_id,
                candidate_sha=self.inputs.expected_candidate_sha,
                started_at=_now(),
                tool=self.inputs.bootstrap_tool_identity,
            )
            events: tuple[PreparationJournalEventV1, ...] = ()
        else:
            state, events = store.load_retryable()
            if (
                state.operation_id != operation_id
                or state.candidate_sha != self.inputs.expected_candidate_sha
                or state.operator_tool_identities != (self.inputs.bootstrap_tool_identity,)
            ):
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        self._active_state = state
        self._active_events = events
        quarantine = operation_root / "quarantine"
        staging = self.inputs.releases_root / f".p3d-staging-{self.inputs.expected_candidate_sha}-{operation_id}"
        home = operation_root / "home"
        final_committed = state.phase in {
            GateBPhase.FINAL_RENAME_COMMITTED.value,
            GateBPhase.FINAL_VERIFIED.value,
            GateBPhase.COMPLETE.value,
        }
        try:
            result = self._execute(
                state=state,
                events=events,
                store=store,
                quarantine=quarantine,
                staging=staging,
                home=home,
                initial_current=initial_current,
            )
            return result
        except BootstrapError as error:
            active_state = self._active_state or state
            active_events = self._active_events
            final_committed = final_committed or active_state.phase in {
                GateBPhase.FINAL_RENAME_COMMITTED.value,
                GateBPhase.FINAL_VERIFIED.value,
                GateBPhase.COMPLETE.value,
            }
            if active_state.phase not in {GateBPhase.COMPLETE.value, GateBPhase.FAILED.value}:
                try:
                    store.advance(
                        active_state,
                        active_events,
                        GateBPhase.FAILED,
                        tool=self.inputs.bootstrap_tool_identity,
                        evidence_fingerprints=(_sha256_bytes(error.code.value.encode()),),
                        failure_code=error.code,
                    )
                except Exception:
                    pass
            if not final_committed:
                _secure_remove(staging, allowed_parent=self.inputs.releases_root)
            _secure_remove(quarantine, allowed_parent=operation_root)
            _secure_remove(operation_root / "approved-bundle.tar", allowed_parent=operation_root)
            if _current_snapshot(self.inputs.current_path) != initial_current:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            raise

    def _execute(
        self,
        *,
        state: PreparationOperationStateV1,
        events: tuple[PreparationJournalEventV1, ...],
        store: GateBJournalStore,
        quarantine: Path,
        staging: Path,
        home: Path,
        initial_current: tuple[str, str],
    ) -> BootstrapResult:
        phases = {item.value: index for index, item in enumerate(GateBPhase) if item is not GateBPhase.FAILED}
        candidate = self.inputs.expected_candidate_sha

        sealed_bundle = _seal_bundle(
            self.inputs.bundle_path,
            store.root / "approved-bundle.tar",
            expected_sha256=self.inputs.expected_bundle_sha256,
            policy=self.policy,
        )

        try:
            digests = verify_release_input_bundle(
                sealed_bundle,
                expected_candidate_sha=candidate,
                expected_bundle_sha256=self.inputs.expected_bundle_sha256,
                expected_os_manifest_sha256=self.inputs.expected_os_runtime_manifest_sha256,
                perform_offline_install=False,
            )
        except ReleaseBundleError as error:
            code = FailureCode.RELEASE_WHEELHOUSE_INVALID if "WHEELHOUSE" in error.code else FailureCode.RELEASE_ARTIFACT_INVALID
            _fail(code)
        if quarantine.exists() or quarantine.is_symlink():
            if phases[state.phase] < phases[GateBPhase.ARTIFACT_VERIFIED.value]:
                _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        else:
            try:
                safe_extract_bundle(sealed_bundle, quarantine)
                for path in sorted(quarantine.rglob("*")):
                    if path.is_dir():
                        os.chmod(path, 0o700)
                    elif path.is_file():
                        os.chmod(path, 0o600)
                    os.chown(path, self.policy.filesystem_owner_uid, self.policy.filesystem_owner_gid)
                os.chown(quarantine, self.policy.filesystem_owner_uid, self.policy.filesystem_owner_gid)
                os.chmod(quarantine, 0o700)
            except (OSError, ReleaseBundleError):
                _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        authority = _parse_authority_class(quarantine)
        if authority != self.inputs.expected_authority_class:
            _fail(FailureCode.RELEASE_ARTIFACT_INVALID)
        artifact_fingerprint = _artifact_fingerprint(digests, authority)
        if state.phase == GateBPhase.NEW.value:
            state, events = self._advance(
                store, GateBPhase.ARTIFACT_VERIFIED,
                evidence_fingerprints=(artifact_fingerprint,),
            )

        try:
            manifest = load_os_runtime_manifest(quarantine / "manifests/os-runtime.json")
        except ReleaseBundleError:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        if os_runtime_manifest_fingerprint(manifest) != self.inputs.expected_os_runtime_manifest_sha256:
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        runtime_authority = self.host_runtime_provider.verify(manifest, policy=self.policy)
        if state.phase == GateBPhase.ARTIFACT_VERIFIED.value:
            state, events = self._advance(
                store, GateBPhase.OS_RUNTIME_VERIFIED,
                evidence_fingerprints=(
                    self.inputs.expected_os_runtime_manifest_sha256,
                    runtime_authority.authority_fingerprint,
                ),
            )

        if state.phase == GateBPhase.OS_RUNTIME_VERIFIED.value:
            if staging.exists() or staging.is_symlink():
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            try:
                staging.mkdir(mode=0o700)
                os.chown(staging, self.policy.filesystem_owner_uid, self.policy.filesystem_owner_gid)
                os.chmod(staging, 0o700)
                if staging.stat().st_dev != self.inputs.releases_root.stat().st_dev:
                    _fail(FailureCode.RELEASE_FINAL_CONFLICT)
                home.mkdir(mode=0o700, exist_ok=True)
                os.chown(home, self.policy.filesystem_owner_uid, self.policy.filesystem_owner_gid)
            except OSError:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            state, events = self._advance(
                store, GateBPhase.STAGING_CREATED,
                evidence_fingerprints=(contract_fingerprint({"candidate": candidate, "operation": state.operation_id}),),
            )
        else:
            if state.phase == GateBPhase.IMMUTABILITY_VERIFIED.value and not staging.exists() and self.inputs.final_path.exists():
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            _trusted_directory(
                staging,
                owner_uid=self.policy.filesystem_owner_uid,
                owner_gid=self.policy.filesystem_owner_gid,
            )

        if state.phase == GateBPhase.STAGING_CREATED.value:
            _checkout_source(staging, quarantine / "source/pdi.git.bundle", candidate=candidate, home=home)
            state, events = self._advance(
                store, GateBPhase.SOURCE_CHECKED_OUT,
                evidence_fingerprints=(_sha256_bytes(candidate.encode()),),
            )
        else:
            _verify_git(staging, candidate=candidate, home=home, code=FailureCode.RELEASE_SOURCE_CHECKOUT_FAILED)

        if state.phase == GateBPhase.SOURCE_CHECKED_OUT.value:
            _build_venv(staging, quarantine, runtime_authority.system_python_path)
            _rewrite_staging_references(staging, self.inputs.final_path)
            _canonicalize_tree(staging, policy=self.policy, home=home)
            state, events = self._advance(
                store, GateBPhase.VENV_BUILT,
                evidence_fingerprints=(
                    sha256_file(quarantine / "requirements/runtime.lock"),
                    sha256_file(quarantine / "manifests/wheelhouse.json"),
                ),
            )

        expected_head = _source_alembic_head(staging)
        if state.phase == GateBPhase.VENV_BUILT.value:
            alembic_head, runtime_fingerprint = _runtime_verify(
                staging,
                candidate=candidate,
                expected_alembic_head=expected_head,
                policy=self.policy,
                home=home,
            )
            state, events = self._advance(
                store, GateBPhase.RUNTIME_VERIFIED,
                evidence_fingerprints=(runtime_fingerprint, _sha256_bytes(alembic_head.encode())),
            )
        else:
            alembic_head, runtime_fingerprint = _runtime_verify(
                staging,
                candidate=candidate,
                expected_alembic_head=expected_head,
                policy=self.policy,
                home=home,
            )

        staged_fingerprint = _verify_release_tree(
            staging,
            candidate=candidate,
            policy=self.policy,
            approved_python=runtime_authority.system_python_path,
            home=home,
        )
        if state.phase == GateBPhase.RUNTIME_VERIFIED.value:
            _fsync_tree(staging)
            state, events = self._advance(
                store, GateBPhase.IMMUTABILITY_VERIFIED,
                evidence_fingerprints=(staged_fingerprint,),
            )

        if _current_snapshot(self.inputs.current_path) != initial_current:
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        disposition = "CREATED"
        try:
            _atomic_rename_no_replace(staging, self.inputs.final_path)
            _fsync_directory(self.inputs.releases_root)
        except FileExistsError:
            disposition = "IDEMPOTENT"
            try:
                final_fingerprint = _verify_release_tree(
                    self.inputs.final_path,
                    candidate=candidate,
                    policy=self.policy,
                    approved_python=runtime_authority.system_python_path,
                    home=home,
                )
                final_head = _source_alembic_head(self.inputs.final_path)
                _runtime_verify(
                    self.inputs.final_path,
                    candidate=candidate,
                    expected_alembic_head=final_head,
                    policy=self.policy,
                    home=home,
                )
            except BootstrapError:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            if final_fingerprint != staged_fingerprint:
                _fail(FailureCode.RELEASE_FINAL_CONFLICT)
            _secure_remove(staging, allowed_parent=self.inputs.releases_root)
        state, events = self._advance(
            store, GateBPhase.FINAL_RENAME_COMMITTED,
            evidence_fingerprints=(staged_fingerprint, _sha256_bytes(str(self.inputs.final_path).encode())),
        )

        final_fingerprint = _verify_release_tree(
            self.inputs.final_path,
            candidate=candidate,
            policy=self.policy,
            approved_python=runtime_authority.system_python_path,
            home=home,
        )
        final_head = _source_alembic_head(self.inputs.final_path)
        _, final_runtime_fingerprint = _runtime_verify(
            self.inputs.final_path,
            candidate=candidate,
            expected_alembic_head=final_head,
            policy=self.policy,
            home=home,
        )
        if final_fingerprint != staged_fingerprint or final_runtime_fingerprint != runtime_fingerprint:
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        state, events = self._advance(
            store, GateBPhase.FINAL_VERIFIED,
            evidence_fingerprints=(final_fingerprint, final_runtime_fingerprint),
        )
        if _current_snapshot(self.inputs.current_path) != initial_current:
            _fail(FailureCode.RELEASE_FINAL_CONFLICT)
        state, events = self._advance(
            store, GateBPhase.COMPLETE,
            evidence_fingerprints=(final_fingerprint,),
        )
        _secure_remove(quarantine, allowed_parent=store.root)
        _secure_remove(sealed_bundle, allowed_parent=store.root)
        return BootstrapResult(
            state.operation_id,
            disposition,
            self.inputs.final_path,
            final_fingerprint,
            state,
            events,
        )


def resolve_runtime_identity(user: str, group: str) -> tuple[int, int]:
    try:
        account = pwd.getpwnam(user)
        group_entry = grp.getgrnam(group)
    except KeyError:
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)
    if account.pw_uid == 0 or group_entry.gr_gid == 0:
        _fail(FailureCode.RELEASE_RUNTIME_INVALID)
    return account.pw_uid, group_entry.gr_gid


def bootstrap_artifact_design() -> dict[str, str]:
    """Non-building boundary for the separately reviewed future bootstrap artifact."""

    return {
        "FORMAT": "stdlib-pyz-v1",
        "AUTHORITY": "INDEPENDENT_BOOTSTRAP",
        "SELF_UPDATE": "FORBIDDEN",
        "BUILD_STATUS": "DEFERRED",
    }
