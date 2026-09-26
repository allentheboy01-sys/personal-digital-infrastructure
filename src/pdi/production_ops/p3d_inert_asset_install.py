"""MU13-P3D Gate C: install inert, candidate-bound systemd assets.

The production policy in this module has fixed paths.  Qualification may map
those logical paths below one disposable root, but the frozen authority
manifest always records the production paths.  The installer never reloads
systemd, changes enablement, invokes a pipeline, or mutates ``/opt/pdi/current``.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import shutil
import sys
from typing import Callable, Mapping, Protocol, Sequence
from uuid import UUID, uuid4

from pdi.database import create_postgres_engine
from pdi.production_ops.contracts import ENV_KEYS, QUALIFICATION, parse_env
from pdi.production_ops.enrichment_cutover import P3D_TIMER_UNITS
from pdi.production_ops.p3d_evidence import (
    PersonalDatabaseEvidence,
    RoutedPersonalDatabaseEvidenceReader,
)
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    AtomicCreateResult,
    CANONICAL_P3D_INSTALL_PATH_MODES,
    CANONICAL_P3D_INSTALL_PATHS,
    CANONICAL_P3D_PIPELINE_KEYS,
    CANONICAL_P3D_PROFILE_PATHS,
    CANONICAL_P3D_SYSTEMD_PATHS,
    FailureCode,
    GateAPhase,
    GateBPhase,
    GateCPhase,
    InstalledFileEntryV1,
    OperatorToolIdentity,
    P3DAssetInstallationCompleteV1,
    PreparationContractError,
    PreparationGate,
    PreparationJournalEventV1,
    PreparationOperationStateV1,
    RollbackReleasePinV1,
    ToolName,
    asset_installation_fingerprint,
    atomic_create_no_replace,
    canonical_json_bytes,
    contract_fingerprint,
    preparation_journal_fingerprint,
    release_pin_fingerprint,
    rollback_metadata_fingerprint,
    transition_preparation_state,
    validate_complete_marker_authorities,
    validate_preparation_journal_chain,
    validate_rollback_release_pin,
)
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapMode,
    BootstrapPolicy,
    _verify_release_tree,
)
from pdi.production_ops.p3d_release_bundle import (
    CANONICAL_SYSTEMD_ASSETS,
    SystemdAssetV1,
    systemd_asset_fingerprint,
)
from pdi.production_ops.p3d_rollback_qualification import parse_metadata
from pdi.scoped_enrichment_profiles import build_trusted_enrichment_profile, render_environment_file
from pdi.scoped_operator_config import load_scoped_operator_configuration


SYSTEMD_ANALYZE = Path("/usr/bin/systemd-analyze")
SYSTEMCTL = Path("/usr/bin/systemctl")
GIT = Path("/usr/bin/git")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
GIT_READ_ONLY_ENV = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_OPTIONAL_LOCKS": "0",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
P3C_TIMERS = (
    "pdi-p3c-nextcloud-incremental.timer",
    "pdi-p3c-nextcloud-full.timer",
    "pdi-p3c-immich-incremental.timer",
    "pdi-p3c-immich-daily.timer",
)
P3C_SERVICE = "pdi-p3c-writer@.service"


class InertAssetInstallError(RuntimeError):
    """Fixed, non-secret Gate C diagnostic."""

    def __init__(self, code: FailureCode):
        self.code = code
        super().__init__(code.value)


def _fail(code: FailureCode) -> None:
    raise InertAssetInstallError(code)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _safe_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError):
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
    if str(parsed) != value:
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
    return value


def _safe_sha(value: str, *, git: bool = False) -> str:
    pattern = GIT_SHA_RE if git else SHA256_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
    return value


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def verify_candidate_installer_runtime(
    policy: "InertAssetPolicy",
    candidate_sha: str,
    *,
    executable: Path | None = None,
    module_file: Path | None = None,
    script_file: Path | None = None,
    runner=subprocess.run,
) -> str:
    """Bind the running installer bytes and interpreter to one exact release."""
    candidate = _safe_sha(candidate_sha, git=True)
    release = policy.candidate_releases_root / candidate
    expected_python = release / ".venv/bin/python"
    expected_source = release / "src/pdi/production_ops/p3d_inert_asset_install.py"
    expected_script = release / "scripts/pdi_p3d_inert_asset_install.py"
    executable = Path(sys.executable if executable is None else executable).absolute()
    module_file = Path(__file__ if module_file is None else module_file).absolute()
    script_file = Path(sys.argv[0] if script_file is None else script_file).absolute()
    try:
        release_info = release.lstat()
        if (not stat.S_ISDIR(release_info.st_mode) or stat.S_ISLNK(release_info.st_mode) or
                executable != expected_python or script_file != expected_script):
            raise OSError
        resolved_python = executable.resolve(strict=True)
        resolved_module = module_file.resolve(strict=True)
        resolved_source = expected_source.resolve(strict=True)
        resolved_script = script_file.resolve(strict=True)
        venv = (release / ".venv").resolve(strict=True)
        if (not _inside(resolved_python, venv) or
                not _inside(resolved_module, venv) or
                resolved_source != expected_source or
                resolved_script != expected_script or
                resolved_module.read_bytes() != resolved_source.read_bytes()):
            raise OSError
        for argv in (
            (str(GIT), "-C", str(release), "rev-parse", "HEAD"),
            (str(GIT), "-C", str(release), "status", "--porcelain", "--untracked-files=all"),
        ):
            result = runner(
                argv, capture_output=True, text=True, timeout=30,
                env=dict(GIT_READ_ONLY_ENV), shell=False,
            )
            if result.returncode != 0:
                raise OSError
            if argv[-2:] == ("rev-parse", "HEAD"):
                if result.stdout.strip() != candidate:
                    raise OSError
            elif result.stdout.strip():
                raise OSError
        return _sha256(resolved_module.read_bytes())
    except (OSError, subprocess.TimeoutExpired):
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)


class InstallMode(str, Enum):
    QUALIFICATION = "QUALIFICATION"
    PRODUCTION = "PRODUCTION"


@dataclass(frozen=True)
class InertAssetPolicy:
    mode: InstallMode
    root: Path
    owner_uid: int
    owner_gid: int
    runtime_uid: int
    runtime_gid: int

    @classmethod
    def production(cls) -> "InertAssetPolicy":
        if os.geteuid() != 0:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        import grp
        import pwd
        try:
            account = pwd.getpwnam("pdi")
            group = grp.getgrnam("pdi")
            if account.pw_uid == 0 or group.gr_gid == 0:
                _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
            return cls(
                InstallMode.PRODUCTION, Path("/"), 0, 0,
                account.pw_uid, group.gr_gid,
            )
        except KeyError:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)

    @classmethod
    def qualification(
        cls, root: Path, *, owner_uid: int, owner_gid: int,
        runtime_uid: int, runtime_gid: int,
    ) -> "InertAssetPolicy":
        root = root.absolute()
        if (root == Path("/") or not root.is_dir() or root.is_symlink() or
                owner_uid < 0 or owner_gid < 0 or runtime_uid == 0 or runtime_gid == 0):
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        return cls(InstallMode.QUALIFICATION, root, owner_uid, owner_gid, runtime_uid, runtime_gid)

    def physical(self, logical: str | Path) -> Path:
        logical_path = PurePosixPath(str(logical))
        if not logical_path.is_absolute() or ".." in logical_path.parts:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        if self.mode is InstallMode.PRODUCTION:
            return Path(str(logical_path))
        return self.root.joinpath(*logical_path.parts[1:])

    @property
    def candidate_releases_root(self) -> Path:
        return self.physical("/opt/pdi/releases")

    @property
    def current(self) -> Path:
        return self.physical("/opt/pdi/current")

    @property
    def registry(self) -> Path:
        return self.physical("/etc/pdi/scoped/registry.toml")

    @property
    def environment(self) -> Path:
        return self.physical("/etc/pdi/pdi.env")

    @property
    def p3c_state(self) -> Path:
        return self.physical("/var/lib/pdi-p3c/state.json")

    @property
    def preparation_root(self) -> Path:
        return self.physical("/var/lib/pdi-p3d/preparation")

    @property
    def gate_c_root(self) -> Path:
        return self.preparation_root / "inert-assets"

    @property
    def lock_path(self) -> Path:
        return self.physical("/run/lock/pdi/p3d-inert-asset-install.lock")


@dataclass(frozen=True)
class InertAssetInputs:
    candidate_sha: str
    gate_a_operation_id: str
    gate_b_operation_id: str
    expected_systemd_asset_fingerprint: str
    tool_identity: OperatorToolIdentity

    def validate(self) -> None:
        _safe_sha(self.candidate_sha, git=True)
        _safe_uuid(self.gate_a_operation_id)
        _safe_uuid(self.gate_b_operation_id)
        _safe_sha(self.expected_systemd_asset_fingerprint)
        if (self.tool_identity.tool_name is not ToolName.INERT_ASSET_INSTALL or
                self.tool_identity.tool_source_sha != self.candidate_sha):
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)


@dataclass(frozen=True)
class PrerequisiteEvidence:
    rollback_metadata: object
    rollback_metadata_sha256: str
    release_pin: RollbackReleasePinV1
    gate_b_release_fingerprint: str
    current_target: str
    p3c_context_fingerprint: str
    p3c_state_sha256: str
    p3c_systemd_before: str


@dataclass(frozen=True)
class SystemdSnapshot:
    p3c_fingerprint: str
    p3d_fingerprint: str
    p3d_quiet: bool


@dataclass(frozen=True)
class SystemdReadResult:
    action: str
    unit: str
    returncode: int
    value: str


@dataclass(frozen=True)
class RenderedAssets:
    content: Mapping[str, bytes]
    expected_manifest: tuple[InstalledFileEntryV1, ...]
    installation_fingerprint: str
    candidate_systemd_fingerprint: str


@dataclass(frozen=True)
class InertAssetInstallResult:
    operation_id: str
    disposition: str
    marker: P3DAssetInstallationCompleteV1
    final_state: PreparationOperationStateV1
    events: tuple[PreparationJournalEventV1, ...]


class SystemdStateProvider(Protocol):
    def snapshot(self, *, post_install: bool = False) -> SystemdSnapshot: ...


class ProductionReadOnlySystemdStateProvider:
    """Fixed systemctl read surface.  No caller-provided action is accepted."""

    def __init__(self, runner=subprocess.run) -> None:
        self.runner = runner

    def _read(self, action: str, unit: str) -> SystemdReadResult:
        if action not in {"is-enabled", "is-active", "show"}:
            _fail(FailureCode.ASSET_SYSTEMD_NOT_QUIET)
        argv = (str(SYSTEMCTL), action, unit)
        if action == "show":
            argv = (*argv, "--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath")
        try:
            result = self.runner(
                argv, capture_output=True, text=True,
                timeout=30, env=dict(SAFE_ENV), shell=False,
            )
            value = result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            _fail(FailureCode.ASSET_SYSTEMD_NOT_QUIET)
        if not value or (action != "show" and "\n" in value):
            _fail(FailureCode.ASSET_SYSTEMD_NOT_QUIET)
        return SystemdReadResult(action, unit, result.returncode, value)

    @staticmethod
    def _exact(result: SystemdReadResult, expected: str, returncodes: frozenset[int]) -> bool:
        return result.value == expected and result.returncode in returncodes

    def snapshot(self, *, post_install: bool = False) -> SystemdSnapshot:
        p3c: list[dict[str, object]] = []
        for unit in (*P3C_TIMERS, P3C_SERVICE):
            enabled = self._read("is-enabled", unit)
            active = self._read("is-active", unit)
            shown = self._read("show", unit)
            if unit in P3C_TIMERS and not (
                    self._exact(enabled, "enabled", frozenset({0})) and
                    self._exact(active, "active", frozenset({0})) and
                    shown.returncode == 0):
                _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
            if shown.returncode != 0:
                _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
            p3c.append({
                "unit": unit, "enabled": enabled.value, "active": active.value,
                "show_sha256": _sha256(shown.value.encode()),
            })
        p3d: list[dict[str, str]] = []
        quiet = True
        for key in CANONICAL_P3D_PIPELINE_KEYS:
            unit = P3D_TIMER_UNITS[key]
            enabled = self._read("is-enabled", unit)
            active = self._read("is-active", unit)
            disabled_inactive = (
                self._exact(enabled, "disabled", frozenset({1})) and
                self._exact(active, "inactive", frozenset({3}))
            )
            absent_quiet = (
                not post_install and
                self._exact(enabled, "not-found", frozenset({1, 4})) and
                (
                    self._exact(active, "unknown", frozenset({3, 4})) or
                    self._exact(active, "inactive", frozenset({3}))
                )
            )
            if not (disabled_inactive or absent_quiet):
                quiet = False
            p3d.append({"unit": unit, "enabled": enabled.value, "active": active.value})
        return SystemdSnapshot(
            contract_fingerprint({"p3c": p3c}),
            contract_fingerprint({"p3d": p3d}),
            quiet,
        )


class SyntheticSystemdStateProvider:
    """Qualification-only state provider; never selected by production policy."""

    def __init__(self, snapshot: SystemdSnapshot) -> None:
        self.value = snapshot
        self.calls = 0

    def snapshot(self, *, post_install: bool = False) -> SystemdSnapshot:
        self.calls += 1
        return self.value


def _trusted_leaf(path: Path, *, policy: InertAssetPolicy, mode: int,
                  group: int | None = None) -> None:
    try:
        info = path.lstat()
        expected_gid = policy.owner_gid if group is None else group
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                info.st_uid != policy.owner_uid or info.st_gid != expected_gid or
                stat.S_IMODE(info.st_mode) != mode):
            raise OSError
        current = path.parent
        while True:
            parent = current.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or
                    parent.st_uid != policy.owner_uid or parent.st_mode & 0o022):
                raise OSError
            if current == policy.root:
                break
            if policy.root not in current.parents:
                raise OSError
            current = current.parent
    except OSError:
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)


def _secure_read_policy(path: Path, *, policy: InertAssetPolicy, mode: int,
                        gid: int) -> str:
    """Read one protected file after validating its chain to the policy root."""
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                info.st_uid != policy.owner_uid or info.st_gid != gid or
                stat.S_IMODE(info.st_mode) != mode):
            raise OSError
        current = path.parent
        while True:
            parent = current.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or
                    parent.st_uid != policy.owner_uid or parent.st_mode & 0o022):
                raise OSError
            if current == policy.root:
                break
            if policy.root not in current.parents:
                raise OSError
            current = current.parent
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _fail(FailureCode.ASSET_REGISTRY_INVALID)


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)


@dataclass(frozen=True)
class FrozenP3CPassEvidence:
    """Safe subset of one exact frozen P3C V0.1 PASS state."""

    context_fingerprint: str
    state_sha256: str


_FROZEN_P3C_PASS_FIELDS = {
    "phase", "sha", "old_target", "context", "baseline", "qualified", "verified",
}


def _read_frozen_p3c_pass_state(
    path: Path, *, policy: InertAssetPolicy,
    expected_sha: str, expected_context: str,
) -> FrozenP3CPassEvidence:
    """Read only the exact frozen P3C state schema; never expose private evidence."""
    expected_sha = _safe_sha(expected_sha, git=True)
    expected_context = _safe_sha(expected_context)
    try:
        _trusted_leaf(path, policy=policy, mode=0o600)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != policy.owner_uid or
                    info.st_gid != policy.owner_gid or stat.S_IMODE(info.st_mode) != 0o600):
                raise OSError
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read()
        finally:
            os.close(descriptor)
        state = json.loads(payload.decode("utf-8"))
        if type(state) is not dict or set(state) != _FROZEN_P3C_PASS_FIELDS:
            raise ValueError
        if (state["phase"] != "PASS" or state["sha"] != expected_sha or
                state["context"] != expected_context or
                type(state["qualified"]) is not list or
                state["qualified"] != list(QUALIFICATION) or
                type(state["baseline"]) is not dict or not state["baseline"] or
                type(state["verified"]) is not dict or not state["verified"] or
                not isinstance(state["old_target"], str) or not state["old_target"] or
                any(ord(character) < 32 or 0x7f <= ord(character) <= 0x9f
                    for character in state["old_target"])):
            raise ValueError
        return FrozenP3CPassEvidence(expected_context, _sha256(payload))
    except InertAssetInstallError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, TypeError):
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)


def _load_complete_gate(
    root: Path, *, gate: PreparationGate, candidate: str,
    owner_uid: int, owner_gid: int,
) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
    try:
        root_info = root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or
                root_info.st_uid != owner_uid or root_info.st_gid != owner_gid or
                stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ValueError
        state_paths = sorted(root.glob("state-*.json"))
        event_paths = sorted(root.glob("journal-*.json"))
        if not state_paths or len(state_paths) != len(event_paths) + 1:
            raise ValueError
        if [p.name for p in state_paths] != [f"state-{n:06d}.json" for n in range(len(state_paths))]:
            raise ValueError
        if [p.name for p in event_paths] != [f"journal-{n:06d}.json" for n in range(1, len(state_paths))]:
            raise ValueError
        for path in (*state_paths, *event_paths):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                    info.st_uid != owner_uid or info.st_gid != owner_gid or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError
        states = tuple(PreparationOperationStateV1.from_mapping(_read_json(path)) for path in state_paths)
        events = tuple(PreparationJournalEventV1.from_mapping(_read_json(path)) for path in event_paths)
        if (states[0].phase != "NEW" or states[0].evidence_fingerprint is not None or
                states[0].operation_id != states[-1].operation_id):
            raise ValueError
        for index, persisted in enumerate(states[1:], start=1):
            validate_preparation_journal_chain(events[:index], persisted)
        state = states[-1]
        if (state.gate is not gate or state.candidate_sha != candidate or
                state.phase != "COMPLETE" or not events):
            raise ValueError
        validate_preparation_journal_chain(events, state)
        return state, events
    except (OSError, ValueError, PreparationContractError):
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)


class ProtectedPrerequisiteReader:
    """Read Gate A/B and live immutable prerequisites from fixed policy roots."""

    def __init__(self, policy: InertAssetPolicy, inputs: InertAssetInputs,
                 systemd: SystemdStateProvider) -> None:
        self.policy = policy
        self.inputs = inputs
        self.systemd = systemd

    def _current_target(self, rollback_source: str) -> str:
        expected = f"/opt/pdi/releases/{rollback_source}"
        try:
            info = self.policy.current.lstat()
            target = os.readlink(self.policy.current)
        except OSError:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != self.policy.owner_uid or
                target != expected):
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        return expected

    def collect(self, *, home: Path) -> PrerequisiteEvidence:
        candidate = self.inputs.candidate_sha
        gate_a = (
            self.policy.preparation_root
            / f"operation-{self.inputs.gate_a_operation_id}"
            / "authority"
        )
        _, gate_a_events = _load_complete_gate(
            gate_a, gate=PreparationGate.ROLLBACK_QUALIFICATION,
            candidate=candidate, owner_uid=self.policy.owner_uid, owner_gid=self.policy.owner_gid,
        )
        metadata_path = gate_a / "p3d-pre-enrichment.env"
        _trusted_leaf(metadata_path, policy=self.policy, mode=0o600)
        try:
            metadata = parse_metadata(metadata_path.read_bytes())
        except Exception:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        metadata_hash = rollback_metadata_fingerprint(metadata)
        pin_path = gate_a / f"rollback-release-pin-{metadata.snapshot_id}.json"
        _trusted_leaf(pin_path, policy=self.policy, mode=0o600)
        try:
            pin = RollbackReleasePinV1.from_mapping(_read_json(pin_path))
            validate_rollback_release_pin(metadata, pin)
        except (PreparationContractError, ValueError):
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        if (metadata.target_candidate_sha != candidate or
                metadata_hash not in gate_a_events[-1].evidence_fingerprints):
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)

        gate_b = self.policy.preparation_root / self.inputs.gate_b_operation_id
        _, gate_b_events = _load_complete_gate(
            gate_b, gate=PreparationGate.RELEASE_STAGING,
            candidate=candidate, owner_uid=self.policy.owner_uid, owner_gid=self.policy.owner_gid,
        )
        if len(gate_b_events[-1].evidence_fingerprints) != 1:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        gate_b_fingerprint = gate_b_events[-1].evidence_fingerprints[0]
        release = self.policy.candidate_releases_root / candidate
        bootstrap_policy = BootstrapPolicy(
            mode=(BootstrapMode.PRODUCTION if self.policy.mode is InstallMode.PRODUCTION
                  else BootstrapMode.QUALIFICATION),
            trust_root=self.policy.root,
            filesystem_owner_uid=self.policy.owner_uid,
            filesystem_owner_gid=self.policy.owner_gid,
            runtime_uid=self.policy.runtime_uid,
            runtime_gid=self.policy.runtime_gid,
            expected_authority_class=(
                "PRODUCTION_RELEASE" if self.policy.mode is InstallMode.PRODUCTION
                else "QUALIFICATION_ONLY"
            ),
            approved_external_runtime_roots=(Path("/usr"),),
        )
        try:
            approved_python = (release / ".venv/bin/python").resolve(strict=True)
            actual_release_fingerprint = _verify_release_tree(
                release, candidate=candidate, policy=bootstrap_policy,
                approved_python=approved_python, home=home,
            )
        except Exception:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
        if actual_release_fingerprint != gate_b_fingerprint:
            _fail(FailureCode.ASSET_PREREQUISITE_INVALID)

        current = self._current_target(metadata.source_release_sha)
        p3c = _read_frozen_p3c_pass_state(
            self.policy.p3c_state, policy=self.policy,
            expected_sha=metadata.source_release_sha,
            expected_context=metadata.p3c_context_fingerprint,
        )
        snapshot = self.systemd.snapshot(post_install=False)
        if not snapshot.p3d_quiet:
            _fail(FailureCode.ASSET_SYSTEMD_NOT_QUIET)
        return PrerequisiteEvidence(
            metadata, metadata_hash, pin, gate_b_fingerprint, current,
            p3c.context_fingerprint, p3c.state_sha256, snapshot.p3c_fingerprint,
        )

    def verify_p3c_state_unchanged(self, evidence: PrerequisiteEvidence) -> None:
        """Re-read the frozen P3C authority immediately before Gate C completion."""
        try:
            current = _read_frozen_p3c_pass_state(
                self.policy.p3c_state, policy=self.policy,
                expected_sha=evidence.rollback_metadata.source_release_sha,
                expected_context=evidence.rollback_metadata.p3c_context_fingerprint,
            )
            if current.state_sha256 != evidence.p3c_state_sha256:
                _fail(FailureCode.ASSET_COMPLETE_MARKER_FAILED)
        except InertAssetInstallError:
            _fail(FailureCode.ASSET_COMPLETE_MARKER_FAILED)


class GateCJournalStore:
    """Immutable Gate C state/event sequence with frozen whole-chain checks."""

    def __init__(self, root: Path, *, policy: AtomicCreatePolicyV1) -> None:
        self.root = root
        self.policy = policy

    def initialize(self, *, operation_id: str, candidate_sha: str,
                   tool: OperatorToolIdentity) -> PreparationOperationStateV1:
        try:
            self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
            os.chown(self.root, self.policy.owner_uid, self.policy.owner_gid)
            os.chmod(self.root, 0o700)
        except OSError:
            _fail(FailureCode.ASSET_FILE_CONFLICT)
        timestamp = _now()
        state = PreparationOperationStateV1.from_mapping({
            "version": 1, "operation_id": operation_id,
            "gate": PreparationGate.INERT_ASSET_INSTALL.value,
            "candidate_sha": candidate_sha, "phase": GateCPhase.NEW.value,
            "started_at": timestamp, "updated_at": timestamp,
            "operator_tool_identities": [tool.to_mapping()],
            "evidence_fingerprint": None, "failure_code": None,
        })
        atomic_create_no_replace(
            self.root / "state-000000.json",
            canonical_json_bytes(state.to_mapping()) + b"\n", policy=self.policy,
        )
        return state

    def advance(self, state: PreparationOperationStateV1,
                events: tuple[PreparationJournalEventV1, ...], target: GateCPhase,
                *, tool: OperatorToolIdentity, evidence: Sequence[str],
                failure_code: FailureCode | None = None,
                timestamp: str | None = None,
                ) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        timestamp = timestamp or _now()
        event = PreparationJournalEventV1.from_mapping({
            "version": 1, "sequence": len(events) + 1,
            "operation_id": state.operation_id, "gate": state.gate.value,
            "candidate_sha": state.candidate_sha, "from_state": state.phase,
            "to_state": target.value, "timestamp": timestamp,
            "tool_identity": tool.to_mapping(),
            "evidence_fingerprints": sorted(set(evidence)),
            "failure_code": None if failure_code is None else failure_code.value,
        })
        next_events = (*events, event)
        next_state = transition_preparation_state(
            state, target.value, updated_at=timestamp,
            evidence_fingerprint=preparation_journal_fingerprint(next_events),
            failure_code=failure_code,
        )
        validate_preparation_journal_chain(next_events, next_state)
        atomic_create_no_replace(
            self.root / f"journal-{event.sequence:06d}.json",
            canonical_json_bytes(event.to_mapping()) + b"\n", policy=self.policy,
        )
        atomic_create_no_replace(
            self.root / f"state-{event.sequence:06d}.json",
            canonical_json_bytes(next_state.to_mapping()) + b"\n", policy=self.policy,
        )
        return next_state, next_events

    def load_partial(self) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        state, events = _load_complete_or_partial_gate_c(
            self.root, owner_uid=self.policy.owner_uid, owner_gid=self.policy.owner_gid,
        )
        if state.phase != GateCPhase.FILES_PARTIALLY_INSTALLED.value:
            _fail(FailureCode.ASSET_FILE_CONFLICT)
        return state, events


def _load_complete_or_partial_gate_c(root: Path, *, owner_uid: int, owner_gid: int):
    try:
        root_info = root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or
                root_info.st_uid != owner_uid or root_info.st_gid != owner_gid or
                stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ValueError
        state_paths = sorted(root.glob("state-*.json"))
        event_paths = sorted(root.glob("journal-*.json"))
        if not state_paths or len(state_paths) != len(event_paths) + 1:
            raise ValueError
        if [p.name for p in state_paths] != [f"state-{n:06d}.json" for n in range(len(state_paths))]:
            raise ValueError
        if [p.name for p in event_paths] != [f"journal-{n:06d}.json" for n in range(1, len(state_paths))]:
            raise ValueError
        states = tuple(PreparationOperationStateV1.from_mapping(_read_json(p)) for p in state_paths)
        events = tuple(PreparationJournalEventV1.from_mapping(_read_json(p)) for p in event_paths)
        for path in (*state_paths, *event_paths):
            info = path.lstat()
            if (info.st_uid != owner_uid or info.st_gid != owner_gid or
                    stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode)):
                raise ValueError
        state = states[-1]
        if states[0].phase != "NEW" or states[0].evidence_fingerprint is not None:
            raise ValueError
        for index, persisted in enumerate(states[1:], start=1):
            validate_preparation_journal_chain(events[:index], persisted)
        return state, events
    except Exception:
        _fail(FailureCode.ASSET_FILE_CONFLICT)


@contextmanager
def exclusive_gate_c_lock(path: Path, *, policy: InertAssetPolicy):
    try:
        info = path.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                info.st_uid != policy.owner_uid or info.st_gid != policy.owner_gid or
                info.st_mode & 0o022):
            raise OSError
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.fchown(fd, policy.owner_uid, policy.owner_gid)
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        _fail(FailureCode.ASSET_PREREQUISITE_INVALID)
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class SystemdStaticVerifier:
    """Real offline systemd-analyze verification using a private root."""

    def __init__(self, runner=subprocess.run) -> None:
        self.runner = runner

    def verify(self, *, root: Path, content: Mapping[str, bytes], candidate_sha: str,
               owner_uid: int, owner_gid: int, runtime_uid: int, runtime_gid: int) -> str:
        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
            os.chown(root, owner_uid, owner_gid)
            unit_dir = root / "etc/systemd/system"
            profile_dir = root / "etc/pdi/scoped/units"
            for directory, mode in ((unit_dir, 0o755), (profile_dir, 0o700)):
                directory.mkdir(parents=True, exist_ok=True)
                os.chown(directory, owner_uid, owner_gid)
                os.chmod(directory, mode)
            for logical, payload in content.items():
                target = root.joinpath(*PurePosixPath(logical).parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                os.chown(target, owner_uid, owner_gid)
                os.chmod(target, int(CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8))
            for target in ("sysinit", "basic", "shutdown", "timers", "network-online"):
                path = unit_dir / f"{target}.target"
                path.write_text("[Unit]\nDescription=Gate C static target\n", encoding="utf-8")
                os.chown(path, owner_uid, owner_gid)
                os.chmod(path, 0o644)
            passwd = root / "etc/passwd"
            group = root / "etc/group"
            passwd.write_text(
                f"root:x:0:0:root:/root:/bin/sh\npdi:x:{runtime_uid}:{runtime_gid}:pdi:/nonexistent:/usr/sbin/nologin\n",
                encoding="utf-8",
            )
            group.write_text(f"root:x:0:\npdi:x:{runtime_gid}:\n", encoding="utf-8")
            for path in (passwd, group):
                os.chown(path, owner_uid, owner_gid)
                os.chmod(path, 0o644)
            executable = root / "opt/pdi/current/.venv/bin/python"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 125\n", encoding="utf-8")
            os.chown(executable, owner_uid, owner_gid)
            os.chmod(executable, 0o755)
            registry = root / "etc/pdi/scoped/registry.toml"
            registry.parent.mkdir(parents=True, exist_ok=True)
            registry.write_text("# static-only\n", encoding="utf-8")
            os.chown(registry, owner_uid, owner_gid)
            os.chmod(registry, 0o600)
            names = tuple(Path(path).name for path in sorted(CANONICAL_P3D_SYSTEMD_PATHS))
            command = (
                str(SYSTEMD_ANALYZE), f"--root={root}", "--generators=no", "--man=no",
                "verify", *names,
            )
            result = self.runner(
                command, capture_output=True, text=True, timeout=60,
                env=dict(SAFE_ENV), shell=False,
            )
            if result.returncode != 0:
                _fail(FailureCode.ASSET_STATIC_VERIFY_FAILED)
            return contract_fingerprint({"systemd_analyze": names, "candidate": candidate_sha})
        except InertAssetInstallError:
            raise
        except Exception:
            _fail(FailureCode.ASSET_STATIC_VERIFY_FAILED)


def _validate_static_contract(
    content: Mapping[str, bytes],
    *, expected_profile_keys: Mapping[str, frozenset[str]] | None = None,
) -> None:
    try:
        service = content["/etc/systemd/system/pdi-scoped-pipeline@.service"].decode()
        required = (
            "EnvironmentFile=/etc/pdi/scoped/units/%i.env",
            "WorkingDirectory=/opt/pdi/current", "User=pdi", "Group=pdi",
            "NoNewPrivileges=true",
            "ExecStart=/opt/pdi/current/.venv/bin/python -m pdi.production_ops.enrichment ",
        )
        if any(item not in service for item in required):
            raise ValueError
        for key in CANONICAL_P3D_PIPELINE_KEYS:
            timer = P3D_TIMER_UNITS[key]
            logical = f"/etc/systemd/system/{timer}"
            text = content[logical].decode()
            if f"Unit=pdi-scoped-pipeline@{key}.service" not in text:
                raise ValueError
            profile = content[f"/etc/pdi/scoped/units/{key}.env"].decode()
            values: dict[str, str] = {}
            for line in profile.splitlines():
                name, separator, encoded = line.partition("=")
                if not separator:
                    raise ValueError
                values[name] = json.loads(encoded)
            if (values.get("PDI_SCOPED_PIPELINE_KEY") != key or
                    "PDI_PRINCIPAL_REF" not in values or len(values) < 3):
                raise ValueError
            if expected_profile_keys is not None and set(values) != set(expected_profile_keys[key]):
                raise ValueError
    except (KeyError, UnicodeError, ValueError, json.JSONDecodeError):
        _fail(FailureCode.ASSET_STATIC_VERIFY_FAILED)


def _manifest_from_content(content: Mapping[str, bytes]) -> tuple[InstalledFileEntryV1, ...]:
    if set(content) != set(CANONICAL_P3D_INSTALL_PATHS):
        _fail(FailureCode.ASSET_FILE_CONFLICT)
    return tuple(sorted(
        InstalledFileEntryV1(
            path, _sha256(content[path]), 0, 0, CANONICAL_P3D_INSTALL_PATH_MODES[path],
        ) for path in content
    ))


class InertAssetInstaller:
    """Gate C orchestration.  All workload and systemd mutation APIs are absent."""

    def __init__(
        self, *, inputs: InertAssetInputs, policy: InertAssetPolicy,
        systemd: SystemdStateProvider,
        prerequisite_reader_factory: Callable[..., object] = ProtectedPrerequisiteReader,
        static_verifier: SystemdStaticVerifier | None = None,
        configuration_loader=load_scoped_operator_configuration,
        db_evidence_reader_factory=RoutedPersonalDatabaseEvidenceReader,
        engine_factory=create_postgres_engine,
        crash_after_new_files: int | None = None,
    ) -> None:
        self.inputs = inputs
        self.policy = policy
        self.systemd = systemd
        self.prerequisite_reader_factory = prerequisite_reader_factory
        self.static_verifier = static_verifier or SystemdStaticVerifier()
        self.configuration_loader = configuration_loader
        self.db_evidence_reader_factory = db_evidence_reader_factory
        self.engine_factory = engine_factory
        self.crash_after_new_files = crash_after_new_files

    def _ensure_roots(self) -> None:
        for path, mode in (
            (self.policy.preparation_root, 0o700),
            (self.policy.gate_c_root, 0o700),
            (self.policy.lock_path.parent, 0o700),
        ):
            if not path.exists():
                path.mkdir(mode=mode, parents=True)
                os.chown(path, self.policy.owner_uid, self.policy.owner_gid)
                os.chmod(path, mode)
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                    info.st_uid != self.policy.owner_uid or info.st_gid != self.policy.owner_gid or
                    info.st_mode & 0o022):
                _fail(FailureCode.ASSET_PREREQUISITE_INVALID)

    def _load_configuration(self):
        try:
            env_text = _secure_read_policy(
                self.policy.environment, policy=self.policy, mode=0o600,
                gid=self.policy.owner_gid,
            )
            env = parse_env(env_text)
            if set(env) != ENV_KEYS or any(not value for value in env.values()):
                raise ValueError
            registry_text = _secure_read_policy(
                self.policy.registry, policy=self.policy, mode=0o640,
                gid=self.policy.runtime_gid,
            )
            registry_before = self.policy.registry.read_bytes()
            env_stat = self.policy.environment.stat()
            configuration = self.configuration_loader(self.policy.registry, environment=env)
            enabled = configuration.router._principals.list_enabled()
            if len(enabled) != 1:
                raise ValueError
            principal_ref = str(enabled[0].principal_id)
            return (
                configuration, principal_ref, registry_before,
                (
                    env_stat.st_ino, env_stat.st_size, env_stat.st_mtime_ns,
                    _sha256(env_text.encode("utf-8")),
                ),
                _sha256(registry_text.encode()),
            )
        except Exception:
            _fail(FailureCode.ASSET_REGISTRY_INVALID)

    def _collect_db_evidence(self, configuration, principal_ref: str):
        try:
            binding = configuration.router.resolve(principal_ref)
            engine = self.engine_factory(binding.database_url)
            try:
                evidence = self.db_evidence_reader_factory(
                    configuration.router, engine, principal_ref=principal_ref,
                ).collect()
            finally:
                engine.dispose()
            if not evidence.transaction_read_only or evidence.principal_ref != principal_ref:
                raise ValueError
            return evidence
        except Exception:
            _fail(FailureCode.ASSET_DB_EVIDENCE_INVALID)

    def _render_assets(self, configuration, principal_ref: str,
                       evidence: PersonalDatabaseEvidence) -> RenderedAssets:
        content: dict[str, bytes] = {}
        release_systemd = (
            self.policy.candidate_releases_root / self.inputs.candidate_sha / "deployment/systemd"
        )
        assets: list[SystemdAssetV1] = []
        try:
            actual_names = {path.name for path in release_systemd.glob("pdi-scoped-enrichment-*.timer")}
            if actual_names != set(CANONICAL_SYSTEMD_ASSETS[1:]):
                raise ValueError
            for name in CANONICAL_SYSTEMD_ASSETS:
                source = release_systemd / name
                if not source.is_file() or source.is_symlink():
                    raise ValueError
                payload = source.read_bytes()
                logical = f"/etc/systemd/system/{name}"
                content[logical] = payload
                assets.append(SystemdAssetV1(
                    f"deployment/systemd/{name}", logical, _sha256(payload), "0644",
                ))
            systemd_hash = systemd_asset_fingerprint(tuple(assets))
            if systemd_hash != self.inputs.expected_systemd_asset_fingerprint:
                raise ValueError
            scope_ids = {UUID(value) for value in evidence.enabled_scope_ids}
            enabled_bindings = {
                scope_id: binding
                for (bound_principal, scope_id), binding in configuration.bindings.items()
                if str(bound_principal) == principal_ref and scope_id in scope_ids
            }
            if (set(enabled_bindings) != scope_ids or
                    {binding.provider_type for binding in enabled_bindings.values()} != {
                        "nextcloud", "immich"
                    }):
                raise ValueError
            expected_keys: dict[str, frozenset[str]] = {}
            for key in CANONICAL_P3D_PIPELINE_KEYS:
                values = build_trusted_enrichment_profile(
                    configuration, principal_ref, key, enabled_scope_ids=scope_ids,
                )
                database_key = configuration.router.database_environment_key(principal_ref)
                provider = "nextcloud" if key.startswith("enrichment.nextcloud_") else (
                    "immich" if key == "enrichment.immich_ocr" else None
                )
                secrets = {
                    binding.secret_env
                    for (bound_principal, scope_id), binding in configuration.bindings.items()
                    if str(bound_principal) == principal_ref and scope_id in scope_ids
                    and binding.provider_type == provider
                } if provider is not None else set()
                expected = frozenset({
                    "PDI_PRINCIPAL_REF", "PDI_SCOPED_PIPELINE_KEY", database_key, *secrets,
                })
                if set(values) != set(expected):
                    raise ValueError
                expected_keys[key] = expected
                content[f"/etc/pdi/scoped/units/{key}.env"] = (
                    render_environment_file(values).encode("utf-8")
                )
            _validate_static_contract(content, expected_profile_keys=expected_keys)
            manifest = _manifest_from_content(content)
            return RenderedAssets(content, manifest, asset_installation_fingerprint(manifest), systemd_hash)
        except InertAssetInstallError:
            raise
        except Exception:
            _fail(FailureCode.ASSET_PROFILE_INVALID)

    def _physical_entry(self, logical: str, expected: bytes) -> InstalledFileEntryV1:
        path = self.policy.physical(logical)
        try:
            info = path.lstat()
            mode = int(CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8)
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                    info.st_uid != self.policy.owner_uid or info.st_gid != self.policy.owner_gid or
                    stat.S_IMODE(info.st_mode) != mode or path.read_bytes() != expected):
                raise OSError
            return InstalledFileEntryV1(
                logical, _sha256(expected), 0, 0, CANONICAL_P3D_INSTALL_PATH_MODES[logical],
            )
        except OSError:
            _fail(FailureCode.ASSET_FILE_CONFLICT)

    def _verify_static_private(self, *, root: Path, operation_root: Path,
                               content: Mapping[str, bytes]) -> None:
        if root.parent != operation_root or root.exists() or root.is_symlink():
            _fail(FailureCode.ASSET_STATIC_VERIFY_FAILED)
        try:
            self.static_verifier.verify(
                root=root, content=content,
                candidate_sha=self.inputs.candidate_sha,
                owner_uid=self.policy.owner_uid, owner_gid=self.policy.owner_gid,
                runtime_uid=self.policy.runtime_uid, runtime_gid=self.policy.runtime_gid,
            )
        finally:
            if root.exists() and not root.is_symlink() and root.parent == operation_root:
                try:
                    shutil.rmtree(root)
                except OSError:
                    _fail(FailureCode.ASSET_STATIC_VERIFY_FAILED)

    def _install(self, rendered: RenderedAssets, store: GateCJournalStore,
                 state, events):
        created = 0
        partial = state.phase == GateCPhase.FILES_PARTIALLY_INSTALLED.value
        for logical in sorted(rendered.content):
            physical = self.policy.physical(logical)
            mode = int(CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8)
            try:
                result = atomic_create_no_replace(
                    physical, rendered.content[logical],
                    policy=AtomicCreatePolicyV1(
                        self.policy.owner_uid, self.policy.owner_gid, mode, self.policy.root,
                    ),
                )
            except PreparationContractError:
                _fail(FailureCode.ASSET_FILE_CONFLICT)
            if result is AtomicCreateResult.CREATED:
                created += 1
                subset = tuple(
                    self._physical_entry(path, rendered.content[path])
                    for path in sorted(rendered.content)
                    if self.policy.physical(path).exists()
                )
                subset_hash = contract_fingerprint({
                    "installed_subset": [entry.to_mapping() for entry in subset]
                })
                state, events = store.advance(
                    state, events, GateCPhase.FILES_PARTIALLY_INSTALLED,
                    tool=self.inputs.tool_identity, evidence=(subset_hash,),
                )
                partial = True
                if self.crash_after_new_files == created:
                    raise SimulatedGateCCrash
        final_manifest = tuple(
            self._physical_entry(path, rendered.content[path]) for path in sorted(rendered.content)
        )
        final_hash = asset_installation_fingerprint(final_manifest)
        if final_hash != rendered.installation_fingerprint:
            _fail(FailureCode.ASSET_FILE_CONFLICT)
        state, events = store.advance(
            state, events, GateCPhase.FILES_INSTALLED,
            tool=self.inputs.tool_identity, evidence=(final_hash,),
        )
        return state, events, final_manifest, ("CONVERGED" if partial else "IDEMPOTENT")

    def run(self, *, resume_operation_id: str | None = None) -> InertAssetInstallResult:
        self.inputs.validate()
        self._ensure_roots()
        operation_id = resume_operation_id or str(uuid4())
        with exclusive_gate_c_lock(self.policy.lock_path, policy=self.policy):
            try:
                return self._run_locked(
                    operation_id=operation_id, resume=resume_operation_id is not None,
                )
            except InertAssetInstallError as error:
                operation_root = self.policy.gate_c_root / operation_id
                if operation_root.is_dir():
                    try:
                        store = GateCJournalStore(
                            operation_root,
                            policy=AtomicCreatePolicyV1(
                                self.policy.owner_uid, self.policy.owner_gid, 0o600,
                                self.policy.gate_c_root,
                            ),
                        )
                        state, events = _load_complete_or_partial_gate_c(
                            operation_root, owner_uid=self.policy.owner_uid,
                            owner_gid=self.policy.owner_gid,
                        )
                        if state.phase not in {"COMPLETE", "FAILED"}:
                            store.advance(
                                state, events, GateCPhase.FAILED,
                                tool=self.inputs.tool_identity, evidence=(),
                                failure_code=error.code,
                            )
                    except Exception:
                        pass
                raise

    def _run_locked(self, *, operation_id: str, resume: bool) -> InertAssetInstallResult:
        operation_root = self.policy.gate_c_root / operation_id
        store = GateCJournalStore(
            operation_root,
            policy=AtomicCreatePolicyV1(
                self.policy.owner_uid, self.policy.owner_gid, 0o600, self.policy.gate_c_root,
            ),
        )
        if not resume:
            state = store.initialize(
                operation_id=operation_id, candidate_sha=self.inputs.candidate_sha,
                tool=self.inputs.tool_identity,
            )
            events: tuple[PreparationJournalEventV1, ...] = ()
        else:
            state, events = store.load_partial()
            if (state.operation_id != operation_id or
                    state.candidate_sha != self.inputs.candidate_sha or
                    state.operator_tool_identities != (self.inputs.tool_identity,)):
                _fail(FailureCode.ASSET_FILE_CONFLICT)

        home = operation_root / "home"
        if not home.exists():
            home.mkdir(mode=0o700)
            os.chown(home, self.policy.owner_uid, self.policy.owner_gid)
        reader = self.prerequisite_reader_factory(self.policy, self.inputs, self.systemd)
        prerequisites = reader.collect(home=home)
        prereq_hashes = (
            prerequisites.rollback_metadata_sha256,
            release_pin_fingerprint(prerequisites.release_pin),
            prerequisites.gate_b_release_fingerprint,
            prerequisites.p3c_context_fingerprint,
            prerequisites.p3c_state_sha256,
            prerequisites.p3c_systemd_before,
        )
        if state.phase == GateCPhase.NEW.value:
            state, events = store.advance(
                state, events, GateCPhase.PREREQUISITES_VERIFIED,
                tool=self.inputs.tool_identity, evidence=prereq_hashes,
            )
        configuration, principal, registry_before, env_before, registry_hash = (
            self._load_configuration()
        )
        if state.phase == GateCPhase.PREREQUISITES_VERIFIED.value:
            state, events = store.advance(
                state, events, GateCPhase.REGISTRY_VERIFIED,
                tool=self.inputs.tool_identity, evidence=(registry_hash,),
            )
        db_evidence = self._collect_db_evidence(configuration, principal)
        scope_hash = contract_fingerprint({
            "principal_ref": principal,
            "enabled_scope_ids": sorted(db_evidence.enabled_scope_ids),
        })
        if state.phase == GateCPhase.REGISTRY_VERIFIED.value:
            state, events = store.advance(
                state, events, GateCPhase.DB_EVIDENCE_VERIFIED,
                tool=self.inputs.tool_identity,
                evidence=(db_evidence.identity_fingerprint, scope_hash),
            )
        rendered = self._render_assets(configuration, principal, db_evidence)
        profile_hash = contract_fingerprint({
            "profiles": [
                {"path": path, "sha256": _sha256(payload)}
                for path, payload in sorted(rendered.content.items())
                if path in CANONICAL_P3D_PROFILE_PATHS
            ]
        })
        if state.phase == GateCPhase.DB_EVIDENCE_VERIFIED.value:
            state, events = store.advance(
                state, events, GateCPhase.PROFILES_RENDERED,
                tool=self.inputs.tool_identity, evidence=(profile_hash,),
            )
        pre_static_root = operation_root / f"static-pre-{len(events):06d}"
        self._verify_static_private(
            root=pre_static_root, operation_root=operation_root,
            content=rendered.content,
        )
        if state.phase == GateCPhase.PROFILES_RENDERED.value:
            state, events = store.advance(
                state, events, GateCPhase.OFFLINE_STATIC_VERIFIED,
                tool=self.inputs.tool_identity,
                evidence=(rendered.installation_fingerprint, rendered.candidate_systemd_fingerprint),
            )
        state, events, installed, disposition = self._install(rendered, store, state, events)
        final_content = {
            path: self.policy.physical(path).read_bytes() for path in sorted(rendered.content)
        }
        _validate_static_contract(final_content)
        final_static_root = operation_root / f"static-final-{len(events):06d}"
        self._verify_static_private(
            root=final_static_root, operation_root=operation_root,
            content=final_content,
        )
        state, events = store.advance(
            state, events, GateCPhase.FINAL_STATIC_VERIFIED,
            tool=self.inputs.tool_identity, evidence=(rendered.installation_fingerprint,),
        )
        after = self.systemd.snapshot(post_install=True)
        if (not after.p3d_quiet or
                after.p3c_fingerprint != prerequisites.p3c_systemd_before):
            _fail(FailureCode.ASSET_SYSTEMD_NOT_QUIET)
        state, events = store.advance(
            state, events, GateCPhase.SYSTEMD_QUIET_VERIFIED,
            tool=self.inputs.tool_identity,
            evidence=(after.p3c_fingerprint, after.p3d_fingerprint),
        )
        current_after = ProtectedPrerequisiteReader(
            self.policy, self.inputs, self.systemd,
        )._current_target(prerequisites.rollback_metadata.source_release_sha)
        env_after = self.policy.environment.stat()
        if (self.policy.registry.read_bytes() != registry_before or
                (
                    env_after.st_ino, env_after.st_size, env_after.st_mtime_ns,
                    _sha256(self.policy.environment.read_bytes()),
                ) != env_before):
            _fail(FailureCode.ASSET_COMPLETE_MARKER_FAILED)
        reader.verify_p3c_state_unchanged(prerequisites)
        marker = P3DAssetInstallationCompleteV1.from_mapping({
            "marker_version": 1,
            "candidate_sha": self.inputs.candidate_sha,
            "rollback_snapshot_id": prerequisites.rollback_metadata.snapshot_id,
            "rollback_metadata_sha256": prerequisites.rollback_metadata_sha256,
            "rollback_source_sha": prerequisites.rollback_metadata.source_release_sha,
            "registry_fingerprint": registry_hash,
            "db_identity_fingerprint": db_evidence.identity_fingerprint,
            "enabled_scope_fingerprint": scope_hash,
            "unit_profile_asset_fingerprint": rendered.installation_fingerprint,
            "installed_file_manifest": [entry.to_mapping() for entry in installed],
            "current_symlink_before": prerequisites.current_target,
            "current_symlink_after": current_after,
            "p3c_systemd_state_before_fingerprint": prerequisites.p3c_systemd_before,
            "p3c_systemd_state_after_fingerprint": after.p3c_fingerprint,
            "p3d_timer_state": "DISABLED_INACTIVE",
            "preparation_operation_id": operation_id,
            "completed_at_utc": _now(),
            "gate_c_tool_identity": self.inputs.tool_identity.to_mapping(),
        })
        validate_complete_marker_authorities(marker, prerequisites.rollback_metadata)
        if asset_installation_fingerprint(marker.installed_file_manifest) != rendered.installation_fingerprint:
            _fail(FailureCode.ASSET_COMPLETE_MARKER_FAILED)
        marker_payload = canonical_json_bytes(marker.to_mapping()) + b"\n"
        try:
            atomic_create_no_replace(
                operation_root / "complete.json", marker_payload,
                policy=AtomicCreatePolicyV1(
                    self.policy.owner_uid, self.policy.owner_gid, 0o600,
                    self.policy.gate_c_root,
                ),
            )
        except PreparationContractError:
            _fail(FailureCode.ASSET_COMPLETE_MARKER_FAILED)
        marker_hash = contract_fingerprint(marker)
        state, events = store.advance(
            state, events, GateCPhase.COMPLETE_MARKER_COMMITTED,
            tool=self.inputs.tool_identity, evidence=(marker_hash,),
        )
        state, events = store.advance(
            state, events, GateCPhase.COMPLETE,
            tool=self.inputs.tool_identity, evidence=(marker_hash,),
        )
        return InertAssetInstallResult(operation_id, disposition, marker, state, events)


class SimulatedGateCCrash(BaseException):
    """Test-only crash boundary: leaves the frozen partial state intact."""
