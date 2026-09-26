"""Read-only MU13-P3D preparation evidence collection.

This module joins the three frozen preparation gates to fresh production
evidence.  It does not persist control state, acquire a cutover lock, mutate
systemd, execute a pipeline, or change ``/opt/pdi/current``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Callable

from pdi.database import create_postgres_engine
from pdi.production_ops.contracts import ENV_KEYS, parse_env
from pdi.production_ops.p3d_evidence import (
    PersonalDatabaseEvidence,
    RoutedPersonalDatabaseEvidenceReader,
)
from pdi.production_ops.p3d_inert_asset_install import (
    GIT,
    GIT_READ_ONLY_ENV,
    InertAssetInputs,
    InertAssetPolicy,
    InstallMode,
    ProductionReadOnlySystemdStateProvider,
    ProtectedPrerequisiteReader,
    SystemdStateProvider,
    _load_complete_gate,
    _trusted_leaf,
)
from pdi.production_ops.p3d_preparation_contracts import (
    CANONICAL_P3D_INSTALL_PATH_MODES,
    CANONICAL_P3D_INSTALL_PATHS,
    CANONICAL_P3D_PIPELINE_KEYS,
    GateCPhase,
    InstalledFileEntryV1,
    P3DAssetInstallationCompleteV1,
    PreparationGate,
    PreparationPrerequisiteEvidenceV1,
    asset_installation_fingerprint,
    contract_fingerprint,
    validate_complete_marker_authorities,
    validate_pre_rehearsal_preparation_contract,
)
from pdi.scoped_operator_config import load_scoped_operator_configuration


GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
# The frozen Gate C path policy is also the WP6 logical-path authority.  WP6
# adds no independently configurable production root.
PreparationEvidencePolicy = InertAssetPolicy


class PreRehearsalEvidenceError(RuntimeError):
    """Fixed, non-secret rejection at the read-only evidence boundary."""

    def __init__(self, code: str = "P3D_PRE_REHEARSAL_EVIDENCE_REJECTED") -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str = "P3D_PRE_REHEARSAL_EVIDENCE_REJECTED") -> None:
    raise PreRehearsalEvidenceError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_uuid(value: str) -> str:
    from uuid import UUID

    try:
        parsed = UUID(value)
    except (TypeError, ValueError):
        _fail("P3D_PRE_REHEARSAL_SELECTOR_INVALID")
    if str(parsed) != value:
        _fail("P3D_PRE_REHEARSAL_SELECTOR_INVALID")
    return value


def _git_sha(value: str) -> str:
    if not isinstance(value, str) or GIT_SHA_RE.fullmatch(value) is None:
        _fail("P3D_PRE_REHEARSAL_SELECTOR_INVALID")
    return value


@dataclass(frozen=True)
class PreparationEvidenceInputs:
    candidate_sha: str
    gate_a_operation_id: str
    gate_b_operation_id: str
    gate_c_operation_id: str
    rollback_source_cross_check: str | None = None

    def validate(self) -> None:
        _git_sha(self.candidate_sha)
        _canonical_uuid(self.gate_a_operation_id)
        _canonical_uuid(self.gate_b_operation_id)
        _canonical_uuid(self.gate_c_operation_id)
        if self.rollback_source_cross_check is not None:
            _git_sha(self.rollback_source_cross_check)
            if self.rollback_source_cross_check == self.candidate_sha:
                _fail("P3D_PRE_REHEARSAL_SELECTOR_INVALID")


@dataclass(frozen=True)
class _ProtectedSnapshot:
    inode: int
    size: int
    mtime_ns: int
    sha256: str
    payload: bytes

    @property
    def identity(self) -> tuple[int, int, int, str]:
        return self.inode, self.size, self.mtime_ns, self.sha256


@dataclass(frozen=True)
class PreRehearsalEvidenceResult:
    candidate_sha: str
    context_fingerprint: str
    marker_fingerprint: str
    db_identity_fingerprint: str
    enabled_scope_count: int
    enabled_scope_fingerprint: str
    asset_fingerprint: str

    def to_sanitized_mapping(self) -> dict[str, str]:
        return {
            "P3D_COLLECT_EVIDENCE": "PASS",
            "CANDIDATE_SHA": self.candidate_sha,
            "CONTEXT_FINGERPRINT": self.context_fingerprint,
            "PREPARATION_MARKER_FINGERPRINT": self.marker_fingerprint,
            "GATE_A_AUTHORITY": "PASS",
            "GATE_B_AUTHORITY": "PASS",
            "GATE_C_AUTHORITY": "PASS",
            "P3C_EVIDENCE_REAL": "PASS",
            "GMAIL_EVIDENCE_REAL": "PASS",
            "ROUTED_DB_PREFLIGHT": "PASS",
            "READ_ONLY_DB_GUARANTEE": "PASS",
            "DB_IDENTITY_FINGERPRINT": self.db_identity_fingerprint,
            "ENABLED_SCOPE_COUNT": str(self.enabled_scope_count),
            "ENABLED_SCOPE_FINGERPRINT": self.enabled_scope_fingerprint,
            "CANONICAL_PIPELINE_COUNT": str(len(CANONICAL_P3D_PIPELINE_KEYS)),
            "ASSET_FINGERPRINT": self.asset_fingerprint,
            "PRE_REHEARSAL_PREPARATION_CONTRACT": "PASS",
            "PRE_REHEARSAL_QUALIFICATION_PROOF": "PASS",
            "POST_REHEARSAL_RUNTIME_LEDGER_PROOF": "NOT_APPLICABLE_PRE_REHEARSAL",
            "RUNTIME_PIPELINE_COVERAGE": "0/6",
        }


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def verify_candidate_evidence_runtime(
    policy: PreparationEvidencePolicy,
    candidate_sha: str,
    *,
    executable: Path | None = None,
    module_file: Path | None = None,
    script_file: Path | None = None,
    runner=subprocess.run,
) -> str:
    """Bind the operator interpreter, imported module, script, and Git tree."""

    candidate = _git_sha(candidate_sha)
    release = policy.candidate_releases_root / candidate
    expected_python = release / ".venv/bin/python"
    expected_source = release / "src/pdi/production_ops/p3d_pre_rehearsal_evidence.py"
    expected_script = release / "scripts/mu13_p3d_cutover.py"
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
        commands = (
            (str(GIT), "-C", str(release), "rev-parse", "HEAD"),
            (str(GIT), "-C", str(release), "status", "--porcelain", "--untracked-files=all"),
        )
        for argv in commands:
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
        _fail("P3D_PRE_REHEARSAL_RUNTIME_INVALID")


def _read_protected_bytes(
    path: Path,
    *,
    policy: PreparationEvidencePolicy,
    mode: int,
    gid: int,
) -> _ProtectedSnapshot:
    """Read a protected regular file through one no-follow descriptor."""

    try:
        _trusted_leaf(path, policy=policy, mode=mode, group=gid)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != policy.owner_uid or
                    info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode):
                raise OSError
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read()
        finally:
            os.close(descriptor)
        return _ProtectedSnapshot(
            info.st_ino, info.st_size, info.st_mtime_ns, _sha256(payload), payload,
        )
    except Exception:
        _fail("P3D_PRE_REHEARSAL_PROTECTED_FILE_INVALID")


def _trusted_directory(
    path: Path, *, policy: PreparationEvidencePolicy, mode: int,
) -> None:
    try:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                info.st_uid != policy.owner_uid or info.st_gid != policy.owner_gid or
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
        _fail("P3D_PRE_REHEARSAL_PROTECTED_PATH_INVALID")


def _explicit_gate(
    policy: PreparationEvidencePolicy,
    operation_id: str,
    *,
    gate: PreparationGate,
    candidate: str,
) -> tuple[object, tuple[object, ...], Path]:
    operation_id = _canonical_uuid(operation_id)
    candidate = _git_sha(candidate)
    if gate is PreparationGate.ROLLBACK_QUALIFICATION:
        root = policy.preparation_root / f"operation-{operation_id}" / "authority"
    elif gate is PreparationGate.RELEASE_STAGING:
        root = policy.preparation_root / operation_id
    elif gate is PreparationGate.INERT_ASSET_INSTALL:
        root = policy.gate_c_root / operation_id
    else:  # pragma: no cover - enum is closed
        _fail("P3D_PRE_REHEARSAL_SELECTOR_INVALID")
    try:
        _trusted_directory(root, policy=policy, mode=0o700)
        state, events = _load_complete_gate(
            root,
            gate=gate,
            candidate=candidate,
            owner_uid=policy.owner_uid,
            owner_gid=policy.owner_gid,
        )
    except Exception:
        _fail("P3D_PRE_REHEARSAL_GATE_AUTHORITY_INVALID")
    if state.operation_id != operation_id:
        _fail("P3D_PRE_REHEARSAL_GATE_AUTHORITY_INVALID")
    return state, events, root


def _read_gate_c_marker(
    policy: PreparationEvidencePolicy,
    inputs: PreparationEvidenceInputs,
) -> tuple[P3DAssetInstallationCompleteV1, str, _ProtectedSnapshot, Path]:
    _, events, root = _explicit_gate(
        policy, inputs.gate_c_operation_id,
        gate=PreparationGate.INERT_ASSET_INSTALL,
        candidate=inputs.candidate_sha,
    )
    marker_path = root / "complete.json"
    snapshot = _read_protected_bytes(
        marker_path, policy=policy, mode=0o600, gid=policy.owner_gid,
    )
    try:
        marker = P3DAssetInstallationCompleteV1.from_mapping(
            json.loads(snapshot.payload.decode("utf-8"))
        )
    except Exception:
        _fail("P3D_PRE_REHEARSAL_MARKER_INVALID")
    marker_hash = contract_fingerprint(marker)
    if (marker.preparation_operation_id != inputs.gate_c_operation_id or
            marker.candidate_sha != inputs.candidate_sha or len(events) < 2 or
            events[-2].to_state != GateCPhase.COMPLETE_MARKER_COMMITTED.value or
            events[-1].to_state != GateCPhase.COMPLETE.value or
            events[-2].evidence_fingerprints != (marker_hash,) or
            events[-1].evidence_fingerprints != (marker_hash,)):
        _fail("P3D_PRE_REHEARSAL_MARKER_INVALID")
    return marker, marker_hash, snapshot, root


def _load_protected_configuration(
    policy: PreparationEvidencePolicy,
    *,
    configuration_loader=load_scoped_operator_configuration,
) -> tuple[object, str, _ProtectedSnapshot, _ProtectedSnapshot]:
    env_snapshot = _read_protected_bytes(
        policy.environment, policy=policy, mode=0o600, gid=policy.owner_gid,
    )
    registry_snapshot = _read_protected_bytes(
        policy.registry, policy=policy, mode=0o640, gid=policy.runtime_gid,
    )
    try:
        env = parse_env(env_snapshot.payload.decode("utf-8"))
        if set(env) != ENV_KEYS or any(not value for value in env.values()):
            raise ValueError
        configuration = configuration_loader(policy.registry, environment=env)
        enabled = configuration.router._principals.list_enabled()
        if len(enabled) != 1:
            raise ValueError
        principal_ref = str(enabled[0].principal_id)
    except Exception:
        _fail("P3D_PRE_REHEARSAL_CONFIGURATION_INVALID")
    # Close the loader's path-read window before any DB access.
    if (_read_protected_bytes(
            policy.environment, policy=policy, mode=0o600, gid=policy.owner_gid,
        ).identity != env_snapshot.identity or
            _read_protected_bytes(
                policy.registry, policy=policy, mode=0o640, gid=policy.runtime_gid,
            ).identity != registry_snapshot.identity):
        _fail("P3D_PRE_REHEARSAL_CONFIGURATION_DRIFT")
    return configuration, principal_ref, env_snapshot, registry_snapshot


def _collect_db_evidence(
    configuration: object,
    principal_ref: str,
    *,
    engine_factory=create_postgres_engine,
    evidence_reader_factory=RoutedPersonalDatabaseEvidenceReader,
) -> PersonalDatabaseEvidence:
    try:
        binding = configuration.router.resolve(principal_ref)
        engine = engine_factory(binding.database_url)
        try:
            evidence = evidence_reader_factory(
                configuration.router, engine, principal_ref=principal_ref,
            ).collect()
        finally:
            dispose = getattr(engine, "dispose", None)
            if dispose is not None:
                dispose()
        if (not evidence.transaction_read_only or evidence.principal_ref != principal_ref or
                evidence.database_ref != binding.database_ref or
                len(evidence.enabled_scope_ids) != 2):
            raise ValueError
        return evidence
    except Exception:
        _fail("P3D_PRE_REHEARSAL_DATABASE_INVALID")


def _fresh_installed_manifest(
    policy: PreparationEvidencePolicy,
) -> tuple[InstalledFileEntryV1, ...]:
    entries: list[InstalledFileEntryV1] = []
    for logical in sorted(CANONICAL_P3D_INSTALL_PATHS):
        mode = int(CANONICAL_P3D_INSTALL_PATH_MODES[logical], 8)
        snapshot = _read_protected_bytes(
            policy.physical(logical), policy=policy, mode=mode, gid=policy.owner_gid,
        )
        entries.append(InstalledFileEntryV1.from_mapping({
            "path": logical,
            "sha256": snapshot.sha256,
            "owner_uid": policy.owner_uid,
            "owner_gid": policy.owner_gid,
            "mode": CANONICAL_P3D_INSTALL_PATH_MODES[logical],
        }))
    return tuple(entries)


def _current_target(
    policy: PreparationEvidencePolicy, *, expected_source: str,
) -> str:
    expected = f"/opt/pdi/releases/{expected_source}"
    try:
        info = policy.current.lstat()
        target = os.readlink(policy.current)
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != policy.owner_uid or
                info.st_gid != policy.owner_gid or target != expected):
            raise OSError
        current = policy.current.parent
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
        return expected
    except OSError:
        _fail("P3D_PRE_REHEARSAL_CURRENT_INVALID")


def _live_context_mapping(live: PreparationPrerequisiteEvidenceV1) -> dict[str, str]:
    return {
        "candidate_sha": live.candidate_sha,
        "rollback_snapshot_id": live.rollback_snapshot_id,
        "rollback_metadata_sha256": live.rollback_metadata_sha256,
        "rollback_source_sha": live.rollback_source_sha,
        "registry_fingerprint": live.registry_fingerprint,
        "db_identity_fingerprint": live.db_identity_fingerprint,
        "enabled_scope_fingerprint": live.enabled_scope_fingerprint,
        "unit_profile_asset_fingerprint": live.unit_profile_asset_fingerprint,
        "current_symlink": live.current_symlink,
        "p3c_systemd_state_fingerprint": live.p3c_systemd_state_fingerprint,
        "p3d_timer_state": live.p3d_timer_state,
    }


class PreRehearsalEvidenceCollector:
    """Join frozen authorities to fresh, read-only live evidence."""

    def __init__(
        self,
        *,
        policy: PreparationEvidencePolicy,
        inputs: PreparationEvidenceInputs,
        systemd: SystemdStateProvider,
        configuration_loader=load_scoped_operator_configuration,
        engine_factory=create_postgres_engine,
        evidence_reader_factory=RoutedPersonalDatabaseEvidenceReader,
        runtime_verifier: Callable[..., str] = verify_candidate_evidence_runtime,
    ) -> None:
        self.policy = policy
        self.inputs = inputs
        self.systemd = systemd
        self.configuration_loader = configuration_loader
        self.engine_factory = engine_factory
        self.evidence_reader_factory = evidence_reader_factory
        self.runtime_verifier = runtime_verifier
        if policy.owner_uid != 0 or policy.owner_gid != 0:
            _fail("P3D_PRE_REHEARSAL_POLICY_INVALID")
        if (policy.mode is InstallMode.PRODUCTION and
                type(systemd) is not ProductionReadOnlySystemdStateProvider):
            _fail("P3D_PRE_REHEARSAL_SYSTEMD_PROVIDER_INVALID")

    def collect(self) -> PreRehearsalEvidenceResult:
        """Return only PASS evidence or one fixed WP6 boundary rejection."""

        try:
            return self._collect()
        except PreRehearsalEvidenceError:
            raise
        except Exception:
            _fail()

    def _collect(self) -> PreRehearsalEvidenceResult:
        self.inputs.validate()
        self.runtime_verifier(self.policy, self.inputs.candidate_sha)

        gate_a_state, _, _ = _explicit_gate(
            self.policy, self.inputs.gate_a_operation_id,
            gate=PreparationGate.ROLLBACK_QUALIFICATION,
            candidate=self.inputs.candidate_sha,
        )
        gate_b_state, _, _ = _explicit_gate(
            self.policy, self.inputs.gate_b_operation_id,
            gate=PreparationGate.RELEASE_STAGING,
            candidate=self.inputs.candidate_sha,
        )
        marker, marker_hash, marker_snapshot, gate_c_root = _read_gate_c_marker(
            self.policy, self.inputs,
        )
        if (gate_a_state.phase != "COMPLETE" or gate_b_state.phase != "COMPLETE" or
                marker.candidate_sha != self.inputs.candidate_sha):
            _fail("P3D_PRE_REHEARSAL_GATE_AUTHORITY_INVALID")

        home = gate_c_root / "home"
        _trusted_directory(home, policy=self.policy, mode=0o700)
        prerequisite_inputs = InertAssetInputs(
            self.inputs.candidate_sha,
            self.inputs.gate_a_operation_id,
            self.inputs.gate_b_operation_id,
            marker.unit_profile_asset_fingerprint,
            marker.gate_c_tool_identity,
        )
        prerequisite_inputs.validate()
        prerequisite_reader = ProtectedPrerequisiteReader(
            self.policy, prerequisite_inputs, self.systemd,
        )
        prerequisites = prerequisite_reader.collect(home=home)
        try:
            validate_complete_marker_authorities(marker, prerequisites.rollback_metadata)
        except Exception:
            _fail("P3D_PRE_REHEARSAL_ROLLBACK_AUTHORITY_MISMATCH")
        if (self.inputs.rollback_source_cross_check is not None and
                prerequisites.rollback_metadata.source_release_sha !=
                self.inputs.rollback_source_cross_check):
            _fail("P3D_PRE_REHEARSAL_ROLLBACK_SOURCE_MISMATCH")

        configuration, principal_ref, env_before, registry_before = (
            _load_protected_configuration(
                self.policy, configuration_loader=self.configuration_loader,
            )
        )
        registry_fingerprint = registry_before.sha256
        if registry_fingerprint != marker.registry_fingerprint:
            _fail("P3D_PRE_REHEARSAL_REGISTRY_MISMATCH")

        db_evidence = _collect_db_evidence(
            configuration,
            principal_ref,
            engine_factory=self.engine_factory,
            evidence_reader_factory=self.evidence_reader_factory,
        )
        enabled_scope_fingerprint = contract_fingerprint({
            "principal_ref": principal_ref,
            "enabled_scope_ids": sorted(db_evidence.enabled_scope_ids),
        })

        installed = _fresh_installed_manifest(self.policy)
        installed_fingerprint = asset_installation_fingerprint(installed)
        current = _current_target(
            self.policy,
            expected_source=prerequisites.rollback_metadata.source_release_sha,
        )
        live_systemd = self.systemd.snapshot(post_install=True)
        if (not live_systemd.p3d_quiet or
                live_systemd.p3c_fingerprint != marker.p3c_systemd_state_after_fingerprint):
            _fail("P3D_PRE_REHEARSAL_SYSTEMD_STATE_INVALID")

        live = PreparationPrerequisiteEvidenceV1(
            candidate_sha=self.inputs.candidate_sha,
            rollback_snapshot_id=prerequisites.rollback_metadata.snapshot_id,
            rollback_metadata_sha256=prerequisites.rollback_metadata_sha256,
            rollback_source_sha=prerequisites.rollback_metadata.source_release_sha,
            registry_fingerprint=registry_fingerprint,
            db_identity_fingerprint=db_evidence.identity_fingerprint,
            enabled_scope_fingerprint=enabled_scope_fingerprint,
            unit_profile_asset_fingerprint=installed_fingerprint,
            current_symlink=current,
            p3c_systemd_state_fingerprint=live_systemd.p3c_fingerprint,
            p3d_timer_state="DISABLED_INACTIVE",
        )
        try:
            validate_pre_rehearsal_preparation_contract(marker, live)
        except Exception:
            _fail("P3D_PRE_REHEARSAL_CONTRACT_MISMATCH")

        # Re-read all mutable protected inputs immediately before returning PASS.
        env_after = _read_protected_bytes(
            self.policy.environment, policy=self.policy, mode=0o600,
            gid=self.policy.owner_gid,
        )
        registry_after = _read_protected_bytes(
            self.policy.registry, policy=self.policy, mode=0o640,
            gid=self.policy.runtime_gid,
        )
        if env_after.identity != env_before.identity or registry_after.identity != registry_before.identity:
            _fail("P3D_PRE_REHEARSAL_CONFIGURATION_DRIFT")
        prerequisite_reader.verify_p3c_state_unchanged(prerequisites)
        marker_after, marker_hash_after, marker_snapshot_after, _ = _read_gate_c_marker(
            self.policy, self.inputs,
        )
        if (marker_snapshot_after.identity != marker_snapshot.identity or
                marker_hash_after != marker_hash or marker_after != marker):
            _fail("P3D_PRE_REHEARSAL_MARKER_DRIFT")

        return PreRehearsalEvidenceResult(
            self.inputs.candidate_sha,
            contract_fingerprint(_live_context_mapping(live)),
            marker_hash,
            db_evidence.identity_fingerprint,
            len(db_evidence.enabled_scope_ids),
            enabled_scope_fingerprint,
            installed_fingerprint,
        )


def collect_pre_rehearsal_evidence(
    *,
    policy: PreparationEvidencePolicy,
    inputs: PreparationEvidenceInputs,
    systemd: SystemdStateProvider,
    **dependencies: object,
) -> PreRehearsalEvidenceResult:
    """Convenience boundary used by the operator CLI and qualification tests."""

    return PreRehearsalEvidenceCollector(
        policy=policy,
        inputs=inputs,
        systemd=systemd,
        **dependencies,
    ).collect()
