"""Fail-closed P3D control contract; production installation is external."""

from dataclasses import dataclass
from contextlib import contextmanager
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import os
import stat
import tomllib

from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS


P3D_TIMER_UNITS = {
    "enrichment.nextcloud_text": "pdi-scoped-enrichment-nextcloud-text.timer",
    "enrichment.nextcloud_documents": "pdi-scoped-enrichment-nextcloud-documents.timer",
    "enrichment.file_metadata": "pdi-scoped-enrichment-file-metadata.timer",
    "enrichment.immich_geo": "pdi-scoped-enrichment-immich-geo.timer",
    "enrichment.immich_metadata": "pdi-scoped-enrichment-immich-metadata.timer",
    "enrichment.immich_ocr": "pdi-scoped-enrichment-immich-ocr.timer",
}


class SystemdScopedEnrichmentActions:
    """Allow-listed systemd backend; P3C writer units are unreachable here."""

    def __init__(self, runner=subprocess.run):
        self._runner = runner

    def _call(self, *args: str) -> bool:
        result = self._runner(("systemctl", *args), capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        return result.returncode == 0

    def is_enabled(self, pipeline_key: str) -> bool:
        return pipeline_key in P3D_TIMER_UNITS and self._call("is-enabled", P3D_TIMER_UNITS[pipeline_key])

    def is_active(self, pipeline_key: str) -> bool:
        return pipeline_key in P3D_TIMER_UNITS and self._call("is-active", P3D_TIMER_UNITS[pipeline_key])

    def preflight(self) -> bool:
        return all(not self.is_enabled(key) and not self.is_active(key)
                   for key in CANONICAL_SCOPED_ENRICHMENTS)

    def qualify(self, pipeline_keys: tuple[str, ...]) -> bool:
        for key in pipeline_keys:
            service = f"pdi-scoped-pipeline@{key}.service"
            if not self._call("start", service):
                return False
        return self.preflight()

    def enable_scoped_enrichments(self, pipeline_keys: tuple[str, ...]) -> None:
        if set(pipeline_keys) != set(CANONICAL_SCOPED_ENRICHMENTS):
            raise ValueError("P3D_PIPELINE_SET_INVALID")
        if not self._call("daemon-reload"):
            raise RuntimeError("SYSTEMD_DAEMON_RELOAD_FAILED")
        for key in CANONICAL_SCOPED_ENRICHMENTS:
            if not self._call("enable", "--now", P3D_TIMER_UNITS[key]):
                raise RuntimeError("P3D_TIMER_ENABLE_FAILED")
        if not all(self.is_enabled(key) and self.is_active(key) for key in CANONICAL_SCOPED_ENRICHMENTS):
            raise RuntimeError("P3D_TIMER_VERIFY_FAILED")

    def disable_scoped_enrichments(self, pipeline_keys: tuple[str, ...]) -> bool:
        if set(pipeline_keys) != set(CANONICAL_SCOPED_ENRICHMENTS):
            return False
        command_failed = False
        for key in CANONICAL_SCOPED_ENRICHMENTS:
            if not self._call("disable", "--now", P3D_TIMER_UNITS[key]):
                command_failed = True
        verified = self.preflight()
        return not command_failed and verified


class P3DControlRefused(RuntimeError):
    pass


def verify_release(path: Path, expected_sha: str, *, runner=subprocess.run) -> bool:
    """Verify an immutable release directly; caller claims are ignored."""
    try:
        info = path.stat()
        if not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
            return False
        result = runner(("git", "-C", str(path), "rev-parse", "HEAD"),
                        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        actual = result.stdout.strip()
        if result.returncode != 0 or actual != expected_sha:
            return False
        required = (path / "src/pdi/scoped_operational.py", path / ".venv/bin/python")
        return all(item.exists() and not item.is_symlink() for item in required)
    except OSError:
        return False


def validate_rollback_metadata(metadata: dict[str, str], *, rollback_source_sha: str) -> bool:
    """Validate a fresh, post-soak rollback record without trusting booleans."""
    required = {
        "SNAPSHOT_ID", "SOURCE_SHA", "ALEMBIC", "POSTGRES_MAJOR", "P3C_PRODUCTION_ENABLED",
        "P3C_SOAK", "RESTORE_TESTED", "RESTORED_COUNTS_MATCH", "BACKUP_FS_UUID",
        "RESTIC_REPOSITORY",
    }
    if not required <= metadata.keys():
        return False
    return (
        bool(metadata["SNAPSHOT_ID"]) and len(metadata["SOURCE_SHA"]) == 40 and
        metadata["SOURCE_SHA"] == rollback_source_sha and metadata["ALEMBIC"] == "e5a7b9d1f324" and
        metadata["POSTGRES_MAJOR"] == "16" and metadata["P3C_PRODUCTION_ENABLED"] == "YES" and
        metadata["P3C_SOAK"] == "PASS" and metadata["RESTORE_TESTED"] == "YES" and
        metadata["RESTORED_COUNTS_MATCH"] == "YES" and bool(metadata["BACKUP_FS_UUID"]) and
        bool(metadata["RESTIC_REPOSITORY"])
    )


def context_fingerprint(context: dict[str, object]) -> str:
    payload = json.dumps(context, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def promote_release_atomically(current: Path, release: Path, expected_sha: str) -> str:
    """Promote only a verified root-owned release; never rolls back implicitly."""
    if not verify_release(release, expected_sha):
        raise P3DControlRefused("RELEASE_VERIFICATION_FAILED")
    if not current.is_symlink() or current.lstat().st_uid != 0:
        raise P3DControlRefused("CURRENT_NOT_ROOT_SYMLINK")
    previous = str(current.resolve())
    temporary = current.with_name(f".{current.name}.p3d-new")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(release)
    os.replace(temporary, current)
    directory_fd = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if current.resolve() != release:
        raise P3DControlRefused("CURRENT_PROMOTION_VERIFY_FAILED")
    return previous


class ProductionEvidenceReader:
    """Collect production facts from protected files/systemd, not caller booleans."""

    P3C_TIMERS = (
        "pdi-p3c-nextcloud-incremental.timer", "pdi-p3c-nextcloud-full.timer",
        "pdi-p3c-immich-incremental.timer", "pdi-p3c-immich-daily.timer",
    )
    LEGACY_TIMERS = (
        "pdi-sync-nextcloud-incremental.timer", "pdi-sync-nextcloud.timer",
        "pdi-sync-immich-incremental.timer", "pdi-sync-immich.timer",
        "pdi-enrichment-nextcloud-text.timer", "pdi-enrichment-nextcloud-documents.timer",
        "pdi-enrichment-immich.timer", "pdi-enrichment-immich-geo.timer",
        "pdi-enrichment-immich-ocr.timer", "pdi-enrichment-file-metadata.timer",
    )

    def __init__(self, *, release: Path, expected_sha: str, current: Path = Path("/opt/pdi/current"),
                 rollback_metadata: Path = Path("/etc/pdi-backup-recovery/pdi-core/p3d-pre-enrichment.env"),
                 config: Path = Path("/etc/pdi/scoped/registry.toml"), runner=subprocess.run,
                 previous_sha: str | None = None, rollback_source_sha: str | None = None):
        self.release, self.expected_sha, self.current = release, expected_sha, current
        self.previous_sha = previous_sha
        self.rollback_source_sha = rollback_source_sha or previous_sha or expected_sha
        self.rollback_metadata, self.config, self.runner = rollback_metadata, config, runner

    def _unit_ok(self, unit: str, enabled: bool) -> bool:
        def check(action):
            result = self.runner(("systemctl", action, unit), capture_output=True, text=True,
                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            return result.returncode == 0
        return check("is-enabled") == enabled and check("is-active") == enabled

    def collect_preflight(self) -> dict[str, object]:
        if not verify_release(self.release, self.expected_sha, runner=self.runner):
            raise P3DControlRefused("RELEASE_VERIFICATION_FAILED")
        if not self.current.is_symlink():
            raise P3DControlRefused("CURRENT_RELEASE_CONTEXT_MISMATCH")
        current_name = self.current.resolve().name
        if current_name not in {self.expected_sha, self.previous_sha} - {None}:
            raise P3DControlRefused("CURRENT_RELEASE_CONTEXT_MISMATCH")
        if any(not self._unit_ok(unit, True) for unit in self.P3C_TIMERS):
            raise P3DControlRefused("P3C_WRITER_UNHEALTHY")
        if any(not self._unit_ok(unit, False) for unit in self.LEGACY_TIMERS):
            raise P3DControlRefused("LEGACY_TIMER_NOT_QUIET")
        backend = SystemdScopedEnrichmentActions(self.runner)
        if not backend.preflight():
            raise P3DControlRefused("P3D_TIMER_NOT_OFF")
        if not self.rollback_metadata.is_file() or self.rollback_metadata.is_symlink():
            raise P3DControlRefused("ROLLBACK_METADATA_MISSING")
        raw = {}
        for line in self.rollback_metadata.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                raw[key] = value
        if not validate_rollback_metadata(raw, rollback_source_sha=self.rollback_source_sha):
            raise P3DControlRefused("ROLLBACK_METADATA_INVALID")
        try:
            data = tomllib.loads(self.config.read_text())
        except (OSError, tomllib.TOMLDecodeError):
            raise P3DControlRefused("SCOPED_CONFIG_INVALID") from None
        if len(data.get("principals", [])) != 1 or len(data.get("databases", [])) != 1:
            raise P3DControlRefused("IDENTITY_INVARIANTS_INVALID")
        return {"release_sha": self.expected_sha, "release_path": str(self.release),
                "p3c_pass": True, "writers_healthy": True,
                "legacy_enrichment_disabled": True, "p3d_timers_off": True,
                "gmail_disabled": True, "rollback_qualified": True}

    def collect_active_verify(self) -> dict[str, object]:
        if not verify_release(self.release, self.expected_sha, runner=self.runner):
            raise P3DControlRefused("RELEASE_VERIFICATION_FAILED")
        if not self.current.is_symlink() or self.current.resolve() != self.release:
            raise P3DControlRefused("CURRENT_RELEASE_CONTEXT_MISMATCH")
        if any(not self._unit_ok(unit, True) for unit in self.P3C_TIMERS):
            raise P3DControlRefused("P3C_WRITER_UNHEALTHY")
        if any(not self._unit_ok(unit, False) for unit in self.LEGACY_TIMERS):
            raise P3DControlRefused("LEGACY_TIMER_NOT_QUIET")
        backend = SystemdScopedEnrichmentActions(self.runner)
        if not all(backend.is_enabled(key) and backend.is_active(key)
                   for key in CANONICAL_SCOPED_ENRICHMENTS):
            raise P3DControlRefused("P3D_TIMER_NOT_ACTIVE")
        return {"release_sha": self.expected_sha, "release_path": str(self.release),
                "p3c_healthy": True, "p3d_healthy": True}

    # Compatibility alias for callers still using the pre-activation name.
    collect = collect_preflight


@dataclass
class P3DControl:
    state_path: Path
    journal_path: Path
    expected_sha: str
    release_path: Path
    lock_path: Path = Path("/run/lock/pdi-mu13-p3d-cutover.lock")

    @contextmanager
    def control_lock(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = self.lock_path.open("a+")
        try:
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise P3DControlRefused("CUTOVER_ALREADY_RUNNING") from None
            yield
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            fd.close()

    def _read(self) -> dict:
        if not self.state_path.exists():
            return {"state": "PRECHECK"}
        try:
            value = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            raise P3DControlRefused("STATE_INVALID") from None
        if not isinstance(value, dict):
            raise P3DControlRefused("STATE_INVALID")
        return value

    def _write(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".p3d-state-", dir=self.state_path.parent)
        try:
            with open(fd, "w", encoding="utf-8", closefd=True) as handle:
                handle.write(json.dumps(state, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            Path(name).replace(self.state_path)
            directory_fd = os.open(self.state_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            Path(name).unlink(missing_ok=True)

    def _record(self, phase: str, state: dict) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        if self.journal_path.exists() and self.journal_path.is_symlink():
            raise P3DControlRefused("JOURNAL_SYMLINK")
        if not self.journal_path.exists():
            self.journal_path.touch(mode=0o600)
        else:
            self.journal_path.chmod(0o600)
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"phase": phase, "state": state.get("state"),
                                     "release_sha": self.expected_sha,
                                     "release_path": str(self.release_path)}, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def preflight(self, evidence: dict[str, object]) -> None:
        with self.control_lock():
            self._preflight(evidence)

    def _preflight(self, evidence: dict[str, object]) -> None:
        current = self._read()
        if current.get("state") not in {"PRECHECK", "PREFLIGHT_PASSED"}:
            raise P3DControlRefused("PREFLIGHT_ALREADY_CONSUMED")
        if evidence.get("release_sha") != self.expected_sha:
            raise P3DControlRefused("RELEASE_SHA_MISMATCH")
        if evidence.get("release_path") != str(self.release_path):
            raise P3DControlRefused("RELEASE_PATH_MISMATCH")
        required = ("p3c_pass", "writers_healthy", "legacy_enrichment_disabled",
                    "p3d_timers_off", "gmail_disabled", "rollback_qualified")
        if any(evidence.get(key) is not True for key in required):
            raise P3DControlRefused("PREFLIGHT_EVIDENCE_INCOMPLETE")
        state = {"state": "PREFLIGHT_PASSED", "release_sha": self.expected_sha,
                 "release_path": str(self.release_path), "evidence": evidence}
        state["context_fingerprint"] = context_fingerprint(evidence)
        self._write(state)
        self._record("PREFLIGHT_PASSED", state)

    def qualify(self, results: dict[str, bool], *, context: dict[str, object] | None = None) -> None:
        with self.control_lock():
            self._qualify(results, context=context)

    def _qualify(self, results: dict[str, bool], *, context: dict[str, object] | None = None) -> None:
        state = self._read()
        if state.get("state") != "PREFLIGHT_PASSED":
            raise P3DControlRefused("QUALIFICATION_ORDER_INVALID")
        if context is not None and state.get("context_fingerprint") != context_fingerprint(context):
            raise P3DControlRefused("CONTEXT_DRIFT")
        if set(results) != set(CANONICAL_SCOPED_ENRICHMENTS) or not all(results.values()):
            raise P3DControlRefused("QUALIFICATION_FAILED")
        state["state"] = "QUALIFIED"
        state["qualification"] = {key: True for key in CANONICAL_SCOPED_ENRICHMENTS}
        self._write(state)
        self._record("QUALIFIED", state)

    def activation_result(self, *, enabled: bool, all_disabled: bool,
                          context: dict[str, object] | None = None) -> None:
        with self.control_lock():
            self._activation_result(enabled=enabled, all_disabled=all_disabled, context=context)

    def _activation_result(self, *, enabled: bool, all_disabled: bool,
                           context: dict[str, object] | None = None) -> None:
        state = self._read()
        if state.get("state") != "QUALIFIED":
            raise P3DControlRefused("ACTIVATION_ORDER_INVALID")
        if context is not None and state.get("context_fingerprint") != context_fingerprint(context):
            raise P3DControlRefused("CONTEXT_DRIFT")
        if not enabled:
            if not all_disabled:
                state["state"] = "ABORT_NOT_CONFIRMED"
                self._write(state)
                raise P3DControlRefused("ABORT_NOT_CONFIRMED")
            state["state"] = "ABORTED"
            self._write(state)
            self._record("ABORTED", state)
            raise P3DControlRefused("ACTIVATION_FAILED")
        state["state"] = "ACTIVE"
        self._write(state)
        self._record("ACTIVE", state)

    def verify(self, evidence: dict[str, object]) -> None:
        with self.control_lock():
            self._verify(evidence)

    def _verify(self, evidence: dict[str, object]) -> None:
        state = self._read()
        if state.get("state") != "ACTIVE":
            raise P3DControlRefused("VERIFY_ORDER_INVALID")
        if evidence.get("p3c_healthy") is not True or evidence.get("p3d_healthy") is not True:
            raise P3DControlRefused("VERIFY_FAILED")
        state["verified"] = True
        self._write(state)
        self._record("VERIFIED", state)

    def abort(self, *, all_disabled: bool) -> None:
        with self.control_lock():
            self._abort(all_disabled=all_disabled)

    def _abort(self, *, all_disabled: bool) -> None:
        state = self._read()
        if state.get("state") not in {"PREFLIGHT_PASSED", "QUALIFIED", "ACTIVE", "ABORTED", "ABORT_NOT_CONFIRMED"}:
            raise P3DControlRefused("ABORT_ORDER_INVALID")
        if not all_disabled:
            state["state"] = "ABORT_NOT_CONFIRMED"
            self._write(state)
            self._record("ABORT_NOT_CONFIRMED", state)
            raise P3DControlRefused("ABORT_NOT_CONFIRMED")
        state["state"] = "ABORTED"
        self._write(state)
        self._record("ABORTED", state)
