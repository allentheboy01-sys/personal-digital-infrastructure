"""Fail-closed P3D control contract; production installation is external."""

from dataclasses import dataclass
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import subprocess
import tempfile

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
        for key in CANONICAL_SCOPED_ENRICHMENTS:
            if not self._call("disable", "--now", P3D_TIMER_UNITS[key]):
                return False
        return self.preflight()


class P3DControlRefused(RuntimeError):
    pass


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
            Path(name).replace(self.state_path)
        finally:
            Path(name).unlink(missing_ok=True)

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
        self._write(state)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        self.journal_path.write_text("P3D_PREFLIGHT=PASS\n", encoding="utf-8")

    def qualify(self, results: dict[str, bool]) -> None:
        with self.control_lock():
            self._qualify(results)

    def _qualify(self, results: dict[str, bool]) -> None:
        state = self._read()
        if state.get("state") != "PREFLIGHT_PASSED":
            raise P3DControlRefused("QUALIFICATION_ORDER_INVALID")
        if set(results) != set(CANONICAL_SCOPED_ENRICHMENTS) or not all(results.values()):
            raise P3DControlRefused("QUALIFICATION_FAILED")
        state["state"] = "QUALIFIED"
        state["qualification"] = {key: True for key in CANONICAL_SCOPED_ENRICHMENTS}
        self._write(state)

    def activation_result(self, *, enabled: bool, all_disabled: bool) -> None:
        with self.control_lock():
            self._activation_result(enabled=enabled, all_disabled=all_disabled)

    def _activation_result(self, *, enabled: bool, all_disabled: bool) -> None:
        state = self._read()
        if state.get("state") != "QUALIFIED":
            raise P3DControlRefused("ACTIVATION_ORDER_INVALID")
        if not enabled:
            if not all_disabled:
                state["state"] = "ABORT_NOT_CONFIRMED"
                self._write(state)
                raise P3DControlRefused("ABORT_NOT_CONFIRMED")
            state["state"] = "ABORTED"
            self._write(state)
            raise P3DControlRefused("ACTIVATION_FAILED")
        state["state"] = "ACTIVE"
        self._write(state)

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
            raise P3DControlRefused("ABORT_NOT_CONFIRMED")
        state["state"] = "ABORTED"
        self._write(state)
