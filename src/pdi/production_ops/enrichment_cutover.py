"""Fail-closed P3D control contract; production installation is external."""

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile

from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS


class P3DControlRefused(RuntimeError):
    pass


@dataclass
class P3DControl:
    state_path: Path
    journal_path: Path
    expected_sha: str
    release_path: Path

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
        state = self._read()
        if state.get("state") != "PREFLIGHT_PASSED":
            raise P3DControlRefused("QUALIFICATION_ORDER_INVALID")
        if set(results) != set(CANONICAL_SCOPED_ENRICHMENTS) or not all(results.values()):
            raise P3DControlRefused("QUALIFICATION_FAILED")
        state["state"] = "QUALIFIED"
        state["qualification"] = {key: True for key in CANONICAL_SCOPED_ENRICHMENTS}
        self._write(state)

    def activation_result(self, *, enabled: bool, all_disabled: bool) -> None:
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
        state = self._read()
        if state.get("state") != "ACTIVE":
            raise P3DControlRefused("VERIFY_ORDER_INVALID")
        if evidence.get("p3c_healthy") is not True or evidence.get("p3d_healthy") is not True:
            raise P3DControlRefused("VERIFY_FAILED")
        state["verified"] = True
        self._write(state)

    def abort(self, *, all_disabled: bool) -> None:
        state = self._read()
        if state.get("state") not in {"PREFLIGHT_PASSED", "QUALIFIED", "ACTIVE", "ABORTED"}:
            raise P3DControlRefused("ABORT_ORDER_INVALID")
        if not all_disabled:
            state["state"] = "ABORT_NOT_CONFIRMED"
            self._write(state)
            raise P3DControlRefused("ABORT_NOT_CONFIRMED")
        state["state"] = "ABORTED"
        self._write(state)
