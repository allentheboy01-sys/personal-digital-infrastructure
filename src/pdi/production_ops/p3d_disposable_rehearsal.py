"""MU13-P3D disposable real-systemd rehearsal authority.

This module is intentionally qualification-only.  It consumes the frozen WP6
pre-rehearsal authority, targets one explicitly isolated systemd-nspawn
manager, promotes ``current`` only below a protected disposable root, starts
the exact six allow-listed enrichment services, and verifies the resulting
Personal-DB-local PipelineRun ledger.  It has no production mode and no timer
activation API.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from pdi.database import create_postgres_engine
from pdi.production_ops.contracts import parse_env
from pdi.production_ops.enrichment_cutover import P3D_TIMER_UNITS
from pdi.production_ops.p3d_evidence import (
    RoutedPersonalDatabaseEvidenceReader,
)
from pdi.production_ops.p3d_inert_asset_install import InertAssetPolicy
from pdi.production_ops.p3d_pre_rehearsal_evidence import (
    PreRehearsalEvidenceResult,
)
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    atomic_create_no_replace,
    canonical_json_bytes,
    contract_fingerprint,
)
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapPolicy,
    _verify_release_tree,
)
from pdi.scoped_enrichment_activation import CANONICAL_SCOPED_ENRICHMENTS
from pdi.scoped_operator_config import load_scoped_operator_configuration


SYSTEMCTL = Path("/usr/bin/systemctl")
MACHINECTL = Path("/usr/bin/machinectl")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
GIT_READ_ONLY_ENV = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_OPTIONAL_LOCKS": "0",
}
GIT_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MACHINE_NAME = re.compile(r"pdi-p3d-[0-9a-f]{16}")
DISPOSABLE_DATABASE = re.compile(r"pdi_wp7_[a-z0-9_]*_test")
CANONICAL_PIPELINES = tuple(CANONICAL_SCOPED_ENRICHMENTS)
SERVICE_UNITS = {
    key: f"pdi-scoped-pipeline@{key}.service"
    for key in CANONICAL_PIPELINES
}
EXPECTED_EFFECT_GENERATORS: Mapping[str, tuple[str, ...]] = {
    "enrichment.nextcloud_text": ("nextcloud_text",),
    "enrichment.nextcloud_documents": (
        "nextcloud_pdf", "nextcloud_odt", "nextcloud_docx",
    ),
    "enrichment.file_metadata": ("file_metadata",),
    "enrichment.immich_geo": ("immich_geo",),
    "enrichment.immich_metadata": ("immich_metadata",),
    "enrichment.immich_ocr": ("immich_ocr",),
}


class DisposableRehearsalError(RuntimeError):
    """Fixed, non-sensitive WP7 failure."""

    def __init__(self, code: str = "P3D_DISPOSABLE_REHEARSAL_REJECTED") -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str = "P3D_DISPOSABLE_REHEARSAL_REJECTED") -> None:
    raise DisposableRehearsalError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime | None = None) -> str:
    instant = (value or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_sha(value: str) -> str:
    if not isinstance(value, str) or GIT_SHA.fullmatch(value) is None:
        _fail("P3D_REHEARSAL_SELECTOR_INVALID")
    return value


def _canonical_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError):
        _fail("P3D_REHEARSAL_SELECTOR_INVALID")
    if str(parsed) != value:
        _fail("P3D_REHEARSAL_SELECTOR_INVALID")
    return value


def machine_name_for(operation_id: str) -> str:
    return f"pdi-p3d-{UUID(_canonical_uuid(operation_id)).hex[:16]}"


@dataclass(frozen=True, slots=True)
class RehearsalInputs:
    candidate_sha: str
    gate_a_operation_id: str
    gate_b_operation_id: str
    gate_c_operation_id: str
    rehearsal_operation_id: str

    def validate(self) -> None:
        _git_sha(self.candidate_sha)
        _canonical_uuid(self.gate_a_operation_id)
        _canonical_uuid(self.gate_b_operation_id)
        _canonical_uuid(self.gate_c_operation_id)
        _canonical_uuid(self.rehearsal_operation_id)


@dataclass(frozen=True, slots=True)
class RehearsalPolicy:
    root: Path
    owner_uid: int
    owner_gid: int
    runtime_uid: int
    runtime_gid: int
    machine_name: str

    @classmethod
    def qualification(
        cls,
        root: Path,
        *,
        owner_uid: int,
        owner_gid: int,
        runtime_uid: int,
        runtime_gid: int,
        operation_id: str,
    ) -> "RehearsalPolicy":
        root = root.absolute()
        try:
            info = root.lstat()
        except OSError:
            _fail("P3D_REHEARSAL_ROOT_INVALID")
        if (
            root == Path("/")
            or not str(root).startswith("/tmp/pdi-p3d-rehearsal-")
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or info.st_mode & 0o022
            or owner_uid != 0
            or owner_gid != 0
            or runtime_uid <= 0
            or runtime_gid <= 0
        ):
            _fail("P3D_REHEARSAL_ROOT_INVALID")
        machine = machine_name_for(operation_id)
        if MACHINE_NAME.fullmatch(machine) is None:
            _fail("P3D_REHEARSAL_MANAGER_INVALID")
        return cls(
            root, owner_uid, owner_gid, runtime_uid, runtime_gid, machine,
        )

    @property
    def preparation_policy(self) -> InertAssetPolicy:
        return InertAssetPolicy.qualification(
            self.root,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
            runtime_uid=self.runtime_uid,
            runtime_gid=self.runtime_gid,
        )

    def physical(self, logical: str) -> Path:
        if not logical.startswith("/") or ".." in Path(logical).parts:
            _fail("P3D_REHEARSAL_ROOT_INVALID")
        return self.root.joinpath(*Path(logical).parts[1:])

    @property
    def current(self) -> Path:
        return self.physical("/opt/pdi/current")

    @property
    def releases(self) -> Path:
        return self.physical("/opt/pdi/releases")

    @property
    def rehearsal_authority_root(self) -> Path:
        return self.physical("/var/lib/pdi-p3d/rehearsal")


@dataclass(frozen=True, slots=True)
class SystemdManagerIdentity:
    leader_pid: int
    host_boot_id: str
    manager_boot_id: str
    rootfs_fingerprint: str
    identity_fingerprint: str


@dataclass(frozen=True, slots=True)
class ServiceResult:
    pipeline_key: str
    unit: str
    result_fingerprint: str


@dataclass(frozen=True, slots=True)
class DatabaseBaseline:
    started_after: datetime
    pipeline_run_count: int
    identity_fingerprint: str
    enabled_scope_fingerprint: str
    source_identity_fingerprint: str
    sync_state_fingerprint: str


@dataclass(frozen=True, slots=True)
class RehearsalResult:
    candidate_sha: str
    rehearsal_operation_id: str
    preparation_context_fingerprint: str
    preparation_marker_fingerprint: str
    rehearsal_context_fingerprint: str
    systemd_manager_identity_fingerprint: str
    database_identity_fingerprint: str
    runtime_ledger_fingerprint: str
    pipeline_run_ids: tuple[str, ...]
    complete_marker_fingerprint: str

    def to_sanitized_mapping(self) -> dict[str, str | int]:
        return {
            "P3D_DISPOSABLE_REHEARSAL": "PASS",
            "CANDIDATE_SHA": self.candidate_sha,
            "REHEARSAL_OPERATION_ID": self.rehearsal_operation_id,
            "SYSTEMD_MANAGER_REAL": "PASS",
            "SYSTEMD_MANAGER_ISOLATED": "PASS",
            "PRE_REHEARSAL_CONTEXT": self.preparation_context_fingerprint,
            "PREPARATION_MARKER_FINGERPRINT": self.preparation_marker_fingerprint,
            "CURRENT_PROMOTED_IN_DISPOSABLE_ROOT": "PASS",
            "P3D_SERVICE_START_COUNT": 6,
            "P3D_TIMER_ENABLE_COUNT": 0,
            "P3D_TIMER_START_COUNT": 0,
            "POSTGRESQL_MAJOR": 16,
            "RUNTIME_PIPELINE_COVERAGE": "6/6",
            "POST_REHEARSAL_RUNTIME_LEDGER_PROOF": "PASS",
            "TIMERS_FINAL_STATE": "DISABLED_INACTIVE",
            "SYSTEMD_MANAGER_IDENTITY_FINGERPRINT": (
                self.systemd_manager_identity_fingerprint
            ),
            "DATABASE_IDENTITY_FINGERPRINT": self.database_identity_fingerprint,
            "RUNTIME_LEDGER_FINGERPRINT": self.runtime_ledger_fingerprint,
            "REHEARSAL_COMPLETE_MARKER_FINGERPRINT": (
                self.complete_marker_fingerprint
            ),
            "PRODUCTION_TOUCHED": "NO",
        }


class MachineSystemdBackend:
    """Allow-listed systemctl backend for one registered nspawn machine."""

    _SHOW_PROPERTIES = (
        "LoadState", "User", "Group", "Type", "NoNewPrivileges",
        "WorkingDirectory", "ExecStart", "FragmentPath", "DropInPaths",
        "ActiveState", "SubState", "Result", "ExecMainStatus",
    )

    def __init__(
        self,
        machine_name: str,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        proc_root: Path = Path("/proc"),
    ) -> None:
        if MACHINE_NAME.fullmatch(machine_name) is None:
            _fail("P3D_REHEARSAL_MANAGER_INVALID")
        self.machine_name = machine_name
        self.runner = runner
        self.proc_root = proc_root
        self.service_start_count = 0
        self.timer_enable_count = 0
        self.timer_start_count = 0
        self.commands: list[tuple[str, ...]] = []

    def _systemctl(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        command = (
            str(SYSTEMCTL), f"--machine={self.machine_name}", "--no-pager",
            *arguments,
        )
        self.commands.append(command)
        try:
            return self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=1800,
                env=dict(SAFE_ENV),
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            _fail("P3D_REHEARSAL_SYSTEMD_COMMAND_FAILED")

    def _machinectl(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        command = (str(MACHINECTL), *arguments)
        try:
            return self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                env=dict(SAFE_ENV),
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            _fail("P3D_REHEARSAL_MANAGER_INVALID")

    def manager_identity(self, policy: RehearsalPolicy) -> SystemdManagerIdentity:
        result = self._machinectl(
            "show", self.machine_name, "--property=Leader", "--value",
        )
        try:
            leader = int(result.stdout.strip())
            process = self.proc_root / str(leader)
            if result.returncode != 0 or leader <= 1:
                raise ValueError
            comm = (process / "comm").read_text(encoding="utf-8").strip()
            namespace_pid = tuple(
                int(value)
                for line in (process / "status").read_text(encoding="utf-8").splitlines()
                if line.startswith("NSpid:")
                for value in line.split()[1:]
            )
            host_boot = (self.proc_root / "sys/kernel/random/boot_id").read_text().strip()
            manager_root = process / "root"
            manager_boot = (
                manager_root / "proc/sys/kernel/random/boot_id"
            ).read_text().strip()
            if (
                comm != "systemd"
                or not namespace_pid
                or namespace_pid[-1] != 1
                or host_boot == manager_boot
                or not os.path.samefile(manager_root, policy.root)
            ):
                raise ValueError
            rootfs_fingerprint = contract_fingerprint({
                "os_release_sha256": _sha256(
                    (manager_root / "etc/os-release").read_bytes()
                ),
                "systemd_sha256": _sha256(
                    (manager_root / "usr/lib/systemd/systemd").read_bytes()
                ),
            })
            identity = contract_fingerprint({
                "machine_name": self.machine_name,
                "manager_boot_id": manager_boot,
                "rootfs_fingerprint": rootfs_fingerprint,
            })
            return SystemdManagerIdentity(
                leader, host_boot, manager_boot, rootfs_fingerprint, identity,
            )
        except (OSError, ValueError):
            _fail("P3D_REHEARSAL_MANAGER_NOT_ISOLATED")

    def daemon_reload(self) -> None:
        result = self._systemctl("daemon-reload")
        if result.returncode != 0:
            _fail("P3D_REHEARSAL_DAEMON_RELOAD_FAILED")

    def _unit_state(self, action: str, unit: str) -> str:
        result = self._systemctl(action, unit)
        value = result.stdout.strip()
        if action == "is-enabled":
            if value != "disabled":
                _fail("P3D_REHEARSAL_TIMER_NOT_QUIET")
        elif action == "is-active":
            if value != "inactive":
                _fail("P3D_REHEARSAL_UNIT_NOT_INACTIVE")
        else:  # pragma: no cover - internal closed call set
            _fail("P3D_REHEARSAL_SYSTEMD_COMMAND_FAILED")
        return value

    def verify_timers_quiet(self) -> None:
        for key in CANONICAL_PIPELINES:
            timer = P3D_TIMER_UNITS[key]
            self._unit_state("is-enabled", timer)
            self._unit_state("is-active", timer)

    def show_service(self, pipeline_key: str) -> dict[str, str]:
        try:
            unit = SERVICE_UNITS[pipeline_key]
        except KeyError:
            _fail("P3D_REHEARSAL_PIPELINE_SET_INVALID")
        arguments = ["show", unit]
        arguments.extend(f"--property={name}" for name in self._SHOW_PROPERTIES)
        result = self._systemctl(*arguments)
        if result.returncode != 0:
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            name, separator, value = line.partition("=")
            if separator:
                values[name] = value
        if set(values) != set(self._SHOW_PROPERTIES):
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        return values

    def verify_service_contract(self, pipeline_key: str, *, after_run: bool) -> str:
        values = self.show_service(pipeline_key)
        unit = SERVICE_UNITS[pipeline_key]
        expected_exec = (
            "/opt/pdi/current/.venv/bin/python -m "
            "pdi.production_ops.enrichment"
        )
        required = {
            "LoadState": "loaded",
            "User": "pdi",
            "Group": "pdi",
            "Type": "oneshot",
            "NoNewPrivileges": "yes",
            "WorkingDirectory": "/opt/pdi/current",
            "FragmentPath": "/etc/systemd/system/pdi-scoped-pipeline@.service",
            "DropInPaths": "",
        }
        if any(values.get(name) != value for name, value in required.items()):
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        if expected_exec not in values["ExecStart"]:
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        if any(marker in values["ExecStart"].upper() for marker in (
            "DATABASE", "PASSWORD", "TOKEN", "SECRET", "OAUTH",
        )):
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        if values["ActiveState"] != "inactive":
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        if after_run and (
            values["SubState"] != "dead"
            or values["Result"] != "success"
            or values["ExecMainStatus"] != "0"
        ):
            _fail("P3D_REHEARSAL_SERVICE_FAILED")
        if not after_run and values["SubState"] not in {"dead", "failed"}:
            _fail("P3D_REHEARSAL_SERVICE_CONTRACT_INVALID")
        return contract_fingerprint({
            "pipeline_key": pipeline_key,
            "unit": unit,
            "load_state": values["LoadState"],
            "runtime_user": values["User"],
            "runtime_group": values["Group"],
            "result": values["Result"] if after_run else "not_started",
            "exec_main_status": values["ExecMainStatus"] if after_run else "not_started",
        })

    def start_service(self, pipeline_key: str) -> None:
        if pipeline_key not in SERVICE_UNITS:
            _fail("P3D_REHEARSAL_PIPELINE_SET_INVALID")
        result = self._systemctl("start", SERVICE_UNITS[pipeline_key])
        self.service_start_count += 1
        if result.returncode != 0:
            _fail("P3D_REHEARSAL_SERVICE_FAILED")

    def stop_all_services(self) -> bool:
        success = True
        for key in CANONICAL_PIPELINES:
            result = self._systemctl("stop", SERVICE_UNITS[key])
            success = result.returncode == 0 and success
        for key in CANONICAL_PIPELINES:
            try:
                self._unit_state("is-active", SERVICE_UNITS[key])
            except DisposableRehearsalError:
                success = False
        try:
            self.verify_timers_quiet()
        except DisposableRehearsalError:
            success = False
        return success


class RehearsalJournal:
    """Root-only immutable disposable evidence below the rehearsal root."""

    def __init__(self, policy: RehearsalPolicy, operation_id: str) -> None:
        self.policy = policy
        self.operation_id = _canonical_uuid(operation_id)
        self.root = policy.rehearsal_authority_root / self.operation_id
        self.sequence = 0
        self._atomic_policy = AtomicCreatePolicyV1(
            policy.owner_uid, policy.owner_gid, 0o600, policy.root,
        )

    def initialize(self, *, candidate_sha: str) -> None:
        try:
            directory_modes = (
                (self.policy.physical("/var"), 0o755),
                (self.policy.physical("/var/lib"), 0o755),
                (self.policy.physical("/var/lib/pdi-p3d"), 0o700),
                (self.policy.rehearsal_authority_root, 0o700),
            )
            for directory, mode in directory_modes:
                if not directory.exists():
                    directory.mkdir(mode=mode, parents=False)
                    os.chown(
                        directory, self.policy.owner_uid, self.policy.owner_gid,
                    )
                    os.chmod(directory, mode)
                info = directory.lstat()
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != self.policy.owner_uid
                    or info.st_gid != self.policy.owner_gid
                    or stat.S_IMODE(info.st_mode) != mode
                ):
                    raise OSError
            self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
            os.chown(self.root, self.policy.owner_uid, self.policy.owner_gid)
            os.chmod(self.root, 0o700)
        except OSError:
            _fail("P3D_REHEARSAL_AUTHORITY_CONFLICT")
        self.append("NEW", {"candidate_sha": _git_sha(candidate_sha)})

    def append(self, event: str, evidence: Mapping[str, Any]) -> str:
        self.sequence += 1
        payload = {
            "version": 1,
            "sequence": self.sequence,
            "rehearsal_operation_id": self.operation_id,
            "event": event,
            "timestamp": _timestamp(),
            "evidence": dict(evidence),
        }
        encoded = canonical_json_bytes(payload) + b"\n"
        atomic_create_no_replace(
            self.root / f"journal-{self.sequence:06d}.json",
            encoded,
            policy=self._atomic_policy,
        )
        return _sha256(encoded)

    def complete(self, marker: Mapping[str, Any]) -> str:
        encoded = canonical_json_bytes(dict(marker)) + b"\n"
        atomic_create_no_replace(
            self.root / "complete.json", encoded, policy=self._atomic_policy,
        )
        return _sha256(encoded)


class RehearsalDatabaseInspector:
    """SELECT-only verifier for the disposable Personal DB."""

    def __init__(self, engine: Engine, evidence_reader) -> None:
        database = make_url(engine.url).database or ""
        if DISPOSABLE_DATABASE.fullmatch(database) is None:
            _fail("P3D_REHEARSAL_DATABASE_UNSAFE")
        self.engine = engine
        self.evidence_reader = evidence_reader

    @staticmethod
    def _rows_fingerprint(rows: Sequence[Sequence[Any]]) -> str:
        normalized = [
            [None if value is None else str(value) for value in row]
            for row in rows
        ]
        return _sha256(json.dumps(
            normalized, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))

    def _source_identity_fingerprint(self, connection) -> str:
        rows = connection.execute(text(
            "SELECT id,provider,external_id,observation_scope_id,is_active "
            "FROM asset_sources ORDER BY id"
        )).all()
        return self._rows_fingerprint(rows)

    def _sync_state_fingerprint(self, connection) -> str:
        rows = connection.execute(text(
            "SELECT observation_scope_id,mechanism,version,checkpoint,"
            "reconciliation_required FROM observation_scope_sync_state "
            "ORDER BY observation_scope_id,mechanism"
        )).all()
        protected = [
            (
                row[0], row[1], row[2],
                None if row[3] is None else _sha256(str(row[3]).encode()),
                row[4],
            )
            for row in rows
        ]
        return self._rows_fingerprint(protected)

    def baseline(self) -> DatabaseBaseline:
        evidence = self.evidence_reader.collect()
        with self.engine.connect() as connection:
            server_version = int(
                connection.scalar(text("SHOW server_version_num"))
            )
            started_after = connection.scalar(text("SELECT clock_timestamp()"))
            count = int(connection.scalar(text("SELECT count(*) FROM pipeline_runs")))
            source = self._source_identity_fingerprint(connection)
            sync = self._sync_state_fingerprint(connection)
        if (
            server_version // 10_000 != 16
            or started_after.tzinfo is None
            or started_after.utcoffset() is None
        ):
            _fail("P3D_REHEARSAL_DATABASE_INVALID")
        scopes = contract_fingerprint({
            "enabled_scope_ids": sorted(evidence.enabled_scope_ids),
        })
        return DatabaseBaseline(
            started_after.astimezone(UTC), count,
            evidence.identity_fingerprint, scopes, source, sync,
        )

    def assert_no_fresh_run(self, pipeline_key: str, boundary: datetime) -> None:
        with self.engine.connect() as connection:
            count = connection.scalar(text(
                "SELECT count(*) FROM pipeline_runs "
                "WHERE pipeline_key=:key AND started_at > :after"
            ), {"key": pipeline_key, "after": boundary})
        if count != 0:
            _fail("P3D_REHEARSAL_LEDGER_STALE")

    def verify_pipeline(
        self, pipeline_key: str, boundary: datetime,
    ) -> tuple[str, str]:
        with self.engine.connect() as connection:
            rows = connection.execute(text(
                "SELECT id,status,finished_at,error_code FROM pipeline_runs "
                "WHERE pipeline_key=:key AND started_at > :after "
                "ORDER BY started_at,id"
            ), {"key": pipeline_key, "after": boundary}).all()
            generators = EXPECTED_EFFECT_GENERATORS[pipeline_key]
            enrichments = connection.scalar(text(
                "SELECT count(*) FROM resource_enrichments "
                "WHERE extractor_name = ANY(:generators) "
                "AND status='completed' AND completed_at > :after"
            ), {"generators": list(generators), "after": boundary})
            statements = connection.scalar(text(
                "SELECT count(*) FROM resource_statements "
                "WHERE generator_name = ANY(:generators) "
                "AND is_current AND created_at > :after"
            ), {"generators": list(generators), "after": boundary})
        if len(rows) != 1:
            _fail("P3D_REHEARSAL_LEDGER_COVERAGE")
        run_id, status, finished_at, error_code = rows[0]
        if (
            status != "completed"
            or finished_at is None
            or error_code is not None
            or int(enrichments or 0) < 1
            or int(statements or 0) < 1
        ):
            _fail("P3D_REHEARSAL_WORKLOAD_EFFECT_INVALID")
        effect = contract_fingerprint({
            "pipeline_key": pipeline_key,
            "completed_enrichment_count": int(enrichments),
            "current_statement_count": int(statements),
        })
        return str(run_id), effect

    def final(
        self,
        baseline: DatabaseBaseline,
        *,
        candidate_sha: str,
        context_fingerprint: str,
    ) -> tuple[tuple[dict[str, str], ...], str]:
        evidence = self.evidence_reader.collect()
        scopes = contract_fingerprint({
            "enabled_scope_ids": sorted(evidence.enabled_scope_ids),
        })
        with self.engine.connect() as connection:
            rows = connection.execute(text(
                "SELECT id,pipeline_key,status,finished_at,error_code "
                "FROM pipeline_runs WHERE started_at > :after "
                "ORDER BY pipeline_key,id"
            ), {"after": baseline.started_after}).all()
            total = int(connection.scalar(text("SELECT count(*) FROM pipeline_runs")))
            source = self._source_identity_fingerprint(connection)
            sync = self._sync_state_fingerprint(connection)
        if (
            evidence.identity_fingerprint != baseline.identity_fingerprint
            or scopes != baseline.enabled_scope_fingerprint
            or source != baseline.source_identity_fingerprint
            or sync != baseline.sync_state_fingerprint
            or total != baseline.pipeline_run_count + 6
            or len(rows) != 6
            or {row[1] for row in rows} != set(CANONICAL_PIPELINES)
            or len({row[0] for row in rows}) != 6
            or any(
                row[2] != "completed" or row[3] is None or row[4] is not None
                for row in rows
            )
        ):
            _fail("P3D_REHEARSAL_FINAL_INVARIANT_FAILED")
        ledger = tuple({
            "pipeline_key": row[1],
            "run_id": str(row[0]),
            "candidate_sha": _git_sha(candidate_sha),
            "context_fingerprint": context_fingerprint,
        } for row in rows)
        fingerprint = contract_fingerprint({"runtime_ledger": ledger})
        return ledger, fingerprint


def _rootfs_pdi_identity(root: Path) -> tuple[int, int]:
    try:
        passwd_rows = [
            line.split(":")
            for line in (root / "etc/passwd").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        group_rows = [
            line.split(":")
            for line in (root / "etc/group").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        users = [row for row in passwd_rows if row[0] == "pdi" and len(row) >= 4]
        groups = [row for row in group_rows if row[0] == "pdi" and len(row) >= 3]
        if len(users) != 1 or len(groups) != 1:
            raise ValueError
        uid, primary_gid, group_gid = int(users[0][2]), int(users[0][3]), int(groups[0][2])
        if uid <= 0 or primary_gid <= 0 or primary_gid != group_gid:
            raise ValueError
        return uid, group_gid
    except (OSError, ValueError, IndexError):
        _fail("P3D_REHEARSAL_RUNTIME_IDENTITY_INVALID")


def _profile_principal(policy: RehearsalPolicy) -> str:
    principals: set[str] = set()
    for key in CANONICAL_PIPELINES:
        values = parse_env(
            policy.physical(f"/etc/pdi/scoped/units/{key}.env").read_text()
        )
        if values.get("PDI_SCOPED_PIPELINE_KEY") != key:
            _fail("P3D_REHEARSAL_PROFILE_INVALID")
        principal = values.get("PDI_PRINCIPAL_REF")
        if not principal:
            _fail("P3D_REHEARSAL_PROFILE_INVALID")
        principals.add(principal)
    if len(principals) != 1:
        _fail("P3D_REHEARSAL_PROFILE_INVALID")
    return principals.pop()


def build_database_inspector(policy: RehearsalPolicy) -> tuple[Engine, RehearsalDatabaseInspector]:
    try:
        environment = parse_env(
            policy.physical("/etc/pdi/pdi.env").read_text(encoding="utf-8")
        )
        configuration = load_scoped_operator_configuration(
            policy.physical("/etc/pdi/scoped/registry.toml"),
            environment=environment,
        )
        principal = _profile_principal(policy)
        binding = configuration.router.resolve(principal)
        engine = create_postgres_engine(binding.database_url)
        reader = RoutedPersonalDatabaseEvidenceReader(
            configuration.router, engine, principal_ref=principal,
        )
        return engine, RehearsalDatabaseInspector(engine, reader)
    except DisposableRehearsalError:
        raise
    except Exception:
        _fail("P3D_REHEARSAL_DATABASE_INVALID")


def verify_rehearsal_runtime(
    policy: RehearsalPolicy,
    candidate_sha: str,
    *,
    executable: Path | None = None,
    module_file: Path | None = None,
    script_file: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Bind this operator process to the exact immutable candidate release."""

    candidate = _git_sha(candidate_sha)
    release = policy.releases / candidate
    expected_python = release / ".venv/bin/python"
    expected_source = release / "src/pdi/production_ops/p3d_disposable_rehearsal.py"
    expected_script = release / "scripts/pdi_p3d_disposable_rehearsal.py"
    executable = Path(sys.executable if executable is None else executable).absolute()
    module_file = Path(__file__ if module_file is None else module_file).absolute()
    script_file = Path(sys.argv[0] if script_file is None else script_file).absolute()
    try:
        resolved_module = module_file.resolve(strict=True)
        installed_root = (release / ".venv").resolve(strict=True)
        if (
            executable != expected_python
            or script_file != expected_script
            or not os.path.samefile(expected_script, script_file)
            or installed_root not in resolved_module.parents
            or resolved_module.read_bytes() != expected_source.read_bytes()
        ):
            raise OSError
        for arguments in (
            ("/usr/bin/git", "-C", str(release), "rev-parse", "HEAD"),
            (
                "/usr/bin/git", "-C", str(release), "status",
                "--porcelain", "--untracked-files=all",
            ),
        ):
            result = runner(
                arguments,
                capture_output=True,
                text=True,
                timeout=30,
                env=dict(GIT_READ_ONLY_ENV),
                shell=False,
            )
            if result.returncode != 0:
                raise OSError
            if arguments[-2:] == ("rev-parse", "HEAD"):
                if result.stdout.strip() != candidate:
                    raise OSError
            elif result.stdout.strip():
                raise OSError
        return _sha256(resolved_module.read_bytes())
    except (OSError, subprocess.TimeoutExpired):
        _fail("P3D_REHEARSAL_RUNTIME_INVALID")


def verify_candidate_release(
    policy: RehearsalPolicy, candidate_sha: str,
) -> str:
    candidate = _git_sha(candidate_sha)
    release = policy.releases / candidate
    home = policy.physical("/root")
    try:
        home.mkdir(mode=0o700, exist_ok=True)
        os.chown(home, policy.owner_uid, policy.owner_gid)
        os.chmod(home, 0o700)
        bootstrap_policy = BootstrapPolicy.qualification(
            disposable_root=policy.root,
            owner_uid=policy.owner_uid,
            owner_gid=policy.owner_gid,
            runtime_uid=policy.runtime_uid,
            runtime_gid=policy.runtime_gid,
        )
        return _verify_release_tree(
            release,
            candidate=candidate,
            policy=bootstrap_policy,
            approved_python=release / ".venv/bin/python",
            home=home,
        )
    except DisposableRehearsalError:
        raise
    except Exception:
        _fail("P3D_REHEARSAL_CANDIDATE_INVALID")


def promote_disposable_current(
    policy: RehearsalPolicy, candidate_sha: str, operation_id: str,
) -> str:
    candidate = _git_sha(candidate_sha)
    try:
        current = policy.current
        info = current.lstat()
        if not stat.S_ISLNK(info.st_mode):
            raise OSError
        previous = os.readlink(current)
        match = re.fullmatch(r"/opt/pdi/releases/([0-9a-f]{40})", previous)
        if match is None or match.group(1) == candidate:
            raise OSError
        target = f"/opt/pdi/releases/{candidate}"
        temporary = current.parent / f".current-{_canonical_uuid(operation_id)}"
        if temporary.exists() or temporary.is_symlink():
            raise OSError
        os.symlink(target, temporary)
        descriptor = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
            os.replace(temporary, current)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.readlink(current) != target:
            raise OSError
        return previous
    except OSError:
        _fail("P3D_REHEARSAL_PROMOTION_FAILED")


def _configuration_fingerprint(policy: RehearsalPolicy) -> str:
    paths = (
        policy.physical("/etc/pdi/pdi.env"),
        policy.physical("/etc/pdi/scoped/registry.toml"),
        *(policy.physical(f"/etc/pdi/scoped/units/{key}.env")
          for key in CANONICAL_PIPELINES),
    )
    try:
        return contract_fingerprint({
            "protected_file_hashes": [
                _sha256(path.read_bytes()) for path in paths
            ],
        })
    except OSError:
        _fail("P3D_REHEARSAL_CONFIGURATION_INVALID")


class DisposableRehearsal:
    """One-shot WP7 orchestration against an isolated systemd manager."""

    def __init__(
        self,
        *,
        inputs: RehearsalInputs,
        policy: RehearsalPolicy,
        preparation_collector: Callable[[], PreRehearsalEvidenceResult],
        systemd: MachineSystemdBackend,
        database_factory: Callable[
            [RehearsalPolicy], tuple[Engine, RehearsalDatabaseInspector]
        ] = build_database_inspector,
        release_verifier: Callable[[RehearsalPolicy, str], str] = verify_candidate_release,
        crash_after_pipeline: int | None = None,
    ) -> None:
        inputs.validate()
        if policy.machine_name != machine_name_for(inputs.rehearsal_operation_id):
            _fail("P3D_REHEARSAL_MANAGER_INVALID")
        if systemd.machine_name != policy.machine_name:
            _fail("P3D_REHEARSAL_MANAGER_INVALID")
        self.inputs = inputs
        self.policy = policy
        self.preparation_collector = preparation_collector
        self.systemd = systemd
        self.database_factory = database_factory
        self.release_verifier = release_verifier
        self.crash_after_pipeline = crash_after_pipeline

    @staticmethod
    def _preparation_valid(result: PreRehearsalEvidenceResult, candidate: str) -> bool:
        sanitized = result.to_sanitized_mapping()
        return (
            result.candidate_sha == candidate
            and sanitized.get("PRE_REHEARSAL_PREPARATION_CONTRACT") == "PASS"
            and sanitized.get("RUNTIME_PIPELINE_COVERAGE") == "0/6"
        )

    def run(self) -> RehearsalResult:
        journal = RehearsalJournal(
            self.policy, self.inputs.rehearsal_operation_id,
        )
        journal.initialize(candidate_sha=self.inputs.candidate_sha)
        engine: Engine | None = None
        manager_verified = False
        services_cleaned = False
        try:
            preparation = self.preparation_collector()
            preparation_repeat = self.preparation_collector()
            if (
                not self._preparation_valid(preparation, self.inputs.candidate_sha)
                or preparation_repeat != preparation
            ):
                _fail("P3D_REHEARSAL_PREPARATION_INVALID")
            rehearsal_context = contract_fingerprint({
                "candidate_sha": self.inputs.candidate_sha,
                "gate_a_operation_id": self.inputs.gate_a_operation_id,
                "gate_b_operation_id": self.inputs.gate_b_operation_id,
                "gate_c_operation_id": self.inputs.gate_c_operation_id,
                "rehearsal_operation_id": self.inputs.rehearsal_operation_id,
                "preparation_context_fingerprint": preparation.context_fingerprint,
                "preparation_marker_fingerprint": preparation.marker_fingerprint,
            })
            journal.append("PREPARATION_VERIFIED", {
                "preparation_context_fingerprint": preparation.context_fingerprint,
                "preparation_marker_fingerprint": preparation.marker_fingerprint,
                "rehearsal_context_fingerprint": rehearsal_context,
            })

            manager = self.systemd.manager_identity(self.policy)
            manager_verified = True
            journal.append("SYSTEMD_MANAGER_VERIFIED", {
                "systemd_manager_identity_fingerprint": manager.identity_fingerprint,
            })

            release_fingerprint = self.release_verifier(
                self.policy, self.inputs.candidate_sha,
            )
            configuration_before = _configuration_fingerprint(self.policy)
            preparation_before_promotion = self.preparation_collector()
            if preparation_before_promotion != preparation:
                _fail("P3D_REHEARSAL_PREPARATION_DRIFT")
            previous_current = promote_disposable_current(
                self.policy,
                self.inputs.candidate_sha,
                self.inputs.rehearsal_operation_id,
            )
            if self.release_verifier(
                self.policy, self.inputs.candidate_sha,
            ) != release_fingerprint:
                _fail("P3D_REHEARSAL_CANDIDATE_DRIFT")
            journal.append("CANDIDATE_PROMOTED", {
                "previous_current_fingerprint": contract_fingerprint({
                    "previous_current": previous_current,
                }),
                "candidate_release_fingerprint": release_fingerprint,
            })

            self.systemd.daemon_reload()
            journal.append("SYSTEMD_RELOADED", {
                "manager_identity_fingerprint": manager.identity_fingerprint,
            })
            self.systemd.verify_timers_quiet()
            for key in CANONICAL_PIPELINES:
                self.systemd.verify_service_contract(key, after_run=False)
            journal.append("SERVICES_VERIFIED", {
                "service_set_fingerprint": contract_fingerprint({
                    "service_units": [SERVICE_UNITS[key] for key in CANONICAL_PIPELINES],
                }),
            })

            engine, inspector = self.database_factory(self.policy)
            baseline = inspector.baseline()
            if baseline.identity_fingerprint != preparation.db_identity_fingerprint:
                _fail("P3D_REHEARSAL_DATABASE_CONTEXT_MISMATCH")
            run_ids: list[str] = []
            service_results: list[str] = []
            for index, key in enumerate(CANONICAL_PIPELINES, start=1):
                self.systemd.verify_timers_quiet()
                self.systemd.verify_service_contract(key, after_run=False)
                inspector.assert_no_fresh_run(key, baseline.started_after)
                self.systemd.start_service(key)
                service_result = self.systemd.verify_service_contract(
                    key, after_run=True,
                )
                run_id, effect = inspector.verify_pipeline(
                    key, baseline.started_after,
                )
                run_ids.append(run_id)
                service_results.append(service_result)
                self.systemd.verify_timers_quiet()
                journal.append("PIPELINE_VERIFIED", {
                    "pipeline_key": key,
                    "pipeline_run_id": run_id,
                    "service_result_fingerprint": service_result,
                    "workload_effect_fingerprint": effect,
                })
                if self.crash_after_pipeline == index:
                    _fail("P3D_REHEARSAL_INJECTED_FAILURE")

            ledger, ledger_fingerprint = inspector.final(
                baseline,
                candidate_sha=self.inputs.candidate_sha,
                context_fingerprint=preparation.context_fingerprint,
            )
            if tuple(item["run_id"] for item in ledger) != tuple(sorted(run_ids)):
                # The DB verifier orders by pipeline key; compare sets while
                # retaining deterministic canonical ledger serialization.
                if {item["run_id"] for item in ledger} != set(run_ids):
                    _fail("P3D_REHEARSAL_LEDGER_COVERAGE")
            if (
                self.systemd.service_start_count != 6
                or self.systemd.timer_enable_count != 0
                or self.systemd.timer_start_count != 0
            ):
                _fail("P3D_REHEARSAL_SYSTEMD_CARDINALITY_INVALID")
            self.systemd.verify_timers_quiet()
            if _configuration_fingerprint(self.policy) != configuration_before:
                _fail("P3D_REHEARSAL_CONFIGURATION_DRIFT")
            if not self.systemd.stop_all_services():
                _fail("P3D_REHEARSAL_CLEANUP_FAILED")
            services_cleaned = True
            marker = {
                "version": 1,
                "rehearsal_operation_id": self.inputs.rehearsal_operation_id,
                "candidate_sha": self.inputs.candidate_sha,
                "preparation_context_fingerprint": preparation.context_fingerprint,
                "preparation_marker_fingerprint": preparation.marker_fingerprint,
                "rehearsal_context_fingerprint": rehearsal_context,
                "started_at": _timestamp(baseline.started_after),
                "completed_at": _timestamp(),
                "pipeline_keys": list(CANONICAL_PIPELINES),
                "pipeline_run_ids": sorted(run_ids),
                "runtime_ledger_fingerprint": ledger_fingerprint,
                "runtime_pipeline_coverage": "6/6",
                "timers_before": "DISABLED_INACTIVE",
                "timers_after": "DISABLED_INACTIVE",
                "systemd_manager_identity_fingerprint": manager.identity_fingerprint,
                "database_identity_fingerprint": baseline.identity_fingerprint,
                "service_result_fingerprint": contract_fingerprint({
                    "service_results": service_results,
                }),
                "production_touched": False,
            }
            journal.append("LEDGER_VERIFIED", {
                "runtime_ledger_fingerprint": ledger_fingerprint,
            })
            marker_fingerprint = journal.complete(marker)
            return RehearsalResult(
                self.inputs.candidate_sha,
                self.inputs.rehearsal_operation_id,
                preparation.context_fingerprint,
                preparation.marker_fingerprint,
                rehearsal_context,
                manager.identity_fingerprint,
                baseline.identity_fingerprint,
                ledger_fingerprint,
                tuple(sorted(run_ids)),
                marker_fingerprint,
            )
        except DisposableRehearsalError as error:
            try:
                journal.append("FAILED", {"failure_code": error.code})
            except Exception:
                pass
            raise
        except BaseException:
            try:
                journal.append("FAILED", {
                    "failure_code": "P3D_DISPOSABLE_REHEARSAL_REJECTED",
                })
            except Exception:
                pass
            _fail()
        finally:
            if manager_verified and not services_cleaned:
                self.systemd.stop_all_services()
            if engine is not None:
                engine.dispose()


def rootfs_pdi_identity(root: Path) -> tuple[int, int]:
    """Public qualification helper used by the single-purpose CLI."""

    return _rootfs_pdi_identity(root)
