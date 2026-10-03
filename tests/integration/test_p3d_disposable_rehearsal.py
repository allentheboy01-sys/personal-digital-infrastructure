from __future__ import annotations

from base64 import b64encode
from contextlib import contextmanager
from dataclasses import dataclass, replace
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shlex
import shutil
import signal
import stat
import subprocess
import threading
import time
from uuid import UUID, uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from pdi.database import create_postgres_engine
from pdi.production_ops.contracts import QUALIFICATION, parse_env
from pdi.production_ops.cutover import Host as FrozenP3CHost, Paths as FrozenP3CPaths
from pdi.production_ops.p3d_disposable_rehearsal import (
    CANONICAL_PIPELINES,
    DisposableRehearsalError,
    MachineSystemdBackend,
    SERVICE_UNITS,
    machine_name_for,
)
from pdi.production_ops.enrichment_cutover import P3D_TIMER_UNITS
from pdi.production_ops.p3d_preparation_contracts import (
    OperatorToolIdentity,
    ToolName,
)
from pdi.production_ops.p3d_release_bootstrap import (
    BootstrapInputs,
    BootstrapPolicy,
    QualificationHostRuntimeAuthorityProvider,
    ReleaseBootstrap,
    resolve_runtime_identity,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.scope_sync_state import PostgreSQLScopeSyncStateRepository
from tests.integration.database_guard import require_safe_test_database_url
from tests.integration.test_p3d_inert_asset_install import (
    _clean,
    _create_complete_gate_a,
    _write,
)


ROOT = Path(__file__).resolve().parents[2]
H1 = "1" * 64
SOURCE = "b" * 40
IMMICH_ACCOUNT_ID = "33333333-3333-4333-8333-333333333333"
PRINCIPAL_ID = "44444444-4444-4444-8444-444444444444"
SYSTEMD_NSPAWN = Path("/usr/bin/systemd-nspawn")
MACHINECTL = Path("/usr/bin/machinectl")
NSENTER = Path("/usr/bin/nsenter")
SETPRIV = Path("/usr/bin/setpriv")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
READELF = Path("/usr/bin/readelf")
LDD = Path("/usr/bin/ldd")
LDCONFIG = Path("/sbin/ldconfig")
SHA256SUM = Path("/usr/bin/sha256sum")
TEST = Path("/usr/bin/test")
STAT = Path("/usr/bin/stat")
CAT = Path("/usr/bin/cat")
FIND = Path("/usr/bin/find")
_LIBPYTHON_SONAME = "libpython3.13.so.1.0"
_DIAGNOSTIC_LIMIT = 64 * 1024
_LOADER_CACHE_OUTPUT_LIMIT = 4 * 1024 * 1024
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(DATABASE__URL|PASSWORD|API[_-]?KEY|ACCESS[_-]?TOKEN|"
    r"REFRESH[_-]?TOKEN|OAUTH|SECRET)\b\s*[:=]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s\r\n]+)"
)
_PROTECTED_SECRET_MARKERS = (
    "DATABASE__URL",
    "NEXTCLOUD__PASSWORD",
    "IMMICH__API_KEY",
)
_LIBRARY_BASENAME = re.compile(r"[A-Za-z0-9_.+-]+")
_ELF_INTERPRETER = re.compile(
    r"\[Requesting program interpreter: ([/A-Za-z0-9_.+-]+)\]"
)
_PATH_CLASSES = {"APPROVED_RUNTIME", "CANDIDATE_RELEASE", "OTHER", "ABSENT"}
_INTERPRETER_FAILURE_CLASSES = {
    "BASE_RUNTIME_NOT_EXECUTABLE_IN_CONTAINER",
    "CANDIDATE_VENV_NOT_EXECUTABLE_IN_CONTAINER",
    "SYSTEMD_SANDBOX_RUNTIME_FAILURE",
    "DYNAMIC_LIBRARY_RESOLUTION_FAILURE",
    "PHYSICAL_LOGICAL_RUNTIME_PATH_MISMATCH",
    "INTERPRETER_FAILURE_UNCLASSIFIED",
}
_QUALIFICATION_PYTHON_PREFLIGHT_CLASSES = {
    "BASE_PYTHON_PROBE_FAILED",
    "CANDIDATE_PYTHON_PROBE_FAILED",
    "BOTH_PYTHON_PROBES_FAILED",
    "BASE_PYTHON_MISSING_LIBRARY",
    "CANDIDATE_PYTHON_MISSING_LIBRARY",
    "BOTH_PYTHONS_MISSING_LIBRARY",
    "BASE_ELF_INVALID",
    "CANDIDATE_ELF_INVALID",
    "BOTH_ELF_INVALID",
    "QUALIFICATION_PYTHON_PREFLIGHT_UNCLASSIFIED",
}
_LOADER_RESULTS = {"RESOLVED", "NOT_FOUND", "INVALID"}
_CONTAINER_LOADER_CACHE_CLASSES = {
    "CONTAINER_CACHE_FILE_MISSING",
    "CONTAINER_CACHE_BYTES_MISMATCH",
    "CONTAINER_CACHE_LIBPYTHON_ENTRY_MISSING",
    "CONTAINER_CACHE_LIBPYTHON_ENTRY_AMBIGUOUS",
    "CONTAINER_CACHE_TARGET_NOT_VISIBLE",
    "CONTAINER_CACHE_TARGET_IDENTITY_MISMATCH",
    "QUALIFICATION_RUNTIME_BIND_NOT_VISIBLE",
    "LOADER_NOT_RESOLVING_VALID_CACHE_ENTRY",
    "LOADER_CACHE_EFFECTIVE",
    "LOADER_CACHE_VISIBILITY_UNCLASSIFIED",
}
_CACHE_WRITER_UNITS = (
    "ldconfig.service",
    "systemd-update-done.service",
    "systemd-tmpfiles-setup.service",
    "systemd-tmpfiles-setup-dev.service",
)
_CACHE_WRITER_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "InactiveExitTimestampMonotonic",
    "ActiveEnterTimestampMonotonic",
    "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic",
)
_SYSTEMD_LOAD_STATES = {
    "loaded", "not-found", "masked", "error", "bad-setting",
}
_SYSTEMD_ACTIVE_STATES = {
    "active", "reloading", "inactive", "failed", "activating",
    "deactivating", "maintenance",
}
_SYSTEMD_SUB_STATES = {
    "dead", "exited", "running", "failed", "start", "start-pre",
    "start-post", "stop", "stop-sigterm", "stop-sigkill", "auto-restart",
    "condition", "plugged", "mounted", "waiting",
}
_SYSTEMD_RESULTS = {
    "success", "exit-code", "signal", "core-dump", "watchdog",
    "start-limit-hit", "resources", "timeout", "protocol", "dependency",
    "skipped", "oom-kill", "none",
}
_CACHE_WRITER_CLASSES = {
    "LDCONFIG_SERVICE_CONFIRMED",
    "LDCONFIG_SERVICE_EXECUTED_BUT_CAUSALITY_UNPROVEN",
    "OTHER_ALLOWLISTED_SYSTEMD_WRITER_CONFIRMED",
    "CACHE_CHANGED_WITH_NO_ALLOWLISTED_WRITER",
    "CACHE_NOT_CHANGED",
    "ATTRIBUTION_INSUFFICIENT",
}
_CACHE_WRITER_INPUT_CLASSES = {
    "QUALIFICATION_RUNTIME_INCLUDED",
    "QUALIFICATION_RUNTIME_NOT_INCLUDED",
    "WRITER_NOT_CONFIRMED",
    "INPUT_AUTHORITY_UNKNOWN",
}
_LDCONFIG_JOURNAL_CLASSES = {
    "EXECUTED_SUCCESS",
    "EXECUTED_FAILED",
    "SKIPPED_CONDITION",
    "NOT_OBSERVED",
    "AMBIGUOUS",
}


@dataclass(frozen=True)
class _ManagerStartupDiagnostic:
    failure_class: str
    diagnostic_class: str
    nspawn_exit_code: int | None
    nspawn_stdout_sha256: str
    nspawn_stderr_sha256: str
    machinectl_return_code: int
    machinectl_stdout_sha256: str
    machinectl_stderr_sha256: str
    diagnostic_safe_excerpt: str
    nspawn_stderr_safe_excerpt: str
    machinectl_stderr_safe_excerpt: str
    sanitized_nspawn_stdout: str
    sanitized_nspawn_stderr: str
    sanitized_machinectl_stdout: str
    sanitized_machinectl_stderr: str

    def safe_message(self) -> str:
        exit_code = -1 if self.nspawn_exit_code is None else self.nspawn_exit_code
        lines = [
            self.failure_class,
            f"NSPAWN_EXIT_CODE={exit_code}",
            f"NSPAWN_FAILURE_CLASS={self.failure_class}",
            f"NSPAWN_DIAGNOSTIC_CLASS={self.diagnostic_class}",
            f"NSPAWN_STDOUT_SHA256={self.nspawn_stdout_sha256}",
            f"NSPAWN_STDERR_SHA256={self.nspawn_stderr_sha256}",
            f"MACHINECTL_RETURN_CODE={self.machinectl_return_code}",
            f"MACHINECTL_STDOUT_SHA256={self.machinectl_stdout_sha256}",
            f"MACHINECTL_STDERR_SHA256={self.machinectl_stderr_sha256}",
        ]
        if self.diagnostic_safe_excerpt == "PASS":
            lines.extend((
                "DIAGNOSTIC_SAFE_EXCERPT=PASS",
                f"NSPAWN_STDERR_SAFE_EXCERPT={self.nspawn_stderr_safe_excerpt}",
                "MACHINECTL_STDERR_SAFE_EXCERPT="
                f"{self.machinectl_stderr_safe_excerpt}",
            ))
        else:
            lines.append("DIAGNOSTIC_SAFE_EXCERPT=REDACTED")
        return "\n".join(lines)


class _ManagerStartupError(AssertionError):
    def __init__(self, diagnostic: _ManagerStartupDiagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.safe_message())


@dataclass(frozen=True)
class _RehearsalFailureJournalDiagnostic:
    last_event: str
    verified_pipelines: tuple[str, ...]
    failed_pipeline_key: str
    failed_service_unit: str
    systemctl_start_return_code: int
    service_state: dict[str, str]


@dataclass(frozen=True)
class _PipelineRunFailureDiagnostic:
    total: int
    completed: int
    failed: int
    failed_pipeline_present: bool
    failed_pipeline_status: str | None
    failed_pipeline_finished: bool | None
    failed_pipeline_error_code: str | None


@dataclass(frozen=True)
class _ElfDependencyDiagnostic:
    dynamic: bool
    interpreter_present: bool
    missing_libraries: tuple[str, ...]


_ELF_OK = _ElfDependencyDiagnostic(True, True, ())


@dataclass(frozen=True)
class _TrustedLibpython:
    path: Path
    directory: Path
    sha256: str


@dataclass(frozen=True)
class _QualificationPythonPreflight:
    candidate_probe_rc: int
    base_probe_rc: int
    candidate_elf: _ElfDependencyDiagnostic
    base_elf: _ElfDependencyDiagnostic

    def safe_values(
        self,
        classification: str,
    ) -> tuple[tuple[str, str], ...]:
        _validate_qualification_python_preflight(self)
        if classification not in _QUALIFICATION_PYTHON_PREFLIGHT_CLASSES:
            raise AssertionError(
                "QUALIFICATION_PYTHON_PREFLIGHT_DIAGNOSTIC_REJECTED"
            )
        base_missing = self.base_elf.missing_libraries
        candidate_missing = self.candidate_elf.missing_libraries
        return (
            ("QUALIFICATION_PYTHON_PREFLIGHT", "FAIL"),
            ("CONTAINER_BASE_PYTHON_PROBE_RC", str(self.base_probe_rc)),
            (
                "CONTAINER_CANDIDATE_PYTHON_PROBE_RC",
                str(self.candidate_probe_rc),
            ),
            (
                "BASE_PYTHON_ELF_DYNAMIC",
                "YES" if self.base_elf.dynamic else "NO",
            ),
            (
                "BASE_PYTHON_INTERPRETER_PRESENT",
                "YES" if self.base_elf.interpreter_present else "NO",
            ),
            ("BASE_PYTHON_MISSING_LIBRARY_COUNT", str(len(base_missing))),
            (
                "BASE_PYTHON_MISSING_LIBRARIES",
                ",".join(base_missing) or "NONE",
            ),
            (
                "CANDIDATE_PYTHON_ELF_DYNAMIC",
                "YES" if self.candidate_elf.dynamic else "NO",
            ),
            (
                "CANDIDATE_PYTHON_INTERPRETER_PRESENT",
                "YES" if self.candidate_elf.interpreter_present else "NO",
            ),
            (
                "CANDIDATE_PYTHON_MISSING_LIBRARY_COUNT",
                str(len(candidate_missing)),
            ),
            (
                "CANDIDATE_PYTHON_MISSING_LIBRARIES",
                ",".join(candidate_missing) or "NONE",
            ),
            ("QUALIFICATION_PYTHON_PREFLIGHT_CLASS", classification),
        )


class _QualificationPythonPreflightError(AssertionError):
    def __init__(
        self,
        diagnostic: _QualificationPythonPreflight,
        classification: str,
    ) -> None:
        values = diagnostic.safe_values(classification)
        self.candidate_probe_rc = diagnostic.candidate_probe_rc
        self.base_probe_rc = diagnostic.base_probe_rc
        self.candidate_elf = diagnostic.candidate_elf
        self.base_elf = diagnostic.base_elf
        self.classification = classification
        super().__init__("\n".join(f"{name}={value}" for name, value in values))

    def safe_message(self) -> str:
        diagnostic = _QualificationPythonPreflight(
            self.candidate_probe_rc,
            self.base_probe_rc,
            self.candidate_elf,
            self.base_elf,
        )
        return "\n".join(
            f"{name}={value}"
            for name, value in diagnostic.safe_values(self.classification)
        )


@dataclass(frozen=True)
class _ContainerLoaderCacheDiagnostic:
    host_cache_present: bool
    host_cache_sha256_valid: bool
    container_cache_present: bool
    container_cache_regular: bool
    container_cache_bytes_match_host: bool
    libpython_entry_count: int
    cache_target_visible: bool
    cache_target_identity_match: bool
    base_python_visible: bool
    libpython_visible: bool
    base_loader_direct: str
    candidate_loader_direct: str
    base_loader_default_cache: str
    base_loader_inhibit_cache: str

    @property
    def classification(self) -> str:
        return _container_loader_cache_classification(self)

    def safe_values(self) -> tuple[tuple[str, str], ...]:
        _validate_container_loader_cache_diagnostic(self)
        return (
            (
                "HOST_LOADER_CACHE_PRESENT",
                "YES" if self.host_cache_present else "NO",
            ),
            (
                "HOST_LOADER_CACHE_SHA256_VALID",
                "PASS" if self.host_cache_sha256_valid else "FAIL",
            ),
            (
                "CONTAINER_LOADER_CACHE_PRESENT",
                "YES" if self.container_cache_present else "NO",
            ),
            (
                "CONTAINER_LOADER_CACHE_REGULAR",
                "YES" if self.container_cache_regular else "NO",
            ),
            (
                "CONTAINER_LOADER_CACHE_BYTES_MATCH_HOST",
                (
                    "PASS"
                    if self.container_cache_bytes_match_host
                    else "FAIL"
                ),
            ),
            (
                "CONTAINER_CACHE_LIBPYTHON_ENTRY_COUNT",
                str(self.libpython_entry_count),
            ),
            (
                "CONTAINER_CACHE_LIBPYTHON_ENTRY_PRESENT",
                "YES" if self.libpython_entry_count > 0 else "NO",
            ),
            (
                "CONTAINER_CACHE_TARGET_VISIBLE",
                "YES" if self.cache_target_visible else "NO",
            ),
            (
                "CONTAINER_CACHE_TARGET_IDENTITY_MATCH",
                "PASS" if self.cache_target_identity_match else "FAIL",
            ),
            (
                "CONTAINER_BASE_PYTHON_FILE_VISIBLE",
                "YES" if self.base_python_visible else "NO",
            ),
            (
                "CONTAINER_LIBPYTHON_FILE_VISIBLE",
                "YES" if self.libpython_visible else "NO",
            ),
            ("BASE_LOADER_DIRECT_LIBPYTHON", self.base_loader_direct),
            (
                "CANDIDATE_LOADER_DIRECT_LIBPYTHON",
                self.candidate_loader_direct,
            ),
            (
                "BASE_LOADER_DEFAULT_CACHE_RESULT",
                self.base_loader_default_cache,
            ),
            (
                "BASE_LOADER_INHIBIT_CACHE_RESULT",
                self.base_loader_inhibit_cache,
            ),
            (
                "CONTAINER_LOADER_CACHE_DIAGNOSTIC_CLASS",
                self.classification,
            ),
        )

    def safe_message(self) -> str:
        return "\n".join(
            f"{name}={value}" for name, value in self.safe_values()
        )


class _ContainerLoaderCacheDiagnosticError(AssertionError):
    def __init__(self, diagnostic: _ContainerLoaderCacheDiagnostic) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.safe_message())


@dataclass(frozen=True)
class _LoaderCacheSnapshot:
    present: bool
    regular: bool
    nonempty: bool
    owner_uid: int
    owner_gid: int
    mode: int
    size: int
    sha256: str

    @property
    def identity_valid(self) -> bool:
        return (
            self.present
            and self.regular
            and self.nonempty
            and self.owner_uid == 0
            and self.owner_gid == 0
            and self.mode == 0o644
            and self.size > 0
            and re.fullmatch(r"[0-9a-f]{64}", self.sha256) is not None
        )


@dataclass(frozen=True)
class _CacheWriterServiceState:
    unit: str
    load_state: str
    active_state: str
    sub_state: str
    result: str
    exec_main_code: int
    exec_main_status: int
    inactive_exit_monotonic_us: int
    active_enter_monotonic_us: int
    exec_start_monotonic_us: int
    exec_exit_monotonic_us: int

    @property
    def executed(self) -> bool:
        return self.exec_start_monotonic_us > 0


@dataclass(frozen=True)
class _LdConfigInputAuthority:
    main_present: bool
    main_includes_runtime: bool
    conf_d_file_count: int
    conf_d_includes_runtime: bool
    valid: bool = True

    @property
    def includes_runtime(self) -> bool:
        return self.main_includes_runtime or self.conf_d_includes_runtime


@dataclass(frozen=True)
class _BootCacheAttributionDiagnostic:
    pre_boot: _LoaderCacheSnapshot
    post_boot: _LoaderCacheSnapshot
    writer_states: tuple[_CacheWriterServiceState, ...]
    ldconfig_input: _LdConfigInputAuthority
    nspawn_start_monotonic_us: int
    manager_registration_monotonic_us: int
    post_observation_monotonic_us: int
    post_libpython_entry_count: int
    ldconfig_journal_class: str = "NOT_OBSERVED"

    @property
    def cache_changed(self) -> bool:
        if not self.pre_boot.identity_valid:
            return False
        if not self.post_boot.present:
            return True
        return (
            re.fullmatch(r"[0-9a-f]{64}", self.post_boot.sha256) is not None
            and self.pre_boot.sha256 != self.post_boot.sha256
        )

    @property
    def ldconfig_state(self) -> _CacheWriterServiceState:
        return self.writer_states[0]

    @property
    def mutation_during_boot(self) -> str:
        if not self.pre_boot.identity_valid:
            return "UNKNOWN"
        if not self.cache_changed:
            return "NO"
        if (
            0 < self.nspawn_start_monotonic_us
            <= self.manager_registration_monotonic_us
            <= self.post_observation_monotonic_us
        ):
            return "YES"
        return "UNKNOWN"

    def writer_before_post_observation(
        self,
        state: _CacheWriterServiceState,
    ) -> str:
        if not state.executed:
            return "NO"
        if (
            state.exec_start_monotonic_us <= 0
            or state.exec_exit_monotonic_us <= 0
            or self.nspawn_start_monotonic_us <= 0
            or self.post_observation_monotonic_us <= 0
        ):
            return "UNKNOWN"
        if (
            self.nspawn_start_monotonic_us
            <= state.exec_start_monotonic_us
            <= state.exec_exit_monotonic_us
            <= self.post_observation_monotonic_us
        ):
            return "YES"
        if state.exec_start_monotonic_us > self.post_observation_monotonic_us:
            return "NO"
        return "UNKNOWN"

    @property
    def writer_classification(self) -> str:
        if not self.pre_boot.identity_valid:
            return "ATTRIBUTION_INSUFFICIENT"
        if not self.cache_changed:
            return "CACHE_NOT_CHANGED"
        if not self.post_boot.identity_valid:
            return "ATTRIBUTION_INSUFFICIENT"
        ldconfig = self.ldconfig_state
        if ldconfig.executed:
            if (
                self.writer_before_post_observation(ldconfig) == "YES"
                and self.mutation_during_boot == "YES"
                and self.post_libpython_entry_count == 0
            ):
                return "LDCONFIG_SERVICE_CONFIRMED"
            return "LDCONFIG_SERVICE_EXECUTED_BUT_CAUSALITY_UNPROVEN"
        if all(not state.executed for state in self.writer_states):
            return "CACHE_CHANGED_WITH_NO_ALLOWLISTED_WRITER"
        return "ATTRIBUTION_INSUFFICIENT"

    @property
    def writer_input_classification(self) -> str:
        if self.writer_classification != "LDCONFIG_SERVICE_CONFIRMED":
            return "WRITER_NOT_CONFIRMED"
        if not self.ldconfig_input.valid:
            return "INPUT_AUTHORITY_UNKNOWN"
        if self.ldconfig_input.includes_runtime:
            return "QUALIFICATION_RUNTIME_INCLUDED"
        return "QUALIFICATION_RUNTIME_NOT_INCLUDED"

    def safe_values(self) -> tuple[tuple[str, str], ...]:
        _validate_boot_cache_attribution(self)
        ldconfig = self.ldconfig_state
        executed_units = tuple(
            state.unit for state in self.writer_states if state.executed
        )
        return (
            (
                "PRE_BOOT_LOADER_CACHE_PRESENT",
                "YES" if self.pre_boot.present else "NO",
            ),
            (
                "PRE_BOOT_LOADER_CACHE_IDENTITY_VALID",
                "PASS" if self.pre_boot.identity_valid else "FAIL",
            ),
            (
                "POST_BOOT_LOADER_CACHE_PRESENT",
                "YES" if self.post_boot.present else "NO",
            ),
            (
                "POST_BOOT_LOADER_CACHE_CHANGED",
                "YES" if self.cache_changed else "NO",
            ),
            ("LDCONFIG_SERVICE_LOAD_STATE", ldconfig.load_state),
            ("LDCONFIG_SERVICE_ACTIVE_STATE", ldconfig.active_state),
            ("LDCONFIG_SERVICE_SUB_STATE", ldconfig.sub_state),
            ("LDCONFIG_SERVICE_RESULT", ldconfig.result),
            (
                "LDCONFIG_SERVICE_EXEC_MAIN_STATUS",
                str(ldconfig.exec_main_status),
            ),
            (
                "LDCONFIG_SERVICE_EXECUTED",
                "YES" if ldconfig.executed else "NO",
            ),
            ("CACHE_WRITER_CANDIDATE_COUNT", str(len(self.writer_states))),
            (
                "CACHE_WRITER_EXECUTED_COUNT",
                str(len(executed_units)),
            ),
            (
                "CACHE_WRITER_EXECUTED_UNITS",
                ",".join(executed_units) or "NONE",
            ),
            (
                "CACHE_MUTATION_OCCURRED_DURING_BOOT",
                self.mutation_during_boot,
            ),
            (
                "LDCONFIG_EXECUTED_BEFORE_POST_BOOT_OBSERVATION",
                self.writer_before_post_observation(ldconfig),
            ),
            ("LDCONFIG_JOURNAL_CLASS", self.ldconfig_journal_class),
            (
                "CONTAINER_LD_SO_CONF_PRESENT",
                "YES" if self.ldconfig_input.main_present else "NO",
            ),
            (
                "CONTAINER_LD_SO_CONF_INCLUDES_QUALIFICATION_RUNTIME",
                "YES" if self.ldconfig_input.main_includes_runtime else "NO",
            ),
            (
                "CONTAINER_LD_SO_CONF_D_FILE_COUNT",
                str(self.ldconfig_input.conf_d_file_count),
            ),
            (
                "CONTAINER_LD_SO_CONF_D_INCLUDES_QUALIFICATION_RUNTIME",
                "YES" if self.ldconfig_input.conf_d_includes_runtime else "NO",
            ),
            (
                "POST_WRITER_CACHE_DIFFERS_FROM_PRE_BOOT",
                "YES" if self.cache_changed else "NO",
            ),
            (
                "POST_WRITER_LIBPYTHON_ENTRY_COUNT",
                str(self.post_libpython_entry_count),
            ),
            ("BOOT_CACHE_WRITER_CLASS", self.writer_classification),
            (
                "BOOT_CACHE_WRITER_INPUT_CLASS",
                self.writer_input_classification,
            ),
        )

    def safe_message(self) -> str:
        return "\n".join(
            f"{name}={value}" for name, value in self.safe_values()
        )


def _validate_cache_writer_state(state: _CacheWriterServiceState) -> None:
    integer_values = (
        state.exec_main_code,
        state.exec_main_status,
        state.inactive_exit_monotonic_us,
        state.active_enter_monotonic_us,
        state.exec_start_monotonic_us,
        state.exec_exit_monotonic_us,
    )
    if (
        state.unit not in _CACHE_WRITER_UNITS
        or state.load_state not in _SYSTEMD_LOAD_STATES
        or state.active_state not in _SYSTEMD_ACTIVE_STATES
        or state.sub_state not in _SYSTEMD_SUB_STATES
        or state.result not in _SYSTEMD_RESULTS
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in integer_values
        )
        or state.exec_main_code > 255
        or state.exec_main_status > 255
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")


def _validate_loader_cache_snapshot(snapshot: _LoaderCacheSnapshot) -> None:
    if (
        any(
            not isinstance(value, bool)
            for value in (snapshot.present, snapshot.regular, snapshot.nonempty)
        )
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in (
                snapshot.owner_uid,
                snapshot.owner_gid,
                snapshot.mode,
                snapshot.size,
            )
        )
        or snapshot.mode > 0o7777
        or (
            snapshot.sha256
            and re.fullmatch(r"[0-9a-f]{64}", snapshot.sha256) is None
        )
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")


def _validate_boot_cache_attribution(
    diagnostic: _BootCacheAttributionDiagnostic,
) -> None:
    _validate_loader_cache_snapshot(diagnostic.pre_boot)
    _validate_loader_cache_snapshot(diagnostic.post_boot)
    if (
        tuple(state.unit for state in diagnostic.writer_states)
        != _CACHE_WRITER_UNITS
        or not isinstance(diagnostic.ldconfig_input, _LdConfigInputAuthority)
        or any(
            not isinstance(value, bool)
            for value in (
                diagnostic.ldconfig_input.main_present,
                diagnostic.ldconfig_input.main_includes_runtime,
                diagnostic.ldconfig_input.conf_d_includes_runtime,
                diagnostic.ldconfig_input.valid,
            )
        )
        or not isinstance(diagnostic.ldconfig_input.conf_d_file_count, int)
        or isinstance(diagnostic.ldconfig_input.conf_d_file_count, bool)
        or not 0 <= diagnostic.ldconfig_input.conf_d_file_count <= 1024
        or diagnostic.ldconfig_journal_class not in _LDCONFIG_JOURNAL_CLASSES
        or diagnostic.writer_classification not in _CACHE_WRITER_CLASSES
        or diagnostic.writer_input_classification
        not in _CACHE_WRITER_INPUT_CLASSES
        or diagnostic.mutation_during_boot not in {"YES", "NO", "UNKNOWN"}
        or diagnostic.writer_before_post_observation(
            diagnostic.ldconfig_state
        ) not in {"YES", "NO", "UNKNOWN"}
        or not isinstance(diagnostic.post_libpython_entry_count, int)
        or isinstance(diagnostic.post_libpython_entry_count, bool)
        or not 0 <= diagnostic.post_libpython_entry_count <= 1024
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in (
                diagnostic.nspawn_start_monotonic_us,
                diagnostic.manager_registration_monotonic_us,
                diagnostic.post_observation_monotonic_us,
            )
        )
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    for state in diagnostic.writer_states:
        _validate_cache_writer_state(state)


def _validate_container_loader_cache_diagnostic(
    diagnostic: _ContainerLoaderCacheDiagnostic,
) -> None:
    boolean_values = (
        diagnostic.host_cache_present,
        diagnostic.host_cache_sha256_valid,
        diagnostic.container_cache_present,
        diagnostic.container_cache_regular,
        diagnostic.container_cache_bytes_match_host,
        diagnostic.cache_target_visible,
        diagnostic.cache_target_identity_match,
        diagnostic.base_python_visible,
        diagnostic.libpython_visible,
    )
    if (
        any(not isinstance(value, bool) for value in boolean_values)
        or not isinstance(diagnostic.libpython_entry_count, int)
        or isinstance(diagnostic.libpython_entry_count, bool)
        or not 0 <= diagnostic.libpython_entry_count <= 1024
        or any(
            value not in _LOADER_RESULTS
            for value in (
                diagnostic.base_loader_direct,
                diagnostic.candidate_loader_direct,
                diagnostic.base_loader_default_cache,
                diagnostic.base_loader_inhibit_cache,
            )
        )
        or diagnostic.classification not in _CONTAINER_LOADER_CACHE_CLASSES
    ):
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")


def _container_loader_cache_classification(
    diagnostic: _ContainerLoaderCacheDiagnostic,
) -> str:
    if (
        not diagnostic.host_cache_present
        or not diagnostic.host_cache_sha256_valid
    ):
        return "LOADER_CACHE_VISIBILITY_UNCLASSIFIED"
    if (
        not diagnostic.container_cache_present
        or not diagnostic.container_cache_regular
    ):
        return "CONTAINER_CACHE_FILE_MISSING"
    if not diagnostic.container_cache_bytes_match_host:
        return "CONTAINER_CACHE_BYTES_MISMATCH"
    if diagnostic.libpython_entry_count == 0:
        return "CONTAINER_CACHE_LIBPYTHON_ENTRY_MISSING"
    if diagnostic.libpython_entry_count != 1:
        return "CONTAINER_CACHE_LIBPYTHON_ENTRY_AMBIGUOUS"
    if not diagnostic.cache_target_visible:
        return "CONTAINER_CACHE_TARGET_NOT_VISIBLE"
    if not diagnostic.cache_target_identity_match:
        return "CONTAINER_CACHE_TARGET_IDENTITY_MISMATCH"
    if not diagnostic.base_python_visible or not diagnostic.libpython_visible:
        return "QUALIFICATION_RUNTIME_BIND_NOT_VISIBLE"
    if (
        diagnostic.base_loader_default_cache == "NOT_FOUND"
        or diagnostic.candidate_loader_direct == "NOT_FOUND"
    ):
        return "LOADER_NOT_RESOLVING_VALID_CACHE_ENTRY"
    if (
        diagnostic.base_loader_direct == "RESOLVED"
        and diagnostic.candidate_loader_direct == "RESOLVED"
        and diagnostic.base_loader_default_cache == "RESOLVED"
        and diagnostic.base_loader_inhibit_cache == "NOT_FOUND"
    ):
        return "LOADER_CACHE_EFFECTIVE"
    return "LOADER_CACHE_VISIBILITY_UNCLASSIFIED"


@dataclass(frozen=True)
class _PyVenvAuthorityDiagnostic:
    home_class: str
    executable_class: str
    tmp_reference: bool
    run_reference: bool
    rehearsal_root_reference: bool


@dataclass(frozen=True)
class _InterpreterFailureDiagnostic:
    candidate_probe_rc: int
    base_probe_rc: int
    sandbox_probe_rc: int
    candidate_elf: _ElfDependencyDiagnostic
    base_elf: _ElfDependencyDiagnostic
    pyvenv: _PyVenvAuthorityDiagnostic
    physical_reference_count: int
    logical_reference_count: int
    classification: str

    @classmethod
    def unavailable(cls) -> "_InterpreterFailureDiagnostic":
        empty_elf = _ElfDependencyDiagnostic(False, False, ())
        empty_venv = _PyVenvAuthorityDiagnostic(
            "ABSENT", "ABSENT", False, False, False,
        )
        return cls(
            -1, -1, -1, empty_elf, empty_elf, empty_venv, 0, 0,
            "INTERPRETER_FAILURE_UNCLASSIFIED",
        )

    def safe_values(self) -> tuple[tuple[str, str], ...]:
        if (
            self.classification not in _INTERPRETER_FAILURE_CLASSES
            or self.pyvenv.home_class not in _PATH_CLASSES
            or self.pyvenv.executable_class not in _PATH_CLASSES
            or any(
                not isinstance(value, bool)
                for value in (
                    self.candidate_elf.dynamic,
                    self.candidate_elf.interpreter_present,
                    self.base_elf.dynamic,
                    self.base_elf.interpreter_present,
                    self.pyvenv.tmp_reference,
                    self.pyvenv.run_reference,
                    self.pyvenv.rehearsal_root_reference,
                )
            )
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not -255 <= value <= 255
                for value in (
                    self.candidate_probe_rc,
                    self.base_probe_rc,
                    self.sandbox_probe_rc,
                )
            )
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in (
                    self.physical_reference_count,
                    self.logical_reference_count,
                )
            )
            or any(
                _LIBRARY_BASENAME.fullmatch(name) is None
                for name in (
                    *self.candidate_elf.missing_libraries,
                    *self.base_elf.missing_libraries,
                )
            )
            or self.candidate_elf.missing_libraries
            != tuple(sorted(set(self.candidate_elf.missing_libraries)))
            or self.base_elf.missing_libraries
            != tuple(sorted(set(self.base_elf.missing_libraries)))
        ):
            raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED")
        candidate_missing = self.candidate_elf.missing_libraries
        base_missing = self.base_elf.missing_libraries
        return (
            ("CONTAINER_CANDIDATE_PYTHON_PROBE_RC", str(self.candidate_probe_rc)),
            ("CONTAINER_BASE_PYTHON_PROBE_RC", str(self.base_probe_rc)),
            (
                "SYSTEMD_SANDBOX_CANDIDATE_PYTHON_PROBE_RC",
                str(self.sandbox_probe_rc),
            ),
            (
                "CANDIDATE_PYTHON_ELF_DYNAMIC",
                "YES" if self.candidate_elf.dynamic else "NO",
            ),
            (
                "CANDIDATE_PYTHON_INTERPRETER_PRESENT",
                "YES" if self.candidate_elf.interpreter_present else "NO",
            ),
            (
                "CANDIDATE_PYTHON_MISSING_LIBRARY_COUNT",
                str(len(candidate_missing)),
            ),
            (
                "CANDIDATE_PYTHON_MISSING_LIBRARIES",
                ",".join(candidate_missing) or "NONE",
            ),
            ("BASE_PYTHON_MISSING_LIBRARY_COUNT", str(len(base_missing))),
            (
                "BASE_PYTHON_MISSING_LIBRARIES",
                ",".join(base_missing) or "NONE",
            ),
            ("PYVENV_HOME_CLASS", self.pyvenv.home_class),
            ("PYVENV_EXECUTABLE_CLASS", self.pyvenv.executable_class),
            (
                "PYVENV_TMP_REFERENCE",
                "YES" if self.pyvenv.tmp_reference else "NO",
            ),
            (
                "PYVENV_RUN_REFERENCE",
                "YES" if self.pyvenv.run_reference else "NO",
            ),
            (
                "PYVENV_REHEARSAL_ROOT_REFERENCE",
                "YES" if self.pyvenv.rehearsal_root_reference else "NO",
            ),
            (
                "CANDIDATE_RUNTIME_PHYSICAL_REHEARSAL_PATH_REFERENCE_COUNT",
                str(self.physical_reference_count),
            ),
            (
                "CANDIDATE_RUNTIME_LOGICAL_RELEASE_PATH_REFERENCE_COUNT",
                str(self.logical_reference_count),
            ),
            ("INTERPRETER_FAILURE_CLASS", self.classification),
        )


@dataclass(frozen=True)
class _ServiceFailureDiagnostic:
    journal: _RehearsalFailureJournalDiagnostic
    service_state: dict[str, str]
    pipeline_runs: _PipelineRunFailureDiagnostic
    provider_counts: dict[str, int]
    classification: str
    interpreter: _InterpreterFailureDiagnostic | None = None

    def safe_message(self) -> str:
        run = self.pipeline_runs
        values: tuple[tuple[str, str], ...] = (
            ("WP7_LAST_REHEARSAL_EVENT", self.journal.last_event),
            ("WP7_VERIFIED_PIPELINE_COUNT", str(len(self.journal.verified_pipelines))),
            (
                "PIPELINES_VERIFIED_BEFORE_FAILURE",
                ",".join(self.journal.verified_pipelines) or "NONE",
            ),
            ("FAILED_PIPELINE_KEY", self.journal.failed_pipeline_key),
            ("FAILED_SERVICE_UNIT", self.journal.failed_service_unit),
            (
                "SYSTEMCTL_START_RETURN_CODE",
                str(self.journal.systemctl_start_return_code),
            ),
            ("FAILED_SERVICE_LOAD_STATE", self.service_state["LoadState"]),
            ("FAILED_SERVICE_ACTIVE_STATE", self.service_state["ActiveState"]),
            ("FAILED_SERVICE_SUB_STATE", self.service_state["SubState"]),
            ("FAILED_SERVICE_RESULT", self.service_state["Result"]),
            (
                "FAILED_SERVICE_EXEC_MAIN_STATUS",
                self.service_state["ExecMainStatus"],
            ),
            ("FAILED_SERVICE_EXEC_MAIN_CODE", self.service_state["ExecMainCode"]),
            ("FAILED_SERVICE_STATUS_ERRNO", self.service_state["StatusErrno"]),
            ("FRESH_PIPELINE_RUN_COUNT", str(run.total)),
            ("FRESH_COMPLETED_PIPELINE_RUN_COUNT", str(run.completed)),
            ("FRESH_FAILED_PIPELINE_RUN_COUNT", str(run.failed)),
            (
                "FAILED_PIPELINE_RUN_PRESENT",
                "YES" if run.failed_pipeline_present else "NO",
            ),
            (
                "FAILED_PIPELINE_RUN_STATUS",
                run.failed_pipeline_status or "NONE",
            ),
            (
                "FAILED_PIPELINE_RUN_FINISHED",
                (
                    "YES" if run.failed_pipeline_finished
                    else "NO" if run.failed_pipeline_finished is False
                    else "NONE"
                ),
            ),
            (
                "FAILED_PIPELINE_RUN_ERROR_CODE",
                run.failed_pipeline_error_code or "NONE",
            ),
            (
                "NEXTCLOUD_PROPFIND_CALL_COUNT",
                str(self.provider_counts["nextcloud-propfind"]),
            ),
            (
                "NEXTCLOUD_CONTENT_CALL_COUNT",
                str(self.provider_counts["nextcloud-content"]),
            ),
            (
                "IMMICH_ACCOUNT_CALL_COUNT",
                str(self.provider_counts["immich-account"]),
            ),
            (
                "IMMICH_OCR_CALL_COUNT",
                str(self.provider_counts["immich-ocr"]),
            ),
            ("SERVICE_FAILURE_CLASS", self.classification),
        )
        if self.interpreter is not None:
            values += self.interpreter.safe_values()
        return "\n".join(f"{name}={value}" for name, value in values)


def _environment() -> tuple[Path, Path, Path, Path, str]:
    names = (
        "PDI_P3D_WP7_BUNDLE",
        "PDI_P3D_WP7_DIGESTS",
        "PDI_P3D_WP7_REHEARSAL_ROOT",
        "PDI_P3D_WP7_SYSTEM_PYTHON",
        "PDI_P3D_WP7_CANDIDATE_SHA",
    )
    if any(not os.environ.get(name) for name in names):
        pytest.skip("dedicated WP7 disposable real-systemd qualification only")
    return (
        Path(os.environ[names[0]]),
        Path(os.environ[names[1]]),
        Path(os.environ[names[2]]),
        Path(os.environ[names[3]]),
        os.environ[names[4]],
    )


def _validate_qualification_runtime_root(
    runtime_root: Path,
    *,
    resolved: Path,
    runtime_info: os.stat_result,
    run_info: os.stat_result,
) -> Path:
    prefix = "pdi-p3d-wp7-runtime."
    suffix = runtime_root.name.removeprefix(prefix)
    if (
        not runtime_root.is_absolute()
        or runtime_root.parent != Path("/run")
        or not runtime_root.name.startswith(prefix)
        or not suffix
        or not suffix.isalnum()
        or resolved != runtime_root
        or not stat.S_ISDIR(runtime_info.st_mode)
        or stat.S_ISLNK(runtime_info.st_mode)
        or runtime_info.st_uid != 0
        or runtime_info.st_gid != 0
        or runtime_info.st_mode & 0o022
        or not stat.S_ISDIR(run_info.st_mode)
        or stat.S_ISLNK(run_info.st_mode)
        or run_info.st_uid != 0
        or run_info.st_gid != 0
        or run_info.st_mode & 0o022
    ):
        raise AssertionError("QUALIFICATION_RUNTIME_INVALID")
    return resolved


def _verify_qualification_runtime_root(system_python: Path) -> Path:
    runtime_root = system_python.parent.parent
    if system_python != runtime_root / "bin/python":
        raise AssertionError("QUALIFICATION_RUNTIME_INVALID")
    try:
        resolved = runtime_root.resolve(strict=True)
        runtime_info = runtime_root.lstat()
        run_info = Path("/run").lstat()
        python_info = system_python.lstat()
    except OSError as exc:
        raise AssertionError("QUALIFICATION_RUNTIME_INVALID") from exc
    _validate_qualification_runtime_root(
        runtime_root,
        resolved=resolved,
        runtime_info=runtime_info,
        run_info=run_info,
    )
    if (
        not stat.S_ISREG(python_info.st_mode)
        or stat.S_ISLNK(python_info.st_mode)
        or python_info.st_uid != 0
        or python_info.st_gid != 0
        or python_info.st_mode & 0o022
        or not python_info.st_mode & stat.S_IXUSR
    ):
        raise AssertionError("QUALIFICATION_RUNTIME_INVALID")
    return runtime_root


def _validate_trusted_libpython_candidate(
    runtime_root: Path,
    candidate: Path,
) -> _TrustedLibpython:
    try:
        runtime_resolved = runtime_root.resolve(strict=True)
        candidate_resolved = candidate.resolve(strict=True)
        candidate_info = candidate.lstat()
    except (OSError, RuntimeError) as exc:
        raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID") from exc
    if (
        runtime_resolved != runtime_root
        or candidate_resolved != candidate
        or candidate.name != _LIBPYTHON_SONAME
        or runtime_root not in candidate.parents
        or not stat.S_ISREG(candidate_info.st_mode)
        or stat.S_ISLNK(candidate_info.st_mode)
        or candidate_info.st_uid != 0
        or candidate_info.st_gid != 0
        or candidate_info.st_mode & 0o022
        or candidate_info.st_size <= 0
    ):
        raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID")
    parent = candidate.parent
    while True:
        try:
            parent_info = parent.lstat()
            parent_resolved = parent.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID") from exc
        if (
            parent_resolved != parent
            or not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_gid != 0
            or parent_info.st_mode & 0o022
        ):
            raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID")
        if parent == runtime_root:
            break
        if runtime_root not in parent.parents:
            raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID")
        parent = parent.parent
    try:
        digest = sha256(candidate.read_bytes()).hexdigest()
    except OSError as exc:
        raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID") from exc
    return _TrustedLibpython(candidate, candidate.parent, digest)


def _discover_trusted_libpython(runtime_root: Path) -> _TrustedLibpython:
    try:
        candidates = tuple(sorted(runtime_root.rglob(_LIBPYTHON_SONAME)))
    except OSError as exc:
        raise AssertionError("QUALIFICATION_LIBPYTHON_INVALID") from exc
    if len(candidates) != 1:
        raise AssertionError("QUALIFICATION_LIBPYTHON_CARDINALITY_INVALID")
    return _validate_trusted_libpython_candidate(runtime_root, candidates[0])


def _validate_trusted_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise AssertionError("QUALIFICATION_LDCONFIG_INVALID")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise AssertionError("QUALIFICATION_LDCONFIG_INVALID") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o022
        or not info.st_mode & stat.S_IXUSR
    ):
        raise AssertionError("QUALIFICATION_LDCONFIG_INVALID")
    parent = resolved.parent
    while True:
        try:
            parent_info = parent.lstat()
        except OSError as exc:
            raise AssertionError("QUALIFICATION_LDCONFIG_INVALID") from exc
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_gid != 0
            or parent_info.st_mode & 0o022
        ):
            raise AssertionError("QUALIFICATION_LDCONFIG_INVALID")
        if parent == Path("/"):
            break
        parent = parent.parent
    return resolved


def _loader_cache_build_command(
    root: Path,
    configuration: Path,
) -> tuple[str, ...]:
    return (
        str(LDCONFIG),
        "-C", str(root / "etc/ld.so.cache"),
        "-f", str(configuration),
        "-X",
        "--ignore-aux-cache",
    )


def _loader_cache_inspect_command(root: Path) -> tuple[str, ...]:
    return (str(LDCONFIG), "-p", "-C", str(root / "etc/ld.so.cache"))


def _validate_loader_cache_listing(
    payload: str,
    trusted: _TrustedLibpython,
) -> None:
    if (
        len(payload.encode("utf-8")) > _LOADER_CACHE_OUTPUT_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
    ):
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    matches: list[Path] = []
    expression = re.compile(
        rf"\s*{re.escape(_LIBPYTHON_SONAME)}\s+"
        r"\([^()\r\n]+\)\s+=>\s+(/[A-Za-z0-9_./+-]+)\s*"
    )
    for line in payload.splitlines():
        if _LIBPYTHON_SONAME not in line:
            continue
        matched = expression.fullmatch(line)
        if matched is None:
            raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
        matches.append(Path(matched.group(1)))
    if len(matches) != 1 or matches[0] != trusted.path:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")


def _assert_loader_cache_file(cache: Path) -> None:
    try:
        info = cache.lstat()
        resolved = cache.resolve(strict=True)
        parent_info = cache.parent.lstat()
    except (OSError, RuntimeError) as exc:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID") from exc
    if (
        resolved != cache
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o644
        or info.st_size <= 0
        or not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_gid != 0
        or parent_info.st_mode & 0o022
    ):
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")


def _materialize_disposable_loader_cache(
    root: Path,
    runtime_root: Path,
    *,
    runner=subprocess.run,
) -> _TrustedLibpython:
    trusted = _discover_trusted_libpython(runtime_root)
    _validate_trusted_executable(LDCONFIG)
    cache = root / "etc/ld.so.cache"
    configuration = root / "var/lib/pdi-p3d/ld.so.conf.wp7"
    if (
        cache.exists()
        or cache.is_symlink()
        or configuration.exists()
        or configuration.is_symlink()
    ):
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    descriptor = os.open(
        configuration,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        payload = f"{trusted.directory}\n".encode("utf-8")
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        generated = runner(
            _loader_cache_build_command(root, configuration),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
    finally:
        configuration.unlink(missing_ok=True)
    if generated.returncode != 0 or generated.stdout or generated.stderr:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    _assert_loader_cache_file(cache)
    inspected = runner(
        _loader_cache_inspect_command(root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        shell=False,
    )
    if inspected.returncode != 0 or inspected.stderr:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    _validate_loader_cache_listing(inspected.stdout, trusted)
    if _discover_trusted_libpython(runtime_root) != trusted:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    return trusted


def _host_loader_cache_sha256(root: Path) -> str:
    cache = root / "etc/ld.so.cache"
    _assert_loader_cache_file(cache)
    try:
        digest = sha256(cache.read_bytes()).hexdigest()
    except OSError as exc:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID") from exc
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    return digest


def _host_loader_cache_snapshot(root: Path) -> _LoaderCacheSnapshot:
    cache = root / "etc/ld.so.cache"
    _assert_loader_cache_file(cache)
    try:
        info = cache.lstat()
        digest = sha256(cache.read_bytes()).hexdigest()
    except OSError as exc:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID") from exc
    snapshot = _LoaderCacheSnapshot(
        True,
        stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
        info.st_size > 0,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_size,
        digest,
    )
    _validate_loader_cache_snapshot(snapshot)
    if not snapshot.identity_valid:
        raise AssertionError("QUALIFICATION_LOADER_CACHE_INVALID")
    return snapshot


def _assert_candidate_venv_runtime_authority(
    release: Path,
    *,
    system_python: Path,
    runtime_root: Path,
) -> None:
    candidate_python = release / ".venv/bin/python"
    config = release / ".venv/pyvenv.cfg"
    try:
        candidate_resolved = candidate_python.resolve(strict=True)
        candidate_info = candidate_python.lstat()
        values = {
            key.strip(): value.strip()
            for line in config.read_text(encoding="utf-8").splitlines()
            if "=" in line
            for key, value in (line.split("=", 1),)
        }
        home = Path(values["home"])
        executable = Path(values["executable"])
        command_python = Path(values["command"].split(" -m venv", 1)[0])
        resolved_refs = tuple(
            reference.resolve(strict=True)
            for reference in (home, executable, command_python)
        )
    except (KeyError, OSError, ValueError) as exc:
        raise AssertionError("CANDIDATE_RUNTIME_AUTHORITY_INVALID") from exc
    release_resolved = release.resolve(strict=True)
    runtime_resolved = runtime_root.resolve(strict=True)
    if (
        candidate_resolved.parent.parent.parent != release_resolved
        or not stat.S_ISREG(candidate_info.st_mode)
        or stat.S_ISLNK(candidate_info.st_mode)
        or candidate_info.st_uid != 0
        or candidate_info.st_gid != 0
        or candidate_info.st_mode & 0o022
        or not candidate_info.st_mode & stat.S_IXUSR
        or sha256(candidate_python.read_bytes()).digest()
        != sha256(system_python.read_bytes()).digest()
        or any(not reference.is_absolute() for reference in (
            home, executable, command_python,
        ))
        or any(
            reference != runtime_resolved
            and runtime_resolved not in reference.parents
            for reference in resolved_refs
        )
        or command_python.resolve(strict=True) != system_python.resolve(strict=True)
        or any(
            forbidden == reference or forbidden in reference.parents
            for forbidden in (Path("/tmp"), Path("/var/tmp"))
            for reference in resolved_refs
        )
    ):
        raise AssertionError("CANDIDATE_RUNTIME_AUTHORITY_INVALID")


def _docx(content: str) -> bytes:
    output = BytesIO()
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
        f"{content}"
        "</w:t></w:r></w:p></w:body></w:document>"
    ).encode()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", document)
    return output.getvalue()


class _ProviderFixtureHandler(BaseHTTPRequestHandler):
    text_content = b"Synthetic scoped Nextcloud text\n"
    document_content = _docx("Synthetic scoped Nextcloud document")
    nextcloud_authorization = "Basic " + b64encode(
        b"synthetic:synthetic-nextcloud-password"
    ).decode()
    immich_key = "synthetic-immich-api-key"
    calls: list[str] = []

    def log_message(self, format, *args):  # noqa: A002 - stdlib override
        return

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_PROPFIND(self):  # noqa: N802 - HTTP handler API
        if self.headers.get("Authorization") != self.nextcloud_authorization:
            self._send(401, b"", "text/plain")
            return
        self.calls.append("nextcloud-propfind")
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
            '<d:response><d:href>/remote.php/dav/files/synthetic/</d:href>'
            '<d:propstat><d:prop><oc:id>synthetic-root</oc:id>'
            '<oc:fileid>synthetic-root</oc:fileid>'
            '<d:resourcetype><d:collection/></d:resourcetype>'
            '</d:prop></d:propstat></d:response></d:multistatus>'
        ).encode()
        self._send(207, payload, "application/xml")

    def do_GET(self):  # noqa: N802 - HTTP handler API
        if self.path.startswith("/content/"):
            if self.headers.get("Authorization") != self.nextcloud_authorization:
                self._send(401, b"", "text/plain")
                return
            self.calls.append("nextcloud-content")
            payload = (
                self.text_content
                if self.path == "/content/notes.md"
                else self.document_content
            )
            self._send(200, payload, "application/octet-stream")
            return
        if self.headers.get("x-api-key") != self.immich_key:
            self._send(401, b"{}", "application/json")
            return
        if self.path == "/api/users/me":
            self.calls.append("immich-account")
            self._send(
                200,
                json.dumps({"id": IMMICH_ACCOUNT_ID}).encode(),
                "application/json",
            )
            return
        if self.path == f"/api/assets/{IMMICH_ACCOUNT_ID}/ocr":
            self.calls.append("immich-ocr")
            self._send(
                200,
                json.dumps([{"text": "Synthetic OCR evidence"}]).encode(),
                "application/json",
            )
            return
        self._send(404, b"{}", "application/json")


@contextmanager
def _provider_fixture():
    _ProviderFixtureHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], _ProviderFixtureHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _read_failure_journal(
    root: Path,
    operation_id: str,
    *,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> _RehearsalFailureJournalDiagnostic:
    authority = root / "var/lib/pdi-p3d/rehearsal" / operation_id
    try:
        root_info = authority.lstat()
        if (
            stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != owner_uid
            or root_info.st_gid != owner_gid
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise ValueError
        files = sorted(authority.glob("journal-*.json"))
        if not files or set(authority.iterdir()) != set(files):
            raise ValueError
        events: list[tuple[str, dict[str, object]]] = []
        for expected_sequence, path in enumerate(files, start=1):
            if path.name != f"journal-{expected_sequence:06d}.json":
                raise ValueError
            info = path.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != owner_uid
                or info.st_gid != owner_gid
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError
            value = json.loads(path.read_text(encoding="utf-8"))
            if (
                set(value) != {
                    "version", "sequence", "rehearsal_operation_id",
                    "event", "timestamp", "evidence",
                }
                or value["version"] != 1
                or value["sequence"] != expected_sequence
                or value["rehearsal_operation_id"] != operation_id
                or not isinstance(value["event"], str)
                or not isinstance(value["evidence"], dict)
            ):
                raise ValueError
            events.append((value["event"], value["evidence"]))

        required_prefix = (
            "NEW", "PREPARATION_VERIFIED", "SYSTEMD_MANAGER_VERIFIED",
            "CANDIDATE_PROMOTED", "SYSTEMD_RELOADED", "SERVICES_VERIFIED",
        )
        names = tuple(event for event, _ in events)
        if (
            len(events) < len(required_prefix) + 1
            or names[:len(required_prefix)] != required_prefix
            or names[-1] != "FAILED"
            or any(
                name != "PIPELINE_VERIFIED"
                for name in names[len(required_prefix):-1]
            )
        ):
            raise ValueError
        verified = tuple(
            str(evidence.get("pipeline_key"))
            for name, evidence in events
            if name == "PIPELINE_VERIFIED"
        )
        if (
            len(verified) >= len(CANONICAL_PIPELINES)
            or verified != CANONICAL_PIPELINES[:len(verified)]
        ):
            raise ValueError
        failed_pipeline = CANONICAL_PIPELINES[len(verified)]
        failed_unit = SERVICE_UNITS[failed_pipeline]
        failed_evidence = events[-1][1]
        start_return_code = failed_evidence.get("last_start_return_code")
        if (
            failed_evidence.get("failure_code") != "P3D_REHEARSAL_SERVICE_FAILED"
            or failed_evidence.get("last_start_pipeline_key") != failed_pipeline
            or failed_evidence.get("last_start_unit") != failed_unit
            or not isinstance(start_return_code, int)
            or isinstance(start_return_code, bool)
            or not 0 <= start_return_code <= 255
        ):
            raise ValueError
        service_state = {
            "LoadState": failed_evidence.get("service_load_state"),
            "ActiveState": failed_evidence.get("service_active_state"),
            "SubState": failed_evidence.get("service_sub_state"),
            "Result": failed_evidence.get("service_result"),
            "ExecMainStatus": failed_evidence.get("service_exec_main_status"),
            "ExecMainCode": failed_evidence.get("service_exec_main_code"),
            "StatusErrno": failed_evidence.get("service_status_errno"),
        }
        MachineSystemdBackend.validate_service_failure_state(service_state)
        return _RehearsalFailureJournalDiagnostic(
            names[-2], verified, failed_pipeline, failed_unit, start_return_code,
            service_state,
        )
    except (
        OSError, ValueError, TypeError, json.JSONDecodeError,
        DisposableRehearsalError,
    ):
        raise AssertionError("WP7_FAILURE_JOURNAL_DIAGNOSTIC_REJECTED") from None


def _read_failed_service_state(
    machine: str,
    pipeline_key: str,
    *,
    runner=subprocess.run,
) -> dict[str, str]:
    backend = MachineSystemdBackend(machine, runner=runner)
    return backend.show_service_failure_state(pipeline_key)


def _read_pipeline_run_failure(
    engine,
    boundary,
    failed_pipeline: str,
) -> _PipelineRunFailureDiagnostic:
    if failed_pipeline not in CANONICAL_PIPELINES:
        raise AssertionError("WP7_PIPELINE_RUN_DIAGNOSTIC_REJECTED")
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT pipeline_key,status,finished_at IS NOT NULL,error_code "
            "FROM pipeline_runs WHERE started_at > :after "
            "ORDER BY started_at,id"
        ), {"after": boundary}).all()
    statuses = {"running", "completed", "failed"}
    error_codes = {None, "execution_failed", "interrupted_previous_run"}
    if any(
        row[0] not in CANONICAL_PIPELINES
        or row[1] not in statuses
        or not isinstance(row[2], bool)
        or row[3] not in error_codes
        for row in rows
    ):
        raise AssertionError("WP7_PIPELINE_RUN_DIAGNOSTIC_REJECTED")
    selected = [row for row in rows if row[0] == failed_pipeline]
    if len(selected) > 1:
        raise AssertionError("WP7_PIPELINE_RUN_DIAGNOSTIC_REJECTED")
    row = selected[0] if selected else None
    return _PipelineRunFailureDiagnostic(
        len(rows),
        sum(value[1] == "completed" for value in rows),
        sum(value[1] == "failed" for value in rows),
        row is not None,
        None if row is None else row[1],
        None if row is None else row[2],
        None if row is None else row[3],
    )


def _provider_call_counts(calls: tuple[str, ...]) -> dict[str, int]:
    allowed = (
        "nextcloud-propfind", "nextcloud-content",
        "immich-account", "immich-ocr",
    )
    if any(value not in allowed for value in calls):
        raise AssertionError("WP7_PROVIDER_DIAGNOSTIC_REJECTED")
    return {value: calls.count(value) for value in allowed}


def _safe_return_code(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not -255 <= value <= 255
    ):
        raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED")
    return value


def _namespace_command(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    command: tuple[str, ...],
) -> tuple[str, ...]:
    if (
        not isinstance(leader, int)
        or isinstance(leader, bool)
        or leader <= 1
        or runtime_uid <= 0
        or runtime_gid <= 0
        or not command
        or any(not isinstance(item, str) or not item for item in command)
    ):
        raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED")
    return (
        str(NSENTER), "--target", str(leader), "--mount", "--root", "--wd",
        "--", str(SETPRIV), f"--reuid={runtime_uid}",
        f"--regid={runtime_gid}", "--clear-groups", "--no-new-privs", "--",
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "PYTHONDONTWRITEBYTECODE=1", "PYTHONNOUSERSITE=1", *command,
    )


def _container_python_probe(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    python: Path,
    *,
    runner=subprocess.run,
) -> int:
    command = _namespace_command(
        leader,
        runtime_uid,
        runtime_gid,
        (str(python), "-c", "import sys; raise SystemExit(0)"),
    )
    try:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return -1
    return _safe_return_code(result.returncode)


def _systemd_sandbox_python_probe(
    machine: str,
    operation_id: str,
    *,
    runner=subprocess.run,
) -> int:
    try:
        suffix = UUID(operation_id).hex[:16]
    except (TypeError, ValueError, AttributeError):
        raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED") from None
    if re.fullmatch(r"pdi-p3d-[0-9a-f]{16}", machine) is None:
        raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED")
    unit = f"pdi-p3d-wp7-python-probe-{suffix}.service"
    command = (
        str(SYSTEMD_RUN), f"--machine={machine}", "--quiet", "--wait",
        "--collect", f"--unit={unit}", "--uid=pdi", "--gid=pdi",
        "--working-directory=/opt/pdi/current",
        "--property=Type=oneshot",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=ReadWritePaths=/run/lock",
        "--setenv=PYTHONDONTWRITEBYTECODE=1",
        "--setenv=PYTHONPATH=/opt/pdi/current/src",
        "--", "/opt/pdi/current/.venv/bin/python", "-c",
        "raise SystemExit(0)",
    )
    result_code = -1
    try:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
        result_code = _safe_return_code(result.returncode)
    except (OSError, subprocess.TimeoutExpired):
        result_code = -1
    finally:
        for action in ("stop", "reset-failed"):
            try:
                runner(
                    (
                        str(SYSTEMCTL), f"--machine={machine}", "--no-pager",
                        action, unit,
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            cleaned = runner(
                (
                    str(SYSTEMCTL), f"--machine={machine}", "--no-pager",
                    "show", unit, "--property=LoadState", "--value",
                ),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                shell=False,
            )
            if cleaned.returncode != 0 or cleaned.stdout.strip() != "not-found":
                result_code = -1
        except (OSError, subprocess.TimeoutExpired, AttributeError):
            result_code = -1
    return result_code


def _namespace_capture(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    command: tuple[str, ...],
    *,
    runner=subprocess.run,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            _namespace_command(leader, runtime_uid, runtime_gid, command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED") from exc
    if len(result.stdout) + len(result.stderr) > _DIAGNOSTIC_LIMIT:
        raise AssertionError("INTERPRETER_DIAGNOSTIC_REJECTED")
    _safe_return_code(result.returncode)
    return result


def _validate_diagnostic_namespace_path(path: Path) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or ".." in path.parts
        or str(path) != path.as_posix()
        or any(ord(char) < 33 or ord(char) > 126 for char in str(path))
    ):
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    return path


def _namespace_test_path(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    flag: str,
    path: Path,
    *,
    capture=_namespace_capture,
) -> bool:
    if flag not in {"-e", "-f", "-L", "-s"}:
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    selected = _validate_diagnostic_namespace_path(path)
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(TEST), flag, str(selected)),
    )
    if result.returncode not in {0, 1} or result.stdout or result.stderr:
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    return result.returncode == 0


def _namespace_regular_nonempty_file(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    path: Path,
    *,
    capture=_namespace_capture,
) -> tuple[bool, bool]:
    present = _namespace_test_path(
        leader, runtime_uid, runtime_gid, "-e", path, capture=capture,
    )
    regular = _namespace_test_path(
        leader, runtime_uid, runtime_gid, "-f", path, capture=capture,
    )
    symlink = _namespace_test_path(
        leader, runtime_uid, runtime_gid, "-L", path, capture=capture,
    )
    nonempty = _namespace_test_path(
        leader, runtime_uid, runtime_gid, "-s", path, capture=capture,
    )
    return present, present and regular and not symlink and nonempty


def _namespace_file_sha256(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    path: Path,
    *,
    capture=_namespace_capture,
) -> str:
    selected = _validate_diagnostic_namespace_path(path)
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(SHA256SUM), str(selected)),
    )
    matched = re.fullmatch(
        rf"([0-9a-f]{{64}})  {re.escape(str(selected))}\n?",
        result.stdout,
    )
    if result.returncode != 0 or result.stderr or matched is None:
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    return matched.group(1)


def _namespace_loader_cache_snapshot(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    *,
    capture=_namespace_capture,
) -> _LoaderCacheSnapshot:
    cache = Path("/etc/ld.so.cache")
    present, regular_nonempty = _namespace_regular_nonempty_file(
        leader,
        runtime_uid,
        runtime_gid,
        cache,
        capture=capture,
    )
    if not present:
        snapshot = _LoaderCacheSnapshot(False, False, False, 0, 0, 0, 0, "")
        _validate_loader_cache_snapshot(snapshot)
        return snapshot
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(STAT), "--format=%s:%u:%g:%a:%F", "--", str(cache)),
    )
    matched = re.fullmatch(
        r"([0-9]+):([0-9]+):([0-9]+):([0-7]{3,4}):regular file\n?",
        result.stdout,
    )
    if result.returncode != 0 or result.stderr or matched is None:
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    size, owner_uid, owner_gid = (int(matched.group(i)) for i in range(1, 4))
    mode = int(matched.group(4), 8)
    digest = _namespace_file_sha256(
        leader,
        runtime_uid,
        runtime_gid,
        cache,
        capture=capture,
    )
    snapshot = _LoaderCacheSnapshot(
        True,
        regular_nonempty,
        size > 0,
        owner_uid,
        owner_gid,
        mode,
        size,
        digest,
    )
    _validate_loader_cache_snapshot(snapshot)
    return snapshot


def _parse_systemd_monotonic(value: str) -> int:
    if value == "":
        return 0
    if re.fullmatch(r"[0-9]{1,20}", value) is None:
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    return int(value)


def _parse_systemd_status(value: str) -> int:
    if value == "":
        return 0
    if re.fullmatch(r"[0-9]{1,3}", value) is None:
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    result = int(value)
    if result > 255:
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    return result


def _cache_writer_service_state(
    machine: str,
    unit: str,
    *,
    runner=subprocess.run,
) -> _CacheWriterServiceState:
    if (
        re.fullmatch(r"pdi-p3d-[0-9a-f]{16}", machine) is None
        or unit not in _CACHE_WRITER_UNITS
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    command = (
        str(SYSTEMCTL),
        f"--machine={machine}",
        "--no-pager",
        "show",
        unit,
        *(f"--property={name}" for name in _CACHE_WRITER_PROPERTIES),
    )
    try:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssertionError(
            "BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED"
        ) from exc
    payload = result.stdout + "\n" + result.stderr
    if (
        len(payload.encode("utf-8")) > _DIAGNOSTIC_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
        or any(marker in payload for marker in _PROTECTED_SECRET_MARKERS)
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if (
            separator != "="
            or name not in _CACHE_WRITER_PROPERTIES
            or name in values
        ):
            raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
        values[name] = value
    if values.get("LoadState") == "not-found":
        allowed_stderr = {"", f"Unit {unit} could not be found.\n"}
        if result.returncode not in {0, 4} or result.stderr not in allowed_stderr:
            raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
        state = _CacheWriterServiceState(
            unit, "not-found", "inactive", "dead", "success",
            0, 0, 0, 0, 0, 0,
        )
        _validate_cache_writer_state(state)
        return state
    if (
        result.returncode != 0
        or result.stderr
        or set(values) != set(_CACHE_WRITER_PROPERTIES)
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    state = _CacheWriterServiceState(
        unit,
        values["LoadState"],
        values["ActiveState"],
        values["SubState"],
        values["Result"],
        _parse_systemd_status(values["ExecMainCode"]),
        _parse_systemd_status(values["ExecMainStatus"]),
        _parse_systemd_monotonic(values["InactiveExitTimestampMonotonic"]),
        _parse_systemd_monotonic(values["ActiveEnterTimestampMonotonic"]),
        _parse_systemd_monotonic(values["ExecMainStartTimestampMonotonic"]),
        _parse_systemd_monotonic(values["ExecMainExitTimestampMonotonic"]),
    )
    _validate_cache_writer_state(state)
    return state


def _allowlisted_cache_writer_states(
    machine: str,
    *,
    runner=subprocess.run,
) -> tuple[_CacheWriterServiceState, ...]:
    return tuple(
        _cache_writer_service_state(machine, unit, runner=runner)
        for unit in _CACHE_WRITER_UNITS
    )


def _validate_ld_so_conf_payload(payload: str) -> tuple[str, ...]:
    if (
        len(payload.encode("utf-8")) > _DIAGNOSTIC_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
        or any(marker in payload for marker in _PROTECTED_SECRET_MARKERS)
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    entries: list[str] = []
    for raw_line in payload.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("include "):
            continue
        if (
            not line.startswith("/")
            or re.fullmatch(r"/[A-Za-z0-9_./+-]+", line) is None
            or ".." in Path(line).parts
        ):
            raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
        entries.append(line.rstrip("/") or "/")
    return tuple(entries)


def _namespace_text_file(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    path: Path,
    *,
    capture=_namespace_capture,
) -> str:
    selected = _validate_diagnostic_namespace_path(path)
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(CAT), "--", str(selected)),
    )
    if result.returncode != 0 or result.stderr:
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    _validate_ld_so_conf_payload(result.stdout)
    return result.stdout


def _namespace_ld_so_conf_files(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    *,
    capture=_namespace_capture,
) -> tuple[Path, ...]:
    directory = Path("/etc/ld.so.conf.d")
    if not _namespace_test_path(
        leader,
        runtime_uid,
        runtime_gid,
        "-e",
        directory,
        capture=capture,
    ):
        return ()
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (
            str(FIND),
            str(directory),
            "-mindepth", "1",
            "-maxdepth", "1",
            "-type", "f",
            "-name", "*.conf",
            "-print",
        ),
    )
    if result.returncode != 0 or result.stderr:
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    files: list[Path] = []
    for raw_path in result.stdout.splitlines():
        path = _validate_diagnostic_namespace_path(Path(raw_path))
        if path.parent != directory or path.suffix != ".conf":
            raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
        present, regular = _namespace_regular_nonempty_file(
            leader,
            runtime_uid,
            runtime_gid,
            path,
            capture=capture,
        )
        if not present or not regular:
            raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
        files.append(path)
    if len(files) > 1024 or len(set(files)) != len(files):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    return tuple(sorted(files))


def _ldconfig_input_authority(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    trusted: _TrustedLibpython,
    *,
    capture=_namespace_capture,
) -> _LdConfigInputAuthority:
    expected = trusted.directory.as_posix().rstrip("/")
    if (
        not expected.startswith("/run/pdi-p3d-wp7-runtime.")
        or trusted.path.parent != trusted.directory
    ):
        raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
    main = Path("/etc/ld.so.conf")
    main_present = _namespace_test_path(
        leader,
        runtime_uid,
        runtime_gid,
        "-e",
        main,
        capture=capture,
    )
    main_entries: tuple[str, ...] = ()
    if main_present:
        present, regular = _namespace_regular_nonempty_file(
            leader,
            runtime_uid,
            runtime_gid,
            main,
            capture=capture,
        )
        if not present or not regular:
            raise AssertionError("BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED")
        main_entries = _validate_ld_so_conf_payload(
            _namespace_text_file(
                leader,
                runtime_uid,
                runtime_gid,
                main,
                capture=capture,
            )
        )
    conf_d_files = _namespace_ld_so_conf_files(
        leader,
        runtime_uid,
        runtime_gid,
        capture=capture,
    )
    conf_d_entries: list[str] = []
    for path in conf_d_files:
        conf_d_entries.extend(
            _validate_ld_so_conf_payload(
                _namespace_text_file(
                    leader,
                    runtime_uid,
                    runtime_gid,
                    path,
                    capture=capture,
                )
            )
        )
    return _LdConfigInputAuthority(
        main_present,
        expected in main_entries,
        len(conf_d_files),
        expected in conf_d_entries,
    )


def _container_cache_libpython_targets(payload: str) -> tuple[Path, ...]:
    if (
        len(payload.encode("utf-8")) > _LOADER_CACHE_OUTPUT_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
        or any(marker in payload for marker in _PROTECTED_SECRET_MARKERS)
    ):
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    expression = re.compile(
        rf"\s*{re.escape(_LIBPYTHON_SONAME)}\s+"
        r"\([^()\r\n]+\)\s+=>\s+(/[A-Za-z0-9_./+-]+)\s*"
    )
    targets: list[Path] = []
    for line in payload.splitlines():
        if _LIBPYTHON_SONAME not in line:
            continue
        matched = expression.fullmatch(line)
        if matched is None:
            raise AssertionError(
                "CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED"
            )
        raw_target = matched.group(1)
        target = _validate_diagnostic_namespace_path(Path(raw_target))
        if target.name != _LIBPYTHON_SONAME or target.as_posix() != raw_target:
            raise AssertionError(
                "CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED"
            )
        targets.append(target)
    return tuple(targets)


def _container_cache_targets_from_namespace(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    *,
    capture=_namespace_capture,
) -> tuple[Path, ...]:
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(LDCONFIG), "-p", "-C", "/etc/ld.so.cache"),
    )
    if result.returncode != 0 or result.stderr:
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    return _container_cache_libpython_targets(result.stdout)


def _container_elf_interpreter(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    binary: Path,
    *,
    capture=_namespace_capture,
) -> Path | None:
    selected = _validate_diagnostic_namespace_path(binary)
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(READELF), "--program-headers", "--wide", str(selected)),
    )
    payload = result.stdout + "\n" + result.stderr
    if (
        len(payload.encode("utf-8")) > _DIAGNOSTIC_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
        or any(marker in payload for marker in _PROTECTED_SECRET_MARKERS)
    ):
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    interpreters = _ELF_INTERPRETER.findall(result.stdout)
    if result.returncode != 0 or result.stderr or len(interpreters) != 1:
        return None
    interpreter = _validate_diagnostic_namespace_path(Path(interpreters[0]))
    if not _namespace_test_path(
        leader,
        runtime_uid,
        runtime_gid,
        "-e",
        interpreter,
        capture=capture,
    ):
        return None
    return interpreter


def _loader_libpython_result(
    result: subprocess.CompletedProcess[str],
    trusted: _TrustedLibpython,
) -> str:
    payload = result.stdout + "\n" + result.stderr
    if (
        len(payload.encode("utf-8")) > _DIAGNOSTIC_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
        or any(marker in payload for marker in _PROTECTED_SECRET_MARKERS)
    ):
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    _safe_return_code(result.returncode)
    missing_line = re.compile(
        rf"\s*{re.escape(_LIBPYTHON_SONAME)}\s+=>\s+not found\s*"
    )
    resolved_line = re.compile(
        rf"\s*{re.escape(_LIBPYTHON_SONAME)}\s+=>\s+"
        r"(/[A-Za-z0-9_./+-]+)\s+\(0x[0-9A-Fa-f]+\)\s*"
    )
    matching_lines = [
        line for line in payload.splitlines() if _LIBPYTHON_SONAME in line
    ]
    if len(matching_lines) == 1:
        if missing_line.fullmatch(matching_lines[0]):
            return "NOT_FOUND"
        resolved = resolved_line.fullmatch(matching_lines[0])
        if resolved is not None:
            raw_target = resolved.group(1)
            target = _validate_diagnostic_namespace_path(Path(raw_target))
            if target.as_posix() == raw_target and target == trusted.path:
                return "RESOLVED"
    if (
        result.returncode != 0
        and _LIBPYTHON_SONAME in payload
        and "cannot open shared object file" in payload
        and "No such file or directory" in payload
    ):
        return "NOT_FOUND"
    return "INVALID"


def _direct_loader_probe(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    interpreter: Path | None,
    binary: Path,
    trusted: _TrustedLibpython,
    *,
    inhibit_cache: bool = False,
    capture=_namespace_capture,
) -> str:
    if interpreter is None:
        return "INVALID"
    selected_binary = _validate_diagnostic_namespace_path(binary)
    command = [str(interpreter)]
    if inhibit_cache:
        command.append("--inhibit-cache")
    command.extend(("--list", str(selected_binary)))
    result = capture(
        leader,
        runtime_uid,
        runtime_gid,
        tuple(command),
    )
    return _loader_libpython_result(result, trusted)


def _collect_container_loader_cache_diagnostic(
    *,
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    system_python: Path,
    candidate: str,
    runtime_root: Path,
    trusted: _TrustedLibpython,
    host_cache_sha256: str,
    capture=_namespace_capture,
) -> _ContainerLoaderCacheDiagnostic:
    if (
        re.fullmatch(r"[0-9a-f]{40}", candidate) is None
        or re.fullmatch(r"[0-9a-f]{64}", host_cache_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", trusted.sha256) is None
        or trusted.path.name != _LIBPYTHON_SONAME
        or runtime_root not in trusted.path.parents
    ):
        raise AssertionError("CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED")
    cache = Path("/etc/ld.so.cache")
    candidate_python = (
        Path("/opt/pdi/releases") / candidate / ".venv/bin/python"
    )
    container_cache_present, container_cache_regular = (
        _namespace_regular_nonempty_file(
            leader,
            runtime_uid,
            runtime_gid,
            cache,
            capture=capture,
        )
    )
    cache_bytes_match = False
    targets: tuple[Path, ...] = ()
    if container_cache_regular:
        cache_bytes_match = (
            _namespace_file_sha256(
                leader,
                runtime_uid,
                runtime_gid,
                cache,
                capture=capture,
            )
            == host_cache_sha256
        )
        targets = _container_cache_targets_from_namespace(
            leader,
            runtime_uid,
            runtime_gid,
            capture=capture,
        )

    target_visible = False
    target_identity_match = False
    if len(targets) == 1:
        target = targets[0]
        target_present, target_regular = _namespace_regular_nonempty_file(
            leader,
            runtime_uid,
            runtime_gid,
            target,
            capture=capture,
        )
        target_visible = target_present and target_regular
        if target_visible:
            target_identity_match = (
                runtime_root in target.parents
                and target == trusted.path
                and _namespace_file_sha256(
                    leader,
                    runtime_uid,
                    runtime_gid,
                    target,
                    capture=capture,
                )
                == trusted.sha256
            )

    base_present, base_regular = _namespace_regular_nonempty_file(
        leader,
        runtime_uid,
        runtime_gid,
        system_python,
        capture=capture,
    )
    libpython_present, libpython_regular = _namespace_regular_nonempty_file(
        leader,
        runtime_uid,
        runtime_gid,
        trusted.path,
        capture=capture,
    )
    candidate_present, candidate_regular = _namespace_regular_nonempty_file(
        leader,
        runtime_uid,
        runtime_gid,
        candidate_python,
        capture=capture,
    )
    base_visible = base_present and base_regular
    libpython_visible = libpython_present and libpython_regular
    candidate_visible = candidate_present and candidate_regular

    base_direct = "INVALID"
    candidate_direct = "INVALID"
    base_inhibit = "INVALID"
    if (
        container_cache_regular
        and cache_bytes_match
        and len(targets) == 1
        and target_visible
        and target_identity_match
        and base_visible
        and libpython_visible
        and candidate_visible
    ):
        base_interpreter = _container_elf_interpreter(
            leader,
            runtime_uid,
            runtime_gid,
            system_python,
            capture=capture,
        )
        candidate_interpreter = _container_elf_interpreter(
            leader,
            runtime_uid,
            runtime_gid,
            candidate_python,
            capture=capture,
        )
        base_direct = _direct_loader_probe(
            leader,
            runtime_uid,
            runtime_gid,
            base_interpreter,
            system_python,
            trusted,
            capture=capture,
        )
        candidate_direct = _direct_loader_probe(
            leader,
            runtime_uid,
            runtime_gid,
            candidate_interpreter,
            candidate_python,
            trusted,
            capture=capture,
        )
        base_inhibit = _direct_loader_probe(
            leader,
            runtime_uid,
            runtime_gid,
            base_interpreter,
            system_python,
            trusted,
            inhibit_cache=True,
            capture=capture,
        )

    diagnostic = _ContainerLoaderCacheDiagnostic(
        True,
        True,
        container_cache_present,
        container_cache_regular,
        cache_bytes_match,
        len(targets),
        target_visible,
        target_identity_match,
        base_visible,
        libpython_visible,
        base_direct,
        candidate_direct,
        base_direct,
        base_inhibit,
    )
    _validate_container_loader_cache_diagnostic(diagnostic)
    return diagnostic


def _verify_container_loader_cache_visibility(
    **kwargs,
) -> _ContainerLoaderCacheDiagnostic:
    diagnostic = _collect_container_loader_cache_diagnostic(**kwargs)
    if diagnostic.classification != "LOADER_CACHE_EFFECTIVE":
        raise _ContainerLoaderCacheDiagnosticError(diagnostic)
    return diagnostic


def _collect_boot_cache_attribution(
    *,
    machine: str,
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    trusted: _TrustedLibpython,
    pre_boot: _LoaderCacheSnapshot,
    nspawn_start_monotonic_us: int,
    manager_registration_monotonic_us: int,
    post_libpython_entry_count: int,
    capture=_namespace_capture,
    systemd_runner=subprocess.run,
    monotonic_ns=time.monotonic_ns,
) -> _BootCacheAttributionDiagnostic:
    _validate_loader_cache_snapshot(pre_boot)
    post_boot = _namespace_loader_cache_snapshot(
        leader,
        runtime_uid,
        runtime_gid,
        capture=capture,
    )
    post_observation_monotonic_us = monotonic_ns() // 1000
    writer_states = _allowlisted_cache_writer_states(
        machine,
        runner=systemd_runner,
    )
    if writer_states[0].executed:
        try:
            ldconfig_input = _ldconfig_input_authority(
                leader,
                runtime_uid,
                runtime_gid,
                trusted,
                capture=capture,
            )
        except AssertionError:
            ldconfig_input = _LdConfigInputAuthority(
                False, False, 0, False, valid=False,
            )
    else:
        ldconfig_input = _LdConfigInputAuthority(False, False, 0, False)
    diagnostic = _BootCacheAttributionDiagnostic(
        pre_boot,
        post_boot,
        writer_states,
        ldconfig_input,
        nspawn_start_monotonic_us,
        manager_registration_monotonic_us,
        post_observation_monotonic_us,
        post_libpython_entry_count,
    )
    _validate_boot_cache_attribution(diagnostic)
    return diagnostic


def _parse_missing_libraries(payload: str) -> tuple[str, ...]:
    if (
        "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
    ):
        raise AssertionError("ELF_DIAGNOSTIC_REJECTED")
    missing: set[str] = set()
    for line in payload.splitlines():
        if "not found" not in line:
            continue
        matched = re.fullmatch(
            r"\s*([A-Za-z0-9_.+-]+)\s+=>\s+not found\s*",
            line,
        )
        if matched is None:
            raise AssertionError("ELF_DIAGNOSTIC_REJECTED")
        name = matched.group(1)
        if _LIBRARY_BASENAME.fullmatch(name) is None:
            raise AssertionError("ELF_DIAGNOSTIC_REJECTED")
        missing.add(name)
    return tuple(sorted(missing))


def _elf_dependency_diagnostic(
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    binary: Path,
    *,
    runner=subprocess.run,
) -> _ElfDependencyDiagnostic:
    headers = _namespace_capture(
        leader,
        runtime_uid,
        runtime_gid,
        (str(READELF), "--program-headers", "--wide", str(binary)),
        runner=runner,
    )
    if headers.returncode != 0:
        raise AssertionError("ELF_DIAGNOSTIC_REJECTED")
    interpreters = _ELF_INTERPRETER.findall(headers.stdout)
    if len(interpreters) > 1:
        raise AssertionError("ELF_DIAGNOSTIC_REJECTED")
    dynamic = len(interpreters) == 1
    interpreter_present = False
    if dynamic:
        interpreter = interpreters[0]
        present = _namespace_capture(
            leader,
            runtime_uid,
            runtime_gid,
            ("/usr/bin/test", "-e", interpreter),
            runner=runner,
        )
        if present.returncode not in {0, 1}:
            raise AssertionError("ELF_DIAGNOSTIC_REJECTED")
        interpreter_present = present.returncode == 0
    missing: tuple[str, ...] = ()
    if dynamic:
        dependencies = _namespace_capture(
            leader,
            runtime_uid,
            runtime_gid,
            (str(LDD), str(binary)),
            runner=runner,
        )
        missing = _parse_missing_libraries(
            dependencies.stdout + "\n" + dependencies.stderr
        )
    return _ElfDependencyDiagnostic(dynamic, interpreter_present, missing)


def _verify_container_python_preflight(
    *,
    leader: int,
    runtime_uid: int,
    runtime_gid: int,
    system_python: Path,
    candidate: str,
    python_probe=_container_python_probe,
    elf_probe=_elf_dependency_diagnostic,
) -> _QualificationPythonPreflight:
    if re.fullmatch(r"[0-9a-f]{40}", candidate) is None:
        raise AssertionError("QUALIFICATION_PYTHON_PREFLIGHT_INVALID")
    candidate_python = (
        Path("/opt/pdi/releases") / candidate / ".venv/bin/python"
    )
    candidate_rc = python_probe(
        leader, runtime_uid, runtime_gid, candidate_python,
    )
    base_rc = python_probe(leader, runtime_uid, runtime_gid, system_python)
    candidate_elf = elf_probe(
        leader, runtime_uid, runtime_gid, candidate_python,
    )
    base_elf = elf_probe(leader, runtime_uid, runtime_gid, system_python)
    diagnostic = _QualificationPythonPreflight(
        candidate_rc,
        base_rc,
        candidate_elf,
        base_elf,
    )
    _validate_qualification_python_preflight(diagnostic)
    if not _qualification_python_preflight_passed(diagnostic):
        raise _QualificationPythonPreflightError(
            diagnostic,
            _qualification_python_preflight_failure_class(diagnostic),
        )
    return diagnostic


def _validate_qualification_python_preflight(
    diagnostic: _QualificationPythonPreflight,
) -> None:
    elf_values = (diagnostic.candidate_elf, diagnostic.base_elf)
    if (
        any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not -255 <= value <= 255
            for value in (
                diagnostic.candidate_probe_rc,
                diagnostic.base_probe_rc,
            )
        )
        or any(
            not isinstance(value, _ElfDependencyDiagnostic)
            for value in elf_values
        )
        or any(
            not isinstance(value.dynamic, bool)
            or not isinstance(value.interpreter_present, bool)
            or not isinstance(value.missing_libraries, tuple)
            for value in elf_values
        )
        or any(
            not isinstance(name, str)
            or _LIBRARY_BASENAME.fullmatch(name) is None
            for value in elf_values
            for name in value.missing_libraries
        )
        or any(
            value.missing_libraries
            != tuple(sorted(set(value.missing_libraries)))
            for value in elf_values
        )
    ):
        raise AssertionError(
            "QUALIFICATION_PYTHON_PREFLIGHT_DIAGNOSTIC_REJECTED"
        )


def _qualification_python_preflight_passed(
    diagnostic: _QualificationPythonPreflight,
) -> bool:
    return (
        diagnostic.candidate_probe_rc == 0
        and diagnostic.base_probe_rc == 0
        and diagnostic.candidate_elf.dynamic
        and diagnostic.candidate_elf.interpreter_present
        and not diagnostic.candidate_elf.missing_libraries
        and diagnostic.base_elf.dynamic
        and diagnostic.base_elf.interpreter_present
        and not diagnostic.base_elf.missing_libraries
    )


def _qualification_python_preflight_failure_class(
    diagnostic: _QualificationPythonPreflight,
) -> str:
    _validate_qualification_python_preflight(diagnostic)
    candidate_probe_failed = diagnostic.candidate_probe_rc != 0
    base_probe_failed = diagnostic.base_probe_rc != 0
    candidate_missing = bool(diagnostic.candidate_elf.missing_libraries)
    base_missing = bool(diagnostic.base_elf.missing_libraries)
    candidate_elf_invalid = (
        not diagnostic.candidate_elf.dynamic
        or not diagnostic.candidate_elf.interpreter_present
    )
    base_elf_invalid = (
        not diagnostic.base_elf.dynamic
        or not diagnostic.base_elf.interpreter_present
    )
    if candidate_probe_failed and base_probe_failed:
        return "BOTH_PYTHON_PROBES_FAILED"
    if candidate_probe_failed:
        return "CANDIDATE_PYTHON_PROBE_FAILED"
    if base_probe_failed:
        return "BASE_PYTHON_PROBE_FAILED"
    if candidate_missing and base_missing:
        return "BOTH_PYTHONS_MISSING_LIBRARY"
    if candidate_missing:
        return "CANDIDATE_PYTHON_MISSING_LIBRARY"
    if base_missing:
        return "BASE_PYTHON_MISSING_LIBRARY"
    if candidate_elf_invalid and base_elf_invalid:
        return "BOTH_ELF_INVALID"
    if candidate_elf_invalid:
        return "CANDIDATE_ELF_INVALID"
    if base_elf_invalid:
        return "BASE_ELF_INVALID"
    return "QUALIFICATION_PYTHON_PREFLIGHT_UNCLASSIFIED"


def _lexically_inside(path: Path, root: Path) -> bool:
    if not path.is_absolute() or ".." in path.parts:
        return False
    return path == root or root in path.parents


def _path_class(
    value: str | None,
    *,
    runtime_root: Path,
    candidate: str,
) -> str:
    if value is None:
        return "ABSENT"
    path = Path(value)
    if _lexically_inside(path, runtime_root):
        return "APPROVED_RUNTIME"
    if any(_lexically_inside(path, root) for root in (
        Path("/opt/pdi/current"),
        Path("/opt/pdi/releases") / candidate,
    )):
        return "CANDIDATE_RELEASE"
    return "OTHER"


def _pyvenv_authority_diagnostic(
    payload: str,
    *,
    runtime_root: Path,
    candidate: str,
    rehearsal_root: Path,
) -> _PyVenvAuthorityDiagnostic:
    if (
        len(payload.encode("utf-8")) > _DIAGNOSTIC_LIMIT
        or "\x00" in payload
        or any(ord(char) < 32 and char not in "\n\r\t" for char in payload)
        or _SECRET_ASSIGNMENT.search(payload)
    ):
        raise AssertionError("PYVENV_DIAGNOSTIC_REJECTED")
    selected: dict[str, str] = {}
    for line in payload.splitlines():
        name, separator, value = line.partition("=")
        name = name.strip().lower()
        if separator and name in {"home", "executable", "command"}:
            if name in selected:
                raise AssertionError("PYVENV_DIAGNOSTIC_REJECTED")
            selected[name] = value.strip()
    try:
        command_parts = shlex.split(selected.get("command", ""), posix=True)
    except ValueError as exc:
        raise AssertionError("PYVENV_DIAGNOSTIC_REJECTED") from exc
    paths = [
        Path(value)
        for value in (
            selected.get("home"),
            selected.get("executable"),
            *(part for part in command_parts if part.startswith("/")),
        )
        if value
    ]
    if any(".." in path.parts for path in paths):
        raise AssertionError("PYVENV_DIAGNOSTIC_REJECTED")
    return _PyVenvAuthorityDiagnostic(
        _path_class(
            selected.get("home"),
            runtime_root=runtime_root,
            candidate=candidate,
        ),
        _path_class(
            selected.get("executable"),
            runtime_root=runtime_root,
            candidate=candidate,
        ),
        any(
            _lexically_inside(path, root)
            for path in paths
            for root in (Path("/tmp"), Path("/var/tmp"))
        ),
        any(_lexically_inside(path, runtime_root) for path in paths),
        any(_lexically_inside(path, rehearsal_root) for path in paths),
    )


def _runtime_reference_counts(
    release: Path,
    rehearsal_root: Path,
    candidate: str,
) -> tuple[int, int]:
    if re.fullmatch(r"[0-9a-f]{40}", candidate) is None:
        raise AssertionError("RUNTIME_REFERENCE_DIAGNOSTIC_REJECTED")
    venv = release / ".venv"
    selected: set[Path] = {venv / "pyvenv.cfg"}
    try:
        selected.update(venv.joinpath("bin").iterdir())
        selected.update(venv.rglob("*.pth"))
        selected.update(venv.rglob("*.dist-info/RECORD"))
        physical = str(rehearsal_root).encode()
        logical = (
            f"/opt/pdi/releases/{candidate}".encode(),
            b"/opt/pdi/current",
        )
        physical_count = 0
        logical_count = 0
        for path in sorted(selected):
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                payload = path.read_bytes()
            elif stat.S_ISLNK(info.st_mode):
                payload = os.fsencode(os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                continue
            else:
                raise OSError
            physical_count += payload.count(physical)
            logical_count += sum(payload.count(marker) for marker in logical)
    except OSError as exc:
        raise AssertionError("RUNTIME_REFERENCE_DIAGNOSTIC_REJECTED") from exc
    return physical_count, logical_count


def _classify_interpreter_failure(
    *,
    candidate_rc: int,
    base_rc: int,
    sandbox_rc: int,
    candidate_elf: _ElfDependencyDiagnostic,
    base_elf: _ElfDependencyDiagnostic,
    physical_reference_count: int,
    logical_reference_count: int,
) -> str:
    if (
        candidate_elf.missing_libraries
        or base_elf.missing_libraries
        or (candidate_elf.dynamic and not candidate_elf.interpreter_present)
        or (base_elf.dynamic and not base_elf.interpreter_present)
    ):
        return "DYNAMIC_LIBRARY_RESOLUTION_FAILURE"
    if physical_reference_count > 0 and logical_reference_count == 0:
        return "PHYSICAL_LOGICAL_RUNTIME_PATH_MISMATCH"
    if base_rc == 127:
        return "BASE_RUNTIME_NOT_EXECUTABLE_IN_CONTAINER"
    if candidate_rc == 127 and base_rc == 0:
        return "CANDIDATE_VENV_NOT_EXECUTABLE_IN_CONTAINER"
    if candidate_rc == 0 and sandbox_rc == 127:
        return "SYSTEMD_SANDBOX_RUNTIME_FAILURE"
    return "INTERPRETER_FAILURE_UNCLASSIFIED"


def _collect_interpreter_failure_diagnostic(
    *,
    leader: int,
    machine: str,
    operation_id: str,
    runtime_uid: int,
    runtime_gid: int,
    system_python: Path,
    release: Path,
    rehearsal_root: Path,
    candidate: str,
) -> _InterpreterFailureDiagnostic:
    candidate_python = Path("/opt/pdi/current/.venv/bin/python")
    candidate_rc = _container_python_probe(
        leader, runtime_uid, runtime_gid, candidate_python,
    )
    base_rc = _container_python_probe(
        leader, runtime_uid, runtime_gid, system_python,
    )
    sandbox_rc = (
        _systemd_sandbox_python_probe(machine, operation_id)
        if candidate_rc == 0
        else -1
    )
    candidate_elf = _elf_dependency_diagnostic(
        leader, runtime_uid, runtime_gid, candidate_python,
    )
    base_elf = _elf_dependency_diagnostic(
        leader, runtime_uid, runtime_gid, system_python,
    )
    pyvenv = _pyvenv_authority_diagnostic(
        (release / ".venv/pyvenv.cfg").read_text(encoding="utf-8"),
        runtime_root=system_python.parent.parent,
        candidate=candidate,
        rehearsal_root=rehearsal_root,
    )
    physical_count, logical_count = _runtime_reference_counts(
        release, rehearsal_root, candidate,
    )
    classification = _classify_interpreter_failure(
        candidate_rc=candidate_rc,
        base_rc=base_rc,
        sandbox_rc=sandbox_rc,
        candidate_elf=candidate_elf,
        base_elf=base_elf,
        physical_reference_count=physical_count,
        logical_reference_count=logical_count,
    )
    return _InterpreterFailureDiagnostic(
        candidate_rc,
        base_rc,
        sandbox_rc,
        candidate_elf,
        base_elf,
        pyvenv,
        physical_count,
        logical_count,
        classification,
    )


def _service_failure_class(
    journal: _RehearsalFailureJournalDiagnostic,
    service_state: dict[str, str],
    pipeline_runs: _PipelineRunFailureDiagnostic,
) -> str:
    if journal.systemctl_start_return_code != 0:
        return "SERVICE_START_COMMAND_FAILED"
    if (
        service_state["Result"] != "success"
        or service_state["ExecMainStatus"] != "0"
    ):
        return "SERVICE_PROCESS_EXITED_NONZERO"
    if (
        pipeline_runs.failed_pipeline_present
        and pipeline_runs.failed_pipeline_status == "failed"
    ):
        return "SERVICE_LEDGER_FAILED"
    if (
        pipeline_runs.failed_pipeline_present
        and pipeline_runs.failed_pipeline_status == "completed"
    ):
        return "SERVICE_EFFECT_VALIDATION_FAILED"
    if (
        service_state["LoadState"] != "loaded"
        or service_state["ActiveState"] not in {"inactive", "failed"}
    ):
        return "SERVICE_STATUS_INCONSISTENT"
    return "UNCLASSIFIED_SERVICE_FAILURE"


def _collect_service_failure_diagnostic(
    *,
    root: Path,
    operation_id: str,
    engine,
    boundary,
    provider_calls: tuple[str, ...],
) -> _ServiceFailureDiagnostic:
    journal = _read_failure_journal(root, operation_id)
    pipeline_runs = _read_pipeline_run_failure(
        engine, boundary, journal.failed_pipeline_key,
    )
    provider_counts = _provider_call_counts(provider_calls)
    return _ServiceFailureDiagnostic(
        journal,
        journal.service_state,
        pipeline_runs,
        provider_counts,
        _service_failure_class(journal, journal.service_state, pipeline_runs),
    )


def _interpreter_probe_required(diagnostic: _ServiceFailureDiagnostic) -> bool:
    return (
        diagnostic.service_state["ExecMainStatus"] == "127"
        and diagnostic.pipeline_runs.total == 0
    )


def _seed_database(url: str):
    engine = create_postgres_engine(url)
    with engine.connect() as connection:
        config = Config(str(ROOT / "alembic.ini"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    _clean(engine)
    identities = PostgreSQLProviderIdentityRepository(engine)
    scopes = {}
    for provider, enabled in (
        ("nextcloud", True),
        ("immich", True),
        ("gmail", False),
        ("integration-test", False),
    ):
        instance = identities.create_instance(
            provider_type=provider,
            instance_key=f"wp7-{provider}",
            enabled=enabled,
        )
        account = None
        if enabled:
            account = identities.create_account(
                provider_instance_id=instance.id,
                account_key=f"wp7-{provider}",
                provider_native_id=(
                    IMMICH_ACCOUNT_ID if provider == "immich" else "synthetic-nextcloud"
                ),
                enabled=True,
            )
        scopes[provider] = identities.create_scope(
            provider_instance_id=instance.id,
            provider_account_id=None if account is None else account.id,
            scope_key=f"wp7-{provider}",
            enabled=enabled,
        )

    text_content = _ProviderFixtureHandler.text_content
    document_content = _ProviderFixtureHandler.document_content
    resources = (
        (
            "nextcloud", scopes["nextcloud"].id, "nextcloud-text",
            text_content, "text/markdown", "notes.md", "/content/notes.md",
            {"href": "/content/notes.md", "getlastmodified": "Sat, 26 Sep 2026 01:00:00 GMT"},
        ),
        (
            "nextcloud", scopes["nextcloud"].id, "nextcloud-document",
            document_content,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "document.docx", "/content/document.docx",
            {"href": "/content/document.docx", "getlastmodified": "Sat, 26 Sep 2026 01:00:00 GMT"},
        ),
        (
            "immich", scopes["immich"].id, IMMICH_ACCOUNT_ID,
            b"synthetic-image", "image/jpeg", "image.jpg", None,
            {
                "fileModifiedAt": "2026-09-26T01:00:00Z",
                "exif": {
                    "dateTimeOriginal": "2026-09-26T01:00:00Z",
                    "latitude": 1.25,
                    "longitude": 103.8,
                    "country": "Synthetic Country",
                    "state": "Synthetic State",
                    "city": "Synthetic City",
                    "make": "Synthetic Camera",
                    "model": "Synthetic Model",
                },
            },
        ),
        (
            "gmail", scopes["gmail"].id, "synthetic-gmail-preserved",
            b"g", "message/rfc822", "message.eml", None, {},
        ),
        (
            "integration-test", scopes["integration-test"].id,
            "synthetic-integration-quarantine", b"i", "application/octet-stream",
            "quarantine.bin", None, {},
        ),
    )
    with engine.begin() as connection:
        for provider, scope_id, external_id, content, mime, name, href, metadata in resources:
            asset_id, blob_id, source_id = uuid4(), uuid4(), uuid4()
            connection.execute(text(
                "INSERT INTO assets(id,resource_type,title,metadata,created_at,updated_at) "
                "VALUES (:id,'file',:title,'{}'::jsonb,now(),now())"
            ), {"id": asset_id, "title": f"Synthetic {provider}"})
            connection.execute(text(
                "INSERT INTO blobs(id,asset_id,hash,size,mime_type) "
                "VALUES (:id,:asset,:hash,:size,:mime)"
            ), {
                "id": blob_id,
                "asset": asset_id,
                "hash": sha256(content).hexdigest(),
                "size": len(content),
                "mime": mime,
            })
            connection.execute(text(
                "INSERT INTO asset_sources("
                "id,blob_id,provider,external_id,observation_scope_id,path,name,"
                "version_tag,provider_mime_type,provider_size,metadata,is_active) "
                "VALUES (:id,:blob,:provider,:external,:scope,:path,:name,'synthetic-v1',"
                ":mime,:size,CAST(:metadata AS jsonb),true)"
            ), {
                "id": source_id,
                "blob": blob_id,
                "provider": provider,
                "external": external_id,
                "scope": scope_id,
                "path": name,
                "name": name,
                "mime": mime,
                "size": len(content),
                "metadata": json.dumps(metadata),
            })
    sync = PostgreSQLScopeSyncStateRepository(engine)
    for provider, mechanism in (
        ("nextcloud", "activity_v2_hint_v1"),
        ("immich", "metadata_updated_at_v1"),
    ):
        row = sync.get_or_create(scopes[provider].id, mechanism)
        assert sync.compare_and_swap_checkpoint(
            scopes[provider].id,
            mechanism,
            expected_version=row.version,
            checkpoint=f"synthetic-{provider}",
        ) is not None
    return engine, scopes


def _clean_rehearsal_database(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM resource_statements"))
        connection.execute(text("DELETE FROM resource_enrichments"))
    _clean(engine)


def _tree_snapshot(paths: tuple[Path, ...]) -> str:
    facts = []
    for root in paths:
        if not root.exists() and not root.is_symlink():
            facts.append((str(root), "absent"))
            continue
        members = (root, *sorted(root.rglob("*"))) if root.is_dir() else (root,)
        for path in members:
            info = path.lstat()
            relative = str(path)
            if stat.S_ISREG(info.st_mode):
                facts.append((relative, "file", stat.S_IMODE(info.st_mode), sha256(path.read_bytes()).hexdigest()))
            elif stat.S_ISLNK(info.st_mode):
                facts.append((relative, "symlink", os.readlink(path)))
            elif stat.S_ISDIR(info.st_mode):
                facts.append((relative, "directory", stat.S_IMODE(info.st_mode)))
    return sha256(json.dumps(facts, sort_keys=True, default=str).encode()).hexdigest()


def _host_systemd_snapshot() -> str:
    facts = []
    units = tuple(SERVICE_UNITS.values()) + tuple(
        P3D_TIMER_UNITS[key] for key in CANONICAL_PIPELINES
    )
    for unit in units:
        result = subprocess.run(
            (
                "/usr/bin/systemctl", "--no-pager", "show", unit,
                "--property=LoadState", "--property=ActiveState",
                "--property=SubState", "--property=UnitFileState",
            ),
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            shell=False,
        )
        facts.append((unit, result.returncode, result.stdout))
    return sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()


def _trusted_host_os_release(
    candidates: tuple[Path, ...] = (
        Path("/usr/lib/os-release"),
        Path("/etc/os-release"),
    ),
) -> tuple[Path, bytes]:
    for candidate in candidates:
        if not candidate.exists() and not candidate.is_symlink():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AssertionError("ROOTFS_OS_RELEASE_SOURCE_INVALID") from exc
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise AssertionError("ROOTFS_OS_RELEASE_SOURCE_NOT_REGULAR")
        payload = resolved.read_bytes()
        if not payload:
            raise AssertionError("ROOTFS_OS_RELEASE_SOURCE_EMPTY")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise AssertionError("ROOTFS_OS_RELEASE_SOURCE_UNTRUSTED")
        return resolved, payload
    raise AssertionError("ROOTFS_OS_RELEASE_SOURCE_MISSING")


def _assert_materialized_os_release(root: Path, expected: bytes) -> None:
    destination = root / "etc/os-release"
    info = destination.lstat()
    assert stat.S_ISREG(info.st_mode) and not destination.is_symlink()
    assert info.st_uid == 0 and info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o644
    assert expected and destination.read_bytes() == expected


def _materialize_rootfs_os_release(
    root: Path,
    *,
    candidates: tuple[Path, ...] = (
        Path("/usr/lib/os-release"),
        Path("/etc/os-release"),
    ),
) -> bytes:
    _, payload = _trusted_host_os_release(candidates)
    destination = root / "etc/os-release"
    assert not destination.exists() and not destination.is_symlink()
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _assert_materialized_os_release(root, payload)
    return payload


def _prepare_rootfs(root: Path, runtime_uid: int, runtime_gid: int) -> bytes:
    for relative, mode in (
        ("usr", 0o755), ("etc", 0o755), ("etc/systemd", 0o755),
        ("etc/systemd/system", 0o755), ("opt", 0o755), ("opt/pdi", 0o755),
        ("var", 0o755), ("var/lib", 0o755), ("var/lib/pdi-p3d", 0o700),
        ("run", 0o755), ("run/lock", 0o755), ("tmp", 0o1777), ("root", 0o700),
    ):
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 0, 0)
        os.chmod(path, mode)
    for name, target in (
        ("bin", "usr/bin"), ("sbin", "usr/sbin"),
        ("lib", "usr/lib"), ("lib64", "usr/lib64"),
    ):
        path = root / name
        if not path.exists() and not path.is_symlink():
            path.symlink_to(target)
    os_release = _materialize_rootfs_os_release(root)
    _write(
        root / "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        f"pdi:x:{runtime_uid}:{runtime_gid}:pdi:/nonexistent:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        0o644, 0, 0,
    )
    _write(
        root / "etc/group",
        "root:x:0:\n"
        f"pdi:x:{runtime_gid}:\n"
        "nogroup:x:65534:\n",
        0o644, 0, 0,
    )
    _write(root / "etc/nsswitch.conf", "passwd: files\ngroup: files\nhosts: files dns\n", 0o644, 0, 0)
    _write(root / "etc/hosts", "127.0.0.1 localhost\n::1 localhost\n", 0o644, 0, 0)
    _write(root / "etc/machine-id", "", 0o644, 0, 0)
    default_target = root / "etc/systemd/system/default.target"
    default_target.symlink_to("/usr/lib/systemd/system/basic.target")
    return os_release


def _tool(candidate: str) -> OperatorToolIdentity:
    source = Path(__import__(
        "pdi.production_ops.p3d_release_bootstrap", fromlist=["__file__"]
    ).__file__)
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": ToolName.RELEASE_BOOTSTRAP.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": sha256(source.read_bytes()).hexdigest(),
        "TOOL_SOURCE_SHA": candidate,
    })


def _build_nspawn_command(
    machine: str,
    root: Path,
    system_python: Path,
) -> tuple[str, ...]:
    runtime_root = system_python.parent.parent
    return (
        str(SYSTEMD_NSPAWN), "--quiet", "--boot", "--register=yes",
        f"--machine={machine}", f"--directory={root}",
        "--bind-ro=/usr:/usr",
        f"--bind-ro={runtime_root}:{runtime_root}",
        "--console=pipe", "--link-journal=no", "--settings=no",
        "--resolv-conf=off", "--timezone=off",
    )


def test_nspawn_command_uses_only_approved_options() -> None:
    machine = "pdi-p3d-1234567812344234"
    root = Path("/tmp/pdi-p3d-rehearsal-synthetic")
    system_python = Path("/run/pdi-p3d-wp7-runtime.SYNTHETIC/bin/python")
    assert _build_nspawn_command(machine, root, system_python) == (
        str(SYSTEMD_NSPAWN),
        "--quiet",
        "--boot",
        "--register=yes",
        f"--machine={machine}",
        f"--directory={root}",
        "--bind-ro=/usr:/usr",
        "--bind-ro=/run/pdi-p3d-wp7-runtime.SYNTHETIC:"
        "/run/pdi-p3d-wp7-runtime.SYNTHETIC",
        "--console=pipe",
        "--link-journal=no",
        "--settings=no",
        "--resolv-conf=off",
        "--timezone=off",
    )
    assert "--unit=basic.target" not in _build_nspawn_command(
        machine,
        root,
        system_python,
    )


def _directory_stat(mode: int = 0o755, uid: int = 0, gid: int = 0) -> os.stat_result:
    return os.stat_result((stat.S_IFDIR | mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


def _regular_stat(
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
    size: int = 1,
) -> os.stat_result:
    return os.stat_result(
        (stat.S_IFREG | mode, 0, 0, 1, uid, gid, size, 0, 0, 0)
    )


def _symlink_stat() -> os.stat_result:
    return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))


def test_qualification_runtime_accepts_trusted_run_path() -> None:
    runtime = Path("/run/pdi-p3d-wp7-runtime.A1b2C3")
    assert _validate_qualification_runtime_root(
        runtime,
        resolved=runtime,
        runtime_info=_directory_stat(),
        run_info=_directory_stat(),
    ) == runtime


@pytest.mark.parametrize("runtime", (
    Path("/tmp/pdi-p3d-wp7-runtime.A1b2C3"),
    Path("/var/tmp/pdi-p3d-wp7-runtime.A1b2C3"),
))
def test_qualification_runtime_rejects_private_tmp_paths(runtime: Path) -> None:
    with pytest.raises(AssertionError, match="QUALIFICATION_RUNTIME_INVALID"):
        _validate_qualification_runtime_root(
            runtime,
            resolved=runtime,
            runtime_info=_directory_stat(),
            run_info=_directory_stat(),
        )


@pytest.mark.parametrize("runtime_info,run_info,resolved", (
    (
        _directory_stat(uid=1000), _directory_stat(),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3"),
    ),
    (
        _directory_stat(gid=1000), _directory_stat(),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3"),
    ),
    (
        _directory_stat(mode=0o775), _directory_stat(),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3"),
    ),
    (
        _symlink_stat(), _directory_stat(),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3"),
    ),
    (
        _directory_stat(), _directory_stat(mode=0o777),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3"),
    ),
    (
        _directory_stat(), _symlink_stat(),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3"),
    ),
    (
        _directory_stat(), _directory_stat(),
        Path("/run/other-runtime.A1b2C3"),
    ),
))
def test_qualification_runtime_rejects_untrusted_path_facts(
    runtime_info: os.stat_result,
    run_info: os.stat_result,
    resolved: Path,
) -> None:
    runtime = Path("/run/pdi-p3d-wp7-runtime.A1b2C3")
    with pytest.raises(AssertionError, match="QUALIFICATION_RUNTIME_INVALID"):
        _validate_qualification_runtime_root(
            runtime,
            resolved=resolved,
            runtime_info=runtime_info,
            run_info=run_info,
        )


def _runtime_libpython_fixture(
    tmp_path: Path,
    monkeypatch,
    *,
    file_mode: int = 0o644,
    file_size: int = 7,
) -> tuple[Path, Path]:
    runtime = tmp_path / "pdi-p3d-wp7-runtime.A1b2C3"
    directory = runtime / "lib"
    directory.mkdir(parents=True)
    library = directory / _LIBPYTHON_SONAME
    library.write_bytes(b"runtime" if file_size else b"")
    original_lstat = Path.lstat
    facts = {
        runtime: _directory_stat(),
        directory: _directory_stat(),
        library: _regular_stat(mode=file_mode, size=file_size),
    }

    def trusted_lstat(path: Path):
        return facts.get(path, original_lstat(path))

    monkeypatch.setattr(Path, "lstat", trusted_lstat)
    return runtime, library


def test_trusted_runtime_libpython_exactly_one_is_accepted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime, library = _runtime_libpython_fixture(tmp_path, monkeypatch)
    trusted = _discover_trusted_libpython(runtime)
    assert trusted.path == library
    assert trusted.directory == library.parent
    assert trusted.sha256 == sha256(b"runtime").hexdigest()


def test_trusted_runtime_libpython_missing_or_multiple_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    missing = tmp_path / "missing-runtime"
    missing.mkdir()
    with pytest.raises(
        AssertionError,
        match="QUALIFICATION_LIBPYTHON_CARDINALITY_INVALID",
    ):
        _discover_trusted_libpython(missing)

    runtime, _ = _runtime_libpython_fixture(tmp_path, monkeypatch)
    duplicate = runtime / "alt" / _LIBPYTHON_SONAME
    duplicate.parent.mkdir()
    duplicate.write_bytes(b"duplicate")
    with pytest.raises(
        AssertionError,
        match="QUALIFICATION_LIBPYTHON_CARDINALITY_INVALID",
    ):
        _discover_trusted_libpython(runtime)


def test_trusted_runtime_libpython_outside_runtime_is_rejected(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    outside = tmp_path / _LIBPYTHON_SONAME
    outside.write_bytes(b"outside")
    with pytest.raises(AssertionError, match="QUALIFICATION_LIBPYTHON_INVALID"):
        _validate_trusted_libpython_candidate(runtime, outside)


@pytest.mark.parametrize("file_mode,file_size", ((0o664, 7), (0o644, 0)))
def test_trusted_runtime_libpython_writable_or_empty_is_rejected(
    tmp_path: Path,
    monkeypatch,
    file_mode: int,
    file_size: int,
) -> None:
    runtime, _ = _runtime_libpython_fixture(
        tmp_path,
        monkeypatch,
        file_mode=file_mode,
        file_size=file_size,
    )
    with pytest.raises(AssertionError, match="QUALIFICATION_LIBPYTHON_INVALID"):
        _discover_trusted_libpython(runtime)


def test_loader_cache_requires_exact_soname_and_trusted_target() -> None:
    trusted_path = Path(
        "/run/pdi-p3d-wp7-runtime.A1b2C3/lib/libpython3.13.so.1.0"
    )
    trusted = _TrustedLibpython(
        trusted_path,
        trusted_path.parent,
        "1" * 64,
    )
    payload = (
        "1 libs found in cache `/root/etc/ld.so.cache'\n"
        "\tlibpython3.13.so.1.0 (libc6,x86-64) => "
        f"{trusted_path}\n"
    )
    _validate_loader_cache_listing(payload, trusted)
    with pytest.raises(
        AssertionError,
        match="QUALIFICATION_LOADER_CACHE_INVALID",
    ):
        _validate_loader_cache_listing("0 libs found in cache\n", trusted)
    with pytest.raises(
        AssertionError,
        match="QUALIFICATION_LOADER_CACHE_INVALID",
    ):
        _validate_loader_cache_listing(
            payload.replace(str(trusted_path), "/usr/lib/libpython3.13.so.1.0"),
            trusted,
        )
    with pytest.raises(
        AssertionError,
        match="QUALIFICATION_LOADER_CACHE_INVALID",
    ):
        _validate_loader_cache_listing(payload + payload.splitlines()[-1], trusted)


def test_loader_cache_commands_are_fixed_nonmutating_host_invocations() -> None:
    root = Path("/tmp/pdi-p3d-rehearsal-synthetic")
    configuration = root / "var/lib/pdi-p3d/ld.so.conf.wp7"
    assert _loader_cache_build_command(root, configuration) == (
        "/sbin/ldconfig",
        "-C", "/tmp/pdi-p3d-rehearsal-synthetic/etc/ld.so.cache",
        "-f", str(configuration),
        "-X",
        "--ignore-aux-cache",
    )
    assert _loader_cache_inspect_command(root) == (
        "/sbin/ldconfig",
        "-p",
        "-C", "/tmp/pdi-p3d-rehearsal-synthetic/etc/ld.so.cache",
    )
    combined = " ".join(_loader_cache_build_command(root, configuration))
    assert "LD_LIBRARY_PATH" not in combined
    assert "LD_PRELOAD" not in combined
    assert "patchelf" not in combined


def test_loader_cache_materialization_uses_fixed_env_and_shell_false(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "rehearsal"
    (root / "etc").mkdir(parents=True)
    (root / "var/lib/pdi-p3d").mkdir(parents=True)
    runtime = Path("/run/pdi-p3d-wp7-runtime.A1b2C3")
    library = runtime / "lib" / _LIBPYTHON_SONAME
    trusted = _TrustedLibpython(library, library.parent, "1" * 64)
    discoveries = []
    commands = []
    listings = []

    def discover(selected: Path) -> _TrustedLibpython:
        discoveries.append(selected)
        return trusted

    def runner(argv, **kwargs):
        commands.append((tuple(argv), kwargs))
        if "-p" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                f"\t{_LIBPYTHON_SONAME} (libc6,x86-64) => {library}\n",
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setitem(globals(), "_discover_trusted_libpython", discover)
    monkeypatch.setitem(
        globals(), "_validate_trusted_executable", lambda path: path,
    )
    monkeypatch.setitem(globals(), "_assert_loader_cache_file", lambda path: None)
    monkeypatch.setitem(
        globals(),
        "_validate_loader_cache_listing",
        lambda payload, selected: listings.append((payload, selected)),
    )
    monkeypatch.setattr(os, "fchown", lambda *args: None)
    monkeypatch.setattr(os, "fchmod", lambda *args: None)

    assert _materialize_disposable_loader_cache(
        root,
        runtime,
        runner=runner,
    ) == trusted
    assert discoveries == [runtime, runtime]
    assert listings and listings[0][1] == trusted
    assert len(commands) == 2
    assert all(command[1]["shell"] is False for command in commands)
    assert all(command[1]["env"] == {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C",
    } for command in commands)
    assert not (root / "var/lib/pdi-p3d/ld.so.conf.wp7").exists()


def _effective_container_loader_cache_diagnostic(
    **changes,
) -> _ContainerLoaderCacheDiagnostic:
    return replace(
        _ContainerLoaderCacheDiagnostic(
            True,
            True,
            True,
            True,
            True,
            1,
            True,
            True,
            True,
            True,
            "RESOLVED",
            "RESOLVED",
            "RESOLVED",
            "NOT_FOUND",
        ),
        **changes,
    )


def test_container_loader_cache_diagnostic_proves_effective_exact_cache() -> None:
    runtime = Path("/run/pdi-p3d-wp7-runtime.A1b2C3")
    system_python = runtime / "bin/python"
    trusted = _TrustedLibpython(
        runtime / "lib" / _LIBPYTHON_SONAME,
        runtime / "lib",
        "2" * 64,
    )
    host_cache_digest = "1" * 64
    interpreter = Path("/lib64/ld-linux-x86-64.so.2")
    commands: list[tuple[str, ...]] = []

    def capture(leader, uid, gid, command):
        assert (leader, uid, gid) == (4321, 998, 997)
        commands.append(command)
        if command[0] == str(TEST):
            return subprocess.CompletedProcess(
                command, 1 if command[1] == "-L" else 0, "", "",
            )
        if command[0] == str(SHA256SUM):
            digest = (
                host_cache_digest
                if command[1] == "/etc/ld.so.cache"
                else trusted.sha256
            )
            return subprocess.CompletedProcess(
                command, 0, f"{digest}  {command[1]}\n", "",
            )
        if command[0] == str(LDCONFIG):
            return subprocess.CompletedProcess(
                command,
                0,
                "1 libs found in cache `/etc/ld.so.cache'\n"
                f"\t{_LIBPYTHON_SONAME} (libc6,x86-64) => "
                f"{trusted.path}\n",
                "",
            )
        if command[0] == str(READELF):
            return subprocess.CompletedProcess(
                command,
                0,
                f"      [Requesting program interpreter: {interpreter}]\n",
                "",
            )
        if command[0] == str(interpreter):
            if "--inhibit-cache" in command:
                return subprocess.CompletedProcess(
                    command,
                    127,
                    "",
                    f"{command[-1]}: error while loading shared libraries: "
                    f"{_LIBPYTHON_SONAME}: cannot open shared object file: "
                    "No such file or directory\n",
                )
            return subprocess.CompletedProcess(
                command,
                0,
                f"\t{_LIBPYTHON_SONAME} => {trusted.path} (0x1234)\n",
                "",
            )
        raise AssertionError("UNEXPECTED_DIAGNOSTIC_COMMAND")

    diagnostic = _verify_container_loader_cache_visibility(
        leader=4321,
        runtime_uid=998,
        runtime_gid=997,
        system_python=system_python,
        candidate="a" * 40,
        runtime_root=runtime,
        trusted=trusted,
        host_cache_sha256=host_cache_digest,
        capture=capture,
    )
    assert diagnostic.classification == "LOADER_CACHE_EFFECTIVE"
    values = dict(diagnostic.safe_values())
    assert values["HOST_LOADER_CACHE_PRESENT"] == "YES"
    assert values["HOST_LOADER_CACHE_SHA256_VALID"] == "PASS"
    assert values["CONTAINER_LOADER_CACHE_BYTES_MATCH_HOST"] == "PASS"
    assert values["CONTAINER_CACHE_LIBPYTHON_ENTRY_COUNT"] == "1"
    assert values["CONTAINER_CACHE_TARGET_IDENTITY_MATCH"] == "PASS"
    assert values["BASE_LOADER_DEFAULT_CACHE_RESULT"] == "RESOLVED"
    assert values["BASE_LOADER_INHIBIT_CACHE_RESULT"] == "NOT_FOUND"
    assert (
        str(LDCONFIG), "-p", "-C", "/etc/ld.so.cache"
    ) in commands
    assert any("--inhibit-cache" in command for command in commands)
    assert not any(
        "LD_LIBRARY_PATH" in item
        for command in commands
        for item in command
    )
    assert not any(
        "LD_PRELOAD" in item for command in commands for item in command
    )


@pytest.mark.parametrize(
    "changes,classification",
    (
        (
            {"container_cache_present": False, "container_cache_regular": False},
            "CONTAINER_CACHE_FILE_MISSING",
        ),
        (
            {"container_cache_bytes_match_host": False},
            "CONTAINER_CACHE_BYTES_MISMATCH",
        ),
        (
            {
                "libpython_entry_count": 0,
                "cache_target_visible": False,
                "cache_target_identity_match": False,
            },
            "CONTAINER_CACHE_LIBPYTHON_ENTRY_MISSING",
        ),
        (
            {"libpython_entry_count": 2},
            "CONTAINER_CACHE_LIBPYTHON_ENTRY_AMBIGUOUS",
        ),
        (
            {"cache_target_visible": False},
            "CONTAINER_CACHE_TARGET_NOT_VISIBLE",
        ),
        (
            {"cache_target_identity_match": False},
            "CONTAINER_CACHE_TARGET_IDENTITY_MISMATCH",
        ),
        (
            {"base_python_visible": False},
            "QUALIFICATION_RUNTIME_BIND_NOT_VISIBLE",
        ),
        (
            {
                "base_loader_direct": "NOT_FOUND",
                "base_loader_default_cache": "NOT_FOUND",
            },
            "LOADER_NOT_RESOLVING_VALID_CACHE_ENTRY",
        ),
        (
            {"base_loader_inhibit_cache": "RESOLVED"},
            "LOADER_CACHE_VISIBILITY_UNCLASSIFIED",
        ),
        ({}, "LOADER_CACHE_EFFECTIVE"),
    ),
)
def test_container_loader_cache_classification_is_fixed_and_prioritized(
    changes: dict[str, object],
    classification: str,
) -> None:
    diagnostic = _effective_container_loader_cache_diagnostic(**changes)
    assert diagnostic.classification == classification
    _validate_container_loader_cache_diagnostic(diagnostic)


def test_container_loader_cache_safe_output_contains_no_raw_evidence() -> None:
    diagnostic = _effective_container_loader_cache_diagnostic()
    output = diagnostic.safe_message()
    assert set(line.split("=", 1)[0] for line in output.splitlines()) == {
        "HOST_LOADER_CACHE_PRESENT",
        "HOST_LOADER_CACHE_SHA256_VALID",
        "CONTAINER_LOADER_CACHE_PRESENT",
        "CONTAINER_LOADER_CACHE_REGULAR",
        "CONTAINER_LOADER_CACHE_BYTES_MATCH_HOST",
        "CONTAINER_CACHE_LIBPYTHON_ENTRY_COUNT",
        "CONTAINER_CACHE_LIBPYTHON_ENTRY_PRESENT",
        "CONTAINER_CACHE_TARGET_VISIBLE",
        "CONTAINER_CACHE_TARGET_IDENTITY_MATCH",
        "CONTAINER_BASE_PYTHON_FILE_VISIBLE",
        "CONTAINER_LIBPYTHON_FILE_VISIBLE",
        "BASE_LOADER_DIRECT_LIBPYTHON",
        "CANDIDATE_LOADER_DIRECT_LIBPYTHON",
        "BASE_LOADER_DEFAULT_CACHE_RESULT",
        "BASE_LOADER_INHIBIT_CACHE_RESULT",
        "CONTAINER_LOADER_CACHE_DIAGNOSTIC_CLASS",
    }
    assert "/" not in output
    assert re.search(r"\b[0-9a-f]{64}\b", output) is None
    assert _LIBPYTHON_SONAME not in output
    assert "not found" not in output.lower()
    assert not any(marker in output for marker in _PROTECTED_SECRET_MARKERS)


@pytest.mark.parametrize(
    "changes",
    (
        {"libpython_entry_count": -1},
        {"libpython_entry_count": True},
        {"base_loader_direct": "/run/raw/path"},
        {"candidate_loader_direct": "libpython => not found"},
    ),
)
def test_container_loader_cache_safe_output_rejects_untrusted_values(
    changes: dict[str, object],
) -> None:
    diagnostic = _effective_container_loader_cache_diagnostic(**changes)
    with pytest.raises(
        AssertionError,
        match="CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED",
    ):
        diagnostic.safe_values()


def test_container_loader_cache_raw_parsers_reject_secret_material() -> None:
    with pytest.raises(
        AssertionError,
        match="CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED",
    ):
        _container_cache_libpython_targets(
            "PASSWORD=synthetic\n"
            f"{_LIBPYTHON_SONAME} (libc6) => /run/lib/{_LIBPYTHON_SONAME}\n"
        )
    trusted = _TrustedLibpython(
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3/lib") / _LIBPYTHON_SONAME,
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3/lib"),
        "1" * 64,
    )
    with pytest.raises(
        AssertionError,
        match="CONTAINER_LOADER_CACHE_DIAGNOSTIC_REJECTED",
    ):
        _loader_libpython_result(
            subprocess.CompletedProcess(
                ("loader",), 1, "", "IMMICH__API_KEY=synthetic\n",
            ),
            trusted,
        )


def test_host_loader_cache_identity_revalidates_exact_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "root"
    cache = root / "etc/ld.so.cache"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"synthetic-cache")
    checked = []
    monkeypatch.setitem(
        globals(), "_assert_loader_cache_file", lambda path: checked.append(path),
    )
    assert _host_loader_cache_sha256(root) == sha256(
        b"synthetic-cache"
    ).hexdigest()
    assert checked == [cache]


def _cache_snapshot(digest: str = "1" * 64) -> _LoaderCacheSnapshot:
    return _LoaderCacheSnapshot(True, True, True, 0, 0, 0o644, 128, digest)


def _cache_writer_state(
    unit: str,
    *,
    executed: bool = False,
    start: int = 0,
    exit: int = 0,
) -> _CacheWriterServiceState:
    return _CacheWriterServiceState(
        unit,
        "loaded",
        "inactive",
        "dead",
        "success",
        1 if executed else 0,
        0,
        exit if executed else 0,
        exit if executed else 0,
        start if executed else 0,
        exit if executed else 0,
    )


def _boot_cache_diagnostic(
    *,
    changed: bool = True,
    ldconfig_executed: bool = True,
    ldconfig_start: int = 120,
    ldconfig_exit: int = 140,
    other_executed: bool = False,
    input_included: bool = False,
    post_libpython_entry_count: int = 0,
) -> _BootCacheAttributionDiagnostic:
    states = tuple(
        _cache_writer_state(
            unit,
            executed=(ldconfig_executed if index == 0 else other_executed),
            start=(ldconfig_start if index == 0 else 125),
            exit=(ldconfig_exit if index == 0 else 135),
        )
        for index, unit in enumerate(_CACHE_WRITER_UNITS)
    )
    return _BootCacheAttributionDiagnostic(
        _cache_snapshot("1" * 64),
        _cache_snapshot("2" * 64 if changed else "1" * 64),
        states,
        _LdConfigInputAuthority(False, False, 0, input_included),
        100,
        150,
        200,
        post_libpython_entry_count,
    )


@pytest.mark.parametrize(
    "diagnostic,writer_class,input_class",
    (
        (
            _boot_cache_diagnostic(),
            "LDCONFIG_SERVICE_CONFIRMED",
            "QUALIFICATION_RUNTIME_NOT_INCLUDED",
        ),
        (
            _boot_cache_diagnostic(ldconfig_exit=0),
            "LDCONFIG_SERVICE_EXECUTED_BUT_CAUSALITY_UNPROVEN",
            "WRITER_NOT_CONFIRMED",
        ),
        (
            _boot_cache_diagnostic(
                ldconfig_executed=False,
                other_executed=False,
            ),
            "CACHE_CHANGED_WITH_NO_ALLOWLISTED_WRITER",
            "WRITER_NOT_CONFIRMED",
        ),
        (
            _boot_cache_diagnostic(changed=False),
            "CACHE_NOT_CHANGED",
            "WRITER_NOT_CONFIRMED",
        ),
        (
            _boot_cache_diagnostic(input_included=True),
            "LDCONFIG_SERVICE_CONFIRMED",
            "QUALIFICATION_RUNTIME_INCLUDED",
        ),
        (
            replace(
                _boot_cache_diagnostic(),
                ldconfig_input=_LdConfigInputAuthority(
                    False, False, 0, False, valid=False,
                ),
            ),
            "LDCONFIG_SERVICE_CONFIRMED",
            "INPUT_AUTHORITY_UNKNOWN",
        ),
        (
            _boot_cache_diagnostic(
                ldconfig_executed=False,
                other_executed=True,
            ),
            "ATTRIBUTION_INSUFFICIENT",
            "WRITER_NOT_CONFIRMED",
        ),
    ),
)
def test_boot_cache_writer_classification_is_fixed_and_evidence_bound(
    diagnostic: _BootCacheAttributionDiagnostic,
    writer_class: str,
    input_class: str,
) -> None:
    assert diagnostic.writer_classification == writer_class
    assert diagnostic.writer_input_classification == input_class
    _validate_boot_cache_attribution(diagnostic)


def test_boot_cache_change_is_not_hidden_by_missing_or_untrusted_post_cache() -> None:
    missing = replace(
        _boot_cache_diagnostic(),
        post_boot=_LoaderCacheSnapshot(
            False, False, False, 0, 0, 0, 0, "",
        ),
    )
    assert missing.cache_changed
    assert missing.mutation_during_boot == "YES"
    assert missing.writer_classification == "ATTRIBUTION_INSUFFICIENT"
    weak_mode = replace(
        _boot_cache_diagnostic(),
        post_boot=replace(_cache_snapshot("2" * 64), mode=0o666),
    )
    assert weak_mode.cache_changed
    assert weak_mode.writer_classification == "ATTRIBUTION_INSUFFICIENT"


def test_boot_cache_writer_safe_output_is_allowlisted_and_path_free() -> None:
    diagnostic = _boot_cache_diagnostic()
    output = diagnostic.safe_message()
    assert "BOOT_CACHE_WRITER_CLASS=LDCONFIG_SERVICE_CONFIRMED" in output
    assert "BOOT_CACHE_WRITER_INPUT_CLASS=QUALIFICATION_RUNTIME_NOT_INCLUDED" in output
    assert "CACHE_MUTATION_OCCURRED_DURING_BOOT=YES" in output
    assert "LDCONFIG_EXECUTED_BEFORE_POST_BOOT_OBSERVATION=YES" in output
    assert "CACHE_WRITER_EXECUTED_UNITS=ldconfig.service" in output
    assert "/" not in output
    assert re.search(r"\b[0-9a-f]{64}\b", output) is None
    assert _LIBPYTHON_SONAME not in output
    assert not any(marker in output for marker in _PROTECTED_SECRET_MARKERS)


def test_cache_writer_query_is_fixed_read_only_and_rejects_unknown_unit() -> None:
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        values = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "InactiveExitTimestampMonotonic": "140",
            "ActiveEnterTimestampMonotonic": "140",
            "ExecMainStartTimestampMonotonic": "120",
            "ExecMainExitTimestampMonotonic": "140",
        }
        return subprocess.CompletedProcess(
            command,
            0,
            "".join(f"{name}={values[name]}\n" for name in _CACHE_WRITER_PROPERTIES),
            "",
        )

    state = _cache_writer_service_state(
        "pdi-p3d-1234567812345678",
        "ldconfig.service",
        runner=runner,
    )
    assert state.executed
    command, kwargs = calls[0]
    assert command[:5] == (
        str(SYSTEMCTL),
        "--machine=pdi-p3d-1234567812345678",
        "--no-pager",
        "show",
        "ldconfig.service",
    )
    assert command[5:] == tuple(
        f"--property={name}" for name in _CACHE_WRITER_PROPERTIES
    )
    assert kwargs["shell"] is False
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    with pytest.raises(
        AssertionError,
        match="BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED",
    ):
        _cache_writer_service_state(
            "pdi-p3d-1234567812345678",
            "arbitrary.service",
            runner=runner,
        )

    missing = _cache_writer_service_state(
        "pdi-p3d-1234567812345678",
        "ldconfig.service",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            4,
            "LoadState=not-found\n",
            "Unit ldconfig.service could not be found.\n",
        ),
    )
    assert missing.load_state == "not-found"
    assert not missing.executed


def test_boot_cache_attribution_collects_post_boot_authority_read_only() -> None:
    trusted = _TrustedLibpython(
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3/lib") / _LIBPYTHON_SONAME,
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3/lib"),
        "3" * 64,
    )

    def capture(leader, uid, gid, command):
        assert (leader, uid, gid) == (4321, 998, 997)
        if command[0] == str(TEST):
            path = command[-1]
            if path in {"/etc/ld.so.conf", "/etc/ld.so.conf.d"}:
                return subprocess.CompletedProcess(command, 1, "", "")
            return subprocess.CompletedProcess(
                command, 1 if command[1] == "-L" else 0, "", "",
            )
        if command[0] == str(STAT):
            return subprocess.CompletedProcess(
                command, 0, "128:0:0:644:regular file\n", "",
            )
        if command[0] == str(SHA256SUM):
            return subprocess.CompletedProcess(
                command, 0, f"{'2' * 64}  /etc/ld.so.cache\n", "",
            )
        raise AssertionError("UNEXPECTED_ATTRIBUTION_COMMAND")

    def systemd_runner(command, **kwargs):
        unit = command[4]
        executed = unit == "ldconfig.service"
        values = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainCode": "1" if executed else "0",
            "ExecMainStatus": "0",
            "InactiveExitTimestampMonotonic": "140" if executed else "0",
            "ActiveEnterTimestampMonotonic": "140" if executed else "0",
            "ExecMainStartTimestampMonotonic": "120" if executed else "0",
            "ExecMainExitTimestampMonotonic": "140" if executed else "0",
        }
        return subprocess.CompletedProcess(
            command,
            0,
            "".join(f"{name}={values[name]}\n" for name in _CACHE_WRITER_PROPERTIES),
            "",
        )

    diagnostic = _collect_boot_cache_attribution(
        machine="pdi-p3d-1234567812345678",
        leader=4321,
        runtime_uid=998,
        runtime_gid=997,
        trusted=trusted,
        pre_boot=_cache_snapshot("1" * 64),
        nspawn_start_monotonic_us=100,
        manager_registration_monotonic_us=150,
        post_libpython_entry_count=0,
        capture=capture,
        systemd_runner=systemd_runner,
        monotonic_ns=lambda: 200_000,
    )
    assert diagnostic.writer_classification == "LDCONFIG_SERVICE_CONFIRMED"
    assert (
        diagnostic.writer_input_classification
        == "QUALIFICATION_RUNTIME_NOT_INCLUDED"
    )
    assert diagnostic.mutation_during_boot == "YES"


def test_ldconfig_input_parser_rejects_raw_secret_and_unsafe_path() -> None:
    assert _validate_ld_so_conf_payload(
        "/run/pdi-p3d-wp7-runtime.A1b2C3/lib\n"
        "include /etc/ld.so.conf.d/*.conf\n"
    ) == ("/run/pdi-p3d-wp7-runtime.A1b2C3/lib",)
    for payload in (
        "DATABASE__URL=postgresql://secret\n",
        "/run/../tmp/escape\n",
        "relative/path\n",
    ):
        with pytest.raises(
            AssertionError,
            match="BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED",
        ):
            _validate_ld_so_conf_payload(payload)


def test_ldconfig_input_authority_finds_runtime_only_in_conf_d() -> None:
    runtime = Path("/run/pdi-p3d-wp7-runtime.A1b2C3")
    trusted = _TrustedLibpython(
        runtime / "lib" / _LIBPYTHON_SONAME,
        runtime / "lib",
        "1" * 64,
    )
    main = Path("/etc/ld.so.conf")
    conf_a = Path("/etc/ld.so.conf.d/a.conf")
    conf_b = Path("/etc/ld.so.conf.d/b.conf")

    def capture(leader, uid, gid, command):
        assert (leader, uid, gid) == (4321, 998, 997)
        if command[0] == str(TEST):
            return subprocess.CompletedProcess(
                command, 1 if command[1] == "-L" else 0, "", "",
            )
        if command[0] == str(FIND):
            return subprocess.CompletedProcess(
                command, 0, f"{conf_b}\n{conf_a}\n", "",
            )
        if command[0] == str(CAT):
            payload = {
                str(main): "include /etc/ld.so.conf.d/*.conf\n",
                str(conf_a): f"{trusted.directory}\n",
                str(conf_b): "/usr/local/lib\n",
            }[command[-1]]
            return subprocess.CompletedProcess(command, 0, payload, "")
        raise AssertionError("UNEXPECTED_LDCONFIG_INPUT_COMMAND")

    authority = _ldconfig_input_authority(
        4321,
        998,
        997,
        trusted,
        capture=capture,
    )
    assert authority.main_present
    assert not authority.main_includes_runtime
    assert authority.conf_d_file_count == 2
    assert authority.conf_d_includes_runtime
    assert authority.includes_runtime


def test_boot_cache_safe_output_rejects_raw_journal_or_runtime_path() -> None:
    raw_journal = replace(
        _boot_cache_diagnostic(),
        ldconfig_journal_class="started /run/private",
    )
    with pytest.raises(
        AssertionError,
        match="BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED",
    ):
        raw_journal.safe_values()
    unsafe_state = replace(
        _boot_cache_diagnostic().ldconfig_state,
        unit="/run/pdi-p3d-wp7-runtime.private",
    )
    unsafe_diagnostic = replace(
        _boot_cache_diagnostic(),
        writer_states=(
            unsafe_state,
            *_boot_cache_diagnostic().writer_states[1:],
        ),
    )
    with pytest.raises(
        AssertionError,
        match="BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_REJECTED",
    ):
        unsafe_diagnostic.safe_values()


def test_container_python_preflight_requires_both_runtimes_and_clean_elf() -> None:
    probed = []
    inspected = []

    def python_probe(leader, uid, gid, python):
        probed.append((leader, uid, gid, python))
        return 0

    def elf_probe(leader, uid, gid, python):
        inspected.append((leader, uid, gid, python))
        return _ELF_OK

    candidate = "a" * 40
    result = _verify_container_python_preflight(
        leader=4321,
        runtime_uid=998,
        runtime_gid=997,
        system_python=Path("/run/pdi-p3d-wp7-runtime.A1b2C3/bin/python"),
        candidate=candidate,
        python_probe=python_probe,
        elf_probe=elf_probe,
    )
    assert result.candidate_probe_rc == 0 and result.base_probe_rc == 0
    assert [item[-1] for item in probed] == [
        Path(f"/opt/pdi/releases/{candidate}/.venv/bin/python"),
        Path("/run/pdi-p3d-wp7-runtime.A1b2C3/bin/python"),
    ]
    assert inspected == probed


@pytest.mark.parametrize(
    "candidate_rc,base_rc,candidate_elf,base_elf,classification",
    (
        (127, 127, _ELF_OK, _ELF_OK, "BOTH_PYTHON_PROBES_FAILED"),
        (127, 0, _ELF_OK, _ELF_OK, "CANDIDATE_PYTHON_PROBE_FAILED"),
        (0, 127, _ELF_OK, _ELF_OK, "BASE_PYTHON_PROBE_FAILED"),
        (
            0,
            0,
            _ElfDependencyDiagnostic(True, True, (_LIBPYTHON_SONAME,)),
            _ElfDependencyDiagnostic(True, True, (_LIBPYTHON_SONAME,)),
            "BOTH_PYTHONS_MISSING_LIBRARY",
        ),
        (
            0,
            0,
            _ElfDependencyDiagnostic(
                True, True, (_LIBPYTHON_SONAME,),
            ),
            _ELF_OK,
            "CANDIDATE_PYTHON_MISSING_LIBRARY",
        ),
        (
            0,
            0,
            _ELF_OK,
            _ElfDependencyDiagnostic(
                True, True, (_LIBPYTHON_SONAME,),
            ),
            "BASE_PYTHON_MISSING_LIBRARY",
        ),
        (
            0,
            0,
            _ElfDependencyDiagnostic(False, False, ()),
            _ElfDependencyDiagnostic(False, False, ()),
            "BOTH_ELF_INVALID",
        ),
        (
            0,
            0,
            _ElfDependencyDiagnostic(False, False, ()),
            _ELF_OK,
            "CANDIDATE_ELF_INVALID",
        ),
        (
            0,
            0,
            _ELF_OK,
            _ElfDependencyDiagnostic(False, False, ()),
            "BASE_ELF_INVALID",
        ),
    ),
)
def test_container_python_preflight_fails_closed_before_workload(
    candidate_rc: int,
    base_rc: int,
    candidate_elf: _ElfDependencyDiagnostic,
    base_elf: _ElfDependencyDiagnostic,
    classification: str,
) -> None:
    probe_results = [candidate_rc, base_rc]
    elf_results = [candidate_elf, base_elf]
    probe_calls = []
    elf_calls = []

    def python_probe(*args):
        probe_calls.append(args)
        return probe_results[len(probe_calls) - 1]

    def elf_probe(*args):
        elf_calls.append(args)
        return elf_results[len(elf_calls) - 1]

    with pytest.raises(_QualificationPythonPreflightError) as raised:
        _verify_container_python_preflight(
            leader=4321,
            runtime_uid=998,
            runtime_gid=997,
            system_python=Path(
                "/run/pdi-p3d-wp7-runtime.A1b2C3/bin/python"
            ),
            candidate="a" * 40,
            python_probe=python_probe,
            elf_probe=elf_probe,
        )
    error = raised.value
    assert error.classification == classification
    assert set(error.__dict__) == {
        "candidate_probe_rc",
        "base_probe_rc",
        "candidate_elf",
        "base_elf",
        "classification",
    }
    assert len(probe_calls) == 2
    assert len(elf_calls) == 2
    output = error.safe_message()
    values = dict(line.split("=", 1) for line in output.splitlines())
    assert values == {
        "QUALIFICATION_PYTHON_PREFLIGHT": "FAIL",
        "CONTAINER_BASE_PYTHON_PROBE_RC": str(base_rc),
        "CONTAINER_CANDIDATE_PYTHON_PROBE_RC": str(candidate_rc),
        "BASE_PYTHON_ELF_DYNAMIC": "YES" if base_elf.dynamic else "NO",
        "BASE_PYTHON_INTERPRETER_PRESENT": (
            "YES" if base_elf.interpreter_present else "NO"
        ),
        "BASE_PYTHON_MISSING_LIBRARY_COUNT": str(
            len(base_elf.missing_libraries)
        ),
        "BASE_PYTHON_MISSING_LIBRARIES": (
            ",".join(base_elf.missing_libraries) or "NONE"
        ),
        "CANDIDATE_PYTHON_ELF_DYNAMIC": (
            "YES" if candidate_elf.dynamic else "NO"
        ),
        "CANDIDATE_PYTHON_INTERPRETER_PRESENT": (
            "YES" if candidate_elf.interpreter_present else "NO"
        ),
        "CANDIDATE_PYTHON_MISSING_LIBRARY_COUNT": str(
            len(candidate_elf.missing_libraries)
        ),
        "CANDIDATE_PYTHON_MISSING_LIBRARIES": (
            ",".join(candidate_elf.missing_libraries) or "NONE"
        ),
        "QUALIFICATION_PYTHON_PREFLIGHT_CLASS": classification,
    }
    assert "/" not in output
    assert "not found" not in output
    assert not any(marker in output for marker in _PROTECTED_SECRET_MARKERS)


@pytest.mark.parametrize(
    "diagnostic,classification",
    (
        (
            _QualificationPythonPreflight(
                "0", 0, _ELF_OK, _ELF_OK,  # type: ignore[arg-type]
            ),
            "QUALIFICATION_PYTHON_PREFLIGHT_UNCLASSIFIED",
        ),
        (
            _QualificationPythonPreflight(
                0,
                0,
                _ElfDependencyDiagnostic(True, True, ("/tmp/libpython.so",)),
                _ELF_OK,
            ),
            "CANDIDATE_PYTHON_MISSING_LIBRARY",
        ),
        (
            _QualificationPythonPreflight(
                0,
                0,
                _ElfDependencyDiagnostic(
                    True, True, ("libpython.so => not found",),
                ),
                _ELF_OK,
            ),
            "CANDIDATE_PYTHON_MISSING_LIBRARY",
        ),
        (
            _QualificationPythonPreflight(0, 0, _ELF_OK, _ELF_OK),
            "FREE_FORM_CLASSIFICATION",
        ),
    ),
)
def test_python_preflight_safe_serialization_rejects_non_allowlisted_values(
    diagnostic: _QualificationPythonPreflight,
    classification: str,
) -> None:
    with pytest.raises(
        AssertionError,
        match="QUALIFICATION_PYTHON_PREFLIGHT_DIAGNOSTIC_REJECTED",
    ):
        diagnostic.safe_values(classification)


def test_python_preflight_classification_priority_is_deterministic() -> None:
    diagnostic = _QualificationPythonPreflight(
        127,
        127,
        _ElfDependencyDiagnostic(False, False, (_LIBPYTHON_SONAME,)),
        _ElfDependencyDiagnostic(False, False, (_LIBPYTHON_SONAME,)),
    )
    assert (
        _qualification_python_preflight_failure_class(diagnostic)
        == "BOTH_PYTHON_PROBES_FAILED"
    )
    assert (
        _qualification_python_preflight_failure_class(
            _QualificationPythonPreflight(0, 0, _ELF_OK, _ELF_OK)
        )
        == "QUALIFICATION_PYTHON_PREFLIGHT_UNCLASSIFIED"
    )


def test_rootfs_default_target_remains_basic_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(os, "chown", lambda *args: None)
    monkeypatch.setitem(
        globals(),
        "_materialize_rootfs_os_release",
        lambda root: b"trusted-os-release\n",
    )
    root = tmp_path / "root"
    _prepare_rootfs(root, 65534, 65534)
    default_target = root / "etc/systemd/system/default.target"
    assert default_target.is_symlink()
    assert os.readlink(default_target) == "/usr/lib/systemd/system/basic.target"


def test_trusted_host_os_release_accepts_resolved_root_authority(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "os-release"
    candidate.symlink_to("/usr/lib/os-release")
    resolved, payload = _trusted_host_os_release((candidate,))
    info = resolved.stat()
    assert resolved == Path("/usr/lib/os-release").resolve(strict=True)
    assert stat.S_ISREG(info.st_mode)
    assert info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022
    assert payload and payload == resolved.read_bytes()


def test_trusted_host_os_release_rejects_missing_source(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="ROOTFS_OS_RELEASE_SOURCE_MISSING"):
        _trusted_host_os_release((tmp_path / "missing-os-release",))


def test_trusted_host_os_release_rejects_writable_source(tmp_path: Path) -> None:
    source = tmp_path / "writable-os-release"
    source.write_bytes(b"ID=synthetic\n")
    source.chmod(0o666)
    with pytest.raises(AssertionError, match="ROOTFS_OS_RELEASE_SOURCE_UNTRUSTED"):
        _trusted_host_os_release((source,))


def test_trusted_host_os_release_rejects_non_regular_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "os-release-directory"
    source.mkdir()
    candidate = tmp_path / "os-release-link"
    candidate.symlink_to(source, target_is_directory=True)
    with pytest.raises(
        AssertionError,
        match="ROOTFS_OS_RELEASE_SOURCE_NOT_REGULAR",
    ):
        _trusted_host_os_release((candidate,))


def test_trusted_host_os_release_rejects_empty_source(tmp_path: Path) -> None:
    source = tmp_path / "empty-os-release"
    source.write_bytes(b"")
    source.chmod(0o644)
    with pytest.raises(AssertionError, match="ROOTFS_OS_RELEASE_SOURCE_EMPTY"):
        _trusted_host_os_release((source,))


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership assertion")
def test_rootfs_os_release_is_materialized_from_exact_trusted_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    source, expected = _trusted_host_os_release()
    actual = _materialize_rootfs_os_release(root)
    destination = root / "etc/os-release"
    _assert_materialized_os_release(root, expected)
    assert source.is_file()
    assert actual == expected == destination.read_bytes()
    assert not destination.is_symlink()


def _secure_diagnostic_stream(path: Path):
    parent = path.parent
    if parent.exists() or parent.is_symlink():
        existing = parent.lstat()
        assert stat.S_ISDIR(existing.st_mode) and not parent.is_symlink()
    else:
        parent.mkdir(mode=0o700)
    os.chown(parent, 0, 0)
    os.chmod(parent, 0o700)
    parent_info = parent.lstat()
    assert stat.S_ISDIR(parent_info.st_mode) and not parent.is_symlink()
    assert parent_info.st_uid == 0 and parent_info.st_gid == 0
    assert stat.S_IMODE(parent_info.st_mode) == 0o700
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        assert stat.S_ISREG(info.st_mode)
        assert info.st_uid == 0 and info.st_gid == 0
        assert stat.S_IMODE(info.st_mode) == 0o600
        return os.fdopen(descriptor, "wb", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


def _sanitize_diagnostic(value: str, secret_values: tuple[str, ...]) -> str:
    sanitized = value
    for secret in sorted((item for item in secret_values if item), key=len, reverse=True):
        sanitized = sanitized.replace(secret, "[REDACTED]")
    return _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        sanitized,
    )


def _read_diagnostic(
    path: Path,
    secret_values: tuple[str, ...],
) -> tuple[str, str]:
    payload = path.read_bytes()
    digest = sha256(payload).hexdigest()
    excerpt = payload[-_DIAGNOSTIC_LIMIT:].decode("utf-8", errors="replace")
    return digest, _sanitize_diagnostic(excerpt, secret_values)


def _contains_unsafe_secret_material(
    value: str,
    secret_values: tuple[str, ...],
) -> bool:
    folded = value.casefold()
    if any(marker.casefold() in folded for marker in _PROTECTED_SECRET_MARKERS):
        return True
    if any(secret in value for secret in secret_values if secret):
        return True
    return _SECRET_ASSIGNMENT.search(value) is not None


def _escaped_tail(value: str, limit: int) -> str:
    pieces = []
    length = 0
    for character in reversed(value):
        escaped = json.dumps(character, ensure_ascii=False)[1:-1]
        if length + len(escaped) > limit:
            break
        pieces.append(escaped)
        length += len(escaped)
    return "".join(reversed(pieces))


def _safe_diagnostic_excerpts(
    nspawn_stderr: str,
    machinectl_stderr: str,
    secret_values: tuple[str, ...],
) -> tuple[str, str, str]:
    if any(
        _contains_unsafe_secret_material(value, secret_values)
        for value in (nspawn_stderr, machinectl_stderr)
    ):
        return "REDACTED", "", ""
    return (
        "PASS",
        _escaped_tail(nspawn_stderr, 1024),
        _escaped_tail(machinectl_stderr, 512),
    )


def _diagnostic_class(*values: str) -> str:
    combined = "\n".join(values).casefold()
    categories = (
        (
            "MOUNT_OR_BIND_FAILURE",
            ("failed to mount", "mount failed", "failed to bind", "bind mount"),
        ),
        (
            "ROOTFS_FAILURE",
            ("invalid rootfs", "root directory", "os tree", "root filesystem"),
        ),
        (
            "NAMESPACE_OR_CGROUP_FAILURE",
            ("namespace", "failed to clone", "failed to unshare", "cgroup"),
        ),
        (
            "MACHINE_REGISTRATION_FAILURE",
            ("no machine", "not registered", "failed to register machine"),
        ),
        (
            "PID1_EXEC_FAILURE",
            (
                "failed to execute /sbin/init",
                "failed to execute /usr/lib/systemd/systemd",
                "failed to exec pid 1",
            ),
        ),
        (
            "SYSTEMD_BOOT_FAILURE",
            (
                "failed to boot",
                "failed to start systemd",
                "failed to invoke systemd",
                "pid 1 exited",
            ),
        ),
    )
    for category, markers in categories:
        if any(marker in combined for marker in markers):
            return category
    return "UNCLASSIFIED"


def _manager_startup_error(
    failure_class: str,
    *,
    machine_process,
    nspawn_stdout: Path,
    nspawn_stderr: Path,
    last_machinectl,
    secret_values: tuple[str, ...],
) -> _ManagerStartupError:
    stdout_sha, sanitized_stdout = _read_diagnostic(nspawn_stdout, secret_values)
    stderr_sha, sanitized_stderr = _read_diagnostic(nspawn_stderr, secret_values)
    machinectl_return_code = -1
    machinectl_stdout = ""
    machinectl_stderr = ""
    if last_machinectl is not None:
        machinectl_return_code = last_machinectl.returncode
        machinectl_stdout = _sanitize_diagnostic(last_machinectl.stdout, secret_values)
        machinectl_stderr = _sanitize_diagnostic(last_machinectl.stderr, secret_values)
    safe_state, nspawn_safe_excerpt, machinectl_safe_excerpt = (
        _safe_diagnostic_excerpts(
            sanitized_stderr,
            machinectl_stderr,
            secret_values,
        )
    )
    diagnostic = _ManagerStartupDiagnostic(
        failure_class=failure_class,
        diagnostic_class=_diagnostic_class(
            sanitized_stdout,
            sanitized_stderr,
            machinectl_stdout,
            machinectl_stderr,
        ),
        nspawn_exit_code=machine_process.poll(),
        nspawn_stdout_sha256=stdout_sha,
        nspawn_stderr_sha256=stderr_sha,
        machinectl_return_code=machinectl_return_code,
        machinectl_stdout_sha256=sha256(machinectl_stdout.encode()).hexdigest(),
        machinectl_stderr_sha256=sha256(machinectl_stderr.encode()).hexdigest(),
        diagnostic_safe_excerpt=safe_state,
        nspawn_stderr_safe_excerpt=nspawn_safe_excerpt,
        machinectl_stderr_safe_excerpt=machinectl_safe_excerpt,
        sanitized_nspawn_stdout=sanitized_stdout,
        sanitized_nspawn_stderr=sanitized_stderr,
        sanitized_machinectl_stdout=machinectl_stdout,
        sanitized_machinectl_stderr=machinectl_stderr,
    )
    return _ManagerStartupError(diagnostic)


def _wait_for_machine(
    machine: str,
    machine_process,
    *,
    nspawn_stdout: Path,
    nspawn_stderr: Path,
    secret_values: tuple[str, ...] = (),
    timeout: float = 30,
    runner=subprocess.run,
    monotonic=time.monotonic,
    sleeper=time.sleep,
) -> int:
    deadline = monotonic() + timeout
    last_machinectl = None
    while monotonic() < deadline:
        if machine_process.poll() is not None:
            raise _manager_startup_error(
                "DISPOSABLE_SYSTEMD_MANAGER_EXITED_EARLY",
                machine_process=machine_process,
                nspawn_stdout=nspawn_stdout,
                nspawn_stderr=nspawn_stderr,
                last_machinectl=last_machinectl,
                secret_values=secret_values,
            )
        result = runner(
            (str(MACHINECTL), "show", machine, "--property=Leader", "--value"),
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        last_machinectl = result
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
        sleeper(0.25)
    if machine_process.poll() is not None:
        raise _manager_startup_error(
            "DISPOSABLE_SYSTEMD_MANAGER_EXITED_EARLY",
            machine_process=machine_process,
            nspawn_stdout=nspawn_stdout,
            nspawn_stderr=nspawn_stderr,
            last_machinectl=last_machinectl,
            secret_values=secret_values,
        )
    raise _manager_startup_error(
        "DISPOSABLE_SYSTEMD_MANAGER_REGISTRATION_TIMEOUT",
        machine_process=machine_process,
        nspawn_stdout=nspawn_stdout,
        nspawn_stderr=nspawn_stderr,
        last_machinectl=last_machinectl,
        secret_values=secret_values,
    )


class _SyntheticProcess:
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode

    def poll(self):
        return self.returncode


def _synthetic_diagnostics(tmp_path: Path) -> tuple[Path, Path]:
    stdout = tmp_path / "nspawn.stdout"
    stderr = tmp_path / "nspawn.stderr"
    stdout.write_text("", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    return stdout, stderr


def test_wait_for_machine_detects_early_exit_with_sanitized_diagnostics(
    tmp_path: Path,
) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    secret = "postgresql://synthetic:do-not-print@127.0.0.1/test"
    stderr.write_text(
        f"Failed to mount rootfs DATABASE__URL={secret}\n",
        encoding="utf-8",
    )

    def unexpected_runner(*args, **kwargs):
        raise AssertionError("machinectl must not run after child exit")

    with pytest.raises(_ManagerStartupError) as raised:
        _wait_for_machine(
            "pdi-p3d-synthetic",
            _SyntheticProcess(1),
            nspawn_stdout=stdout,
            nspawn_stderr=stderr,
            secret_values=(secret, "do-not-print"),
            runner=unexpected_runner,
        )

    diagnostic = raised.value.diagnostic
    assert diagnostic.failure_class == "DISPOSABLE_SYSTEMD_MANAGER_EXITED_EARLY"
    assert diagnostic.nspawn_exit_code == 1
    assert diagnostic.diagnostic_class == "MOUNT_OR_BIND_FAILURE"
    assert diagnostic.machinectl_return_code == -1
    assert "[REDACTED]" in diagnostic.sanitized_nspawn_stderr
    assert secret not in diagnostic.sanitized_nspawn_stderr
    assert secret not in str(raised.value)
    assert diagnostic.diagnostic_safe_excerpt == "REDACTED"
    assert "DIAGNOSTIC_SAFE_EXCERPT=REDACTED" in str(raised.value)
    assert "NSPAWN_STDERR_SAFE_EXCERPT=" not in str(raised.value)


def test_wait_for_machine_emits_safe_nspawn_stderr_excerpt(tmp_path: Path) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    stderr.write_text(
        "Failed to execute /usr/lib/systemd/systemd\nSecond safe line\n",
        encoding="utf-8",
    )

    with pytest.raises(_ManagerStartupError) as raised:
        _wait_for_machine(
            "pdi-p3d-synthetic",
            _SyntheticProcess(1),
            nspawn_stdout=stdout,
            nspawn_stderr=stderr,
            runner=lambda *args, **kwargs: None,
        )

    diagnostic = raised.value.diagnostic
    assert diagnostic.diagnostic_class == "PID1_EXEC_FAILURE"
    assert diagnostic.diagnostic_safe_excerpt == "PASS"
    assert diagnostic.nspawn_stderr_safe_excerpt == (
        "Failed to execute /usr/lib/systemd/systemd\\nSecond safe line\\n"
    )
    assert "NSPAWN_STDERR_SAFE_EXCERPT=" in str(raised.value)
    assert "Second safe line\\n" in str(raised.value)


def test_wait_for_machine_distinguishes_registration_timeout(tmp_path: Path) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    clock = [0.0]
    calls = []

    def monotonic():
        return clock[0]

    def sleeper(interval):
        clock[0] += interval

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 1, "", "No machine known\n")

    with pytest.raises(_ManagerStartupError) as raised:
        _wait_for_machine(
            "pdi-p3d-synthetic",
            _SyntheticProcess(None),
            nspawn_stdout=stdout,
            nspawn_stderr=stderr,
            timeout=0.5,
            runner=runner,
            monotonic=monotonic,
            sleeper=sleeper,
        )

    diagnostic = raised.value.diagnostic
    assert diagnostic.failure_class == (
        "DISPOSABLE_SYSTEMD_MANAGER_REGISTRATION_TIMEOUT"
    )
    assert diagnostic.nspawn_exit_code is None
    assert diagnostic.diagnostic_class == "MACHINE_REGISTRATION_FAILURE"
    assert diagnostic.machinectl_return_code == 1
    assert diagnostic.sanitized_machinectl_stderr == "No machine known\n"
    assert diagnostic.diagnostic_safe_excerpt == "PASS"
    assert diagnostic.machinectl_stderr_safe_excerpt == "No machine known\\n"
    assert "MACHINECTL_STDERR_SAFE_EXCERPT=No machine known\\n" in str(
        raised.value
    )
    assert len(calls) == 2


def test_safe_diagnostic_excerpt_escapes_newlines_and_caps_lengths() -> None:
    nspawn = "nspawn diagnostic\n" * 200
    machinectl = "machine diagnostic\n" * 100
    state, nspawn_excerpt, machinectl_excerpt = _safe_diagnostic_excerpts(
        nspawn,
        machinectl,
        (),
    )
    assert state == "PASS"
    assert len(nspawn_excerpt) <= 1024
    assert len(machinectl_excerpt) <= 512
    assert "\n" not in nspawn_excerpt and "\r" not in nspawn_excerpt
    assert "\n" not in machinectl_excerpt and "\r" not in machinectl_excerpt
    assert "\\n" in nspawn_excerpt
    assert "\\n" in machinectl_excerpt


@pytest.mark.parametrize(
    ("nspawn", "machinectl", "secret_values"),
    (
        ("DATABASE__URL=[REDACTED]", "", ()),
        ("PASSWORD=[REDACTED]", "", ()),
        ("ordinary leaked-value text", "", ("leaked-value",)),
        ("", "IMMICH__API_KEY=[REDACTED]", ()),
    ),
)
def test_unsafe_diagnostic_excerpt_is_suppressed(
    nspawn: str,
    machinectl: str,
    secret_values: tuple[str, ...],
) -> None:
    assert _safe_diagnostic_excerpts(
        nspawn,
        machinectl,
        secret_values,
    ) == ("REDACTED", "", "")


def test_diagnostic_class_prefers_specific_failure_over_systemd_boot() -> None:
    assert _diagnostic_class(
        "Failed to mount root filesystem; failed to boot systemd",
    ) == "MOUNT_OR_BIND_FAILURE"
    assert _diagnostic_class(
        "Failed to unshare namespace before failed to boot",
    ) == "NAMESPACE_OR_CGROUP_FAILURE"


def test_plain_systemd_occurrence_is_not_systemd_boot_failure() -> None:
    assert _diagnostic_class(
        "systemd-nspawn terminated before registration",
    ) == "UNCLASSIFIED"
    assert _diagnostic_class(
        "Failed to invoke systemd",
    ) == "SYSTEMD_BOOT_FAILURE"


def test_wait_for_machine_accepts_successful_registration(tmp_path: Path) -> None:
    stdout, stderr = _synthetic_diagnostics(tmp_path)
    calls = []

    def runner(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, "4321\n", "")

    assert _wait_for_machine(
        "pdi-p3d-synthetic",
        _SyntheticProcess(None),
        nspawn_stdout=stdout,
        nspawn_stderr=stderr,
        runner=runner,
    ) == 4321
    assert len(calls) == 1


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership assertion")
def test_nspawn_diagnostic_stream_is_root_only(tmp_path: Path) -> None:
    stdout = tmp_path / "diagnostics/nspawn.stdout"
    stderr = tmp_path / "diagnostics/nspawn.stderr"
    streams = (
        _secure_diagnostic_stream(stdout),
        _secure_diagnostic_stream(stderr),
    )
    try:
        for path in (stdout, stderr):
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
            assert info.st_uid == 0 and info.st_gid == 0
            assert stat.S_IMODE(info.st_mode) == 0o600
        parent = stdout.parent.lstat()
        assert parent.st_uid == 0 and parent.st_gid == 0
        assert stat.S_IMODE(parent.st_mode) == 0o700
    finally:
        for stream in streams:
            stream.close()


def _write_failure_journal_fixture(
    root: Path,
    operation_id: str,
    verified: tuple[str, ...],
) -> None:
    authority = root / "var/lib/pdi-p3d/rehearsal" / operation_id
    authority.mkdir(parents=True)
    authority.chmod(0o700)
    events: list[tuple[str, dict[str, object]]] = [
        ("NEW", {"candidate_sha": "a" * 40}),
        ("PREPARATION_VERIFIED", {}),
        ("SYSTEMD_MANAGER_VERIFIED", {}),
        ("CANDIDATE_PROMOTED", {}),
        ("SYSTEMD_RELOADED", {}),
        ("SERVICES_VERIFIED", {}),
        *(("PIPELINE_VERIFIED", {"pipeline_key": key}) for key in verified),
    ]
    failed = CANONICAL_PIPELINES[len(verified)]
    events.append(("FAILED", {
        "failure_code": "P3D_REHEARSAL_SERVICE_FAILED",
        "last_start_pipeline_key": failed,
        "last_start_unit": SERVICE_UNITS[failed],
        "last_start_return_code": 1,
        "service_load_state": "loaded",
        "service_active_state": "failed",
        "service_sub_state": "failed",
        "service_result": "exit-code",
        "service_exec_main_status": "1",
        "service_exec_main_code": "1",
        "service_status_errno": "0",
    }))
    for sequence, (event, evidence) in enumerate(events, start=1):
        path = authority / f"journal-{sequence:06d}.json"
        path.write_text(json.dumps({
            "version": 1,
            "sequence": sequence,
            "rehearsal_operation_id": operation_id,
            "event": event,
            "timestamp": "2026-09-29T00:00:00Z",
            "evidence": evidence,
        }), encoding="utf-8")
        path.chmod(0o600)


@pytest.mark.parametrize("verified_count", range(6))
def test_failure_journal_derives_exact_next_canonical_pipeline(
    tmp_path: Path,
    verified_count: int,
) -> None:
    operation_id = str(uuid4())
    verified = CANONICAL_PIPELINES[:verified_count]
    _write_failure_journal_fixture(tmp_path, operation_id, verified)
    result = _read_failure_journal(
        tmp_path,
        operation_id,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
    )
    assert result.verified_pipelines == verified
    assert result.failed_pipeline_key == CANONICAL_PIPELINES[verified_count]
    assert result.failed_service_unit == SERVICE_UNITS[result.failed_pipeline_key]
    assert result.systemctl_start_return_code == 1
    assert result.service_state == {
        "LoadState": "loaded",
        "ActiveState": "failed",
        "SubState": "failed",
        "Result": "exit-code",
        "ExecMainStatus": "1",
        "ExecMainCode": "1",
        "StatusErrno": "0",
    }
    assert result.last_event == (
        "SERVICES_VERIFIED" if verified_count == 0 else "PIPELINE_VERIFIED"
    )


def test_failure_journal_rejects_noncanonical_pipeline_sequence(
    tmp_path: Path,
) -> None:
    operation_id = str(uuid4())
    _write_failure_journal_fixture(
        tmp_path, operation_id, (CANONICAL_PIPELINES[1],),
    )
    with pytest.raises(AssertionError, match="JOURNAL_DIAGNOSTIC_REJECTED"):
        _read_failure_journal(
            tmp_path,
            operation_id,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )


def test_failed_service_query_uses_only_safe_property_allowlist() -> None:
    values = {
        "LoadState": "loaded",
        "ActiveState": "failed",
        "SubState": "failed",
        "Result": "exit-code",
        "ExecMainStatus": "1",
        "ExecMainCode": "1",
        "StatusErrno": "0",
    }
    commands = []

    def runner(argv, **kwargs):
        commands.append(tuple(argv))
        return subprocess.CompletedProcess(
            argv, 0, "".join(f"{key}={value}\n" for key, value in values.items()), "",
        )

    result = _read_failed_service_state(
        "pdi-p3d-1234567812345678",
        CANONICAL_PIPELINES[0],
        runner=runner,
    )
    assert result == values
    command = commands[0]
    assert command[3:5] == (
        "show", "pdi-scoped-pipeline@enrichment.nextcloud_text.service",
    )
    assert set(command[5:]) == {
        "--property=LoadState", "--property=ActiveState",
        "--property=SubState", "--property=Result",
        "--property=ExecMainStatus", "--property=ExecMainCode",
        "--property=StatusErrno",
    }
    assert all(
        forbidden not in " ".join(command)
        for forbidden in ("Environment", "EnvironmentFiles", "ExecStart")
    )


def test_failed_service_query_rejects_extra_or_freeform_properties() -> None:
    output = (
        "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
        "Result=exit-code\nExecMainStatus=1\nExecMainCode=1\nStatusErrno=0\n"
        "Environment=PASSWORD=unsafe\n"
    )
    with pytest.raises(DisposableRehearsalError, match="DIAGNOSTIC_INVALID"):
        _read_failed_service_state(
            "pdi-p3d-1234567812345678",
            CANONICAL_PIPELINES[0],
            runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, output, "",
            ),
        )


def test_failed_service_query_rejects_invalid_status_errno() -> None:
    values = {
        "LoadState": "loaded", "ActiveState": "failed",
        "SubState": "failed", "Result": "exit-code",
        "ExecMainStatus": "127", "ExecMainCode": "1",
        "StatusErrno": "4096",
    }
    with pytest.raises(DisposableRehearsalError, match="DIAGNOSTIC_INVALID"):
        MachineSystemdBackend.validate_service_failure_state(values)


class _FailureRows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return list(self.rows)


class _FailureConnection:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, parameters):
        self.statements.append((str(statement), parameters))
        return _FailureRows(self.rows)


class _FailureEngine:
    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


def test_pipeline_run_failure_diagnostic_is_select_only_and_aggregate() -> None:
    key = CANONICAL_PIPELINES[1]
    connection = _FailureConnection((
        (CANONICAL_PIPELINES[0], "completed", True, None),
        (key, "failed", True, "execution_failed"),
    ))
    result = _read_pipeline_run_failure(
        _FailureEngine(connection),
        "synthetic-boundary",
        key,
    )
    assert result == _PipelineRunFailureDiagnostic(
        2, 1, 1, True, "failed", True, "execution_failed",
    )
    sql, parameters = connection.statements[0]
    assert sql.lstrip().upper().startswith("SELECT ")
    assert all(
        keyword not in sql.upper()
        for keyword in ("INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ")
    )
    assert parameters == {"after": "synthetic-boundary"}


def test_pipeline_run_failure_diagnostic_reports_absent_failed_run() -> None:
    connection = _FailureConnection(())
    result = _read_pipeline_run_failure(
        _FailureEngine(connection),
        "synthetic-boundary",
        CANONICAL_PIPELINES[0],
    )
    assert result == _PipelineRunFailureDiagnostic(
        0, 0, 0, False, None, None, None,
    )


def test_provider_and_combined_failure_diagnostic_emit_counts_and_allowlists_only() -> None:
    counts = _provider_call_counts((
        "nextcloud-propfind", "nextcloud-content", "nextcloud-content",
    ))
    state = {
        "LoadState": "loaded", "ActiveState": "failed",
        "SubState": "failed", "Result": "exit-code",
        "ExecMainStatus": "1", "ExecMainCode": "1", "StatusErrno": "0",
    }
    journal = _RehearsalFailureJournalDiagnostic(
        "SERVICES_VERIFIED", (), CANONICAL_PIPELINES[0],
        SERVICE_UNITS[CANONICAL_PIPELINES[0]], 1, state,
    )
    runs = _PipelineRunFailureDiagnostic(0, 0, 0, False, None, None, None)
    diagnostic = _ServiceFailureDiagnostic(
        journal, state, runs, counts,
        _service_failure_class(journal, state, runs),
    ).safe_message()
    assert "NEXTCLOUD_PROPFIND_CALL_COUNT=1" in diagnostic
    assert "NEXTCLOUD_CONTENT_CALL_COUNT=2" in diagnostic
    assert "IMMICH_ACCOUNT_CALL_COUNT=0" in diagnostic
    assert "IMMICH_OCR_CALL_COUNT=0" in diagnostic
    assert "SERVICE_FAILURE_CLASS=SERVICE_START_COMMAND_FAILED" in diagnostic
    assert "FAILED_SERVICE_STATUS_ERRNO=0" in diagnostic
    assert all(secret not in diagnostic for secret in (
        "DATABASE__URL", "PASSWORD", "IMMICH__API_KEY",
        "synthetic-nextcloud-password", "raw journal", "traceback",
    ))
    with pytest.raises(AssertionError, match="PROVIDER_DIAGNOSTIC_REJECTED"):
        _provider_call_counts(("Authorization: secret",))


@pytest.mark.parametrize(
    "candidate_rc,base_rc,sandbox_rc,candidate_elf,base_elf,physical,logical,expected",
    (
        (
            127, 0, -1, _ELF_OK, _ELF_OK, 0, 0,
            "CANDIDATE_VENV_NOT_EXECUTABLE_IN_CONTAINER",
        ),
        (
            127, 127, -1, _ELF_OK, _ELF_OK, 0, 0,
            "BASE_RUNTIME_NOT_EXECUTABLE_IN_CONTAINER",
        ),
        (
            0, 0, 127, _ELF_OK, _ELF_OK, 0, 0,
            "SYSTEMD_SANDBOX_RUNTIME_FAILURE",
        ),
        (
            127, 0, -1,
            _ElfDependencyDiagnostic(True, True, ("libpython3.13.so.1.0",)),
            _ELF_OK, 0, 0, "DYNAMIC_LIBRARY_RESOLUTION_FAILURE",
        ),
        (
            127, 0, -1, _ELF_OK, _ELF_OK, 3, 0,
            "PHYSICAL_LOGICAL_RUNTIME_PATH_MISMATCH",
        ),
    ),
)
def test_interpreter_failure_classification_is_fixed_and_evidence_driven(
    candidate_rc: int,
    base_rc: int,
    sandbox_rc: int,
    candidate_elf: _ElfDependencyDiagnostic,
    base_elf: _ElfDependencyDiagnostic,
    physical: int,
    logical: int,
    expected: str,
) -> None:
    assert _classify_interpreter_failure(
        candidate_rc=candidate_rc,
        base_rc=base_rc,
        sandbox_rc=sandbox_rc,
        candidate_elf=candidate_elf,
        base_elf=base_elf,
        physical_reference_count=physical,
        logical_reference_count=logical,
    ) == expected


def test_container_python_probe_uses_only_mount_view_and_runtime_identity() -> None:
    commands = []

    def runner(argv, **kwargs):
        commands.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 127)

    result = _container_python_probe(
        4321, 998, 997, Path("/opt/pdi/current/.venv/bin/python"),
        runner=runner,
    )
    assert result == 127
    command, kwargs = commands[0]
    assert command[:7] == (
        "/usr/bin/nsenter", "--target", "4321", "--mount", "--root",
        "--wd", "--",
    )
    assert "--pid" not in command and "--net" not in command
    assert "--user" not in command and "--ipc" not in command
    assert "--reuid=998" in command and "--regid=997" in command
    assert "--clear-groups" in command and "--no-new-privs" in command
    assert command[-3:] == (
        "/opt/pdi/current/.venv/bin/python", "-c",
        "import sys; raise SystemExit(0)",
    )
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["shell"] is False


def test_sandbox_probe_mirrors_contract_without_affecting_six_service_count() -> None:
    commands = []

    def runner(argv, **kwargs):
        commands.append(tuple(argv))
        if len(commands) == 1:
            return subprocess.CompletedProcess(argv, 127)
        if tuple(argv)[3] == "show":
            return subprocess.CompletedProcess(argv, 0, "not-found\n", "")
        return subprocess.CompletedProcess(argv, 0)

    backend = MachineSystemdBackend("pdi-p3d-1234567812345678")
    result = _systemd_sandbox_python_probe(
        "pdi-p3d-1234567812345678",
        "12345678-1234-4234-8234-123456789abc",
        runner=runner,
    )
    assert result == 127
    assert backend.service_start_count == 0
    command = commands[0]
    assert command[0] == "/usr/bin/systemd-run"
    assert "--uid=pdi" in command and "--gid=pdi" in command
    assert "--working-directory=/opt/pdi/current" in command
    assert set(item for item in command if item.startswith("--property=")) == {
        "--property=Type=oneshot",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=ReadWritePaths=/run/lock",
    }
    assert "--setenv=PYTHONDONTWRITEBYTECODE=1" in command
    assert "--setenv=PYTHONPATH=/opt/pdi/current/src" in command
    assert all(unit not in " ".join(command) for unit in SERVICE_UNITS.values())
    assert not any("EnvironmentFile" in item for item in command)
    assert [command[3] for command in commands[1:]] == [
        "stop", "reset-failed", "show",
    ]


def test_missing_library_parser_emits_only_validated_basenames() -> None:
    payload = (
        "linux-vdso.so.1 (0x0000)\n"
        "libpython3.13.so.1.0 => not found\n"
        "libz.so.1 => not found\n"
    )
    assert _parse_missing_libraries(payload) == (
        "libpython3.13.so.1.0", "libz.so.1",
    )
    with pytest.raises(AssertionError, match="ELF_DIAGNOSTIC_REJECTED"):
        _parse_missing_libraries("/tmp/libunsafe.so => not found\n")
    with pytest.raises(AssertionError, match="ELF_DIAGNOSTIC_REJECTED"):
        _parse_missing_libraries("DATABASE__URL=secret-value\n")


def test_pyvenv_authority_is_classified_without_emitting_paths() -> None:
    runtime = Path("/run/pdi-p3d-wp7-runtime.A1b2C3")
    rehearsal = Path("/tmp/pdi-p3d-rehearsal-12345678")
    candidate = "a" * 40
    payload = (
        f"home = {runtime}/bin\n"
        f"executable = {runtime}/bin/python3.13\n"
        f"command = {runtime}/bin/python -m venv --copies "
        f"{rehearsal}/opt/pdi/releases/{candidate}/.venv\n"
    )
    result = _pyvenv_authority_diagnostic(
        payload,
        runtime_root=runtime,
        candidate=candidate,
        rehearsal_root=rehearsal,
    )
    assert result == _PyVenvAuthorityDiagnostic(
        "APPROVED_RUNTIME", "APPROVED_RUNTIME", True, True, True,
    )
    logical = _pyvenv_authority_diagnostic(
        f"home = /opt/pdi/releases/{candidate}/.venv\n",
        runtime_root=runtime,
        candidate=candidate,
        rehearsal_root=rehearsal,
    )
    assert logical.home_class == "CANDIDATE_RELEASE"


def test_runtime_reference_counts_only_selected_candidate_metadata(
    tmp_path: Path,
) -> None:
    candidate = "b" * 40
    root = tmp_path / "pdi-p3d-rehearsal-12345678"
    release = root / "opt/pdi/releases" / candidate
    (release / ".venv/bin").mkdir(parents=True)
    (release / ".venv/lib/python3.13/site-packages/a.dist-info").mkdir(
        parents=True
    )
    (release / ".venv/pyvenv.cfg").write_text(
        f"home = {root}/runtime\n", encoding="utf-8",
    )
    (release / ".venv/bin/tool").write_text(
        f"#!{root}/runtime/bin/python\n", encoding="utf-8",
    )
    (release / ".venv/lib/python3.13/site-packages/authority.pth").write_text(
        f"/opt/pdi/releases/{candidate}/src\n", encoding="utf-8",
    )
    (release / ".venv/lib/python3.13/site-packages/a.dist-info/RECORD").write_text(
        "/opt/pdi/current/src/pdi/__init__.py,,\n", encoding="utf-8",
    )
    assert _runtime_reference_counts(release, root, candidate) == (2, 2)


def test_interpreter_diagnostic_safe_output_never_contains_raw_paths_or_loader_text(
) -> None:
    runtime_path = "/run/pdi-p3d-wp7-runtime.RANDOM"
    diagnostic = _InterpreterFailureDiagnostic(
        127,
        0,
        -1,
        _ELF_OK,
        _ELF_OK,
        _PyVenvAuthorityDiagnostic(
            "APPROVED_RUNTIME", "APPROVED_RUNTIME", False, True, False,
        ),
        0,
        0,
        "CANDIDATE_VENV_NOT_EXECUTABLE_IN_CONTAINER",
    )
    output = "\n".join(f"{key}={value}" for key, value in diagnostic.safe_values())
    assert "CONTAINER_CANDIDATE_PYTHON_PROBE_RC=127" in output
    assert "INTERPRETER_FAILURE_CLASS=CANDIDATE_VENV_NOT_EXECUTABLE_IN_CONTAINER" in output
    assert runtime_path not in output
    assert "not found" not in output
    assert "DATABASE__URL" not in output


def test_interpreter_probes_require_exact_exit_127_without_fresh_ledger() -> None:
    state = {
        "LoadState": "loaded", "ActiveState": "failed",
        "SubState": "failed", "Result": "exit-code",
        "ExecMainStatus": "127", "ExecMainCode": "1", "StatusErrno": "2",
    }
    journal = _RehearsalFailureJournalDiagnostic(
        "SERVICES_VERIFIED", (), CANONICAL_PIPELINES[0],
        SERVICE_UNITS[CANONICAL_PIPELINES[0]], 1, state,
    )
    counts = _provider_call_counts(())
    absent = _PipelineRunFailureDiagnostic(0, 0, 0, False, None, None, None)
    present = _PipelineRunFailureDiagnostic(
        1, 0, 1, True, "failed", True, "execution_failed",
    )
    assert _interpreter_probe_required(
        _ServiceFailureDiagnostic(
            journal, state, absent, counts, "SERVICE_START_COMMAND_FAILED",
        )
    )
    assert not _interpreter_probe_required(
        _ServiceFailureDiagnostic(
            journal, state, present, counts, "SERVICE_START_COMMAND_FAILED",
        )
    )
    non_127 = dict(state, ExecMainStatus="1")
    assert not _interpreter_probe_required(
        _ServiceFailureDiagnostic(
            journal, non_127, absent, counts, "SERVICE_START_COMMAND_FAILED",
        )
    )


def _terminate_machine(machine: str, process: subprocess.Popen) -> bool:
    subprocess.run(
        (str(MACHINECTL), "terminate", machine),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=30,
    )
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGRTMIN + 3)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    return process.poll() is not None


@pytest.mark.skipif(os.geteuid() != 0, reason="WP7 requires disposable root authority")
def test_cross_gate_disposable_real_systemd_six_pipeline_rehearsal() -> None:
    bundle, digest_path, root, system_python, candidate = _environment()
    assert os.environ.get("PDI_P3D_WP7_DISPOSABLE") == "1"
    assert root != Path("/") and str(root).startswith("/tmp/pdi-p3d-rehearsal-")
    assert SYSTEMD_NSPAWN.is_file() and MACHINECTL.is_file()
    assert bundle.is_file() and digest_path.is_file() and system_python.is_file()
    runtime_root = _verify_qualification_runtime_root(system_python)
    assert not root.exists()
    root.mkdir(mode=0o755)
    os.chown(root, 0, 0)
    os.chmod(root, 0o755)
    account = pwd.getpwnam("pdi")
    group = grp.getgrnam("pdi")
    assert account.pw_uid > 0 and group.gr_gid > 0 and account.pw_gid == group.gr_gid
    trusted_os_release = _prepare_rootfs(root, account.pw_uid, group.gr_gid)
    trusted_libpython = _materialize_disposable_loader_cache(root, runtime_root)
    host_loader_cache_sha256 = _host_loader_cache_sha256(root)
    digests = json.loads(digest_path.read_text(encoding="utf-8"))
    assert digests["CANDIDATE_SHA"] == candidate
    assert len(candidate) == 40
    url = require_safe_test_database_url()
    assert (make_url(url).database or "").startswith("pdi_wp7_")
    host_paths = (
        Path("/opt/pdi"), Path("/etc/pdi"), Path("/var/lib/pdi-p3d"),
        Path("/etc/systemd/system/pdi-scoped-pipeline@.service"),
    )
    host_before = _tree_snapshot(host_paths)
    host_systemd_before = _host_systemd_snapshot()
    engine = None
    machine_process = None
    diagnostic_streams = []
    machine = ""
    complete_fingerprint = None
    manager_cleaned = False
    db_cleaned = False
    filesystem_cleaned = False
    try:
        with _provider_fixture() as (provider_port, fixture):
            engine, scopes = _seed_database(url)
            releases_root = root / "opt/pdi/releases"
            preparation_root = root / "var/lib/pdi-p3d/preparation"
            bootstrap_lock = root / "run/lock/pdi/p3d-release-bootstrap.lock"
            current = root / "opt/pdi/current"
            bootstrap = ReleaseBootstrap(
                inputs=BootstrapInputs(
                    bundle.absolute(), candidate, digests["BUNDLE_SHA256"],
                    digests["OS_RUNTIME_MANIFEST_SHA256"], "QUALIFICATION_ONLY",
                    _tool(candidate), releases_root, preparation_root,
                    bootstrap_lock, current, "pdi", "pdi",
                ),
                policy=BootstrapPolicy.qualification(
                    disposable_root=root, owner_uid=0, owner_gid=0,
                    runtime_uid=account.pw_uid, runtime_gid=group.gr_gid,
                ),
                host_runtime_provider=QualificationHostRuntimeAuthorityProvider(
                    system_python, digests["OS_RUNTIME_MANIFEST_SHA256"],
                ),
            ).run()
            assert bootstrap.final_state.phase == "COMPLETE"
            release = releases_root / candidate
            _assert_candidate_venv_runtime_authority(
                release,
                system_python=system_python,
                runtime_root=runtime_root,
            )

            gate_a_operation = str(uuid4())
            rollback_metadata, _ = _create_complete_gate_a(
                preparation_root,
                operation_id=gate_a_operation,
                candidate=candidate,
                source=SOURCE,
            )
            current.symlink_to(f"/opt/pdi/releases/{SOURCE}")

            p3c_state_root = root / "var/lib/pdi-p3c"
            frozen_host = FrozenP3CHost(
                FrozenP3CPaths(
                    staging=root / "p3c-unused/staging",
                    env=root / "p3c-unused/pdi.env",
                    recovery=root / "p3c-unused/recovery",
                    config=root / "p3c-unused/config",
                    units=root / "p3c-unused/units",
                    current=root / "p3c-unused/current",
                    releases=root / "p3c-unused/releases",
                    state=p3c_state_root,
                    control=root / "p3c-unused/control.lock",
                    sync=root / "p3c-unused/sync.lock",
                ),
                root / "p3c-unused/release", SOURCE,
                "synthetic-host", H1, SOURCE,
            )
            frozen_host.save({
                "phase": "PASS",
                "sha": SOURCE,
                "old_target": "/opt/pdi/releases/" + "c" * 40,
                "context": rollback_metadata.p3c_context_fingerprint,
                "baseline": {"synthetic": "private-baseline-evidence"},
                "qualified": list(QUALIFICATION),
                "verified": {"synthetic": "private-verified-evidence"},
            })

            endpoint = f"http://127.0.0.1:{provider_port}"
            environment = root / "etc/pdi/pdi.env"
            _write(
                environment,
                f'DATABASE__URL="{url}"\n'
                f'NEXTCLOUD__URL="{endpoint}"\n'
                'NEXTCLOUD__USER="synthetic"\n'
                'NEXTCLOUD__PASSWORD="synthetic-nextcloud-password"\n'
                f'IMMICH__URL="{endpoint}"\n'
                'IMMICH__API_KEY="synthetic-immich-api-key"\n',
                0o600, 0, 0,
            )
            registry = root / "etc/pdi/scoped/registry.toml"
            _write(
                registry,
                '[[principals]]\n'
                f'id = "{PRINCIPAL_ID}"\n'
                'database_ref = "wp7-personal-db"\n'
                'enabled = true\n\n'
                '[[databases]]\nref = "wp7-personal-db"\n'
                'url_env = "DATABASE__URL"\n\n'
                '[[provider_bindings]]\n'
                f'principal_id = "{PRINCIPAL_ID}"\n'
                f'scope_id = "{scopes["nextcloud"].id}"\n'
                'provider_type = "nextcloud"\n'
                f'endpoint = "{endpoint}"\n'
                'secret_env = "NEXTCLOUD__PASSWORD"\n'
                'username = "synthetic"\n\n'
                '[[provider_bindings]]\n'
                f'principal_id = "{PRINCIPAL_ID}"\n'
                f'scope_id = "{scopes["immich"].id}"\n'
                'provider_type = "immich"\n'
                f'endpoint = "{endpoint}"\n'
                'secret_env = "IMMICH__API_KEY"\n',
                0o640, 0, group.gr_gid,
            )
            profiles = root / "etc/pdi/scoped/units"
            profiles.mkdir(mode=0o700)
            os.chown(profiles, 0, 0)
            os.chmod(profiles, 0o700)

            gate_c = subprocess.run(
                (
                    str(release / ".venv/bin/python"),
                    str(release / "scripts/pdi_p3d_inert_asset_install.py"),
                    "--mode", "QUALIFICATION",
                    "--expected-candidate-sha", candidate,
                    "--gate-a-operation-id", gate_a_operation,
                    "--gate-b-operation-id", bootstrap.operation_id,
                    "--expected-systemd-asset-fingerprint",
                    digests["SYSTEMD_ASSET_FINGERPRINT"],
                    "--qualification-root", str(root),
                    "--qualification-runtime-user", "pdi",
                    "--qualification-runtime-group", "pdi",
                ),
                cwd=release,
                env={
                    "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                },
                capture_output=True, text=True, timeout=300, shell=False,
            )
            assert gate_c.returncode == 0, "GATE_C_FAILED"
            gate_c_result = json.loads(gate_c.stdout)
            assert gate_c_result["PHASE"] == "COMPLETE"
            for key in CANONICAL_PIPELINES:
                profile = profiles / f"{key}.env"
                info = profile.lstat()
                assert info.st_uid == 0 and info.st_gid == 0
                assert stat.S_IMODE(info.st_mode) == 0o600
                values = parse_env(profile.read_text(encoding="utf-8"))
                expected_keys = {
                    "PDI_PRINCIPAL_REF", "PDI_SCOPED_PIPELINE_KEY",
                    "DATABASE__URL",
                }
                if key.startswith("enrichment.nextcloud_"):
                    expected_keys.add("NEXTCLOUD__PASSWORD")
                elif key == "enrichment.immich_ocr":
                    expected_keys.add("IMMICH__API_KEY")
                assert set(values) == expected_keys

            rehearsal_operation = str(uuid4())
            machine = machine_name_for(rehearsal_operation)
            _assert_materialized_os_release(root, trusted_os_release)
            command = _build_nspawn_command(machine, root, system_python)
            diagnostic_root = root / "var/lib/pdi-p3d/rehearsal-diagnostics"
            nspawn_stdout = diagnostic_root / "nspawn.stdout"
            nspawn_stderr = diagnostic_root / "nspawn.stderr"
            diagnostic_streams.append(_secure_diagnostic_stream(nspawn_stdout))
            diagnostic_streams.append(_secure_diagnostic_stream(nspawn_stderr))
            pre_boot_cache = _host_loader_cache_snapshot(root)
            assert pre_boot_cache.sha256 == host_loader_cache_sha256
            nspawn_start_monotonic_us = time.monotonic_ns() // 1000
            machine_process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL,
                stdout=diagnostic_streams[0], stderr=diagnostic_streams[1],
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            database_password = make_url(url).password or ""
            leader = _wait_for_machine(
                machine,
                machine_process,
                nspawn_stdout=nspawn_stdout,
                nspawn_stderr=nspawn_stderr,
                secret_values=(
                    url,
                    database_password,
                    "synthetic-nextcloud-password",
                    "synthetic-immich-api-key",
                ),
            )
            manager_registration_monotonic_us = time.monotonic_ns() // 1000
            try:
                loader_cache_diagnostic = (
                    _verify_container_loader_cache_visibility(
                        leader=leader,
                        runtime_uid=account.pw_uid,
                        runtime_gid=group.gr_gid,
                        system_python=system_python,
                        candidate=candidate,
                        runtime_root=runtime_root,
                        trusted=trusted_libpython,
                        host_cache_sha256=host_loader_cache_sha256,
                    )
                )
            except _ContainerLoaderCacheDiagnosticError as exc:
                print(exc.diagnostic.safe_message())
                try:
                    cache_attribution = _collect_boot_cache_attribution(
                        machine=machine,
                        leader=leader,
                        runtime_uid=account.pw_uid,
                        runtime_gid=group.gr_gid,
                        trusted=trusted_libpython,
                        pre_boot=pre_boot_cache,
                        nspawn_start_monotonic_us=nspawn_start_monotonic_us,
                        manager_registration_monotonic_us=(
                            manager_registration_monotonic_us
                        ),
                        post_libpython_entry_count=(
                            exc.diagnostic.libpython_entry_count
                        ),
                    )
                except AssertionError:
                    raise AssertionError(
                        "BOOT_CACHE_ATTRIBUTION_DIAGNOSTIC_INVALID"
                    ) from None
                print(cache_attribution.safe_message())
                raise AssertionError(
                    "CONTAINER_LOADER_CACHE_DIAGNOSTIC_INVALID"
                ) from None
            print(loader_cache_diagnostic.safe_message())
            try:
                python_preflight = _verify_container_python_preflight(
                    leader=leader,
                    runtime_uid=account.pw_uid,
                    runtime_gid=group.gr_gid,
                    system_python=system_python,
                    candidate=candidate,
                )
            except _QualificationPythonPreflightError as exc:
                print(exc.safe_message())
                raise AssertionError(
                    "QUALIFICATION_PYTHON_PREFLIGHT_INVALID"
                ) from None
            assert trusted_libpython.path.name == _LIBPYTHON_SONAME
            print("LOADER_CACHE_LIBPYTHON_ENTRY_COUNT=1")
            print("LOADER_CACHE_LIBPYTHON_TARGET_TRUSTED=PASS")
            print(
                "CONTAINER_BASE_PYTHON_PROBE_RC="
                f"{python_preflight.base_probe_rc}"
            )
            print(
                "CONTAINER_CANDIDATE_PYTHON_PROBE_RC="
                f"{python_preflight.candidate_probe_rc}"
            )
            print(
                "BASE_PYTHON_MISSING_LIBRARY_COUNT="
                f"{len(python_preflight.base_elf.missing_libraries)}"
            )
            print(
                "CANDIDATE_PYTHON_MISSING_LIBRARY_COUNT="
                f"{len(python_preflight.candidate_elf.missing_libraries)}"
            )
            lock = Path(f"/proc/{leader}/root/run/lock/pdi-sync.lock")
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.touch(exist_ok=False)
            os.chown(lock, account.pw_uid, group.gr_gid)
            os.chmod(lock, 0o600)

            with engine.connect() as connection:
                rehearsal_boundary = connection.scalar(text(
                    "SELECT clock_timestamp()"
                ))

            wp7 = subprocess.run(
                (
                    str(release / ".venv/bin/python"),
                    str(release / "scripts/pdi_p3d_disposable_rehearsal.py"),
                    "run",
                    "--expected-candidate-sha", candidate,
                    "--gate-a-operation-id", gate_a_operation,
                    "--gate-b-operation-id", bootstrap.operation_id,
                    "--gate-c-operation-id", gate_c_result["OPERATION_ID"],
                    "--rehearsal-operation-id", rehearsal_operation,
                    "--rehearsal-root", str(root),
                ),
                cwd=release,
                env={
                    "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                },
                capture_output=True, text=True, timeout=1800, shell=False,
            )
            if wp7.returncode != 0:
                if (
                    wp7.stderr != ""
                    or wp7.stdout.splitlines() != [
                        "P3D_DISPOSABLE_REHEARSAL=FAIL",
                        "FAILURE_CODE=P3D_REHEARSAL_SERVICE_FAILED",
                    ]
                ):
                    raise AssertionError("WP7_FAILURE_OUTPUT_INVALID")
                diagnostic = _collect_service_failure_diagnostic(
                    root=root,
                    operation_id=rehearsal_operation,
                    engine=engine,
                    boundary=rehearsal_boundary,
                    provider_calls=tuple(fixture.calls),
                )
                if _interpreter_probe_required(diagnostic):
                    try:
                        interpreter = _collect_interpreter_failure_diagnostic(
                            leader=leader,
                            machine=machine,
                            operation_id=rehearsal_operation,
                            runtime_uid=account.pw_uid,
                            runtime_gid=group.gr_gid,
                            system_python=system_python,
                            release=release,
                            rehearsal_root=root,
                            candidate=candidate,
                        )
                    except (AssertionError, OSError, UnicodeError):
                        interpreter = _InterpreterFailureDiagnostic.unavailable()
                    diagnostic = replace(diagnostic, interpreter=interpreter)
                raise AssertionError(
                    "P3D_DISPOSABLE_REHEARSAL=FAIL\n"
                    "FAILURE_CODE=P3D_REHEARSAL_SERVICE_FAILED\n"
                    + diagnostic.safe_message()
                )
            assert wp7.returncode == 0, wp7.stdout
            assert wp7.stderr == ""
            result = json.loads(wp7.stdout)
            assert result["P3D_DISPOSABLE_REHEARSAL"] == "PASS"
            assert result["P3D_SERVICE_START_COUNT"] == 6
            assert result["P3D_TIMER_ENABLE_COUNT"] == 0
            assert result["P3D_TIMER_START_COUNT"] == 0
            assert result["POSTGRESQL_MAJOR"] == 16
            assert result["RUNTIME_PIPELINE_COVERAGE"] == "6/6"
            assert result["POST_REHEARSAL_RUNTIME_LEDGER_PROOF"] == "PASS"
            assert result["TIMERS_FINAL_STATE"] == "DISABLED_INACTIVE"
            complete_fingerprint = result["REHEARSAL_COMPLETE_MARKER_FINGERPRINT"]
            assert len(complete_fingerprint) == 64
            assert fixture.calls.count("nextcloud-propfind") >= 2
            assert fixture.calls.count("nextcloud-content") >= 2
            assert fixture.calls.count("immich-account") >= 1
            assert fixture.calls.count("immich-ocr") >= 1
            assert os.readlink(current) == f"/opt/pdi/releases/{candidate}"
            with engine.connect() as connection:
                assert connection.scalar(text("SELECT count(*) FROM pipeline_runs")) == 6
                assert connection.scalar(text(
                    "SELECT count(*) FROM pipeline_runs WHERE status='completed' "
                    "AND finished_at IS NOT NULL AND error_code IS NULL"
                )) == 6
                assert connection.scalar(text(
                    "SELECT count(DISTINCT pipeline_key) FROM pipeline_runs"
                )) == 6
    finally:
        if machine_process is not None:
            manager_cleaned = _terminate_machine(machine, machine_process)
        for stream in diagnostic_streams:
            stream.close()
        if engine is not None:
            _clean_rehearsal_database(engine)
            with engine.connect() as connection:
                db_cleaned = connection.scalar(text("SELECT count(*) FROM pipeline_runs")) == 0
            engine.dispose()
        if root.exists():
            shutil.rmtree(root)
        filesystem_cleaned = not root.exists()

    assert complete_fingerprint is not None
    assert manager_cleaned
    assert db_cleaned
    assert filesystem_cleaned
    assert _tree_snapshot(host_paths) == host_before
    assert _host_systemd_snapshot() == host_systemd_before
    print("P3D_DISPOSABLE_REHEARSAL=PASS")
    print("SYSTEMD_MANAGER_REAL=PASS")
    print("SYSTEMD_MANAGER_ISOLATED=PASS")
    print("P3D_SERVICE_START_COUNT=6")
    print("P3D_TIMER_ENABLE_COUNT=0")
    print("POSTGRESQL_MAJOR=16")
    print("RUNTIME_PIPELINE_COVERAGE=6/6")
    print("POST_REHEARSAL_RUNTIME_LEDGER_PROOF=PASS")
    print("TIMERS_FINAL_STATE=DISABLED_INACTIVE")
    print(f"REHEARSAL_COMPLETE_MARKER_FINGERPRINT={complete_fingerprint}")
    print("PRODUCTION_TOUCHED=NO")
