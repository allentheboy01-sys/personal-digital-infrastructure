"""Narrow, non-persisting WP8 Phase B local-systemd capability.

This is not an operator entrypoint or execution authorization. The future
orchestrator must validate protected Phase A/review/B authorization, serialize
the operation, and journal mutation boundaries before calling this backend.
There is no timer control, DB/Provider access, promotion, or state machine here.
Imports and construction are inert. Real-systemd qualification is a later gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import struct
import subprocess
import threading
import time
from types import MappingProxyType
from uuid import UUID

from .p3d_preparation_contracts import contract_fingerprint
from .p3d_wp8_contracts import (
    WP8_CANONICAL_PIPELINE_KEYS,
    WP8ContractError,
    WP8FailureCode,
    WP8PhaseAEvidenceV1,
)

__all__ = ["WP8ProductionSystemdBackend"]

_SYSTEMCTL = "/usr/bin/systemctl"
_BUSCTL = "/usr/bin/busctl"
_BUS_FLAGS = ("--system", "--no-pager", "--json=short")
_FLAGS = ("--system", "--no-pager", "--no-ask-password")
_ENV = MappingProxyType({"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
_SERVICE_UNITS = MappingProxyType({
    key: f"pdi-scoped-pipeline@{key}.service" for key in WP8_CANONICAL_PIPELINE_KEYS
})
_TEMPLATE = "/etc/systemd/system/pdi-scoped-pipeline@.service"
_STABLE_PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath",
)
_IDENTITY_PROPERTIES = (
    "Id", "LoadState", "FragmentPath", "DropInPaths", "Transient", "NeedDaemonReload",
)
# Reviewed systemd v257: Before/After order jobs, whereas other relations can pull
# jobs in, propagate stops/restarts, trigger handlers, or expose foreign graph
# authority. Include inverse relations: RequiredBy/BoundBy/ConsistsOf can stop
# other units even when the outbound Requires/BindsTo/PartOf sets are empty.
_ORDERING_PROPERTIES = ("Before", "After")
_GRAPH_PROPERTIES = (
    "Wants", "Requires", "Requisite", "BindsTo", "PartOf", "ConsistsOf", "Upholds",
    "RequiredBy", "RequisiteOf", "WantedBy", "BoundBy", "UpheldBy", "Conflicts",
    "ConflictedBy", "OnFailure", "OnSuccess", "OnFailureOf", "OnSuccessOf",
    "Triggers", "TriggeredBy", "PropagatesStopTo", "StopPropagatedFrom",
    "PropagatesReloadTo", "ReloadPropagatedFrom", "JoinsNamespaceOf", "SliceOf",
    "RequiresMountsFor", "WantsMountsFor",
)
_PATH_PROPERTIES = ("RequiresMountsFor", "WantsMountsFor")
_UNIT_LOAD_ROOTS = (
    "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
    "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late",
)
_DEFAULT_SLICE = r"system-pdi\x2dscoped\x2dpipeline.slice"
_SERVICE_PROPERTIES = (*_IDENTITY_PROPERTIES, "Names", "Following",
    "User", "Group", "Type", "WorkingDirectory", "EnvironmentFiles", "ExecStart",
    "NoNewPrivileges", "PrivateTmp", "PrivateTmpEx", "ProtectSystem", "ProtectHome", "ReadWritePaths",
    "TimeoutStartUSec", "TimeoutStopUSec", "KillMode", "StandardOutput", "StandardError",
    "RemainAfterExit", "Restart", "FailureAction", "SuccessAction", "StartLimitAction",
    "JobTimeoutAction", "DefaultDependencies", "Slice", *_GRAPH_PROPERTIES, *_ORDERING_PROPERTIES,
    "ConditionResult", "AssertResult", "ActiveState", "SubState",
    "Job", "Result", "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic", "InvocationID",
)
# Activity/freshness is proved separately at the immediate prerequisite gate.
# Do not make a stable authority seal depend on an invocation's changing state.
_SERVICE_RUNTIME_PROPERTIES = frozenset({
    "ConditionResult", "AssertResult", "ActiveState", "SubState", "Job", "Result",
    "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic", "InvocationID",
})
_TIMER_PROPERTIES = (*_IDENTITY_PROPERTIES, "ActiveState", "SubState", "Unit", "Job")
_MANAGER_PROPERTIES = ("Version", "Virtualization", "SystemState", "UnitPath")
# Package identity is authority, not a major-version compatibility heuristic.
_VERSION = "257.13-1~deb13u1"
# Read authority is finite and is NOT an execution API for these units. Unknown
# host boot/mount/service dependencies require a separate authority review;
# being root-owned, already active or named systemd-* does not grant authority.
_DEFAULT_START_UNITS = frozenset({
    "sysinit.target", "local-fs.target", "swap.target", _DEFAULT_SLICE,
    "system.slice", "-.slice", "tmp.mount", "-.mount", "opt.mount",
    "opt-pdi.mount", "opt-pdi-current.mount", "var.mount", "var-tmp.mount",
})
_DEFAULT_STOP_UNITS = frozenset({"shutdown.target", "umount.target", "emergency.target", "emergency.service"})
_DEFAULT_UNITS = _DEFAULT_START_UNITS | _DEFAULT_STOP_UNITS
_DEFAULT_PROPERTIES = (*_IDENTITY_PROPERTIES, "Names", "Following",
    *_GRAPH_PROPERTIES, *_ORDERING_PROPERTIES, "ActiveState", "SubState", "Job",
    "FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction", "StopWhenUnneeded")
_MAX_CLOSURE_NODES, _MAX_CLOSURE_EDGES, _MAX_CLOSURE_DEPTH = 32, 128, 16
# Reviewed v257 unit-dependency-atom.c / transaction.c: directed job edges,
# not undirected dependencies. Requisite verifies activity; its deps are not
# started. PartOf and StopPropagatedFrom do NOT propagate a stop from this unit.
_START_RELATIONS = ("Wants", "Requires", "BindsTo", "Upholds")
_STOP_RELATIONS = ("RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf", "PropagatesStopTo")
_FULL_VM = frozenset({
    "kvm", "qemu", "vmware", "microsoft", "oracle", "xen", "bochs", "parallels",
    "bhyve", "uml", "amazon", "apple", "zvm",
})


class _Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    COMMAND_FAILED = "COMMAND_FAILED"
    TIMEOUT = "TIMEOUT"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    BUSY = "BUSY"


class _BackendError(WP8ContractError):
    def __init__(self, code: WP8FailureCode, outcome: _Outcome) -> None:
        self.outcome = outcome
        super().__init__(code)


def _fail(code: WP8FailureCode, outcome: _Outcome = _Outcome.EVIDENCE_REJECTED) -> None:
    raise _BackendError(code, outcome) from None


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _key(value: str) -> str:
    if not isinstance(value, str) or value not in WP8_CANONICAL_PIPELINE_KEYS:
        _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
    return value


class _Request(Enum):
    MANAGER = "manager"
    RELOAD = "reload"
    SERVICE_SHOW = "service_show"
    SERVICE_RUNTIME_SHOW = "service_runtime_show"
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    TIMER_SHOW = "timer_show"
    TIMER_ENABLED = "timer_enabled"
    TIMER_ACTIVE = "timer_active"
    P3C_SHOW = "p3c_show"
    P3C_ENABLED = "p3c_enabled"
    P3C_ACTIVE = "p3c_active"
    DEFAULT_SHOW = "default_show"


class _TypedAuthority(Enum):
    CANONICAL_SERVICE = "canonical_service"
    EMERGENCY_STOP = "emergency_stop"


_EXEC_EMPTY_PROPERTIES = ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition")
_UNIT_EMPTY_PROPERTIES = ("Conditions", "Asserts")
_EMERGENCY_EMPTY_PROPERTIES = ("ExecStop", "ExecStopPost")
_EXEC_SIGNATURE = "a(sasbttttuii)"
_UNIT_SIGNATURE = "a(sbbsi)"


def _typed_commands(authority: _TypedAuthority, key: str | None = None):
    """Two sealed authorities, no caller-selectable unit/property/object path.

    busctl get-property calls Properties.Get (never LoadUnit/StartUnit). v257
    prints one JSON variant per requested property, in fixed argv order.
    """
    if authority is _TypedAuthority.CANONICAL_SERVICE:
        unit = _SERVICE_UNITS[_key(key)]
        groups = (("Service", _EXEC_EMPTY_PROPERTIES, _EXEC_SIGNATURE),
                  ("Unit", _UNIT_EMPTY_PROPERTIES, _UNIT_SIGNATURE))
    elif authority is _TypedAuthority.EMERGENCY_STOP and key is None:
        unit = "emergency.service"
        groups = (("Service", _EMERGENCY_EMPTY_PROPERTIES, _EXEC_SIGNATURE),)
    else:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    label = "".join(c if c.isascii() and c.isalnum() else f"_{ord(c):02x}" for c in unit)
    path = "/org/freedesktop/systemd1/unit/" + label
    return tuple(((_BUSCTL, *_BUS_FLAGS, "get-property", "org.freedesktop.systemd1", path,
                   "org.freedesktop.systemd1." + interface, *names), names, signature)
                 for interface, names, signature in groups)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        result[key] = value
    return result


def _empty_typed(values, names, signature):
    for name in names:
        value = values.get(name)
        if (type(value) is not dict or set(value) != {"type", "data"} or
                value["type"] != signature or type(value["data"]) is not list or value["data"] != []):
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)


def _typed_empty(authority: _TypedAuthority, key: str | None = None):
    commands = _typed_commands(authority, key)
    code = WP8FailureCode.SERVICE_CONTRACT_INVALID
    try:
        if not _trusted(Path(_BUSCTL), kind="file"):
            _fail(code)
        values = {}
        for argv, names, signature in commands:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                                    env=dict(_ENV), shell=False, stdin=subprocess.DEVNULL)
            if (type(result.returncode) is not int or result.returncode != 0 or
                    not isinstance(result.stdout, str) or not isinstance(result.stderr, str) or
                    len(result.stdout) > 65536):
                _fail(code, _Outcome.COMMAND_FAILED)
            lines = result.stdout.splitlines()
            if len(lines) != len(names):
                _fail(code)
            for name, line in zip(names, lines, strict=True):
                values[name] = json.loads(line, object_pairs_hook=_json_object)
            _empty_typed(values, names, signature)
        return values  # private typed EMPTY proof only, never raw bus output
    except _BackendError:
        raise
    except subprocess.TimeoutExpired:
        _fail(code, _Outcome.TIMEOUT)
    except BaseException:
        _fail(code, _Outcome.COMMAND_FAILED)


def _timer_units():
    # Reuse the frozen mapping, never infer an additional scheduling authority.
    from .enrichment_cutover import P3D_TIMER_UNITS
    if set(P3D_TIMER_UNITS) != set(WP8_CANONICAL_PIPELINE_KEYS):
        _fail(WP8FailureCode.CONTRACT_PIPELINE_SET_INVALID)
    return P3D_TIMER_UNITS


def _p3c_units():
    from .p3d_inert_asset_install import P3C_SERVICE, P3C_TIMERS
    return (*P3C_TIMERS, P3C_SERVICE)


def _command(request: _Request, key: str | None = None) -> tuple[tuple[str, ...], int]:
    """Closed request algebra, not a verb/unit/argv passthrough."""
    if not isinstance(request, _Request):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    if request in {_Request.MANAGER, _Request.RELOAD}:
        if key is not None:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        if request is _Request.RELOAD:
            return (_SYSTEMCTL, *_FLAGS, "daemon-reload"), 30
        return (_SYSTEMCTL, *_FLAGS, "show", "--all",
                "--property=" + ",".join(_MANAGER_PROPERTIES)), 30
    if request in {_Request.SERVICE_SHOW, _Request.SERVICE_RUNTIME_SHOW, _Request.SERVICE_START, _Request.SERVICE_STOP}:
        unit = _SERVICE_UNITS[_key(key)]
        if request is _Request.SERVICE_START:
            return (_SYSTEMCTL, *_FLAGS, "start", unit), 1800
        if request is _Request.SERVICE_STOP:
            return (_SYSTEMCTL, *_FLAGS, "stop", unit), 90
        properties = (tuple(name for name in _SERVICE_PROPERTIES if name in _SERVICE_RUNTIME_PROPERTIES)
                      if request is _Request.SERVICE_RUNTIME_SHOW else _SERVICE_PROPERTIES)
    elif request in {_Request.TIMER_SHOW, _Request.TIMER_ENABLED, _Request.TIMER_ACTIVE}:
        unit = _timer_units()[_key(key)]
        properties = _TIMER_PROPERTIES
    elif request is _Request.DEFAULT_SHOW:
        if key not in _DEFAULT_UNITS:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        unit, properties = key, _DEFAULT_PROPERTIES
    else:
        if key not in _p3c_units():
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        unit, properties = key, _STABLE_PROPERTIES
    if request in {_Request.TIMER_ENABLED, _Request.P3C_ENABLED}:
        return (_SYSTEMCTL, *_FLAGS, "is-enabled", unit), 30
    if request in {_Request.TIMER_ACTIVE, _Request.P3C_ACTIVE}:
        return (_SYSTEMCTL, *_FLAGS, "is-active", unit), 30
    # Text omission is NOT empty structured-array evidence. P3C is unchanged.
    flags = () if request is _Request.P3C_SHOW else ("--all",)
    return (_SYSTEMCTL, *_FLAGS, "show", unit, *flags,
            "--property=" + ",".join(properties)), 30


def _trusted(path: Path, *, kind: str, mode: int | None = None) -> bool:
    from .cutover import trusted_path
    return trusted_path(path, expected_kind=kind, exact_mode=mode, require_root_group=True)


def _systemctl(request: _Request, key: str | None = None) -> subprocess.CompletedProcess[str]:
    argv, timeout = _command(request, key)
    code = (WP8FailureCode.DAEMON_RELOAD_FAILED if request is _Request.RELOAD else
            WP8FailureCode.SYSTEMD_MANAGER_INVALID if request is _Request.MANAGER else
            WP8FailureCode.SERVICE_EXECUTION_FAILED if request is _Request.SERVICE_START else
            WP8FailureCode.CLEANUP_FAILED if request is _Request.SERVICE_STOP else
            WP8FailureCode.SERVICE_CONTRACT_INVALID)
    try:
        if not _trusted(Path(_SYSTEMCTL), kind="file"):
            _fail(code)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                env=dict(_ENV), shell=False, stdin=subprocess.DEVNULL)
        if (type(result.returncode) is not int or not isinstance(result.stdout, str) or
                not isinstance(result.stderr, str) or len(result.stdout) > 65536):
            _fail(code)
        return result  # private only; no raw output escapes the public boundary
    except _BackendError:
        raise
    except subprocess.TimeoutExpired:
        _fail(code, _Outcome.TIMEOUT)
    except BaseException:
        _fail(code, _Outcome.COMMAND_FAILED)


def _properties(result, names: tuple[str, ...], code=WP8FailureCode.SERVICE_CONTRACT_INVALID):
    if result.returncode != 0:
        _fail(code, _Outcome.COMMAND_FAILED)
    if any((ord(c) < 32 and c != "\n") or ord(c) == 127 for c in result.stdout):
        _fail(code)
    values = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if not separator or name not in names or name in values or any(ord(c) < 32 for c in value):
            _fail(code)
        values[name] = value
    if set(values) != set(names):
        _fail(code)
    return values


def _no_job(values) -> bool:
    # v257 show renders a no-job (uo) value as Job=, NOT Job=0.
    return "Job" in values and type(values["Job"]) is str and values["Job"] == ""


@dataclass(frozen=True)
class _ManagerIdentity:
    fingerprint: str
    boot_fingerprint: str
    host_class: str
    continuity_token: str
    authority_domain: tuple[str, ...] = ()


def _manager_continuity_facts():
    """Bounded /proc + inode + peer observations, no file-content hashing/query.

    These facts only maintain continuity with a preceding FULL manager proof;
    they are never independently sufficient to authorize a manager.
    """
    try:
        if os.geteuid() != 0 or Path("/run/systemd/container").exists():
            raise ValueError
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            raise ValueError
        executable = Path("/proc/1/exe").resolve(strict=True)
        if (executable.name != "systemd" or
                not _trusted(executable, kind="file") or
                not _trusted(Path("/run/systemd"), kind="directory")):
            raise ValueError
        namespaces = {}
        # Start freshness compares CLOCK_MONOTONIC values with the manager, so
        # a different time namespace cannot be accepted either.
        for name in ("pid", "mnt", "user", "time"):
            leader = os.readlink(f"/proc/1/ns/{name}")
            if leader != os.readlink(f"/proc/self/ns/{name}"):
                raise ValueError
            namespaces[name] = leader
        if not os.path.samefile("/proc/1/root", "/"):
            raise ValueError
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if str(UUID(boot)) != boot:
            raise ValueError
        endpoint = Path("/run/systemd/private")
        info = endpoint.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
            raise ValueError
        # Socket access bits permit connecting, not replacing the root-owned inode.
        # Bind the peer itself; a root-owned pathname alone is not sufficient.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(str(endpoint))
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer != (1, 0, 0):
            raise ValueError
        executable_info = executable.lstat()
        return {"boot": boot, "namespaces": namespaces, "peer": peer,
                "executable": str(executable),
                "executable_identity": (executable_info.st_dev, executable_info.st_ino,
                    executable_info.st_size, executable_info.st_mtime_ns, executable_info.st_ctime_ns),
                "socket_identity": (info.st_dev, info.st_ino, info.st_ctime_ns)}
    except BaseException:
        _fail(WP8FailureCode.SYSTEMD_MANAGER_INVALID)


def _manager_os_facts():
    """Full authority proof adds the trusted PID1 executable content hash."""
    facts = _manager_continuity_facts()
    try:
        return {**facts, "executable_sha256": _digest(Path(facts["executable"]).read_bytes())}
    except BaseException:
        _fail(WP8FailureCode.SYSTEMD_MANAGER_INVALID)


def _manager_token(identity: _ManagerIdentity) -> None:
    if contract_fingerprint(_manager_continuity_facts()) != identity.continuity_token:
        _fail(WP8FailureCode.SYSTEMD_MANAGER_INVALID)


def _observe_manager() -> _ManagerIdentity:
    before = _manager_os_facts()
    values = _properties(_systemctl(_Request.MANAGER), _MANAGER_PROPERTIES,
                         WP8FailureCode.SYSTEMD_MANAGER_INVALID)
    after = _manager_os_facts()
    roots = values["UnitPath"].split()
    if (before != after or values["Version"] != _VERSION or
            tuple(roots) != _UNIT_LOAD_ROOTS or
            values["SystemState"] not in {"running", "degraded"} or
            values["Virtualization"] not in {"", *_FULL_VM}):
        _fail(WP8FailureCode.SYSTEMD_MANAGER_INVALID)
    return _ManagerIdentity(contract_fingerprint({"manager": before,
                            "version": values["Version"], "virtualization": values["Virtualization"],
                            "unit_path": roots}),
                            _digest(before["boot"].encode()),
                            "FULL_VM" if values["Virtualization"] else "BARE_METAL",
                            contract_fingerprint({k: v for k, v in before.items() if k != "executable_sha256"}),
                            _schema_domain({"manager": before, "version": values["Version"],
                                            "virtualization": values["Virtualization"], "unit_path": roots}))


@dataclass(frozen=True)
class _Assets:
    fingerprint: str
    template: tuple[tuple[str, str, str], ...]


def _template(payload: bytes) -> tuple[tuple[str, str, str], ...]:
    """Parse the verified frozen asset, not another service definition."""
    section, entries = "", []
    for line in payload.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if line in {"[Unit]", "[Service]"}:
            section = line[1:-1]
            continue
        name, separator, value = line.partition("=")
        if not section or not separator or not name or not value or "\\" in line:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        if name != "Environment" and any(s == section and n == name for s, n, _ in entries):
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        entries.append((section, name, value))
    return tuple(entries)


def _read_assets(evidence: WP8PhaseAEvidenceV1) -> _Assets:
    """Read frozen Gate C chain and every installed asset, without collector/DB calls."""
    from . import p3d_pre_rehearsal_evidence as wp6
    from .p3d_inert_asset_install import InertAssetPolicy
    from .p3d_preparation_contracts import PreparationGate, asset_installation_fingerprint
    from .p3d_wp8_preflight import _gate_binding

    try:
        policy = InertAssetPolicy.production()
        inputs = wp6.PreparationEvidenceInputs(evidence.candidate_sha, evidence.gate_a_operation_id,
            evidence.gate_b_operation_id, evidence.gate_c_operation_id, evidence.rollback_source_sha)
        state, events, _ = wp6._explicit_gate(policy, inputs.gate_c_operation_id,
            gate=PreparationGate.INERT_ASSET_INSTALL, candidate=evidence.candidate_sha)
        marker, marker_hash, snapshot, root = wp6._read_gate_c_marker(policy, inputs)
        manifest = wp6._fresh_installed_manifest(policy)
        fingerprint = asset_installation_fingerprint(manifest)
        if (marker_hash != evidence.gate_c_marker_fingerprint or
                manifest != marker.installed_file_manifest or
                fingerprint != evidence.unit_profile_asset_fingerprint or
                marker.rollback_source_sha != evidence.rollback_source_sha or
                marker.registry_fingerprint != evidence.registry_fingerprint or
                marker.db_identity_fingerprint != evidence.db_identity_fingerprint or
                marker.enabled_scope_fingerprint != evidence.enabled_scope_fingerprint or
                marker.p3c_systemd_state_after_fingerprint != evidence.p3c_systemd_fingerprint or
                _gate_binding("gate_c", state, events, {"marker": marker_hash, "assets": fingerprint})
                != evidence.gate_c_authority_binding_fingerprint):
            raise ValueError
        payload = wp6._read_protected_bytes(policy.physical(_TEMPLATE), policy=policy, mode=0o644, gid=0)
        for key in WP8_CANONICAL_PIPELINE_KEYS:
            # Gate C pins the secret set; only principal/key binding is inspected.
            profile = wp6._read_protected_bytes(policy.physical(f"/etc/pdi/scoped/units/{key}.env"),
                                                policy=policy, mode=0o600, gid=0)
            values = {}
            for line in profile.payload.decode("utf-8").splitlines():
                name, separator, encoded = line.partition("=")
                if not separator or name in values or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                    raise ValueError
                values[name] = json.loads(encoded)
            principal = values.get("PDI_PRINCIPAL_REF", "")
            if (str(UUID(principal)) != principal or values.get("PDI_SCOPED_PIPELINE_KEY") != key):
                raise ValueError
            if key == WP8_CANONICAL_PIPELINE_KEYS[0]:
                expected_principal = principal
            elif principal != expected_principal:
                raise ValueError
        if (manifest != wp6._fresh_installed_manifest(policy) or
                snapshot.identity != wp6._read_protected_bytes(root / "complete.json", policy=policy,
                mode=0o600, gid=0).identity or
                _digest(payload.payload) != next(item.sha256 for item in manifest if item.path == _TEMPLATE)):
            raise ValueError
        return _Assets(fingerprint, _template(payload.payload))
    except BaseException:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)


def _verify_candidate(evidence: WP8PhaseAEvidenceV1) -> str:
    """Rehash the immutable runtime using frozen WP1/Gate B representation."""
    from . import p3d_pre_rehearsal_evidence as wp6
    from .p3d_inert_asset_install import InertAssetPolicy, GIT_READ_ONLY_ENV
    from .p3d_preparation_contracts import PreparationGate, SourceFileFingerprintEntryV1, source_release_fingerprint
    from .enrichment_cutover import verify_release_immutability
    from .p3d_wp8_preflight import _gate_binding
    try:
        policy = InertAssetPolicy.production()
        wp6._current_target(policy, expected_source=evidence.candidate_sha)
    except BaseException:
        _fail(WP8FailureCode.CURRENT_DRIFT)
    try:
        release = policy.candidate_releases_root / evidence.candidate_sha
        if not verify_release_immutability(release, evidence.candidate_sha):
            raise ValueError
        entries = []
        for path in sorted(release.rglob("*")):
            relative = path.relative_to(release).as_posix()
            if relative == ".git" or relative.startswith(".git/"):
                continue
            info = path.lstat()
            mode = f"0{stat.S_IMODE(info.st_mode):03o}"
            if stat.S_ISLNK(info.st_mode):
                target = path.resolve(strict=True)
                target_text = (target.relative_to(release).as_posix()
                               if release in target.parents else str(target))
                entry = SourceFileFingerprintEntryV1(relative, "symlink", mode, 0, 0,
                                                     symlink_target=target_text)
            elif stat.S_ISDIR(info.st_mode):
                entry = SourceFileFingerprintEntryV1(relative, "directory", mode, 0, 0)
            else:
                entry = SourceFileFingerprintEntryV1(relative, "file", mode, 0, 0,
                                                     _digest(path.read_bytes()))
            entries.append(entry)
        fingerprint = source_release_fingerprint(evidence.candidate_sha, entries)
        state, events, _ = wp6._explicit_gate(policy, evidence.gate_b_operation_id,
            gate=PreparationGate.RELEASE_STAGING, candidate=evidence.candidate_sha)
        if (events[-1].evidence_fingerprints != (fingerprint,) or
                _gate_binding("gate_b", state, events, {"release": fingerprint})
                != evidence.gate_b_authority_binding_fingerprint):
            raise ValueError
        for args in (("rev-parse", "HEAD"), ("status", "--porcelain", "--untracked-files=all")):
            result = subprocess.run(("/usr/bin/git", "-C", str(release), *args), capture_output=True,
                text=True, shell=False, stdin=subprocess.DEVNULL, timeout=30, env=dict(GIT_READ_ONLY_ENV))
            if result.returncode or (result.stdout.strip() != evidence.candidate_sha if args[0] == "rev-parse"
                                     else bool(result.stdout.strip())):
                raise ValueError
        wp6._current_target(policy, expected_source=evidence.candidate_sha)
        return fingerprint
    except BaseException:
        _fail(WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)


def _exec_argv(value: str) -> tuple[str, ...]:
    # systemctl's documented ExecStart structure; accept one command only.
    match = re.fullmatch(r"\{ path=([^;\s]+) ; argv\[\]=(.*?) ; ignore_errors=no ; "
                         r"start_time=\[[^\]\r\n]*\] ; stop_time=\[[^\]\r\n]*\] ; "
                         r"pid=[0-9]+ ; code=[a-z()]+ ; status=[0-9]+(?:/[A-Z0-9]+)? \}", value)
    if match is None or ";" in match[2]:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    # systemctl joins the actual argv with spaces, losing quoting information.
    # The frozen argv has no spaces within arguments; reject ambiguous encoding.
    args = tuple(match[2].split(" "))
    if not args or any(not arg for arg in args) or args[0] != match[1]:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return args


def _identity(values, key: str, *, timer: bool = False, allow_stale: bool = False):
    unit = _timer_units()[key] if timer else _SERVICE_UNITS[key]
    fragment = f"/etc/systemd/system/{unit}" if timer else _TEMPLATE
    required = {"Id": unit, "LoadState": "loaded", "FragmentPath": fragment,
                "DropInPaths": "", "Transient": "no"}
    if any(values[name] != value for name, value in required.items()):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    if values["NeedDaemonReload"] not in ({"no", "yes"} if allow_stale else {"no"}):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)


def _dependency_directories(key: str) -> None:
    """No Gate C authority grants template/instance .wants/.requires entries.

    This is a bounded check of those two directories, not a systemd crawler.
    Loaded properties cannot distinguish an injected link to an allowed default
    (e.g. sysinit.target) from an implicit dependency. UnitPath is independently
    restricted/pinned by the manager observation.
    """
    key = _key(key)
    for root in _UNIT_LOAD_ROOTS:
        for unit in (Path(_TEMPLATE).name, _SERVICE_UNITS[key]):
            for suffix in ("wants", "requires"):
                path = Path(root) / f"{unit}.{suffix}"
                existing = Path("/")
                for part in path.parts[1:]:
                    existing /= part
                    try:
                        existing.lstat()
                    except FileNotFoundError:
                        break
                    except BaseException:
                        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
                    if not _trusted(existing, kind="directory"):
                        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
                else:
                    try:
                        if next(path.iterdir(), None) is not None:
                            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
                    except BaseException:
                        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)


def _unit_names(value: str) -> frozenset[str]:
    names = value.split()
    if (len(names) != len(set(names)) or any(len(name) > 255 or not re.fullmatch(
            r"[A-Za-z0-9:_.@\\-]+\.(?:service|socket|device|mount|automount|swap|target|path|timer|slice|scope)",
            name) for name in names)):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return frozenset(names)


def _check_graph(values, key: str, assets: _Assets) -> dict[str, list[str]]:
    """Exact v257/frozen-template graph policy; never authorize arbitrary units.

    service_add_default_dependencies() adds sysinit + shutdown; template
    instances get a per-template slice. unit_add_exec_dependencies() adds
    connected PrivateTmp's wanted paths and required WorkingDirectory prefixes.
    Only these finite OS defaults are allowed; no user workload
    dependency or stop/failure/success propagation is granted by Gate C.
    """
    source = {name: value for section, name, value in assets.template if section == "Service"}
    unit = {name: value for section, name, value in assets.template if section == "Unit"}
    if (set(unit) != {"After", "Description"} or unit["After"] != "network-online.target" or
            source["PrivateTmp"] != "true" or
            source["WorkingDirectory"] != "/opt/pdi/current" or
            values["DefaultDependencies"] != "yes" or values["Slice"] != _DEFAULT_SLICE or
            _unit_names(values["Names"]) != {_SERVICE_UNITS[key]} or values["Following"]):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    graph = {name: _unit_names(values[name]) for name in _GRAPH_PROPERTIES if name not in _PATH_PROPERTIES}
    required = _paths(values["RequiresMountsFor"], {source["WorkingDirectory"]}, exact=True)
    wanted = _paths(values["WantsMountsFor"], {"/tmp", "/var/tmp"}, exact=True)
    # v257 adds prefix Requires/Wants + After for loaded mount fragments.
    # Bound each relation to its own finite paths; do not authorize all mounts.
    required_mounts, wanted_mounts = _mount_prefixes(required), _mount_prefixes(wanted)
    mandatory = {"sysinit.target", _DEFAULT_SLICE}
    if (not graph["Wants"] <= wanted_mounts or not mandatory <= graph["Requires"] or
            not graph["Requires"] <= mandatory | required_mounts or graph["Conflicts"] != {"shutdown.target"} or
            not graph["ConflictedBy"] <= {"shutdown.target"} or
            not graph["TriggeredBy"] <= {_timer_units()[key]}):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    allowed = {"Wants", "Requires", "Conflicts", "ConflictedBy", "TriggeredBy"}
    if any(graph[name] for name in graph.keys() - allowed):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    # Ordering is not activation authority. Preserve frozen/default ordering,
    # allow other ordering-only edges, but never treat them as dependencies.
    after, before = (_unit_names(values[name]) for name in ("After", "Before"))
    if (not (mandatory | graph["Wants"] | graph["Requires"] |
             {unit["After"], "basic.target", "systemd-tmpfiles-setup.service"}) <= after or
            "shutdown.target" not in before):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return {name: sorted(names) for name, names in graph.items()}


def _paths(value: str, allowed: set[str], *, exact: bool = False) -> frozenset[str]:
    paths = value.split()
    if (len(paths) != len(set(paths)) or not set(paths) <= allowed or
            (exact and set(paths) != allowed)):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return frozenset(paths)


def _mount_prefixes(paths):
    mounts = {"-.mount"}
    for path in paths:
        parts = Path(path).parts[1:]
        mounts.update("-".join(parts[:i]) + ".mount" for i in range(1, len(parts) + 1))
    return mounts


def _check_service(values, key: str, assets: _Assets) -> str:
    _identity(values, key)
    source = {name: value for section, name, value in assets.template if section == "Service"}
    direct = ("User", "Group", "Type", "WorkingDirectory", "ProtectSystem", "ReadWritePaths",
              "KillMode", "StandardOutput", "StandardError")
    if any(values[name] != source[name] for name in direct):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    for name in ("NoNewPrivileges", "PrivateTmp", "ProtectHome"):
        if source[name] != "true" or values[name] != "yes":
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    if values["PrivateTmpEx"] != "connected":
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    expected_environment = source["EnvironmentFile"].replace("%i", key)
    if (values["EnvironmentFiles"] != f"{expected_environment} (ignore_errors=no)" or
            _exec_argv(values["ExecStart"]) != tuple(shlex.split(source["ExecStart"])) or
            source["TimeoutStartSec"] != "infinity" or values["TimeoutStartUSec"] != "infinity" or
            source["TimeoutStopSec"] != "60" or values["TimeoutStopUSec"] != "1min" or
            values["RemainAfterExit"] != "no" or values["Restart"] != "no"):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    _empty_typed(values, _EXEC_EMPTY_PROPERTIES, _EXEC_SIGNATURE)
    _empty_typed(values, _UNIT_EMPTY_PROPERTIES, _UNIT_SIGNATURE)
    if any(values[name] != "none" for name in
           ("FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction")):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    graph = _check_graph(values, key, assets)
    return contract_fingerprint({"pipeline": key, "assets": assets.fingerprint,
        "template_sha256": contract_fingerprint(assets.template), "graph": graph,
        "private_tmp": values["PrivateTmp"], "private_tmp_ex": values["PrivateTmpEx"],
        "mount_paths": {name: sorted(values[name].split()) for name in _PATH_PROPERTIES},
        "typed_empty": {name: values[name] for name in (*_EXEC_EMPTY_PROPERTIES, *_UNIT_EMPTY_PROPERTIES)},
        "loaded_authority": _service_authority_text(values),
        "no_job_representation": "EMPTY_V257"})


def _service_authority_text(values):
    authority = {name: values[name] for name in _SERVICE_PROPERTIES if name not in _SERVICE_RUNTIME_PROPERTIES}
    # The ExecStart show structure also embeds per-invocation pid/timestamps/
    # exit status. Preserve its validated executable/argv/ignore-errors contract
    # without letting those volatile members alter the stable authority seal.
    authority["ExecStart"] = _exec_argv(values["ExecStart"])
    for name in (*_GRAPH_PROPERTIES, *_ORDERING_PROPERTIES):
        authority[name] = tuple(sorted(values[name].split()))
    return authority


def _collect_current_service_authority(key: str):
    """Bounded two-pass observation, never old typed evidence + new text.

    Rebind the loaded identity before accessing the sealed typed object. Re-read
    all stable text AND all typed fields in this collection stage, rejecting
    drift, and return only the newly collected typed proof. This is continuity,
    not a claim of an atomic multi-interface systemd snapshot. No slow/static
    validation or fallback is introduced after the final typed reads.
    """
    key = _key(key)
    before = _properties(_systemctl(_Request.SERVICE_SHOW, key), _SERVICE_PROPERTIES)
    _identity(before, key, allow_stale=True)
    if _unit_names(before["Names"]) != {_SERVICE_UNITS[key]} or before["Following"]:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    prior_typed = _typed_empty(_TypedAuthority.CANONICAL_SERVICE, key)
    current = _properties(_systemctl(_Request.SERVICE_SHOW, key), _SERVICE_PROPERTIES)
    if _service_authority_text(current) != _service_authority_text(before):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    current_typed = _typed_empty(_TypedAuthority.CANONICAL_SERVICE, key)
    if current_typed != prior_typed:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return {**current, **current_typed}


class _JobAuthority(str, Enum):
    START = "START"
    STOP = "STOP"
    VERIFY = "VERIFY"


def _default_show(unit: str):
    values = _properties(_systemctl(_Request.DEFAULT_SHOW, unit), _DEFAULT_PROPERTIES)
    if unit == "emergency.service":
        # Sole default typed exception, bound BEFORE reading the fixed object.
        if (values["Id"] != unit or _unit_names(values["Names"]) != {unit} or values["Following"] or
                values["LoadState"] != "loaded" or values["Transient"] != "no" or
                values["FragmentPath"] != "/usr/lib/systemd/system/emergency.service" or
                values["DropInPaths"] or values["NeedDaemonReload"] != "no"):
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        prior_typed = _typed_empty(_TypedAuthority.EMERGENCY_STOP)
        after = _properties(_systemctl(_Request.DEFAULT_SHOW, unit), _DEFAULT_PROPERTIES)
        if after != values:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        # The current closure gate consumes a fresh stop-hook proof, not the
        # earlier EMPTY result merged with a newer textual observation.
        current_typed = _typed_empty(_TypedAuthority.EMERGENCY_STOP)
        if current_typed != prior_typed:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        values = {**after, **current_typed}
    return values


def _default_fragment(values) -> str:
    unit, fragment = values["Id"], values["FragmentPath"]
    if not fragment:
        if unit not in {_DEFAULT_SLICE, "system.slice", "-.slice", "-.mount"}:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        return "IMPLICIT_V257_UNIT"
    expected = {str(Path(root) / unit) for root in _UNIT_LOAD_ROOTS}
    if fragment not in expected or not _trusted(Path(fragment), kind="file"):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return _digest(Path(fragment).read_bytes())


def _default_dependency_directories(unit: str, values) -> None:
    """Reconcile exact default-unit links with the loaded, reviewed graph.

    Unlike Gate C's PDI template, packaged defaults can legitimately have links.
    Each link must be root-controlled, resolve to the same exact authorized unit
    under a fixed load root, and be represented in the current loaded relation.
    No recursive filesystem crawler or arbitrary unit query is introduced.
    """
    if unit not in _DEFAULT_UNITS:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    count = 0
    for root in _UNIT_LOAD_ROOTS:
        for suffix, relation in (("wants", "Wants"), ("requires", "Requires")):
            path = Path(root) / f"{unit}.{suffix}"
            existing = Path("/")
            for part in path.parts[1:]:
                existing /= part
                try:
                    existing.lstat()
                except FileNotFoundError:
                    break
                if not _trusted(existing, kind="directory"):
                    _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
            else:
                for entry in path.iterdir():
                    count += 1
                    if count > _MAX_CLOSURE_EDGES or entry.name not in _DEFAULT_START_UNITS:
                        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
                    info = entry.lstat()
                    linked = Path(os.readlink(entry))
                    linked = linked if linked.is_absolute() else entry.parent / linked
                    # Validate the literal target chain BEFORE resolution, so a
                    # root-owned link cannot launder a user-controlled alias.
                    if not _trusted(linked, kind="file"):
                        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
                    target = linked.resolve(strict=True)
                    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
                            entry.name not in _unit_names(values[relation]) or
                            str(target) not in {str(Path(r) / entry.name) for r in _UNIT_LOAD_ROOTS} or
                            not _trusted(target, kind="file")):
                        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)


def _default_authority(values, unit: str, job: _JobAuthority) -> dict[str, frozenset[str]]:
    # Name + loaded identity + exact relation direction, never name/root owner
    # alone. Required base systems are observation-only healthy prerequisites;
    # this backend does not authorize starting a new OS service or mount.
    permitted = _DEFAULT_STOP_UNITS if job is _JobAuthority.STOP else _DEFAULT_START_UNITS
    if (unit not in permitted or values["Id"] != unit or _unit_names(values["Names"]) != {unit} or
            values["Following"] or values["LoadState"] != "loaded" or values["Transient"] != "no" or
            values["NeedDaemonReload"] != "no" or values["DropInPaths"] or not _no_job(values) or
            values["StopWhenUnneeded"] != "no" or any(values[name] != "none" for name in
                ("FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction"))):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    if job is _JobAuthority.STOP:
        if values["ActiveState"] != "inactive" or values["SubState"] != "dead":
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        if unit.endswith(".service"):
            if unit != "emergency.service":
                _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
            _empty_typed(values, _EMERGENCY_EMPTY_PROPERTIES, _EXEC_SIGNATURE)
    elif unit == _DEFAULT_SLICE and job is _JobAuthority.START:
        if (values["ActiveState"], values["SubState"]) not in {("inactive", "dead"), ("active", "active")}:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    elif values["ActiveState"] != "active" or values["SubState"] != ("mounted" if unit.endswith(".mount") else "active"):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    graph = {name: _unit_names(values[name]) for name in _GRAPH_PROPERTIES if name not in _PATH_PROPERTIES}
    for name in _ORDERING_PROPERTIES:
        _unit_names(values[name])  # validate representation; do NOT pull jobs in
    for name in _PATH_PROPERTIES:
        _paths(values[name], {"/", "/tmp", "/opt", "/opt/pdi", "/opt/pdi/current", "/var", "/var/tmp"})
    # No execution handlers, independent triggers, namespace sharing, or reload
    # side channel is granted for a default prerequisite, in ANY job direction.
    if any(graph[name] for name in ("OnFailure", "OnSuccess", "Triggers", "JoinsNamespaceOf", "PropagatesReloadTo")):
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    if job is _JobAuthority.START and values["ActiveState"] == "inactive":
        # Only our per-template slice may newly activate. Failure of that start
        # must not propagate to a foreign dependent (especially a P3C writer).
        # The six canonical dependents are independently proved inactive/Job=
        # by the complete final bundle; no other consumer is authorized here.
        if any(not graph[name] <= set(_SERVICE_UNITS.values()) for name in
               ("RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf")):
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    return graph


def _job_edges(graph, job: _JobAuthority):
    if job is _JobAuthority.START:
        for name in _START_RELATIONS:
            for unit in sorted(graph[name]):
                yield name, unit, _JobAuthority.START
        for name in ("Conflicts", "ConflictedBy"):
            for unit in sorted(graph[name]):
                yield name, unit, _JobAuthority.STOP
        for unit in sorted(graph["Requisite"]):
            yield "Requisite", unit, _JobAuthority.VERIFY
    elif job is _JobAuthority.STOP:
        for name in _STOP_RELATIONS:
            for unit in sorted(graph[name]):
                yield name, unit, _JobAuthority.STOP
    # VERIFY_ACTIVE is an activity check, not START. Neither After/Before nor
    # PartOf/StopPropagatedFrom is an outgoing job expansion in this direction.


@dataclass(frozen=True)
class _JobClosure:
    fingerprint: str
    authority: dict
    runtime: tuple[tuple[str, _JobAuthority, tuple[str, str, str]], ...]


def _start_closure(key: str, source, assets: _Assets) -> _JobClosure:
    return _job_closure(key, source, assets, _JobAuthority.START)


def _job_closure(key: str, source, assets: _Assets, direction: _JobAuthority) -> _JobClosure:
    root = _SERVICE_UNITS[_key(key)]
    stack = [(root, direction, 0)]
    visited, fragments, edges = set(), [], []
    members, runtime = {}, []
    while stack:
        unit, job, depth = stack.pop()
        if (unit, job) in visited:
            continue
        if depth > _MAX_CLOSURE_DEPTH or len(visited) >= _MAX_CLOSURE_NODES:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        visited.add((unit, job))
        if unit == root and job is direction:
            _check_service(source, key, assets)
            graph = {name: _unit_names(source[name]) for name in _GRAPH_PROPERTIES if name not in _PATH_PROPERTIES}
        else:
            permitted = _DEFAULT_STOP_UNITS if job is _JobAuthority.STOP else _DEFAULT_START_UNITS
            if unit not in permitted:
                _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
            values = _default_show(unit)
            graph = _default_authority(values, unit, job)
            _default_dependency_directories(unit, values)
            fragments.append((unit, _default_fragment(values)))
            # Activity is independently checked and sealed in the final bundle,
            # not stable authority. The reviewed per-template slice can legally
            # become active due to the one authorized start. Keep that expected
            # change distinct from a changed fragment/graph/action authority.
            members[f"{unit}:{job.value}"] = _stable_default(values)
            runtime.append((unit, job, tuple(values[name] for name in ("ActiveState", "SubState", "Job"))))
        successors = tuple(_job_edges(graph, job))
        if any(target == "emergency.service" and
               (unit != "sysinit.target" or job is not _JobAuthority.START or relation != "Conflicts")
               for relation, target, _ in successors):
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        if len(edges) + len(successors) > _MAX_CLOSURE_EDGES:
            _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        for relation, target, target_job in successors:
            edges.append((unit, job.value, relation, target, target_job.value))
        stack.extend((target, target_job, depth + 1) for _, target, target_job in reversed(successors))
    authority = {"root": root, "direction": direction.value,
                 "edges": {"|".join(edge): edge for edge in sorted(edges)},
                 "defaults": members, "fragments": dict(sorted(fragments)),
                 "root_members": _relationship_members(source)}
    return _JobClosure(contract_fingerprint(authority), authority, tuple(runtime))


def _relationship_members(values):
    # Explicit member identity is part of the domain, not just the digest.
    return {name: {member: None for member in sorted(values[name].split())}
            for name in (*_GRAPH_PROPERTIES, *_ORDERING_PROPERTIES)}


def _stable_default(values):
    return {"properties": {name: tuple(sorted(value.split())) if name in
                           (*_GRAPH_PROPERTIES, *_ORDERING_PROPERTIES) else value
                           for name, value in values.items() if name not in {"ActiveState", "SubState", "Job"}},
            "members": _relationship_members(values)}


def _schema_domain(value, prefix="") -> tuple[str, ...]:
    """Exact recursive fields/members; separate comparison precedes hashing."""
    paths = [prefix]
    if isinstance(value, dict):
        for name in sorted(value):
            paths.extend(_schema_domain(value[name], prefix + "/" + name))
    elif isinstance(value, (tuple, list)):
        for index, member in enumerate(value):
            paths.extend(_schema_domain(member, prefix + f"/{index}"))
    return tuple(paths)


@dataclass(frozen=True, repr=False)
class _MutationSnapshot:
    domain: tuple[str, ...]
    fingerprint: str
    manager: _ManagerIdentity
    closure: _JobClosure


def _same_snapshot(before: _MutationSnapshot, after: _MutationSnapshot) -> None:
    if before.domain != after.domain:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    if before.fingerprint != after.fingerprint:
        _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)


def _invocation_id(value, *, prior: bool = False) -> str | None:
    # An absent prior invocation may be empty/zero; a new invocation never may.
    if prior and isinstance(value, str) and value in {"", "0" * 32}:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value) or value == "0" * 32:
        _fail(WP8FailureCode.SERVICE_EXECUTION_FAILED)
    return value


def _current_candidate(evidence: WP8PhaseAEvidenceV1) -> None:
    """Bounded final readlink/path check; full runtime rehash belongs before fence."""
    from .p3d_pre_rehearsal_evidence import _current_target
    from .p3d_inert_asset_install import InertAssetPolicy
    try:
        _current_target(InertAssetPolicy.production(), expected_source=evidence.candidate_sha)
    except BaseException:
        _fail(WP8FailureCode.CURRENT_DRIFT)


def _require_inactive(values) -> None:
    if values["ActiveState"] != "inactive" or values["SubState"] != "dead" or not _no_job(values):
        _fail(WP8FailureCode.SERVICE_EXECUTION_FAILED)


@dataclass(frozen=True)
class _ServiceResult:
    pipeline_key: str
    unit: str
    outcome: _Outcome
    manager_fingerprint: str
    unit_contract_fingerprint: str
    service_result_fingerprint: str
    final_state: str


@dataclass(frozen=True)
class _ServiceState:
    pipeline_key: str
    state: str  # INACTIVE or NOT_CONFIRMED; never return an arbitrary property


@dataclass(frozen=True)
class _ServiceStates:
    services: tuple[_ServiceState, ...]
    service_state: str


@dataclass(frozen=True)
class _TimerState:
    timer_state: str
    fingerprint: str


@dataclass(frozen=True)
class _P3CSnapshot:
    fingerprint: str
    p3c_state: str


@dataclass(frozen=True)
class _StopFact:
    pipeline_key: str
    outcome: _Outcome
    final_state: str


@dataclass(frozen=True)
class _CleanupFacts:
    attempts: tuple[_StopFact, ...]
    stop_failure_count: int
    service_state: str
    timer_state: str
    p3c_state: str


def _boundary(code):
    """Suppress arbitrary dependency exceptions at each public boundary."""
    from functools import wraps
    def decorate(method):
        @wraps(method)
        def safe(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except _BackendError:
                raise
            except BaseException:
                _fail(code)
        return safe
    return decorate


def _p3c_read_adapter(argv, **_kwargs):
    """Accept only exact read requests from the frozen provider, not a runner API."""
    if not isinstance(argv, tuple) or len(argv) not in {3, 4} or argv[0] != _SYSTEMCTL:
        _fail(WP8FailureCode.PREREQUISITE_DRIFT)
    requests = {"show": _Request.P3C_SHOW, "is-enabled": _Request.P3C_ENABLED,
                "is-active": _Request.P3C_ACTIVE}
    if argv[1] not in requests:
        _fail(WP8FailureCode.PREREQUISITE_DRIFT)
    if argv[2] in _p3c_units():
        if (len(argv) != (4 if argv[1] == "show" else 3) or
                (argv[1] == "show" and argv[3] != "--property=" + ",".join(_STABLE_PROPERTIES))):
            _fail(WP8FailureCode.PREREQUISITE_DRIFT)
        result = _systemctl(requests[argv[1]], argv[2])
        if argv[1] == "show":
            values = _properties(result, _STABLE_PROPERTIES, WP8FailureCode.PREREQUISITE_DRIFT)
            if (values["Id"] != argv[2] or values["LoadState"] != "loaded" or
                    values["FragmentPath"] != f"/etc/systemd/system/{argv[2]}"):
                _fail(WP8FailureCode.PREREQUISITE_DRIFT)
        return result
    # The frozen snapshot also observes P3D timers; it cannot target workloads.
    if len(argv) != 3 or argv[1] == "show":
        _fail(WP8FailureCode.PREREQUISITE_DRIFT)
    reverse = {unit: key for key, unit in _timer_units().items()}
    if argv[2] not in reverse:
        _fail(WP8FailureCode.PREREQUISITE_DRIFT)
    request = _Request.TIMER_ENABLED if argv[1] == "is-enabled" else _Request.TIMER_ACTIVE
    return _systemctl(request, reverse[argv[2]])


class WP8ProductionSystemdBackend:
    """Only the eight reviewed methods; no public runner, paths, or selectors.

    Phase A evidence is a binding, not execution authorization. A protected
    orchestrator must establish B authority before using any mutation method.
    In-process single-flight is not cross-process cutover serialization.
    The caller must hold the future protected operation lock and exclude P3D,
    P3C, Gate B/C, package/config maintenance and manual systemd/current changes.
    Two complete observations detect observable drift, not atomic CAS or ABA.
    Privileged external mutation after the final observation is an unavoidable
    API race, outside the cooperative serialization/root-trust guarantee.
    """

    def __init__(self, phase_a_evidence: WP8PhaseAEvidenceV1) -> None:
        try:
            self._evidence = WP8PhaseAEvidenceV1.from_mapping(phase_a_evidence.to_mapping())
        except BaseException:
            _fail(WP8FailureCode.PREREQUISITE_DRIFT)
        self._manager_anchor = None
        self._anchor_guard = threading.Lock()
        self._flight = threading.Lock()

    @_boundary(WP8FailureCode.SYSTEMD_MANAGER_INVALID)
    def manager_identity(self) -> _ManagerIdentity:
        identity = _observe_manager()
        with self._anchor_guard:
            if self._manager_anchor is None:
                self._manager_anchor = identity
            elif self._manager_anchor != identity:
                _fail(WP8FailureCode.SYSTEMD_MANAGER_INVALID)
        return identity

    @_boundary(WP8FailureCode.DAEMON_RELOAD_FAILED)
    def daemon_reload(self) -> str:
        if not self._flight.acquire(blocking=False):
            _fail(WP8FailureCode.DAEMON_RELOAD_FAILED, _Outcome.BUSY)
        try:
            before = self.manager_identity()
            self.snapshot_p3c()
            self._timer_facts(allow_stale=True)
            _verify_candidate(self._evidence)
            assets = _read_assets(self._evidence)
            # Inspect trusted definitions before reload; stale loaded properties
            # are checked only after the explicit, authorized manager mutation.
            for key in WP8_CANONICAL_PIPELINE_KEYS:
                values = self._show(key)
                _identity(values, key, allow_stale=True)
                if values["ActiveState"] != "inactive" or not _no_job(values):
                    _fail(WP8FailureCode.DAEMON_RELOAD_FAILED)
            result = _systemctl(_Request.RELOAD)
            if result.returncode != 0:
                _fail(WP8FailureCode.DAEMON_RELOAD_FAILED, _Outcome.COMMAND_FAILED)
            if before != self.manager_identity() or assets != _read_assets(self._evidence):
                _fail(WP8FailureCode.DAEMON_RELOAD_FAILED)
            for key in WP8_CANONICAL_PIPELINE_KEYS:
                _check_service(self._show(key), key, assets)
            self.verify_all_services_inactive()
            self.verify_timers_quiet()
            self.snapshot_p3c()
            _verify_candidate(self._evidence)
            return contract_fingerprint({"daemon_reload": "SUCCESS", "manager": before.fingerprint,
                                         "assets": assets.fingerprint})
        finally:
            self._flight.release()

    @_boundary(WP8FailureCode.PREREQUISITE_DRIFT)
    def snapshot_p3c(self) -> _P3CSnapshot:
        from .p3d_inert_asset_install import ProductionReadOnlySystemdStateProvider
        self.manager_identity()
        observed = ProductionReadOnlySystemdStateProvider(runner=_p3c_read_adapter).snapshot(post_install=True)
        if not observed.p3d_quiet or observed.p3c_fingerprint != self._evidence.p3c_systemd_fingerprint:
            _fail(WP8FailureCode.PREREQUISITE_DRIFT)
        self.manager_identity()
        return _P3CSnapshot(observed.p3c_fingerprint, "UNCHANGED_HEALTHY")

    @_boundary(WP8FailureCode.PREREQUISITE_DRIFT)
    def verify_timers_quiet(self) -> _TimerState:
        return self._timer_facts()

    def _timer_facts(self, *, allow_stale: bool = False) -> _TimerState:
        _read_assets(self._evidence)
        return self._observe_timers(allow_stale=allow_stale)

    def _observe_timers(self, *, allow_stale: bool = False, manager: _ManagerIdentity | None = None) -> _TimerState:
        """Immediate loaded-state reads; no asset traversal/profile hashing."""
        self.manager_identity() if manager is None else _manager_token(manager)
        facts = []
        for key in WP8_CANONICAL_PIPELINE_KEYS:
            values = _properties(_systemctl(_Request.TIMER_SHOW, key), _TIMER_PROPERTIES)
            _identity(values, key, timer=True, allow_stale=allow_stale)
            enabled, active = _systemctl(_Request.TIMER_ENABLED, key), _systemctl(_Request.TIMER_ACTIVE, key)
            if (enabled.returncode != 1 or enabled.stdout.strip() != "disabled" or
                    active.returncode != 3 or active.stdout.strip() != "inactive" or
                    values["ActiveState"] != "inactive" or values["SubState"] != "dead" or
                    not _no_job(values) or values["Unit"] != _SERVICE_UNITS[key]):
                _fail(WP8FailureCode.PREREQUISITE_DRIFT)
            facts.append({"pipeline": key, "enabled": "disabled", "active": "inactive"})
        self.manager_identity() if manager is None else _manager_token(manager)
        return _TimerState("DISABLED_INACTIVE", contract_fingerprint({"timers": facts}))

    def _show(self, key):
        return _collect_current_service_authority(key)

    def _p3c_authority(self):
        from .p3d_inert_asset_install import ProductionReadOnlySystemdStateProvider
        observed = ProductionReadOnlySystemdStateProvider(runner=_p3c_read_adapter).snapshot(post_install=True)
        if not observed.p3d_quiet or observed.p3c_fingerprint != self._evidence.p3c_systemd_fingerprint:
            _fail(WP8FailureCode.PREREQUISITE_DRIFT)
        return {unit: _properties(_p3c_read_adapter((_SYSTEMCTL, "show", unit,
                "--property=" + ",".join(_STABLE_PROPERTIES))), _STABLE_PROPERTIES)
                for unit in _p3c_units()}

    def _collect_complete_start_authority_snapshot(self, key):
        return self._collect_complete_authority_snapshot(key, _JobAuthority.START)

    def _collect_complete_stop_authority_snapshot(self, key):
        return self._collect_complete_authority_snapshot(key, _JobAuthority.STOP)

    @_boundary(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    def _collect_complete_authority_snapshot(self, key, direction):
        """Self-contained collection; never takes another snapshot as input.

        Every loaded text/typed/default/emergency/manager/asset observation is
        read anew. Completion does not assert an atomic multi-interface view.
        """
        key = _key(key)
        manager = self.manager_identity()
        runtime = _verify_candidate(self._evidence)
        assets = _read_assets(self._evidence)
        timers = {}
        for other in WP8_CANONICAL_PIPELINE_KEYS:
            values = _properties(_systemctl(_Request.TIMER_SHOW, other), _TIMER_PROPERTIES)
            _identity(values, other, timer=True)
            if values["Unit"] != _SERVICE_UNITS[other]:
                _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
            timers[other] = {name: value for name, value in values.items()
                             if name not in {"ActiveState", "SubState", "Job"}}
        p3c = self._p3c_authority()
        services, loaded = {}, {}
        selected = WP8_CANONICAL_PIPELINE_KEYS if direction is _JobAuthority.START else (key,)
        for other in selected:
            _dependency_directories(other)
            values = self._show(other)
            _check_service(values, other, assets)
            loaded[other] = values
            services[other] = {"text": _service_authority_text(values),
                              "typed": {name: values[name] for name in
                                        (*_EXEC_EMPTY_PROPERTIES, *_UNIT_EMPTY_PROPERTIES)},
                              "members": _relationship_members(values)}
        closure = _job_closure(key, loaded[key], assets, direction)
        # Actual current, not a Phase A cached loaded state. Full runtime proof
        # above independently binds Gate B; assets bind Gate C/profiles.
        _current_candidate(self._evidence)
        _manager_token(manager)
        payload = {"direction": direction.value, "pipeline": key,
            "manager": {"fingerprint": manager.fingerprint, "boot": manager.boot_fingerprint,
                        "host_class": manager.host_class,
                        "domain": {field: None for field in manager.authority_domain},
                        "continuity": manager.continuity_token},
            "context": {"candidate": self._evidence.candidate_sha,
                        "phase_a": self._evidence.phase_a_context_fingerprint,
                        "current_candidate": self._evidence.candidate_sha,
                        "gate_b": self._evidence.gate_b_authority_binding_fingerprint,
                        "gate_c": self._evidence.gate_c_authority_binding_fingerprint},
            "runtime": runtime, "assets": assets.fingerprint, "services": services,
            "timers": timers, "p3c": {unit: {name: value for name, value in values.items()
                if name not in {"ActiveState", "SubState"}} for unit, values in p3c.items()},
            "closure": closure.authority}
        return _MutationSnapshot(_schema_domain(payload), contract_fingerprint(payload), manager, closure)

    def _final_runtime_prerequisites(self, key, snapshot, *, starting):
        """Bounded reads after A/B equality; no tree hash or graph traversal.

        Current observations cannot prevent an external privileged mutation
        between their completion and systemd accepting the fixed command.
        """
        _manager_token(snapshot.manager)
        self._observe_timers(manager=snapshot.manager)
        self._p3c_authority()
        for unit, job, expected in snapshot.closure.runtime:
            values = _properties(_systemctl(_Request.DEFAULT_SHOW, unit), _DEFAULT_PROPERTIES)
            if tuple(values[name] for name in ("ActiveState", "SubState", "Job")) != expected:
                _fail(WP8FailureCode.SERVICE_CONTRACT_INVALID)
        target = None
        selected = tuple(other for other in WP8_CANONICAL_PIPELINE_KEYS if other != key) + (key,) if starting else (key,)
        for other in selected:
            values = _properties(_systemctl(_Request.SERVICE_RUNTIME_SHOW, other),
                                 tuple(name for name in _SERVICE_PROPERTIES if name in _SERVICE_RUNTIME_PROPERTIES))
            if starting:
                _require_inactive(values)
            if other == key:
                target = values
        _current_candidate(self._evidence)
        _manager_token(snapshot.manager)
        return target

    @_boundary(WP8FailureCode.SERVICE_CONTRACT_INVALID)
    def verify_service_contract(self, pipeline_key: str) -> str:
        key = _key(pipeline_key)
        self.manager_identity()
        runtime = _verify_candidate(self._evidence)
        assets = _read_assets(self._evidence)
        _dependency_directories(key)
        values = self._show(key)
        fingerprint = _check_service(values, key, assets)
        closure = _start_closure(key, values, assets)
        self.manager_identity()
        return contract_fingerprint({"service_contract": fingerprint, "runtime": runtime,
                                     "context": self._evidence.phase_a_context_fingerprint,
                                     "closure": closure.fingerprint})

    @_boundary(WP8FailureCode.SERVICE_EXECUTION_FAILED)
    def start_service(self, pipeline_key: str) -> _ServiceResult:
        key = _key(pipeline_key)
        if not self._flight.acquire(blocking=False):
            _fail(WP8FailureCode.SERVICE_EXECUTION_FAILED, _Outcome.BUSY)
        try:
            first = self._collect_complete_start_authority_snapshot(key)
            second = self._collect_complete_start_authority_snapshot(key)
            _same_snapshot(first, second)
            manager, contract = second.manager, second.fingerprint
            before = self._final_runtime_prerequisites(key, second, starting=True)
            prior_start = int(before["ExecMainStartTimestampMonotonic"])
            prior_invocation = _invocation_id(before["InvocationID"], prior=True)
            # The last observation before fixed start. No candidate tree walk,
            # manifest/profile hashing or dependency scan may occur in this gap.
            boundary = time.monotonic_ns() // 1000
            result = _systemctl(_Request.SERVICE_START, key)
            if result.returncode != 0:
                _fail(WP8FailureCode.SERVICE_EXECUTION_FAILED, _Outcome.COMMAND_FAILED)
            after = self._show(key)
            finished = time.monotonic_ns() // 1000
            start, end = int(after["ExecMainStartTimestampMonotonic"]), int(after["ExecMainExitTimestampMonotonic"])
            if (after["ConditionResult"] != "yes" or after["AssertResult"] != "yes" or
                    after["Result"] != "success" or after["ExecMainCode"] != "1" or
                    after["ExecMainStatus"] != "0" or after["ActiveState"] != "inactive" or
                    after["SubState"] != "dead" or not _no_job(after) or
                    not (prior_start < start and boundary <= start <= end <= finished)):
                _fail(WP8FailureCode.SERVICE_EXECUTION_FAILED)
            invocation = _invocation_id(after["InvocationID"])
            if invocation == prior_invocation:
                _fail(WP8FailureCode.SERVICE_EXECUTION_FAILED)
            post = self._collect_complete_start_authority_snapshot(key)
            _same_snapshot(second, post)
            self.verify_all_services_inactive()
            self.verify_timers_quiet()
            self.snapshot_p3c()
            fingerprint = contract_fingerprint({
                "candidate": self._evidence.candidate_sha,
                "context": self._evidence.phase_a_context_fingerprint,
                "pipeline": key, "manager": manager.fingerprint, "contract": contract,
                "start": start, "exit": end, "invocation_hash": _digest(invocation.encode()),
                "result": "success", "exit_status": 0,
            })
            return _ServiceResult(key, _SERVICE_UNITS[key], _Outcome.SUCCESS,
                                  manager.fingerprint, contract, fingerprint, "INACTIVE")
        finally:
            self._flight.release()

    def _inactive_facts(self) -> _ServiceStates:
        facts = []
        try:
            assets = _read_assets(self._evidence)
        except BaseException:
            assets = None
        for key in WP8_CANONICAL_PIPELINE_KEYS:
            state = "NOT_CONFIRMED"
            try:
                self.manager_identity()
                directories_trusted = False
                try:
                    _dependency_directories(key)
                    directories_trusted = True
                except BaseException:
                    pass
                values = self._show(key)  # every final state independently queried
                if assets is not None and directories_trusted:
                    _check_service(values, key, assets)
                    if values["ActiveState"] == "inactive" and values["SubState"] == "dead" and _no_job(values):
                        state = "INACTIVE"
            except BaseException:
                pass
            facts.append(_ServiceState(key, state))
        try:
            self.manager_identity()
        except BaseException:
            facts = [_ServiceState(item.pipeline_key, "NOT_CONFIRMED") for item in facts]
        return _ServiceStates(tuple(facts), "INACTIVE" if all(item.state == "INACTIVE" for item in facts)
                              else "NOT_CONFIRMED")

    @_boundary(WP8FailureCode.CLEANUP_FAILED)
    def verify_all_services_inactive(self) -> _ServiceStates:
        result = self._inactive_facts()
        if result.service_state != "INACTIVE":
            _fail(WP8FailureCode.CLEANUP_FAILED)
        return result

    @_boundary(WP8FailureCode.CLEANUP_FAILED)
    def stop_all_services(self) -> _CleanupFacts:
        if not self._flight.acquire(blocking=False):
            _fail(WP8FailureCode.CLEANUP_FAILED, _Outcome.BUSY)
        try:
            outcomes = []
            for key in WP8_CANONICAL_PIPELINE_KEYS:
                stop_requested = False
                try:
                    # Stop can propagate through the loaded graph. Prove each
                    # target BEFORE mutating; an unsafe target is skipped while
                    # remaining targets are independently evaluated.
                    first = self._collect_complete_stop_authority_snapshot(key)
                    second = self._collect_complete_stop_authority_snapshot(key)
                    _same_snapshot(first, second)
                    self._final_runtime_prerequisites(key, second, starting=False)
                    stop_requested = True
                    result = _systemctl(_Request.SERVICE_STOP, key)
                    outcome = _Outcome.SUCCESS if result.returncode == 0 else _Outcome.COMMAND_FAILED
                    post = self._collect_complete_stop_authority_snapshot(key)
                    _same_snapshot(second, post)
                    _require_inactive(self._show(key))
                except _BackendError as exc:
                    # Failed evidence reads are not issued stop commands.
                    outcome = exc.outcome if stop_requested else _Outcome.EVIDENCE_REJECTED
                except BaseException:
                    outcome = _Outcome.EVIDENCE_REJECTED
                outcomes.append((key, outcome))  # no short circuit, including timeouts
            final = self._inactive_facts()
            # A failed authority/post-continuity proof cannot be upgraded to a
            # confirmed cleanup just because a later activity read is inactive.
            final = _ServiceStates(tuple(_ServiceState(state.pipeline_key,
                "NOT_CONFIRMED" if outcome is _Outcome.EVIDENCE_REJECTED else state.state)
                for (_, outcome), state in zip(outcomes, final.services, strict=True)), final.service_state)
            final = _ServiceStates(final.services, "INACTIVE" if all(
                state.state == "INACTIVE" for state in final.services) else "NOT_CONFIRMED")
            try:
                timers = self.verify_timers_quiet().timer_state
            except BaseException:
                timers = "NOT_CONFIRMED"
            try:
                p3c = self.snapshot_p3c().p3c_state
            except BaseException:
                p3c = "NOT_CONFIRMED"
            return _CleanupFacts(
                tuple(_StopFact(key, outcome, state.state)
                      for (key, outcome), state in zip(outcomes, final.services, strict=True)),
                sum(outcome is not _Outcome.SUCCESS for _, outcome in outcomes),
                final.service_state, timers, p3c,
            )
        finally:
            self._flight.release()
