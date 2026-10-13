"""Pure MU13-P3D preparation contracts.

This module defines versioned schemas, canonical fingerprints and state
machines.  Importing it performs no filesystem, database, subprocess, Git or
systemd operation.  The atomic persistence helper is inert until explicitly
called and defaults to a root-owned trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, Mapping, Sequence
import unicodedata
from uuid import UUID


GIT_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)
PACKAGE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}")
PINNED_VERSION = re.compile(r"[0-9][0-9A-Za-z._+~:-]{0,127}")
MODE = re.compile(r"0[0-7]{3}")
FORBIDDEN_SECRET_MARKERS = (
    "DATABASE_URL", "PASSWORD", "TOKEN", "SECRET", "OAUTH",
    "MAIL_BODY", "MAIL_SUBJECT",
)


class FailureCode(str, Enum):
    """Fixed diagnostics allowed in preparation state and journals."""

    CONTRACT_FIELD_SET_INVALID = "P3D_PREP_CONTRACT_FIELD_SET_INVALID"
    CONTRACT_VALUE_INVALID = "P3D_PREP_CONTRACT_VALUE_INVALID"
    CONTRACT_VERSION_UNSUPPORTED = "P3D_PREP_CONTRACT_VERSION_UNSUPPORTED"
    CONTRACT_SECRET_MATERIAL = "P3D_PREP_CONTRACT_SECRET_MATERIAL"
    CONTRACT_TRANSITION_INVALID = "P3D_PREP_CONTRACT_TRANSITION_INVALID"
    CONTRACT_CANDIDATE_MISMATCH = "P3D_PREP_CONTRACT_CANDIDATE_MISMATCH"
    CONTRACT_FINGERPRINT_MISMATCH = "P3D_PREP_CONTRACT_FINGERPRINT_MISMATCH"
    CONTRACT_PERSISTENCE_CONFLICT = "P3D_PREP_CONTRACT_PERSISTENCE_CONFLICT"
    CONTRACT_PERSISTENCE_UNTRUSTED = "P3D_PREP_CONTRACT_PERSISTENCE_UNTRUSTED"

    ROLLBACK_SOURCE_INVALID = "P3D_ROLLBACK_SOURCE_INVALID"
    ROLLBACK_SNAPSHOT_EXPORT_FAILED = "P3D_ROLLBACK_SNAPSHOT_EXPORT_FAILED"
    ROLLBACK_DUMP_FAILED = "P3D_ROLLBACK_DUMP_FAILED"
    ROLLBACK_BACKUP_FAILED = "P3D_ROLLBACK_BACKUP_FAILED"
    ROLLBACK_RESTORE_FAILED = "P3D_ROLLBACK_RESTORE_FAILED"
    ROLLBACK_RUNTIME_INVALID = "P3D_ROLLBACK_RUNTIME_INVALID"
    ROLLBACK_COMPATIBILITY_FAILED = "P3D_ROLLBACK_COMPATIBILITY_FAILED"
    ROLLBACK_PIN_FAILED = "P3D_ROLLBACK_PIN_FAILED"
    ROLLBACK_METADATA_CONFLICT = "P3D_ROLLBACK_METADATA_CONFLICT"

    RELEASE_ARTIFACT_INVALID = "P3D_RELEASE_STAGE_ARTIFACT_INVALID"
    RELEASE_OS_RUNTIME_MISMATCH = "P3D_RELEASE_STAGE_OS_RUNTIME_MISMATCH"
    RELEASE_WHEELHOUSE_INVALID = "P3D_RELEASE_STAGE_WHEELHOUSE_INVALID"
    RELEASE_SOURCE_CHECKOUT_FAILED = "P3D_RELEASE_STAGE_SOURCE_CHECKOUT_FAILED"
    RELEASE_VENV_FAILED = "P3D_RELEASE_STAGE_VENV_FAILED"
    RELEASE_RUNTIME_INVALID = "P3D_RELEASE_STAGE_RUNTIME_INVALID"
    RELEASE_IMMUTABILITY_FAILED = "P3D_RELEASE_STAGE_IMMUTABILITY_FAILED"
    RELEASE_FINAL_CONFLICT = "P3D_RELEASE_STAGE_FINAL_CONFLICT"

    ASSET_PREREQUISITE_INVALID = "P3D_ASSET_INSTALL_PREREQUISITE_INVALID"
    ASSET_REGISTRY_INVALID = "P3D_ASSET_INSTALL_REGISTRY_INVALID"
    ASSET_DB_EVIDENCE_INVALID = "P3D_ASSET_INSTALL_DB_EVIDENCE_INVALID"
    ASSET_PROFILE_INVALID = "P3D_ASSET_INSTALL_PROFILE_INVALID"
    ASSET_STATIC_VERIFY_FAILED = "P3D_ASSET_INSTALL_STATIC_VERIFY_FAILED"
    ASSET_FILE_CONFLICT = "P3D_ASSET_INSTALL_FILE_CONFLICT"
    ASSET_SYSTEMD_NOT_QUIET = "P3D_ASSET_INSTALL_SYSTEMD_NOT_QUIET"
    ASSET_COMPLETE_MARKER_FAILED = "P3D_ASSET_INSTALL_COMPLETE_MARKER_FAILED"


class PreparationContractError(ValueError):
    """A fail-closed contract rejection containing only a fixed code."""

    def __init__(self, code: FailureCode):
        self.code = code
        super().__init__(code.value)


def _fail(code: FailureCode = FailureCode.CONTRACT_VALUE_INVALID) -> None:
    raise PreparationContractError(code)


def _exact(mapping: Mapping[str, Any], fields: set[str]) -> None:
    if not isinstance(mapping, Mapping) or set(mapping) != fields:
        _fail(FailureCode.CONTRACT_FIELD_SET_INVALID)


def _safe_text(value: Any, *, pattern: re.Pattern[str] | None = None) -> str:
    if (not isinstance(value, str) or not value or
            any(unicodedata.category(char) == "Cc" for char in value)):
        _fail()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail()
    return value


def _git_sha(value: Any) -> str:
    return _safe_text(value, pattern=GIT_SHA)


def _sha256(value: Any) -> str:
    return _safe_text(value, pattern=SHA256)


def _utc_timestamp(value: Any) -> str:
    value = _safe_text(value)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        _fail()
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail()
    return value


def utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail()
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        _fail()
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid(value: Any) -> str:
    value = _safe_text(value)
    try:
        parsed = UUID(value)
    except ValueError:
        _fail()
    if str(parsed) != value:
        _fail()
    return value


def _sorted_unique(values: Any, validator) -> tuple[Any, ...]:
    if not isinstance(values, (list, tuple)):
        _fail()
    normalized = tuple(validator(item) for item in values)
    if not normalized or len(set(normalized)) != len(normalized):
        _fail()
    return tuple(sorted(normalized))


def reject_secret_material(value: Any) -> None:
    """Defense in depth around strict allowlisted schemas."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail()
            upper = key.upper()
            if any(marker in upper for marker in FORBIDDEN_SECRET_MARKERS):
                _fail(FailureCode.CONTRACT_SECRET_MATERIAL)
            reject_secret_material(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            reject_secret_material(item)
    elif isinstance(value, str):
        upper = value.upper()
        if any(marker in upper for marker in FORBIDDEN_SECRET_MARKERS):
            _fail(FailureCode.CONTRACT_SECRET_MATERIAL)


def _canonicalize(value: Any) -> Any:
    if hasattr(value, "to_mapping"):
        value = value.to_mapping()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return utc_timestamp(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            _fail()
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ))
    if isinstance(value, (tuple, list)):
        return [_canonicalize(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    _fail()


def canonical_json_bytes(value: Any) -> bytes:
    """Return the single long-term canonical representation for contracts."""

    normalized = _canonicalize(value)
    reject_secret_material(normalized)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def contract_fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class ToolName(str, Enum):
    BACKUP_EXPORT = "pdi.p3d.backup-export"
    RESTORE_QUALIFY = "pdi.p3d.restore-qualify"
    RELEASE_BUNDLE_BUILD = "pdi.p3d.release-bundle-build"
    RELEASE_BOOTSTRAP = "pdi.p3d.release-bootstrap"
    INERT_ASSET_INSTALL = "pdi.p3d.inert-asset-install"


@dataclass(frozen=True)
class OperatorToolIdentity:
    tool_name: ToolName
    tool_version: str
    tool_artifact_sha256: str
    tool_source_sha: str

    FIELDS = {"TOOL_NAME", "TOOL_VERSION", "TOOL_ARTIFACT_SHA256", "TOOL_SOURCE_SHA"}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OperatorToolIdentity":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        try:
            name = ToolName(value["TOOL_NAME"])
        except (ValueError, TypeError):
            _fail()
        return cls(
            name,
            _safe_text(value["TOOL_VERSION"], pattern=SEMVER),
            _sha256(value["TOOL_ARTIFACT_SHA256"]),
            _git_sha(value["TOOL_SOURCE_SHA"]),
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "TOOL_NAME": self.tool_name.value,
            "TOOL_VERSION": self.tool_version,
            "TOOL_ARTIFACT_SHA256": self.tool_artifact_sha256,
            "TOOL_SOURCE_SHA": self.tool_source_sha,
        }


def _prefixed_tool(value: Mapping[str, Any], prefix: str) -> OperatorToolIdentity:
    return OperatorToolIdentity.from_mapping({
        key: value[f"{prefix}_{key}"] for key in OperatorToolIdentity.FIELDS
    })


@dataclass(frozen=True)
class P3DRollbackMetadataV1:
    snapshot_id: str
    snapshot_tags: tuple[str, ...]
    dump_sha256: str
    baseline_counts_sha256: str
    exported_snapshot_evidence_hash: str
    source_sha: str
    source_release_sha: str
    source_release_fingerprint: str
    source_runtime_fingerprint: str
    source_system_runtime_fingerprint: str
    target_candidate_sha: str
    source_db_fingerprint: str
    p3c_context_fingerprint: str
    p3c_soak_evidence_sha256: str
    restored_invariants_sha256: str
    backup_fs_uuid: str
    restic_repository: str
    qualified_at_utc: str
    export_tool: OperatorToolIdentity
    restore_tool: OperatorToolIdentity

    FIXED = {
        "METADATA_VERSION": "1",
        "BACKUP_CLASS": "P3D_PRE_ENRICHMENT",
        "ALEMBIC": "e5a7b9d1f324",
        "POSTGRES_MAJOR": "16",
        "P3C_PRODUCTION_ENABLED": "YES",
        "P3C_SOAK": "PASS",
        "RESTORE_TESTED": "YES",
        "RESTORED_COUNTS_MATCH": "YES",
        "ROLLBACK_DB_SNAPSHOT_QUALIFIED": "YES",
        "ROLLBACK_RUNTIME_RELEASE_QUALIFIED": "YES",
        "ROLLBACK_DB_RUNTIME_COMPATIBILITY": "PASS",
        "ROLLBACK_SOURCE_RELEASE_PINNED": "YES",
        "ROLLBACK_METADATA_READY": "YES",
    }
    FIELDS = set(FIXED) | {
        "SNAPSHOT_ID", "SNAPSHOT_TAGS", "DUMP_SHA256", "BASELINE_COUNTS_SHA256",
        "EXPORTED_SNAPSHOT_EVIDENCE_HASH", "SOURCE_SHA", "SOURCE_RELEASE_SHA",
        "SOURCE_RELEASE_FINGERPRINT", "SOURCE_RUNTIME_FINGERPRINT",
        "SOURCE_SYSTEM_RUNTIME_FINGERPRINT", "TARGET_CANDIDATE_SHA",
        "SOURCE_DB_FINGERPRINT", "P3C_CONTEXT_FINGERPRINT",
        "P3C_SOAK_EVIDENCE_SHA256", "RESTORED_INVARIANTS_SHA256",
        "BACKUP_FS_UUID", "RESTIC_REPOSITORY", "QUALIFIED_AT_UTC",
    } | {f"EXPORT_{field}" for field in OperatorToolIdentity.FIELDS} | {
        f"RESTORE_{field}" for field in OperatorToolIdentity.FIELDS
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "P3DRollbackMetadataV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if any(value[key] != expected for key, expected in cls.FIXED.items()):
            _fail()
        source_sha = _git_sha(value["SOURCE_SHA"])
        source_release_sha = _git_sha(value["SOURCE_RELEASE_SHA"])
        candidate_sha = _git_sha(value["TARGET_CANDIDATE_SHA"])
        if source_sha != source_release_sha or source_sha == candidate_sha:
            _fail()
        repository = _safe_text(value["RESTIC_REPOSITORY"])
        if "\n" in repository or "\r" in repository or "://" in repository:
            _fail(FailureCode.CONTRACT_SECRET_MATERIAL)
        export_tool = _prefixed_tool(value, "EXPORT")
        restore_tool = _prefixed_tool(value, "RESTORE")
        if (export_tool.tool_name is not ToolName.BACKUP_EXPORT or
                restore_tool.tool_name is not ToolName.RESTORE_QUALIFY):
            _fail(FailureCode.CONTRACT_VALUE_INVALID)
        return cls(
            _safe_text(value["SNAPSHOT_ID"], pattern=SHA256),
            _sorted_unique(value["SNAPSHOT_TAGS"], lambda item: _safe_text(item, pattern=SAFE_NAME)),
            _sha256(value["DUMP_SHA256"]),
            _sha256(value["BASELINE_COUNTS_SHA256"]),
            _sha256(value["EXPORTED_SNAPSHOT_EVIDENCE_HASH"]),
            source_sha,
            source_release_sha,
            _sha256(value["SOURCE_RELEASE_FINGERPRINT"]),
            _sha256(value["SOURCE_RUNTIME_FINGERPRINT"]),
            _sha256(value["SOURCE_SYSTEM_RUNTIME_FINGERPRINT"]),
            candidate_sha,
            _sha256(value["SOURCE_DB_FINGERPRINT"]),
            _sha256(value["P3C_CONTEXT_FINGERPRINT"]),
            _sha256(value["P3C_SOAK_EVIDENCE_SHA256"]),
            _sha256(value["RESTORED_INVARIANTS_SHA256"]),
            _uuid(value["BACKUP_FS_UUID"]),
            repository,
            _utc_timestamp(value["QUALIFIED_AT_UTC"]),
            export_tool,
            restore_tool,
        )

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            **self.FIXED,
            "SNAPSHOT_ID": self.snapshot_id,
            "SNAPSHOT_TAGS": list(self.snapshot_tags),
            "DUMP_SHA256": self.dump_sha256,
            "BASELINE_COUNTS_SHA256": self.baseline_counts_sha256,
            "EXPORTED_SNAPSHOT_EVIDENCE_HASH": self.exported_snapshot_evidence_hash,
            "SOURCE_SHA": self.source_sha,
            "SOURCE_RELEASE_SHA": self.source_release_sha,
            "SOURCE_RELEASE_FINGERPRINT": self.source_release_fingerprint,
            "SOURCE_RUNTIME_FINGERPRINT": self.source_runtime_fingerprint,
            "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": self.source_system_runtime_fingerprint,
            "TARGET_CANDIDATE_SHA": self.target_candidate_sha,
            "SOURCE_DB_FINGERPRINT": self.source_db_fingerprint,
            "P3C_CONTEXT_FINGERPRINT": self.p3c_context_fingerprint,
            "P3C_SOAK_EVIDENCE_SHA256": self.p3c_soak_evidence_sha256,
            "RESTORED_INVARIANTS_SHA256": self.restored_invariants_sha256,
            "BACKUP_FS_UUID": self.backup_fs_uuid,
            "RESTIC_REPOSITORY": self.restic_repository,
            "QUALIFIED_AT_UTC": self.qualified_at_utc,
        }
        result.update({f"EXPORT_{key}": item for key, item in self.export_tool.to_mapping().items()})
        result.update({f"RESTORE_{key}": item for key, item in self.restore_tool.to_mapping().items()})
        return result


@dataclass(frozen=True, order=True)
class PackageVersionEntryV1:
    name: str
    version: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PackageVersionEntryV1":
        _exact(value, {"NAME", "VERSION"})
        return cls(
            _safe_text(value["NAME"], pattern=PACKAGE_NAME),
            _safe_text(value["VERSION"], pattern=PINNED_VERSION),
        )

    def to_mapping(self) -> dict[str, str]:
        return {"NAME": self.name, "VERSION": self.version}


@dataclass(frozen=True)
class OSRuntimeManifestV1:
    os_id: str
    os_version_id: str
    arch: str
    approved_packages: tuple[PackageVersionEntryV1, ...]
    system_python_path: str
    python_implementation: str
    python_version: str
    python_abi: str
    system_runtime_file_sha256: str
    native_library_package_set: tuple[str, ...]

    FIELDS = {
        "MANIFEST_VERSION", "OS_ID", "OS_VERSION_ID", "ARCH",
        "APPROVED_PACKAGE_NAMES_AND_VERSIONS", "SYSTEM_PYTHON_PATH",
        "PYTHON_IMPLEMENTATION", "PYTHON_VERSION", "PYTHON_ABI",
        "SYSTEM_RUNTIME_FILE_SHA256", "NATIVE_LIBRARY_PACKAGE_SET",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OSRuntimeManifestV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if value["MANIFEST_VERSION"] != "1":
            _fail(FailureCode.CONTRACT_VERSION_UNSUPPORTED)
        raw_packages = value["APPROVED_PACKAGE_NAMES_AND_VERSIONS"]
        if not isinstance(raw_packages, (list, tuple)) or not raw_packages:
            _fail()
        packages = tuple(sorted(PackageVersionEntryV1.from_mapping(item) for item in raw_packages))
        if len({item.name for item in packages}) != len(packages):
            _fail()
        python_path = _safe_text(value["SYSTEM_PYTHON_PATH"])
        if not PurePosixPath(python_path).is_absolute() or ".." in PurePosixPath(python_path).parts:
            _fail()
        native_packages = _sorted_unique(
            value["NATIVE_LIBRARY_PACKAGE_SET"],
            lambda item: _safe_text(item, pattern=PACKAGE_NAME),
        )
        if not set(native_packages).issubset({item.name for item in packages}):
            _fail(FailureCode.RELEASE_OS_RUNTIME_MISMATCH)
        return cls(
            _safe_text(value["OS_ID"], pattern=SAFE_NAME),
            _safe_text(value["OS_VERSION_ID"], pattern=SAFE_NAME),
            _safe_text(value["ARCH"], pattern=SAFE_NAME),
            packages,
            python_path,
            _safe_text(value["PYTHON_IMPLEMENTATION"], pattern=SAFE_NAME),
            _safe_text(value["PYTHON_VERSION"], pattern=SAFE_NAME),
            _safe_text(value["PYTHON_ABI"], pattern=SAFE_NAME),
            _sha256(value["SYSTEM_RUNTIME_FILE_SHA256"]),
            native_packages,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "MANIFEST_VERSION": "1",
            "OS_ID": self.os_id,
            "OS_VERSION_ID": self.os_version_id,
            "ARCH": self.arch,
            "APPROVED_PACKAGE_NAMES_AND_VERSIONS": [item.to_mapping() for item in self.approved_packages],
            "SYSTEM_PYTHON_PATH": self.system_python_path,
            "PYTHON_IMPLEMENTATION": self.python_implementation,
            "PYTHON_VERSION": self.python_version,
            "PYTHON_ABI": self.python_abi,
            "SYSTEM_RUNTIME_FILE_SHA256": self.system_runtime_file_sha256,
            "NATIVE_LIBRARY_PACKAGE_SET": list(self.native_library_package_set),
        }


def os_runtime_manifest_fingerprint(value: OSRuntimeManifestV1) -> str:
    return contract_fingerprint(value)


@dataclass(frozen=True, order=True)
class WheelEntryV1:
    package: str
    version: str
    filename: str
    sha256: str
    tags: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WheelEntryV1":
        _exact(value, {"PACKAGE", "VERSION", "FILENAME", "SHA256", "TAGS"})
        package = _safe_text(value["PACKAGE"], pattern=PACKAGE_NAME)
        version = _safe_text(value["VERSION"], pattern=PINNED_VERSION)
        filename = _safe_text(value["FILENAME"])
        if PurePosixPath(filename).name != filename or not filename.endswith(".whl"):
            _fail()
        return cls(
            package,
            version,
            filename,
            _sha256(value["SHA256"]),
            _sorted_unique(value["TAGS"], lambda item: _safe_text(item, pattern=SAFE_NAME)),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "PACKAGE": self.package,
            "VERSION": self.version,
            "FILENAME": self.filename,
            "SHA256": self.sha256,
            "TAGS": list(self.tags),
        }


def wheel_inventory_fingerprint(entries: Sequence[WheelEntryV1]) -> str:
    ordered = sorted(entries)
    if not ordered:
        _fail()
    return contract_fingerprint({"WHEELS": [item.to_mapping() for item in ordered]})


@dataclass(frozen=True)
class WheelhouseManifestV1:
    python_implementation: str
    python_version: str
    python_abi: str
    platform_tag: str
    arch: str
    os_runtime_manifest_sha256: str
    wheelhouse_manifest_sha256: str
    wheels: tuple[WheelEntryV1, ...]

    FIELDS = {
        "MANIFEST_VERSION", "PYTHON_IMPLEMENTATION", "PYTHON_VERSION", "PYTHON_ABI",
        "PLATFORM_TAG", "ARCH", "OS_RUNTIME_MANIFEST_SHA256",
        "WHEELHOUSE_MANIFEST_SHA256", "WHEELS",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WheelhouseManifestV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if value["MANIFEST_VERSION"] != "1":
            _fail(FailureCode.CONTRACT_VERSION_UNSUPPORTED)
        raw_wheels = value["WHEELS"]
        if not isinstance(raw_wheels, (list, tuple)) or not raw_wheels:
            _fail()
        wheels = tuple(sorted(WheelEntryV1.from_mapping(item) for item in raw_wheels))
        if len({(item.package, item.version) for item in wheels}) != len(wheels):
            _fail()
        if len({item.filename for item in wheels}) != len(wheels):
            _fail()
        inventory_hash = _sha256(value["WHEELHOUSE_MANIFEST_SHA256"])
        if wheel_inventory_fingerprint(wheels) != inventory_hash:
            _fail(FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        return cls(
            _safe_text(value["PYTHON_IMPLEMENTATION"], pattern=SAFE_NAME),
            _safe_text(value["PYTHON_VERSION"], pattern=SAFE_NAME),
            _safe_text(value["PYTHON_ABI"], pattern=SAFE_NAME),
            _safe_text(value["PLATFORM_TAG"], pattern=SAFE_NAME),
            _safe_text(value["ARCH"], pattern=SAFE_NAME),
            _sha256(value["OS_RUNTIME_MANIFEST_SHA256"]),
            inventory_hash,
            wheels,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "MANIFEST_VERSION": "1",
            "PYTHON_IMPLEMENTATION": self.python_implementation,
            "PYTHON_VERSION": self.python_version,
            "PYTHON_ABI": self.python_abi,
            "PLATFORM_TAG": self.platform_tag,
            "ARCH": self.arch,
            "OS_RUNTIME_MANIFEST_SHA256": self.os_runtime_manifest_sha256,
            "WHEELHOUSE_MANIFEST_SHA256": self.wheelhouse_manifest_sha256,
            "WHEELS": [item.to_mapping() for item in self.wheels],
        }


def wheelhouse_manifest_fingerprint(value: WheelhouseManifestV1) -> str:
    return contract_fingerprint(value)


@dataclass(frozen=True)
class ReleaseInputBundleManifestV1:
    candidate_sha: str
    git_bundle_sha256: str
    git_bundle_source_sha: str
    pdi_wheel_sha256: str
    pdi_wheel_source_sha: str
    pdi_sdist_sha256: str
    pdi_sdist_source_sha: str
    wheelhouse_manifest_sha256: str
    os_runtime_manifest_sha256: str
    systemd_asset_fingerprint: str
    build_workflow_identity: str
    build_artifact_identity: str
    provenance_sha256: str
    builder_tool: OperatorToolIdentity

    FIELDS = {
        "MANIFEST_VERSION", "CANDIDATE_SHA", "GIT_BUNDLE_SHA256",
        "GIT_BUNDLE_SOURCE_SHA", "PDI_WHEEL_SHA256", "PDI_WHEEL_SOURCE_SHA",
        "PDI_SDIST_SHA256", "PDI_SDIST_SOURCE_SHA", "WHEELHOUSE_MANIFEST_SHA256",
        "OS_RUNTIME_MANIFEST_SHA256", "SYSTEMD_ASSET_FINGERPRINT",
        "BUILD_WORKFLOW_IDENTITY", "BUILD_ARTIFACT_IDENTITY", "PROVENANCE_SHA256",
        "BUILDER_TOOL",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReleaseInputBundleManifestV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if value["MANIFEST_VERSION"] != "1":
            _fail(FailureCode.CONTRACT_VERSION_UNSUPPORTED)
        candidate = _git_sha(value["CANDIDATE_SHA"])
        source_shas = tuple(_git_sha(value[key]) for key in (
            "GIT_BUNDLE_SOURCE_SHA", "PDI_WHEEL_SOURCE_SHA", "PDI_SDIST_SOURCE_SHA",
        ))
        if any(item != candidate for item in source_shas):
            _fail(FailureCode.CONTRACT_CANDIDATE_MISMATCH)
        builder = OperatorToolIdentity.from_mapping(value["BUILDER_TOOL"])
        if (builder.tool_name is not ToolName.RELEASE_BUNDLE_BUILD or
                builder.tool_source_sha != candidate):
            _fail(FailureCode.CONTRACT_CANDIDATE_MISMATCH)
        return cls(
            candidate,
            _sha256(value["GIT_BUNDLE_SHA256"]),
            source_shas[0],
            _sha256(value["PDI_WHEEL_SHA256"]),
            source_shas[1],
            _sha256(value["PDI_SDIST_SHA256"]),
            source_shas[2],
            _sha256(value["WHEELHOUSE_MANIFEST_SHA256"]),
            _sha256(value["OS_RUNTIME_MANIFEST_SHA256"]),
            _sha256(value["SYSTEMD_ASSET_FINGERPRINT"]),
            _safe_text(value["BUILD_WORKFLOW_IDENTITY"]),
            _safe_text(value["BUILD_ARTIFACT_IDENTITY"]),
            _sha256(value["PROVENANCE_SHA256"]),
            builder,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "MANIFEST_VERSION": "1",
            "CANDIDATE_SHA": self.candidate_sha,
            "GIT_BUNDLE_SHA256": self.git_bundle_sha256,
            "GIT_BUNDLE_SOURCE_SHA": self.git_bundle_source_sha,
            "PDI_WHEEL_SHA256": self.pdi_wheel_sha256,
            "PDI_WHEEL_SOURCE_SHA": self.pdi_wheel_source_sha,
            "PDI_SDIST_SHA256": self.pdi_sdist_sha256,
            "PDI_SDIST_SOURCE_SHA": self.pdi_sdist_source_sha,
            "WHEELHOUSE_MANIFEST_SHA256": self.wheelhouse_manifest_sha256,
            "OS_RUNTIME_MANIFEST_SHA256": self.os_runtime_manifest_sha256,
            "SYSTEMD_ASSET_FINGERPRINT": self.systemd_asset_fingerprint,
            "BUILD_WORKFLOW_IDENTITY": self.build_workflow_identity,
            "BUILD_ARTIFACT_IDENTITY": self.build_artifact_identity,
            "PROVENANCE_SHA256": self.provenance_sha256,
            "BUILDER_TOOL": self.builder_tool.to_mapping(),
        }


def release_bundle_fingerprint(value: ReleaseInputBundleManifestV1) -> str:
    return contract_fingerprint(value)


class ReleasePinState(str, Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass(frozen=True)
class RollbackReleasePinV1:
    snapshot_id: str
    source_release_sha: str
    source_release_fingerprint: str
    source_runtime_fingerprint: str
    source_system_runtime_fingerprint: str
    rollback_metadata_sha256: str
    qualified_at_utc: str
    state: ReleasePinState

    FIELDS = {
        "PIN_VERSION", "SNAPSHOT_ID", "SOURCE_RELEASE_SHA", "SOURCE_RELEASE_FINGERPRINT",
        "SOURCE_RUNTIME_FINGERPRINT", "SOURCE_SYSTEM_RUNTIME_FINGERPRINT",
        "ROLLBACK_METADATA_SHA256", "QUALIFIED_AT_UTC", "STATE",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RollbackReleasePinV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if value["PIN_VERSION"] != "1":
            _fail(FailureCode.CONTRACT_VERSION_UNSUPPORTED)
        try:
            state = ReleasePinState(value["STATE"])
        except (ValueError, TypeError):
            _fail()
        return cls(
            _safe_text(value["SNAPSHOT_ID"], pattern=SHA256),
            _git_sha(value["SOURCE_RELEASE_SHA"]),
            _sha256(value["SOURCE_RELEASE_FINGERPRINT"]),
            _sha256(value["SOURCE_RUNTIME_FINGERPRINT"]),
            _sha256(value["SOURCE_SYSTEM_RUNTIME_FINGERPRINT"]),
            _sha256(value["ROLLBACK_METADATA_SHA256"]),
            _utc_timestamp(value["QUALIFIED_AT_UTC"]),
            state,
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "PIN_VERSION": "1",
            "SNAPSHOT_ID": self.snapshot_id,
            "SOURCE_RELEASE_SHA": self.source_release_sha,
            "SOURCE_RELEASE_FINGERPRINT": self.source_release_fingerprint,
            "SOURCE_RUNTIME_FINGERPRINT": self.source_runtime_fingerprint,
            "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": self.source_system_runtime_fingerprint,
            "ROLLBACK_METADATA_SHA256": self.rollback_metadata_sha256,
            "QUALIFIED_AT_UTC": self.qualified_at_utc,
            "STATE": self.state.value,
        }


def release_pin_fingerprint(value: RollbackReleasePinV1) -> str:
    return contract_fingerprint(value)


def validate_rollback_release_pin(
    metadata: P3DRollbackMetadataV1,
    pin: RollbackReleasePinV1,
) -> bool:
    """Bind the active release pin to one exact rollback authority."""

    expected = (
        metadata.snapshot_id,
        metadata.source_release_sha,
        metadata.source_release_fingerprint,
        metadata.source_runtime_fingerprint,
        metadata.source_system_runtime_fingerprint,
        rollback_metadata_fingerprint(metadata),
        metadata.qualified_at_utc,
        ReleasePinState.ACTIVE,
    )
    actual = (
        pin.snapshot_id,
        pin.source_release_sha,
        pin.source_release_fingerprint,
        pin.source_runtime_fingerprint,
        pin.source_system_runtime_fingerprint,
        pin.rollback_metadata_sha256,
        pin.qualified_at_utc,
        pin.state,
    )
    if actual != expected:
        _fail(FailureCode.ROLLBACK_PIN_FAILED)
    return True


class PreparationGate(str, Enum):
    ROLLBACK_QUALIFICATION = "ROLLBACK_QUALIFICATION"
    RELEASE_STAGING = "RELEASE_STAGING"
    INERT_ASSET_INSTALL = "INERT_ASSET_INSTALL"


class GateAPhase(str, Enum):
    NEW = "NEW"
    SOURCE_VERIFIED = "SOURCE_VERIFIED"
    SNAPSHOT_EXPORTED = "SNAPSHOT_EXPORTED"
    DUMP_COMPLETED = "DUMP_COMPLETED"
    BACKUP_SNAPSHOT_CREATED = "BACKUP_SNAPSHOT_CREATED"
    RESTORE_STARTED = "RESTORE_STARTED"
    RESTORE_COMPLETED = "RESTORE_COMPLETED"
    RESTORE_QUALIFIED = "RESTORE_QUALIFIED"
    RUNTIME_QUALIFIED = "RUNTIME_QUALIFIED"
    DB_RUNTIME_COMPATIBLE = "DB_RUNTIME_COMPATIBLE"
    SOURCE_RELEASE_PINNED = "SOURCE_RELEASE_PINNED"
    METADATA_COMMITTED = "METADATA_COMMITTED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class GateBPhase(str, Enum):
    NEW = "NEW"
    ARTIFACT_VERIFIED = "ARTIFACT_VERIFIED"
    OS_RUNTIME_VERIFIED = "OS_RUNTIME_VERIFIED"
    STAGING_CREATED = "STAGING_CREATED"
    SOURCE_CHECKED_OUT = "SOURCE_CHECKED_OUT"
    VENV_BUILT = "VENV_BUILT"
    RUNTIME_VERIFIED = "RUNTIME_VERIFIED"
    IMMUTABILITY_VERIFIED = "IMMUTABILITY_VERIFIED"
    FINAL_RENAME_COMMITTED = "FINAL_RENAME_COMMITTED"
    FINAL_VERIFIED = "FINAL_VERIFIED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class GateCPhase(str, Enum):
    NEW = "NEW"
    PREREQUISITES_VERIFIED = "PREREQUISITES_VERIFIED"
    REGISTRY_VERIFIED = "REGISTRY_VERIFIED"
    DB_EVIDENCE_VERIFIED = "DB_EVIDENCE_VERIFIED"
    PROFILES_RENDERED = "PROFILES_RENDERED"
    OFFLINE_STATIC_VERIFIED = "OFFLINE_STATIC_VERIFIED"
    FILES_PARTIALLY_INSTALLED = "FILES_PARTIALLY_INSTALLED"
    FILES_INSTALLED = "FILES_INSTALLED"
    FINAL_STATIC_VERIFIED = "FINAL_STATIC_VERIFIED"
    SYSTEMD_QUIET_VERIFIED = "SYSTEMD_QUIET_VERIFIED"
    COMPLETE_MARKER_COMMITTED = "COMPLETE_MARKER_COMMITTED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


PHASE_TYPES = {
    PreparationGate.ROLLBACK_QUALIFICATION: GateAPhase,
    PreparationGate.RELEASE_STAGING: GateBPhase,
    PreparationGate.INERT_ASSET_INSTALL: GateCPhase,
}

GATE_TOOL_ROLES = {
    PreparationGate.ROLLBACK_QUALIFICATION: frozenset({
        ToolName.BACKUP_EXPORT,
        ToolName.RESTORE_QUALIFY,
    }),
    PreparationGate.RELEASE_STAGING: frozenset({ToolName.RELEASE_BOOTSTRAP}),
    PreparationGate.INERT_ASSET_INSTALL: frozenset({ToolName.INERT_ASSET_INSTALL}),
}

GATE_A_TARGET_TOOL_ROLES = {
    "SOURCE_VERIFIED": frozenset({ToolName.BACKUP_EXPORT}),
    "SNAPSHOT_EXPORTED": frozenset({ToolName.BACKUP_EXPORT}),
    "DUMP_COMPLETED": frozenset({ToolName.BACKUP_EXPORT}),
    "BACKUP_SNAPSHOT_CREATED": frozenset({ToolName.BACKUP_EXPORT}),
    "RESTORE_STARTED": frozenset({ToolName.RESTORE_QUALIFY}),
    "RESTORE_COMPLETED": frozenset({ToolName.RESTORE_QUALIFY}),
    "RESTORE_QUALIFIED": frozenset({ToolName.RESTORE_QUALIFY}),
    "RUNTIME_QUALIFIED": frozenset({ToolName.RESTORE_QUALIFY}),
    "DB_RUNTIME_COMPATIBLE": frozenset({ToolName.RESTORE_QUALIFY}),
    "SOURCE_RELEASE_PINNED": frozenset({ToolName.RESTORE_QUALIFY}),
    "METADATA_COMMITTED": frozenset({ToolName.RESTORE_QUALIFY}),
    "COMPLETE": frozenset({ToolName.RESTORE_QUALIFY}),
    "FAILED": GATE_TOOL_ROLES[PreparationGate.ROLLBACK_QUALIFICATION],
}


def validate_gate_tool_authority(
    gate: PreparationGate,
    tool_identities: Sequence[OperatorToolIdentity],
    candidate_sha: str,
) -> tuple[OperatorToolIdentity, ...]:
    """Validate the complete, gate-specific operator authority set."""

    candidate = _git_sha(candidate_sha)
    if not isinstance(tool_identities, (list, tuple)) or not tool_identities:
        _fail(FailureCode.CONTRACT_VALUE_INVALID)
    tools = tuple(sorted(tool_identities, key=lambda item: item.tool_name.value))
    roles = tuple(item.tool_name for item in tools)
    if len(set(roles)) != len(roles) or frozenset(roles) != GATE_TOOL_ROLES[gate]:
        _fail(FailureCode.CONTRACT_VALUE_INVALID)
    if (gate is PreparationGate.INERT_ASSET_INSTALL and
            any(item.tool_source_sha != candidate for item in tools)):
        _fail(FailureCode.CONTRACT_CANDIDATE_MISMATCH)
    return tools


def validate_journal_event_tool_authority(
    gate: PreparationGate,
    target_phase: str,
    tool_identity: OperatorToolIdentity,
    candidate_sha: str,
) -> None:
    """Bind one transition to its exact reviewed tool role."""

    target = _phase(gate, target_phase)
    if gate is PreparationGate.ROLLBACK_QUALIFICATION:
        allowed = GATE_A_TARGET_TOOL_ROLES[target]
    else:
        allowed = GATE_TOOL_ROLES[gate]
    if tool_identity.tool_name not in allowed:
        _fail(FailureCode.CONTRACT_VALUE_INVALID)
    if (gate is PreparationGate.INERT_ASSET_INSTALL and
            tool_identity.tool_source_sha != _git_sha(candidate_sha)):
        _fail(FailureCode.CONTRACT_CANDIDATE_MISMATCH)


def _linear_transitions(enum_type) -> dict[str, set[str]]:
    phases = list(enum_type)
    result = {phase.value: set() for phase in phases}
    non_failed = [phase for phase in phases if phase.value != "FAILED"]
    for current, following in zip(non_failed, non_failed[1:]):
        result[current.value].add(following.value)
    for phase in non_failed:
        if phase.value not in {"COMPLETE", "FAILED"}:
            result[phase.value].add("FAILED")
    return result


ALLOWED_TRANSITIONS = {
    gate: _linear_transitions(enum_type) for gate, enum_type in PHASE_TYPES.items()
}
ALLOWED_TRANSITIONS[PreparationGate.INERT_ASSET_INSTALL]["OFFLINE_STATIC_VERIFIED"].add("FILES_INSTALLED")
ALLOWED_TRANSITIONS[PreparationGate.INERT_ASSET_INSTALL]["FILES_PARTIALLY_INSTALLED"].add(
    "FILES_PARTIALLY_INSTALLED"
)
TERMINAL_PHASES = {"COMPLETE", "FAILED"}
RETRYABLE_PHASES = {
    PreparationGate.ROLLBACK_QUALIFICATION: frozenset({"NEW", "SOURCE_VERIFIED"}),
    PreparationGate.RELEASE_STAGING: frozenset({
        "ARTIFACT_VERIFIED", "OS_RUNTIME_VERIFIED", "STAGING_CREATED",
        "SOURCE_CHECKED_OUT", "VENV_BUILT", "RUNTIME_VERIFIED", "IMMUTABILITY_VERIFIED",
    }),
    PreparationGate.INERT_ASSET_INSTALL: frozenset({"FILES_PARTIALLY_INSTALLED"}),
}


def _phase(gate: PreparationGate, value: Any) -> str:
    try:
        return PHASE_TYPES[gate](value).value
    except (ValueError, TypeError):
        _fail()


@dataclass(frozen=True)
class PreparationOperationStateV1:
    operation_id: str
    gate: PreparationGate
    candidate_sha: str
    phase: str
    started_at: str
    updated_at: str
    operator_tool_identities: tuple[OperatorToolIdentity, ...]
    evidence_fingerprint: str | None = None
    failure_code: FailureCode | None = None

    FIELDS = {
        "version", "operation_id", "gate", "candidate_sha", "phase",
        "started_at", "updated_at", "operator_tool_identities", "evidence_fingerprint",
        "failure_code",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PreparationOperationStateV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if type(value["version"]) is not int or value["version"] != 1:
            _fail(FailureCode.CONTRACT_VERSION_UNSUPPORTED)
        try:
            gate = PreparationGate(value["gate"])
        except (ValueError, TypeError):
            _fail()
        phase = _phase(gate, value["phase"])
        failure = value["failure_code"]
        if failure is not None:
            try:
                failure = FailureCode(failure)
            except (ValueError, TypeError):
                _fail()
        if (phase == "FAILED") != (failure is not None):
            _fail()
        evidence = value["evidence_fingerprint"]
        started = _utc_timestamp(value["started_at"])
        updated = _utc_timestamp(value["updated_at"])
        candidate = _git_sha(value["candidate_sha"])
        raw_tools = value["operator_tool_identities"]
        if not isinstance(raw_tools, (list, tuple)):
            _fail(FailureCode.CONTRACT_VALUE_INVALID)
        tools = validate_gate_tool_authority(
            gate,
            tuple(OperatorToolIdentity.from_mapping(item) for item in raw_tools),
            candidate,
        )
        if updated < started:
            _fail(FailureCode.CONTRACT_VALUE_INVALID)
        if failure is not None:
            _validate_gate_failure_code(gate, failure)
        return cls(
            _uuid(value["operation_id"]),
            gate,
            candidate,
            phase,
            started,
            updated,
            tools,
            None if evidence is None else _sha256(evidence),
            failure,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "operation_id": self.operation_id,
            "gate": self.gate.value,
            "candidate_sha": self.candidate_sha,
            "phase": self.phase,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "operator_tool_identities": [item.to_mapping() for item in self.operator_tool_identities],
            "evidence_fingerprint": self.evidence_fingerprint,
            "failure_code": None if self.failure_code is None else self.failure_code.value,
        }


@dataclass(frozen=True)
class PreparationJournalEventV1:
    sequence: int
    operation_id: str
    gate: PreparationGate
    candidate_sha: str
    from_state: str
    to_state: str
    timestamp: str
    tool_identity: OperatorToolIdentity
    evidence_fingerprints: tuple[str, ...]
    failure_code: FailureCode | None = None

    FIELDS = {
        "version", "sequence", "operation_id", "gate", "candidate_sha",
        "from_state", "to_state", "timestamp", "tool_identity",
        "evidence_fingerprints", "failure_code",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PreparationJournalEventV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if (type(value["version"]) is not int or value["version"] != 1 or
                isinstance(value["sequence"], bool) or
                not isinstance(value["sequence"], int) or value["sequence"] < 1):
            _fail(
                FailureCode.CONTRACT_VERSION_UNSUPPORTED
                if value["version"] != 1
                else FailureCode.CONTRACT_VALUE_INVALID
            )
        try:
            gate = PreparationGate(value["gate"])
        except (ValueError, TypeError):
            _fail()
        source = _phase(gate, value["from_state"])
        target = _phase(gate, value["to_state"])
        validate_state_transition(gate, source, target)
        failure = value["failure_code"]
        if failure is not None:
            try:
                failure = FailureCode(failure)
            except (ValueError, TypeError):
                _fail()
        if (target == "FAILED") != (failure is not None):
            _fail()
        raw_fingerprints = value["evidence_fingerprints"]
        if not isinstance(raw_fingerprints, (list, tuple)):
            _fail()
        fingerprints = tuple(sorted(_sha256(item) for item in raw_fingerprints))
        if len(set(fingerprints)) != len(fingerprints):
            _fail()
        tool = OperatorToolIdentity.from_mapping(value["tool_identity"])
        candidate = _git_sha(value["candidate_sha"])
        validate_journal_event_tool_authority(gate, target, tool, candidate)
        if failure is not None:
            _validate_gate_failure_code(gate, failure)
        return cls(
            value["sequence"],
            _uuid(value["operation_id"]),
            gate,
            candidate,
            source,
            target,
            _utc_timestamp(value["timestamp"]),
            tool,
            fingerprints,
            failure,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": 1,
            "sequence": self.sequence,
            "operation_id": self.operation_id,
            "gate": self.gate.value,
            "candidate_sha": self.candidate_sha,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "timestamp": self.timestamp,
            "tool_identity": self.tool_identity.to_mapping(),
            "evidence_fingerprints": list(self.evidence_fingerprints),
            "failure_code": None if self.failure_code is None else self.failure_code.value,
        }


def validate_state_transition(gate: PreparationGate, source: str, target: str) -> None:
    source = _phase(gate, source)
    target = _phase(gate, target)
    if target not in ALLOWED_TRANSITIONS[gate][source]:
        _fail(FailureCode.CONTRACT_TRANSITION_INVALID)


GATE_FAILURE_PREFIXES = {
    PreparationGate.ROLLBACK_QUALIFICATION: "P3D_ROLLBACK_",
    PreparationGate.RELEASE_STAGING: "P3D_RELEASE_STAGE_",
    PreparationGate.INERT_ASSET_INSTALL: "P3D_ASSET_INSTALL_",
}


def _validate_gate_failure_code(gate: PreparationGate, failure_code: FailureCode) -> None:
    if not failure_code.value.startswith(GATE_FAILURE_PREFIXES[gate]):
        _fail(FailureCode.CONTRACT_VALUE_INVALID)


def transition_preparation_state(
    state: PreparationOperationStateV1,
    target: str,
    *,
    updated_at: str,
    evidence_fingerprint: str | None = None,
    failure_code: FailureCode | None = None,
    candidate_sha: str | None = None,
) -> PreparationOperationStateV1:
    if candidate_sha is not None and _git_sha(candidate_sha) != state.candidate_sha:
        _fail(FailureCode.CONTRACT_CANDIDATE_MISMATCH)
    target = _phase(state.gate, target)
    validate_state_transition(state.gate, state.phase, target)
    timestamp = _utc_timestamp(updated_at)
    if timestamp < state.updated_at:
        _fail()
    if (target == "FAILED") != (failure_code is not None):
        _fail()
    if failure_code is not None:
        if not isinstance(failure_code, FailureCode):
            _fail(FailureCode.CONTRACT_VALUE_INVALID)
        _validate_gate_failure_code(state.gate, failure_code)
    return replace(
        state,
        phase=target,
        updated_at=timestamp,
        evidence_fingerprint=(
            state.evidence_fingerprint if evidence_fingerprint is None else _sha256(evidence_fingerprint)
        ),
        failure_code=failure_code,
    )


def preparation_journal_fingerprint(
    events: Sequence[PreparationJournalEventV1],
) -> str:
    if not isinstance(events, (list, tuple)) or not events:
        _fail(FailureCode.CONTRACT_VALUE_INVALID)
    normalized = tuple(
        PreparationJournalEventV1.from_mapping(event.to_mapping()) for event in events
    )
    return contract_fingerprint({"events": [event.to_mapping() for event in normalized]})


def validate_preparation_journal_chain(
    events: Sequence[PreparationJournalEventV1],
    persisted_state: PreparationOperationStateV1,
) -> bool:
    """Validate a complete journal prefix and bind it to persisted state.

    Equal timestamps are valid because contract timestamps have one-second
    precision. A timestamp may never move backward.
    """

    if not isinstance(events, (list, tuple)) or not events:
        _fail(FailureCode.CONTRACT_VALUE_INVALID)
    normalized = tuple(
        PreparationJournalEventV1.from_mapping(event.to_mapping()) for event in events
    )
    state = PreparationOperationStateV1.from_mapping(persisted_state.to_mapping())
    first = normalized[0]
    if first.sequence != 1 or first.from_state != "NEW" or state.started_at > first.timestamp:
        _fail(FailureCode.CONTRACT_VALUE_INVALID)
    authority = frozenset(state.operator_tool_identities)
    previous: PreparationJournalEventV1 | None = None
    for expected_sequence, event in enumerate(normalized, start=1):
        if (event.sequence != expected_sequence or
                event.operation_id != state.operation_id or
                event.gate is not state.gate or
                event.candidate_sha != state.candidate_sha or
                event.tool_identity not in authority):
            _fail(FailureCode.CONTRACT_VALUE_INVALID)
        if previous is not None:
            if (previous.to_state in TERMINAL_PHASES or
                    event.from_state != previous.to_state or
                    event.timestamp < previous.timestamp):
                _fail(FailureCode.CONTRACT_TRANSITION_INVALID)
        previous = event
    final = normalized[-1]
    if (final.to_state != state.phase or
            final.timestamp != state.updated_at or
            final.failure_code is not state.failure_code or
            state.evidence_fingerprint != preparation_journal_fingerprint(normalized)):
        _fail(FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
    return True


CANONICAL_P3D_PIPELINE_KEYS = (
    "enrichment.nextcloud_text",
    "enrichment.nextcloud_documents",
    "enrichment.file_metadata",
    "enrichment.immich_geo",
    "enrichment.immich_metadata",
    "enrichment.immich_ocr",
)
CANONICAL_P3D_SYSTEMD_PATHS = frozenset({
    "/etc/systemd/system/pdi-scoped-pipeline@.service",
    "/etc/systemd/system/pdi-scoped-enrichment-nextcloud-text.timer",
    "/etc/systemd/system/pdi-scoped-enrichment-nextcloud-documents.timer",
    "/etc/systemd/system/pdi-scoped-enrichment-file-metadata.timer",
    "/etc/systemd/system/pdi-scoped-enrichment-immich-geo.timer",
    "/etc/systemd/system/pdi-scoped-enrichment-immich-metadata.timer",
    "/etc/systemd/system/pdi-scoped-enrichment-immich-ocr.timer",
})
CANONICAL_P3D_PROFILE_PATHS = frozenset(
    f"/etc/pdi/scoped/units/{key}.env" for key in CANONICAL_P3D_PIPELINE_KEYS
)
CANONICAL_P3D_INSTALL_PATH_MODES = {
    **{path: "0644" for path in CANONICAL_P3D_SYSTEMD_PATHS},
    **{path: "0600" for path in CANONICAL_P3D_PROFILE_PATHS},
}
CANONICAL_P3D_INSTALL_PATHS = frozenset(CANONICAL_P3D_INSTALL_PATH_MODES)


@dataclass(frozen=True, order=True)
class InstalledFileEntryV1:
    path: str
    sha256: str
    owner_uid: int
    owner_gid: int
    mode: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "InstalledFileEntryV1":
        _exact(value, {"path", "sha256", "owner_uid", "owner_gid", "mode"})
        path = _safe_text(value["path"])
        parsed = PurePosixPath(path)
        if not parsed.is_absolute() or ".." in parsed.parts:
            _fail()
        if (type(value["owner_uid"]) is not int or type(value["owner_gid"]) is not int or
                value["owner_uid"] != 0 or value["owner_gid"] != 0):
            _fail()
        mode = _safe_text(value["mode"], pattern=MODE)
        if path not in CANONICAL_P3D_INSTALL_PATHS:
            _fail(FailureCode.ASSET_FILE_CONFLICT)
        if mode != CANONICAL_P3D_INSTALL_PATH_MODES[path]:
            _fail()
        return cls(path, _sha256(value["sha256"]), 0, 0, mode)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "mode": self.mode,
        }


def asset_installation_fingerprint(entries: Sequence[InstalledFileEntryV1]) -> str:
    normalized = tuple(InstalledFileEntryV1.from_mapping(entry.to_mapping()) for entry in entries)
    ordered = sorted(normalized)
    paths = [entry.path for entry in ordered]
    if (len(paths) != len(set(paths)) or
            frozenset(paths) != CANONICAL_P3D_INSTALL_PATHS):
        _fail(FailureCode.ASSET_FILE_CONFLICT)
    return contract_fingerprint({"installed_files": [entry.to_mapping() for entry in ordered]})


@dataclass(frozen=True)
class P3DAssetInstallationCompleteV1:
    candidate_sha: str
    rollback_snapshot_id: str
    rollback_metadata_sha256: str
    rollback_source_sha: str
    registry_fingerprint: str
    db_identity_fingerprint: str
    enabled_scope_fingerprint: str
    unit_profile_asset_fingerprint: str
    installed_file_manifest: tuple[InstalledFileEntryV1, ...]
    current_symlink_before: str
    current_symlink_after: str
    p3c_systemd_state_before_fingerprint: str
    p3c_systemd_state_after_fingerprint: str
    p3d_timer_state: str
    preparation_operation_id: str
    completed_at_utc: str
    gate_c_tool_identity: OperatorToolIdentity

    FIELDS = {
        "marker_version", "candidate_sha", "rollback_snapshot_id",
        "rollback_metadata_sha256", "rollback_source_sha", "registry_fingerprint",
        "db_identity_fingerprint", "enabled_scope_fingerprint",
        "unit_profile_asset_fingerprint", "installed_file_manifest",
        "current_symlink_before", "current_symlink_after",
        "p3c_systemd_state_before_fingerprint", "p3c_systemd_state_after_fingerprint",
        "p3d_timer_state", "preparation_operation_id", "completed_at_utc",
        "gate_c_tool_identity",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "P3DAssetInstallationCompleteV1":
        _exact(value, cls.FIELDS)
        reject_secret_material(value)
        if type(value["marker_version"]) is not int or value["marker_version"] != 1:
            _fail(FailureCode.CONTRACT_VERSION_UNSUPPORTED)
        raw_files = value["installed_file_manifest"]
        if not isinstance(raw_files, (list, tuple)):
            _fail()
        files = tuple(sorted(InstalledFileEntryV1.from_mapping(item) for item in raw_files))
        asset_hash = _sha256(value["unit_profile_asset_fingerprint"])
        if asset_installation_fingerprint(files) != asset_hash:
            _fail(FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        before = _safe_text(value["current_symlink_before"])
        after = _safe_text(value["current_symlink_after"])
        p3c_before = _sha256(value["p3c_systemd_state_before_fingerprint"])
        p3c_after = _sha256(value["p3c_systemd_state_after_fingerprint"])
        candidate = _git_sha(value["candidate_sha"])
        rollback_source = _git_sha(value["rollback_source_sha"])
        expected_current = f"/opt/pdi/releases/{rollback_source}"
        if (before != expected_current or after != expected_current or
                p3c_before != p3c_after or
                value["p3d_timer_state"] != "DISABLED_INACTIVE"):
            _fail(FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
        gate_tool = OperatorToolIdentity.from_mapping(value["gate_c_tool_identity"])
        if (candidate == rollback_source or
                gate_tool.tool_name is not ToolName.INERT_ASSET_INSTALL or
                gate_tool.tool_source_sha != candidate):
            _fail(FailureCode.CONTRACT_CANDIDATE_MISMATCH)
        return cls(
            candidate,
            _safe_text(value["rollback_snapshot_id"], pattern=SHA256),
            _sha256(value["rollback_metadata_sha256"]),
            rollback_source,
            _sha256(value["registry_fingerprint"]),
            _sha256(value["db_identity_fingerprint"]),
            _sha256(value["enabled_scope_fingerprint"]),
            asset_hash,
            files,
            before,
            after,
            p3c_before,
            p3c_after,
            "DISABLED_INACTIVE",
            _uuid(value["preparation_operation_id"]),
            _utc_timestamp(value["completed_at_utc"]),
            gate_tool,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "marker_version": 1,
            "candidate_sha": self.candidate_sha,
            "rollback_snapshot_id": self.rollback_snapshot_id,
            "rollback_metadata_sha256": self.rollback_metadata_sha256,
            "rollback_source_sha": self.rollback_source_sha,
            "registry_fingerprint": self.registry_fingerprint,
            "db_identity_fingerprint": self.db_identity_fingerprint,
            "enabled_scope_fingerprint": self.enabled_scope_fingerprint,
            "unit_profile_asset_fingerprint": self.unit_profile_asset_fingerprint,
            "installed_file_manifest": [item.to_mapping() for item in self.installed_file_manifest],
            "current_symlink_before": self.current_symlink_before,
            "current_symlink_after": self.current_symlink_after,
            "p3c_systemd_state_before_fingerprint": self.p3c_systemd_state_before_fingerprint,
            "p3c_systemd_state_after_fingerprint": self.p3c_systemd_state_after_fingerprint,
            "p3d_timer_state": self.p3d_timer_state,
            "preparation_operation_id": self.preparation_operation_id,
            "completed_at_utc": self.completed_at_utc,
            "gate_c_tool_identity": self.gate_c_tool_identity.to_mapping(),
        }


def validate_complete_marker_authorities(
    marker: P3DAssetInstallationCompleteV1,
    rollback_metadata: P3DRollbackMetadataV1,
) -> bool:
    """Bind a Gate C marker to exact Gate A rollback metadata."""

    expected = (
        rollback_metadata.target_candidate_sha,
        rollback_metadata.snapshot_id,
        rollback_metadata_fingerprint(rollback_metadata),
        rollback_metadata.source_release_sha,
    )
    actual = (
        marker.candidate_sha,
        marker.rollback_snapshot_id,
        marker.rollback_metadata_sha256,
        marker.rollback_source_sha,
    )
    if actual != expected:
        _fail(FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
    return True


@dataclass(frozen=True)
class PreparationPrerequisiteEvidenceV1:
    candidate_sha: str
    rollback_snapshot_id: str
    rollback_metadata_sha256: str
    rollback_source_sha: str
    registry_fingerprint: str
    db_identity_fingerprint: str
    enabled_scope_fingerprint: str
    unit_profile_asset_fingerprint: str
    current_symlink: str
    p3c_systemd_state_fingerprint: str
    p3d_timer_state: str


def validate_pre_rehearsal_preparation_contract(
    marker: P3DAssetInstallationCompleteV1,
    live: PreparationPrerequisiteEvidenceV1,
) -> bool:
    """Pure live-fingerprint comparison for later collect-evidence wiring."""

    expected = (
        marker.candidate_sha,
        marker.rollback_snapshot_id,
        marker.rollback_metadata_sha256,
        marker.rollback_source_sha,
        marker.registry_fingerprint,
        marker.db_identity_fingerprint,
        marker.enabled_scope_fingerprint,
        marker.unit_profile_asset_fingerprint,
        marker.current_symlink_after,
        marker.p3c_systemd_state_after_fingerprint,
        marker.p3d_timer_state,
    )
    actual = (
        _git_sha(live.candidate_sha),
        _safe_text(live.rollback_snapshot_id, pattern=SHA256),
        _sha256(live.rollback_metadata_sha256),
        _git_sha(live.rollback_source_sha),
        _sha256(live.registry_fingerprint),
        _sha256(live.db_identity_fingerprint),
        _sha256(live.enabled_scope_fingerprint),
        _sha256(live.unit_profile_asset_fingerprint),
        _safe_text(live.current_symlink),
        _sha256(live.p3c_systemd_state_fingerprint),
        _safe_text(live.p3d_timer_state),
    )
    if actual != expected:
        _fail(FailureCode.CONTRACT_FINGERPRINT_MISMATCH)
    return True


@dataclass(frozen=True, order=True)
class SourceFileFingerprintEntryV1:
    relative_path: str
    kind: str
    mode: str
    owner_uid: int
    owner_gid: int
    content_sha256: str | None = None
    symlink_target: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        path = PurePosixPath(_safe_text(self.relative_path))
        if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
            _fail()
        if self.kind not in {"file", "directory", "symlink"} or MODE.fullmatch(self.mode) is None:
            _fail()
        if (type(self.owner_uid) is not int or type(self.owner_gid) is not int or
                self.owner_uid != 0 or self.owner_gid != 0):
            _fail()
        if self.kind == "file" and (self.content_sha256 is None or self.symlink_target is not None):
            _fail()
        if self.kind == "directory" and (self.content_sha256 is not None or self.symlink_target is not None):
            _fail()
        if self.kind == "symlink" and (self.symlink_target is None or self.content_sha256 is not None):
            _fail()
        return {
            "relative_path": str(path),
            "kind": self.kind,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "content_sha256": None if self.content_sha256 is None else _sha256(self.content_sha256),
            "symlink_target": None if self.symlink_target is None else _safe_text(self.symlink_target),
        }


def _source_release_fingerprint_bytes(
    candidate_sha: str,
    entries: Sequence[SourceFileFingerprintEntryV1],
) -> bytes:
    """Canonical bytes for the closed filesystem-path fingerprint schema.

    ``relative_path`` and ``symlink_target`` are validated path identities,
    not free-form secret values.  Keeping this serializer private prevents
    other contracts from bypassing the generic secret-material defense.
    """

    ordered = sorted(entries)
    if not ordered or len({entry.relative_path for entry in ordered}) != len(ordered):
        _fail()
    payload = _canonicalize({
        "candidate_sha": _git_sha(candidate_sha),
        "entries": [entry.to_mapping() for entry in ordered],
    })
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def source_release_fingerprint(candidate_sha: str, entries: Sequence[SourceFileFingerprintEntryV1]) -> str:
    return hashlib.sha256(_source_release_fingerprint_bytes(candidate_sha, entries)).hexdigest()


@dataclass(frozen=True, order=True)
class RuntimeDistributionEntryV1:
    name: str
    version: str
    record_sha256: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "name": _safe_text(self.name, pattern=PACKAGE_NAME),
            "version": _safe_text(self.version, pattern=PINNED_VERSION),
            "record_sha256": _sha256(self.record_sha256),
        }


def source_runtime_fingerprint(
    *,
    source_release_sha256: str,
    system_runtime_sha256: str,
    python_version: str,
    python_abi: str,
    distributions: Sequence[RuntimeDistributionEntryV1],
) -> str:
    ordered = sorted(distributions)
    if not ordered or len({item.name for item in ordered}) != len(ordered):
        _fail()
    return contract_fingerprint({
        "source_release_fingerprint": _sha256(source_release_sha256),
        "system_runtime_fingerprint": _sha256(system_runtime_sha256),
        "python_version": _safe_text(python_version, pattern=SAFE_NAME),
        "python_abi": _safe_text(python_abi, pattern=SAFE_NAME),
        "distributions": [item.to_mapping() for item in ordered],
    })


def rollback_metadata_fingerprint(value: P3DRollbackMetadataV1) -> str:
    return contract_fingerprint(value)


@dataclass(frozen=True)
class AtomicCreatePolicyV1:
    owner_uid: int = 0
    owner_gid: int = 0
    mode: int = 0o600
    trust_root: Path = Path("/")

    def validate(self) -> None:
        if (type(self.owner_uid) is not int or type(self.owner_gid) is not int or
                self.owner_uid < 0 or self.owner_gid < 0 or self.mode not in {0o600, 0o644}):
            _fail()
        if not self.trust_root.is_absolute():
            _fail()


class AtomicCreateResult(str, Enum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"


def _trusted_parent(path: Path, policy: AtomicCreatePolicyV1) -> bool:
    try:
        root = policy.trust_root.absolute()
        current = path.parent.absolute()
        if current != root and root not in current.parents:
            return False
        while True:
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
                    info.st_uid != policy.owner_uid or info.st_gid != policy.owner_gid or
                    info.st_mode & 0o022):
                return False
            if current == root:
                return True
            current = current.parent
    except OSError:
        return False


def _existing_equivalent(path: Path, content: bytes, policy: AtomicCreatePolicyV1) -> bool:
    try:
        info = path.lstat()
        return (
            stat.S_ISREG(info.st_mode) and info.st_uid == policy.owner_uid and
            info.st_gid == policy.owner_gid and stat.S_IMODE(info.st_mode) == policy.mode and
            path.read_bytes() == content
        )
    except OSError:
        return False


def _fsync_parent_directory(path: Path) -> None:
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def atomic_create_no_replace(
    path: Path,
    content: bytes,
    *,
    policy: AtomicCreatePolicyV1 = AtomicCreatePolicyV1(),
) -> AtomicCreateResult:
    """Create exact bytes atomically; never overwrite an existing object."""

    policy.validate()
    if not path.is_absolute() or not isinstance(content, bytes) or not _trusted_parent(path, policy):
        _fail(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
    if path.exists() or path.is_symlink():
        if _existing_equivalent(path, content, policy):
            try:
                _fsync_parent_directory(path)
            except OSError:
                _fail(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
            return AtomicCreateResult.IDEMPOTENT
        _fail(FailureCode.CONTRACT_PERSISTENCE_CONFLICT)
    descriptor = -1
    temporary: Path | None = None
    cleanup_failed = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".p3d-contract-", dir=path.parent)
        temporary = Path(temporary_name)
        os.fchown(descriptor, policy.owner_uid, policy.owner_gid)
        os.fchmod(descriptor, policy.mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if not _existing_equivalent(temporary, content, policy):
            _fail(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _existing_equivalent(path, content, policy):
                _fsync_parent_directory(path)
                return AtomicCreateResult.IDEMPOTENT
            _fail(FailureCode.CONTRACT_PERSISTENCE_CONFLICT)
        if not _existing_equivalent(path, content, policy):
            _fail(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
        _fsync_parent_directory(path)
        return AtomicCreateResult.CREATED
    except PreparationContractError:
        raise
    except OSError:
        _fail(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                cleanup_failed = True
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            _fail(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
