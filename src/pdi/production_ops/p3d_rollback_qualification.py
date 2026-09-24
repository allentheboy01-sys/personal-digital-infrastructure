"""Disposable-only MU13-P3D Gate A rollback qualification core.

The module composes the frozen WP1 contracts.  It deliberately exposes no
production CLI and accepts all database, release, backup and restore effects as
explicit dependencies.  Concrete PostgreSQL/Restic adapters in this module are
guarded to loopback, ``*_test`` targets and a caller-provided disposable root.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
from psycopg import sql

from .p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    FailureCode,
    OperatorToolIdentity,
    P3DRollbackMetadataV1,
    PreparationContractError,
    PreparationGate,
    PreparationJournalEventV1,
    PreparationOperationStateV1,
    ReleasePinState,
    RollbackReleasePinV1,
    RuntimeDistributionEntryV1,
    SourceFileFingerprintEntryV1,
    ToolName,
    atomic_create_no_replace,
    canonical_json_bytes,
    contract_fingerprint,
    preparation_journal_fingerprint,
    rollback_metadata_fingerprint,
    source_release_fingerprint,
    source_runtime_fingerprint,
    transition_preparation_state,
    validate_preparation_journal_chain,
    validate_rollback_release_pin,
)


EXPECTED_ALEMBIC = "e5a7b9d1f324"
EXPECTED_POSTGRES_MAJOR = 16
SNAPSHOT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
SNAPSHOT_TOKEN_PATTERN = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9]+")
SAFE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}")
ALEMBIC_REVISION_PATTERN = re.compile(r"[0-9a-z]{1,64}")
SYSTEM_PACKAGE_NAME_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?"
)
SYSTEM_PACKAGE_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}")
CANONICAL_BASELINE_TABLES = (
    "assets",
    "blobs",
    "asset_sources",
    "persons",
    "person_sources",
    "resource_person_relations",
    "resource_statements",
    "resource_enrichments",
    "pipeline_runs",
    "provider_sync_state",
)
EXPECTED_PROVIDER_STATES = {
    "gmail": False,
    "immich": True,
    "integration-test": False,
    "nextcloud": True,
}
EXPECTED_SOURCE_PROVIDERS = frozenset(EXPECTED_PROVIDER_STATES)
EXPECTED_SCOPE_SYNC_STATE_KEYS = (
    "immich:metadata_updated_at_v1",
    "nextcloud:activity_v2_hint_v1",
)
EXPECTED_CRITICAL_CONSTRAINTS = frozenset({
    "fk_asset_sources_blob",
    "fk_asset_sources_observation_scope",
    "fk_observation_scope_sync_state_scope",
    "fk_observation_scopes_account_instance",
    "fk_observation_scopes_instance",
    "fk_provider_accounts_instance",
    "pk_observation_scope_sync_state",
    "pk_observation_scopes",
    "pk_provider_accounts",
    "pk_provider_instances",
})
CRITICAL_CONSTRAINT_TABLES = (*CANONICAL_BASELINE_TABLES, *(
    "provider_instances",
    "provider_accounts",
    "observation_scopes",
    "observation_scope_sync_state",
))
GATE_A_TAGS = ("final-quiesced", "p3d-pre-enrichment")


class RollbackQualificationError(RuntimeError):
    """A fixed-code Gate A failure; raw exceptions never cross this boundary."""

    def __init__(self, code: FailureCode):
        self.code = code
        super().__init__(code.value)


def _raise(code: FailureCode) -> None:
    raise RollbackQualificationError(code)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_private_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_sha(value: str) -> str:
    if not isinstance(value, str) or GIT_SHA_PATTERN.fullmatch(value) is None:
        _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
    return value


def _require_hash(value: str) -> str:
    if not isinstance(value, str) or SNAPSHOT_ID_PATTERN.fullmatch(value) is None:
        _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
    return value


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _single_source_alembic_head(payload: str) -> str:
    try:
        heads = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
    if (not isinstance(heads, list) or len(heads) != 1 or
            not isinstance(heads[0], str) or
            ALEMBIC_REVISION_PATTERN.fullmatch(heads[0]) is None):
        _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
    return heads[0]


def _disposable_root(path: Path, *, code: FailureCode) -> Path:
    """Resolve a caller-owned operation root while refusing broad host roots."""

    try:
        if path.is_symlink() or not path.is_dir():
            _raise(code)
        resolved = path.resolve(strict=True)
        forbidden = {Path(item) for item in ("/", "/etc", "/home", "/opt", "/srv", "/tmp", "/var")}
        if resolved in forbidden:
            _raise(code)
        return resolved
    except RollbackQualificationError:
        raise
    except OSError:
        _raise(code)


def _require_utc(value: str, *, code: FailureCode) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError):
        _raise(code)
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _raise(code)
    return value


@dataclass(frozen=True, order=True)
class CountEntryV1:
    name: str
    value: int

    def to_mapping(self) -> dict[str, Any]:
        if SAFE_NAME_PATTERN.fullmatch(self.name) is None or type(self.value) is not int or self.value < 0:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True, order=True)
class ProviderStateEntryV1:
    provider: str
    instance_enabled: bool
    account_count: int
    enabled_account_count: int
    scope_count: int
    enabled_scope_count: int

    def to_mapping(self) -> dict[str, Any]:
        if (self.provider not in EXPECTED_PROVIDER_STATES or
                type(self.instance_enabled) is not bool or
                any(type(item) is not int or item < 0 for item in (
                    self.account_count,
                    self.enabled_account_count,
                    self.scope_count,
                    self.enabled_scope_count,
                ))):
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return {
            "provider": self.provider,
            "instance_enabled": self.instance_enabled,
            "account_count": self.account_count,
            "enabled_account_count": self.enabled_account_count,
            "scope_count": self.scope_count,
            "enabled_scope_count": self.enabled_scope_count,
        }


@dataclass(frozen=True)
class RollbackBaselineEvidenceV1:
    alembic_revision: str
    postgres_major: int
    table_counts: tuple[CountEntryV1, ...]
    provider_states: tuple[ProviderStateEntryV1, ...]
    source_provider_counts: tuple[CountEntryV1, ...]
    null_scope_sources: int
    duplicate_scoped_sources: int
    sync_state_rows: int
    initialized_sync_state_rows: int
    reconciliation_required_rows: int
    null_external_ids: int
    empty_external_ids: int
    missing_blob_links: int
    scope_sync_state_keys: tuple[str, ...]
    legacy_sync_state_keys: tuple[str, ...]
    critical_constraints: tuple[str, ...]
    source_db_fingerprint: str

    FIELDS = {
        "version", "alembic_revision", "postgres_major", "table_counts",
        "provider_states", "source_provider_counts", "null_scope_sources",
        "duplicate_scoped_sources", "sync_state_rows",
        "initialized_sync_state_rows", "reconciliation_required_rows",
        "null_external_ids", "empty_external_ids", "missing_blob_links",
        "scope_sync_state_keys", "legacy_sync_state_keys",
        "critical_constraints", "source_db_fingerprint",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RollbackBaselineEvidenceV1":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS or value["version"] != 1:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        try:
            counts = tuple(sorted(
                CountEntryV1(item["name"], item["value"])
                for item in value["table_counts"]
            ))
            source_counts = tuple(sorted(
                CountEntryV1(item["name"], item["value"])
                for item in value["source_provider_counts"]
            ))
            states = tuple(sorted(
                ProviderStateEntryV1(
                    item["provider"],
                    item["instance_enabled"],
                    item["account_count"],
                    item["enabled_account_count"],
                    item["scope_count"],
                    item["enabled_scope_count"],
                )
                for item in value["provider_states"]
            ))
            result = cls(
                str(value["alembic_revision"]),
                int(value["postgres_major"]),
                counts,
                states,
                source_counts,
                value["null_scope_sources"],
                value["duplicate_scoped_sources"],
                value["sync_state_rows"],
                value["initialized_sync_state_rows"],
                value["reconciliation_required_rows"],
                value["null_external_ids"],
                value["empty_external_ids"],
                value["missing_blob_links"],
                tuple(sorted(str(item) for item in value["scope_sync_state_keys"])),
                tuple(sorted(str(item) for item in value["legacy_sync_state_keys"])),
                tuple(sorted(str(item) for item in value["critical_constraints"])),
                str(value["source_db_fingerprint"]),
            )
        except (KeyError, TypeError, ValueError):
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        result.validate()
        return result

    def validate(self) -> None:
        if (self.alembic_revision != EXPECTED_ALEMBIC or
                self.postgres_major != EXPECTED_POSTGRES_MAJOR or
                tuple(item.name for item in self.table_counts) != tuple(sorted(CANONICAL_BASELINE_TABLES)) or
                len({item.name for item in self.table_counts}) != len(self.table_counts) or
                len(self.provider_states) != len(EXPECTED_PROVIDER_STATES) or
                {item.provider: item.instance_enabled for item in self.provider_states} != EXPECTED_PROVIDER_STATES or
                len(self.source_provider_counts) != len(EXPECTED_SOURCE_PROVIDERS) or
                {item.name for item in self.source_provider_counts} != EXPECTED_SOURCE_PROVIDERS or
                self.null_scope_sources != 0 or self.duplicate_scoped_sources != 0 or
                self.sync_state_rows != 2 or self.initialized_sync_state_rows != 2 or
                self.reconciliation_required_rows != 0 or
                self.null_external_ids != 0 or self.empty_external_ids != 0 or
                self.missing_blob_links != 0 or
                self.scope_sync_state_keys != EXPECTED_SCOPE_SYNC_STATE_KEYS or
                self.legacy_sync_state_keys != EXPECTED_SCOPE_SYNC_STATE_KEYS or
                not EXPECTED_CRITICAL_CONSTRAINTS.issubset(self.critical_constraints) or
                SNAPSHOT_ID_PATTERN.fullmatch(self.source_db_fingerprint) is None):
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        for item in self.provider_states:
            item.to_mapping()
            expected_accounts = 1 if item.provider in {"nextcloud", "immich"} else 0
            expected_enabled_scopes = 1 if EXPECTED_PROVIDER_STATES[item.provider] else 0
            if (item.account_count != expected_accounts or
                    item.enabled_account_count != expected_accounts or
                    item.scope_count != 1 or
                    item.enabled_scope_count != expected_enabled_scopes):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        for item in (*self.table_counts, *self.source_provider_counts):
            item.to_mapping()

    def to_mapping(self) -> dict[str, Any]:
        self.validate()
        return {
            "version": 1,
            "alembic_revision": self.alembic_revision,
            "postgres_major": self.postgres_major,
            "table_counts": [item.to_mapping() for item in sorted(self.table_counts)],
            "provider_states": [item.to_mapping() for item in sorted(self.provider_states)],
            "source_provider_counts": [item.to_mapping() for item in sorted(self.source_provider_counts)],
            "null_scope_sources": self.null_scope_sources,
            "duplicate_scoped_sources": self.duplicate_scoped_sources,
            "sync_state_rows": self.sync_state_rows,
            "initialized_sync_state_rows": self.initialized_sync_state_rows,
            "reconciliation_required_rows": self.reconciliation_required_rows,
            "null_external_ids": self.null_external_ids,
            "empty_external_ids": self.empty_external_ids,
            "missing_blob_links": self.missing_blob_links,
            "scope_sync_state_keys": list(self.scope_sync_state_keys),
            "legacy_sync_state_keys": list(self.legacy_sync_state_keys),
            "critical_constraints": list(sorted(self.critical_constraints)),
            "source_db_fingerprint": self.source_db_fingerprint,
        }


def baseline_counts_fingerprint(value: RollbackBaselineEvidenceV1) -> str:
    return contract_fingerprint({
        "table_counts": [item.to_mapping() for item in sorted(value.table_counts)],
        "source_provider_counts": [
            item.to_mapping() for item in sorted(value.source_provider_counts)
        ],
    })


def baseline_evidence_fingerprint(value: RollbackBaselineEvidenceV1) -> str:
    return contract_fingerprint(value.to_mapping())


@dataclass(frozen=True)
class SourceRuntimeEvidenceV1:
    source_sha: str
    source_release_fingerprint: str
    source_runtime_fingerprint: str
    source_system_runtime_fingerprint: str
    python_version: str
    python_abi: str
    migration_tree_fingerprint: str
    expected_alembic: str

    def validate(self) -> None:
        _require_sha(self.source_sha)
        for value in (
            self.source_release_fingerprint,
            self.source_runtime_fingerprint,
            self.source_system_runtime_fingerprint,
            self.migration_tree_fingerprint,
        ):
            _require_hash(value)
        if self.expected_alembic != EXPECTED_ALEMBIC:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)


@dataclass(frozen=True)
class ExportedSnapshotEvidenceV1:
    operation_id: str
    source_db_fingerprint: str
    exporter_started_at: str
    snapshot_id_sha256: str
    dump_sha256: str
    baseline_counts_sha256: str
    source_release_fingerprint: str
    source_runtime_fingerprint: str

    FIELDS = {
        "version", "operation_id", "source_db_fingerprint", "exporter_started_at",
        "snapshot_id_sha256", "dump_sha256", "baseline_counts_sha256",
        "source_release_fingerprint", "source_runtime_fingerprint",
    }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExportedSnapshotEvidenceV1":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS or value["version"] != "1":
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        try:
            result = cls(
                str(value["operation_id"]),
                str(value["source_db_fingerprint"]),
                str(value["exporter_started_at"]),
                str(value["snapshot_id_sha256"]),
                str(value["dump_sha256"]),
                str(value["baseline_counts_sha256"]),
                str(value["source_release_fingerprint"]),
                str(value["source_runtime_fingerprint"]),
            )
            result.to_mapping()
            return result
        except (TypeError, ValueError):
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)

    def to_mapping(self) -> dict[str, str]:
        UUID(self.operation_id)
        _require_utc(self.exporter_started_at, code=FailureCode.ROLLBACK_RESTORE_FAILED)
        for value in (
            self.source_db_fingerprint,
            self.snapshot_id_sha256,
            self.dump_sha256,
            self.baseline_counts_sha256,
            self.source_release_fingerprint,
            self.source_runtime_fingerprint,
        ):
            _require_hash(value)
        return {
            "version": "1",
            "operation_id": self.operation_id,
            "source_db_fingerprint": self.source_db_fingerprint,
            "exporter_started_at": self.exporter_started_at,
            "snapshot_id_sha256": self.snapshot_id_sha256,
            "dump_sha256": self.dump_sha256,
            "baseline_counts_sha256": self.baseline_counts_sha256,
            "source_release_fingerprint": self.source_release_fingerprint,
            "source_runtime_fingerprint": self.source_runtime_fingerprint,
        }


def exported_snapshot_evidence_fingerprint(value: ExportedSnapshotEvidenceV1) -> str:
    return contract_fingerprint(value.to_mapping())


@dataclass(frozen=True)
class RestoredInvariantsEvidenceV1:
    baseline_evidence_sha256: str
    restored_evidence_sha256: str
    counts_match: bool
    invariants_match: bool
    compatibility_fingerprint: str

    def to_mapping(self) -> dict[str, Any]:
        if not self.counts_match or not self.invariants_match:
            _raise(FailureCode.ROLLBACK_COMPATIBILITY_FAILED)
        return {
            "version": 1,
            "baseline_evidence_sha256": _require_hash(self.baseline_evidence_sha256),
            "restored_evidence_sha256": _require_hash(self.restored_evidence_sha256),
            "counts_match": True,
            "invariants_match": True,
            "compatibility_fingerprint": _require_hash(self.compatibility_fingerprint),
        }


def restored_invariants_fingerprint(value: RestoredInvariantsEvidenceV1) -> str:
    return contract_fingerprint(value.to_mapping())


@dataclass(frozen=True)
class PostgresTarget:
    host: str
    port: int
    database: str
    user: str
    password: str

    def validate_disposable(self) -> None:
        if (self.host not in {"127.0.0.1", "localhost", "::1"} or
                type(self.port) is not int or not 1 <= self.port <= 65535 or
                not self.database.endswith("_test") or not self.user or not self.password):
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)

    def sanitized_identity(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port, "database": self.database, "user": self.user}

    def conninfo(self, *, database: str | None = None) -> str:
        target_db = self.database if database is None else database
        return psycopg.conninfo.make_conninfo(
            host=self.host,
            port=self.port,
            dbname=target_db,
            user=self.user,
            password=self.password,
        )


class BaselineCollector(Protocol):
    def collect(self, connection: Any) -> RollbackBaselineEvidenceV1: ...


class PostgresBaselineCollector:
    """Collect the fixed aggregate Gate A authority on one existing connection."""

    def collect(self, connection: Any) -> RollbackBaselineEvidenceV1:
        try:
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            version_num = int(connection.execute("SHOW server_version_num").fetchone()[0])
            table_counts = tuple(sorted(
                CountEntryV1(
                    table,
                    int(connection.execute(
                        sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))
                    ).fetchone()[0]),
                )
                for table in CANONICAL_BASELINE_TABLES
            ))
            instance_rows = connection.execute(
                "SELECT provider_type, enabled FROM provider_instances ORDER BY provider_type"
            ).fetchall()
            provider_states = []
            for provider, enabled in instance_rows:
                account = connection.execute(
                    "SELECT count(*), count(*) FILTER (WHERE account.enabled) "
                    "FROM provider_accounts account JOIN provider_instances instance "
                    "ON instance.id=account.provider_instance_id WHERE instance.provider_type=%s",
                    (provider,),
                ).fetchone()
                scope = connection.execute(
                    "SELECT count(*), count(*) FILTER (WHERE scope.enabled) "
                    "FROM observation_scopes scope JOIN provider_instances instance "
                    "ON instance.id=scope.provider_instance_id WHERE instance.provider_type=%s",
                    (provider,),
                ).fetchone()
                provider_states.append(ProviderStateEntryV1(
                    str(provider), bool(enabled), int(account[0]), int(account[1]),
                    int(scope[0]), int(scope[1]),
                ))
            source_counts = tuple(sorted(
                CountEntryV1(str(provider), int(count))
                for provider, count in connection.execute(
                    "SELECT provider, count(*) FROM asset_sources GROUP BY provider"
                ).fetchall()
            ))
            null_scope = int(connection.execute(
                "SELECT count(*) FROM asset_sources WHERE observation_scope_id IS NULL"
            ).fetchone()[0])
            duplicate = int(connection.execute(
                "SELECT count(*) FROM (SELECT observation_scope_id, external_id "
                "FROM asset_sources GROUP BY observation_scope_id, external_id "
                "HAVING count(*) > 1) duplicate_sources"
            ).fetchone()[0])
            sync = connection.execute(
                "SELECT count(*), count(*) FILTER (WHERE checkpoint IS NOT NULL), "
                "count(*) FILTER (WHERE reconciliation_required) "
                "FROM observation_scope_sync_state"
            ).fetchone()
            source_hygiene = connection.execute(
                "SELECT count(*) FILTER (WHERE source.external_id IS NULL), "
                "count(*) FILTER (WHERE btrim(source.external_id) = ''), "
                "count(*) FILTER (WHERE blob.id IS NULL) "
                "FROM asset_sources source LEFT JOIN blobs blob ON blob.id=source.blob_id"
            ).fetchone()
            scope_state_keys = tuple(sorted(
                f"{provider}:{mechanism}"
                for provider, mechanism in connection.execute(
                    "SELECT instance.provider_type, state.mechanism "
                    "FROM observation_scope_sync_state state "
                    "JOIN observation_scopes scope ON scope.id=state.observation_scope_id "
                    "JOIN provider_instances instance ON instance.id=scope.provider_instance_id"
                ).fetchall()
            ))
            legacy_state_keys = tuple(sorted(
                f"{provider}:{mechanism}"
                for provider, mechanism in connection.execute(
                    "SELECT provider, mechanism FROM provider_sync_state"
                ).fetchall()
            ))
            constraints = tuple(sorted(row[0] for row in connection.execute(
                "SELECT constraint_name FROM information_schema.table_constraints "
                "WHERE table_schema='public' AND table_name = ANY(%s) "
                "AND constraint_type IN ('PRIMARY KEY','FOREIGN KEY','UNIQUE')",
                (list(CRITICAL_CONSTRAINT_TABLES),),
            ).fetchall()))
            database_name = str(connection.execute("SELECT current_database()").fetchone()[0])
            schema_fingerprint = contract_fingerprint({
                "database_name_hash": _sha256_bytes(database_name.encode()),
                "alembic": str(revision),
                "postgres_major": version_num // 10000,
                "constraints": constraints,
            })
            evidence = RollbackBaselineEvidenceV1(
                str(revision), version_num // 10000, table_counts,
                tuple(sorted(provider_states)), source_counts,
                null_scope, duplicate, int(sync[0]), int(sync[1]), int(sync[2]),
                int(source_hygiene[0]), int(source_hygiene[1]), int(source_hygiene[2]),
                scope_state_keys, legacy_state_keys,
                constraints, schema_fingerprint,
            )
            evidence.validate()
            return evidence
        except RollbackQualificationError:
            raise
        except Exception:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)


class DumpAdapter(Protocol):
    def dump(self, *, snapshot_id: str, output_path: Path) -> None: ...

    def restore(self, *, dump_path: Path, target: PostgresTarget) -> None: ...


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class PostgresCommandAdapter:
    """Fixed-argv PostgreSQL 16 tools; passwords are environment-only."""

    def __init__(
        self,
        source: PostgresTarget,
        *,
        disposable_root: Path,
        pg_dump_path: Path = Path("/usr/bin/pg_dump"),
        pg_restore_path: Path = Path("/usr/bin/pg_restore"),
        runner: CommandRunner = subprocess.run,
    ) -> None:
        self.source = source
        self.disposable_root = _disposable_root(
            disposable_root, code=FailureCode.ROLLBACK_DUMP_FAILED,
        )
        self.pg_dump_path = pg_dump_path
        self.pg_restore_path = pg_restore_path
        self.runner = runner
        self._tools_verified = False

    @staticmethod
    def _environment(password: str) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PGPASSWORD": password}

    def _verify_tools(self) -> None:
        if self._tools_verified:
            return
        for executable in (self.pg_dump_path, self.pg_restore_path):
            result = self.runner(
                (str(executable), "--version"),
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                text=True,
                capture_output=True,
                check=False,
                shell=False,
            )
            if result.returncode != 0 or "(PostgreSQL) 16." not in result.stdout:
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        self._tools_verified = True

    def dump(self, *, snapshot_id: str, output_path: Path) -> None:
        self._verify_tools()
        if SNAPSHOT_TOKEN_PATTERN.fullmatch(snapshot_id) is None or not _inside(output_path, self.disposable_root):
            _raise(FailureCode.ROLLBACK_DUMP_FAILED)
        argv = (
            str(self.pg_dump_path), "--format=custom", "--no-owner", "--no-acl",
            f"--snapshot={snapshot_id}", "--host", self.source.host,
            "--port", str(self.source.port), "--username", self.source.user,
            "--dbname", self.source.database, "--file", str(output_path),
        )
        result = self.runner(
            argv,
            env=self._environment(self.source.password),
            text=True,
            capture_output=True,
            check=False,
            shell=False,
        )
        if result.returncode != 0 or not output_path.is_file() or output_path.stat().st_size == 0:
            _raise(FailureCode.ROLLBACK_DUMP_FAILED)

    def restore(self, *, dump_path: Path, target: PostgresTarget) -> None:
        self._verify_tools()
        target.validate_disposable()
        if not _inside(dump_path, self.disposable_root):
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        argv = (
            str(self.pg_restore_path), "--no-owner", "--no-acl", "--exit-on-error",
            "--host", target.host, "--port", str(target.port),
            "--username", target.user, "--dbname", target.database, str(dump_path),
        )
        result = self.runner(
            argv,
            env=self._environment(target.password),
            text=True,
            capture_output=True,
            check=False,
            shell=False,
        )
        if result.returncode != 0:
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)


@dataclass(frozen=True)
class SnapshotExportResult:
    baseline: RollbackBaselineEvidenceV1
    dump_path: Path
    dump_sha256: str
    evidence: ExportedSnapshotEvidenceV1


class ExportedSnapshotCoordinator:
    """Hold one exported snapshot through baseline, dump and evidence hashing."""

    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        baseline_collector: BaselineCollector,
        dump_adapter: DumpAdapter,
        lifecycle: Callable[[str], None] | None = None,
    ) -> None:
        self.connect = connect
        self.baseline_collector = baseline_collector
        self.dump_adapter = dump_adapter
        self.lifecycle = lifecycle or (lambda _event: None)

    def export(
        self,
        *,
        operation_id: str,
        output_path: Path,
        source_runtime: SourceRuntimeEvidenceV1,
        on_snapshot_exported: Callable[[], None],
        on_dump_completed: Callable[[], None],
    ) -> SnapshotExportResult:
        exporter = None
        importer = None
        try:
            exporter = self.connect()
            exporter.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            self.lifecycle("EXPORTER_BEGIN")
            started_at = _utc_now()
            snapshot_id = str(exporter.execute("SELECT pg_export_snapshot()").fetchone()[0])
            if SNAPSHOT_TOKEN_PATTERN.fullmatch(snapshot_id) is None:
                _raise(FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED)
            self.lifecycle("SNAPSHOT_EXPORTED")
            on_snapshot_exported()

            importer = self.connect()
            importer.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            self.lifecycle("IMPORTER_BEGIN")
            importer.execute(f"SET TRANSACTION SNAPSHOT '{snapshot_id}'")
            self.lifecycle("IMPORTER_SNAPSHOT_SET")
            read_only = str(importer.execute("SHOW transaction_read_only").fetchone()[0]).lower()
            if read_only != "on":
                _raise(FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED)
            self.lifecycle("IMPORTER_READ_ONLY")
            baseline = self.baseline_collector.collect(importer)
            self.lifecycle("BASELINE_COLLECTED")

            self.dump_adapter.dump(snapshot_id=snapshot_id, output_path=output_path)
            self.lifecycle("DUMP_EXIT_ZERO")
            with output_path.open("rb") as handle:
                os.fsync(handle.fileno())
            self.lifecycle("DUMP_FSYNCED")
            dump_sha = _sha256_file(output_path)
            self.lifecycle("DUMP_HASHED")
            counts_hash = baseline_counts_fingerprint(baseline)
            evidence = ExportedSnapshotEvidenceV1(
                operation_id,
                baseline.source_db_fingerprint,
                started_at,
                _sha256_bytes(snapshot_id.encode()),
                dump_sha,
                counts_hash,
                source_runtime.source_release_fingerprint,
                source_runtime.source_runtime_fingerprint,
            )
            exported_snapshot_evidence_fingerprint(evidence)
            self.lifecycle("EVIDENCE_HASHED")
            on_dump_completed()
            return SnapshotExportResult(baseline, output_path, dump_sha, evidence)
        except RollbackQualificationError:
            raise
        except Exception:
            _raise(FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED)
        finally:
            if importer is not None:
                try:
                    importer.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    importer.close()
                except Exception:
                    pass
            if exporter is not None:
                self.lifecycle("EXPORTER_ROLLBACK")
                try:
                    exporter.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    exporter.close()
                except Exception:
                    pass


@dataclass(frozen=True)
class BackupSnapshot:
    snapshot_id: str
    repository_identity: str
    backup_fs_uuid: str


class BackupAdapter(Protocol):
    def create_snapshot(self, payload_dir: Path) -> BackupSnapshot: ...

    def restore_snapshot(self, snapshot_id: str, destination: Path) -> Path: ...


class FilesystemBackupAdapter:
    """Faithful disposable content-addressed backup used by unit tests."""

    def __init__(self, repository: Path, *, disposable_root: Path, backup_fs_uuid: str) -> None:
        self.disposable_root = _disposable_root(
            disposable_root, code=FailureCode.ROLLBACK_BACKUP_FAILED,
        )
        self.repository = repository
        self.backup_fs_uuid = str(UUID(backup_fs_uuid))
        if not _inside(repository, self.disposable_root):
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        repository.mkdir(mode=0o700, parents=True, exist_ok=True)

    def create_snapshot(self, payload_dir: Path) -> BackupSnapshot:
        if not _inside(payload_dir, self.disposable_root):
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        entries = []
        for path in sorted(item for item in payload_dir.rglob("*") if item.is_file()):
            entries.append((str(path.relative_to(payload_dir)), _sha256_file(path)))
        if not entries:
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        snapshot_id = contract_fingerprint({"files": entries})
        target = self.repository / snapshot_id
        if target.exists():
            existing = [(str(path.relative_to(target)), _sha256_file(path))
                        for path in sorted(item for item in target.rglob("*") if item.is_file())]
            if existing != entries:
                _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        else:
            shutil.copytree(payload_dir, target)
        return BackupSnapshot(snapshot_id, str(self.repository), self.backup_fs_uuid)

    def restore_snapshot(self, snapshot_id: str, destination: Path) -> Path:
        if SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id) is None or not _inside(destination, self.disposable_root):
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        source = self.repository / snapshot_id
        if not source.is_dir() or destination.exists():
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        shutil.copytree(source, destination)
        return destination


class ResticBackupAdapter:
    """Disposable-only Restic adapter exposing no destructive operations."""

    def __init__(
        self,
        repository: Path,
        password_file: Path,
        *,
        disposable_root: Path,
        backup_fs_uuid: str,
        restic_path: Path = Path("/usr/bin/restic"),
        runner: CommandRunner = subprocess.run,
    ) -> None:
        self.disposable_root = _disposable_root(
            disposable_root, code=FailureCode.ROLLBACK_BACKUP_FAILED,
        )
        self.repository = repository
        self.password_file = password_file
        self.backup_fs_uuid = str(UUID(backup_fs_uuid))
        self.restic_path = restic_path
        self.runner = runner
        if (not _inside(repository, self.disposable_root) or
                not _inside(password_file, self.disposable_root)):
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)

    def _env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "RESTIC_REPOSITORY": str(self.repository),
            "RESTIC_PASSWORD_FILE": str(self.password_file),
        }

    def initialize_disposable(self) -> None:
        if self.repository.exists():
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        result = self.runner(
            (str(self.restic_path), "init"), env=self._env(), text=True,
            capture_output=True, check=False, shell=False,
        )
        if result.returncode != 0:
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)

    def create_snapshot(self, payload_dir: Path) -> BackupSnapshot:
        if not _inside(payload_dir, self.disposable_root):
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        result = self.runner(
            (
                str(self.restic_path), "backup", "--json", "--tag", "pdi-core-db",
                "--tag", "mu13-p3d", "--tag", "p3d-pre-enrichment", str(payload_dir),
            ),
            env=self._env(), text=True, capture_output=True, check=False, shell=False,
        )
        if result.returncode != 0:
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        try:
            records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            snapshot_ids = [item.get("snapshot_id") for item in records if item.get("message_type") == "summary"]
        except (AttributeError, json.JSONDecodeError):
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        if len(snapshot_ids) != 1 or SNAPSHOT_ID_PATTERN.fullmatch(str(snapshot_ids[0])) is None:
            _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
        return BackupSnapshot(str(snapshot_ids[0]), str(self.repository), self.backup_fs_uuid)

    def restore_snapshot(self, snapshot_id: str, destination: Path) -> Path:
        if SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id) is None or not _inside(destination, self.disposable_root):
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        if destination.exists():
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        destination.mkdir(mode=0o700, parents=False)
        result = self.runner(
            (str(self.restic_path), "restore", snapshot_id, "--target", str(destination)),
            env=self._env(), text=True, capture_output=True, check=False, shell=False,
        )
        if result.returncode != 0:
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        return destination


@dataclass(frozen=True, order=True)
class SystemRuntimeFileEvidenceV1:
    path: str
    resolved_path: str
    file_sha256: str
    uid: int
    gid: int
    mode: str
    package_name: str
    package_version: str

    def to_mapping(self) -> dict[str, Any]:
        for value in (self.path, self.resolved_path):
            if not isinstance(value, str):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            parsed = Path(value)
            if (not parsed.is_absolute() or
                    ".." in parsed.parts or any(character in value for character in ("\n", "\r", "\x00"))):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        if (self.uid != 0 or self.gid != 0 or
                re.fullmatch(r"0[0-7]{3,4}", self.mode) is None or
                int(self.mode, 8) & 0o022 or
                SYSTEM_PACKAGE_NAME_PATTERN.fullmatch(self.package_name) is None or
                SYSTEM_PACKAGE_VERSION_PATTERN.fullmatch(self.package_version) is None):
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return {
            "path": self.path,
            "resolved_path": self.resolved_path,
            "file_sha256": _require_hash(self.file_sha256),
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
            "package_name": self.package_name,
            "package_version": self.package_version,
        }


@dataclass(frozen=True)
class SourceSystemRuntimeEvidenceV1:
    os_id: str
    os_version_id: str
    architecture: str
    python_implementation: str
    python_version: str
    python_abi: str
    platform: str
    entries: tuple[SystemRuntimeFileEvidenceV1, ...]

    def to_mapping(self) -> dict[str, Any]:
        for value in (
            self.os_id, self.os_version_id, self.architecture,
            self.python_implementation, self.python_version, self.python_abi, self.platform,
        ):
            if SAFE_NAME_PATTERN.fullmatch(value) is None:
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        ordered = tuple(sorted(self.entries))
        if (not ordered or len({(item.path, item.resolved_path) for item in ordered}) != len(ordered)):
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return {
            "version": 1,
            "os_id": self.os_id,
            "os_version_id": self.os_version_id,
            "architecture": self.architecture,
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
            "python_abi": self.python_abi,
            "platform": self.platform,
            "entries": [item.to_mapping() for item in ordered],
        }


def source_system_runtime_fingerprint(value: SourceSystemRuntimeEvidenceV1) -> str:
    return contract_fingerprint(value.to_mapping())


@dataclass(frozen=True)
class ReleaseFilesystemFacts:
    current_target: Path
    git_head: str
    git_clean: bool
    entries: tuple[SourceFileFingerprintEntryV1, ...]
    python_path: Path
    python_version: str
    python_abi: str
    system_runtime_fingerprint: str
    distributions: tuple[RuntimeDistributionEntryV1, ...]
    migration_tree_fingerprint: str
    source_alembic_head: str
    import_smoke: bool


class ReleaseFactsReader(Protocol):
    def read(self, release_path: Path) -> ReleaseFilesystemFacts: ...


class SourceRuntimeQualifier:
    def __init__(self, facts_reader: ReleaseFactsReader, *, releases_root: Path = Path("/opt/pdi/releases")):
        self.facts_reader = facts_reader
        self.releases_root = releases_root

    def qualify(self, expected_source_sha: str) -> SourceRuntimeEvidenceV1:
        source_sha = _require_sha(expected_source_sha)
        release = self.releases_root / source_sha
        facts = self.facts_reader.read(release)
        if (release != self.releases_root / source_sha or facts.current_target != release or
                facts.git_head != source_sha or not facts.git_clean or not facts.import_smoke or
                facts.python_path != release / ".venv/bin/python"):
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
        release_hash = source_release_fingerprint(source_sha, facts.entries)
        runtime_hash = source_runtime_fingerprint(
            source_release_sha256=release_hash,
            system_runtime_sha256=facts.system_runtime_fingerprint,
            python_version=facts.python_version,
            python_abi=facts.python_abi,
            distributions=facts.distributions,
        )
        runtime_hash = contract_fingerprint({
            "source_runtime_fingerprint": runtime_hash,
            "migration_tree_fingerprint": facts.migration_tree_fingerprint,
            "source_alembic_head": facts.source_alembic_head,
        })
        evidence = SourceRuntimeEvidenceV1(
            source_sha, release_hash, runtime_hash, facts.system_runtime_fingerprint,
            facts.python_version, facts.python_abi, facts.migration_tree_fingerprint,
            facts.source_alembic_head,
        )
        evidence.validate()
        return evidence


class RootControlledReleaseFactsReader:
    """Read a canonical immutable release using fixed read-only subprocess env."""

    REQUIRED = (
        "pyproject.toml",
        "alembic.ini",
        "scripts/mu13_p3c_cutover.py",
        "src/pdi/__init__.py",
        "src/pdi/scoped_operational.py",
        ".venv/bin/python",
    )

    def __init__(
        self,
        current_path: Path = Path("/opt/pdi/current"),
        *,
        approved_external_symlink_roots: tuple[Path, ...] = (Path("/usr"),),
        os_release_path: Path = Path("/etc/os-release"),
        ldd_path: Path = Path("/usr/bin/ldd"),
        dpkg_path: Path = Path("/usr/bin/dpkg"),
        dpkg_query_path: Path = Path("/usr/bin/dpkg-query"),
        runner: CommandRunner = subprocess.run,
    ):
        self.current_path = current_path
        self.approved_external_symlink_roots = approved_external_symlink_roots
        self.os_release_path = os_release_path
        self.ldd_path = ldd_path
        self.dpkg_path = dpkg_path
        self.dpkg_query_path = dpkg_query_path
        self.runner = runner

    @staticmethod
    def _git_env() -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"}

    def _run(self, argv: tuple[str, ...], *, cwd: Path, env: Mapping[str, str]) -> str:
        result = self.runner(argv, cwd=cwd, env=dict(env), text=True,
                             capture_output=True, check=False, shell=False)
        if result.returncode != 0:
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
        return result.stdout.strip()

    @staticmethod
    def _system_env() -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

    def _run_system(self, argv: tuple[str, ...], *, cwd: Path) -> str:
        result = self.runner(
            argv, cwd=cwd, env=self._system_env(), text=True,
            capture_output=True, check=False, shell=False,
        )
        if result.returncode != 0:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return result.stdout.strip()

    @staticmethod
    def _root_controlled(path: Path, *, stop: Path) -> bool:
        try:
            current = path
            stop = stop.resolve(strict=True)
            while True:
                info = current.lstat()
                if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
                    return False
                if current == stop:
                    return True
                if current == current.parent:
                    return False
                current = current.parent
        except OSError:
            return False

    def _os_identity(self) -> tuple[str, str]:
        try:
            raw_info = self.os_release_path.lstat()
            resolved = self.os_release_path.resolve(strict=True)
            resolved_info = resolved.lstat()
            if (raw_info.st_uid != 0 or raw_info.st_gid != 0 or
                    (not stat.S_ISLNK(raw_info.st_mode) and raw_info.st_mode & 0o022) or
                    not stat.S_ISREG(resolved_info.st_mode) or resolved_info.st_uid != 0 or
                    resolved_info.st_gid != 0 or resolved_info.st_mode & 0o022 or
                    not self._root_controlled(self.os_release_path.parent, stop=Path("/")) or
                    not self._root_controlled(resolved, stop=Path("/"))):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            values: dict[str, str] = {}
            for line in resolved.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, encoded = line.split("=", 1)
                if key not in {"ID", "VERSION_ID"}:
                    continue
                decoded = shlex.split(encoded, posix=True)
                if len(decoded) != 1 or SAFE_NAME_PATTERN.fullmatch(decoded[0]) is None:
                    _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
                values[key] = decoded[0]
            if set(values) != {"ID", "VERSION_ID"}:
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            return values["ID"], values["VERSION_ID"]
        except RollbackQualificationError:
            raise
        except (OSError, UnicodeError, ValueError):
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)

    @staticmethod
    def _parse_ldd_output(payload: str) -> tuple[Path, ...]:
        dependencies: set[Path] = set()
        for raw_line in payload.splitlines():
            line = raw_line.strip()
            if not line or line == "statically linked":
                continue
            if "=>" in line:
                _name, target = line.split("=>", 1)
                token = target.strip().split(maxsplit=1)[0]
                if token == "not" or not token.startswith("/"):
                    _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
                dependencies.add(Path(token))
                continue
            token = line.split(maxsplit=1)[0]
            if token in {"linux-vdso.so.1", "linux-gate.so.1"}:
                continue
            if not token.startswith("/"):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            dependencies.add(Path(token))
        return tuple(sorted(dependencies))

    def _package_identity(self, path: Path, resolved: Path, *, cwd: Path) -> tuple[str, str]:
        packages: set[str] = set()
        for candidate in dict.fromkeys((path, resolved)):
            result = self.runner(
                (str(self.dpkg_query_path), "--search", str(candidate)),
                cwd=cwd, env=self._system_env(), text=True,
                capture_output=True, check=False, shell=False,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                if ": " not in line:
                    _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
                package, _installed_path = line.split(": ", 1)
                if SYSTEM_PACKAGE_NAME_PATTERN.fullmatch(package) is None:
                    _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
                packages.add(package)
        if len(packages) != 1:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        package = next(iter(packages))
        version = self._run_system((
            str(self.dpkg_query_path), "--show", "--showformat=${Version}", package,
        ), cwd=cwd)
        if SYSTEM_PACKAGE_VERSION_PATTERN.fullmatch(version) is None:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return package, version

    def _system_runtime_entry(self, path: Path, *, cwd: Path) -> SystemRuntimeFileEvidenceV1:
        try:
            raw_info = path.lstat()
            resolved = path.resolve(strict=True)
            resolved_info = resolved.lstat()
            if (raw_info.st_uid != 0 or raw_info.st_gid != 0 or
                    (not stat.S_ISLNK(raw_info.st_mode) and raw_info.st_mode & 0o022) or
                    not stat.S_ISREG(resolved_info.st_mode) or resolved_info.st_uid != 0 or
                    resolved_info.st_gid != 0 or resolved_info.st_mode & 0o022 or
                    not self._root_controlled(path.parent, stop=Path("/")) or
                    not self._root_controlled(resolved, stop=Path("/"))):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            package, version = self._package_identity(path, resolved, cwd=cwd)
            entry = SystemRuntimeFileEvidenceV1(
                str(path), str(resolved), _sha256_file(resolved),
                resolved_info.st_uid, resolved_info.st_gid,
                f"0{stat.S_IMODE(resolved_info.st_mode):03o}", package, version,
            )
            entry.to_mapping()
            return entry
        except RollbackQualificationError:
            raise
        except OSError:
            _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)

    def _system_runtime_evidence(
        self,
        *,
        release_path: Path,
        python_path: Path,
        site_packages: Path,
        runtime: Mapping[str, Any],
    ) -> SourceSystemRuntimeEvidenceV1:
        python_target = python_path.resolve(strict=True)
        binaries = {python_target}
        for path in site_packages.rglob("*"):
            if path.is_file() and (path.name.endswith(".so") or ".so." in path.name):
                binaries.add(path.resolve(strict=True))
        dependency_paths: set[Path] = {python_target}
        for binary in sorted(binaries):
            binary_inside_release = _inside(binary, release_path)
            trust_root = release_path if binary_inside_release else Path("/")
            if ((not binary_inside_release and binary != python_target) or
                    not self._root_controlled(binary, stop=trust_root)):
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            ldd_output = self._run_system((str(self.ldd_path), str(binary)), cwd=release_path)
            dependency_paths.update(self._parse_ldd_output(ldd_output))
        os_id, os_version_id = self._os_identity()
        architecture = self._run_system(
            (str(self.dpkg_path), "--print-architecture"), cwd=release_path,
        )
        evidence = SourceSystemRuntimeEvidenceV1(
            os_id,
            os_version_id,
            architecture,
            str(runtime["implementation"]),
            str(runtime["version"]),
            str(runtime["abi"]),
            str(runtime["platform"]),
            tuple(self._system_runtime_entry(path, cwd=release_path) for path in sorted(dependency_paths)),
        )
        evidence.to_mapping()
        return evidence

    def read(self, release_path: Path) -> ReleaseFilesystemFacts:
        try:
            current_info = self.current_path.lstat()
            if (release_path.is_symlink() or not release_path.is_dir() or
                    not self.current_path.is_symlink() or current_info.st_uid != 0 or
                    current_info.st_gid != 0 or
                    not self._root_controlled(release_path, stop=Path("/"))):
                _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
            current_target = self.current_path.resolve(strict=True)
            entries: list[SourceFileFingerprintEntryV1] = []
            for path in sorted(release_path.rglob("*")):
                relative = str(path.relative_to(release_path))
                if Path(relative).parts[0] == ".git":
                    continue
                info = path.lstat()
                mode = f"0{stat.S_IMODE(info.st_mode):03o}"
                if info.st_uid != 0 or info.st_gid != 0:
                    _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
                if stat.S_ISLNK(info.st_mode):
                    resolved = path.resolve(strict=True)
                    if _inside(resolved, release_path):
                        target = str(resolved.relative_to(release_path))
                    else:
                        approved_root = next((
                            root.resolve(strict=True)
                            for root in self.approved_external_symlink_roots
                            if _inside(resolved, root)
                        ), None)
                        if (approved_root is None or
                                not self._root_controlled(resolved, stop=approved_root)):
                            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
                        target = str(resolved)
                    if not target:
                        _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
                    entries.append(SourceFileFingerprintEntryV1(
                        relative, "symlink", mode, 0, 0,
                        symlink_target=target,
                    ))
                elif stat.S_ISDIR(info.st_mode):
                    if info.st_mode & 0o022:
                        _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
                    entries.append(SourceFileFingerprintEntryV1(relative, "directory", mode, 0, 0))
                elif stat.S_ISREG(info.st_mode):
                    if info.st_mode & 0o022:
                        _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
                    entries.append(SourceFileFingerprintEntryV1(
                        relative, "file", mode, 0, 0, _sha256_file(path),
                    ))
                else:
                    _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
            if any(not (release_path / item).is_file() for item in self.REQUIRED):
                _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
            head = self._run(("/usr/bin/git", "-C", str(release_path), "rev-parse", "HEAD"),
                             cwd=release_path, env=self._git_env())
            status_output = self._run((
                "/usr/bin/git", "-C", str(release_path), "status", "--porcelain",
                "--untracked-files=all",
            ), cwd=release_path, env=self._git_env())
            python_path = release_path / ".venv/bin/python"
            import_env = {
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(release_path / "src"),
            }
            runtime_json = self._run((
                str(python_path), "-c",
                "import json,platform,sys,sysconfig,pdi,psycopg,sqlalchemy; print(json.dumps({"
                "'version':sys.version.split()[0],"
                "'abi':sysconfig.get_config_var('SOABI') or 'unknown',"
                "'implementation':platform.python_implementation(),"
                "'platform':sys.platform}))",
            ), cwd=release_path, env=import_env)
            runtime = json.loads(runtime_json)
            source_alembic_head = _single_source_alembic_head(self._run((
                str(python_path), "-c",
                "import json; from alembic.config import Config; "
                "from alembic.script import ScriptDirectory; "
                "print(json.dumps(sorted(ScriptDirectory.from_config("
                "Config('alembic.ini')).get_heads())))",
            ), cwd=release_path, env=import_env))
            distributions = []
            site_packages = next(iter(sorted((release_path / ".venv").glob("lib/python*/site-packages"))), None)
            if site_packages is None:
                _raise(FailureCode.ROLLBACK_RUNTIME_INVALID)
            for dist_info in sorted(site_packages.glob("*.dist-info")):
                metadata = (dist_info / "METADATA").read_text(encoding="utf-8")
                name = next((re.sub(r"[-_.]+", "-", line[6:].strip().lower())
                             for line in metadata.splitlines() if line.startswith("Name: ")), "")
                version = next((line[9:].strip()
                                for line in metadata.splitlines() if line.startswith("Version: ")), "")
                record = dist_info / "RECORD"
                distributions.append(RuntimeDistributionEntryV1(name, version, _sha256_file(record)))
            migration_entries = [
                (str(path.relative_to(release_path)), _sha256_file(path))
                for path in sorted((release_path / "migrations").rglob("*.py"))
            ]
            system_runtime = self._system_runtime_evidence(
                release_path=release_path,
                python_path=python_path,
                site_packages=site_packages,
                runtime=runtime,
            )
            return ReleaseFilesystemFacts(
                current_target, head, status_output == "", tuple(entries), python_path,
                str(runtime["version"]), str(runtime["abi"]),
                source_system_runtime_fingerprint(system_runtime),
                tuple(distributions), contract_fingerprint({"migrations": migration_entries}),
                source_alembic_head, True,
            )
        except RollbackQualificationError:
            raise
        except Exception:
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)


def serialize_metadata(value: P3DRollbackMetadataV1) -> bytes:
    mapping = value.to_mapping()
    lines = []
    for key in sorted(mapping):
        item = mapping[key]
        encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if any(character in encoded for character in ("\n", "\r", "\x00")):
            _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
        lines.append(f"{key}={encoded}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_metadata(payload: bytes) -> P3DRollbackMetadataV1:
    try:
        text_value = payload.decode("utf-8", errors="strict")
        if not text_value.endswith("\n") or "\r" in text_value or "\x00" in text_value:
            _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
        mapping: dict[str, Any] = {}
        for line in text_value.splitlines():
            key, encoded = line.split("=", 1)
            if not key or key in mapping:
                _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
            mapping[key] = json.loads(encoded)
        metadata = P3DRollbackMetadataV1.from_mapping(mapping)
        if serialize_metadata(metadata) != payload:
            _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
        return metadata
    except (PreparationContractError, UnicodeError, ValueError, json.JSONDecodeError):
        _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)


class GateAJournalStore:
    """Immutable sequence files with WP1 whole-chain validation."""

    def __init__(self, root: Path, *, policy: AtomicCreatePolicyV1 = AtomicCreatePolicyV1()) -> None:
        self.root = root
        self.policy = policy

    def initialize(
        self,
        *,
        operation_id: str,
        candidate_sha: str,
        started_at: str,
        export_tool: OperatorToolIdentity,
        restore_tool: OperatorToolIdentity,
    ) -> PreparationOperationStateV1:
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        state = PreparationOperationStateV1.from_mapping({
            "version": 1,
            "operation_id": operation_id,
            "gate": PreparationGate.ROLLBACK_QUALIFICATION.value,
            "candidate_sha": candidate_sha,
            "phase": "NEW",
            "started_at": started_at,
            "updated_at": started_at,
            "operator_tool_identities": [export_tool.to_mapping(), restore_tool.to_mapping()],
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
        target: str,
        *,
        timestamp: str,
        tool: OperatorToolIdentity,
        evidence_fingerprints: Sequence[str],
        failure_code: FailureCode | None = None,
    ) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        event = PreparationJournalEventV1.from_mapping({
            "version": 1,
            "sequence": len(events) + 1,
            "operation_id": state.operation_id,
            "gate": state.gate.value,
            "candidate_sha": state.candidate_sha,
            "from_state": state.phase,
            "to_state": target,
            "timestamp": timestamp,
            "tool_identity": tool.to_mapping(),
            "evidence_fingerprints": list(evidence_fingerprints),
            "failure_code": None if failure_code is None else failure_code.value,
        })
        next_events = (*events, event)
        next_state = transition_preparation_state(
            state,
            target,
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

    @staticmethod
    def resume_allowed(state: PreparationOperationStateV1) -> bool:
        return state.gate is PreparationGate.ROLLBACK_QUALIFICATION and state.phase in {
            "NEW", "SOURCE_VERIFIED",
        }

    def load_retryable(
        self,
    ) -> tuple[PreparationOperationStateV1, tuple[PreparationJournalEventV1, ...]]:
        try:
            state_paths = sorted(self.root.glob("state-*.json"))
            journal_paths = sorted(self.root.glob("journal-*.json"))
            if len(state_paths) != len(journal_paths) + 1 or not state_paths:
                _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
            states = tuple(
                PreparationOperationStateV1.from_mapping(json.loads(path.read_text()))
                for path in state_paths
            )
            events = tuple(
                PreparationJournalEventV1.from_mapping(json.loads(path.read_text()))
                for path in journal_paths
            )
            state = states[-1]
            if events:
                validate_preparation_journal_chain(events, state)
            elif state.phase != "NEW" or state.evidence_fingerprint is not None:
                _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
            if not self.resume_allowed(state):
                _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
            return state, events
        except RollbackQualificationError:
            raise
        except Exception:
            _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)


@dataclass(frozen=True)
class QualificationContext:
    candidate_sha: str
    source_sha: str
    p3c_context_fingerprint: str
    p3c_soak_evidence_sha256: str
    backup_fs_uuid: str
    qualified_at_utc: str

    def validate(self) -> None:
        _require_sha(self.candidate_sha)
        _require_sha(self.source_sha)
        if self.candidate_sha == self.source_sha:
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
        _require_hash(self.p3c_context_fingerprint)
        _require_hash(self.p3c_soak_evidence_sha256)
        UUID(self.backup_fs_uuid)


@dataclass(frozen=True)
class RestoreQualificationResult:
    restored_invariants: RestoredInvariantsEvidenceV1


class RestoreQualificationAdapter(Protocol):
    def qualify(
        self,
        *,
        recovered_dump: Path,
        baseline: RollbackBaselineEvidenceV1,
        source_runtime: SourceRuntimeEvidenceV1,
    ) -> RestoreQualificationResult: ...


@dataclass(frozen=True)
class RollbackQualificationResult:
    metadata: P3DRollbackMetadataV1
    metadata_sha256: str
    release_pin: RollbackReleasePinV1
    final_state: PreparationOperationStateV1
    events: tuple[PreparationJournalEventV1, ...]


class RollbackQualificationOrchestrator:
    """Gate A orchestration; runnable only with explicit disposable dependencies."""

    def __init__(
        self,
        *,
        disposable_root: Path,
        source_qualifier: SourceRuntimeQualifier,
        snapshot_coordinator_factory: Callable[[Callable[[str], None]], ExportedSnapshotCoordinator],
        backup_adapter: BackupAdapter,
        restore_adapter: RestoreQualificationAdapter,
        export_tool: OperatorToolIdentity,
        restore_tool: OperatorToolIdentity,
        persistence_policy: AtomicCreatePolicyV1,
    ) -> None:
        self.disposable_root = _disposable_root(
            disposable_root, code=FailureCode.ROLLBACK_SOURCE_INVALID,
        )
        self.source_qualifier = source_qualifier
        self.snapshot_coordinator_factory = snapshot_coordinator_factory
        self.backup_adapter = backup_adapter
        self.restore_adapter = restore_adapter
        self.persistence_policy = persistence_policy
        try:
            self.export_tool = OperatorToolIdentity.from_mapping(export_tool.to_mapping())
            self.restore_tool = OperatorToolIdentity.from_mapping(restore_tool.to_mapping())
        except PreparationContractError:
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
        if (self.export_tool.tool_name is not ToolName.BACKUP_EXPORT or
                self.restore_tool.tool_name is not ToolName.RESTORE_QUALIFY):
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)

    def run(self, context: QualificationContext) -> RollbackQualificationResult:
        context.validate()
        operation_id = str(uuid4())
        operation_root = self.disposable_root / f"operation-{operation_id}"
        operation_root.mkdir(mode=0o700)
        authority_root = operation_root / "authority"
        journal_store = GateAJournalStore(authority_root, policy=self.persistence_policy)
        timestamp = context.qualified_at_utc
        state = journal_store.initialize(
            operation_id=operation_id,
            candidate_sha=context.candidate_sha,
            started_at=timestamp,
            export_tool=self.export_tool,
            restore_tool=self.restore_tool,
        )
        events: tuple[PreparationJournalEventV1, ...] = ()
        snapshot_created = False

        def advance(target: str, tool: OperatorToolIdentity, evidence: Sequence[str]) -> None:
            nonlocal state, events
            state, events = journal_store.advance(
                state, events, target, timestamp=timestamp, tool=tool,
                evidence_fingerprints=evidence,
            )

        try:
            runtime = self.source_qualifier.qualify(context.source_sha)
            advance("SOURCE_VERIFIED", self.export_tool, (
                runtime.source_release_fingerprint, runtime.source_runtime_fingerprint,
            ))
            payload = operation_root / "payload"
            payload.mkdir(mode=0o700)
            dump_path = payload / "pdi-core.dump"
            coordinator = self.snapshot_coordinator_factory(lambda _event: None)
            export_result = coordinator.export(
                operation_id=operation_id,
                output_path=dump_path,
                source_runtime=runtime,
                on_snapshot_exported=lambda: advance(
                    "SNAPSHOT_EXPORTED", self.export_tool, (runtime.source_release_fingerprint,),
                ),
                on_dump_completed=lambda: advance(
                    "DUMP_COMPLETED", self.export_tool, (_sha256_file(dump_path),),
                ),
            )
            baseline_payload = canonical_json_bytes(export_result.baseline.to_mapping()) + b"\n"
            evidence_payload = canonical_json_bytes(export_result.evidence.to_mapping()) + b"\n"
            _write_private_file(payload / "baseline.json", baseline_payload)
            _write_private_file(payload / "exported-snapshot-evidence.json", evidence_payload)
            snapshot = self.backup_adapter.create_snapshot(payload)
            try:
                backup_fs_uuid = str(UUID(snapshot.backup_fs_uuid))
            except (AttributeError, TypeError, ValueError):
                _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
            if (not isinstance(snapshot.snapshot_id, str) or
                    SNAPSHOT_ID_PATTERN.fullmatch(snapshot.snapshot_id) is None or
                    backup_fs_uuid != context.backup_fs_uuid or
                    not isinstance(snapshot.repository_identity, str) or
                    not snapshot.repository_identity or
                    any(character in snapshot.repository_identity for character in ("\n", "\r")) or
                    "://" in snapshot.repository_identity):
                _raise(FailureCode.ROLLBACK_BACKUP_FAILED)
            snapshot_created = True
            advance("BACKUP_SNAPSHOT_CREATED", self.export_tool, (
                snapshot.snapshot_id,
                exported_snapshot_evidence_fingerprint(export_result.evidence),
            ))

            advance("RESTORE_STARTED", self.restore_tool, (snapshot.snapshot_id,))
            restored_root = operation_root / "restored"
            self.backup_adapter.restore_snapshot(snapshot.snapshot_id, restored_root)
            recovered_files = tuple(path for path in restored_root.rglob("*") if path.is_file())
            recovered_candidates = tuple(restored_root.rglob("pdi-core.dump"))
            recovered_baselines = tuple(restored_root.rglob("baseline.json"))
            recovered_evidence_files = tuple(
                restored_root.rglob("exported-snapshot-evidence.json")
            )
            if (len(recovered_files) != 3 or
                    {path.name for path in recovered_files} != {
                        "pdi-core.dump", "baseline.json", "exported-snapshot-evidence.json",
                    } or
                    len(recovered_candidates) != 1 or len(recovered_baselines) != 1 or
                    len(recovered_evidence_files) != 1 or
                    _sha256_file(recovered_candidates[0]) != export_result.dump_sha256):
                _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
            try:
                recovered_baseline = RollbackBaselineEvidenceV1.from_mapping(
                    json.loads(recovered_baselines[0].read_text(encoding="utf-8"))
                )
                recovered_evidence = ExportedSnapshotEvidenceV1.from_mapping(
                    json.loads(recovered_evidence_files[0].read_text(encoding="utf-8"))
                )
            except (RollbackQualificationError, OSError, UnicodeError, json.JSONDecodeError):
                _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
            if (baseline_evidence_fingerprint(recovered_baseline) !=
                    baseline_evidence_fingerprint(export_result.baseline) or
                    exported_snapshot_evidence_fingerprint(recovered_evidence) !=
                    exported_snapshot_evidence_fingerprint(export_result.evidence)):
                _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
            advance("RESTORE_COMPLETED", self.restore_tool, (export_result.dump_sha256,))
            restored = self.restore_adapter.qualify(
                recovered_dump=recovered_candidates[0],
                baseline=recovered_baseline,
                source_runtime=runtime,
            )
            restored_hash = restored_invariants_fingerprint(restored.restored_invariants)
            advance("RESTORE_QUALIFIED", self.restore_tool, (restored_hash,))
            advance("RUNTIME_QUALIFIED", self.restore_tool, (
                runtime.source_runtime_fingerprint, runtime.source_system_runtime_fingerprint,
            ))
            advance("DB_RUNTIME_COMPATIBLE", self.restore_tool, (
                restored.restored_invariants.compatibility_fingerprint,
            ))

            # Disposable data must be gone before either authority artifact exists.
            for path in (payload, restored_root):
                try:
                    shutil.rmtree(path)
                except OSError:
                    _raise(FailureCode.ROLLBACK_RESTORE_FAILED)

            metadata = P3DRollbackMetadataV1.from_mapping({
                **P3DRollbackMetadataV1.FIXED,
                "SNAPSHOT_ID": snapshot.snapshot_id,
                "SNAPSHOT_TAGS": list(GATE_A_TAGS),
                "DUMP_SHA256": export_result.dump_sha256,
                "BASELINE_COUNTS_SHA256": baseline_counts_fingerprint(export_result.baseline),
                "EXPORTED_SNAPSHOT_EVIDENCE_HASH": exported_snapshot_evidence_fingerprint(
                    export_result.evidence
                ),
                "SOURCE_SHA": runtime.source_sha,
                "SOURCE_RELEASE_SHA": runtime.source_sha,
                "SOURCE_RELEASE_FINGERPRINT": runtime.source_release_fingerprint,
                "SOURCE_RUNTIME_FINGERPRINT": runtime.source_runtime_fingerprint,
                "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": runtime.source_system_runtime_fingerprint,
                "TARGET_CANDIDATE_SHA": context.candidate_sha,
                "SOURCE_DB_FINGERPRINT": export_result.baseline.source_db_fingerprint,
                "P3C_CONTEXT_FINGERPRINT": context.p3c_context_fingerprint,
                "P3C_SOAK_EVIDENCE_SHA256": context.p3c_soak_evidence_sha256,
                "RESTORED_INVARIANTS_SHA256": restored_hash,
                "BACKUP_FS_UUID": snapshot.backup_fs_uuid,
                "RESTIC_REPOSITORY": snapshot.repository_identity,
                "QUALIFIED_AT_UTC": context.qualified_at_utc,
                **{f"EXPORT_{key}": value for key, value in self.export_tool.to_mapping().items()},
                **{f"RESTORE_{key}": value for key, value in self.restore_tool.to_mapping().items()},
            })
            metadata_hash = rollback_metadata_fingerprint(metadata)
            release_pin = RollbackReleasePinV1.from_mapping({
                "PIN_VERSION": "1",
                "SNAPSHOT_ID": snapshot.snapshot_id,
                "SOURCE_RELEASE_SHA": runtime.source_sha,
                "SOURCE_RELEASE_FINGERPRINT": runtime.source_release_fingerprint,
                "SOURCE_RUNTIME_FINGERPRINT": runtime.source_runtime_fingerprint,
                "SOURCE_SYSTEM_RUNTIME_FINGERPRINT": runtime.source_system_runtime_fingerprint,
                "ROLLBACK_METADATA_SHA256": metadata_hash,
                "QUALIFIED_AT_UTC": context.qualified_at_utc,
                "STATE": ReleasePinState.ACTIVE.value,
            })
            validate_rollback_release_pin(metadata, release_pin)
            try:
                atomic_create_no_replace(
                    authority_root / f"rollback-release-pin-{snapshot.snapshot_id}.json",
                    canonical_json_bytes(release_pin.to_mapping()) + b"\n",
                    policy=self.persistence_policy,
                )
            except PreparationContractError:
                _raise(FailureCode.ROLLBACK_PIN_FAILED)
            advance("SOURCE_RELEASE_PINNED", self.restore_tool, (
                metadata_hash, runtime.source_release_fingerprint,
            ))
            try:
                atomic_create_no_replace(
                    authority_root / "p3d-pre-enrichment.env",
                    serialize_metadata(metadata),
                    policy=self.persistence_policy,
                )
            except PreparationContractError:
                _raise(FailureCode.ROLLBACK_METADATA_CONFLICT)
            advance("METADATA_COMMITTED", self.restore_tool, (metadata_hash,))
            advance("COMPLETE", self.restore_tool, (metadata_hash,))
            return RollbackQualificationResult(metadata, metadata_hash, release_pin, state, events)
        except Exception as error:
            if state.phase not in {"COMPLETE", "FAILED"}:
                code = error.code if isinstance(error, RollbackQualificationError) else (
                    FailureCode.ROLLBACK_BACKUP_FAILED
                    if snapshot_created else FailureCode.ROLLBACK_SOURCE_INVALID
                )
                tool = self.restore_tool if state.phase in {
                    "BACKUP_SNAPSHOT_CREATED", "RESTORE_STARTED", "RESTORE_COMPLETED",
                    "RESTORE_QUALIFIED", "RUNTIME_QUALIFIED", "DB_RUNTIME_COMPATIBLE",
                    "SOURCE_RELEASE_PINNED", "METADATA_COMMITTED",
                } else self.export_tool
                try:
                    state, events = journal_store.advance(
                        state, events, "FAILED", timestamp=timestamp, tool=tool,
                        evidence_fingerprints=(), failure_code=code,
                    )
                except Exception:
                    pass
            if isinstance(error, RollbackQualificationError):
                raise
            _raise(FailureCode.ROLLBACK_SOURCE_INVALID)
        finally:
            cleanup_failed = False
            for path in (operation_root / "payload", operation_root / "restored"):
                if path.exists():
                    try:
                        shutil.rmtree(path)
                    except OSError:
                        cleanup_failed = True
            if cleanup_failed:
                _raise(FailureCode.ROLLBACK_RESTORE_FAILED)


class Postgres16RestoreQualificationAdapter:
    """Create, qualify and always drop one loopback ``*_test`` database."""

    def __init__(
        self,
        *,
        admin_target: PostgresTarget,
        dump_adapter: DumpAdapter,
        baseline_collector: BaselineCollector,
    ) -> None:
        admin_target.validate_disposable()
        self.admin_target = admin_target
        self.dump_adapter = dump_adapter
        self.baseline_collector = baseline_collector

    def qualify(
        self,
        *,
        recovered_dump: Path,
        baseline: RollbackBaselineEvidenceV1,
        source_runtime: SourceRuntimeEvidenceV1,
    ) -> RestoreQualificationResult:
        identity = uuid4().hex
        database = f"pdi_p3d_restore_{identity}_test"
        owner_role = f"pdi_p3d_restore_owner_{identity}_test"
        target = replace(self.admin_target, database=database)
        admin_database = "postgres"
        try:
            source_runtime.validate()
            with psycopg.connect(self.admin_target.conninfo(database=admin_database), autocommit=True) as connection:
                connection.execute(
                    sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(owner_role))
                )
                connection.execute(
                    sql.SQL("CREATE DATABASE {} OWNER {}").format(
                        sql.Identifier(database), sql.Identifier(owner_role),
                    )
                )
            self.dump_adapter.restore(dump_path=recovered_dump, target=target)
            with psycopg.connect(target.conninfo()) as connection:
                connection.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                if str(connection.execute("SHOW transaction_read_only").fetchone()[0]).lower() != "on":
                    _raise(FailureCode.ROLLBACK_COMPATIBILITY_FAILED)
                restored = self.baseline_collector.collect(connection)
                if (baseline_counts_fingerprint(restored) != baseline_counts_fingerprint(baseline) or
                        restored.alembic_revision != baseline.alembic_revision or
                        restored.alembic_revision != source_runtime.expected_alembic or
                        restored.postgres_major != baseline.postgres_major or
                        restored.provider_states != baseline.provider_states or
                        restored.source_provider_counts != baseline.source_provider_counts or
                        restored.null_scope_sources != baseline.null_scope_sources or
                        restored.duplicate_scoped_sources != baseline.duplicate_scoped_sources or
                        restored.sync_state_rows != baseline.sync_state_rows or
                        restored.initialized_sync_state_rows != baseline.initialized_sync_state_rows or
                        restored.reconciliation_required_rows != baseline.reconciliation_required_rows or
                        restored.null_external_ids != baseline.null_external_ids or
                        restored.empty_external_ids != baseline.empty_external_ids or
                        restored.missing_blob_links != baseline.missing_blob_links or
                        restored.scope_sync_state_keys != baseline.scope_sync_state_keys or
                        restored.legacy_sync_state_keys != baseline.legacy_sync_state_keys or
                        restored.critical_constraints != baseline.critical_constraints):
                    _raise(FailureCode.ROLLBACK_COMPATIBILITY_FAILED)
                read_smoke = connection.execute(
                    "SELECT (SELECT count(*) FROM assets), "
                    "(SELECT count(*) FROM observation_scopes), "
                    "(SELECT count(*) FROM observation_scope_sync_state)"
                ).fetchone()
                compatibility = contract_fingerprint({
                    "source_runtime_fingerprint": source_runtime.source_runtime_fingerprint,
                    "migration_tree_fingerprint": source_runtime.migration_tree_fingerprint,
                    "source_alembic_head": source_runtime.expected_alembic,
                    "alembic": restored.alembic_revision,
                    "postgres_major": restored.postgres_major,
                    "read_smoke": list(read_smoke),
                    "transaction_read_only": True,
                })
                connection.execute("ROLLBACK")
            evidence = RestoredInvariantsEvidenceV1(
                baseline_evidence_fingerprint(baseline),
                baseline_evidence_fingerprint(restored),
                True,
                True,
                compatibility,
            )
            evidence.to_mapping()
            return RestoreQualificationResult(evidence)
        except RollbackQualificationError:
            raise
        except Exception:
            _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
        finally:
            cleanup_failed = False
            try:
                with psycopg.connect(
                    self.admin_target.conninfo(database=admin_database), autocommit=True,
                ) as connection:
                    connection.execute(
                        sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                            sql.Identifier(database)
                        )
                    )
                    connection.execute(
                        sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(owner_role))
                    )
            except Exception:
                cleanup_failed = True
            if cleanup_failed:
                _raise(FailureCode.ROLLBACK_RESTORE_FAILED)
