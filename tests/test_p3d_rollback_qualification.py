from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from uuid import UUID

import pytest

from pdi.production_ops import p3d_rollback_qualification as module
from pdi.production_ops.p3d_preparation_contracts import (
    AtomicCreatePolicyV1,
    FailureCode,
    OperatorToolIdentity,
    PreparationContractError,
    PreparationGate,
    RuntimeDistributionEntryV1,
    SourceFileFingerprintEntryV1,
    ToolName,
    canonical_json_bytes,
    validate_preparation_journal_chain,
)
from pdi.production_ops.p3d_rollback_qualification import (
    CANONICAL_BASELINE_TABLES,
    BackupSnapshot,
    CountEntryV1,
    ExportedSnapshotCoordinator,
    FilesystemBackupAdapter,
    GateAJournalStore,
    Postgres16RestoreQualificationAdapter,
    PostgresCommandAdapter,
    PostgresTarget,
    ProviderStateEntryV1,
    QualificationContext,
    ReleaseFilesystemFacts,
    ResticBackupAdapter,
    RootControlledReleaseFactsReader,
    RestoreQualificationResult,
    RestoredInvariantsEvidenceV1,
    RollbackBaselineEvidenceV1,
    RollbackQualificationError,
    RollbackQualificationOrchestrator,
    SourceSystemRuntimeEvidenceV1,
    SourceRuntimeQualifier,
    SystemRuntimeFileEvidenceV1,
    baseline_counts_fingerprint,
    baseline_evidence_fingerprint,
    exported_snapshot_evidence_fingerprint,
    parse_metadata,
    restored_invariants_fingerprint,
    serialize_metadata,
    source_system_runtime_fingerprint,
)


CANDIDATE = "a" * 40
SOURCE = "b" * 40
EXPORT_TOOL_SOURCE = "c" * 40
RESTORE_TOOL_SOURCE = "d" * 40
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
WHEN = "2026-09-23T01:02:03Z"
BACKUP_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def tool(name: ToolName, source: str) -> OperatorToolIdentity:
    return OperatorToolIdentity.from_mapping({
        "TOOL_NAME": name.value,
        "TOOL_VERSION": "1.0.0",
        "TOOL_ARTIFACT_SHA256": H1,
        "TOOL_SOURCE_SHA": source,
    })


EXPORT_TOOL = tool(ToolName.BACKUP_EXPORT, EXPORT_TOOL_SOURCE)
RESTORE_TOOL = tool(ToolName.RESTORE_QUALIFY, RESTORE_TOOL_SOURCE)


def baseline(*, asset_count: int = 4) -> RollbackBaselineEvidenceV1:
    evidence = RollbackBaselineEvidenceV1(
        "e5a7b9d1f324",
        16,
        tuple(sorted(
            CountEntryV1(name, asset_count if name == "assets" else 1)
            for name in CANONICAL_BASELINE_TABLES
        )),
        tuple(sorted((
            ProviderStateEntryV1("nextcloud", True, 1, 1, 1, 1),
            ProviderStateEntryV1("immich", True, 1, 1, 1, 1),
            ProviderStateEntryV1("gmail", False, 0, 0, 1, 0),
            ProviderStateEntryV1("integration-test", False, 0, 0, 1, 0),
        ))),
        tuple(sorted(CountEntryV1(name, 1) for name in (
            "nextcloud", "immich", "gmail", "integration-test",
        ))),
        0,
        0,
        2,
        2,
        0,
        0,
        0,
        0,
        module.EXPECTED_SCOPE_SYNC_STATE_KEYS,
        module.EXPECTED_SCOPE_SYNC_STATE_KEYS,
        tuple(sorted(module.EXPECTED_CRITICAL_CONSTRAINTS)),
        H2,
    )
    evidence.validate()
    return evidence


class FakeFactsReader:
    def __init__(
        self,
        *,
        source: str = SOURCE,
        clean: bool = True,
        import_smoke: bool = True,
        migration_tree_fingerprint: str = H4,
        source_alembic_head: str = module.EXPECTED_ALEMBIC,
    ):
        self.source = source
        self.clean = clean
        self.import_smoke = import_smoke
        self.migration_tree_fingerprint = migration_tree_fingerprint
        self.source_alembic_head = source_alembic_head

    def read(self, release_path: Path) -> ReleaseFilesystemFacts:
        return ReleaseFilesystemFacts(
            Path("/opt/pdi/releases") / self.source,
            self.source,
            self.clean,
            (
                SourceFileFingerprintEntryV1("src", "directory", "0755", 0, 0),
                SourceFileFingerprintEntryV1("src/pdi.py", "file", "0644", 0, 0, H1),
            ),
            release_path / ".venv/bin/python",
            "3.13.7",
            "cpython-313",
            H2,
            (RuntimeDistributionEntryV1("pdi", "1.0.0", H3),),
            self.migration_tree_fingerprint,
            self.source_alembic_head,
            self.import_smoke,
        )


def source_qualifier(**kwargs) -> SourceRuntimeQualifier:
    return SourceRuntimeQualifier(FakeFactsReader(**kwargs))


class FakeResult:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return (self.value,)


class FakeSnapshotConnection:
    def __init__(
        self, name: str, calls: list[str], *, fail_export: bool = False,
        fail_snapshot_import: bool = False,
    ):
        self.name = name
        self.calls = calls
        self.fail_export = fail_export
        self.fail_snapshot_import = fail_snapshot_import
        self.closed = False

    def execute(self, query, params=None):
        rendered = str(query)
        self.calls.append(f"{self.name}:{rendered}")
        if rendered == "SELECT pg_export_snapshot()":
            if self.fail_export:
                raise RuntimeError("synthetic")
            return FakeResult("00000001-00000001-1")
        if rendered.startswith("SET TRANSACTION SNAPSHOT") and self.fail_snapshot_import:
            raise RuntimeError("synthetic")
        if rendered == "SHOW transaction_read_only":
            return FakeResult("on")
        return FakeResult(None)

    def close(self):
        self.closed = True
        self.calls.append(f"{self.name}:CLOSE")


class FakeBaselineCollector:
    def __init__(
        self, calls: list[str], value: RollbackBaselineEvidenceV1 | None = None,
        *, fail: bool = False,
    ):
        self.calls = calls
        self.value = value or baseline()
        self.fail = fail

    def collect(self, connection) -> RollbackBaselineEvidenceV1:
        self.calls.append("BASELINE_QUERY")
        if self.fail:
            raise RollbackQualificationError(FailureCode.ROLLBACK_RUNTIME_INVALID)
        return self.value


class FakeDumpAdapter:
    def __init__(self, calls: list[str], *, fail_dump: bool = False):
        self.calls = calls
        self.fail_dump = fail_dump
        self.dump_snapshot = None
        self.restore_calls = []

    def dump(self, *, snapshot_id: str, output_path: Path) -> None:
        self.calls.append("PG_DUMP")
        self.dump_snapshot = snapshot_id
        if self.fail_dump:
            raise RollbackQualificationError(FailureCode.ROLLBACK_DUMP_FAILED)
        output_path.write_bytes(b"synthetic-custom-archive")

    def restore(self, *, dump_path: Path, target: PostgresTarget) -> None:
        self.restore_calls.append((dump_path, target))


def snapshot_coordinator(
    tmp_path: Path, *, fail_dump: bool = False, fail_export: bool = False,
    fail_snapshot_import: bool = False, fail_baseline: bool = False,
    fail_importer_connect: bool = False,
):
    calls: list[str] = []
    exporter = FakeSnapshotConnection("EXPORTER", calls, fail_export=fail_export)
    importer = FakeSnapshotConnection(
        "IMPORTER", calls, fail_snapshot_import=fail_snapshot_import,
    )
    connection_count = 0

    def connect():
        nonlocal connection_count
        connection_count += 1
        if connection_count == 2 and fail_importer_connect:
            raise RuntimeError("synthetic")
        return exporter if connection_count == 1 else importer
    dump = FakeDumpAdapter(calls, fail_dump=fail_dump)
    lifecycle = []
    coordinator = ExportedSnapshotCoordinator(
        connect=connect,
        baseline_collector=FakeBaselineCollector(calls, fail=fail_baseline),
        dump_adapter=dump,
        lifecycle=lifecycle.append,
    )
    return coordinator, calls, lifecycle, dump


class FakeRestoreAdapter:
    def __init__(self, *, failure: FailureCode | None = None, counts_match: bool = True):
        self.failure = failure
        self.counts_match = counts_match
        self.calls = []

    def qualify(self, *, recovered_dump: Path, baseline, source_runtime):
        self.calls.append((recovered_dump, baseline, source_runtime))
        if self.failure is not None:
            raise RollbackQualificationError(self.failure)
        evidence = RestoredInvariantsEvidenceV1(
            baseline_evidence_fingerprint(baseline),
            baseline_evidence_fingerprint(baseline),
            self.counts_match,
            True,
            H4,
        )
        evidence.to_mapping()
        return RestoreQualificationResult(evidence)


class FailingBackupAdapter:
    def create_snapshot(self, payload_dir: Path):
        raise RollbackQualificationError(FailureCode.ROLLBACK_BACKUP_FAILED)

    def restore_snapshot(self, snapshot_id: str, destination: Path):
        raise AssertionError("restore must not run")


class TamperingBackupAdapter:
    def __init__(self, delegate: FilesystemBackupAdapter, filename: str, payload: bytes):
        self.delegate = delegate
        self.filename = filename
        self.payload = payload

    def create_snapshot(self, payload_dir: Path):
        return self.delegate.create_snapshot(payload_dir)

    def restore_snapshot(self, snapshot_id: str, destination: Path):
        result = self.delegate.restore_snapshot(snapshot_id, destination)
        target = next(result.rglob(self.filename), result / self.filename)
        target.write_bytes(self.payload)
        return result


class WrongBackupIdentityAdapter:
    def __init__(self, delegate: FilesystemBackupAdapter):
        self.delegate = delegate

    def create_snapshot(self, payload_dir: Path):
        snapshot = self.delegate.create_snapshot(payload_dir)
        return replace(snapshot, backup_fs_uuid="bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")

    def restore_snapshot(self, snapshot_id: str, destination: Path):
        raise AssertionError("identity mismatch must fail before restore")


def context() -> QualificationContext:
    return QualificationContext(CANDIDATE, SOURCE, H1, H2, BACKUP_UUID, WHEN)


def policy(tmp_path: Path) -> AtomicCreatePolicyV1:
    tmp_path.chmod(0o700)
    return AtomicCreatePolicyV1(
        owner_uid=os.getuid(), owner_gid=os.getgid(), mode=0o600, trust_root=tmp_path,
    )


def make_orchestrator(
    tmp_path: Path,
    *,
    qualifier: SourceRuntimeQualifier | None = None,
    backup=None,
    restore=None,
    fail_dump: bool = False,
    fail_export: bool = False,
    fail_snapshot_import: bool = False,
    fail_baseline: bool = False,
    fail_importer_connect: bool = False,
    export_tool: OperatorToolIdentity = EXPORT_TOOL,
    restore_tool: OperatorToolIdentity = RESTORE_TOOL,
):
    repository = tmp_path / "repository"
    backup = backup or FilesystemBackupAdapter(
        repository, disposable_root=tmp_path, backup_fs_uuid=BACKUP_UUID,
    )
    restore = restore or FakeRestoreAdapter()
    coordinators = []

    def factory(_lifecycle):
        coordinator, calls, lifecycle, dump = snapshot_coordinator(
            tmp_path, fail_dump=fail_dump, fail_export=fail_export,
            fail_snapshot_import=fail_snapshot_import,
            fail_baseline=fail_baseline,
            fail_importer_connect=fail_importer_connect,
        )
        coordinators.append((calls, lifecycle, dump))
        return coordinator

    orchestrator = RollbackQualificationOrchestrator(
        disposable_root=tmp_path,
        source_qualifier=qualifier or source_qualifier(),
        snapshot_coordinator_factory=factory,
        backup_adapter=backup,
        restore_adapter=restore,
        export_tool=export_tool,
        restore_tool=restore_tool,
        persistence_policy=policy(tmp_path),
    )
    return orchestrator, coordinators, backup, restore


def operation_authority_root(tmp_path: Path) -> Path:
    operations = tuple(tmp_path.glob("operation-*"))
    assert len(operations) == 1
    return operations[0] / "authority"


def latest_state_mapping(tmp_path: Path) -> dict:
    root = operation_authority_root(tmp_path)
    path = sorted(root.glob("state-*.json"))[-1]
    return json.loads(path.read_text())


def test_source_runtime_qualification_binds_actual_facts() -> None:
    evidence = source_qualifier().qualify(SOURCE)
    assert evidence.source_sha == SOURCE
    assert evidence.expected_alembic == module.EXPECTED_ALEMBIC
    assert evidence.source_release_fingerprint != evidence.source_runtime_fingerprint
    evidence.validate()


def test_source_runtime_fingerprint_binds_migration_tree_with_same_head() -> None:
    first = source_qualifier(migration_tree_fingerprint=H3).qualify(SOURCE)
    second = source_qualifier(migration_tree_fingerprint=H4).qualify(SOURCE)
    assert first.expected_alembic == second.expected_alembic == module.EXPECTED_ALEMBIC
    assert first.source_runtime_fingerprint != second.source_runtime_fingerprint


def test_source_runtime_refuses_actual_alembic_head_mismatch() -> None:
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        source_qualifier(source_alembic_head="differenthead").qualify(SOURCE)


@pytest.mark.parametrize("heads", [[], [module.EXPECTED_ALEMBIC, "otherhead"]])
def test_source_alembic_discovery_requires_exactly_one_head(heads: list[str]) -> None:
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        module._single_source_alembic_head(json.dumps(heads))


def test_root_controlled_release_reader_scans_runtime_with_fixed_environments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = tmp_path / "opt/pdi/releases" / SOURCE
    for relative in (
        "scripts", "src/pdi", ".venv/bin", ".venv/lib/python3.13/site-packages/demo.dist-info",
        "migrations/versions", ".git",
    ):
        (release / relative).mkdir(parents=True, exist_ok=True)
    for relative in (
        "pyproject.toml", "alembic.ini", "scripts/mu13_p3c_cutover.py",
        "src/pdi/__init__.py", "src/pdi/scoped_operational.py", "migrations/versions/a.py",
    ):
        (release / relative).write_text("synthetic\n", encoding="utf-8")
    (release / ".git/ignored-authority").write_text("unstable\n", encoding="utf-8")
    dist_info = release / ".venv/lib/python3.13/site-packages/demo.dist-info"
    (dist_info / "METADATA").write_text("Name: Demo_Package\nVersion: 1.2.3\n", encoding="utf-8")
    (dist_info / "RECORD").write_text("demo.py,,\n", encoding="utf-8")
    external_runtime_root = tmp_path / "trusted-system-runtime"
    python_target = external_runtime_root / "bin/python3.13"
    python_target.parent.mkdir(parents=True)
    python_target.write_bytes(b"synthetic-python-binary")
    python_target.chmod(0o755)
    (release / ".venv/bin/python").symlink_to(python_target)
    release.chmod(0o755)
    for path in release.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)
    current = tmp_path / "opt/pdi/current"
    current.symlink_to(release)
    os_release = tmp_path / "etc/os-release"
    os_release.parent.mkdir(parents=True)
    os_release.write_text('ID="synthetic"\nVERSION_ID="1.0"\n', encoding="utf-8")
    os_release.chmod(0o644)

    original_lstat = Path.lstat

    def root_owned_lstat(path: Path):
        value = original_lstat(path)
        return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0)

    monkeypatch.setattr(Path, "lstat", root_owned_lstat)
    monkeypatch.setattr(
        RootControlledReleaseFactsReader,
        "_root_controlled",
        staticmethod(lambda _path, *, stop: True),
    )
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if "rev-parse" in argv:
            stdout = SOURCE + "\n"
        elif "status" in argv:
            stdout = ""
        elif argv[0] == "/usr/bin/ldd":
            stdout = "statically linked\n"
        elif argv[0] == "/usr/bin/dpkg":
            stdout = "amd64\n"
        elif argv[0] == "/usr/bin/dpkg-query" and "--search" in argv:
            stdout = f"python3.13-minimal: {argv[-1]}\n"
        elif argv[0] == "/usr/bin/dpkg-query" and "--show" in argv:
            stdout = "3.13.7-1\n"
        elif "ScriptDirectory" in argv[-1]:
            stdout = json.dumps([module.EXPECTED_ALEMBIC]) + "\n"
        else:
            stdout = json.dumps({
                "version": "3.13.7",
                "abi": "cpython-313",
                "implementation": "CPython",
                "platform": "linux",
            }) + "\n"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_SOURCE_INVALID.value):
        RootControlledReleaseFactsReader(
            current_path=current,
            approved_external_symlink_roots=(tmp_path / "unapproved-external-root",),
            os_release_path=os_release,
            runner=runner,
        ).read(release)

    python_target.chmod(0o777)
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        RootControlledReleaseFactsReader(
            current_path=current,
            approved_external_symlink_roots=(external_runtime_root,),
            os_release_path=os_release,
            runner=runner,
        ).read(release)
    python_target.chmod(0o755)
    calls.clear()

    facts = RootControlledReleaseFactsReader(
        current_path=current,
        approved_external_symlink_roots=(external_runtime_root,),
        os_release_path=os_release,
        runner=runner,
    ).read(release)
    assert facts.git_head == SOURCE
    assert facts.git_clean is True
    assert all(not entry.relative_path.startswith(".git") for entry in facts.entries)
    assert any(entry.relative_path == ".venv/bin/python" for entry in facts.entries)
    assert facts.source_alembic_head == module.EXPECTED_ALEMBIC
    assert facts.system_runtime_fingerprint
    git_calls = [call for call in calls if call[0][0] == "/usr/bin/git"]
    assert all(call[1]["env"] == {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0",
    } for call in git_calls)
    system_calls = [
        call for call in calls
        if call[0][0] in {"/usr/bin/ldd", "/usr/bin/dpkg", "/usr/bin/dpkg-query"}
    ]
    assert system_calls
    assert all(call[1]["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
               for call in system_calls)
    alembic_calls = [call for call in calls if "ScriptDirectory" in call[0][-1]]
    assert len(alembic_calls) == 1
    assert alembic_calls[0][1]["env"] == {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(release / "src"),
    }
    assert facts.distributions[0].name == "demo-package"


def system_runtime_entry(**changes) -> SystemRuntimeFileEvidenceV1:
    values = {
        "path": "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "resolved_path": "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "file_sha256": H1,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
        "package_name": "libc6:amd64",
        "package_version": "2.39-0ubuntu8.6",
    }
    values.update(changes)
    return SystemRuntimeFileEvidenceV1(**values)


def system_runtime_evidence(
    *entries: SystemRuntimeFileEvidenceV1, os_version: str = "24.04",
) -> SourceSystemRuntimeEvidenceV1:
    return SourceSystemRuntimeEvidenceV1(
        "ubuntu", os_version, "amd64", "CPython", "3.13.7", "cpython-313",
        "linux", tuple(entries or (system_runtime_entry(),)),
    )


def test_system_runtime_fingerprint_is_deterministic_and_binds_authority() -> None:
    python = system_runtime_entry(
        path="/usr/bin/python3.13", resolved_path="/usr/bin/python3.13",
        file_sha256=H2, package_name="python3.13-minimal", package_version="3.13.7-1",
    )
    library = system_runtime_entry()
    first = source_system_runtime_fingerprint(system_runtime_evidence(python, library))
    second = source_system_runtime_fingerprint(system_runtime_evidence(library, python))
    assert first == second
    assert first != source_system_runtime_fingerprint(system_runtime_evidence(
        python, replace(library, file_sha256=H3),
    ))
    assert first != source_system_runtime_fingerprint(system_runtime_evidence(
        python, replace(library, package_version="2.40-1"),
    ))
    assert first != source_system_runtime_fingerprint(system_runtime_evidence(
        python, library, os_version="24.10",
    ))


@pytest.mark.parametrize(
    "entry",
    [
        system_runtime_entry(package_name="unknown package"),
        system_runtime_entry(mode="0775"),
        system_runtime_entry(uid=1000),
        system_runtime_entry(gid=1000),
    ],
)
def test_system_runtime_entries_fail_closed(entry: SystemRuntimeFileEvidenceV1) -> None:
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        source_system_runtime_fingerprint(system_runtime_evidence(entry))


def test_native_dependency_discovery_refuses_missing_and_unowned_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        RootControlledReleaseFactsReader._parse_ldd_output(
            "libmissing.so.1 => not found\n"
        )

    library = tmp_path / "libsynthetic.so.1"
    library.write_bytes(b"synthetic-native-library")
    library.chmod(0o755)
    original_lstat = Path.lstat

    def root_owned_lstat(path: Path):
        value = original_lstat(path)
        return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0)

    monkeypatch.setattr(Path, "lstat", root_owned_lstat)
    monkeypatch.setattr(
        RootControlledReleaseFactsReader,
        "_root_controlled",
        staticmethod(lambda _path, *, stop: True),
    )

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "not package-owned")

    reader = RootControlledReleaseFactsReader(runner=runner)
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        reader._system_runtime_entry(library, cwd=tmp_path)


@pytest.mark.parametrize(
    "reader",
    [
        FakeFactsReader(source=CANDIDATE),
        FakeFactsReader(clean=False),
        FakeFactsReader(import_smoke=False),
    ],
)
def test_source_runtime_qualification_fails_closed(reader) -> None:
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_SOURCE_INVALID.value):
        SourceRuntimeQualifier(reader).qualify(SOURCE)


def test_baseline_schema_is_strict_and_canonical() -> None:
    value = baseline()
    parsed = RollbackBaselineEvidenceV1.from_mapping(value.to_mapping())
    assert parsed == value
    assert baseline_counts_fingerprint(parsed) == baseline_counts_fingerprint(value)
    invalid = value.to_mapping()
    invalid["unexpected"] = 1
    with pytest.raises(RollbackQualificationError):
        RollbackBaselineEvidenceV1.from_mapping(invalid)
    duplicate = value.to_mapping()
    duplicate["provider_states"].append(duplicate["provider_states"][0])
    with pytest.raises(RollbackQualificationError):
        RollbackBaselineEvidenceV1.from_mapping(duplicate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: replace(value, alembic_revision="wrong"),
        lambda value: replace(value, postgres_major=15),
        lambda value: replace(value, null_scope_sources=1),
        lambda value: replace(value, duplicate_scoped_sources=1),
        lambda value: replace(value, sync_state_rows=1),
        lambda value: replace(value, reconciliation_required_rows=1),
        lambda value: replace(value, critical_constraints=()),
    ],
)
def test_baseline_invariants_fail_closed(mutation) -> None:
    with pytest.raises(RollbackQualificationError):
        mutation(baseline()).validate()


def test_exported_snapshot_order_and_exporter_lifetime(tmp_path: Path) -> None:
    coordinator, calls, lifecycle, dump = snapshot_coordinator(tmp_path)
    runtime = source_qualifier().qualify(SOURCE)
    phases = []
    result = coordinator.export(
        operation_id="11111111-2222-4333-8444-555555555555",
        output_path=tmp_path / "pdi-core.dump",
        source_runtime=runtime,
        on_snapshot_exported=lambda: phases.append("SNAPSHOT_EXPORTED"),
        on_dump_completed=lambda: phases.append("DUMP_COMPLETED"),
    )
    assert calls.index("IMPORTER:SET TRANSACTION SNAPSHOT '00000001-00000001-1'") < calls.index(
        "BASELINE_QUERY"
    )
    assert calls.index("IMPORTER:SHOW transaction_read_only") < calls.index("BASELINE_QUERY")
    assert lifecycle.index("EVIDENCE_HASHED") < lifecycle.index("EXPORTER_ROLLBACK")
    assert dump.dump_snapshot == "00000001-00000001-1"
    assert phases == ["SNAPSHOT_EXPORTED", "DUMP_COMPLETED"]
    assert result.dump_sha256 == module._sha256_file(result.dump_path)
    assert exported_snapshot_evidence_fingerprint(result.evidence)


@pytest.mark.parametrize(
    ("options", "code"),
    [
        ({"fail_export": True}, FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED),
        ({"fail_dump": True}, FailureCode.ROLLBACK_DUMP_FAILED),
        ({"fail_snapshot_import": True}, FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED),
        ({"fail_importer_connect": True}, FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED),
        ({"fail_baseline": True}, FailureCode.ROLLBACK_RUNTIME_INVALID),
    ],
)
def test_exported_snapshot_failures_close_exporter(
    tmp_path: Path, options: dict[str, bool], code: FailureCode,
) -> None:
    coordinator, _calls, lifecycle, _dump = snapshot_coordinator(tmp_path, **options)
    with pytest.raises(RollbackQualificationError, match=code.value):
        coordinator.export(
            operation_id="11111111-2222-4333-8444-555555555555",
            output_path=tmp_path / "pdi-core.dump",
            source_runtime=source_qualifier().qualify(SOURCE),
            on_snapshot_exported=lambda: None,
            on_dump_completed=lambda: None,
        )
    assert "EXPORTER_ROLLBACK" in lifecycle


def test_postgres_command_adapter_uses_fixed_argv_and_environment(tmp_path: Path) -> None:
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, "pg_dump (PostgreSQL) 16.10\n", "")
        if "--file" in argv:
            Path(argv[argv.index("--file") + 1]).write_bytes(b"dump")
        return subprocess.CompletedProcess(argv, 0, "", "")

    target = PostgresTarget("127.0.0.1", 5432, "source_test", "user", "password")
    adapter = PostgresCommandAdapter(
        target,
        disposable_root=tmp_path,
        pg_dump_path=Path("/usr/bin/pg_dump"),
        pg_restore_path=Path("/usr/bin/pg_restore"),
        runner=runner,
    )
    output = tmp_path / "pdi-core.dump"
    adapter.dump(snapshot_id="00000001-00000002-1", output_path=output)
    adapter.restore(dump_path=output, target=replace(target, database="restore_test"))
    operation_calls = [item for item in calls if "--version" not in item[0]]
    assert "--snapshot=00000001-00000002-1" in operation_calls[0][0]
    assert "--no-owner" in operation_calls[0][0] and "--no-acl" in operation_calls[0][0]
    assert all("password" not in argument for call, _kwargs in calls for argument in call)
    assert all(kwargs["env"] == {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PGPASSWORD": "password",
    } for _argv, kwargs in operation_calls)
    assert all(kwargs["shell"] is False for _argv, kwargs in calls)


def test_postgres_command_adapter_refuses_non_v16_tools(tmp_path: Path) -> None:
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, "pg_dump (PostgreSQL) 15.12\n", "")

    adapter = PostgresCommandAdapter(
        PostgresTarget("127.0.0.1", 5432, "source_test", "user", "password"),
        disposable_root=tmp_path,
        runner=runner,
    )
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RUNTIME_INVALID.value):
        adapter.dump(snapshot_id="00000001-00000002-1", output_path=tmp_path / "dump")


class FakeRestoreQueryResult:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeRestoreConnection:
    def __init__(self, calls: list[str]):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        return False

    def execute(self, query, params=None):
        rendered = query.as_string() if hasattr(query, "as_string") else str(query)
        self.calls.append(rendered)
        if rendered == "SHOW transaction_read_only":
            return FakeRestoreQueryResult(("on",))
        if rendered.startswith("SELECT (SELECT count(*) FROM assets)"):
            return FakeRestoreQueryResult((4, 4, 2))
        return FakeRestoreQueryResult((None,))


def postgres_restore_adapter(
    monkeypatch: pytest.MonkeyPatch,
    *,
    restored: RollbackBaselineEvidenceV1 | None = None,
    fail_restore: bool = False,
):
    sql_calls: list[str] = []
    connection_calls = []

    def connect(conninfo, **kwargs):
        connection_calls.append((conninfo, kwargs))
        return FakeRestoreConnection(sql_calls)

    monkeypatch.setattr(module.psycopg, "connect", connect)
    dump = FakeDumpAdapter([])
    if fail_restore:
        def restore_failure(*, dump_path: Path, target: PostgresTarget) -> None:
            dump.restore_calls.append((dump_path, target))
            raise RollbackQualificationError(FailureCode.ROLLBACK_RESTORE_FAILED)
        dump.restore = restore_failure
    collector = FakeBaselineCollector([], value=restored or baseline())
    admin = PostgresTarget(
        "127.0.0.1", 5432, "pdi_ci_test", "pdi_ci", "injected-admin-password",
    )
    adapter = Postgres16RestoreQualificationAdapter(
        admin_target=admin,
        dump_adapter=dump,
        baseline_collector=collector,
    )
    return adapter, admin, dump, sql_calls, connection_calls


def test_restore_adapter_uses_nologin_owner_and_injected_disposable_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, admin, dump, sql_calls, _connections = postgres_restore_adapter(monkeypatch)
    result = adapter.qualify(
        recovered_dump=tmp_path / "pdi-core.dump",
        baseline=baseline(),
        source_runtime=source_qualifier().qualify(SOURCE),
    )
    assert result.restored_invariants.counts_match is True
    assert any(call.startswith('CREATE ROLE "pdi_p3d_restore_owner_') and call.endswith('" NOLOGIN')
               for call in sql_calls)
    assert not any("PASSWORD" in call or " LOGIN " in call for call in sql_calls)
    assert any(call.startswith('DROP DATABASE IF EXISTS "pdi_p3d_restore_') for call in sql_calls)
    assert any(call.startswith('DROP ROLE IF EXISTS "pdi_p3d_restore_owner_') for call in sql_calls)
    restore_target = dump.restore_calls[0][1]
    assert restore_target.host in {"127.0.0.1", "localhost", "::1"}
    assert restore_target.database.endswith("_test")
    assert restore_target.user == admin.user
    assert restore_target.password == admin.password
    assert "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" in sql_calls
    assert "SHOW transaction_read_only" in sql_calls


@pytest.mark.parametrize("failure", ["pg_restore", "invariant"])
def test_restore_adapter_cleans_database_and_owner_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    restored = replace(baseline(), alembic_revision="wrong") if failure == "invariant" else None
    adapter, _admin, _dump, sql_calls, _connections = postgres_restore_adapter(
        monkeypatch,
        restored=restored,
        fail_restore=failure == "pg_restore",
    )
    expected = (
        FailureCode.ROLLBACK_COMPATIBILITY_FAILED
        if failure == "invariant" else FailureCode.ROLLBACK_RESTORE_FAILED
    )
    with pytest.raises(RollbackQualificationError, match=expected.value):
        adapter.qualify(
            recovered_dump=tmp_path / "pdi-core.dump",
            baseline=baseline(),
            source_runtime=source_qualifier().qualify(SOURCE),
        )
    assert any(call.startswith('DROP DATABASE IF EXISTS "pdi_p3d_restore_') for call in sql_calls)
    assert any(call.startswith('DROP ROLE IF EXISTS "pdi_p3d_restore_owner_') for call in sql_calls)


def test_restore_adapter_creates_no_temporary_password() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "token_urlsafe" not in source
    assert "LOGIN PASSWORD" not in source
    assert "sql.Literal" not in source


def test_disposable_adapters_refuse_broad_root() -> None:
    with pytest.raises(RollbackQualificationError):
        FilesystemBackupAdapter(
            Path("/tmp/repository"), disposable_root=Path("/tmp"), backup_fs_uuid=BACKUP_UUID,
        )


@pytest.mark.parametrize(
    "target",
    [
        PostgresTarget("db.internal", 5432, "restore_test", "u", "p"),
        PostgresTarget("127.0.0.1", 5432, "production", "u", "p"),
    ],
)
def test_restore_target_guard_refuses_non_disposable_database(target: PostgresTarget) -> None:
    with pytest.raises(RollbackQualificationError):
        target.validate_disposable()


def test_filesystem_backup_round_trip_and_wrong_snapshot_refusal(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "pdi-core.dump").write_bytes(b"dump")
    adapter = FilesystemBackupAdapter(
        repository, disposable_root=tmp_path, backup_fs_uuid=BACKUP_UUID,
    )
    snapshot = adapter.create_snapshot(payload)
    restored = adapter.restore_snapshot(snapshot.snapshot_id, tmp_path / "restore")
    assert (restored / "pdi-core.dump").read_bytes() == b"dump"
    with pytest.raises(RollbackQualificationError):
        adapter.restore_snapshot("f" * 64, tmp_path / "wrong")


def test_restic_adapter_has_only_guarded_init_backup_restore(tmp_path: Path) -> None:
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if "backup" in argv:
            stdout = json.dumps({"message_type": "summary", "snapshot_id": H4}) + "\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    password = tmp_path / "password-file"
    password.write_text("synthetic")
    adapter = ResticBackupAdapter(
        tmp_path / "restic", password, disposable_root=tmp_path,
        backup_fs_uuid=BACKUP_UUID, runner=runner,
    )
    adapter.initialize_disposable()
    payload = tmp_path / "payload"
    payload.mkdir()
    snapshot = adapter.create_snapshot(payload)
    destination = tmp_path / "restored"
    adapter.restore_snapshot(snapshot.snapshot_id, destination)
    assert snapshot.snapshot_id == H4
    assert [call[0][1] for call in calls] == ["init", "backup", "restore"]
    assert all(call[1]["shell"] is False for call in calls)
    assert not any(action in {"forget", "prune", "migrate"} for call in calls for action in call[0])


def test_metadata_serialization_is_deterministic_non_shell_and_round_trips(tmp_path: Path) -> None:
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(tmp_path)
    result = orchestrator.run(context())
    payload = serialize_metadata(result.metadata)
    assert parse_metadata(payload) == result.metadata
    assert payload == serialize_metadata(parse_metadata(payload))
    assert not payload.startswith(b"export ")
    lines = payload.decode().splitlines()
    assert lines == sorted(lines)
    with pytest.raises(RollbackQualificationError):
        parse_metadata(payload + b"EXTRA=\"x\"\n")


def test_gate_a_journal_store_persists_valid_multi_tool_chain(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    store = GateAJournalStore(root, policy=policy(tmp_path))
    state = store.initialize(
        operation_id="11111111-2222-4333-8444-555555555555",
        candidate_sha=CANDIDATE,
        started_at=WHEN,
        export_tool=EXPORT_TOOL,
        restore_tool=RESTORE_TOOL,
    )
    events = ()
    state, events = store.advance(
        state, events, "SOURCE_VERIFIED", timestamp=WHEN,
        tool=EXPORT_TOOL, evidence_fingerprints=(H1,),
    )
    assert GateAJournalStore.resume_allowed(state)
    state, events = store.advance(
        state, events, "SNAPSHOT_EXPORTED", timestamp=WHEN,
        tool=EXPORT_TOOL, evidence_fingerprints=(H2,),
    )
    assert not GateAJournalStore.resume_allowed(state)
    assert validate_preparation_journal_chain(events, state)
    assert {event.tool_identity.tool_name for event in events} == {ToolName.BACKUP_EXPORT}
    persisted = json.loads((root / "state-000002.json").read_text())
    assert persisted == state.to_mapping()


def test_gate_a_journal_rejects_wrong_phase_tool(tmp_path: Path) -> None:
    store = GateAJournalStore(tmp_path / "journal", policy=policy(tmp_path))
    state = store.initialize(
        operation_id="11111111-2222-4333-8444-555555555555",
        candidate_sha=CANDIDATE,
        started_at=WHEN,
        export_tool=EXPORT_TOOL,
        restore_tool=RESTORE_TOOL,
    )
    with pytest.raises(PreparationContractError):
        store.advance(
            state, (), "SOURCE_VERIFIED", timestamp=WHEN,
            tool=RESTORE_TOOL, evidence_fingerprints=(H1,),
        )


def test_full_orchestration_generates_pin_before_metadata_and_complete_state(tmp_path: Path) -> None:
    orchestrator, coordinators, backup, restore = make_orchestrator(tmp_path)
    result = orchestrator.run(context())
    assert result.final_state.phase == "COMPLETE"
    assert validate_preparation_journal_chain(result.events, result.final_state)
    assert [event.to_state for event in result.events] == [
        "SOURCE_VERIFIED", "SNAPSHOT_EXPORTED", "DUMP_COMPLETED",
        "BACKUP_SNAPSHOT_CREATED", "RESTORE_STARTED", "RESTORE_COMPLETED",
        "RESTORE_QUALIFIED", "RUNTIME_QUALIFIED", "DB_RUNTIME_COMPATIBLE",
        "SOURCE_RELEASE_PINNED", "METADATA_COMMITTED", "COMPLETE",
    ]
    assert [event.tool_identity.tool_name for event in result.events[:4]] == [
        ToolName.BACKUP_EXPORT,
    ] * 4
    assert [event.tool_identity.tool_name for event in result.events[4:]] == [
        ToolName.RESTORE_QUALIFY,
    ] * 8
    authority = operation_authority_root(tmp_path)
    pin = authority / f"rollback-release-pin-{result.metadata.snapshot_id}.json"
    metadata = authority / "p3d-pre-enrichment.env"
    assert pin.exists() and metadata.exists()
    assert pin.stat().st_mtime_ns <= metadata.stat().st_mtime_ns
    assert parse_metadata(metadata.read_bytes()) == result.metadata
    assert result.metadata.snapshot_id == result.release_pin.snapshot_id
    assert result.metadata.export_tool.tool_source_sha == EXPORT_TOOL_SOURCE
    assert result.metadata.restore_tool.tool_source_sha == RESTORE_TOOL_SOURCE
    assert len({
        CANDIDATE,
        result.metadata.export_tool.tool_source_sha,
        result.metadata.restore_tool.tool_source_sha,
    }) == 3
    assert not (authority.parent / "payload").exists()
    assert not (authority.parent / "restored").exists()
    assert tuple((tmp_path / "repository").iterdir())


def test_orchestrator_preserves_independent_gate_a_tool_authorities(tmp_path: Path) -> None:
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(tmp_path)
    result = orchestrator.run(context())
    assert result.final_state.operator_tool_identities == tuple(sorted(
        (EXPORT_TOOL, RESTORE_TOOL), key=lambda item: item.tool_name.value,
    ))
    assert all(event.tool_identity in result.final_state.operator_tool_identities
               for event in result.events)


def test_orchestrator_rejects_wrong_gate_a_tool_role(tmp_path: Path) -> None:
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_SOURCE_INVALID.value):
        make_orchestrator(
            tmp_path,
            export_tool=tool(ToolName.RELEASE_BOOTSTRAP, EXPORT_TOOL_SOURCE),
        )


def test_gate_a_chain_rejects_event_identity_outside_state_authority(tmp_path: Path) -> None:
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(tmp_path)
    result = orchestrator.run(context())
    foreign = tool(ToolName.BACKUP_EXPORT, "e" * 40)
    tampered = (replace(result.events[0], tool_identity=foreign), *result.events[1:])
    with pytest.raises(PreparationContractError):
        validate_preparation_journal_chain(tampered, result.final_state)


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("source", FailureCode.ROLLBACK_SOURCE_INVALID),
        ("snapshot", FailureCode.ROLLBACK_SNAPSHOT_EXPORT_FAILED),
        ("dump", FailureCode.ROLLBACK_DUMP_FAILED),
        ("backup", FailureCode.ROLLBACK_BACKUP_FAILED),
        ("restore", FailureCode.ROLLBACK_RESTORE_FAILED),
        ("pg_restore", FailureCode.ROLLBACK_RESTORE_FAILED),
        ("count", FailureCode.ROLLBACK_COMPATIBILITY_FAILED),
        ("invariant", FailureCode.ROLLBACK_RUNTIME_INVALID),
        ("runtime", FailureCode.ROLLBACK_SOURCE_INVALID),
        ("compatibility", FailureCode.ROLLBACK_COMPATIBILITY_FAILED),
    ],
)
def test_orchestrator_failure_matrix_is_fixed_and_no_metadata(
    tmp_path: Path, case: str, expected: FailureCode,
) -> None:
    qualifier = source_qualifier(clean=False) if case in {"source", "runtime"} else None
    backup = FailingBackupAdapter() if case == "backup" else None
    restore_failure = None
    if case in {"restore", "pg_restore"}:
        restore_failure = FailureCode.ROLLBACK_RESTORE_FAILED
    elif case in {"count", "compatibility"}:
        restore_failure = FailureCode.ROLLBACK_COMPATIBILITY_FAILED
    elif case == "invariant":
        restore_failure = FailureCode.ROLLBACK_RUNTIME_INVALID
    restore = FakeRestoreAdapter(failure=restore_failure) if restore_failure else None
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(
        tmp_path,
        qualifier=qualifier,
        backup=backup,
        restore=restore,
        fail_export=case == "snapshot",
        fail_dump=case == "dump",
    )
    with pytest.raises(RollbackQualificationError, match=expected.value):
        orchestrator.run(context())
    authority = operation_authority_root(tmp_path)
    assert not (authority / "p3d-pre-enrichment.env").exists()
    assert not tuple(authority.glob("rollback-release-pin-*.json"))
    assert latest_state_mapping(tmp_path)["phase"] == "FAILED"


@pytest.mark.parametrize(
    ("failure_name", "expected"),
    [
        ("rollback-release-pin", FailureCode.ROLLBACK_PIN_FAILED),
        ("p3d-pre-enrichment.env", FailureCode.ROLLBACK_METADATA_CONFLICT),
    ],
)
def test_pin_and_metadata_persistence_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_name: str,
    expected: FailureCode,
) -> None:
    original = module.atomic_create_no_replace

    def fail_selected(path: Path, content: bytes, *, policy):
        if failure_name in path.name:
            raise PreparationContractError(FailureCode.CONTRACT_PERSISTENCE_UNTRUSTED)
        return original(path, content, policy=policy)

    monkeypatch.setattr(module, "atomic_create_no_replace", fail_selected)
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(tmp_path)
    with pytest.raises(RollbackQualificationError, match=expected.value):
        orchestrator.run(context())
    authority = operation_authority_root(tmp_path)
    assert not (authority / "p3d-pre-enrichment.env").exists()
    assert latest_state_mapping(tmp_path)["phase"] == "FAILED"


def test_unqualified_backup_is_preserved_after_restore_failure(tmp_path: Path) -> None:
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(
        tmp_path,
        restore=FakeRestoreAdapter(failure=FailureCode.ROLLBACK_RESTORE_FAILED),
    )
    with pytest.raises(RollbackQualificationError):
        orchestrator.run(context())
    snapshots = tuple((tmp_path / "repository").iterdir())
    assert len(snapshots) == 1
    assert not (operation_authority_root(tmp_path) / "p3d-pre-enrichment.env").exists()


def test_cleanup_failure_prevents_authority_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = module.shutil.rmtree
    attempts = 0

    def fail_first_cleanup(path: Path):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic")
        return original(path)

    monkeypatch.setattr(module.shutil, "rmtree", fail_first_cleanup)
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(tmp_path)
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RESTORE_FAILED.value):
        orchestrator.run(context())
    authority = operation_authority_root(tmp_path)
    assert not (authority / "p3d-pre-enrichment.env").exists()
    assert not tuple(authority.glob("rollback-release-pin-*.json"))


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        ("baseline.json", b"{}\n"),
        ("exported-snapshot-evidence.json", b"{}\n"),
        ("unexpected.txt", b"unexpected"),
    ],
)
def test_recovered_backup_manifest_is_authoritative_and_exact(
    tmp_path: Path, filename: str, payload: bytes,
) -> None:
    delegate = FilesystemBackupAdapter(
        tmp_path / "repository", disposable_root=tmp_path, backup_fs_uuid=BACKUP_UUID,
    )
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(
        tmp_path, backup=TamperingBackupAdapter(delegate, filename, payload),
    )
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_RESTORE_FAILED.value):
        orchestrator.run(context())
    assert not (operation_authority_root(tmp_path) / "p3d-pre-enrichment.env").exists()


def test_backup_filesystem_identity_must_match_context(tmp_path: Path) -> None:
    delegate = FilesystemBackupAdapter(
        tmp_path / "repository", disposable_root=tmp_path, backup_fs_uuid=BACKUP_UUID,
    )
    orchestrator, _coordinators, _backup, _restore = make_orchestrator(
        tmp_path, backup=WrongBackupIdentityAdapter(delegate),
    )
    with pytest.raises(RollbackQualificationError, match=FailureCode.ROLLBACK_BACKUP_FAILED.value):
        orchestrator.run(context())


def test_crash_resume_policy_refuses_raw_snapshot_and_later_phases(tmp_path: Path) -> None:
    store = GateAJournalStore(tmp_path / "journal", policy=policy(tmp_path))
    state = store.initialize(
        operation_id="11111111-2222-4333-8444-555555555555",
        candidate_sha=CANDIDATE,
        started_at=WHEN,
        export_tool=EXPORT_TOOL,
        restore_tool=RESTORE_TOOL,
    )
    assert store.resume_allowed(state)
    events = ()
    state, events = store.advance(
        state, events, "SOURCE_VERIFIED", timestamp=WHEN,
        tool=EXPORT_TOOL, evidence_fingerprints=(H1,),
    )
    assert store.resume_allowed(state)
    loaded_state, loaded_events = store.load_retryable()
    assert loaded_state == state
    assert loaded_events == events
    state, _events = store.advance(
        state, events, "SNAPSHOT_EXPORTED", timestamp=WHEN,
        tool=EXPORT_TOOL, evidence_fingerprints=(H2,),
    )
    assert not store.resume_allowed(state)
    with pytest.raises(RollbackQualificationError):
        store.load_retryable()


def test_resume_loader_refuses_orphaned_state_or_journal(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    store = GateAJournalStore(root, policy=policy(tmp_path))
    store.initialize(
        operation_id="11111111-2222-4333-8444-555555555555",
        candidate_sha=CANDIDATE,
        started_at=WHEN,
        export_tool=EXPORT_TOOL,
        restore_tool=RESTORE_TOOL,
    )
    (root / "journal-000001.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(RollbackQualificationError):
        store.load_retryable()


def test_no_production_cli_or_implicit_environment_capability() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "if __name__ ==" not in source
    assert "argparse" not in source
    assert "DATABASE__URL" not in source
    assert "os.environ" not in source
    assert "shell=True" not in source
