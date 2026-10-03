from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

import pdi.production_ops.p3d_disposable_rehearsal as module
from pdi.production_ops.p3d_disposable_rehearsal import (
    CANONICAL_PIPELINES,
    DatabaseBaseline,
    DisposableRehearsal,
    DisposableRehearsalError,
    MachineSystemdBackend,
    RehearsalDatabaseInspector,
    RehearsalInputs,
    RehearsalPolicy,
    SystemdManagerIdentity,
    machine_name_for,
)
from pdi.production_ops.p3d_pre_rehearsal_evidence import (
    PreRehearsalEvidenceError,
    PreRehearsalEvidenceResult,
    verify_candidate_evidence_runtime,
)


CANDIDATE = "a" * 40
SOURCE = "b" * 40
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
NOW = datetime(2026, 9, 26, 1, tzinfo=UTC)


def _inputs() -> RehearsalInputs:
    return RehearsalInputs(
        CANDIDATE,
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
    )


def _policy(root: Path, inputs: RehearsalInputs) -> RehearsalPolicy:
    return RehearsalPolicy(
        root,
        os.geteuid(),
        os.getegid(),
        65534,
        65534,
        machine_name_for(inputs.rehearsal_operation_id),
    )


def _runtime_layout(tmp_path: Path):
    inputs = _inputs()
    root = tmp_path / "root"
    root.mkdir()
    policy = _policy(root, inputs)
    release = policy.releases / CANDIDATE
    source_root = release / "src/pdi/production_ops"
    installed_root = (
        release / ".venv/lib/python3.13/site-packages/pdi/production_ops"
    )
    scripts = release / "scripts"
    python = release / ".venv/bin/python"
    for directory in (source_root, installed_root, scripts, python.parent):
        directory.mkdir(parents=True, exist_ok=True)
    wp7_bytes = b"exact wp7 module\n"
    wp6_bytes = b"exact frozen wp6 module\n"
    wp7_source = source_root / "p3d_disposable_rehearsal.py"
    wp7_installed = installed_root / "p3d_disposable_rehearsal.py"
    wp6_source = source_root / "p3d_pre_rehearsal_evidence.py"
    wp6_installed = installed_root / "p3d_pre_rehearsal_evidence.py"
    wp7_script = scripts / "pdi_p3d_disposable_rehearsal.py"
    wp6_script = scripts / "mu13_p3d_cutover.py"
    for path, payload in (
        (wp7_source, wp7_bytes),
        (wp7_installed, wp7_bytes),
        (wp6_source, wp6_bytes),
        (wp6_installed, wp6_bytes),
        (wp7_script, b"wp7 script\n"),
        (wp6_script, b"wp6 script\n"),
        (python, b"python\n"),
    ):
        path.write_bytes(payload)
        path.chmod(0o644)
    return SimpleNamespace(
        inputs=inputs,
        policy=policy,
        preparation_policy=policy.preparation_policy,
        release=release,
        python=python,
        wp7_source=wp7_source,
        wp7_installed=wp7_installed,
        wp6_source=wp6_source,
        wp6_installed=wp6_installed,
        wp7_script=wp7_script,
        wp6_script=wp6_script,
    )


def _git_runner(candidate: str = CANDIDATE, *, dirty: bool = False):
    def runner(argv, **kwargs):
        assert kwargs["env"] == module.GIT_READ_ONLY_ENV
        assert kwargs["shell"] is False
        if argv[-2:] == ("rev-parse", "HEAD"):
            return subprocess.CompletedProcess(argv, 0, candidate + "\n", "")
        return subprocess.CompletedProcess(argv, 0, "dirty\n" if dirty else "", "")

    return runner


def _protected_files(policy: RehearsalPolicy) -> None:
    environment = policy.physical("/etc/pdi/pdi.env")
    registry = policy.physical("/etc/pdi/scoped/registry.toml")
    environment.parent.mkdir(parents=True)
    environment.write_text("synthetic\n", encoding="utf-8")
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text("synthetic\n", encoding="utf-8")
    profiles = policy.physical("/etc/pdi/scoped/units")
    profiles.mkdir(parents=True)
    for key in CANONICAL_PIPELINES:
        (profiles / f"{key}.env").write_text(
            f'PDI_PRINCIPAL_REF="synthetic"\n'
            f'PDI_SCOPED_PIPELINE_KEY="{key}"\n',
            encoding="utf-8",
        )


def _current(policy: RehearsalPolicy) -> None:
    policy.current.parent.mkdir(parents=True, exist_ok=True)
    policy.current.symlink_to(f"/opt/pdi/releases/{SOURCE}")


class FakeSystemd:
    def __init__(self, policy: RehearsalPolicy) -> None:
        self.machine_name = policy.machine_name
        self.service_start_count = 0
        self.timer_enable_count = 0
        self.timer_start_count = 0
        self.started: list[str] = []
        self.events: list[object] = []
        self.last_start_pipeline_key = None
        self.last_start_unit = None
        self.last_start_return_code = None

    def manager_identity(self, policy):
        self.events.append("manager")
        return SystemdManagerIdentity(22, "host", "machine", H1, H2)

    def daemon_reload(self):
        self.events.append("reload")

    def verify_timers_quiet(self):
        self.events.append("timers")

    def verify_service_contract(self, key, *, after_run):
        self.events.append(("show", key, after_run))
        return H3

    def start_service(self, key):
        assert key in CANONICAL_PIPELINES
        self.service_start_count += 1
        self.started.append(key)
        self.events.append(("start", key))
        self.last_start_pipeline_key = key
        self.last_start_unit = f"pdi-scoped-pipeline@{key}.service"
        self.last_start_return_code = 0

    def show_service_failure_state(self, key):
        assert key in CANONICAL_PIPELINES
        return {
            "LoadState": "loaded",
            "ActiveState": "failed",
            "SubState": "failed",
            "Result": "exit-code",
            "ExecMainStatus": "1",
            "ExecMainCode": "1",
            "StatusErrno": "0",
        }

    def stop_all_services(self):
        self.events.append("cleanup")
        return True


class FakeEngine:
    def __init__(self) -> None:
        self.disposed = False

    def dispose(self):
        self.disposed = True


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _LedgerConnection:
    def __init__(self, rows, *, fresh_count=0, enrichments=1, statements=1):
        self.rows = rows
        self.fresh_count = fresh_count
        self.enrichments = enrichments
        self.statements = statements

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, parameters=None):
        assert "FROM pipeline_runs" in str(statement)
        return _Rows(self.rows)

    def scalar(self, statement, parameters=None):
        sql = str(statement)
        if "count(*) FROM pipeline_runs" in sql:
            return self.fresh_count
        if "resource_enrichments" in sql:
            return self.enrichments
        if "resource_statements" in sql:
            return self.statements
        raise AssertionError(sql)


class _LedgerEngine:
    url = "postgresql+psycopg://synthetic:synthetic@127.0.0.1/pdi_wp7_unit_test"

    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


class _BaselineConnection(_LedgerConnection):
    def __init__(self, server_version: str):
        super().__init__([])
        self.server_version = server_version

    def execute(self, statement, parameters=None):
        sql = str(statement)
        if "FROM asset_sources" in sql or "FROM observation_scope_sync_state" in sql:
            return _Rows([])
        raise AssertionError(sql)

    def scalar(self, statement, parameters=None):
        sql = str(statement)
        if "SHOW server_version_num" in sql:
            return self.server_version
        if "clock_timestamp" in sql:
            return NOW
        if "count(*) FROM pipeline_runs" in sql:
            return 0
        raise AssertionError(sql)


class _EvidenceReader:
    def collect(self):
        return SimpleNamespace(enabled_scope_ids=("scope-a",), identity_fingerprint=H3)


class FakeInspector:
    def __init__(self) -> None:
        self.baseline_value = DatabaseBaseline(NOW, 0, H3, H4, H1, H2)
        self.verified: list[str] = []

    def baseline(self):
        return self.baseline_value

    def assert_no_fresh_run(self, key, boundary):
        assert boundary == NOW

    def verify_pipeline(self, key, boundary):
        assert boundary == NOW
        self.verified.append(key)
        return str(uuid4()), H4

    def final(self, baseline, *, candidate_sha, context_fingerprint):
        assert baseline is self.baseline_value
        assert candidate_sha == CANDIDATE
        assert context_fingerprint == H1
        return tuple(
            {
                "pipeline_key": key,
                "run_id": run_id,
                "candidate_sha": candidate_sha,
                "context_fingerprint": context_fingerprint,
            }
            for key, run_id in zip(CANONICAL_PIPELINES, self.run_ids, strict=True)
        ), H2

    @property
    def run_ids(self):
        # The orchestration obtains IDs from verify_pipeline.  Keep the exact
        # IDs so final coverage proves the same six runs.
        return tuple(self._run_ids)

    _run_ids: list[str] = []


class RecordingInspector(FakeInspector):
    def __init__(self):
        super().__init__()
        self._run_ids = []

    def verify_pipeline(self, key, boundary):
        run_id, effect = super().verify_pipeline(key, boundary)
        self._run_ids.append(run_id)
        return run_id, effect


def _preparation() -> PreRehearsalEvidenceResult:
    return PreRehearsalEvidenceResult(CANDIDATE, H1, H2, H3, 2, H4, "5" * 64)


def _subject(tmp_path: Path, *, crash_after: int | None = None):
    inputs = _inputs()
    root = tmp_path / "root"
    root.mkdir()
    root.chmod(0o755)
    policy = _policy(root, inputs)
    _protected_files(policy)
    _current(policy)
    backend = FakeSystemd(policy)
    engine = FakeEngine()
    inspector = RecordingInspector()
    subject = DisposableRehearsal(
        inputs=inputs,
        policy=policy,
        preparation_collector=_preparation,
        systemd=backend,
        database_factory=lambda actual: (engine, inspector),
        release_verifier=lambda actual, candidate: "6" * 64,
        crash_after_pipeline=crash_after,
    )
    return subject, policy, backend, engine, inspector


def test_machine_name_is_derived_from_canonical_operation_uuid() -> None:
    operation = "12345678-1234-4234-8234-123456789abc"
    assert machine_name_for(operation) == "pdi-p3d-1234567812344234"
    with pytest.raises(DisposableRehearsalError, match="SELECTOR_INVALID"):
        machine_name_for("latest")


def test_policy_rejects_host_root() -> None:
    with pytest.raises(DisposableRehearsalError, match="ROOT_INVALID"):
        RehearsalPolicy.qualification(
            Path("/"), owner_uid=0, owner_gid=0,
            runtime_uid=65534, runtime_gid=65534,
            operation_id=str(uuid4()),
        )


def test_embedded_preparation_runtime_binds_exact_wp7_and_installed_wp6(
    tmp_path: Path,
) -> None:
    layout = _runtime_layout(tmp_path)
    result = module.verify_embedded_preparation_runtime(
        layout.preparation_policy,
        CANDIDATE,
        rehearsal_policy=layout.policy,
        rehearsal_candidate_sha=CANDIDATE,
        executable=layout.python,
        module_file=layout.wp7_installed,
        script_file=layout.wp7_script,
        preparation_module_file=layout.wp6_installed,
        runner=_git_runner(),
    )
    assert result == hashlib.sha256(layout.wp6_installed.read_bytes()).hexdigest()


def test_frozen_wp6_standalone_runtime_still_rejects_wp7_script(
    tmp_path: Path,
) -> None:
    layout = _runtime_layout(tmp_path)
    with pytest.raises(PreRehearsalEvidenceError, match="RUNTIME_INVALID"):
        verify_candidate_evidence_runtime(
            layout.preparation_policy,
            CANDIDATE,
            executable=layout.python,
            module_file=layout.wp6_installed,
            script_file=layout.wp7_script,
            runner=_git_runner(),
        )


def test_embedded_preparation_runtime_rejects_cross_root_and_wrong_candidate(
    tmp_path: Path,
) -> None:
    layout = _runtime_layout(tmp_path)
    other_root = tmp_path / "other-root"
    other_root.mkdir()
    other_policy = _policy(other_root, layout.inputs)
    for preparation_policy, candidate in (
        (other_policy.preparation_policy, CANDIDATE),
        (layout.preparation_policy, "c" * 40),
    ):
        with pytest.raises(DisposableRehearsalError, match="PREPARATION_INVALID"):
            module.verify_embedded_preparation_runtime(
                preparation_policy,
                candidate,
                rehearsal_policy=layout.policy,
                rehearsal_candidate_sha=CANDIDATE,
                executable=layout.python,
                module_file=layout.wp7_installed,
                script_file=layout.wp7_script,
                preparation_module_file=layout.wp6_installed,
                runner=_git_runner(),
            )


def test_embedded_preparation_runtime_rejects_stale_or_external_wp6_module(
    tmp_path: Path,
) -> None:
    layout = _runtime_layout(tmp_path)
    stale = layout.wp6_installed.read_bytes()
    layout.wp6_installed.write_bytes(stale + b"stale\n")
    with pytest.raises(DisposableRehearsalError, match="PREPARATION_INVALID"):
        module.verify_embedded_preparation_runtime(
            layout.preparation_policy,
            CANDIDATE,
            rehearsal_policy=layout.policy,
            rehearsal_candidate_sha=CANDIDATE,
            executable=layout.python,
            module_file=layout.wp7_installed,
            script_file=layout.wp7_script,
            preparation_module_file=layout.wp6_installed,
            runner=_git_runner(),
        )

    layout.wp6_installed.write_bytes(stale)
    external = tmp_path / "p3d_pre_rehearsal_evidence.py"
    external.write_bytes(stale)
    with pytest.raises(DisposableRehearsalError, match="PREPARATION_INVALID"):
        module.verify_embedded_preparation_runtime(
            layout.preparation_policy,
            CANDIDATE,
            rehearsal_policy=layout.policy,
            rehearsal_candidate_sha=CANDIDATE,
            executable=layout.python,
            module_file=layout.wp7_installed,
            script_file=layout.wp7_script,
            preparation_module_file=external,
            runner=_git_runner(),
        )


@pytest.mark.parametrize(
    "change",
    ("stale-wp7", "workspace-script", "wrong-head", "dirty", "wrong-python"),
)
def test_embedded_preparation_runtime_rejects_inexact_wp7_runtime(
    tmp_path: Path, change: str,
) -> None:
    layout = _runtime_layout(tmp_path)
    executable = layout.python
    module_file = layout.wp7_installed
    script_file = layout.wp7_script
    runner = _git_runner()
    if change == "stale-wp7":
        module_file.write_bytes(b"stale wp7 module\n")
    elif change == "workspace-script":
        script_file = Path(__file__).parents[1] / "scripts/pdi_p3d_disposable_rehearsal.py"
    elif change == "wrong-head":
        runner = _git_runner("d" * 40)
    elif change == "dirty":
        runner = _git_runner(dirty=True)
    else:
        executable = tmp_path / "python"
    with pytest.raises(DisposableRehearsalError, match="RUNTIME_INVALID"):
        module.verify_embedded_preparation_runtime(
            layout.preparation_policy,
            CANDIDATE,
            rehearsal_policy=layout.policy,
            rehearsal_candidate_sha=CANDIDATE,
            executable=executable,
            module_file=module_file,
            script_file=script_file,
            preparation_module_file=layout.wp6_installed,
            runner=runner,
        )


def test_wp7_cli_explicitly_uses_embedded_preparation_runtime_boundary() -> None:
    source = (
        Path(__file__).parents[1] / "scripts/pdi_p3d_disposable_rehearsal.py"
    ).read_text(encoding="utf-8")
    assert "runtime_verifier=(" in source
    assert "verify_embedded_preparation_runtime(" in source
    assert "P3D_REHEARSAL_PREPARATION_INVALID" in source


def test_systemd_backend_always_targets_machine_and_only_starts_service() -> None:
    commands = []

    def runner(argv, **kwargs):
        commands.append(tuple(argv))
        if "is-enabled" in argv:
            return subprocess.CompletedProcess(argv, 1, "disabled\n", "")
        if "is-active" in argv:
            return subprocess.CompletedProcess(argv, 3, "inactive\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    backend = MachineSystemdBackend(
        "pdi-p3d-1234567812344234", runner=runner,
    )
    backend.daemon_reload()
    backend.verify_timers_quiet()
    backend.start_service(CANONICAL_PIPELINES[0])
    assert backend.stop_all_services()
    assert all(command[0] == "/usr/bin/systemctl" for command in commands)
    assert all(command[1] == "--machine=pdi-p3d-1234567812344234" for command in commands)
    starts = [command for command in commands if "start" in command]
    assert starts == [(
        "/usr/bin/systemctl", "--machine=pdi-p3d-1234567812344234",
        "--no-pager", "start",
        "pdi-scoped-pipeline@enrichment.nextcloud_text.service",
    )]
    assert [command[-1] for command in commands if "stop" in command] == [
        f"pdi-scoped-pipeline@{key}.service" for key in CANONICAL_PIPELINES
    ]
    assert not any("enable" == item or "--now" == item for command in commands for item in command)
    assert not any(command[-1].endswith(".timer") and "start" in command for command in commands)
    with pytest.raises(DisposableRehearsalError, match="PIPELINE_SET_INVALID"):
        backend.start_service("provider.arbitrary.sync")


def test_systemd_backend_retains_only_fixed_service_start_result() -> None:
    commands = []

    def runner(argv, **kwargs):
        commands.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 17, "", "sensitive ignored")

    backend = MachineSystemdBackend(
        "pdi-p3d-1234567812344234", runner=runner,
    )
    key = CANONICAL_PIPELINES[0]
    with pytest.raises(DisposableRehearsalError, match="SERVICE_FAILED"):
        backend.start_service(key)
    assert backend.last_start_pipeline_key == key
    assert backend.last_start_unit == f"pdi-scoped-pipeline@{key}.service"
    assert backend.last_start_return_code == 17
    assert commands == [(
        "/usr/bin/systemctl", "--machine=pdi-p3d-1234567812344234",
        "--no-pager", "start", f"pdi-scoped-pipeline@{key}.service",
    )]


def test_service_failure_state_queries_only_allowlisted_properties() -> None:
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

    backend = MachineSystemdBackend(
        "pdi-p3d-1234567812344234", runner=runner,
    )
    assert backend.show_service_failure_state(CANONICAL_PIPELINES[0]) == values
    command = commands[0]
    assert command[:4] == (
        "/usr/bin/systemctl", "--machine=pdi-p3d-1234567812344234",
        "--no-pager", "show",
    )
    assert command[4] == (
        "pdi-scoped-pipeline@enrichment.nextcloud_text.service"
    )
    assert set(command[5:]) == {
        "--property=LoadState", "--property=ActiveState",
        "--property=SubState", "--property=Result",
        "--property=ExecMainStatus", "--property=ExecMainCode",
        "--property=StatusErrno",
    }
    assert not any(
        marker in " ".join(command)
        for marker in ("Environment", "ExecStart", "Password", "Token")
    )


def test_service_failure_journal_retains_fixed_start_result(tmp_path: Path) -> None:
    subject, policy, backend, _, _ = _subject(tmp_path)
    key = CANONICAL_PIPELINES[0]

    def fail_start(actual_key):
        assert actual_key == key
        backend.service_start_count += 1
        backend.last_start_pipeline_key = actual_key
        backend.last_start_unit = f"pdi-scoped-pipeline@{actual_key}.service"
        backend.last_start_return_code = 1
        raise DisposableRehearsalError("P3D_REHEARSAL_SERVICE_FAILED")

    backend.start_service = fail_start
    with pytest.raises(DisposableRehearsalError, match="SERVICE_FAILED"):
        subject.run()
    journals = sorted((
        policy.rehearsal_authority_root
        / subject.inputs.rehearsal_operation_id
    ).glob("journal-*.json"))
    failed = json.loads(journals[-1].read_text(encoding="utf-8"))
    assert failed["event"] == "FAILED"
    assert failed["evidence"] == {
        "failure_code": "P3D_REHEARSAL_SERVICE_FAILED",
        "last_start_pipeline_key": key,
        "last_start_return_code": 1,
        "last_start_unit": f"pdi-scoped-pipeline@{key}.service",
        "service_active_state": "failed",
        "service_exec_main_code": "1",
        "service_exec_main_status": "1",
        "service_status_errno": "0",
        "service_load_state": "loaded",
        "service_result": "exit-code",
        "service_sub_state": "failed",
    }


def test_manager_identity_requires_real_isolated_pid1(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "proc/sys/kernel/random").mkdir(parents=True)
    (root / "proc/sys/kernel/random/boot_id").write_text("machine\n")
    (root / "etc").mkdir()
    (root / "etc/os-release").write_text("ID=synthetic\n")
    (root / "usr/lib/systemd").mkdir(parents=True)
    (root / "usr/lib/systemd/systemd").write_bytes(b"systemd")
    proc = tmp_path / "proc"
    (proc / "22").mkdir(parents=True)
    (proc / "22/comm").write_text("systemd\n")
    (proc / "22/status").write_text("Name:\tsystemd\nNSpid:\t22\t1\n")
    (proc / "22/root").symlink_to(root, target_is_directory=True)
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("host\n")

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, "22\n", "")

    inputs = _inputs()
    policy = _policy(root, inputs)
    backend = MachineSystemdBackend(policy.machine_name, runner=runner, proc_root=proc)
    identity = backend.manager_identity(policy)
    assert identity.manager_boot_id == "machine"
    assert identity.host_boot_id == "host"

    (root / "proc/sys/kernel/random/boot_id").write_text("host\n")
    with pytest.raises(DisposableRehearsalError, match="NOT_ISOLATED"):
        backend.manager_identity(policy)


def test_service_contract_is_exact_and_sanitized() -> None:
    values = {
        "LoadState": "loaded",
        "User": "pdi",
        "Group": "pdi",
        "Type": "oneshot",
        "NoNewPrivileges": "yes",
        "WorkingDirectory": "/opt/pdi/current",
        "ExecStart": (
            "{ path=/opt/pdi/current/.venv/bin/python ; "
            "argv[]=/opt/pdi/current/.venv/bin/python -m "
            "pdi.production_ops.enrichment --config /etc/pdi/scoped/registry.toml ; }"
        ),
        "FragmentPath": "/etc/systemd/system/pdi-scoped-pipeline@.service",
        "DropInPaths": "",
        "ActiveState": "inactive",
        "SubState": "dead",
        "Result": "success",
        "ExecMainStatus": "0",
    }

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 0, "".join(f"{key}={value}\n" for key, value in values.items()), "",
        )

    backend = MachineSystemdBackend(
        "pdi-p3d-1234567812344234", runner=runner,
    )
    assert len(backend.verify_service_contract(CANONICAL_PIPELINES[0], after_run=True)) == 64
    values["ExecStart"] += " --password exposed"
    with pytest.raises(DisposableRehearsalError, match="SERVICE_CONTRACT_INVALID"):
        backend.verify_service_contract(CANONICAL_PIPELINES[0], after_run=True)


def test_success_runs_exact_six_with_timers_quiet_and_writes_complete_marker(tmp_path: Path) -> None:
    subject, policy, backend, engine, inspector = _subject(tmp_path)
    result = subject.run()
    assert backend.started == list(CANONICAL_PIPELINES)
    assert inspector.verified == list(CANONICAL_PIPELINES)
    assert backend.service_start_count == 6
    assert backend.timer_enable_count == 0
    assert backend.timer_start_count == 0
    assert engine.disposed is True
    assert policy.current.readlink() == Path(f"/opt/pdi/releases/{CANDIDATE}")
    marker = (
        policy.rehearsal_authority_root
        / subject.inputs.rehearsal_operation_id
        / "complete.json"
    )
    assert marker.is_file()
    sanitized = result.to_sanitized_mapping()
    assert sanitized["RUNTIME_PIPELINE_COVERAGE"] == "6/6"
    assert sanitized["P3D_TIMER_ENABLE_COUNT"] == 0
    assert sanitized["POSTGRESQL_MAJOR"] == 16
    assert "cleanup" in backend.events
    assert backend.events.count("timers") >= 14


@pytest.mark.parametrize("after", [1, 3, 6])
def test_partial_failure_never_creates_complete_marker_and_cleans_services(
    tmp_path: Path, after: int,
) -> None:
    subject, policy, backend, engine, _ = _subject(tmp_path, crash_after=after)
    with pytest.raises(DisposableRehearsalError, match="INJECTED_FAILURE"):
        subject.run()
    assert backend.service_start_count == after
    assert "cleanup" in backend.events
    assert engine.disposed is True
    assert not (
        policy.rehearsal_authority_root
        / subject.inputs.rehearsal_operation_id
        / "complete.json"
    ).exists()


def test_preparation_mismatch_prevents_promotion_and_service_start(tmp_path: Path) -> None:
    subject, policy, backend, _, _ = _subject(tmp_path)
    subject.preparation_collector = lambda: replace(
        _preparation(), candidate_sha="c" * 40,
    )
    with pytest.raises(DisposableRehearsalError, match="PREPARATION_INVALID"):
        subject.run()
    assert policy.current.readlink() == Path(f"/opt/pdi/releases/{SOURCE}")
    assert backend.service_start_count == 0
    assert "cleanup" not in backend.events


def test_unverified_manager_is_never_targeted_for_cleanup(tmp_path: Path) -> None:
    subject, policy, backend, _, _ = _subject(tmp_path)

    def reject_manager(actual_policy):
        backend.events.append("manager-rejected")
        raise DisposableRehearsalError("P3D_REHEARSAL_MANAGER_NOT_ISOLATED")

    backend.manager_identity = reject_manager
    with pytest.raises(DisposableRehearsalError, match="MANAGER_NOT_ISOLATED"):
        subject.run()
    assert policy.current.readlink() == Path(f"/opt/pdi/releases/{SOURCE}")
    assert backend.service_start_count == 0
    assert backend.events == ["manager-rejected"]


def test_preparation_drift_immediately_before_promotion_is_refused(tmp_path: Path) -> None:
    subject, policy, backend, _, _ = _subject(tmp_path)
    results = iter((_preparation(), _preparation(), replace(
        _preparation(), marker_fingerprint="9" * 64,
    )))
    subject.preparation_collector = lambda: next(results)
    with pytest.raises(DisposableRehearsalError, match="PREPARATION_DRIFT"):
        subject.run()
    assert policy.current.readlink() == Path(f"/opt/pdi/releases/{SOURCE}")
    assert backend.service_start_count == 0


def test_cleanup_failure_never_creates_complete_marker(tmp_path: Path) -> None:
    subject, policy, backend, _, _ = _subject(tmp_path)
    backend.stop_all_services = lambda: False
    with pytest.raises(DisposableRehearsalError, match="CLEANUP_FAILED"):
        subject.run()
    assert not (
        policy.rehearsal_authority_root
        / subject.inputs.rehearsal_operation_id
        / "complete.json"
    ).exists()


@pytest.mark.parametrize("rows", [[], [(uuid4(), "completed", NOW, None)] * 2])
def test_pipeline_ledger_missing_or_duplicate_is_rejected(rows) -> None:
    connection = _LedgerConnection(rows)
    inspector = RehearsalDatabaseInspector(_LedgerEngine(connection), object())
    with pytest.raises(DisposableRehearsalError, match="LEDGER_COVERAGE"):
        inspector.verify_pipeline(CANONICAL_PIPELINES[0], NOW)


def test_stale_pipeline_ledger_is_rejected_before_service_start() -> None:
    connection = _LedgerConnection([], fresh_count=1)
    inspector = RehearsalDatabaseInspector(_LedgerEngine(connection), object())
    with pytest.raises(DisposableRehearsalError, match="LEDGER_STALE"):
        inspector.assert_no_fresh_run(CANONICAL_PIPELINES[0], NOW)


@pytest.mark.parametrize(
    "row,enrichments,statements",
    [
        ((uuid4(), "running", None, None), 1, 1),
        ((uuid4(), "completed", NOW, "execution_failed"), 1, 1),
        ((uuid4(), "completed", NOW, None), 0, 1),
        ((uuid4(), "completed", NOW, None), 1, 0),
    ],
)
def test_pipeline_requires_completed_ledger_and_nonzero_useful_work(
    row, enrichments, statements,
) -> None:
    connection = _LedgerConnection(
        [row], enrichments=enrichments, statements=statements,
    )
    inspector = RehearsalDatabaseInspector(_LedgerEngine(connection), object())
    with pytest.raises(DisposableRehearsalError, match="WORKLOAD_EFFECT_INVALID"):
        inspector.verify_pipeline(CANONICAL_PIPELINES[0], NOW)


def test_database_guard_accepts_only_dedicated_wp7_test_name() -> None:
    safe = create_engine(
        "postgresql+psycopg://synthetic:synthetic@127.0.0.1/pdi_wp7_runtime_test"
    )
    RehearsalDatabaseInspector(safe, object())
    unsafe = create_engine(
        "postgresql+psycopg://synthetic:synthetic@127.0.0.1/pdi"
    )
    with pytest.raises(DisposableRehearsalError, match="DATABASE_UNSAFE"):
        RehearsalDatabaseInspector(unsafe, object())
    safe.dispose()
    unsafe.dispose()


def test_database_baseline_requires_postgresql_16() -> None:
    accepted = RehearsalDatabaseInspector(
        _LedgerEngine(_BaselineConnection("160011")), _EvidenceReader(),
    ).baseline()
    assert accepted.started_after == NOW
    with pytest.raises(DisposableRehearsalError, match="DATABASE_INVALID"):
        RehearsalDatabaseInspector(
            _LedgerEngine(_BaselineConnection("150015")), _EvidenceReader(),
        ).baseline()


def test_production_module_has_no_timer_activation_provider_http_or_manual_ledger_sql() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    forbidden = (
        "systemctl enable",
        "systemctl disable",
        "enable --now",
        "requests.",
        "httpx.",
        "INSERT INTO pipeline_runs",
        "UPDATE pipeline_runs",
        "DELETE FROM pipeline_runs",
        "shell=True",
    )
    assert all(item not in source for item in forbidden)
    assert "start_service" in source


def test_cli_exposes_no_production_or_arbitrary_database_selector() -> None:
    source = (Path(__file__).parents[1] / "scripts/pdi_p3d_disposable_rehearsal.py").read_text()
    assert "--database-url" not in source
    assert "--production" not in source
    assert "--host-systemd" not in source
    assert "--pipeline" not in source
    assert "enable" not in source


def test_dedicated_ci_requires_real_unskipped_systemd_rehearsal() -> None:
    workflow = (Path(__file__).parents[1] / ".github/workflows/ci.yml").read_text()
    assert "p3d-disposable-rehearsal:" in workflow
    assert "name: P3D disposable real-systemd rehearsal" in workflow
    assert "test \"$(ps -p 1 -o comm= | xargs)\" = systemd" in workflow
    assert "test -x /usr/bin/systemd-nspawn" in workflow
    assert "test -x /usr/bin/machinectl" in workflow
    assert '--junitxml="$rehearsal_report"' in workflow
    assert '"skipped": 0' in workflow
    assert "P3D_SERVICE_START_COUNT=6" in workflow
    assert "P3D_TIMER_ENABLE_COUNT=0" in workflow
    assert "RUNTIME_PIPELINE_COVERAGE=6/6" in workflow


def test_dedicated_ci_keeps_runtime_visible_with_private_tmp() -> None:
    root = Path(__file__).parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text()
    service = (
        root / "deployment/systemd/pdi-scoped-pipeline@.service"
    ).read_text()
    assert "PrivateTmp=true" in service
    assert "PrivateTmp=false" not in service
    assert "mktemp -d /run/pdi-p3d-wp7-runtime.XXXXXX" in workflow
    assert "/tmp/pdi-p3d-wp7-runtime." not in workflow
    assert 'readlink -f "$qualification_runtime"' in workflow
    assert "stat -Lc '%u:%g:%a:%F' /run" in workflow
    assert "stat -Lc '%u:%g:%a:%F' \"$qualification_runtime\"" in workflow
    assert '"$system_python" -c \'import sys; assert sys.executable\'' in workflow
    assert "QUALIFICATION_RUNTIME_CLEANED=PASS" in workflow
    integration = (
        root / "tests/integration/test_p3d_disposable_rehearsal.py"
    ).read_text()
    assert "runtime_root = _verify_qualification_runtime_root(system_python)" in integration
    assert "_assert_candidate_venv_runtime_authority(" in integration


def test_wp7_loader_cache_fix_is_disposable_and_preserves_service_contract() -> None:
    root = Path(__file__).parents[1]
    integration = (
        root / "tests/integration/test_p3d_disposable_rehearsal.py"
    ).read_text(encoding="utf-8")
    service = (
        root / "deployment/systemd/pdi-scoped-pipeline@.service"
    ).read_text(encoding="utf-8")
    assert "_materialize_disposable_loader_cache(root, runtime_root)" in integration
    assert "_verify_container_python_preflight(" in integration
    assert 'LDCONFIG = Path("/sbin/ldconfig")' in integration
    assert '"-X"' in integration
    assert '"--ignore-aux-cache"' in integration
    assert "LOADER_CACHE_LIBPYTHON_ENTRY_COUNT=1" in integration
    assert "LOADER_CACHE_LIBPYTHON_TARGET_TRUSTED=PASS" in integration
    assert "LD_LIBRARY_PATH=" not in integration
    assert "LD_PRELOAD=" not in integration
    assert 'Path("/usr/bin/patchelf")' not in integration
    assert "PrivateTmp=true" in service
    assert "PrivateTmp=false" not in service
    assert "LD_LIBRARY_PATH" not in service
    assert "LD_PRELOAD" not in service


def test_wp7_python_preflight_failure_emits_only_structured_safe_evidence() -> None:
    integration = (
        Path(__file__).parents[1]
        / "tests/integration/test_p3d_disposable_rehearsal.py"
    ).read_text(encoding="utf-8")
    assert (
        "class _QualificationPythonPreflightError(AssertionError):"
        in integration
    )
    assert "diagnostic = _QualificationPythonPreflight(" in integration
    assert "except _QualificationPythonPreflightError as exc:" in integration
    assert "print(exc.safe_message())" in integration
    assert '"QUALIFICATION_PYTHON_PREFLIGHT", "FAIL"' in integration
    assert '"QUALIFICATION_PYTHON_PREFLIGHT_CLASS"' in integration
    assert (
        'raise AssertionError(\n'
        '                    "QUALIFICATION_PYTHON_PREFLIGHT_INVALID"'
        in integration
    )
    assert (
        "_materialize_disposable_loader_cache(root, runtime_root)"
        in integration
    )


def test_wp7_container_loader_cache_diagnostic_is_pre_workload_only() -> None:
    integration = (
        Path(__file__).parents[1]
        / "tests/integration/test_p3d_disposable_rehearsal.py"
    ).read_text(encoding="utf-8")
    rehearsal = integration.index(
        "def test_cross_gate_disposable_real_systemd_six_pipeline_rehearsal()"
    )
    diagnostic = integration.index(
        "_verify_container_loader_cache_visibility(", rehearsal
    )
    python_preflight = integration.index(
        "_verify_container_python_preflight(", diagnostic
    )
    formal_lock = integration.index(
        'Path(f"/proc/{leader}/root/run/lock/pdi-sync.lock")',
        python_preflight,
    )
    wp7_cli = integration.index(
        'str(release / "scripts/pdi_p3d_disposable_rehearsal.py")',
        formal_lock,
    )
    assert diagnostic < python_preflight < formal_lock < wp7_cli
    assert 'LDCONFIG), "-p", "-C", "/etc/ld.so.cache"' in integration
    assert 'command.append("--inhibit-cache")' in integration
    assert 'CONTAINER_LOADER_CACHE_DIAGNOSTIC_CLASS' in integration
    assert "LD_LIBRARY_PATH=" not in integration
    assert "LD_PRELOAD=" not in integration


def test_wp7_boot_cache_attribution_is_read_only_and_pre_workload() -> None:
    integration = (
        Path(__file__).parents[1]
        / "tests/integration/test_p3d_disposable_rehearsal.py"
    ).read_text(encoding="utf-8")
    rehearsal = integration.index(
        "def test_cross_gate_disposable_real_systemd_six_pipeline_rehearsal()"
    )
    loader_diagnostic = integration.index(
        "_verify_container_loader_cache_visibility(", rehearsal
    )
    attribution = integration.index(
        "_collect_boot_cache_attribution(", loader_diagnostic
    )
    python_preflight = integration.index(
        "_verify_container_python_preflight(", attribution
    )
    formal_lock = integration.index(
        'Path(f"/proc/{leader}/root/run/lock/pdi-sync.lock")',
        python_preflight,
    )
    assert loader_diagnostic < attribution < python_preflight < formal_lock
    writer_query_start = integration.index(
        "def _cache_writer_service_state("
    )
    writer_query_end = integration.index(
        "def _allowlisted_cache_writer_states(", writer_query_start
    )
    writer_query = integration[writer_query_start:writer_query_end]
    assert '"show"' in writer_query
    assert all(
        f'"{action}"' not in writer_query
        for action in ("start", "stop", "restart", "enable", "disable")
    )
    assert '"ldconfig.service"' in integration
    assert '"systemd-update-done.service"' in integration
    assert '"systemd-tmpfiles-setup.service"' in integration
    assert '"systemd-tmpfiles-setup-dev.service"' in integration
    assert "journalctl" not in writer_query
