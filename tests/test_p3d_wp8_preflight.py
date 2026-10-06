from __future__ import annotations

import ast
from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

from pdi.production_ops import p3d_pre_rehearsal_evidence as wp6
from pdi.production_ops import p3d_wp8_preflight as module
from pdi.production_ops.p3d_wp8_contracts import (
    WP8ContractError, WP8InvariantSnapshotV1, wp8_contract_bytes,
)
from tests.test_p3d_wp8_contracts import phase_a


CANDIDATE = "a" * 40
SOURCE = "b" * 40
H = "c" * 64
CANARY = "synthetic-password-token@provider.invalid"


def inputs(**changes):
    a = phase_a()
    values = dict(candidate_sha=CANDIDATE, gate_a_operation_id=a.gate_a_operation_id,
                  gate_b_operation_id=a.gate_b_operation_id, gate_c_operation_id=a.gate_c_operation_id,
                  rollback_source_cross_check=SOURCE)
    return wp6.PreparationEvidenceInputs(**(values | changes))


def ready_result():
    a = phase_a()
    return wp6.PreRehearsalEvidenceResult(CANDIDATE, a.wp6_context_fingerprint,
        a.gate_c_marker_fingerprint, a.db_identity_fingerprint, a.enabled_scope_count,
        a.enabled_scope_fingerprint, a.unit_profile_asset_fingerprint)


def projection():
    a = phase_a()
    return module._Projection(a.invariant_baseline, SOURCE, a.gate_c_marker_fingerprint,
                              a.wp6_context_fingerprint, 2, (("protected", (1, 2, 3, H)),))


def collect(*, collector=None, projector=None, runtime=None, selected=None):
    return module._collect(SimpleNamespace(root=Path("/synthetic")), selected or inputs(), object(),
        runtime_verifier=runtime or (lambda *_: H),
        collector=collector or (lambda **_: ready_result()),
        projector=projector or (lambda *_: projection()))


def test_public_api_has_only_explicit_authority_selectors():
    assert set(inspect.signature(module.collect_phase_a_evidence).parameters) == {
        "candidate_sha", "gate_a_operation_id", "gate_b_operation_id", "gate_c_operation_id", "rollback_source_sha",
    }


def test_public_api_uses_only_fixed_production_policy_and_reader(monkeypatch):
    from pdi.production_ops import p3d_inert_asset_install as gate_c
    policy, systemd = object(), object()
    seen = []
    monkeypatch.setattr(gate_c.InertAssetPolicy, "production", classmethod(lambda _: policy))
    monkeypatch.setattr(gate_c, "ProductionReadOnlySystemdStateProvider", lambda: systemd)
    def collector(actual_policy, selected, actual_systemd):
        seen.append((actual_policy, selected, actual_systemd))
        assert (actual_policy, actual_systemd) == (policy, systemd)
        assert selected == inputs()
        return phase_a()
    monkeypatch.setattr(module, "_collect", collector)
    evidence = module.collect_phase_a_evidence(candidate_sha=CANDIDATE, rollback_source_sha=SOURCE,
        gate_a_operation_id=inputs().gate_a_operation_id, gate_b_operation_id=inputs().gate_b_operation_id,
        gate_c_operation_id=inputs().gate_c_operation_id)
    assert evidence == phase_a() and len(seen) == 1


@pytest.mark.parametrize("changes", ({"candidate_sha": "wrong"}, {"rollback_source_sha": None},
                                    {"rollback_source_sha": CANDIDATE}))
def test_public_api_invalid_candidate_or_missing_rollback_fails_before_readers(monkeypatch, changes):
    from pdi.production_ops.p3d_inert_asset_install import InertAssetPolicy
    def forbidden(*_, **kw):
        pytest.fail("invalid selector must not reach protected readers")
    monkeypatch.setattr(InertAssetPolicy, "production", classmethod(forbidden))
    with pytest.raises(WP8ContractError) as caught:
        module.collect_phase_a_evidence(**(dict(candidate_sha=CANDIDATE, rollback_source_sha=SOURCE,
            gate_a_operation_id=inputs().gate_a_operation_id, gate_b_operation_id=inputs().gate_b_operation_id,
            gate_c_operation_id=inputs().gate_c_operation_id) | changes))
    assert str(caught.value) == "P3D_WP8_PREREQUISITE_DRIFT"


def test_frozen_wp6_is_first_and_only_readiness_authority():
    calls = []

    def runtime(*_):
        calls.append("runtime")
        return H

    def collector(**kwargs):
        calls.append("wp6")
        assert kwargs["runtime_verifier"](kwargs["policy"], CANDIDATE) == H
        return ready_result()

    def projector(*_):
        calls.append("project")
        return projection()

    evidence = collect(collector=collector, projector=projector, runtime=runtime)
    assert calls == ["runtime", "wp6", "runtime", "project", "wp6", "runtime", "project"]
    assert wp8_contract_bytes(evidence) == wp8_contract_bytes(phase_a())
    assert evidence.runtime_pipeline_coverage == "0/6"
    assert evidence.post_rehearsal_runtime_ledger_proof == "NOT_APPLICABLE_PRE_REHEARSAL"


def test_wp6_failure_cannot_be_overridden_by_projector():
    calls = []

    def reject(**_):
        raise RuntimeError(CANARY)

    with pytest.raises(WP8ContractError) as caught:
        collect(collector=reject, projector=lambda *_: calls.append("forbidden"))
    assert calls == []
    assert CANARY not in str(caught.value)
    assert caught.value.__suppress_context__


def test_projection_failure_after_wp6_pass_fails_without_partial_evidence():
    def reject(*_):
        raise RuntimeError(CANARY)
    with pytest.raises(WP8ContractError) as caught:
        collect(projector=reject)
    assert str(caught.value) == "P3D_WP8_PREREQUISITE_DRIFT"


@pytest.mark.parametrize("field", tuple(ready_result().__dataclass_fields__))
def test_every_wp6_public_field_drift_rejected(field):
    original = ready_result()
    value = 3 if field == "enabled_scope_count" else ("d" * 40 if field == "candidate_sha" else "d" * 64)
    results = iter((original, replace(original, **{field: value})))
    with pytest.raises(WP8ContractError):
        collect(collector=lambda **_: next(results))


@pytest.mark.parametrize("field", WP8InvariantSnapshotV1.HASH_FIELDS)
def test_supplemental_semantic_drift_rejected(field):
    original = projection()
    different = replace(original, baseline=replace(original.baseline, **{field: "d" * 64}))
    observations = iter((original, different))
    with pytest.raises(WP8ContractError):
        collect(projector=lambda *_: next(observations))


@pytest.mark.parametrize("changes", (
    {"rollback_source": "d" * 40}, {"marker": "d" * 64}, {"wp6_context": "d" * 64},
    {"scope_count": 3}, {"anchors": (("protected", (2, 2, 3, H)),)},
))
def test_anchor_and_cross_context_drift_rejected(changes):
    observations = iter((projection(), replace(projection(), **changes)))
    with pytest.raises(WP8ContractError):
        collect(projector=lambda *_: next(observations))


@pytest.mark.parametrize("changes", (
    {"candidate_sha": "wrong"}, {"candidate_sha": "d" * 40},
    {"rollback_source_cross_check": CANDIDATE}, {"rollback_source_cross_check": "d" * 40},
    {"gate_a_operation_id": "wrong"}, {"gate_b_operation_id": inputs().gate_a_operation_id},
))
def test_selector_and_candidate_mismatch_rejected(changes):
    with pytest.raises(WP8ContractError):
        collect(selected=inputs(**changes))


def test_embedded_callback_rejects_foreign_candidate_or_policy():
    def collector(**kwargs):
        for selected, candidate in ((object(), CANDIDATE), (kwargs["policy"], SOURCE)):
            with pytest.raises(WP8ContractError):
                kwargs["runtime_verifier"](selected, candidate)
        return ready_result()
    collect(collector=collector)


def test_unchanged_collections_are_byte_equivalent_and_sanitized():
    first, second = collect(), collect()
    assert wp8_contract_bytes(first) == wp8_contract_bytes(second)
    assert first.phase_a_context_fingerprint == second.phase_a_context_fingerprint
    assert first.phase_a_evidence_fingerprint == second.phase_a_evidence_fingerprint
    raw = wp8_contract_bytes(first).decode()
    for forbidden in (CANARY, "postgresql://", "@provider.invalid", "checkpoint", "collection_timestamp"):
        assert forbidden not in raw


def test_no_persistence_provider_or_workload_primitives(tmp_path, monkeypatch):
    before = list(tmp_path.iterdir())
    tree = ast.parse(Path(module.__file__).read_text())
    def forbidden(*_args, **_kwargs):
        pytest.fail("mutation or Provider contact")
    for name in ("open", "mkdir", "write_text", "write_bytes", "touch", "unlink", "rename"):
        monkeypatch.setattr(Path, name, forbidden)
    import socket
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    collect()
    assert list(tmp_path.iterdir()) == before
    calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not calls & {"commit", "add", "flush", "create_all", "write_text", "write_bytes", "mkdir", "touch",
                        "replace", "unlink", "symlink_to", "acquire", "promote", "activate", "abort", "run_pipeline"}
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("adapter" in name or "repository" in name or "rehearsal" == name for name in imports)


class Rows(list):
    def one(self):
        assert len(self) == 1
        return self[0]
    def all(self):
        return list(self)


class Transaction:
    is_active = True
    def __init__(self):
        self.rollbacks = 0
    def rollback(self):
        self.rollbacks += 1
        self.is_active = False
    def commit(self):
        pytest.fail("commit forbidden")


class Connection:
    def __init__(self):
        self.transaction = Transaction()
        self.read_only = False
        self.closed = False
        self.queries = []
        self.schema_change = False
        self.business_payload = "first"
        self.version = 1
        self.checkpoint = "cursor-one"
        self.scope_enabled = True
        self.reconciliation = False
        self.native_identity = "account-one"
        self.provider_key = "nc"
        self.provenance_extra = False
    def __enter__(self):
        return self
    def __exit__(self, *_):
        self.closed = True
    def begin(self):
        return self.transaction
    def scalar(self, sql):
        self.queries.append(str(sql))
        return {"SHOW transaction_read_only": "on" if self.read_only else "off",
                "SHOW transaction_isolation": "repeatable read"}[str(sql)]
    def execute(self, sql, parameters=None):
        sql = str(sql)
        self.queries.append(sql)
        if sql == "SET TRANSACTION READ ONLY":
            self.read_only = True
            return Rows()
        if sql.startswith("INSERT"):
            assert self.read_only
            raise PermissionError("read-only transaction")
        assert self.read_only, "query escaped read-only connection"
        assert sql.startswith("SELECT"), sql
        if "version_num FROM alembic_version" in sql:
            return Rows([(module.EXPECTED_ALEMBIC_REVISION,)])
        if "current_database()" in sql:
            return Rows([("pdi_phase_a_test", "synthetic", "127.0.0.1", 5432)])
        if "FROM pg_catalog.pg_class" in sql:
            if sql.startswith("SELECT c.relname,c.relkind"):
                return Rows([(name, "r", "p", False, False) for name in sorted(module._PDI_RELATIONS)])
            if sql.startswith("SELECT c.relname,a.attnum"):
                return Rows([("assets", 1, "id", "text" if self.schema_change else "uuid", True, "", "", None)])
            return Rows()
        if "SELECT id,provider_type" in sql:
            return Rows([(UUID(int=i), p, self.provider_key if i == 1 else p, i < 3)
                         for i, p in enumerate(("nextcloud", "immich", "gmail", "integration-test"), 1)])
        if "SELECT id,provider_instance_id,account_key" in sql:
            return Rows([(UUID(int=10+i), UUID(int=i), "account", self.native_identity, True) for i in (1, 2)])
        if "SELECT id,provider_instance_id,provider_account_id" in sql:
            return Rows([(UUID(int=20+i), UUID(int=i), UUID(int=10+i) if i < 3 else None,
                          f"scope-{i}", self.scope_enabled if i < 3 else False) for i in range(1, 5)])
        if "SELECT DISTINCT source.provider" in sql:
            rows = [(p, UUID(int=20+i), UUID(int=i), UUID(int=10+i) if i < 3 else None, p)
                    for i, p in enumerate(("nextcloud", "immich", "gmail", "integration-test"), 1)]
            if self.provenance_extra:
                rows.append(("nextcloud", UUID(int=22), UUID(int=2), UUID(int=12), "immich"))
            return Rows(rows)
        if "SELECT EXISTS" in sql:
            return Rows([(False, False, False)])
        if "checkpoint IS NOT NULL" in sql:
            return Rows([(UUID(int=20+i), f"mechanism-{i}", self.checkpoint is not None, self.reconciliation) for i in (1, 2)])
        pytest.fail(sql)


class Engine:
    url = "postgresql://synthetic:synthetic-password@127.0.0.1/pdi_phase_a_test"
    def __init__(self, connection=None):
        self.connection = connection or Connection()
        self.connect_count = 0
        self.disposed = False
    def execution_options(self, **options):
        assert options == {"isolation_level": "REPEATABLE READ"}
        self.isolation = options
        return self
    def connect(self):
        self.connect_count += 1
        return self.connection
    def dispose(self):
        self.disposed = True


def database_projection(monkeypatch, *, connection=None, principal="synthetic-principal", route="personal-db"):
    import pdi.scoped_enrichment_profiles as profiles
    engine = Engine(connection)
    router = SimpleNamespace(
        resolve=lambda selected: SimpleNamespace(database_url=engine.url, database_ref=route),
        database_environment_key=lambda selected: "DB_A_URL",
    )
    def derive(selected):
        assert selected is engine.connection
        assert selected.read_only
        return {UUID(int=21), UUID(int=22)}
    monkeypatch.setattr(profiles, "derive_enabled_scope_ids", derive)
    result = module._project_database(SimpleNamespace(router=router), principal, engine_factory=lambda _: engine)
    return result, engine


def test_db_snapshot_uses_one_connection_and_rolls_back(monkeypatch):
    result, engine = database_projection(monkeypatch)
    assert result.enabled_count == 2
    assert engine.connect_count == 1
    assert engine.connection.read_only
    assert engine.connection.transaction.rollbacks == 1
    assert engine.connection.closed and engine.disposed


def test_read_only_write_rejection_and_failure_rollback():
    from sqlalchemy import text
    engine = Engine()
    with pytest.raises(PermissionError):
        with module._baseline_connection(engine) as connection:
            assert connection.scalar(text("SHOW transaction_read_only")) == "on"
            connection.execute(text("INSERT INTO harmless_probe VALUES (1)"))
    assert engine.connection.transaction.rollbacks == 1 and engine.connection.closed


@pytest.mark.parametrize("invalid", ("off", "read committed"))
def test_db_isolation_not_verified_fails_closed(invalid):
    engine = Engine()
    original = engine.connection.scalar
    def scalar(sql):
        if str(sql) == ("SHOW transaction_read_only" if invalid == "off" else "SHOW transaction_isolation"):
            return invalid
        return original(sql)
    engine.connection.scalar = scalar
    with pytest.raises(Exception):
        with module._baseline_connection(engine):
            pytest.fail("must not yield")
    assert engine.connection.transaction.rollbacks == 1 and engine.connection.closed


def test_schema_is_deterministic_and_not_business_data(monkeypatch):
    first, _ = database_projection(monkeypatch)
    moving = Connection()
    moving.business_payload = CANARY
    moving.version = 900
    moving.checkpoint = "different-moving-content"
    second, _ = database_projection(monkeypatch, connection=moving)
    assert first == second
    changed = Connection()
    changed.schema_change = True
    third, _ = database_projection(monkeypatch, connection=changed)
    assert third.schema != first.schema


@pytest.mark.parametrize("property_name,value,field", (
    ("provider_key", "new-key", "providers"), ("native_identity", "new-account", "providers"),
    ("reconciliation", True, "sync"), ("checkpoint", None, "sync"),
    ("provenance_extra", True, "sources"),
))
def test_semantic_projection_changes_affect_own_fingerprint(monkeypatch, property_name, value, field):
    first, _ = database_projection(monkeypatch)
    different = Connection()
    setattr(different, property_name, value)
    second, _ = database_projection(monkeypatch, connection=different)
    assert getattr(first, field) != getattr(second, field)


def test_route_fingerprint_changes_on_principal_or_db_binding(monkeypatch):
    a, _ = database_projection(monkeypatch)
    b, _ = database_projection(monkeypatch, principal="foreign-principal")
    c, _ = database_projection(monkeypatch, route="foreign-db")
    assert len({a.route, b.route, c.route}) == 3
    assert a.identity != b.identity and a.identity != c.identity


def test_projected_identity_exactly_matches_frozen_wp6_reader(monkeypatch):
    from sqlalchemy import text
    from pdi.production_ops.p3d_evidence import RoutedPersonalDatabaseEvidenceReader
    projected, _ = database_projection(monkeypatch)
    connection = Connection()
    execute = connection.execute
    scalar = connection.scalar
    def frozen_scalar(statement):
        sql = str(statement)
        if sql == "SELECT version_num FROM alembic_version":
            return module.EXPECTED_ALEMBIC_REVISION
        if sql.startswith("SELECT count(*)"):
            return 0
        return scalar(statement)
    def frozen_execute(statement, parameters=None):
        sql = str(statement)
        if "SELECT count(*)," in sql:
            return Rows([(2, 2, 2)])
        if "SELECT provider, count(*)" in sql:
            return Rows([(provider, 1) for provider in ("nextcloud", "immich", "gmail", "integration-test")])
        return execute(statement, parameters)
    connection.scalar, connection.execute = frozen_scalar, frozen_execute
    class IdentityRepository:
        def __init__(self, selected):
            assert selected is connection and selected.read_only
        def list_instances(self):
            return tuple(SimpleNamespace(id=row[0], provider_type=row[1], enabled=row[3])
                for row in connection.execute(text("SELECT id,provider_type")))
        def list_accounts_for_instance(self, instance):
            return tuple(SimpleNamespace(id=row[0], enabled=True)
                for row in connection.execute(text("SELECT id,provider_instance_id,account_key")) if row[1] == instance)
        def list_scopes_for_instance(self, instance):
            return tuple(SimpleNamespace(id=row[0], provider_account_id=row[2], enabled=row[4])
                for row in connection.execute(text("SELECT id,provider_instance_id,provider_account_id")) if row[1] == instance)
    engine = Engine(connection)
    router = SimpleNamespace(resolve=lambda _: SimpleNamespace(database_ref="personal-db", database_url=engine.url))
    frozen = RoutedPersonalDatabaseEvidenceReader(router, engine, principal_ref="synthetic-principal",
        identity_repository_factory=IdentityRepository, scope_id_deriver=lambda selected: {UUID(int=21), UUID(int=22)}).collect()
    assert projected.identity == frozen.identity_fingerprint
    assert projected.enabled_count == len(frozen.enabled_scope_ids)
    from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint
    assert projected.enabled_scopes == contract_fingerprint({
        "principal_ref": "synthetic-principal", "enabled_scope_ids": sorted(frozen.enabled_scope_ids),
    })


def test_engine_cannot_route_to_another_database():
    engine = Engine()
    router = SimpleNamespace(resolve=lambda _: SimpleNamespace(database_ref="personal-db",
        database_url="postgresql://synthetic:synthetic-password@127.0.0.1/another_test"))
    with pytest.raises(WP8ContractError):
        module._project_database(SimpleNamespace(router=router), "synthetic-principal", engine_factory=lambda _: engine)
    assert engine.connect_count == 0 and engine.disposed


@pytest.mark.parametrize("failure", ("unavailable", "wrong-target", "wrong-revision", "missing-schema", "gmail-enabled"))
def test_db_invalid_evidence_fails_without_commit(monkeypatch, failure):
    connection = Connection()
    original = connection.execute
    def execute(sql, parameters=None):
        statement = str(sql)
        if failure == "unavailable" and statement.startswith("SELECT"):
            raise RuntimeError(CANARY)
        if failure == "wrong-target" and "current_database()" in statement:
            return Rows([("foreign_database", "synthetic", None, None)])
        if failure == "wrong-revision" and "version_num FROM alembic_version" in statement:
            return Rows([("wrong",)])
        if failure == "missing-schema" and statement.startswith("SELECT c.relname,c.relkind"):
            return Rows()
        result = original(sql, parameters)
        if failure == "gmail-enabled" and "SELECT id,provider_type" in statement:
            return Rows([(*row[:3], True) if row[1] == "gmail" else row for row in result])
        return result
    connection.execute = execute
    with pytest.raises(Exception):
        database_projection(monkeypatch, connection=connection)
    assert connection.transaction.rollbacks == 1 and connection.closed


def test_actual_postgresql_snapshot_select_and_write_rejection():
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    from pdi.database import create_postgres_engine
    from tests.integration.database_guard import require_safe_test_database_url
    engine = create_postgres_engine(require_safe_test_database_url())
    try:
        with module._baseline_connection(engine) as connection:
            assert connection.scalar(text("SELECT 1")) == 1
            assert connection.scalar(text("SHOW transaction_read_only")) == "on"
            assert connection.scalar(text("SHOW transaction_isolation")) == "repeatable read"
            with pytest.raises(DBAPIError) as rejected:
                connection.execute(text("INSERT INTO alembic_version(version_num) VALUES ('wp8_readonly_probe')"))
            assert rejected.value.orig.sqlstate == "25006"
    finally:
        engine.dispose()


def runtime_tree(tmp_path, monkeypatch):
    import pdi.production_ops.cutover as trust
    release = tmp_path / CANDIDATE
    interpreter = release / ".venv/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"synthetic-executable")
    sources, installed = [], []
    for name in ("p3d_wp8_preflight.py", "p3d_pre_rehearsal_evidence.py", "p3d_wp8_contracts.py"):
        source = release / "src/pdi/production_ops" / name
        imported = release / ".venv/lib/python3.13/site-packages/pdi/production_ops" / name
        for path in (source, imported):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        sources.append(source)
        installed.append(imported)
    monkeypatch.setattr(trust, "trusted_path", lambda path, **_: not path.is_symlink() and path.exists())
    original = Path.lstat
    def stat_reader(path):
        result = original(path)
        if path == interpreter:
            return SimpleNamespace(st_uid=0, st_gid=0, st_mode=result.st_mode)
        return result
    monkeypatch.setattr(Path, "lstat", stat_reader)
    policy = SimpleNamespace(candidate_releases_root=tmp_path)
    return policy, interpreter, sources, installed


def test_runtime_exact_modules_and_fixed_read_only_git_env(tmp_path, monkeypatch):
    policy, python, _, installed = runtime_tree(tmp_path, monkeypatch)
    commands = []
    for key, value in {"GIT_OPTIONAL_LOCKS": "1", "GIT_INDEX_FILE": "/tmp/evil-index",
                       "GIT_DIR": "/tmp/evil-git", "GIT_WORK_TREE": "/tmp/evil-worktree"}.items():
        monkeypatch.setenv(key, value)
    def runner(argv, **kwargs):
        commands.append(argv)
        assert kwargs["env"] == {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
        }
        assert kwargs["shell"] is False
        return SimpleNamespace(returncode=0, stdout=CANDIDATE if argv[-1] == "HEAD" else "")
    fingerprint = module._verify_runtime(policy, CANDIDATE, executable=python,
        module_file=installed[0], preparation_module_file=installed[1], contract_module_file=installed[2], runner=runner)
    assert fingerprint == hashlib.sha256(installed[1].read_bytes()).hexdigest()
    assert commands[-1][-3:] == ("status", "--porcelain", "--untracked-files=no")


@pytest.mark.parametrize("case", ("python", "wp8-stale", "wp6-stale", "contract-stale", "workspace", "head", "dirty", "command"))
def test_runtime_wrong_authority_rejected(tmp_path, monkeypatch, case):
    policy, python, _, installed = runtime_tree(tmp_path, monkeypatch)
    if case.endswith("stale"):
        index = {"wp8-stale": 0, "wp6-stale": 1, "contract-stale": 2}[case]
        installed[index].write_bytes(b"stale")
    if case == "workspace":
        installed[0] = tmp_path / "workspace.py"
        installed[0].write_bytes(b"workspace")
    def runner(argv, **_):
        return SimpleNamespace(returncode=1 if case == "command" else 0,
            stdout=(SOURCE if case == "head" else CANDIDATE) if argv[-1] == "HEAD" else (" M tracked.py" if case == "dirty" else ""))
    with pytest.raises(WP8ContractError):
        module._verify_runtime(policy, CANDIDATE, executable=python if case != "python" else tmp_path / "wrong-python",
            module_file=installed[0], preparation_module_file=installed[1], contract_module_file=installed[2], runner=runner)


def test_migration_projection_is_exact_candidate_and_never_executes(tmp_path, monkeypatch):
    import pdi.production_ops.cutover as trust
    from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint
    monkeypatch.setattr(trust, "trusted_path", lambda path, **_: not path.is_symlink() and path.exists())
    policy = SimpleNamespace(candidate_releases_root=tmp_path)
    root = tmp_path / CANDIDATE / "migrations"
    root.mkdir(parents=True)
    path = root / "env.py"
    path.write_text("raise RuntimeError('must never execute')")
    expected = contract_fingerprint({"migrations": [("migrations/env.py", hashlib.sha256(path.read_bytes()).hexdigest())]})
    assert module._migration_fingerprint(policy, CANDIDATE) == expected
    path.write_text("different bytes")
    assert module._migration_fingerprint(policy, CANDIDATE) != expected
    (root / "escape").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(WP8ContractError):
        module._migration_fingerprint(policy, CANDIDATE)


def test_only_fixed_read_only_legacy_units_are_queried():
    from pdi.production_ops.contracts import LEGACY
    calls = []
    class ReadOnly:
        def _read(self, action, unit):
            calls.append((action, unit))
            return SimpleNamespace(returncode=1 if action == "is-enabled" else 3,
                value="disabled" if action == "is-enabled" else "inactive")
    assert module._legacy_states(ReadOnly()) == ("DISABLED_INACTIVE", "DISABLED_INACTIVE")
    assert calls == [(action, name + ".timer") for name in LEGACY for action in ("is-enabled", "is-active")]


@pytest.mark.parametrize("value", ("enabled", "active", "not-found", "unknown"))
def test_legacy_unconfirmed_or_enabled_is_not_safe(value):
    systemd = SimpleNamespace(_read=lambda *_: SimpleNamespace(returncode=1, value=value))
    with pytest.raises(WP8ContractError):
        module._legacy_states(systemd)


def test_import_is_inert():
    script = '''
import pathlib, subprocess, socket, os
import pdi.production_ops.p3d_wp8_contracts
def forbidden(*a, **k):
    raise RuntimeError("IMPORT_SIDE_EFFECT")
pathlib.Path.read_text = forbidden
pathlib.Path.read_bytes = forbidden
pathlib.Path.open = forbidden
pathlib.Path.mkdir = forbidden
os.open = forbidden
subprocess.run = forbidden
socket.socket = forbidden
import pdi.production_ops.p3d_wp8_preflight
print("IMPORT_SIDE_EFFECTS=NONE")
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(module.__file__).parents[2])})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "IMPORT_SIDE_EFFECTS=NONE"


@pytest.fixture
def joined_authorities(tmp_path, monkeypatch):
    """Synthetic authority I/O only; run both real collection/join functions."""
    from pdi.production_ops import p3d_inert_asset_install as gate_c
    from pdi.production_ops.p3d_preparation_contracts import (
        GATE_A_TARGET_TOOL_ROLES, GateAPhase, GateBPhase, GateCPhase, PreparationGate, RollbackReleasePinV1,
        ToolName, contract_fingerprint,
    )
    from tests.test_p3d_pre_rehearsal_evidence import (
        _wire_success, _inputs, _metadata, H1, H3, H4, H5, PRINCIPAL,
    )
    from tests.test_p3d_preparation_contracts import release_pin_mapping, state_for, journal_event

    policy, systemd, _, marker = _wire_success(monkeypatch, tmp_path)
    policy.root = tmp_path
    policy.environment = tmp_path / "protected/pdi.env"
    policy.registry = tmp_path / "protected/registry.toml"
    policy.p3c_state = tmp_path / "protected/p3c-state.json"
    policy.physical = lambda path: tmp_path / path.lstrip("/")
    selected = _inputs()
    roots = {gate: tmp_path / f"authority-{index}" for index, gate in enumerate(PreparationGate)}
    states, journals = {}, {}
    for gate, operation_id in (
        (PreparationGate.ROLLBACK_QUALIFICATION, selected.gate_a_operation_id),
        (PreparationGate.RELEASE_STAGING, selected.gate_b_operation_id),
        (PreparationGate.INERT_ASSET_INSTALL, selected.gate_c_operation_id),
    ):
        root = roots[gate]
        root.mkdir()
        (root / "state-0001.json").write_bytes(b"synthetic state anchor")
        (root / "journal-0001.json").write_bytes(b"synthetic journal anchor")
        states[gate] = replace(state_for(gate, "COMPLETE"), operation_id=operation_id)
        phases, tool = {
            PreparationGate.ROLLBACK_QUALIFICATION: (GateAPhase, ToolName.RESTORE_QUALIFY),
            PreparationGate.RELEASE_STAGING: (GateBPhase, ToolName.RELEASE_BOOTSTRAP),
            PreparationGate.INERT_ASSET_INSTALL: (GateCPhase, ToolName.INERT_ASSET_INSTALL),
        }[gate]
        sequence = [phase.value for phase in phases if phase.value != "FAILED"]
        tools = {item.tool_name: item for item in states[gate].operator_tool_identities}
        events = []
        for index, (previous, current) in enumerate(zip(sequence, sequence[1:]), 1):
            role = next(iter(GATE_A_TARGET_TOOL_ROLES[current])) if gate is PreparationGate.ROLLBACK_QUALIFICATION else tool
            events.append(journal_event(gate=gate, sequence=index, from_state=previous, to_state=current,
                operation_id=operation_id, tool_name=role, tool_source_sha=tools[role].tool_source_sha))
        journals[gate] = tuple(events)

    monkeypatch.setattr(wp6, "_explicit_gate", lambda _policy, operation_id, *, gate, candidate:
                        (states[gate], journals[gate], roots[gate]))
    complete = roots[PreparationGate.INERT_ASSET_INSTALL] / "complete.json"
    protected = wp6._ProtectedSnapshot(1, 1, 1, H3, b"protected")
    p3c = replace(protected, sha256=H1)
    reads = []
    def protected_reader(path, *, policy, mode, gid):
        reads.append((path, mode, gid))
        return p3c if path == policy.p3c_state else protected
    monkeypatch.setattr(wp6, "_read_protected_bytes", protected_reader)
    monkeypatch.setattr(wp6, "_read_gate_c_marker", lambda *_:
                        (marker, contract_fingerprint(marker), protected, complete.parent))
    configuration = SimpleNamespace()
    monkeypatch.setattr(wp6, "_load_protected_configuration", lambda *_, **kw:
                        (configuration, PRINCIPAL, protected, protected))
    prerequisite = SimpleNamespace(
        rollback_metadata=_metadata(),
        rollback_metadata_sha256=marker.rollback_metadata_sha256,
        release_pin=RollbackReleasePinV1.from_mapping(release_pin_mapping()),
        gate_b_release_fingerprint=H,
        p3c_state_sha256=H1,
    )
    class PrerequisiteReader:
        def __init__(self, *_):
            pass
        def collect(self, *, home):
            assert home == complete.parent / "home"
            return prerequisite
        def verify_p3c_state_unchanged(self, actual):
            assert actual is prerequisite
    monkeypatch.setattr(wp6, "ProtectedPrerequisiteReader", PrerequisiteReader)
    monkeypatch.setattr(gate_c, "ProtectedPrerequisiteReader", PrerequisiteReader)
    monkeypatch.setattr(module, "_project_database", lambda actual, principal:
                        module._DatabaseProjection(H, H, H4, H, 2, marker.enabled_scope_fingerprint, H, H,
                                                   module.EXPECTED_ALEMBIC_REVISION))
    monkeypatch.setattr(module, "_migration_fingerprint", lambda *_: H)
    systemd._read = lambda action, unit: SimpleNamespace(
        returncode=1 if action == "is-enabled" else 3,
        value="disabled" if action == "is-enabled" else "inactive")
    return SimpleNamespace(policy=policy, inputs=selected, systemd=systemd, marker=marker,
        protected=protected, p3c=p3c, prerequisites=prerequisite, reads=reads, roots=roots,
        states=states, configuration=configuration, p3c_systemd=H5,
        run=lambda: module._collect(policy, selected, systemd, runtime_verifier=lambda *_: H))


def test_real_wp6_and_supplemental_join_are_deterministic(joined_authorities):
    fixture = joined_authorities
    first, second = fixture.run(), fixture.run()
    assert wp8_contract_bytes(first) == wp8_contract_bytes(second)
    assert first.invariant_baseline.db_identity_fingerprint == first.db_identity_fingerprint
    assert first.invariant_baseline.enabled_scope_fingerprint == first.enabled_scope_fingerprint
    assert first.runtime_pipeline_coverage == "0/6"
    assert first.invariant_baseline.p3d_timer_state == "DISABLED_INACTIVE"
    assert first.invariant_baseline.legacy_writer_state == "DISABLED_INACTIVE"
    assert first.invariant_baseline.legacy_enrichment_state == "DISABLED_INACTIVE"
    # Every installed unit/profile and every selected state/journal is anchored.
    from pdi.production_ops.p3d_preparation_contracts import CANONICAL_P3D_INSTALL_PATH_MODES
    observed = {path for path, _, _ in fixture.reads}
    assert {fixture.policy.physical(path) for path in CANONICAL_P3D_INSTALL_PATH_MODES} <= observed
    assert {root / name for root in fixture.roots.values()
            for name in ("state-0001.json", "journal-0001.json")} <= observed
    output = wp8_contract_bytes(first).decode()
    for raw in (str(fixture.policy.root), "synthetic-principal", "protected state anchor", "postgresql://"):
        assert raw not in output


@pytest.mark.parametrize("drift", ("registry", "database", "scopes", "asset", "current", "p3c-systemd"))
def test_real_wp6_rejection_stops_joined_projection(joined_authorities, monkeypatch, drift):
    fixture = joined_authorities
    from pdi.production_ops.p3d_inert_asset_install import SystemdSnapshot
    calls = []
    monkeypatch.setattr(module, "_project", lambda *_: calls.append("forbidden projection"))
    if drift == "registry":
        other = replace(fixture.protected, sha256="d" * 64)
        monkeypatch.setattr(wp6, "_load_protected_configuration", lambda *_, **kw:
                            (fixture.configuration, "synthetic-principal", other, other))
    elif drift in {"database", "scopes"}:
        original = wp6._collect_db_evidence
        monkeypatch.setattr(wp6, "_collect_db_evidence", lambda *_, **kw:
                            replace(original(), **({"identity_fingerprint": "d" * 64} if drift == "database"
                                else {"enabled_scope_ids": frozenset({str(UUID(int=99))})})))
    elif drift == "asset":
        altered = list(fixture.marker.installed_file_manifest)
        altered[0] = replace(altered[0], sha256="d" * 64)
        monkeypatch.setattr(wp6, "_fresh_installed_manifest", lambda _: tuple(altered))
    elif drift == "current":
        monkeypatch.setattr(wp6, "_current_target", lambda *_, **kw: "/opt/pdi/releases/" + CANDIDATE)
    else:
        fixture.systemd.value = SystemdSnapshot("d" * 64, H, True)
    with pytest.raises(WP8ContractError):
        fixture.run()
    assert calls == []


@pytest.mark.parametrize("drift", ("env", "p3c-state", "unit", "journal"))
def test_actual_projector_detects_in_window_protected_anchor_drift(joined_authorities, monkeypatch, drift):
    fixture = joined_authorities
    result = wp6.collect_pre_rehearsal_evidence(policy=fixture.policy, inputs=fixture.inputs,
        systemd=fixture.systemd, runtime_verifier=lambda *_: H)
    from pdi.production_ops.p3d_preparation_contracts import PreparationGate, CANONICAL_P3D_INSTALL_PATH_MODES
    target = {
        "env": fixture.policy.environment,
        "p3c-state": fixture.policy.p3c_state,
        "unit": fixture.policy.physical(next(iter(CANONICAL_P3D_INSTALL_PATH_MODES))),
        "journal": fixture.roots[PreparationGate.RELEASE_STAGING] / "journal-0001.json",
    }[drift]
    original = wp6._read_protected_bytes
    count = 0
    def reader(path, **kwargs):
        nonlocal count
        value = original(path, **kwargs)
        if path == target:
            count += 1
            if count > 1:
                return replace(value, inode=value.inode + 1)
        return value
    monkeypatch.setattr(wp6, "_read_protected_bytes", reader)
    with pytest.raises(WP8ContractError):
        module._project(fixture.policy, fixture.inputs, fixture.systemd, result)


def test_gate_binding_binds_operation_journal_and_artifact():
    from pdi.production_ops.p3d_preparation_contracts import PreparationGate
    from tests.test_p3d_preparation_contracts import state_for, journal_event
    gate = PreparationGate.RELEASE_STAGING
    state = state_for(gate, "COMPLETE")
    event = journal_event(sequence=1, from_state="FINAL_VERIFIED", to_state="COMPLETE")
    baseline = module._gate_binding("gate_b", state, (event,), {"release": H})
    assert module._gate_binding("gate_b", state, (event,), {"release": H}) == baseline
    assert module._gate_binding("gate_b", replace(state, operation_id=inputs().gate_b_operation_id),
                                (event,), {"release": H}) != baseline
    assert module._gate_binding("gate_b", state, (replace(event, evidence_fingerprints=("d" * 64,)),),
                                {"release": H}) != baseline
    assert module._gate_binding("gate_b", state, (event,), {"release": "d" * 64}) != baseline


@dataclass(frozen=True)
class _FilesystemMutationEntry:
    kind: int
    device: int
    inode: int
    links: int
    uid: int
    gid: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    content_sha256: str | None
    symlink_target: str | None


def _filesystem_mutation_snapshot(root: Path) -> dict[str, _FilesystemMutationEntry]:
    """Observe persistence, excluding read-access time and never following links.

    This is a local code-path check, not a proof against a privileged actor
    restoring every observable field. Content hashes also cover same-size
    rewrites and rewrites with restored mtime.
    """
    snapshot = {}
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        snapshot[str(path.relative_to(root))] = _FilesystemMutationEntry(
            kind=stat.S_IFMT(info.st_mode), device=info.st_dev,
            inode=info.st_ino, links=info.st_nlink,
            uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
            size=info.st_size, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
            content_sha256=(hashlib.sha256(path.read_bytes()).hexdigest()
                            if stat.S_ISREG(info.st_mode) else None),
            symlink_target=(os.readlink(path) if stat.S_ISLNK(info.st_mode) else None),
        )
    return snapshot


@pytest.mark.parametrize("kind", ("directory", "file"))
def test_mutation_snapshot_accepts_read_only_atime_change(tmp_path, monkeypatch, kind):
    file = tmp_path / "protected.json"
    file.write_bytes(b"synthetic protected content")
    before = _filesystem_mutation_snapshot(tmp_path)
    target = tmp_path if kind == "directory" else file
    original = Path.lstat

    def accessed(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path != target:
            return info
        # Model only the observed access-time delta: os.utime itself changes
        # ctime, and real read-atime behavior depends on the filesystem mount.
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields["st_atime"] += 60
        fields["st_atime_ns"] += 60_000_000_000
        return SimpleNamespace(**fields)

    monkeypatch.setattr(Path, "lstat", accessed)
    list(tmp_path.iterdir())
    file.read_bytes()
    assert target.lstat().st_atime_ns != original(target).st_atime_ns
    assert _filesystem_mutation_snapshot(tmp_path) == before


@pytest.mark.parametrize("attribute", (
    "st_dev", "st_ino", "st_nlink", "st_uid", "st_gid", "st_mode", "st_size",
    "st_mtime_ns", "st_ctime_ns",
))
def test_mutation_snapshot_rejects_safe_metadata_projection_drift(tmp_path, monkeypatch, attribute):
    file = tmp_path / "protected.json"
    file.write_bytes(b"synthetic protected content")
    before = _filesystem_mutation_snapshot(tmp_path)
    original = Path.lstat

    def changed(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path != file:
            return info
        # Ownership/ctime checks need no privileged chown or clock control.
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields[attribute] += 1
        return SimpleNamespace(**fields)

    monkeypatch.setattr(Path, "lstat", changed)
    assert _filesystem_mutation_snapshot(tmp_path) != before


@pytest.mark.parametrize("mutation", (
    "mtime", "mode", "same-size-content", "content-restored-mtime", "truncate",
    "new", "delete", "rename", "replace", "kind",
))
def test_mutation_snapshot_rejects_actual_filesystem_changes(tmp_path, mutation):
    root = tmp_path / "watched"
    root.mkdir()
    file = root / "protected.json"
    file.write_bytes(b"AAAA")
    file.chmod(0o644)
    before = _filesystem_mutation_snapshot(root)
    original = file.stat()
    if mutation == "mtime":
        os.utime(file, ns=(original.st_atime_ns, original.st_mtime_ns + 1_000_000_000))
    elif mutation == "mode":
        file.chmod(0o600)
    elif mutation in {"same-size-content", "content-restored-mtime"}:
        file.write_bytes(b"BBBB")
        if mutation == "content-restored-mtime":
            os.utime(file, ns=(original.st_atime_ns, original.st_mtime_ns))
    elif mutation == "truncate":
        file.write_bytes(b"A")
    elif mutation == "new":
        (root / "new.json").write_bytes(b"new")
    elif mutation == "delete":
        file.unlink()
    elif mutation == "rename":
        file.rename(root / "renamed.json")
    elif mutation == "replace":
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(b"AAAA")
        replacement.chmod(0o644)
        replacement.replace(file)
    else:
        file.unlink()
        file.mkdir()
    after = _filesystem_mutation_snapshot(root)
    assert after != before
    if mutation in {"new", "delete", "rename"}:
        assert set(after) != set(before)
    elif mutation == "replace":
        assert after[file.name].inode != before[file.name].inode
        assert after[file.name].content_sha256 == before[file.name].content_sha256
    elif mutation in {"same-size-content", "content-restored-mtime"}:
        assert after[file.name].size == before[file.name].size
        assert after[file.name].content_sha256 != before[file.name].content_sha256
        if mutation == "content-restored-mtime":
            assert after[file.name].mtime_ns == before[file.name].mtime_ns


def test_joined_collection_has_no_mutation_or_provider_path(joined_authorities, monkeypatch):
    import socket
    fixture = joined_authorities
    before = _filesystem_mutation_snapshot(fixture.policy.root)
    def forbidden(*_, **kw):
        pytest.fail("Phase A attempted mutation or Provider/workload invocation")
    for name in ("mkdir", "write_text", "write_bytes", "touch", "unlink", "rename", "replace", "symlink_to"):
        monkeypatch.setattr(Path, name, forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    fixture.run()
    after = _filesystem_mutation_snapshot(fixture.policy.root)
    assert before == after


def test_actual_identity_repository_reads_share_outer_connection(monkeypatch):
    """Verify the frozen helper's Sessions cannot escape a supplied Connection.

    This in-memory binding test complements the optional PostgreSQL isolation
    test; SQLite is not evidence of PostgreSQL READ ONLY enforcement.
    """
    from sqlalchemy import CheckConstraint, MetaData, create_engine, event, insert
    from pdi.repository.orm.provider_identity import ProviderInstanceORM, ProviderAccountORM, ObservationScopeORM
    from pdi.provider_identity import PostgreSQLProviderIdentityRepository
    from pdi.scoped_enrichment_profiles import derive_enabled_scope_ids
    from datetime import UTC, datetime
    engine = create_engine("sqlite://")
    metadata = MetaData()
    tables = tuple(orm.__table__.to_metadata(metadata) for orm in
                   (ProviderInstanceORM, ProviderAccountORM, ObservationScopeORM))
    instant = datetime.now(UTC)
    instance_id, account_id, scope_id = (UUID(letter * 32) for letter in "abc")
    # This test exercises real ORM SELECT/Session connection binding, not domain
    # conversion (SQLite loses timestamptz information). Retain loaded ORM rows.
    for conversion in ("_instance", "_account", "_scope"):
        monkeypatch.setattr(PostgreSQLProviderIdentityRepository, conversion, staticmethod(lambda row: row))
    # SQLite cannot parse the PostgreSQL regex CHECK expressions. Only these
    # local test-table clones omit them; frozen ORM/schema authority is intact.
    for table in tables:
        for constraint in tuple(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
        table.create(engine)
    with engine.begin() as fixture:
        fixture.execute(insert(tables[0]), dict(id=instance_id, provider_type="nextcloud", instance_key="synthetic",
            enabled=True, created_at=instant, updated_at=instant))
        fixture.execute(insert(tables[1]), dict(id=account_id, provider_instance_id=instance_id, account_key="synthetic",
            enabled=True, created_at=instant, updated_at=instant))
        fixture.execute(insert(tables[2]), dict(id=scope_id, provider_instance_id=instance_id,
            provider_account_id=account_id, scope_key="synthetic", enabled=True, created_at=instant, updated_at=instant))
    observed = []
    event.listen(engine, "before_execute", lambda connection, *args: observed.append(connection))
    with engine.connect() as connection:
        transaction = connection.begin()
        assert derive_enabled_scope_ids(connection) == {scope_id}
        assert transaction.is_active
        assert observed and all(selected is connection for selected in observed)
        transaction.rollback()
    engine.dispose()


@pytest.mark.parametrize("asset", ("release", "interpreter-parent", "phase-a", "wp6", "contracts", "source"))
def test_runtime_rejects_untrusted_candidate_assets(tmp_path, monkeypatch, asset):
    import pdi.production_ops.cutover as trust
    policy, python, sources, installed = runtime_tree(tmp_path, monkeypatch)
    target = {
        "release": policy.candidate_releases_root / CANDIDATE,
        "interpreter-parent": python.parent, "phase-a": installed[0], "wp6": installed[1],
        "contracts": installed[2], "source": sources[0],
    }[asset]
    original = trust.trusted_path
    monkeypatch.setattr(trust, "trusted_path", lambda path, **kw: path != target and original(path, **kw))
    with pytest.raises(WP8ContractError):
        module._verify_runtime(policy, CANDIDATE, executable=python, module_file=installed[0],
            preparation_module_file=installed[1], contract_module_file=installed[2],
            runner=lambda argv, **_: SimpleNamespace(returncode=0, stdout=CANDIDATE if argv[-1] == "HEAD" else ""))


def test_runtime_rejects_symlinked_imported_module(tmp_path, monkeypatch):
    policy, python, sources, installed = runtime_tree(tmp_path, monkeypatch)
    installed[0].unlink()
    installed[0].symlink_to(sources[0])
    with pytest.raises(WP8ContractError):
        module._verify_runtime(policy, CANDIDATE, executable=python, module_file=installed[0],
            preparation_module_file=installed[1], contract_module_file=installed[2])
