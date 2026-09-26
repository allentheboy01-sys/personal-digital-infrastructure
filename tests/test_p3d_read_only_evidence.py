from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.engine import make_url

from pdi.production_ops.enrichment_cutover import P3DControlRefused
from pdi.production_ops.p3d_evidence import RoutedPersonalDatabaseEvidenceReader


class _Transaction:
    def __init__(self):
        self.is_active = True
        self.rolled_back = False

    def rollback(self):
        self.is_active = False
        self.rolled_back = True


class _Rows:
    def __init__(self, *, one=None, all_rows=None):
        self._one = one
        self._all = all_rows

    def one(self):
        return self._one

    def all(self):
        return self._all


class _ReadOnlyConnection:
    def __init__(self, *, read_only="on"):
        self.read_only = read_only
        self.transaction = _Transaction()
        self.statements = []

    def begin(self):
        return self.transaction

    def execute(self, statement, *_args, **_kwargs):
        sql = str(statement)
        self.statements.append(sql)
        if sql == "SET TRANSACTION READ ONLY":
            return _Rows()
        if "observation_scope_sync_state" in sql:
            return _Rows(one=(2, 2, 2))
        if "GROUP BY provider" in sql:
            return _Rows(all_rows=[
                ("nextcloud", 1), ("immich", 1), ("gmail", 1),
                ("integration-test", 1),
            ])
        raise AssertionError(f"unexpected execute: {sql}")

    def scalar(self, statement, *_args, **_kwargs):
        sql = str(statement)
        self.statements.append(sql)
        if sql == "SHOW transaction_read_only":
            return self.read_only
        if "alembic_version" in sql:
            return "e5a7b9d1f324"
        if "count(*)" in sql:
            return 0
        raise AssertionError(f"unexpected scalar: {sql}")


class _ConnectionContext:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_args):
        return False


class _Engine:
    def __init__(self, url, connection):
        self.url = make_url(url)
        self.connection = connection

    def connect(self):
        return _ConnectionContext(self.connection)


def _identities():
    values = []
    for provider, enabled, has_account in (
        ("nextcloud", True, True),
        ("immich", True, True),
        ("gmail", False, False),
        ("integration-test", False, False),
    ):
        instance_id = uuid4()
        account_id = uuid4() if has_account else None
        instance = SimpleNamespace(id=instance_id, provider_type=provider, enabled=enabled)
        accounts = (() if account_id is None else (
            SimpleNamespace(id=account_id, enabled=True),
        ))
        scope = SimpleNamespace(
            id=uuid4(), enabled=enabled, provider_account_id=account_id
        )
        values.append((instance, accounts, (scope,)))
    return values


def test_routed_evidence_uses_one_verified_read_only_connection_for_all_queries():
    url = "postgresql+psycopg://synthetic:password@db.invalid/personal"
    connection = _ReadOnlyConnection()
    engine = _Engine(url, connection)
    identities = _identities()
    used_connections = []

    class Repository:
        def list_instances(self):
            return tuple(item[0] for item in identities)

        def list_accounts_for_instance(self, instance_id):
            return next(item[1] for item in identities if item[0].id == instance_id)

        def list_scopes_for_instance(self, instance_id):
            return next(item[2] for item in identities if item[0].id == instance_id)

    def repository_factory(actual_connection):
        used_connections.append(actual_connection)
        return Repository()

    def scope_deriver(actual_connection):
        used_connections.append(actual_connection)
        return {item[2][0].id for item in identities if item[0].enabled}

    router = SimpleNamespace(resolve=lambda _principal: SimpleNamespace(
        database_url=url, database_ref="personal-db"
    ))
    evidence = RoutedPersonalDatabaseEvidenceReader(
        router,
        engine,
        principal_ref="synthetic-principal",
        identity_repository_factory=repository_factory,
        scope_id_deriver=scope_deriver,
    ).collect()

    assert evidence.transaction_read_only is True
    assert used_connections == [connection, connection]
    assert connection.statements[0] == "SET TRANSACTION READ ONLY"
    assert connection.statements[1] == "SHOW transaction_read_only"
    assert connection.transaction.rolled_back is True


def test_routed_evidence_fails_closed_when_transaction_is_not_read_only():
    url = "postgresql+psycopg://synthetic:password@db.invalid/personal"
    connection = _ReadOnlyConnection(read_only="off")
    engine = _Engine(url, connection)
    router = SimpleNamespace(resolve=lambda _principal: SimpleNamespace(
        database_url=url, database_ref="personal-db"
    ))

    with pytest.raises(P3DControlRefused, match="READ_ONLY_TRANSACTION_REQUIRED"):
        RoutedPersonalDatabaseEvidenceReader(
            router, engine, principal_ref="synthetic-principal"
        ).collect()

    assert connection.transaction.rolled_back is True
