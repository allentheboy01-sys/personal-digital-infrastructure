from dataclasses import FrozenInstanceError
from pathlib import Path
import asyncio
import inspect

import pytest
from sqlalchemy.exc import SQLAlchemyError

from pdi.consumer import (
    PrincipalBoundConsumerRuntimeFactory,
    TrustedPrincipalContext,
)
from pdi.principal import (
    DatabaseBindingRegistry,
    DatabaseBindingRecord,
    DisabledPrincipalError,
    PrincipalDatabaseRouter,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
    UnknownDatabaseBindingError,
    UnknownPrincipalError,
)


def _router(*records: PrincipalRecord) -> PrincipalDatabaseRouter:
    return PrincipalDatabaseRouter(
        PrincipalRegistry(records), DatabaseBindingRegistry((), {})
    )


def test_trusted_principal_context_is_validated_and_immutable() -> None:
    context = TrustedPrincipalContext(PrincipalId("principal-a"))
    with pytest.raises(FrozenInstanceError):
        context.principal_id = PrincipalId("principal-b")
    with pytest.raises(TypeError):
        TrustedPrincipalContext("principal-a")


@pytest.mark.parametrize(
    ("context", "router", "error"),
    [
        (
            TrustedPrincipalContext(PrincipalId("unknown")),
            _router(),
            UnknownPrincipalError,
        ),
        (
            TrustedPrincipalContext(PrincipalId("disabled")),
            _router(
                PrincipalRecord(PrincipalId("disabled"), "disabled-db", False)
            ),
            DisabledPrincipalError,
        ),
        (
            TrustedPrincipalContext(PrincipalId("missing-binding")),
            _router(
                PrincipalRecord(
                    PrincipalId("missing-binding"), "missing-database"
                )
            ),
            UnknownDatabaseBindingError,
        ),
    ],
)
def test_routing_failure_occurs_before_engine_creation(
    context, router, error
) -> None:
    called = False

    def forbidden_engine(_url):
        nonlocal called
        called = True
        raise AssertionError("engine must not be created")

    factory = PrincipalBoundConsumerRuntimeFactory(
        router, engine_factory=forbidden_engine
    )
    with pytest.raises(error):
        factory.bind(context)
    assert called is False


def test_generic_consumer_package_has_no_mcp_dependency() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "pdi" / "consumer"
    assert "pdi_mcp" not in "\n".join(
        path.read_text() for path in root.glob("*.py")
    )


def test_consumer_factory_has_no_database_selector_or_global_settings() -> None:
    parameters = set(
        inspect.signature(PrincipalBoundConsumerRuntimeFactory.bind).parameters
    )
    assert parameters == {"self", "context"}
    source = "\n".join(
        path.read_text()
        for path in (
            Path(__file__).resolve().parents[1] / "src" / "pdi" / "consumer"
        ).glob("*.py")
    )
    assert "load_database_url" not in source
    assert "load_immich_settings" not in source
    assert "load_nextcloud_settings" not in source


def test_missing_trusted_context_is_denied_before_routing() -> None:
    with pytest.raises(TypeError, match="trusted Principal context"):
        PrincipalBoundConsumerRuntimeFactory(_bound_router()).bind(None)


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _Engine:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.disposed = 0

    def connect(self):
        if self.error is not None:
            raise self.error
        return _Connection()

    def dispose(self) -> None:
        self.disposed += 1


class _AccessRuntime:
    def __init__(self, principal_id: PrincipalId) -> None:
        self.principal_id = principal_id
        self.representation_service = f"representation:{principal_id}"
        self.text_service = f"text:{principal_id}"
        self.closed = 0

    async def aclose(self) -> None:
        self.closed += 1


class _AccessFactory:
    def __init__(self) -> None:
        self.runtimes = []

    def build(self, principal_id: PrincipalId):
        runtime = _AccessRuntime(principal_id)
        self.runtimes.append(runtime)
        return runtime


def _bound_router() -> PrincipalDatabaseRouter:
    return PrincipalDatabaseRouter(
        PrincipalRegistry(
            (
                PrincipalRecord(PrincipalId("principal-a"), "database-a"),
                PrincipalRecord(PrincipalId("principal-b"), "database-b"),
            )
        ),
        DatabaseBindingRegistry(
            (
                DatabaseBindingRecord("database-a", "DATABASE_A_URL"),
                DatabaseBindingRecord("database-b", "DATABASE_B_URL"),
            ),
            {
                "DATABASE_A_URL": "postgresql://runtime:synthetic@db/a",
                "DATABASE_B_URL": "postgresql://runtime:synthetic@db/b",
            },
        ),
    )


def test_runtime_is_immutable_read_only_and_access_is_principal_bound() -> None:
    engines = []
    access = _AccessFactory()

    def engine_factory(_url):
        engine = _Engine()
        engines.append(engine)
        return engine

    factory = PrincipalBoundConsumerRuntimeFactory(
        _bound_router(),
        scoped_access_factory=access,
        engine_factory=engine_factory,
    )
    runtimes = tuple(
        factory.bind(TrustedPrincipalContext(PrincipalId(name)))
        for name in ("principal-a", "principal-b")
    )
    assert runtimes[0].resource_access_service == "representation:principal-a"
    assert runtimes[1].resource_access_service == "representation:principal-b"
    with pytest.raises(FrozenInstanceError):
        runtimes[0].principal_context = runtimes[1].principal_context
    forbidden = {
        "sync",
        "bootstrap",
        "recover",
        "reconcile",
        "publish",
        "create_scope",
        "provision_database",
        "backfill",
        "switch_principal",
        "select_database",
        "select_scope",
    }
    assert not (set(dir(runtimes[0])) & forbidden)

    asyncio.run(runtimes[0].aclose())
    asyncio.run(runtimes[0].aclose())
    assert engines[0].disposed == 1
    assert access.runtimes[0].closed == 1
    assert engines[1].disposed == 0
    assert access.runtimes[1].closed == 0
    asyncio.run(runtimes[1].aclose())


def test_database_connection_error_is_sanitized() -> None:
    secret = "postgresql://user:DO_NOT_DISCLOSE@example/personal"
    engine = _Engine(error=SQLAlchemyError(secret))
    factory = PrincipalBoundConsumerRuntimeFactory(
        _bound_router(), engine_factory=lambda _url: engine
    )
    with pytest.raises(Exception) as caught:
        factory.bind(TrustedPrincipalContext(PrincipalId("principal-a")))
    assert secret not in str(caught.value)
    assert "DO_NOT_DISCLOSE" not in repr(caught.value)
    assert engine.disposed == 1
