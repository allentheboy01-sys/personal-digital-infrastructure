"""Principal-bound, read-only PDI consumer composition."""

from dataclasses import dataclass, field
from typing import Callable, Protocol

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from pdi.database import create_postgres_engine
from pdi.observation import PostgreSQLObservationRepository
from pdi.principal import (
    PersonalDatabaseUnavailableError,
    PrincipalDatabaseRouter,
    PrincipalId,
)
from pdi.query import QueryService
from pdi.repository import PostgreSQLRepository
from pdi.resource_query import ResourceQueryService
from pdi.rich_retrieval import RichRetrievalService

from .models import TrustedPrincipalContext


class ScopedAccessRuntime(Protocol):
    principal_id: PrincipalId
    representation_service: object
    text_service: object

    async def aclose(self) -> None: ...


class ScopedAccessRuntimeFactory(Protocol):
    def build(self, principal_id: PrincipalId) -> ScopedAccessRuntime: ...


class ObservationReader:
    """Read-only projection of the Observation service contract."""

    def __init__(self, repository: PostgreSQLObservationRepository) -> None:
        self._repository = repository

    def get_resource_statements(
        self,
        resource_ref: str,
        *,
        predicate: str | None = None,
        include_history: bool = False,
        limit: int = 100,
    ):
        from pdi.observation import ObservationService

        return ObservationService(self._repository).get_resource_statements(
            resource_ref,
            predicate=predicate,
            include_history=include_history,
            limit=limit,
        )


@dataclass(slots=True)
class _CloseState:
    closed: bool = False


@dataclass(frozen=True, slots=True)
class PrincipalBoundConsumerRuntime:
    """Read-only capabilities permanently bound to one Personal database."""

    principal_context: TrustedPrincipalContext
    query_service: QueryService
    observation_reader: ObservationReader
    rich_retrieval_service: RichRetrievalService
    resource_query_service: ResourceQueryService
    resource_text_service: object | None
    resource_access_service: object | None
    _engine: Engine = field(repr=False, compare=False)
    _access_runtime: ScopedAccessRuntime | None = field(
        default=None, repr=False, compare=False
    )
    _close_state: _CloseState = field(
        default_factory=_CloseState, repr=False, compare=False
    )

    @property
    def principal_id(self) -> PrincipalId:
        return self.principal_context.principal_id

    @property
    def closed(self) -> bool:
        return self._close_state.closed

    async def aclose(self) -> None:
        if self._close_state.closed:
            return
        self._close_state.closed = True
        try:
            if self._access_runtime is not None:
                await self._access_runtime.aclose()
        finally:
            self._engine.dispose()

    async def __aenter__(self) -> "PrincipalBoundConsumerRuntime":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()


class PrincipalBoundConsumerRuntimeFactory:
    """Trusted Principal -> routed Personal DB -> read-only runtime."""

    def __init__(
        self,
        router: PrincipalDatabaseRouter,
        *,
        scoped_access_factory: ScopedAccessRuntimeFactory | None = None,
        engine_factory: Callable[[str], Engine] = create_postgres_engine,
    ) -> None:
        self._router = router
        self._scoped_access_factory = scoped_access_factory
        self._engine_factory = engine_factory

    def bind(
        self, context: TrustedPrincipalContext
    ) -> PrincipalBoundConsumerRuntime:
        if not isinstance(context, TrustedPrincipalContext):
            raise TypeError("trusted Principal context is required")
        binding = self._router.resolve(context.principal_id)
        engine = self._engine_factory(binding.database_url)
        access_runtime = None
        try:
            with engine.connect():
                pass
            repository = PostgreSQLRepository(engine)
            query = QueryService(repository)
            rich = RichRetrievalService(repository, retrieval_service=None)
            if self._scoped_access_factory is not None:
                access_runtime = self._scoped_access_factory.build(
                    context.principal_id
                )
                if access_runtime.principal_id != context.principal_id:
                    raise RuntimeError("scoped access Principal mismatch")
            return PrincipalBoundConsumerRuntime(
                principal_context=context,
                query_service=query,
                observation_reader=ObservationReader(
                    PostgreSQLObservationRepository(engine)
                ),
                rich_retrieval_service=rich,
                resource_query_service=ResourceQueryService(query, rich),
                resource_text_service=(
                    None if access_runtime is None else access_runtime.text_service
                ),
                resource_access_service=(
                    None
                    if access_runtime is None
                    else access_runtime.representation_service
                ),
                _engine=engine,
                _access_runtime=access_runtime,
            )
        except SQLAlchemyError:
            engine.dispose()
            raise PersonalDatabaseUnavailableError(
                "Personal database is unavailable"
            ) from None
        except Exception:
            engine.dispose()
            if access_runtime is not None:
                access_engine = getattr(access_runtime, "engine", None)
                dispose = getattr(access_engine, "dispose", None)
                if dispose is not None:
                    dispose()
            raise
