from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Engine

from pdi.adapters.base import Adapter
from pdi.database import create_postgres_engine
from pdi.engine import SyncEngine
from pdi.identity import Matcher
from pdi.principal import PrincipalDatabaseRouter, PrincipalId
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.repository import PostgreSQLRepository
from pdi.scope_sync_state import PostgreSQLScopeSyncStateRepository

from .context import ObservationContext
from .errors import (
    ScopedIdentityUnavailableError,
    ScopedProviderMismatchError,
)
from .repository import ScopeBoundRepository
from .state import ScopeBoundProviderSyncStateRepository


@dataclass(slots=True)
class ScopedIngestionRuntime:
    context: ObservationContext
    engine: Engine
    repository: ScopeBoundRepository
    state_repository: ScopeBoundProviderSyncStateRepository
    sync_engine: SyncEngine

    def close(self) -> None:
        self.engine.dispose()

    def __enter__(self) -> "ScopedIngestionRuntime":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ScopedIngestionRuntimeFactory:
    """Trusted Principal -> Personal DB -> Scope composition boundary."""

    def __init__(
        self,
        router: PrincipalDatabaseRouter,
        *,
        engine_factory: Callable[[str], Engine] = create_postgres_engine,
    ) -> None:
        self._router = router
        self._engine_factory = engine_factory

    def build(
        self,
        principal_id: PrincipalId | str | None,
        observation_scope_id: UUID,
        adapter: Adapter,
    ) -> ScopedIngestionRuntime:
        binding = self._router.resolve(principal_id)
        parsed_principal = (
            principal_id
            if isinstance(principal_id, PrincipalId)
            else PrincipalId(principal_id or "")
        )
        engine = self._engine_factory(binding.database_url)
        try:
            identities = PostgreSQLProviderIdentityRepository(engine)
            scope = identities.get_scope(observation_scope_id)
            if scope is None:
                raise ScopedIdentityUnavailableError(
                    "Observation Scope is unavailable in the Personal DB"
                )
            instance = identities.get_instance(scope.provider_instance_id)
            if instance is None or not instance.enabled:
                raise ScopedIdentityUnavailableError(
                    "Provider Instance is missing or disabled"
                )
            if not scope.enabled:
                raise ScopedIdentityUnavailableError(
                    "Observation Scope is disabled"
                )
            account = None
            if scope.provider_account_id is not None:
                account = identities.get_account(scope.provider_account_id)
                if (
                    account is None
                    or not account.enabled
                    or account.provider_instance_id != instance.id
                ):
                    raise ScopedIdentityUnavailableError(
                        "Provider Account is missing, disabled, or inconsistent"
                    )
            if adapter.provider_name != instance.provider_type:
                raise ScopedProviderMismatchError(
                    "Adapter Provider does not match Observation Scope"
                )
            context = ObservationContext(
                principal_id=parsed_principal,
                observation_scope_id=scope.id,
                provider_instance_id=instance.id,
                provider_account_id=(None if account is None else account.id),
                provider_type=instance.provider_type,
            )
            repository = ScopeBoundRepository(
                PostgreSQLRepository(engine), context
            )
            state_repository = ScopeBoundProviderSyncStateRepository(
                PostgreSQLScopeSyncStateRepository(engine), context
            )
            sync_engine = SyncEngine(
                adapter,
                Matcher(),
                repository,
                state_repository,
            )
            return ScopedIngestionRuntime(
                context=context,
                engine=engine,
                repository=repository,
                state_repository=state_repository,
                sync_engine=sync_engine,
            )
        except Exception:
            engine.dispose()
            raise
