"""Principal-bound Resource Access composition and Scope credential routing."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

import anyio
from sqlalchemy import Engine

from pdi.database import create_postgres_engine
from pdi.principal import PrincipalDatabaseRouter, PrincipalId
from pdi.provider_identity import (
    PostgreSQLProviderIdentityRepository,
    ProviderIdentityRepository,
)
from pdi.repository import PostgreSQLRepository

from .errors import ResourceAccessUnavailableError
from .models import ResourceAccessSource
from .provider import ProviderRepresentationAdapter
from .service import ResourceAccessService
from .text_models import TextResourceAccessSource
from .text_provider import ProviderTextAdapter
from .text_service import ResourceTextService


def _binding_key(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError("binding_ref must be a non-empty opaque identifier")
    if any(character.isspace() or ord(character) < 33 for character in value):
        raise ValueError("binding_ref must be a non-empty opaque identifier")
    return value


@dataclass(frozen=True, slots=True)
class ProviderAccessBinding:
    """Non-secret control-plane authorization for one Principal and Scope."""

    principal_id: PrincipalId
    observation_scope_id: UUID
    provider_type: str
    binding_ref: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, PrincipalId):
            raise ValueError("principal_id must be a PrincipalId")
        if not isinstance(self.observation_scope_id, UUID):
            raise ValueError("observation_scope_id must be a UUID")
        if not isinstance(self.provider_type, str) or not self.provider_type:
            raise ValueError("provider_type must be non-empty")
        object.__setattr__(self, "binding_ref", _binding_key(self.binding_ref))
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")


@dataclass(frozen=True, slots=True)
class ProviderAccessMaterial:
    """Protected runtime material whose value is never rendered in repr."""

    value: object = field(repr=False, compare=False)


class ProviderAccessSecretResolver(Protocol):
    def resolve(self, binding_ref: str) -> ProviderAccessMaterial: ...


class ProviderAccessBindingRegistry:
    """Exact, fail-closed `(Principal, Scope)` access-binding registry."""

    def __init__(self, bindings: Iterable[ProviderAccessBinding]) -> None:
        indexed: dict[tuple[PrincipalId, UUID], ProviderAccessBinding] = {}
        for binding in bindings:
            key = (binding.principal_id, binding.observation_scope_id)
            if key in indexed:
                raise ValueError("duplicate Principal/Scope access binding")
            indexed[key] = binding
        self._bindings = indexed

    def resolve(
        self,
        principal_id: PrincipalId,
        observation_scope_id: UUID,
        provider_type: str,
    ) -> ProviderAccessBinding:
        binding = self._bindings.get((principal_id, observation_scope_id))
        if binding is None:
            raise ResourceAccessUnavailableError(
                "Resource access binding is unavailable"
            )
        if not binding.enabled:
            raise ResourceAccessUnavailableError(
                "Resource access binding is disabled"
            )
        if binding.provider_type != provider_type:
            raise ResourceAccessUnavailableError(
                "Resource access binding Provider does not match Source Scope"
            )
        return binding


RepresentationAdapterFactory = Callable[
    [ProviderAccessBinding, ProviderAccessMaterial],
    ProviderRepresentationAdapter,
]
TextAdapterFactory = Callable[
    [ProviderAccessBinding, ProviderAccessMaterial], ProviderTextAdapter
]


class ScopeResourceAccessAdapterResolver:
    """Resolve exactly one adapter from actual Source Scope provenance."""

    def __init__(
        self,
        principal_id: PrincipalId,
        identities: ProviderIdentityRepository,
        bindings: ProviderAccessBindingRegistry,
        secrets: ProviderAccessSecretResolver,
        *,
        representation_factories: Mapping[str, RepresentationAdapterFactory],
        text_factories: Mapping[str, TextAdapterFactory],
    ) -> None:
        self._principal_id = principal_id
        self._identities = identities
        self._bindings = bindings
        self._secrets = secrets
        self._representation_factories = dict(representation_factories)
        self._text_factories = dict(text_factories)
        self._owned_adapters: list[object] = []

    async def resolve_representation_adapter(
        self, source: ResourceAccessSource
    ) -> ProviderRepresentationAdapter:
        binding = await anyio.to_thread.run_sync(
            self._validated_binding,
            source.provider,
            source.observation_scope_id,
        )
        factory = self._representation_factories.get(source.provider)
        if factory is None:
            raise ResourceAccessUnavailableError(
                "Scoped representation access is not configured"
            )
        adapter = self._build(factory, binding)
        self._owned_adapters.append(adapter)
        if adapter.provider != source.provider:
            raise ResourceAccessUnavailableError(
                "Resolved representation adapter Provider is inconsistent"
            )
        return adapter

    async def resolve_text_adapter(
        self, source: TextResourceAccessSource
    ) -> ProviderTextAdapter:
        binding = await anyio.to_thread.run_sync(
            self._validated_binding,
            source.provider,
            source.observation_scope_id,
        )
        factory = self._text_factories.get(source.provider)
        if factory is None:
            raise ResourceAccessUnavailableError(
                "Scoped text access is not configured"
            )
        adapter = self._build(factory, binding)
        self._owned_adapters.append(adapter)
        if adapter.provider != source.provider:
            raise ResourceAccessUnavailableError(
                "Resolved text adapter Provider is inconsistent"
            )
        return adapter

    def _validated_binding(
        self, provider: str, raw_scope_id: str | None
    ) -> ProviderAccessBinding:
        if raw_scope_id is None:
            raise ResourceAccessUnavailableError(
                "Legacy Source has no Resource Access Scope provenance"
            )
        try:
            scope_id = UUID(raw_scope_id)
        except (TypeError, ValueError, AttributeError):
            raise ResourceAccessUnavailableError(
                "Source Scope provenance is invalid"
            ) from None
        scope = self._identities.get_scope(scope_id)
        if scope is None or not scope.enabled:
            raise ResourceAccessUnavailableError(
                "Observation Scope is missing or disabled"
            )
        instance = self._identities.get_instance(scope.provider_instance_id)
        if instance is None or not instance.enabled:
            raise ResourceAccessUnavailableError(
                "Provider Instance is missing or disabled"
            )
        if provider != instance.provider_type:
            raise ResourceAccessUnavailableError(
                "Source Provider does not match Observation Scope"
            )
        if scope.provider_account_id is not None:
            account = self._identities.get_account(scope.provider_account_id)
            if (
                account is None
                or not account.enabled
                or account.provider_instance_id != instance.id
            ):
                raise ResourceAccessUnavailableError(
                    "Provider Account is missing, disabled, or inconsistent"
                )
        return self._bindings.resolve(
            self._principal_id, scope.id, instance.provider_type
        )

    def _build(self, factory: Callable, binding: ProviderAccessBinding):
        try:
            material = self._secrets.resolve(binding.binding_ref)
            if not isinstance(material, ProviderAccessMaterial):
                raise TypeError
            return factory(binding, material)
        except ResourceAccessUnavailableError:
            raise
        except Exception:
            raise ResourceAccessUnavailableError(
                "Provider access material or adapter is unavailable"
            ) from None

    async def aclose(self) -> None:
        adapters, self._owned_adapters = self._owned_adapters, []
        for adapter in adapters:
            close = getattr(adapter, "aclose", None)
            if close is not None:
                await close()


@dataclass(slots=True)
class ScopedResourceAccessRuntime:
    principal_id: PrincipalId
    engine: Engine
    representation_service: ResourceAccessService
    text_service: ResourceTextService
    _resolver: ScopeResourceAccessAdapterResolver
    _closed: bool = field(default=False, init=False)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._resolver.aclose()
        finally:
            self.engine.dispose()

    async def __aenter__(self) -> "ScopedResourceAccessRuntime":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()


class ScopedResourceAccessRuntimeFactory:
    """Trusted Principal -> Personal DB -> scoped Resource Access boundary."""

    def __init__(
        self,
        router: PrincipalDatabaseRouter,
        bindings: ProviderAccessBindingRegistry,
        secrets: ProviderAccessSecretResolver,
        *,
        representation_factories: Mapping[str, RepresentationAdapterFactory],
        text_factories: Mapping[str, TextAdapterFactory],
        engine_factory: Callable[[str], Engine] = create_postgres_engine,
    ) -> None:
        self._router = router
        self._bindings = bindings
        self._secrets = secrets
        self._representation_factories = representation_factories
        self._text_factories = text_factories
        self._engine_factory = engine_factory

    def build(
        self, principal_id: PrincipalId | str | None
    ) -> ScopedResourceAccessRuntime:
        database = self._router.resolve(principal_id)
        parsed_principal = (
            principal_id
            if isinstance(principal_id, PrincipalId)
            else PrincipalId(principal_id or "")
        )
        engine = self._engine_factory(database.database_url)
        try:
            repository = PostgreSQLRepository(engine)
            resolver = ScopeResourceAccessAdapterResolver(
                parsed_principal,
                PostgreSQLProviderIdentityRepository(engine),
                self._bindings,
                self._secrets,
                representation_factories=self._representation_factories,
                text_factories=self._text_factories,
            )
            return ScopedResourceAccessRuntime(
                principal_id=parsed_principal,
                engine=engine,
                representation_service=ResourceAccessService(
                    repository, adapter_resolver=resolver
                ),
                text_service=ResourceTextService(
                    repository, adapter_resolver=resolver
                ),
                _resolver=resolver,
            )
        except Exception:
            engine.dispose()
            raise
