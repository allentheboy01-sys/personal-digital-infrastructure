"""Protected-file configuration for principal-bound formal operations."""

from collections.abc import Mapping
from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from uuid import UUID

from pdi.principal import PrincipalDatabaseRouter, PrincipalId, load_registries


class ScopedOperatorConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ScopedProviderBinding:
    principal_id: PrincipalId
    observation_scope_id: UUID
    provider_type: str
    endpoint: str
    secret_env: str = field(repr=False)
    username: str | None = None


@dataclass(frozen=True, slots=True)
class ScopedOperatorConfiguration:
    router: PrincipalDatabaseRouter
    bindings: Mapping[tuple[PrincipalId, UUID], ScopedProviderBinding]
    environment: Mapping[str, str] = field(repr=False)

    def resolve(
        self, principal_id: PrincipalId, scope_id: UUID, provider_type: str
    ) -> tuple[ScopedProviderBinding, str]:
        binding = self.bindings.get((principal_id, scope_id))
        if binding is None or binding.provider_type != provider_type:
            raise ScopedOperatorConfigurationError(
                "Provider binding is unavailable for Principal and Scope"
            )
        secret = self.environment.get(binding.secret_env)
        if not secret:
            raise ScopedOperatorConfigurationError(
                "Provider binding secret is unavailable"
            )
        return binding, secret


def load_scoped_operator_configuration(
    path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> ScopedOperatorConfiguration:
    environment = os.environ if environment is None else environment
    principals, databases = load_registries(path, environment=environment)
    try:
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
        raw = data.get("provider_bindings", [])
        if not isinstance(raw, list):
            raise TypeError
        indexed: dict[tuple[PrincipalId, UUID], ScopedProviderBinding] = {}
        for item in raw:
            if not isinstance(item, dict):
                raise TypeError
            binding = ScopedProviderBinding(
                principal_id=PrincipalId(item["principal_id"]),
                observation_scope_id=UUID(item["scope_id"]),
                provider_type=item["provider_type"],
                endpoint=item["endpoint"],
                username=item.get("username"),
                secret_env=item["secret_env"],
            )
            key = (binding.principal_id, binding.observation_scope_id)
            if key in indexed:
                raise ValueError
            if binding.provider_type not in {"nextcloud", "immich"}:
                raise ValueError
            if not binding.endpoint.startswith(("http://", "https://")):
                raise ValueError
            if (
                not binding.secret_env
                or binding.secret_env.upper() != binding.secret_env
                or not binding.secret_env.replace("_", "").isalnum()
            ):
                raise ValueError
            if binding.provider_type == "nextcloud" and not binding.username:
                raise ValueError
            indexed[key] = binding
    except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        raise ScopedOperatorConfigurationError(
            "Scoped operator configuration is invalid"
        ) from error
    return ScopedOperatorConfiguration(
        PrincipalDatabaseRouter(principals, databases), indexed, environment
    )
