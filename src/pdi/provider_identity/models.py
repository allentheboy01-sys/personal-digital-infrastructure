"""Provider-neutral identity and observation-scope domain models."""

from dataclasses import dataclass
from datetime import UTC, datetime
import re
from uuid import UUID


_OPAQUE_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def canonical_key(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_KEY.fullmatch(value):
        raise ValueError(f"{field_name} must be a canonical opaque key")
    return value


def optional_label(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty when present")
    return value.strip()


def utc_instant(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ProviderInstance:
    id: UUID
    provider_type: str
    instance_key: str
    display_label: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_type", canonical_key(self.provider_type, "provider_type"))
        object.__setattr__(self, "instance_key", canonical_key(self.instance_key, "instance_key"))
        object.__setattr__(self, "display_label", optional_label(self.display_label, "display_label"))
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")
        object.__setattr__(self, "created_at", utc_instant(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", utc_instant(self.updated_at, "updated_at"))


@dataclass(frozen=True, slots=True)
class ProviderAccount:
    id: UUID
    provider_instance_id: UUID
    account_key: str
    provider_native_id: str | None
    display_label: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "account_key", canonical_key(self.account_key, "account_key"))
        object.__setattr__(self, "provider_native_id", optional_label(self.provider_native_id, "provider_native_id"))
        object.__setattr__(self, "display_label", optional_label(self.display_label, "display_label"))
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")
        object.__setattr__(self, "created_at", utc_instant(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", utc_instant(self.updated_at, "updated_at"))


@dataclass(frozen=True, slots=True)
class ObservationScope:
    id: UUID
    provider_instance_id: UUID
    provider_account_id: UUID | None
    scope_key: str
    display_label: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_key", canonical_key(self.scope_key, "scope_key"))
        object.__setattr__(self, "display_label", optional_label(self.display_label, "display_label"))
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be boolean")
        object.__setattr__(self, "created_at", utc_instant(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", utc_instant(self.updated_at, "updated_at"))
