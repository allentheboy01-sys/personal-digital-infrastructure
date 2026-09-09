from dataclasses import dataclass
from datetime import UTC, datetime
import unicodedata
from uuid import UUID


def utc_instant(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("person identity timestamp must be timezone-aware")
    return value.astimezone(UTC)


def normalize_person_display_name(value: object) -> str | None:
    """Normalize one optional Provider-declared Person display name."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("person display_name must be a string or null")
    normalized = unicodedata.normalize("NFC", value).strip()
    return normalized or None


def normalize_person_label_query(value: object) -> str:
    """Normalize one exact Person label query without adding inference."""

    normalized = normalize_person_display_name(value)
    if normalized is None:
        raise ValueError("person label must be non-empty")
    return normalized


@dataclass(frozen=True)
class Person:
    id: UUID
    created_at: datetime


@dataclass(frozen=True)
class PersonSource:
    provider: str
    external_id: str
    person_id: UUID
    display_name: str | None
    inactive_at: datetime | None


@dataclass(frozen=True)
class ScopedPersonSource:
    observation_scope_id: UUID
    external_id: str
    person_id: UUID
    display_name: str | None
    inactive_at: datetime | None


@dataclass(frozen=True)
class ProviderPersonIdentity:
    external_id: str
    display_name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.external_id, str) or not self.external_id.strip():
            raise ValueError("person external_id must be non-empty")
        object.__setattr__(
            self,
            "display_name",
            normalize_person_display_name(self.display_name),
        )


@dataclass(frozen=True)
class EnumerablePersonInventory:
    provider: str
    identities: tuple[ProviderPersonIdentity, ...]
    reported_total: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "identities", tuple(self.identities))

    @property
    def external_ids(self) -> tuple[str, ...]:
        return tuple(identity.external_id for identity in self.identities)


@dataclass(frozen=True)
class PersonSyncResult:
    discovered: int
    created: int
    existing: int
    reactivated: int
    inactivated: int
    labels_updated: int = 0
