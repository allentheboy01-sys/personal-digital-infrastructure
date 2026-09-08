from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807


def effective_source_mime_type(
    provider_mime_type: str | None,
    legacy_blob_mime_type: str | None,
) -> str | None:
    """Return Provider MIME, with a NULL-only legacy Blob fallback."""

    if provider_mime_type is not None:
        return provider_mime_type
    return legacy_blob_mime_type


def validate_provider_size(value: object) -> int | None:
    """Validate a normalized Provider size for durable Source storage."""

    if value is None:
        return None

    if (
        type(value) is not int
        or value < 0
        or value > POSTGRES_BIGINT_MAX
    ):
        raise ValueError(
            "provider_size must be None or a non-negative "
            "PostgreSQL BIGINT integer"
        )

    return value


@dataclass
class AssetSource:
    id: str = field(default_factory=lambda: str(uuid4()))
    blob_id: str | None = None
    provider: str = "unknown"
    external_id: str | None = None
    observation_scope_id: str | None = None
    path: str | None = None
    name: str | None = None
    version_tag: str | None = None
    provider_mime_type: str | None = None
    provider_size: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    deleted_at: datetime | None = None

    def __post_init__(self) -> None:
        validate_provider_size(self.provider_size)
        if self.observation_scope_id is not None:
            if (
                not isinstance(self.observation_scope_id, str)
                or not self.observation_scope_id.strip()
            ):
                raise ValueError("observation_scope_id must be a non-empty UUID string")
            if not isinstance(self.external_id, str) or not self.external_id.strip():
                raise ValueError("scoped Source external_id must be non-empty")
