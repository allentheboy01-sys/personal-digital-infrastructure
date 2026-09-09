from dataclasses import dataclass, field


RESOURCE_TEXT_SCHEMA = "pdi.resource-text.v1"


@dataclass(frozen=True, slots=True)
class TextResourceAccessSource:
    """Private detached Source/Blob projection for bounded text access."""

    source_id: str = field(repr=False)
    provider: str
    provider_locator: str = field(repr=False)
    resource_type: str
    mime_type: str | None
    size_bytes: int | None
    blob_sha256: str = field(repr=False)
    version_tag: str | None = field(default=None, repr=False)
    observation_scope_id: str | None = None


@dataclass(frozen=True, slots=True)
class ResourceText:
    schema: str
    resource_ref: str
    provider: str
    media_type: str
    encoding: str
    source: str
    text: str
    offset_bytes: int
    returned_bytes: int
    total_bytes: int
    truncated: bool
    next_offset: int | None
    content_sha256: str
