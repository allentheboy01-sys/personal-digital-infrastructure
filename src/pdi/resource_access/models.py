from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum


class ResourceRepresentationKind(StrEnum):
    THUMBNAIL = "thumbnail"
    PREVIEW = "preview"


@dataclass(frozen=True, slots=True)
class ResourceAccessSource:
    """Private, detached Source projection used only for access."""

    provider: str
    provider_locator: str = field(repr=False)
    resource_type: str
    mime_type: str | None
    source_id: str | None = field(default=None, repr=False)
    observation_scope_id: str | None = None


@dataclass(frozen=True, slots=True)
class ResourceRepresentationDescriptor:
    resource_ref: str
    representation_kind: ResourceRepresentationKind
    media_type: str
    content_length: int | None
    etag: str | None
    last_modified: str | None
    provider: str


class ResourceRepresentation:
    """One-shot bounded byte stream with deterministic close semantics."""

    __slots__ = ("descriptor", "_body", "_close")

    def __init__(
        self,
        descriptor: ResourceRepresentationDescriptor,
        body: AsyncIterator[bytes],
        close: Callable[[], Awaitable[None]],
    ) -> None:
        self.descriptor = descriptor
        self._body = body
        self._close = close

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._body

    async def aclose(self) -> None:
        body_close = getattr(self._body, "aclose", None)
        if body_close is not None:
            await body_close()
        await self._close()

    async def __aenter__(self) -> "ResourceRepresentation":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


@dataclass(frozen=True, slots=True)
class ResourceVideoDescriptor:
    resource_ref: str
    status_code: int
    media_type: str | None
    content_length: int | None
    content_range: str | None
    accept_ranges: str | None
    provider: str


class ResourceVideo:
    """One-shot unbuffered video stream with deterministic close semantics."""

    __slots__ = ("descriptor", "_body", "_close")

    def __init__(
        self,
        descriptor: ResourceVideoDescriptor,
        body: AsyncIterator[bytes],
        close: Callable[[], Awaitable[None]],
    ) -> None:
        self.descriptor = descriptor
        self._body = body
        self._close = close

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._body

    async def aclose(self) -> None:
        body_close = getattr(self._body, "aclose", None)
        if body_close is not None:
            await body_close()
        await self._close()

    async def __aenter__(self) -> "ResourceVideo":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
