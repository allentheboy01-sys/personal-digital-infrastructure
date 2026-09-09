import asyncio
from collections.abc import Mapping
from hashlib import sha256
import re
import unicodedata
from typing import Protocol

import anyio

from pdi.query.errors import InvalidResourceRefError
from pdi.query.resources import parse_resource_ref

from .errors import (
    AmbiguousTextContentError,
    ContentChangedSinceSyncError,
    InvalidResourceReferenceError,
    InvalidTextContentError,
    InvalidTextWindowError,
    ProviderInvalidResponseError,
    ProviderUnavailableError,
    ResourceAccessError,
    ResourceAccessUnavailableError,
    ResourceNotFoundError,
    TextTooLargeError,
    TextUnavailableError,
)
from .repository import ResourceTextRepository
from .text_models import (
    RESOURCE_TEXT_SCHEMA,
    ResourceText,
    TextResourceAccessSource,
)
from .text_provider import ProviderTextAdapter, ProviderTextContent


MAX_TEXT_SOURCE_BYTES = 1024 * 1024
DEFAULT_TEXT_WINDOW_BYTES = 8192
MAX_TEXT_WINDOW_BYTES = 16384
MIN_TEXT_WINDOW_BYTES = 4
MAX_ACTIVE_TEXT_READS = 8

_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
_TEXT_MEDIA_TYPE = re.compile(r"text/[a-z0-9!#$&^_.+\-]+")
_APPLICATION_TEXT_MEDIA_TYPES = {
    "application/json",
    "application/markdown",
}


class TextAdapterResolver(Protocol):
    async def resolve_text_adapter(
        self, source: TextResourceAccessSource
    ) -> ProviderTextAdapter: ...


class ResourceTextService:
    """Read and verify one bounded complete Provider-backed text Resource."""

    def __init__(
        self,
        repository: ResourceTextRepository,
        provider_adapters: Mapping[str, ProviderTextAdapter] | None = None,
        *,
        adapter_resolver: TextAdapterResolver | None = None,
        max_active_reads: int = MAX_ACTIVE_TEXT_READS,
    ) -> None:
        if max_active_reads < 1:
            raise ValueError("max_active_reads must be positive")
        self._repository = repository
        if (provider_adapters is None) == (adapter_resolver is None):
            raise ValueError(
                "exactly one provider adapter mapping or scoped resolver is required"
            )
        self._provider_adapters = dict(provider_adapters or {})
        self._adapter_resolver = adapter_resolver
        self._semaphore = asyncio.Semaphore(max_active_reads)

    async def read_text(
        self,
        resource_ref: str,
        *,
        offset_bytes: int = 0,
        max_bytes: int = DEFAULT_TEXT_WINDOW_BYTES,
    ) -> ResourceText:
        offset_bytes = self._offset(offset_bytes)
        max_bytes = self._window_size(max_bytes)
        sources = await self._resolve_sources(resource_ref)
        source, expected_digest = self._select_source(sources)
        if source.size_bytes is not None:
            if (
                type(source.size_bytes) is not int
                or source.size_bytes < 0
            ):
                raise ResourceAccessUnavailableError(
                    "Text Source size is invalid"
                )
            if source.size_bytes > MAX_TEXT_SOURCE_BYTES:
                raise TextTooLargeError(
                    "Text representation exceeds the source byte limit"
                )

        if self._adapter_resolver is not None:
            adapter = await self._adapter_resolver.resolve_text_adapter(source)
        else:
            adapter = self._provider_adapters.get(source.provider)
            if adapter is None:
                raise ResourceAccessUnavailableError(
                    "Text Provider access is not configured"
                )

        async with self._semaphore:
            upstream: ProviderTextContent | None = None
            try:
                upstream = await adapter.open_text(source.provider_locator)
                declared_length = self._validate_upstream(
                    source=source,
                    upstream=upstream,
                )
                raw = await self._read_complete(
                    upstream,
                    declared_length=declared_length,
                )
            except asyncio.CancelledError:
                raise
            except ResourceAccessError:
                raise
            except Exception:
                raise ProviderUnavailableError(
                    "Provider text read failed"
                ) from None
            finally:
                if upstream is not None:
                    await upstream.close()

        actual_digest = sha256(raw).hexdigest()
        if actual_digest != expected_digest:
            raise ContentChangedSinceSyncError(
                "Provider content changed since PDI synchronization"
            )
        text = self._decode_text(raw)
        canonical = text.encode("utf-8")
        total_bytes = len(canonical)
        if offset_bytes > total_bytes:
            raise InvalidTextWindowError(
                "Text offset exceeds the representation length"
            )
        if not self._is_codepoint_boundary(canonical, offset_bytes):
            raise InvalidTextWindowError(
                "Text offset must be a UTF-8 codepoint boundary"
            )

        end = min(total_bytes, offset_bytes + max_bytes)
        while (
            end > offset_bytes
            and end < total_bytes
            and not self._is_codepoint_boundary(canonical, end)
        ):
            end -= 1
        window = canonical[offset_bytes:end].decode("utf-8")
        next_offset = end if end < total_bytes else None
        return ResourceText(
            schema=RESOURCE_TEXT_SCHEMA,
            resource_ref=resource_ref,
            provider=source.provider,
            media_type=self._normalized_media_type(source.mime_type),
            encoding="utf-8",
            source="provider_access",
            text=window,
            offset_bytes=offset_bytes,
            returned_bytes=end - offset_bytes,
            total_bytes=total_bytes,
            truncated=next_offset is not None,
            next_offset=next_offset,
            content_sha256=actual_digest,
        )

    async def _resolve_sources(
        self,
        resource_ref: str,
    ) -> tuple[TextResourceAccessSource, ...]:
        try:
            asset_id = parse_resource_ref(resource_ref)
        except InvalidResourceRefError as error:
            raise InvalidResourceReferenceError(
                "Resource reference is invalid"
            ) from error
        try:
            sources = await anyio.to_thread.run_sync(
                self._repository.resolve_text_access_sources,
                asset_id,
            )
        except Exception:
            raise ResourceAccessUnavailableError(
                "Resource text persistence is unavailable"
            ) from None
        if sources is None:
            raise ResourceNotFoundError("Resource was not found")
        return sources

    def _select_source(
        self,
        sources: tuple[TextResourceAccessSource, ...],
    ) -> tuple[TextResourceAccessSource, str]:
        eligible = tuple(
            source
            for source in sources
            if source.provider == "nextcloud"
            and source.resource_type == "file"
            and self._media_type_is_supported(source.mime_type)
        )
        if not eligible:
            raise TextUnavailableError("Resource text is unavailable")

        by_digest: dict[str, list[TextResourceAccessSource]] = {}
        for source in eligible:
            if (
                not isinstance(source.source_id, str)
                or not source.source_id
                or not isinstance(source.provider_locator, str)
                or not source.provider_locator
                or not isinstance(source.blob_sha256, str)
                or _SHA256_HEX.fullmatch(source.blob_sha256) is None
            ):
                raise ResourceAccessUnavailableError(
                    "Text Source identity is invalid"
                )
            by_digest.setdefault(
                source.blob_sha256.lower(),
                [],
            ).append(source)
        if len(by_digest) != 1:
            raise AmbiguousTextContentError(
                "Resource has ambiguous current text content"
            )
        digest, same_content = next(iter(by_digest.items()))
        return min(same_content, key=lambda source: source.source_id), digest

    @classmethod
    def _validate_upstream(
        cls,
        *,
        source: TextResourceAccessSource,
        upstream: ProviderTextContent,
    ) -> int | None:
        if upstream.status_code in {404, 410}:
            raise TextUnavailableError("Resource text is unavailable")
        if upstream.status_code == 412:
            raise ContentChangedSinceSyncError(
                "Provider content changed since PDI synchronization"
            )
        if upstream.status_code >= 500:
            raise ProviderUnavailableError(
                "Provider text service is unavailable"
            )
        if upstream.status_code != 200:
            raise ProviderInvalidResponseError(
                "Provider returned an unexpected text response"
            )
        if (
            upstream.content_encoding is not None
            and upstream.content_encoding.strip().lower() != "identity"
        ):
            raise ProviderInvalidResponseError(
                "Provider returned unsupported content encoding"
            )

        media_type = cls._normalized_media_type(upstream.media_type)
        expected_media_type = cls._normalized_media_type(source.mime_type)
        if (
            not cls._media_type_is_supported(media_type)
            or media_type != expected_media_type
        ):
            raise ProviderInvalidResponseError(
                "Provider returned an invalid text Content-Type"
            )

        if upstream.content_length is None:
            return None
        try:
            declared_length = int(upstream.content_length)
        except (TypeError, ValueError):
            raise ProviderInvalidResponseError(
                "Provider returned an invalid Content-Length"
            ) from None
        if declared_length < 0:
            raise ProviderInvalidResponseError(
                "Provider returned an invalid Content-Length"
            )
        if declared_length > MAX_TEXT_SOURCE_BYTES:
            raise TextTooLargeError(
                "Text representation exceeds the source byte limit"
            )
        return declared_length

    @staticmethod
    async def _read_complete(
        upstream: ProviderTextContent,
        *,
        declared_length: int | None,
    ) -> bytes:
        content = bytearray()
        try:
            async for chunk in upstream.body:
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise ProviderInvalidResponseError(
                        "Provider returned an invalid text byte stream"
                    )
                normalized = bytes(chunk)
                if not normalized:
                    continue
                remaining = MAX_TEXT_SOURCE_BYTES + 1 - len(content)
                if remaining > 0:
                    content.extend(normalized[:remaining])
                if len(content) > MAX_TEXT_SOURCE_BYTES:
                    raise TextTooLargeError(
                        "Text representation exceeds the source byte limit"
                    )
        except asyncio.CancelledError:
            raise
        except ResourceAccessError:
            raise
        except Exception:
            raise ProviderUnavailableError(
                "Provider text stream is unavailable"
            ) from None
        if declared_length is not None and len(content) != declared_length:
            raise ProviderInvalidResponseError(
                "Provider Content-Length did not match the text stream"
            )
        return bytes(content)

    @staticmethod
    def _decode_text(content: bytes) -> str:
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise InvalidTextContentError(
                "Text representation is not valid UTF-8"
            ) from None
        if any(
            unicodedata.category(character) == "Cc"
            and character not in "\t\n\r"
            for character in text
        ):
            raise InvalidTextContentError(
                "Text representation contains binary control characters"
            )
        return text

    @staticmethod
    def _is_codepoint_boundary(content: bytes, offset: int) -> bool:
        return (
            offset == 0
            or offset == len(content)
            or content[offset] & 0b1100_0000 != 0b1000_0000
        )

    @staticmethod
    def _offset(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InvalidTextWindowError(
                "offset_bytes must be a non-negative integer"
            )
        return value

    @staticmethod
    def _window_size(value: int) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not MIN_TEXT_WINDOW_BYTES <= value <= MAX_TEXT_WINDOW_BYTES
        ):
            raise InvalidTextWindowError(
                "max_bytes must be between 4 and 16384"
            )
        return value

    @staticmethod
    def _normalized_media_type(value: str | None) -> str:
        if not isinstance(value, str):
            return ""
        return value.split(";", 1)[0].strip().lower()

    @classmethod
    def _media_type_is_supported(cls, value: str | None) -> bool:
        normalized = cls._normalized_media_type(value)
        return (
            _TEXT_MEDIA_TYPE.fullmatch(normalized) is not None
            or normalized in _APPLICATION_TEXT_MEDIA_TYPES
        )
