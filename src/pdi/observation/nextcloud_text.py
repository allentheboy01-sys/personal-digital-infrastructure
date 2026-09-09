from collections.abc import Iterable
import hashlib
import json
from pathlib import PurePosixPath
import re

import requests

from pdi.adapters.base import ProviderFact
from pdi.adapters.nextcloud.adapter import NextcloudAdapter

from .errors import ObservationExtractionError
from .models import (
    EnrichmentResource,
    EnrichmentSource,
    Evidence,
    EvidenceSourceKind,
    GeneratorIdentity,
    ObservationBatch,
    StatementDraft,
    StatementValueType,
    TypedStatementValue,
)
from .predicates import DOCUMENT_TEXT_EXCERPT


MAX_SOURCE_BYTES = 1024 * 1024
MAX_DECODED_CHARACTERS = 1_048_576
MAX_STORED_TEXT_BYTES = 16_384
TRUNCATION_MARKER = "\n[\u2026truncated by PDI]"

_ELIGIBLE_MIME_TYPES = {
    "text/plain",
    "text/markdown",
    "application/markdown",
}
_ELIGIBLE_EXTENSIONS = {".md", ".markdown"}
_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")


def _extraction_error(
    code: str,
    message: str,
) -> ObservationExtractionError:
    error = ObservationExtractionError(message)
    error.code = code
    return error


def _normalized_mime_type(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    return value.split(";", 1)[0].strip().lower()


def _source_extension(source: EnrichmentSource) -> str:
    candidate = source.name or source.path or ""
    return PurePosixPath(candidate).suffix.lower()


def _source_is_eligible(source: EnrichmentSource) -> bool:
    return (
        source.provider == "nextcloud"
        and (
            _normalized_mime_type(source.mime_type)
            in _ELIGIBLE_MIME_TYPES
            or _source_extension(source) in _ELIGIBLE_EXTENSIONS
        )
    )


def _selected_source(
    resource: EnrichmentResource,
) -> EnrichmentSource:
    sources = tuple(
        source
        for source in resource.sources
        if _source_is_eligible(source)
    )
    if not sources:
        raise _extraction_error(
            "no_eligible_nextcloud_source",
            "Resource has no eligible active Nextcloud text source",
        )

    by_digest: dict[str, list[EnrichmentSource]] = {}
    for source in sources:
        digest = source.blob_sha256
        if (
            not isinstance(digest, str)
            or _SHA256_HEX.fullmatch(digest) is None
        ):
            raise _extraction_error(
                "invalid_blob_digest",
                "Nextcloud text source has no valid current Blob digest",
            )
        by_digest.setdefault(digest.lower(), []).append(source)

    if len(by_digest) != 1:
        raise _extraction_error(
            "ambiguous_active_nextcloud_content",
            "Multiple active Nextcloud text contents are ambiguous",
        )

    same_content_sources = next(iter(by_digest.values()))
    return min(same_content_sources, key=lambda source: source.source_id)


def _input_fingerprint(source: EnrichmentSource) -> str:
    digest = source.blob_sha256
    if (
        not isinstance(digest, str)
        or _SHA256_HEX.fullmatch(digest) is None
    ):
        raise _extraction_error(
            "invalid_blob_digest",
            "Nextcloud text source has no valid current Blob digest",
        )
    payload = {
        "format": "pdi.nextcloud_text.input.v1",
        "provider": "nextcloud",
        "blob_sha256": digest.lower(),
        "mime_type": _normalized_mime_type(source.mime_type),
        "extractor_version": "1",
    }
    if source.observation_scope_id is not None:
        payload["source_id"] = source.source_id
        payload["observation_scope_id"] = source.observation_scope_id
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class NextcloudContentReader:
    """Delegate authenticated provider content reads to NextcloudAdapter."""

    def __init__(self, adapter: NextcloudAdapter) -> None:
        self._adapter = adapter

    def open(self, source: EnrichmentSource) -> Iterable[bytes]:
        fact = ProviderFact(
            provider=source.provider,
            kind="file",
            external_id=source.provider_locator,
            name=source.name,
            attributes={
                "path": source.path,
                "size": source.size,
                "mime_type": source.mime_type,
                "version_tag": source.version_tag,
                "content_hash": None,
            },
            raw=dict(source.metadata),
        )
        try:
            yield from self._adapter.open(fact)
        except (requests.Timeout, requests.ConnectionError) as error:
            raise _extraction_error(
                "provider_unavailable",
                "Nextcloud content is unavailable",
            ) from error
        except requests.RequestException as error:
            raise _extraction_error(
                "provider_read_failed",
                "Nextcloud content read failed",
            ) from error
        except (TypeError, ValueError) as error:
            raise _extraction_error(
                "provider_invalid_source",
                "Nextcloud content source is invalid",
            ) from error


def _read_bounded(
    reader: NextcloudContentReader,
    source: EnrichmentSource,
) -> bytes:
    if source.size is not None:
        if type(source.size) is not int or source.size < 0:
            raise _extraction_error(
                "invalid_source_size",
                "Nextcloud text source size is invalid",
            )
        if source.size > MAX_SOURCE_BYTES:
            raise _extraction_error(
                "source_too_large",
                "Nextcloud text source exceeds the extraction limit",
            )

    content = bytearray()
    stream = iter(reader.open(source))
    try:
        for chunk in stream:
            if not isinstance(chunk, bytes):
                raise _extraction_error(
                    "provider_invalid_response",
                    "Nextcloud content reader returned invalid bytes",
                )
            remaining = MAX_SOURCE_BYTES + 1 - len(content)
            if remaining > 0:
                content.extend(chunk[:remaining])
            if len(content) > MAX_SOURCE_BYTES:
                raise _extraction_error(
                    "source_too_large",
                    "Nextcloud text source exceeds the extraction limit",
                )
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            close()
    return bytes(content)


def _decode_and_normalize(content: bytes) -> str:
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise _extraction_error(
            "invalid_text_encoding",
            "Nextcloud text source is not valid UTF-8",
        ) from error

    if len(decoded) > MAX_DECODED_CHARACTERS:
        raise _extraction_error(
            "decoded_text_too_large",
            "Nextcloud decoded text exceeds the extraction limit",
        )
    if "\x00" in decoded:
        raise _extraction_error(
            "binary_content",
            "Nextcloud text source contains NUL bytes",
        )
    if any(
        (ord(character) < 32 and character not in "\t\n\r")
        or ord(character) == 127
        for character in decoded
    ):
        raise _extraction_error(
            "binary_content",
            "Nextcloud text source contains disallowed controls",
        )
    return decoded.replace("\r\n", "\n").replace("\r", "\n")


def _truncate_text(text: str) -> str:
    if len(text.encode("utf-8")) <= MAX_STORED_TEXT_BYTES:
        return text

    marker_size = len(TRUNCATION_MARKER.encode("utf-8"))
    available = MAX_STORED_TEXT_BYTES - marker_size
    prefix: list[str] = []
    used = 0
    for character in text:
        encoded_size = len(character.encode("utf-8"))
        if used + encoded_size > available:
            break
        prefix.append(character)
        used += encoded_size
    result = "".join(prefix) + TRUNCATION_MARKER
    if len(result.encode("utf-8")) > MAX_STORED_TEXT_BYTES:
        raise AssertionError("Text truncation exceeded the UTF-8 boundary")
    return result


class NextcloudTextExtractor:
    generator = GeneratorIdentity(
        "deterministic_extractor",
        "nextcloud_text",
        "1",
    )
    covered_predicates = (DOCUMENT_TEXT_EXCERPT,)

    def __init__(self, reader: NextcloudContentReader) -> None:
        self._reader = reader

    @staticmethod
    def is_eligible(resource: EnrichmentResource) -> bool:
        return any(
            _source_is_eligible(source)
            for source in resource.sources
        )

    def input_fingerprint(self, resource: EnrichmentResource) -> str:
        return _input_fingerprint(_selected_source(resource))

    def extract(self, resource: EnrichmentResource) -> ObservationBatch:
        source = _selected_source(resource)
        fingerprint = _input_fingerprint(source)
        content = _read_bounded(self._reader, source)
        if hashlib.sha256(content).hexdigest() != source.blob_sha256.lower():
            raise _extraction_error(
                "content_changed_since_sync",
                "Nextcloud content no longer matches the current Blob",
            )
        normalized = _decode_and_normalize(content)
        statements = ()
        if normalized:
            statements = (
                StatementDraft(
                    DOCUMENT_TEXT_EXCERPT,
                    TypedStatementValue(
                        StatementValueType.STRING,
                        _truncate_text(normalized),
                    ),
                    Evidence(
                        EvidenceSourceKind.RESOURCE_CONTENT,
                        "nextcloud.webdav.content",
                    ),
                    None,
                ),
            )
        return ObservationBatch(
            resource.resource_ref,
            self.generator,
            self.covered_predicates,
            fingerprint,
            statements,
        )
