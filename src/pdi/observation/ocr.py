from dataclasses import dataclass
import hashlib
import json
import re
import urllib.parse

import requests

from pdi.adapters.immich_account import (
    ImmichAccountMismatchError,
    authenticated_immich_user_id,
    canonical_immich_user_id,
)
from pdi.config import ImmichSettings

from .errors import ObservationExtractionError
from .models import (
    EnrichmentResource,
    Evidence,
    EvidenceSourceKind,
    GeneratorIdentity,
    ObservationBatch,
    StatementDraft,
    StatementValueType,
    TypedStatementValue,
)
from .predicates import MEDIA_OCR_TEXT


MAX_OCR_TEXT_BYTES = 8192
TRUNCATION_MARKER = "\n[\u2026truncated]"
_HORIZONTAL_WHITESPACE = re.compile(r"[^\S\r\n]+")


def _extraction_error(code: str, message: str) -> ObservationExtractionError:
    error = ObservationExtractionError(message)
    error.code = code
    return error


@dataclass(frozen=True, slots=True)
class OCRRegion:
    text: str


class ImmichOCRReader:
    """Read one asset's provider-native OCR result from Immich."""

    def __init__(
        self,
        settings: ImmichSettings,
        *,
        timeout: float = 10.0,
        expected_user_id: str | None = None,
    ) -> None:
        self._base_url = settings.url.rstrip("/")
        self._api_key = settings.api_key
        self._timeout = timeout
        self._expected_user_id = (
            None
            if expected_user_id is None
            else canonical_immich_user_id(expected_user_id)
        )
        self._account_verified = False

    def _verify_account(self) -> None:
        if self._expected_user_id is None or self._account_verified:
            return
        try:
            response = requests.get(
                f"{self._base_url}/api/users/me",
                headers={"x-api-key": self._api_key},
                timeout=self._timeout,
            )
            response.raise_for_status()
            authenticated = authenticated_immich_user_id(response.json())
        except ImmichAccountMismatchError:
            raise
        except (requests.RequestException, TypeError, ValueError) as error:
            raise _extraction_error(
                "provider_unavailable", "Immich account qualification failed"
            ) from error
        if authenticated != self._expected_user_id:
            raise ImmichAccountMismatchError(
                "Immich credential does not match expected Provider Account"
            )
        self._account_verified = True

    def get_asset_ocr(
        self,
        provider_locator: str,
    ) -> tuple[OCRRegion, ...]:
        self._verify_account()
        locator = urllib.parse.quote(provider_locator, safe="")
        try:
            response = requests.get(
                f"{self._base_url}/api/assets/{locator}/ocr",
                headers={"x-api-key": self._api_key},
                timeout=self._timeout,
            )
        except (requests.Timeout, requests.ConnectionError) as error:
            raise _extraction_error(
                "provider_unavailable",
                "Immich OCR API is unavailable",
            ) from error
        except requests.RequestException as error:
            raise _extraction_error(
                "provider_unavailable",
                "Immich OCR API request failed",
            ) from error

        if response.status_code in {400, 401, 403, 404}:
            raise _extraction_error(
                "provider_not_found",
                "Immich OCR asset was not found or is not readable",
            )
        if response.status_code == 429 or response.status_code >= 500:
            raise _extraction_error(
                "provider_unavailable",
                "Immich OCR API is unavailable",
            )
        if not 200 <= response.status_code < 300:
            raise _extraction_error(
                "provider_invalid_response",
                "Immich OCR API returned an unexpected status",
            )

        try:
            payload = response.json()
        except (requests.JSONDecodeError, ValueError) as error:
            raise _extraction_error(
                "provider_invalid_response",
                "Immich OCR API returned invalid JSON",
            ) from error
        if not isinstance(payload, list):
            raise _extraction_error(
                "provider_invalid_response",
                "Immich OCR API response must be a list",
            )

        regions: list[OCRRegion] = []
        for region in payload:
            if not isinstance(region, dict):
                raise _extraction_error(
                    "provider_invalid_response",
                    "Immich OCR region must be an object",
                )
            text = region.get("text")
            if not isinstance(text, str):
                raise _extraction_error(
                    "provider_invalid_response",
                    "Immich OCR region text must be a string",
                )
            regions.append(OCRRegion(text))
        return tuple(regions)


def _normalize_region(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    for line in normalized.split("\n"):
        line = _HORIZONTAL_WHITESPACE.sub(" ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def _normalize_regions(
    regions: tuple[OCRRegion, ...],
) -> tuple[str, ...]:
    normalized = tuple(_normalize_region(region.text) for region in regions)
    return tuple(text for text in normalized if text)


def _combined_text(normalized_regions: tuple[str, ...]) -> str:
    return "\n".join(normalized_regions).strip()


def _truncate_ocr_text(text: str) -> str:
    if len(text.encode("utf-8")) <= MAX_OCR_TEXT_BYTES:
        return text

    available = MAX_OCR_TEXT_BYTES - len(
        TRUNCATION_MARKER.encode("utf-8")
    )
    prefix: list[str] = []
    used = 0
    for character in text:
        encoded_size = len(character.encode("utf-8"))
        if used + encoded_size > available:
            break
        prefix.append(character)
        used += encoded_size
    result = "".join(prefix).rstrip(" \n") + TRUNCATION_MARKER
    if len(result.encode("utf-8")) > MAX_OCR_TEXT_BYTES:
        raise AssertionError("OCR truncation exceeded the UTF-8 boundary")
    return result


def _fingerprint(
    source_id: str,
    observation_scope_id: str | None,
    provider_locator: str,
    normalized_regions: tuple[str, ...],
) -> str:
    payload = {
        "format": "pdi.immich_ocr.input.v1",
        "provider": "immich",
        "provider_locator": provider_locator,
        "regions": normalized_regions,
    }
    if observation_scope_id is not None:
        payload["source_id"] = source_id
        payload["observation_scope_id"] = observation_scope_id
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class ImmichOCRExtractor:
    generator = GeneratorIdentity("provider_native_ml", "immich_ocr", "1")
    covered_predicates = (MEDIA_OCR_TEXT,)

    def __init__(self, reader: ImmichOCRReader) -> None:
        self._reader = reader

    @staticmethod
    def _selected_source(resource: EnrichmentResource):
        sources = tuple(
            source
            for source in resource.sources
            if source.provider == "immich"
        )
        if not sources:
            raise ObservationExtractionError("No active Immich source")
        if len(sources) > 1:
            raise _extraction_error(
                "ambiguous_active_immich_source",
                "Multiple active Immich sources are ambiguous",
            )
        source = sources[0]
        if source.provider_locator is None:
            raise _extraction_error(
                "provider_not_found",
                "Immich source has no provider locator",
            )
        return source

    def _read(
        self,
        resource: EnrichmentResource,
    ) -> tuple[object, str, tuple[str, ...]]:
        source = self._selected_source(resource)
        scoped_read = getattr(self._reader, "get_source_ocr", None)
        regions = (
            scoped_read(source)
            if scoped_read is not None
            else self._reader.get_asset_ocr(source.provider_locator)
        )
        return source, source.provider_locator, _normalize_regions(regions)

    def input_fingerprint(self, resource: EnrichmentResource) -> str:
        source, provider_locator, normalized_regions = self._read(resource)
        return _fingerprint(
            source.source_id,
            source.observation_scope_id,
            provider_locator,
            normalized_regions,
        )

    def extract(self, resource: EnrichmentResource) -> ObservationBatch:
        source, provider_locator, normalized_regions = self._read(resource)
        full_text = _combined_text(normalized_regions)
        statements = ()
        if full_text:
            statements = (
                StatementDraft(
                    MEDIA_OCR_TEXT,
                    TypedStatementValue(
                        StatementValueType.STRING,
                        _truncate_ocr_text(full_text),
                    ),
                    Evidence(
                        EvidenceSourceKind.PROVIDER_METADATA,
                        "immich.api.asset_ocr",
                    ),
                    None,
                ),
            )
        return ObservationBatch(
            resource.resource_ref,
            self.generator,
            self.covered_predicates,
            _fingerprint(
                source.source_id,
                source.observation_scope_id,
                provider_locator,
                normalized_regions,
            ),
            statements,
        )
