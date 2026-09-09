from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest
import requests

from pdi.adapters.immich import ImmichAccountMismatchError
from pdi.config import ImmichSettings
from pdi.observation import (
    EnrichmentResource,
    EnrichmentSource,
    ImmichOCRExtractor,
    ImmichOCRReader,
    ObservationExtractionError,
    OCRRegion,
)
from pdi.query import format_resource_ref


class FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def raise_for_status(self) -> None:
        if not 200 <= self.status_code < 300:
            raise requests.HTTPError(str(self.status_code))


class FakeReader:
    def __init__(self, regions: tuple[OCRRegion, ...]) -> None:
        self.regions = regions
        self.locators: list[str] = []

    def get_asset_ocr(
        self,
        provider_locator: str,
    ) -> tuple[OCRRegion, ...]:
        self.locators.append(provider_locator)
        return self.regions


def _resource(
    *,
    locator: str = "immich-asset-1",
    sources: tuple[EnrichmentSource, ...] | None = None,
) -> EnrichmentResource:
    if sources is None:
        sources = (
            EnrichmentSource(
                str(uuid4()),
                "immich",
                {},
                locator,
            ),
        )
    return EnrichmentResource(format_resource_ref(uuid4()), sources)


def _extract(
    *texts: str,
    locator: str = "immich-asset-1",
):
    reader = FakeReader(tuple(OCRRegion(text) for text in texts))
    batch = ImmichOCRExtractor(reader).extract(
        _resource(locator=locator)
    )
    return batch, reader


def test_reader_uses_only_curated_immutable_region_text(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}
    response = FakeResponse(
        200,
        [
            {
                "id": "region-id",
                "text": "Hello",
                "boxScore": 0.8,
                "textScore": 0.9,
                "updateId": "update-id",
                "x1": 0.1,
            },
            {"text": "世界"},
        ],
    )

    def fake_get(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return response

    monkeypatch.setattr(
        "pdi.observation.ocr.requests.get",
        fake_get,
    )
    reader = ImmichOCRReader(
        ImmichSettings(
            url="https://immich.example/",
            api_key="secret-key",
        ),
        timeout=7,
    )

    regions = reader.get_asset_ocr("asset/id")

    assert regions == (OCRRegion("Hello"), OCRRegion("世界"))
    assert captured == {
        "url": "https://immich.example/api/assets/asset%2Fid/ocr",
        "headers": {"x-api-key": "secret-key"},
        "timeout": 7,
    }
    assert not hasattr(regions[0], "boxScore")
    with pytest.raises(FrozenInstanceError):
        regions[0].text = "changed"


def test_reader_rejects_wrong_valid_user_before_ocr(monkeypatch) -> None:
    requested_urls: list[str] = []

    def fake_get(url: str, **kwargs):
        requested_urls.append(url)
        return FakeResponse(
            200,
            {"id": "22222222-2222-4222-8222-222222222222"},
        )

    monkeypatch.setattr("pdi.observation.ocr.requests.get", fake_get)
    reader = ImmichOCRReader(
        ImmichSettings(url="https://immich.example", api_key="synthetic-key"),
        expected_user_id="11111111-1111-4111-8111-111111111111",
    )

    with pytest.raises(ImmichAccountMismatchError):
        reader.get_asset_ocr("asset")

    assert requested_urls == ["https://immich.example/api/users/me"]


@pytest.mark.parametrize("payload", [[], [{"text": "one"}], [{"text": "one"}, {"text": "two"}]])
def test_reader_accepts_successful_region_lists(monkeypatch, payload) -> None:
    monkeypatch.setattr(
        "pdi.observation.ocr.requests.get",
        lambda *args, **kwargs: FakeResponse(200, payload),
    )
    reader = ImmichOCRReader(
        ImmichSettings(url="https://immich.example", api_key="key")
    )
    assert tuple(region.text for region in reader.get_asset_ocr("asset")) == tuple(
        region["text"] for region in payload
    )


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_reader_maps_unreadable_assets(monkeypatch, status) -> None:
    monkeypatch.setattr(
        "pdi.observation.ocr.requests.get",
        lambda *args, **kwargs: FakeResponse(status, {}),
    )
    reader = ImmichOCRReader(
        ImmichSettings(url="https://immich.example", api_key="key")
    )
    with pytest.raises(ObservationExtractionError) as caught:
        reader.get_asset_ocr("asset")
    assert caught.value.code == "provider_not_found"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_reader_maps_retryable_provider_failures(monkeypatch, status) -> None:
    monkeypatch.setattr(
        "pdi.observation.ocr.requests.get",
        lambda *args, **kwargs: FakeResponse(status, {}),
    )
    reader = ImmichOCRReader(
        ImmichSettings(url="https://immich.example", api_key="key")
    )
    with pytest.raises(ObservationExtractionError) as caught:
        reader.get_asset_ocr("asset")
    assert caught.value.code == "provider_unavailable"


@pytest.mark.parametrize(
    "error",
    [requests.Timeout("timeout"), requests.ConnectionError("offline")],
)
def test_reader_maps_transport_failures(monkeypatch, error) -> None:
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("pdi.observation.ocr.requests.get", fail)
    reader = ImmichOCRReader(
        ImmichSettings(url="https://immich.example", api_key="key")
    )
    with pytest.raises(ObservationExtractionError) as caught:
        reader.get_asset_ocr("asset")
    assert caught.value.code == "provider_unavailable"


@pytest.mark.parametrize(
    "payload",
    [
        ValueError("not json"),
        {},
        ["not an object"],
        [{}],
        [{"text": None}],
        [{"text": 1}],
    ],
)
def test_reader_rejects_malformed_responses(monkeypatch, payload) -> None:
    monkeypatch.setattr(
        "pdi.observation.ocr.requests.get",
        lambda *args, **kwargs: FakeResponse(200, payload),
    )
    reader = ImmichOCRReader(
        ImmichSettings(url="https://immich.example", api_key="key")
    )
    with pytest.raises(ObservationExtractionError) as caught:
        reader.get_asset_ocr("asset")
    assert caught.value.code == "provider_invalid_response"


@pytest.mark.parametrize(
    ("regions", "expected"),
    [
        (("",), None),
        (("   \t  ",), None),
        (("a\tb",), "a b"),
        (("a\rb",), "a\nb"),
        (("a\r\nb",), "a\nb"),
        ((" a \n\n b ",), "a\nb"),
        (("中文  文本",), "中文 文本"),
        (("A\u200b B",), "A\u200b B"),
        (("é", "e\u0301"), "é\ne\u0301"),
        (("first", "second"), "first\nsecond"),
        (("!@#", "中—English"), "!@#\n中—English"),
    ],
)
def test_normalization_is_minimal_deterministic_and_ordered(
    regions,
    expected,
) -> None:
    batch, _ = _extract(*regions)
    if expected is None:
        assert batch.statements == ()
    else:
        assert batch.statements[0].value.value == expected


@pytest.mark.parametrize("size", [8191, 8192])
def test_values_at_or_below_boundary_are_unchanged(size) -> None:
    value = "a" * size
    batch, _ = _extract(value)
    assert batch.statements[0].value.value == value


def test_truncation_is_utf8_safe_marked_and_bounded() -> None:
    marker = "\n[…truncated]"
    batch, _ = _extract("中" * 3000)
    value = batch.statements[0].value.value
    assert value.endswith(marker)
    assert len(value.encode("utf-8")) <= 8192
    assert value.encode("utf-8").decode("utf-8") == value


def test_8193_bytes_truncate_and_trim_tail_whitespace() -> None:
    marker = "\n[…truncated]"
    batch, _ = _extract("a" * 8176 + " " + "b" * 16)
    value = batch.statements[0].value.value
    assert value.endswith(marker)
    assert not value.removesuffix(marker).endswith((" ", "\n"))
    assert len(value.encode("utf-8")) <= 8192


def test_fingerprint_is_relevant_only_full_and_order_sensitive() -> None:
    first, _ = _extract("one", "two")
    same, _ = _extract("one", "two")
    changed, _ = _extract("one", "changed")
    reordered, _ = _extract("two", "one")
    locator_changed, _ = _extract("one", "two", locator="other-asset")
    assert first.input_fingerprint == same.input_fingerprint
    assert first.input_fingerprint != changed.input_fingerprint
    assert first.input_fingerprint != reordered.input_fingerprint
    assert first.input_fingerprint != locator_changed.input_fingerprint

    long_prefix = "a" * 9000
    tail_a, _ = _extract(long_prefix + "A")
    tail_b, _ = _extract(long_prefix + "B")
    assert tail_a.statements[0].value.value == tail_b.statements[0].value.value
    assert tail_a.input_fingerprint != tail_b.input_fingerprint


def test_region_transport_metadata_cannot_affect_fingerprint(monkeypatch) -> None:
    payloads = [
        [{"text": "same", "id": "one", "boxScore": 0.1}],
        [{"text": "same", "id": "two", "boxScore": 0.9}],
    ]
    readers = []
    for payload in payloads:
        monkeypatch.setattr(
            "pdi.observation.ocr.requests.get",
            lambda *args, _payload=payload, **kwargs: FakeResponse(
                200,
                _payload,
            ),
        )
        reader = ImmichOCRReader(
            ImmichSettings(url="https://immich.example", api_key="key")
        )
        readers.append(reader.get_asset_ocr("asset"))
    first = ImmichOCRExtractor(FakeReader(readers[0])).extract(_resource())
    second = ImmichOCRExtractor(FakeReader(readers[1])).extract(_resource())
    assert first.input_fingerprint == second.input_fingerprint


def test_extractor_emits_frozen_statement_contract() -> None:
    batch, reader = _extract(" Hello ", "世界")
    statement = batch.statements[0]
    assert batch.generator.generator_type == "provider_native_ml"
    assert batch.generator.generator_name == "immich_ocr"
    assert batch.generator.generator_version == "1"
    assert batch.covered_predicates == ("media.ocr_text",)
    assert statement.predicate == "media.ocr_text"
    assert statement.value.value_type == "string"
    assert statement.value.value == "Hello\n世界"
    assert statement.evidence.source_kind == "provider_metadata"
    assert statement.evidence.source_locator == "immich.api.asset_ocr"
    assert statement.confidence is None
    assert reader.locators == ["immich-asset-1"]
    assert "immich-asset-1" not in repr(batch)


def test_extractor_completes_successful_zero_result() -> None:
    batch, _ = _extract("", "  \t ")
    assert batch.covered_predicates == ("media.ocr_text",)
    assert batch.statements == ()
    assert len(batch.input_fingerprint) == 64


def test_active_source_selection_is_never_arbitrary() -> None:
    extractor = ImmichOCRExtractor(FakeReader(()))
    with pytest.raises(ObservationExtractionError):
        extractor.extract(_resource(sources=()))

    sources = (
        EnrichmentSource(str(uuid4()), "immich", {}, "one"),
        EnrichmentSource(str(uuid4()), "immich", {}, "two"),
    )
    with pytest.raises(ObservationExtractionError) as caught:
        extractor.extract(_resource(sources=sources))
    assert caught.value.code == "ambiguous_active_immich_source"


def test_provider_locator_is_required_but_not_public_evidence() -> None:
    source = EnrichmentSource(str(uuid4()), "immich", {})
    extractor = ImmichOCRExtractor(FakeReader((OCRRegion("text"),)))
    with pytest.raises(ObservationExtractionError) as caught:
        extractor.extract(_resource(sources=(source,)))
    assert caught.value.code == "provider_not_found"
