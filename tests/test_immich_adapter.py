import logging

import pytest
import requests

from pdi.adapters.base import ProviderFact
from pdi.adapters.immich import (
    ImmichAccountMismatchError,
    ImmichAdapter,
    ImmichPaginationDriftError,
)


class FakeResponse:
    def __init__(
        self,
        *,
        json_data: object | None = None,
        chunks: tuple[bytes, ...] = (),
    ) -> None:
        self.json_data = json_data
        self.chunks = chunks
        self.raise_for_status_called = False
        self.closed = False

    def raise_for_status(self) -> None:
        self.raise_for_status_called = True

    def json(self) -> object:
        return self.json_data

    def iter_content(
        self,
        *,
        chunk_size: int,
    ) -> tuple[bytes, ...]:
        assert chunk_size == 1024 * 1024
        return self.chunks

    def close(self) -> None:
        self.closed = True


def test_connect_verifies_api_key(
    monkeypatch,
    caplog,
) -> None:
    response = FakeResponse()
    request: dict = {}

    def fake_get(url: str, **kwargs):
        request["url"] = url
        request.update(kwargs)
        return response

    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.get",
        fake_get,
    )

    adapter = ImmichAdapter(
        base_url="https://immich.example/",
        api_key="test-api-key",
    )

    with caplog.at_level(logging.INFO):
        adapter.connect()

    assert request == {
        "url": "https://immich.example/api/server/about",
        "headers": {
            "x-api-key": "test-api-key",
        },
        "timeout": 10,
    }
    assert response.raise_for_status_called is True
    assert "Connecting Immich..." in caplog.messages
    assert "Connected to Immich" in caplog.messages


def test_connect_does_not_swallow_http_errors(
    monkeypatch,
) -> None:
    class ErrorResponse(FakeResponse):
        def raise_for_status(self) -> None:
            raise requests.HTTPError(
                "Immich authentication failed"
            )

    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.get",
        lambda *args, **kwargs: ErrorResponse(),
    )

    adapter = ImmichAdapter(
        base_url="https://immich.example",
        api_key="invalid-api-key",
    )

    with pytest.raises(
        requests.HTTPError,
        match="Immich authentication failed",
    ):
        adapter.connect()


def test_connect_binds_api_key_to_expected_authenticated_user(
    monkeypatch,
) -> None:
    user_id = "65f0a1c2-3d4e-4f50-8123-456789abcdef"
    response = FakeResponse(json_data={"id": user_id})
    request = {}

    def fake_get(url, **kwargs):
        request.update(url=url, **kwargs)
        return response

    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.get", fake_get
    )
    ImmichAdapter(
        "https://immich.example",
        "test-api-key",
        expected_user_id=user_id,
    ).connect()

    assert request["url"] == "https://immich.example/api/users/me"
    assert request["headers"] == {"x-api-key": "test-api-key"}


def test_connect_rejects_valid_key_for_different_user(monkeypatch) -> None:
    expected = "65f0a1c2-3d4e-4f50-8123-456789abcdef"
    actual = "75f0a1c2-3d4e-4f50-8123-456789abcdef"
    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.get",
        lambda *args, **kwargs: FakeResponse(json_data={"id": actual}),
    )

    with pytest.raises(ImmichAccountMismatchError):
        ImmichAdapter(
            "https://immich.example",
            "valid-wrong-user-key",
            expected_user_id=expected,
        ).connect()


def test_incremental_scan_qualifies_account_before_metadata_request(
    monkeypatch,
) -> None:
    expected = "65f0a1c2-3d4e-4f50-8123-456789abcdef"
    actual = "75f0a1c2-3d4e-4f50-8123-456789abcdef"
    calls: list[tuple[str, str]] = []

    def fake_get(url, **kwargs):
        calls.append(("GET", url))
        return FakeResponse(json_data={"id": actual})

    def fake_post(url, **kwargs):
        calls.append(("POST", url))
        raise AssertionError("metadata request must not follow account mismatch")

    monkeypatch.setattr("pdi.adapters.immich.adapter.requests.get", fake_get)
    monkeypatch.setattr("pdi.adapters.immich.adapter.requests.post", fake_post)
    adapter = ImmichAdapter(
        "https://immich.example",
        "valid-wrong-user-key",
        expected_user_id=expected,
    )

    with pytest.raises(ImmichAccountMismatchError):
        tuple(
            adapter.scan_updated_window(
                updated_after="2026-01-01T00:00:00Z",
                updated_before="2026-01-01T00:05:00Z",
            )
        )

    assert calls == [("GET", "https://immich.example/api/users/me")]


def test_scan_paginates_and_maps_provider_facts(
    monkeypatch,
    caplog,
) -> None:
    asset = {
        "id": "asset-1",
        "originalPath": "/library/photo.jpg",
        "originalFileName": "photo.jpg",
        "originalMimeType": "image/jpeg",
        "fileModifiedAt": "2026-07-19T01:02:03.456Z",
        "updatedAt": "2026-07-20T01:02:03.000Z",
        # Standard SHA-1 of empty synthetic test content, Base64 encoded.
        "checksum": "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
        "width": 4032,
        "height": 3024,
        "duration": "0:00:00.00000",
        "isFavorite": True,
        "isArchived": False,
        "isTrashed": False,
        "visibility": "timeline",
        "isEdited": False,
        "ownerId": "excluded-owner",
        "libraryId": "excluded-library",
        "thumbhash": "excluded-thumbhash",
        "exifInfo": {
            "fileSizeInByte": 123456,
            "make": "Camera Co.",
            "model": "Camera Model",
            "latitude": 31.2,
            "longitude": 121.5,
            "country": "People's Republic of China",
            "state": "Shanghai",
            "city": "Shanghai",
        },
    }
    second_asset = {
        "id": "asset-2",
        "originalPath": "/library/video.mp4",
        "originalFileName": "video.mp4",
        "originalMimeType": "video/mp4",
        "updatedAt": "2026-07-20T02:03:04.000Z",
        "checksum": "second-checksum",
        "width": 1920,
        "height": 1080,
        "duration": "0:00:12.00000",
        "isFavorite": False,
        "isArchived": True,
        "isTrashed": False,
        "visibility": "archive",
        "isEdited": True,
        "exifInfo": {
            "fileSizeInByte": 654321,
        },
    }
    responses = [
        FakeResponse(
            json_data={
                "assets": {
                    "items": [asset],
                    "nextPage": "2",
                    "count": 1,
                    "total": 1,
                },
            },
        ),
        FakeResponse(
            json_data={
                "assets": {
                    "items": [second_asset],
                    "nextPage": None,
                    "count": 1,
                    "total": 1,
                },
            },
        ),
    ]
    requests: list[dict] = []

    def fake_post(url: str, **kwargs):
        requests.append(
            {
                "url": url,
                **kwargs,
            }
        )
        return responses[(len(requests) - 1) % 2]

    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.post",
        fake_post,
    )

    adapter = ImmichAdapter(
        base_url="https://immich.example",
        api_key="test-api-key",
    )

    with caplog.at_level(logging.INFO):
        facts = list(adapter.scan())

    assert len(facts) == 2
    expected_requests = [
        {
            "url": "https://immich.example/api/search/metadata",
            "headers": {
                "x-api-key": "test-api-key",
            },
            "json": {
                "page": 1,
                "size": 1000,
                "withExif": True,
                "withDeleted": True,
            },
            "timeout": 30,
        },
        {
            "url": "https://immich.example/api/search/metadata",
            "headers": {
                "x-api-key": "test-api-key",
            },
            "json": {
                "page": 2,
                "size": 1000,
                "withExif": True,
                "withDeleted": True,
            },
            "timeout": 30,
        },
    ]
    assert requests == expected_requests * 2
    assert all(
        response.raise_for_status_called
        for response in responses
    )

    fact = facts[0]

    assert fact.provider == "immich"
    assert fact.kind == "file"
    assert fact.external_id == "asset-1"
    assert fact.name == "photo.jpg"
    assert fact.attributes == {
        "path": "/library/photo.jpg",
        "size": 123456,
        "mime_type": "image/jpeg",
        "version_tag": "2026-07-20T01:02:03.000Z",
        "content_hash": None,
    }
    assert fact.raw == {
        "checksum": "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
        "checksum_algorithm": "sha1",
        "checksum_encoding": "base64",
        "width": 4032,
        "height": 3024,
        "exif": {
            "fileSizeInByte": 123456,
            "make": "Camera Co.",
            "model": "Camera Model",
            "latitude": 31.2,
            "longitude": 121.5,
            "country": "People's Republic of China",
            "state": "Shanghai",
            "city": "Shanghai",
        },
        "fileModifiedAt": "2026-07-19T01:02:03.456Z",
        "favorite": True,
        "archived": False,
        "trashed": False,
        "visibility": "timeline",
        "duration": "0:00:00.00000",
        "isEdited": False,
    }
    assert "ownerId" not in fact.raw
    assert "libraryId" not in fact.raw
    assert "thumbhash" not in fact.raw
    assert "fileCreatedAt" not in fact.raw
    assert "createdAt" not in fact.raw
    assert "updatedAt" not in fact.raw
    assert "localDateTime" not in fact.raw
    assert "Scanning Immich..." in caplog.messages
    assert "Found 2 Immich assets" in caplog.messages
    assert "Immich scan finished" in caplog.messages


def test_incremental_search_accepts_page_local_counts_and_verifies_twice(
    monkeypatch,
) -> None:
    responses = [
        FakeResponse(json_data={
            "assets": {
                "items": [{"id": "a"}],
                "count": 1,
                "nextPage": "2",
                "total": 1,
            },
        }),
        FakeResponse(json_data={
            "assets": {
                "items": [{"id": "b"}, {"id": "c"}],
                "count": 2,
                "nextPage": None,
                "total": 2,
            },
        }),
    ]
    calls: list[dict] = []

    def fake_post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        return responses[(len(calls) - 1) % 2]

    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.post", fake_post
    )
    adapter = ImmichAdapter("https://immich.example", "test-key")

    facts = list(adapter.scan_updated_window(
        updated_after="2026-09-03T00:55:00.000000Z",
        updated_before="2026-09-03T01:10:00.000000Z",
    ))

    assert [fact.external_id for fact in facts] == ["a", "b", "c"]
    expected_payloads = [
        {
            "updatedAfter": "2026-09-03T00:55:00.000000Z",
            "updatedBefore": "2026-09-03T01:10:00.000000Z",
            "withDeleted": True,
            "page": 1,
            "size": 1000,
            "withExif": True,
        },
        {
            "updatedAfter": "2026-09-03T00:55:00.000000Z",
            "updatedBefore": "2026-09-03T01:10:00.000000Z",
            "withDeleted": True,
            "page": 2,
            "size": 1000,
            "withExif": True,
        },
    ]
    assert [call["json"] for call in calls] == expected_payloads * 2


@pytest.mark.parametrize(
    "payload",
    [
        {
            "assets": {
                "items": [], "nextPage": "invalid", "count": 0, "total": 0
            }
        },
        {
            "assets": {
                "items": [], "nextPage": "1", "count": 0, "total": 0
            }
        },
        {
            "assets": {
                "items": "invalid", "nextPage": None, "count": 0, "total": 0
            }
        },
        {"missing": "assets"},
    ],
)
def test_search_metadata_fails_closed_on_malformed_pagination(
    monkeypatch,
    payload,
) -> None:
    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.post",
        lambda *args, **kwargs: FakeResponse(json_data=payload),
    )
    adapter = ImmichAdapter("https://immich.example", "test-key")

    with pytest.raises(ValueError):
        list(adapter.scan())


@pytest.mark.parametrize("field", ["total", "count"])
@pytest.mark.parametrize("invalid_value", [None, True, -1, "0", 1])
def test_search_metadata_rejects_invalid_page_local_count(
    monkeypatch,
    field,
    invalid_value,
) -> None:
    page = {
        "items": [],
        "nextPage": None,
        "count": 0,
        "total": 0,
    }
    page[field] = invalid_value
    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.post",
        lambda *args, **kwargs: FakeResponse(json_data={
            "assets": page
        }),
    )

    with pytest.raises(ValueError, match=f"invalid page {field}"):
        list(ImmichAdapter("https://immich.example", "key").scan())


def test_search_metadata_rejects_duplicate_id_within_one_pass(
    monkeypatch,
) -> None:
    responses = [
        FakeResponse(json_data={
            "assets": {
                "items": [{"id": "a"}, {"id": "b"}],
                "count": 2,
                "nextPage": "2",
                "total": 2,
            }
        }),
        FakeResponse(json_data={
            "assets": {
                "items": [{"id": "b"}, {"id": "c"}],
                "count": 2,
                "nextPage": None,
                "total": 2,
            }
        }),
    ]
    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.post",
        lambda *args, **kwargs: responses.pop(0),
    )

    with pytest.raises(ImmichPaginationDriftError, match="repeated an asset"):
        list(ImmichAdapter("https://immich.example", "key").scan())


@pytest.mark.parametrize(
    "verification_ids",
    [
        ["a", "b", "d", "c"],
        ["a", "c"],
        ["b", "a", "c"],
    ],
)
def test_search_metadata_rejects_verification_membership_or_order_drift(
    monkeypatch,
    verification_ids,
) -> None:
    responses = [FakeResponse(json_data={
        "assets": {
            "items": [{"id": item} for item in ids],
            "count": len(ids),
            "total": len(ids),
            "nextPage": None,
        }
    }) for ids in (["a", "b", "c"], verification_ids)]
    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.post",
        lambda *args, **kwargs: responses.pop(0),
    )

    with pytest.raises(
        ImmichPaginationDriftError, match="ordered membership changed"
    ):
        list(ImmichAdapter("https://immich.example", "key").scan())


def test_search_metadata_accepts_different_page_local_totals() -> None:
    adapter = ImmichAdapter("https://immich.example", "key")
    responses = [
        {
            "items": [{"id": "a"}, {"id": "b"}],
            "count": 2,
            "total": 2,
        },
        {
            "items": [{"id": "c"}],
            "count": 1,
            "total": 1,
        },
    ]
    assert [
        adapter._validate_page_count(page, field, len(page["items"]))
        for page in responses
        for field in ("count", "total")
    ] == [None, None, None, None]


@pytest.mark.parametrize(
    ("file_size", "expected_size"),
    [
        (123456, 123456),
        ("123456", 123456),
        (None, None),
        ("", None),
        ("abc", None),
        (True, None),
        (False, None),
        (-1, None),
    ],
)
def test_maps_only_valid_file_sizes(
    file_size,
    expected_size,
) -> None:
    fact = ImmichAdapter._to_provider_fact(
        {
            "id": "asset-1",
            "exifInfo": {
                "fileSizeInByte": file_size,
            },
        }
    )

    assert fact.attributes["size"] == expected_size


@pytest.mark.parametrize(
    "external_id",
    [
        None,
        "",
    ],
)
def test_rejects_invalid_external_id(
    external_id,
) -> None:
    with pytest.raises(
        ValueError,
        match="Immich asset does not contain a valid id",
    ):
        ImmichAdapter._to_provider_fact(
            {
                "id": external_id,
            }
        )


def test_open_streams_original_asset(
    monkeypatch,
) -> None:
    response = FakeResponse(
        chunks=(
            b"first",
            b"",
            b"second",
        ),
    )
    request: dict = {}

    def fake_get(url: str, **kwargs):
        request["url"] = url
        request.update(kwargs)
        return response

    monkeypatch.setattr(
        "pdi.adapters.immich.adapter.requests.get",
        fake_get,
    )

    adapter = ImmichAdapter(
        base_url="https://immich.example",
        api_key="test-api-key",
    )
    fact = ProviderFact(
        provider="immich",
        kind="file",
        external_id="asset/id",
        name="photo.jpg",
        attributes={},
        raw={},
    )

    assert list(adapter.open(fact)) == [
        b"first",
        b"second",
    ]
    assert request == {
        "url": (
            "https://immich.example"
            "/api/assets/asset%2Fid/original"
        ),
        "headers": {
            "x-api-key": "test-api-key",
        },
        "stream": True,
        "timeout": 30,
    }
    assert response.raise_for_status_called is True
    assert response.closed is True
