import xml.etree.ElementTree as ET
from collections import Counter
import urllib.parse

import pytest
import requests

from pdi.adapters.base import (
    ProviderFact,
    ProviderResourceDisappearedError,
)
from pdi.adapters.nextcloud.adapter import NextcloudAdapter


DAV_ROOT = "/remote.php/dav/files/test-user/"


class FakeResponse:
    def __init__(
        self,
        text: str,
        *,
        status_code: int = 200,
        chunks: tuple[bytes, ...] = (b"content",),
        error: Exception | None = None,
    ) -> None:
        self.text = text
        self.status_code = status_code
        self.chunks = chunks
        self.error = error
        self.raise_for_status_called = False
        self.closed = False

    def raise_for_status(self) -> None:
        self.raise_for_status_called = True

        if self.error is not None:
            raise self.error

        if self.status_code >= 400:
            raise requests.HTTPError(
                f"synthetic HTTP {self.status_code}"
            )

    def iter_content(self, chunk_size: int):
        assert chunk_size == 1024 * 1024
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


def _webdav_response(
    *,
    path: str,
    external_id: str,
    collection: bool = False,
) -> str:
    normalized_path = path.strip("/")
    href = f"{DAV_ROOT}{normalized_path}"

    if collection or not normalized_path:
        href += "/" if normalized_path else ""

    resource_type = (
        "<d:resourcetype><d:collection /></d:resourcetype>"
        if collection
        else "<d:resourcetype />"
    )

    return f"""
    <d:response>
      <d:href>{href}</d:href>
      <d:propstat>
        <d:prop>
          <oc:id>{external_id}</oc:id>
          <oc:fileid>{external_id}-fileid</oc:fileid>
          <d:getcontentlength>10</d:getcontentlength>
          <d:getcontenttype>text/plain</d:getcontenttype>
          <d:getetag>etag-{external_id}</d:getetag>
          <d:getlastmodified>Sun, 10 Aug 2026 00:00:00 GMT</d:getlastmodified>
          {resource_type}
        </d:prop>
      </d:propstat>
    </d:response>
    """


def _multistatus(*responses: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<d:multistatus xmlns:d="DAV:" '
        'xmlns:oc="http://owncloud.org/ns">'
        + "".join(responses)
        + "</d:multistatus>"
    )


def _adapter() -> NextcloudAdapter:
    return NextcloudAdapter(
        base_url="https://nextcloud.example",
        username="test-user",
        password="test-password",
    )


def test_connect_validates_configured_user_webdav_root(monkeypatch) -> None:
    calls = []

    def fake_request(*, method, url, **kwargs):
        calls.append((method, url, kwargs))
        return FakeResponse(
            _multistatus(
                _webdav_response(
                    path="",
                    external_id="root-self",
                    collection=True,
                )
            )
        )

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request", fake_request
    )

    _adapter().connect()

    assert len(calls) == 1
    method, url, kwargs = calls[0]
    assert method == "PROPFIND"
    assert url == "https://nextcloud.example" + DAV_ROOT
    assert kwargs["headers"]["Depth"] == "0"
    assert kwargs["auth"] == ("test-user", "test-password")


def test_connect_rejects_failed_or_malformed_user_webdav_root(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        lambda **kwargs: FakeResponse("", status_code=401),
    )
    with pytest.raises(requests.HTTPError):
        _adapter().connect()

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        lambda **kwargs: FakeResponse(_multistatus()),
    )
    with pytest.raises(ValueError, match="WebDAV root"):
        _adapter().connect()


def test_scan_discovers_complete_tree_with_stable_external_ids(
    monkeypatch,
) -> None:
    responses = {
        "": _multistatus(
            _webdav_response(
                path="",
                external_id="root-self",
                collection=True,
            ),
            _webdav_response(
                path="root.md",
                external_id="root-file-id",
            ),
            _webdav_response(
                path="A",
                external_id="folder-a-id",
                collection=True,
            ),
            _webdav_response(
                path="Sibling",
                external_id="folder-sibling-id",
                collection=True,
            ),
        ),
        "A": _multistatus(
            _webdav_response(
                path="A/",
                external_id="folder-a-id",
                collection=True,
            ),
            _webdav_response(
                path="A/level1.md",
                external_id="level1-file-id",
            ),
            _webdav_response(
                path="A/B",
                external_id="folder-b-id",
                collection=True,
            ),
        ),
        "Sibling": _multistatus(
            _webdav_response(
                path="Sibling/",
                external_id="folder-sibling-id",
                collection=True,
            ),
            _webdav_response(
                path="Sibling/sibling.md",
                external_id="sibling-file-id",
            ),
        ),
        "A/B": _multistatus(
            _webdav_response(
                path="/A/B/",
                external_id="folder-b-id",
                collection=True,
            ),
            _webdav_response(
                path="A/B/level2.md",
                external_id="level2-file-id",
            ),
        ),
    }
    requested_paths: list[str] = []
    fake_responses: list[FakeResponse] = []

    def fake_request(*, method: str, url: str, **kwargs):
        assert method == "PROPFIND"
        assert kwargs["headers"]["Depth"] == "1"
        relative_path = url.removeprefix(
            "https://nextcloud.example" + DAV_ROOT
        ).strip("/")
        requested_paths.append(relative_path)
        response = FakeResponse(responses[relative_path])
        fake_responses.append(response)
        return response

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        fake_request,
    )

    facts = list(_adapter().scan())

    assert requested_paths == [
        "",
        "A",
        "Sibling",
        "A/B",
    ]
    assert all(
        response.raise_for_status_called
        for response in fake_responses
    )
    assert [fact.attributes["path"] for fact in facts] == [
        "root.md",
        "A/",
        "Sibling/",
        "A/level1.md",
        "A/B/",
        "Sibling/sibling.md",
        "A/B/level2.md",
    ]
    assert {
        fact.attributes["path"]: fact.external_id
        for fact in facts
    }["A/B/level2.md"] == "level2-file-id"
    assert "root-self" not in {
        fact.external_id
        for fact in facts
    }
    assert Counter(requested_paths) == {
        "": 1,
        "A": 1,
        "Sibling": 1,
        "A/B": 1,
    }
    assert all(
        fact.raw["getlastmodified"]
        == "Sun, 10 Aug 2026 00:00:00 GMT"
        for fact in facts
    )
    assert all("creationdate" not in fact.raw for fact in facts)


def test_search_by_fileid_is_scoped_and_exact_propfind_reuses_mapping(
    monkeypatch,
) -> None:
    calls = []
    search_xml = _multistatus(
        _webdav_response(path="renamed/文 件.txt", external_id="oc-id")
    )
    exact_xml = _multistatus(
        _webdav_response(path="renamed/文 件.txt", external_id="oc-id")
    )

    def fake_request(*, method, url, **kwargs):
        calls.append((method, url, kwargs))
        return FakeResponse(search_xml if method == "SEARCH" else exact_xml)

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request", fake_request
    )
    adapter = _adapter()
    located = adapter.search_by_fileid("123")
    assert located is not None
    assert located.attributes["path"] == "renamed/文 件.txt"
    fact = adapter.propfind_exact(located.attributes["path"])
    assert fact is not None
    assert fact.external_id == located.external_id
    assert calls[0][0:2] == (
        "SEARCH", "https://nextcloud.example/remote.php/dav/"
    )
    assert "<d:href>/files/test-user</d:href>" in calls[0][2]["data"]
    assert "<oc:fileid/>" in calls[0][2]["data"]
    assert "<d:literal>123</d:literal>" in calls[0][2]["data"]
    assert calls[1][0] == "PROPFIND"
    assert calls[1][2]["headers"]["Depth"] == "0"
    assert "%E6%96%87%20%E4%BB%B6.txt" in calls[1][1]
    assert not calls[1][1].endswith("/")


def test_fileid_search_rejects_multiple_results(monkeypatch) -> None:
    response = _multistatus(
        _webdav_response(path="A.txt", external_id="a"),
        _webdav_response(path="B.txt", external_id="b"),
    )
    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        lambda **kwargs: FakeResponse(response),
    )
    with pytest.raises(ValueError, match="multiple resources"):
        _adapter().search_by_fileid("123")


@pytest.mark.parametrize("status", [404, 410])
def test_exact_propfind_missing_returns_none(monkeypatch, status) -> None:
    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        lambda **kwargs: FakeResponse("", status_code=status),
    )
    assert _adapter().propfind_exact("gone.txt") is None


def test_scan_yields_before_requesting_later_directories(
    monkeypatch,
) -> None:
    root_file = ProviderFact(
        provider="nextcloud",
        kind="file",
        external_id="root-file-id",
        name="root.md",
        attributes={"path": "root.md"},
        raw={"href": f"{DAV_ROOT}root.md"},
    )
    folder = ProviderFact(
        provider="nextcloud",
        kind="folder",
        external_id="folder-a-id",
        name="A",
        attributes={"path": "A/"},
        raw={"href": f"{DAV_ROOT}A/"},
    )
    nested_file = ProviderFact(
        provider="nextcloud",
        kind="file",
        external_id="nested-file-id",
        name="nested.md",
        attributes={"path": "A/nested.md"},
        raw={"href": f"{DAV_ROOT}A/nested.md"},
    )
    requested_paths: list[str] = []

    def fake_propfind(path: str) -> list[ProviderFact]:
        requested_paths.append(path)
        return [root_file, folder] if path == "" else [nested_file]

    adapter = _adapter()
    monkeypatch.setattr(adapter, "_propfind", fake_propfind)

    facts = iter(adapter.scan())
    assert next(facts) is root_file
    assert requested_paths == [""]
    assert list(facts) == [folder, nested_file]
    assert requested_paths == ["", "A"]


def test_scan_streams_large_synthetic_tree_breadth_first(
    monkeypatch,
) -> None:
    directory_count = 64
    folders = [
        ProviderFact(
            provider="nextcloud",
            kind="folder",
            external_id=f"folder-{index}",
            name=f"D{index}",
            attributes={"path": f"D{index}/"},
            raw={"href": f"{DAV_ROOT}D{index}/"},
        )
        for index in range(directory_count)
    ]
    requested_paths: list[str] = []

    def fake_propfind(path: str) -> list[ProviderFact]:
        requested_paths.append(path)
        if path == "":
            return folders
        return [
            ProviderFact(
                provider="nextcloud",
                kind="file",
                external_id=f"file-{path}",
                name="item.txt",
                attributes={"path": f"{path}/item.txt"},
                raw={"href": f"{DAV_ROOT}{path}/item.txt"},
            )
        ]

    adapter = _adapter()
    monkeypatch.setattr(adapter, "_propfind", fake_propfind)

    facts = iter(adapter.scan())
    assert next(facts) is folders[0]
    assert requested_paths == [""]

    remaining = list(facts)
    assert requested_paths == [""] + [
        f"D{index}" for index in range(directory_count)
    ]
    assert remaining[: directory_count - 1] == folders[1:]
    assert len(remaining) == (directory_count - 1) + directory_count


def test_scan_visits_a_repeated_directory_path_only_once(
    monkeypatch,
) -> None:
    adapter = _adapter()
    folder = ProviderFact(
        provider="nextcloud",
        kind="folder",
        external_id="folder-a-id",
        name="A",
        attributes={"path": "A/"},
        raw={},
    )
    calls: list[str] = []

    def fake_propfind(path: str) -> list[ProviderFact]:
        calls.append(path)
        return [folder, folder] if path == "" else []

    monkeypatch.setattr(adapter, "_propfind", fake_propfind)

    list(adapter.scan())

    assert calls == ["", "A"]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("", ""),
        ("/", ""),
        ("/A/", "A"),
        ("/A Folder/", "A Folder"),
    ],
)
def test_traversal_path_normalization(
    path: str,
    expected: str,
) -> None:
    assert (
        NextcloudAdapter._normalize_traversal_path(path)
        == expected
    )


def test_scan_propagates_malformed_nested_response(
    monkeypatch,
) -> None:
    responses = {
        "": _multistatus(
            _webdav_response(
                path="",
                external_id="root-self",
                collection=True,
            ),
            _webdav_response(
                path="A",
                external_id="folder-a-id",
                collection=True,
            ),
        ),
        "A": "<not-valid-webdav",
    }

    def fake_request(*, url: str, **kwargs):
        relative_path = url.removeprefix(
            "https://nextcloud.example" + DAV_ROOT
        ).strip("/")
        return FakeResponse(responses[relative_path])

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        fake_request,
    )

    with pytest.raises(ET.ParseError):
        list(_adapter().scan())


def test_scan_propagates_nested_http_failure(
    monkeypatch,
) -> None:
    root_response = _multistatus(
        _webdav_response(
            path="",
            external_id="root-self",
            collection=True,
        ),
        _webdav_response(
            path="A",
            external_id="folder-a-id",
            collection=True,
        ),
    )

    def fake_request(*, url: str, **kwargs):
        relative_path = url.removeprefix(
            "https://nextcloud.example" + DAV_ROOT
        ).strip("/")

        if relative_path == "A":
            return FakeResponse(
                "",
                error=requests.HTTPError("nested directory failed"),
            )

        return FakeResponse(root_response)

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.request",
        fake_request,
    )

    with pytest.raises(
        requests.HTTPError,
        match="nested directory failed",
    ):
        list(_adapter().scan())


def _file_fact(relative_path: str) -> ProviderFact:
    href = DAV_ROOT + urllib.parse.quote(relative_path, safe="/")
    xml = _multistatus(
        _webdav_response(
            path=urllib.parse.quote(relative_path, safe="/"),
            external_id="file-id",
        )
    )
    fact = _adapter()._parse_webdav_response(
        xml,
        current_path="unrelated",
    )[0]
    assert fact.raw["href"] == href
    return fact


def test_open_stable_file_uses_one_attempt(monkeypatch) -> None:
    response = FakeResponse("", chunks=(b"one", b"two"))
    calls: list[str] = []

    def fake_get(url: str, **kwargs):
        calls.append(url)
        return response

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.get",
        fake_get,
    )
    fact = _file_fact("中文/stable file.txt")

    assert list(_adapter().open(fact)) == [b"one", b"two"]
    assert calls == ["https://nextcloud.example" + fact.raw["href"]]
    assert response.closed is True


def test_open_retries_one_404_then_succeeds(monkeypatch) -> None:
    responses = [
        FakeResponse("", status_code=404),
        FakeResponse("", chunks=(b"recovered",)),
    ]
    calls = 0

    def fake_get(url: str, **kwargs):
        nonlocal calls
        calls += 1
        return responses.pop(0)

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.get",
        fake_get,
    )

    assert list(_adapter().open(_file_fact("transition.txt"))) == [
        b"recovered"
    ]
    assert calls == 2


@pytest.mark.parametrize("status_code", [404, 410])
def test_open_maps_persistent_missing_status_to_typed_error(
    monkeypatch,
    status_code: int,
) -> None:
    responses = [
        FakeResponse("", status_code=status_code),
        FakeResponse("", status_code=status_code),
    ]
    calls = 0

    def fake_get(url: str, **kwargs):
        nonlocal calls
        calls += 1
        return responses.pop(0)

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.get",
        fake_get,
    )
    private_name = "private-sensitive-name.txt"

    with pytest.raises(ProviderResourceDisappearedError) as raised:
        list(_adapter().open(_file_fact(private_name)))

    assert calls == 2
    assert raised.value.provider == "nextcloud"
    assert private_name not in str(raised.value)


@pytest.mark.parametrize("status_code", [401, 403, 408, 429, 500])
def test_open_preserves_ordinary_http_failures(
    monkeypatch,
    status_code: int,
) -> None:
    calls = 0

    def fake_get(url: str, **kwargs):
        nonlocal calls
        calls += 1
        return FakeResponse("", status_code=status_code)

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.get",
        fake_get,
    )

    with pytest.raises(requests.HTTPError):
        list(_adapter().open(_file_fact("ordinary.txt")))

    assert calls == 1


@pytest.mark.parametrize(
    "failure",
    [
        requests.Timeout("synthetic timeout"),
        requests.ConnectionError("synthetic connection failure"),
    ],
)
def test_open_preserves_transport_failure_without_retry(
    monkeypatch,
    failure: requests.RequestException,
) -> None:
    calls = 0

    def fake_get(url: str, **kwargs):
        nonlocal calls
        calls += 1
        raise failure

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.get",
        fake_get,
    )

    with pytest.raises(type(failure), match="synthetic"):
        list(_adapter().open(_file_fact("timeout.txt")))

    assert calls == 1


@pytest.mark.parametrize(
    "relative_path",
    [
        "download/数学建模/资料 包_100%_#+?.zip",
        "unicode/café.txt",
        "unicode/cafe\u0301.txt",
    ],
)
def test_raw_href_and_unicode_encoding_are_preserved(
    monkeypatch,
    relative_path: str,
) -> None:
    fact = _file_fact(relative_path)
    captured_urls: list[str] = []

    def fake_get(url: str, **kwargs):
        captured_urls.append(url)
        return FakeResponse("", chunks=(b"content",))

    monkeypatch.setattr(
        "pdi.adapters.nextcloud.adapter.requests.get",
        fake_get,
    )

    assert fact.attributes["path"] == relative_path
    assert list(_adapter().open(fact)) == [b"content"]
    assert captured_urls == [
        "https://nextcloud.example" + fact.raw["href"]
    ]
