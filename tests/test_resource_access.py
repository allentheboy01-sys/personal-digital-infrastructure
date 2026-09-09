import asyncio
from dataclasses import FrozenInstanceError
from uuid import uuid4

import httpx
import pytest

from pdi.query import format_resource_ref
from pdi.resource_access import (
    AmbiguousAccessSourceError,
    CHUNK_SIZE,
    ImmichRepresentationAdapter,
    InvalidResourceReferenceError,
    PREVIEW_MAX_BYTES,
    ProviderInvalidResponseError,
    ProviderRepresentation,
    ProviderUnavailableError,
    RepresentationTooLargeError,
    RepresentationUnavailableError,
    ResourceAccessService,
    ResourceAccessSource,
    ResourceAccessUnavailableError,
    ResourceNotFoundError,
    ResourceRepresentationDescriptor,
    ResourceRepresentationKind,
    ResourceVideoDescriptor,
    THUMBNAIL_MAX_BYTES,
    UnsupportedRepresentationError,
)


def _source(
    locator: str = "source-a",
    *,
    provider: str = "immich",
    mime_type: str | None = "image/jpeg",
    resource_type: str = "file",
) -> ResourceAccessSource:
    return ResourceAccessSource(
        provider=provider,
        provider_locator=locator,
        resource_type=resource_type,
        mime_type=mime_type,
    )


class StubRepository:
    def __init__(self, sources=()) -> None:
        self.sources = sources
        self.calls: list[str] = []

    def resolve_access_sources(self, asset_id: str):
        self.calls.append(asset_id)
        return self.sources


class StubAdapter:
    provider = "immich"

    def __init__(
        self,
        *,
        status_code: int = 200,
        media_type: str | None = "image/webp",
        content_length: str | None = None,
        chunks: tuple[bytes, ...] = (b"image",),
    ) -> None:
        self.status_code = status_code
        self.media_type = media_type
        self.content_length = content_length
        self.chunks = chunks
        self.calls: list[tuple[str, ResourceRepresentationKind]] = []
        self.video_calls: list[tuple[str, str | None]] = []
        self.close_count = 0
        self.read_count = 0

    async def open_representation(self, locator, kind):
        self.calls.append((locator, kind))

        async def body():
            for chunk in self.chunks:
                self.read_count += 1
                yield chunk

        async def close():
            self.close_count += 1

        return ProviderRepresentation(
            status_code=self.status_code,
            media_type=self.media_type,
            content_length=self.content_length,
            etag='"opaque"',
            last_modified="Sat, 16 Aug 2026 00:00:00 GMT",
            body=body(),
            close=close,
        )

    async def open_video(self, locator, byte_range):
        self.video_calls.append((locator, byte_range))

        async def body():
            for chunk in self.chunks:
                self.read_count += 1
                yield chunk

        async def close():
            self.close_count += 1

        return ProviderRepresentation(
            status_code=206 if byte_range else 200,
            media_type="video/mp4",
            content_length=self.content_length,
            etag='"opaque"',
            last_modified="Sat, 16 Aug 2026 00:00:00 GMT",
            body=body(),
            close=close,
            content_range="bytes 0-0/42" if byte_range else None,
            accept_ranges="bytes",
        )

    async def aclose(self):
        return None


def _service(repository, adapter=None, *, cap=8):
    selected = adapter or StubAdapter()
    return (
        ResourceAccessService(
            repository,
            {selected.provider: selected},
            max_active_streams=cap,
        ),
        selected,
    )


async def _collect(opened) -> bytes:
    return b"".join([chunk async for chunk in opened])


def test_models_are_immutable_and_locator_is_repr_hidden() -> None:
    source = _source("private-provider-locator")
    descriptor = ResourceRepresentationDescriptor(
        resource_ref=format_resource_ref(uuid4()),
        representation_kind=ResourceRepresentationKind.THUMBNAIL,
        media_type="image/webp",
        content_length=5,
        etag=None,
        last_modified=None,
        provider="immich",
    )

    assert "private-provider-locator" not in repr(source)
    with pytest.raises(FrozenInstanceError):
        source.provider = "changed"
    with pytest.raises(FrozenInstanceError):
        descriptor.media_type = "image/jpeg"
    assert tuple(ResourceRepresentationKind) == (
        ResourceRepresentationKind.THUMBNAIL,
        ResourceRepresentationKind.PREVIEW,
    )


def test_service_validates_canonical_ref_and_kind() -> None:
    service, _ = _service(StubRepository((_source(),)))

    async def run() -> None:
        with pytest.raises(InvalidResourceReferenceError):
            await service.open_representation(
                "pdi:resource:NOT-CANONICAL",
                "thumbnail",
            )
        with pytest.raises(UnsupportedRepresentationError):
            await service.open_representation(
                format_resource_ref(uuid4()),
                "original",
            )

    asyncio.run(run())


@pytest.mark.parametrize(
    ("sources", "expected"),
    [
        (None, ResourceNotFoundError),
        ((), RepresentationUnavailableError),
        ((_source(resource_type="message"),), RepresentationUnavailableError),
        ((_source(provider="nextcloud"),), RepresentationUnavailableError),
        (
            (_source(mime_type="application/octet-stream"),),
            RepresentationUnavailableError,
        ),
        ((_source(), _source("source-b")), AmbiguousAccessSourceError),
    ],
)
def test_service_source_resolution(sources, expected) -> None:
    service, adapter = _service(StubRepository(sources))

    async def run() -> None:
        with pytest.raises(expected):
            await service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            )

    asyncio.run(run())
    assert adapter.calls == []


def test_null_mime_is_ineligible_without_crashing() -> None:
    service, adapter = _service(StubRepository((_source(mime_type=None),)))

    async def run() -> None:
        with pytest.raises(RepresentationUnavailableError):
            await service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            )
        with pytest.raises(RepresentationUnavailableError):
            await service.open_video(format_resource_ref(uuid4()), None)

    asyncio.run(run())
    assert adapter.calls == []
    assert adapter.video_calls == []


def test_video_thumbnail_is_a_bounded_image_representation() -> None:
    resource_ref = format_resource_ref(uuid4())
    adapter = StubAdapter(content_length="5")
    service, _ = _service(
        StubRepository((_source(mime_type="video/mp4"),)),
        adapter,
    )

    async def run() -> None:
        opened = await service.open_representation(resource_ref, "thumbnail")
        assert opened.descriptor.media_type == "image/webp"
        assert await _collect(opened) == b"image"

    asyncio.run(run())


def test_video_playback_preserves_range_and_streams_without_image_bounds() -> None:
    resource_ref = format_resource_ref(uuid4())
    chunks = (b"first", b"second")
    adapter = StubAdapter(content_length="11", chunks=chunks)
    service, _ = _service(
        StubRepository((_source(mime_type="video/quicktime"),)),
        adapter,
    )

    async def run() -> None:
        opened = await service.open_video(resource_ref, "bytes=0-0")
        assert adapter.read_count == 0
        assert opened.descriptor == ResourceVideoDescriptor(
            resource_ref=resource_ref,
            status_code=206,
            media_type="video/mp4",
            content_length=11,
            content_range="bytes 0-0/42",
            accept_ranges="bytes",
            provider="immich",
        )
        iterator = opened.__aiter__()
        assert await anext(iterator) == b"first"
        assert adapter.read_count == 1
        assert await anext(iterator) == b"second"
        await opened.aclose()

    asyncio.run(run())
    assert adapter.calls == []
    assert adapter.video_calls == [("source-a", "bytes=0-0")]


def test_video_playback_rejects_invalid_range_before_provider_call() -> None:
    adapter = StubAdapter()
    service, _ = _service(
        StubRepository((_source(mime_type="video/mp4"),)),
        adapter,
    )

    async def run() -> None:
        with pytest.raises(UnsupportedRepresentationError):
            await service.open_video(
                format_resource_ref(uuid4()),
                "bytes=0-1,4-5",
            )

    asyncio.run(run())
    assert adapter.video_calls == []


def test_video_stream_cancellation_closes_upstream_and_releases_slot() -> None:
    closed = asyncio.Event()

    class CancelAdapter(StubAdapter):
        def __init__(self) -> None:
            super().__init__()
            self.video_count = 0

        async def open_video(self, locator, byte_range):
            del locator, byte_range
            self.video_count += 1
            current = self.video_count

            async def body():
                yield b"first"
                if current == 1:
                    await asyncio.Event().wait()

            async def close():
                if current == 1:
                    closed.set()

            return ProviderRepresentation(
                200,
                "video/mp4",
                None,
                None,
                None,
                body(),
                close,
                accept_ranges="bytes",
            )

    adapter = CancelAdapter()
    resource_ref = format_resource_ref(uuid4())
    service, _ = _service(
        StubRepository((_source(mime_type="video/mp4"),)),
        adapter,
        cap=1,
    )

    async def run() -> None:
        first = await service.open_video(resource_ref)

        async def consume() -> None:
            async for _ in first:
                pass

        task = asyncio.create_task(consume())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(closed.wait(), timeout=0.5)

        second = await asyncio.wait_for(
            service.open_video(resource_ref),
            timeout=0.5,
        )
        assert await _collect(second) == b"first"

    asyncio.run(run())
    assert adapter.video_count == 2


def test_repository_failure_is_sanitized_without_connection_details() -> None:
    class FailingRepository:
        def resolve_access_sources(self, asset_id: str):
            del asset_id
            raise RuntimeError(
                "password=private postgresql://role:private@database/pdi"
            )

    service, adapter = _service(FailingRepository())

    async def run() -> None:
        with pytest.raises(ResourceAccessUnavailableError) as captured:
            await service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            )
        assert captured.value.__cause__ is None
        serialized = str(captured.value)
        assert "password" not in serialized
        assert "postgresql" not in serialized
        assert "private" not in serialized

    asyncio.run(run())
    assert adapter.calls == []


def test_service_returns_descriptor_and_lazy_bounded_stream() -> None:
    resource_ref = format_resource_ref(uuid4())
    adapter = StubAdapter(
        content_length="6",
        chunks=(b"one", b"two"),
    )
    service, _ = _service(StubRepository((_source(),)), adapter)

    async def run() -> None:
        opened = await service.open_representation(
            resource_ref,
            ResourceRepresentationKind.THUMBNAIL,
        )
        assert adapter.read_count == 0
        assert opened.descriptor == ResourceRepresentationDescriptor(
            resource_ref=resource_ref,
            representation_kind=ResourceRepresentationKind.THUMBNAIL,
            media_type="image/webp",
            content_length=6,
            etag='"opaque"',
            last_modified="Sat, 16 Aug 2026 00:00:00 GMT",
            provider="immich",
        )
        iterator = opened.__aiter__()
        assert await anext(iterator) == b"one"
        assert adapter.read_count == 1
        assert await anext(iterator) == b"two"
        with pytest.raises(StopAsyncIteration):
            await anext(iterator)
        assert adapter.close_count == 1

    asyncio.run(run())


@pytest.mark.parametrize(
    ("status", "media_type", "content_length", "expected"),
    [
        (302, "image/webp", "5", ProviderInvalidResponseError),
        (404, "application/json", "5", ProviderInvalidResponseError),
        (500, "application/json", "5", ProviderUnavailableError),
        (200, None, "5", ProviderInvalidResponseError),
        (200, "application/json", "5", ProviderInvalidResponseError),
        (200, "image/", "5", ProviderInvalidResponseError),
        (200, "image/webp", "0", ProviderInvalidResponseError),
        (200, "image/webp", "invalid", ProviderInvalidResponseError),
        (
            200,
            "image/webp",
            str(THUMBNAIL_MAX_BYTES + 1),
            RepresentationTooLargeError,
        ),
    ],
)
def test_service_rejects_invalid_provider_response(
    status,
    media_type,
    content_length,
    expected,
) -> None:
    adapter = StubAdapter(
        status_code=status,
        media_type=media_type,
        content_length=content_length,
    )
    service, _ = _service(StubRepository((_source(),)), adapter)

    async def run() -> None:
        with pytest.raises(expected):
            await service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            )

    asyncio.run(run())
    assert adapter.close_count == 1


def test_service_enforces_actual_byte_limit_and_closes() -> None:
    adapter = StubAdapter(
        chunks=(b"a" * THUMBNAIL_MAX_BYTES, b"b"),
    )
    service, _ = _service(StubRepository((_source(),)), adapter)

    async def run() -> None:
        opened = await service.open_representation(
            format_resource_ref(uuid4()),
            "thumbnail",
        )
        with pytest.raises(RepresentationTooLargeError):
            await _collect(opened)

    asyncio.run(run())
    assert adapter.close_count == 1


def test_service_rejects_empty_stream_without_declared_length() -> None:
    adapter = StubAdapter(content_length=None, chunks=())
    service, _ = _service(StubRepository((_source(),)), adapter)

    async def run() -> None:
        opened = await service.open_representation(
            format_resource_ref(uuid4()),
            "thumbnail",
        )
        with pytest.raises(ProviderInvalidResponseError):
            await _collect(opened)

    asyncio.run(run())
    assert adapter.close_count == 1


def test_close_is_deterministic_and_releases_semaphore() -> None:
    class SlowAdapter(StubAdapter):
        async def open_representation(self, locator, kind):
            self.calls.append((locator, kind))

            async def body():
                self.read_count += 1
                yield b"first"
                await asyncio.Event().wait()

            async def close():
                self.close_count += 1

            return ProviderRepresentation(
                200,
                "image/webp",
                None,
                None,
                None,
                body(),
                close,
            )

    adapter = SlowAdapter()
    service, _ = _service(
        StubRepository((_source(),)),
        adapter,
        cap=1,
    )

    async def run() -> None:
        first = await service.open_representation(
            format_resource_ref(uuid4()),
            "preview",
        )

        async def consume() -> None:
            async for _ in first:
                pass

        task = asyncio.create_task(consume())
        while adapter.read_count == 0:
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert adapter.close_count == 1

        second = await asyncio.wait_for(
            service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            ),
            timeout=0.5,
        )
        await second.aclose()
        assert adapter.close_count == 2

    asyncio.run(run())


def test_concurrency_is_capped_for_entire_stream_lifetime() -> None:
    adapter = StubAdapter(content_length="5")
    service, _ = _service(StubRepository((_source(),)), adapter, cap=8)

    async def run() -> None:
        opened = await asyncio.gather(*[
            service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            )
            for _ in range(8)
        ])
        ninth = asyncio.create_task(
            service.open_representation(
                format_resource_ref(uuid4()),
                "thumbnail",
            )
        )
        await asyncio.sleep(0.02)
        assert len(adapter.calls) == 8
        assert not ninth.done()
        await opened[0].aclose()
        ninth_opened = await asyncio.wait_for(ninth, timeout=0.5)
        await ninth_opened.aclose()
        for item in opened[1:]:
            await item.aclose()

    asyncio.run(run())


def test_immich_adapter_uses_official_endpoint_and_64k_streaming() -> None:
    locator = str(uuid4())
    request_seen: httpx.Request | None = None

    class MockByteStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * (CHUNK_SIZE + 1)

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_seen
        request_seen = request
        return httpx.Response(
            200,
            headers={
                "content-type": "image/webp",
                "content-length": str(CHUNK_SIZE + 1),
            },
            stream=MockByteStream(),
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    adapter = ImmichRepresentationAdapter(
        "https://immich.example/",
        "sensitive-key",
        client=client,
    )

    async def run() -> None:
        opened = await adapter.open_representation(
            locator,
            ResourceRepresentationKind.PREVIEW,
        )
        chunks = [chunk async for chunk in opened.body]
        await opened.close()
        assert [len(chunk) for chunk in chunks] == [CHUNK_SIZE, 1]
        await client.aclose()

    asyncio.run(run())
    assert request_seen is not None
    assert request_seen.url.path == f"/api/assets/{locator}/thumbnail"
    assert dict(request_seen.url.params) == {"size": "preview"}
    assert request_seen.headers["x-api-key"] == "sensitive-key"


def test_immich_adapter_forwards_range_to_official_video_endpoint() -> None:
    locator = str(uuid4())
    request_seen: httpx.Request | None = None

    class MockVideoStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"a"
            yield b"b"

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_seen
        request_seen = request
        return httpx.Response(
            206,
            headers={
                "content-type": "video/mp4",
                "content-length": "2",
                "content-range": "bytes 0-1/42",
                "accept-ranges": "bytes",
            },
            stream=MockVideoStream(),
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    adapter = ImmichRepresentationAdapter(
        "https://immich.example/",
        "sensitive-key",
        client=client,
    )

    async def run() -> None:
        opened = await adapter.open_video(locator, "bytes=0-1")
        assert b"".join([chunk async for chunk in opened.body]) == b"ab"
        assert opened.content_range == "bytes 0-1/42"
        assert opened.accept_ranges == "bytes"
        await opened.close()
        await client.aclose()

    asyncio.run(run())
    assert request_seen is not None
    assert request_seen.url.path == f"/api/assets/{locator}/video/playback"
    assert request_seen.headers["range"] == "bytes=0-1"
    assert request_seen.headers["x-api-key"] == "sensitive-key"


def test_immich_adapter_qualifies_expected_account_before_asset_access() -> None:
    locator = str(uuid4())
    expected = str(uuid4())
    paths = []

    class MockByteStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"ok"

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/users/me":
            return httpx.Response(200, json={"id": expected})
        return httpx.Response(
            200,
            headers={"content-type": "image/webp", "content-length": "2"},
            stream=MockByteStream(),
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = ImmichRepresentationAdapter(
        "https://immich.example",
        "sensitive-key",
        expected_user_id=expected,
        client=client,
    )

    async def run() -> None:
        opened = await adapter.open_representation(
            locator, ResourceRepresentationKind.THUMBNAIL
        )
        assert b"".join([chunk async for chunk in opened.body]) == b"ok"
        await opened.close()
        await client.aclose()

    asyncio.run(run())
    assert paths == ["/api/users/me", f"/api/assets/{locator}/thumbnail"]


def test_immich_adapter_rejects_wrong_valid_user_before_asset_access() -> None:
    expected = str(uuid4())
    actual = str(uuid4())
    paths = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"id": actual})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = ImmichRepresentationAdapter(
        "https://immich.example",
        "valid-wrong-user-key",
        expected_user_id=expected,
        client=client,
    )

    async def run() -> None:
        with pytest.raises(ResourceAccessUnavailableError):
            await adapter.open_representation(
                str(uuid4()), ResourceRepresentationKind.THUMBNAIL
            )
        await client.aclose()

    asyncio.run(run())
    assert paths == ["/api/users/me"]


def test_frozen_size_constants() -> None:
    assert THUMBNAIL_MAX_BYTES == 2 * 1024 * 1024
    assert PREVIEW_MAX_BYTES == 16 * 1024 * 1024


def test_immich_adapter_normalizes_connect_and_read_failures() -> None:
    locator = str(uuid4())

    async def connect_failure(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("private upstream", request=request)

    connect_client = httpx.AsyncClient(
        transport=httpx.MockTransport(connect_failure)
    )
    connect_adapter = ImmichRepresentationAdapter(
        "https://private.example",
        "secret",
        client=connect_client,
    )

    class FailingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise httpx.ReadTimeout("private upstream")
            yield b"unreachable"

    async def read_failure(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "image/webp"},
            stream=FailingStream(),
        )

    read_client = httpx.AsyncClient(
        transport=httpx.MockTransport(read_failure)
    )
    read_adapter = ImmichRepresentationAdapter(
        "https://private.example",
        "secret",
        client=read_client,
    )

    async def run() -> None:
        with pytest.raises(ProviderUnavailableError) as connect_error:
            await connect_adapter.open_representation(
                locator,
                ResourceRepresentationKind.THUMBNAIL,
            )
        assert locator not in str(connect_error.value)
        assert "secret" not in str(connect_error.value)

        opened = await read_adapter.open_representation(
            locator,
            ResourceRepresentationKind.THUMBNAIL,
        )
        with pytest.raises(ProviderUnavailableError) as read_error:
            _ = [chunk async for chunk in opened.body]
        await opened.close()
        assert locator not in str(read_error.value)
        assert "secret" not in str(read_error.value)
        await connect_client.aclose()
        await read_client.aclose()

    asyncio.run(run())


def test_backpressure_reads_only_when_downstream_pulls() -> None:
    second_requested = asyncio.Event()
    allow_second = asyncio.Event()

    class PullAdapter(StubAdapter):
        async def open_representation(self, locator, kind):
            del locator, kind

            async def body():
                yield b"first"
                second_requested.set()
                await allow_second.wait()
                yield b"second"

            async def close():
                self.close_count += 1

            return ProviderRepresentation(
                200,
                "image/webp",
                None,
                None,
                None,
                body(),
                close,
            )

    adapter = PullAdapter()
    service, _ = _service(StubRepository((_source(),)), adapter)

    async def run() -> None:
        opened = await service.open_representation(
            format_resource_ref(uuid4()),
            "thumbnail",
        )
        iterator = opened.__aiter__()
        assert await anext(iterator) == b"first"
        await asyncio.sleep(0.01)
        assert not second_requested.is_set()

        pending = asyncio.create_task(anext(iterator))
        await second_requested.wait()
        assert not pending.done()
        allow_second.set()
        assert await pending == b"second"
        await opened.aclose()

    asyncio.run(run())
