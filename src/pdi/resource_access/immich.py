from collections.abc import AsyncIterator
from uuid import UUID

import httpx

from pdi.adapters.immich_account import (
    authenticated_immich_user_id,
    canonical_immich_user_id,
)

from .errors import (
    ProviderInvalidResponseError,
    ProviderUnavailableError,
    ResourceAccessUnavailableError,
)
from .models import ResourceRepresentationKind
from .provider import ProviderRepresentation


CHUNK_SIZE = 64 * 1024


class ImmichRepresentationAdapter:
    provider = "immich"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        expected_user_id: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._expected_user_id = (
            None
            if expected_user_id is None
            else canonical_immich_user_id(expected_user_id)
        )
        self._account_verified = False
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(
                max_connections=8,
                max_keepalive_connections=8,
            ),
            timeout=httpx.Timeout(
                connect=3.0,
                read=30.0,
                write=5.0,
                pool=3.0,
            ),
        )

    async def open_representation(
        self,
        provider_locator: str,
        representation_kind: ResourceRepresentationKind,
    ) -> ProviderRepresentation:
        await self._verify_account()
        try:
            locator = UUID(provider_locator)
        except (TypeError, ValueError, AttributeError) as error:
            raise ProviderInvalidResponseError(
                "Provider Source has an invalid locator"
            ) from None

        if str(locator) != provider_locator:
            raise ProviderInvalidResponseError(
                "Provider Source has an invalid locator"
            )

        request = self._client.build_request(
            "GET",
            f"{self._base_url}/api/assets/{locator}/thumbnail",
            headers={"x-api-key": self._api_key},
            params={"size": representation_kind.value},
        )

        try:
            response = await self._client.send(request, stream=True)
        except (httpx.TimeoutException, httpx.RequestError) as error:
            raise ProviderUnavailableError(
                "Immich representation service is unavailable"
            ) from None

        async def body() -> AsyncIterator[bytes]:
            try:
                async for chunk in response.aiter_raw(
                    chunk_size=CHUNK_SIZE,
                ):
                    if chunk:
                        yield chunk
            except (httpx.TimeoutException, httpx.RequestError) as error:
                raise ProviderUnavailableError(
                    "Immich representation stream is unavailable"
                ) from None

        return ProviderRepresentation(
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
            content_length=response.headers.get("content-length"),
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
            body=body(),
            close=response.aclose,
        )

    async def open_video(
        self,
        provider_locator: str,
        byte_range: str | None,
    ) -> ProviderRepresentation:
        await self._verify_account()
        try:
            locator = UUID(provider_locator)
        except (TypeError, ValueError, AttributeError):
            raise ProviderInvalidResponseError(
                "Provider Source has an invalid locator"
            ) from None

        if str(locator) != provider_locator:
            raise ProviderInvalidResponseError(
                "Provider Source has an invalid locator"
            )

        headers = {"x-api-key": self._api_key}
        if byte_range is not None:
            headers["range"] = byte_range
        request = self._client.build_request(
            "GET",
            f"{self._base_url}/api/assets/{locator}/video/playback",
            headers=headers,
        )

        try:
            response = await self._client.send(request, stream=True)
        except (httpx.TimeoutException, httpx.RequestError):
            raise ProviderUnavailableError(
                "Immich video service is unavailable"
            ) from None

        async def body() -> AsyncIterator[bytes]:
            try:
                async for chunk in response.aiter_raw(chunk_size=CHUNK_SIZE):
                    if chunk:
                        yield chunk
            except (httpx.TimeoutException, httpx.RequestError):
                raise ProviderUnavailableError(
                    "Immich video stream is unavailable"
                ) from None

        return ProviderRepresentation(
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
            content_length=response.headers.get("content-length"),
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
            body=body(),
            close=response.aclose,
            content_range=response.headers.get("content-range"),
            accept_ranges=response.headers.get("accept-ranges"),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _verify_account(self) -> None:
        if self._expected_user_id is None or self._account_verified:
            return
        try:
            response = await self._client.get(
                f"{self._base_url}/api/users/me",
                headers={"x-api-key": self._api_key},
            )
            response.raise_for_status()
            authenticated = authenticated_immich_user_id(response.json())
        except Exception:
            raise ResourceAccessUnavailableError(
                "Immich account qualification failed"
            ) from None
        if authenticated != self._expected_user_id:
            raise ResourceAccessUnavailableError(
                "Immich credential does not match expected Provider Account"
            )
        self._account_verified = True
