from collections.abc import Iterable
from typing import Any

import requests

from pdi.adapters.immich_account import (
    ImmichAccountMismatchError,
    authenticated_immich_user_id,
    canonical_immich_user_id,
)

from .models import ProviderRelationInventory


class ImmichResourcePersonRelationAdapter:
    provider = "immich"
    _PAGE_SIZE = 1000

    def __init__(
        self, base_url: str, api_key: str, *, expected_user_id: str | None = None
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"x-api-key": api_key}
        self._expected_user_id = (
            None
            if expected_user_id is None
            else canonical_immich_user_id(expected_user_id)
        )
        self._account_verified = False

    def connect(self) -> None:
        endpoint = (
            "/api/server/about"
            if self._expected_user_id is None
            else "/api/users/me"
        )
        response = requests.get(
            f"{self._base_url}{endpoint}",
            headers=self._headers,
            timeout=10,
        )
        response.raise_for_status()
        if self._expected_user_id is not None:
            if authenticated_immich_user_id(response.json()) != self._expected_user_id:
                raise ImmichAccountMismatchError(
                    "Immich credential does not match expected Provider Account"
                )
            self._account_verified = True

    def scan(
        self, person_external_ids: Iterable[str]
    ) -> ProviderRelationInventory:
        if self._expected_user_id is not None and not self._account_verified:
            self.connect()
        identities = tuple(person_external_ids)
        if len(set(identities)) != len(identities):
            raise ValueError("PersonSource inventory contains duplicate IDs")
        if any(not identity.strip() for identity in identities):
            raise ValueError("PersonSource inventory contains an empty ID")

        pairs: set[tuple[str, str]] = set()
        for person_external_id in identities:
            page = 1
            seen_pages: set[int] = set()
            while page not in seen_pages:
                seen_pages.add(page)
                response = requests.post(
                    f"{self._base_url}/api/search/metadata",
                    headers=self._headers,
                    json={
                        "page": page,
                        "size": self._PAGE_SIZE,
                        "personIds": [person_external_id],
                    },
                    timeout=30,
                )
                response.raise_for_status()
                assets_page = self._assets_page(response.json())
                for item in assets_page["items"]:
                    if not isinstance(item, dict):
                        raise ValueError("Immich asset item must be an object")
                    asset_external_id = item.get("id")
                    if not isinstance(asset_external_id, str) or not asset_external_id.strip():
                        raise ValueError("Immich asset has an invalid id")
                    pairs.add((asset_external_id, person_external_id))

                next_page = assets_page.get("nextPage")
                if next_page in (None, ""):
                    break
                try:
                    page = int(next_page)
                except (TypeError, ValueError) as error:
                    raise ValueError("Immich relation pagination is invalid") from error
                if page < 1:
                    raise ValueError("Immich relation pagination is invalid")
            else:
                raise ValueError("Immich relation pagination repeated a page")

        return ProviderRelationInventory(
            provider=self.provider,
            pairs=tuple(sorted(pairs)),
        )

    @staticmethod
    def _assets_page(payload: object) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Immich search response must be an object")
        assets = payload.get("assets")
        if not isinstance(assets, dict) or not isinstance(assets.get("items"), list):
            raise ValueError("Immich search response has invalid assets")
        return assets
