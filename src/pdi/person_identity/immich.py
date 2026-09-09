from typing import Any

import requests

from pdi.adapters.immich_account import (
    ImmichAccountMismatchError,
    authenticated_immich_user_id,
    canonical_immich_user_id,
)

from .models import EnumerablePersonInventory, ProviderPersonIdentity


class ImmichEnumerablePeopleAdapter:
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

    def scan(self) -> EnumerablePersonInventory:
        if self._expected_user_id is not None and not self._account_verified:
            self.connect()
        page = 1
        identities: list[ProviderPersonIdentity] = []
        seen: set[str] = set()
        reported_total: int | None = None

        while True:
            response = requests.get(
                f"{self._base_url}/api/people",
                headers=self._headers,
                params={
                    "withHidden": "true",
                    "page": page,
                    "size": self._PAGE_SIZE,
                },
                timeout=30,
            )
            response.raise_for_status()
            payload = self._payload(response.json())
            total = payload.get("total")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise ValueError("Immich People response has invalid total")
            if reported_total is None:
                reported_total = total
            elif total != reported_total:
                raise ValueError("Immich People total changed during scan")

            for item in payload["people"]:
                if not isinstance(item, dict):
                    raise ValueError("Immich People item must be an object")
                external_id = item.get("id")
                if not isinstance(external_id, str) or not external_id.strip():
                    raise ValueError("Immich Person has invalid id")
                if external_id in seen:
                    raise ValueError("Immich People scan returned duplicate id")
                seen.add(external_id)
                identities.append(ProviderPersonIdentity(
                    external_id=external_id,
                    display_name=item.get("name"),
                ))

            has_next = payload.get("hasNextPage")
            if not isinstance(has_next, bool):
                raise ValueError("Immich People response has invalid hasNextPage")
            if not has_next:
                break
            page += 1

        return EnumerablePersonInventory(
            provider=self.provider,
            identities=tuple(identities),
            reported_total=reported_total if reported_total is not None else 0,
        )

    @staticmethod
    def _payload(value: object) -> dict[str, Any]:
        if not isinstance(value, dict) or not isinstance(value.get("people"), list):
            raise ValueError("Immich People response has invalid shape")
        return value
