import requests

import pytest

from pdi.adapters.immich_account import ImmichAccountMismatchError
from pdi.person_identity import (
    EnumerablePersonInventory,
    ImmichEnumerablePeopleAdapter,
    PersonSyncService,
    ProviderPersonIdentity,
)
from pdi.person_identity.models import PersonSyncResult


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload
        self.raise_for_status_called = False

    def raise_for_status(self) -> None:
        self.raise_for_status_called = True

    def json(self) -> object:
        return self._payload


def test_immich_adapter_reads_ids_and_normalized_names_and_allows_total_gap(
    monkeypatch,
) -> None:
    responses = [
        FakeResponse(
            {
                "people": [
                    {
                        "id": "person-a",
                        "name": "  妈妈  ",
                        "birthDate": "2000-01-01",
                        "thumbnailPath": "/ignored/private/path",
                        "updatedAt": "2026-08-18T00:00:00Z",
                    }
                ],
                "total": 501,
                "hidden": 0,
                "hasNextPage": True,
            }
        ),
        FakeResponse(
            {
                "people": [{"id": "person-b", "isFavorite": True}],
                "total": 501,
                "hidden": 0,
                "hasNextPage": False,
            }
        ),
    ]
    calls: list[dict] = []

    def fake_get(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        return responses[len(calls) - 1]

    monkeypatch.setattr("pdi.person_identity.immich.requests.get", fake_get)
    inventory = ImmichEnumerablePeopleAdapter(
        "https://immich.example/", "secret"
    ).scan()

    assert inventory == EnumerablePersonInventory(
        provider="immich",
        identities=(
            ProviderPersonIdentity("person-a", "妈妈"),
            ProviderPersonIdentity("person-b", None),
        ),
        reported_total=501,
    )
    assert inventory.external_ids == ("person-a", "person-b")
    assert [call["params"]["page"] for call in calls] == [1, 2]
    assert all(call["params"]["withHidden"] == "true" for call in calls)


def test_immich_adapter_connects_to_read_only_about(monkeypatch) -> None:
    response = FakeResponse({"version": "v3.0.3"})
    captured: dict = {}

    def fake_get(url: str, **kwargs):
        captured.update({"url": url, **kwargs})
        return response

    monkeypatch.setattr("pdi.person_identity.immich.requests.get", fake_get)
    ImmichEnumerablePeopleAdapter(
        "https://immich.example", "secret"
    ).connect()
    assert captured["url"] == "https://immich.example/api/server/about"
    assert captured["timeout"] == 10
    assert response.raise_for_status_called is True


def test_scoped_people_adapter_rejects_valid_wrong_user_before_scan(
    monkeypatch,
) -> None:
    expected = "65f0a1c2-3d4e-4f50-8123-456789abcdef"
    actual = "75f0a1c2-3d4e-4f50-8123-456789abcdef"
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return FakeResponse({"id": actual})

    monkeypatch.setattr("pdi.person_identity.immich.requests.get", get)
    adapter = ImmichEnumerablePeopleAdapter(
        "https://immich.example",
        "valid-wrong-user-key",
        expected_user_id=expected,
    )
    with pytest.raises(ImmichAccountMismatchError):
        adapter.scan()
    assert calls == ["https://immich.example/api/users/me"]


def test_person_name_is_nfc_normalized_and_empty_is_unnamed(
    monkeypatch,
) -> None:
    payload = {
        "people": [
            {"id": "composed", "name": "  Cafe\u0301  "},
            {"id": "empty", "name": " \n "},
            {"id": "null", "name": None},
        ],
        "total": 3,
        "hasNextPage": False,
    }
    monkeypatch.setattr(
        "pdi.person_identity.immich.requests.get",
        lambda *args, **kwargs: FakeResponse(payload),
    )

    inventory = ImmichEnumerablePeopleAdapter(
        "https://immich.example", "secret"
    ).scan()

    assert inventory.identities == (
        ProviderPersonIdentity("composed", "Caf\u00e9"),
        ProviderPersonIdentity("empty", None),
        ProviderPersonIdentity("null", None),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"people": [{"id": ""}], "total": 1, "hasNextPage": False},
        {"people": [{"id": "same"}, {"id": "same"}], "total": 2,
         "hasNextPage": False},
        {"people": [{"id": "person-a", "name": {}}], "total": 1,
         "hasNextPage": False},
        {"people": [], "total": 0, "hasNextPage": "false"},
    ],
)
def test_immich_adapter_rejects_incomplete_or_ambiguous_inventory(
    monkeypatch, payload
) -> None:
    monkeypatch.setattr(
        "pdi.person_identity.immich.requests.get",
        lambda *args, **kwargs: FakeResponse(payload),
    )
    with pytest.raises(ValueError):
        ImmichEnumerablePeopleAdapter("https://immich.example", "secret").scan()


def test_failed_or_partial_scan_never_reconciles() -> None:
    class FailingAdapter:
        def connect(self) -> None:
            pass

        def scan(self):
            raise requests.HTTPError("page two failed")

    class RecordingRepository:
        called = False

        def reconcile_inventory(self, provider, identities):
            self.called = True

    repository = RecordingRepository()
    with pytest.raises(requests.HTTPError):
        PersonSyncService(FailingAdapter(), repository).sync_once()
    assert repository.called is False


def test_invalid_name_after_valid_page_never_reconciles(monkeypatch) -> None:
    responses = [
        FakeResponse({
            "people": [{"id": "person-a", "name": "valid"}],
            "total": 2,
            "hasNextPage": True,
        }),
        FakeResponse({
            "people": [{"id": "person-b", "name": ["invalid"]}],
            "total": 2,
            "hasNextPage": False,
        }),
    ]
    monkeypatch.setattr(
        "pdi.person_identity.immich.requests.get",
        lambda *args, **kwargs: responses.pop(0),
    )

    class RecordingRepository:
        called = False

        def reconcile_inventory(self, provider, identities):
            self.called = True

    repository = RecordingRepository()
    service = PersonSyncService(
        ImmichEnumerablePeopleAdapter(
            "https://immich.example", "secret"
        ),
        repository,
    )
    monkeypatch.setattr(service._adapter, "connect", lambda: None)

    with pytest.raises(ValueError, match="display_name"):
        service.sync_once()

    assert repository.called is False


def test_cli_prints_only_aggregate_result(monkeypatch, capsys) -> None:
    from pdi.person_identity import __main__ as cli

    class Settings:
        url = "https://immich.example"
        api_key = "private-key"

    class Engine:
        disposed = False

        def dispose(self) -> None:
            self.disposed = True

    engine = Engine()
    monkeypatch.setattr(cli, "load_immich_settings", lambda: Settings())
    monkeypatch.setattr(cli, "load_database_url", lambda: "private-db-url")
    monkeypatch.setattr(cli, "create_postgres_engine", lambda url: engine)
    monkeypatch.setattr(cli, "PersonRepository", lambda value: object())
    monkeypatch.setattr(
        cli, "ImmichEnumerablePeopleAdapter", lambda *args: object()
    )

    class Service:
        def __init__(self, adapter, repository) -> None:
            pass

        def sync_once(self) -> PersonSyncResult:
            return PersonSyncResult(417, 417, 0, 0, 0, 416)

    monkeypatch.setattr(cli, "PersonSyncService", Service)
    assert cli.main() == 0
    output = capsys.readouterr()
    assert "enumerated=417" in output.out
    assert "created_persons=417" in output.out
    assert "created_sources=417" in output.out
    assert "labels_updated=416" in output.out
    assert "private" not in output.out
    assert output.err == ""
    assert engine.disposed is True


def test_cli_failure_is_sanitized(monkeypatch, capsys) -> None:
    from pdi.person_identity import __main__ as cli

    monkeypatch.setattr(
        cli,
        "load_immich_settings",
        lambda: (_ for _ in ()).throw(RuntimeError("private failure")),
    )
    assert cli.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "person_sync status=failed\n"
