import requests

import pytest

from pdi.adapters.immich_account import ImmichAccountMismatchError
from pdi.resource_person_relation import (
    ImmichResourcePersonRelationAdapter,
    ProviderRelationInventory,
    ResourcePersonRelationSyncService,
)
from pdi.resource_person_relation.models import RelationSyncResult


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> object:
        return self.payload


def test_immich_adapter_paginates_and_deduplicates_without_faces(monkeypatch) -> None:
    responses = iter(
        [
            FakeResponse({"assets": {"items": [{"id": "asset-a"}], "nextPage": "2"}}),
            FakeResponse({"assets": {"items": [{"id": "asset-a"}, {"id": "asset-b"}], "nextPage": None}}),
            FakeResponse({"assets": {"items": [{"id": "asset-a"}], "nextPage": None}}),
        ]
    )
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr("pdi.resource_person_relation.immich.requests.post", post)
    inventory = ImmichResourcePersonRelationAdapter(
        "https://immich.example/", "secret"
    ).scan(("person-a", "person-b"))

    assert inventory == ProviderRelationInventory(
        "immich",
        (("asset-a", "person-a"), ("asset-a", "person-b"), ("asset-b", "person-a")),
    )
    assert [call[1]["json"]["page"] for call in calls] == [1, 2, 1]
    assert all("personIds" in call[1]["json"] for call in calls)
    assert all("faces" not in call[0] for call in calls)


def test_scoped_relation_adapter_rejects_valid_wrong_user_before_scan(
    monkeypatch,
) -> None:
    expected = "65f0a1c2-3d4e-4f50-8123-456789abcdef"
    actual = "75f0a1c2-3d4e-4f50-8123-456789abcdef"
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return FakeResponse({"id": actual})

    monkeypatch.setattr(
        "pdi.resource_person_relation.immich.requests.get", get
    )
    adapter = ImmichResourcePersonRelationAdapter(
        "https://immich.example",
        "valid-wrong-user-key",
        expected_user_id=expected,
    )
    with pytest.raises(ImmichAccountMismatchError):
        adapter.scan(("person-a",))
    assert calls == ["https://immich.example/api/users/me"]


@pytest.mark.parametrize(
    "payload",
    [
        {"assets": {"items": [{"id": ""}], "nextPage": None}},
        {"assets": {"items": [], "nextPage": "bad"}},
        {"assets": {"items": [], "nextPage": "1"}},
    ],
)
def test_invalid_or_repeated_pagination_fails_complete_scan(monkeypatch, payload) -> None:
    monkeypatch.setattr(
        "pdi.resource_person_relation.immich.requests.post",
        lambda *args, **kwargs: FakeResponse(payload),
    )
    with pytest.raises(ValueError):
        ImmichResourcePersonRelationAdapter(
            "https://immich.example", "secret"
        ).scan(("person-a",))


def test_partial_http_failure_never_calls_reconciliation() -> None:
    class Adapter:
        provider = "immich"

        def connect(self):
            pass

        def scan(self, identities):
            raise requests.HTTPError("partial scan")

    class Repository:
        reconciled = False

        def list_active_person_external_ids(self, provider):
            return ("person-a",)

        def reconcile_provider_relations(self, provider, pairs):
            self.reconciled = True

    repository = Repository()
    with pytest.raises(requests.HTTPError):
        ResourcePersonRelationSyncService(Adapter(), repository).sync_once()
    assert repository.reconciled is False


def test_cli_prints_only_aggregate_result(monkeypatch, capsys) -> None:
    from pdi.resource_person_relation import __main__ as cli

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
    monkeypatch.setattr(
        cli, "ResourcePersonRelationRepository", lambda value: object()
    )
    monkeypatch.setattr(
        cli, "ImmichResourcePersonRelationAdapter", lambda *args: object()
    )

    class Service:
        def __init__(self, adapter, repository) -> None:
            pass

        def sync_once(self) -> RelationSyncResult:
            return RelationSyncResult(10460, 10460, 0, 0, 0, 0)

    monkeypatch.setattr(cli, "ResourcePersonRelationSyncService", Service)
    assert cli.main() == 0
    output = capsys.readouterr()
    assert "status=completed" in output.out
    assert "observed=10460" in output.out
    assert "created=10460" in output.out
    assert "private" not in output.out
    assert output.err == ""
    assert engine.disposed is True


def test_cli_failure_is_sanitized(monkeypatch, capsys) -> None:
    from pdi.resource_person_relation import __main__ as cli

    monkeypatch.setattr(
        cli,
        "load_immich_settings",
        lambda: (_ for _ in ()).throw(RuntimeError("private failure")),
    )
    assert cli.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "resource_person_relation_sync status=failed\n"
