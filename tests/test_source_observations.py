import pytest

from pdi.decision import Action, ActionType, Decision
from pdi.models import AssetSource, effective_source_mime_type
from pdi.models.asset_source import POSTGRES_BIGINT_MAX
from pdi.repository import InMemoryRepository, SourceIdentityAmbiguityError
from uuid import uuid4


def test_in_memory_source_observations_round_trip() -> None:
    repository = InMemoryRepository()
    source = AssetSource(
        blob_id="blob-id",
        provider="test-provider",
        external_id="source-id",
        provider_mime_type="text/markdown",
        provider_size=321,
    )
    repository.execute(
        Decision(
            actions=[
                Action(
                    type=ActionType.CREATE_SOURCE,
                    source=source,
                )
            ]
        )
    )

    stored = repository.find_source("test-provider", "source-id")

    assert stored == source
    assert stored.provider_mime_type == "text/markdown"
    assert stored.provider_size == 321


def test_legacy_source_without_observations_remains_valid() -> None:
    source = AssetSource(
        blob_id="blob-id",
        provider="test-provider",
        external_id="legacy-source",
    )

    assert source.provider_mime_type is None
    assert source.provider_size is None
    assert source.observation_scope_id is None


def test_scoped_source_requires_external_identity() -> None:
    with pytest.raises(ValueError, match="external_id"):
        AssetSource(observation_scope_id=str(uuid4()), external_id="")


def test_in_memory_scoped_identity_and_legacy_ambiguity() -> None:
    repository = InMemoryRepository()
    scope_a, scope_b = str(uuid4()), str(uuid4())
    for scope in (scope_a, scope_b):
        source = AssetSource(blob_id="blob", provider="nextcloud", external_id="123", observation_scope_id=scope)
        repository.sources[source.id] = source
    assert repository.find_source_in_scope(scope_a, "123").observation_scope_id == scope_a
    assert len(repository.list_active_sources_in_scope(scope_b)) == 1
    with pytest.raises(SourceIdentityAmbiguityError):
        repository.find_source("nextcloud", "123")


@pytest.mark.parametrize(
    ("provider_mime", "blob_mime", "expected"),
    [
        ("text/markdown", "application/octet-stream", "text/markdown"),
        ("application/octet-stream", "image/jpeg", "application/octet-stream"),
        (None, "text/plain", "text/plain"),
        (None, None, None),
    ],
)
def test_effective_source_mime_is_provider_first_with_null_only_fallback(
    provider_mime: str | None,
    blob_mime: str | None,
    expected: str | None,
) -> None:
    assert effective_source_mime_type(provider_mime, blob_mime) == expected


@pytest.mark.parametrize(
    "provider_size",
    [None, 0, POSTGRES_BIGINT_MAX],
)
def test_source_accepts_valid_provider_size(
    provider_size: int | None,
) -> None:
    source = AssetSource(provider_size=provider_size)

    assert source.provider_size == provider_size


@pytest.mark.parametrize(
    "provider_size",
    [True, -1, POSTGRES_BIGINT_MAX + 1, 1.5, "1", object()],
)
def test_source_rejects_invalid_provider_size(
    provider_size: object,
) -> None:
    with pytest.raises(ValueError, match="provider_size"):
        AssetSource(provider_size=provider_size)  # type: ignore[arg-type]
