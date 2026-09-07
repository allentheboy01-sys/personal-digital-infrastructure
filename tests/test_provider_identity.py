from datetime import UTC, datetime
from uuid import uuid4

import pytest

from pdi.provider_identity.models import (
    ObservationScope,
    ProviderAccount,
    ProviderInstance,
    canonical_key,
)


NOW = datetime(2026, 9, 7, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    ["", "Nextcloud", "has space", "../escape", "+key", True],
)
def test_identity_keys_must_be_canonical(value: object) -> None:
    with pytest.raises(ValueError, match="canonical opaque key"):
        canonical_key(value, "identity")


def test_instance_identity_has_no_endpoint_or_credential_dependency() -> None:
    instance = ProviderInstance(
        id=uuid4(),
        provider_type="nextcloud",
        instance_key="synthetic-instance",
        display_label="Synthetic",
        enabled=True,
        created_at=NOW,
        updated_at=NOW,
    )
    assert set(instance.__dataclass_fields__) == {
        "id",
        "provider_type",
        "instance_key",
        "display_label",
        "enabled",
        "created_at",
        "updated_at",
    }


def test_account_and_scope_have_no_credential_identity() -> None:
    instance_id = uuid4()
    account = ProviderAccount(
        id=uuid4(),
        provider_instance_id=instance_id,
        account_key="synthetic-account",
        provider_native_id=None,
        display_label=None,
        enabled=True,
        created_at=NOW,
        updated_at=NOW,
    )
    scope = ObservationScope(
        id=uuid4(),
        provider_instance_id=instance_id,
        provider_account_id=account.id,
        scope_key="visible-files",
        display_label=None,
        enabled=True,
        created_at=NOW,
        updated_at=NOW,
    )
    assert all("credential" not in name for name in account.__dataclass_fields__)
    assert all("credential" not in name for name in scope.__dataclass_fields__)


def test_domain_timestamps_must_be_aware() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ProviderInstance(
            id=uuid4(),
            provider_type="local_files",
            instance_key="local-a",
            display_label=None,
            enabled=True,
            created_at=datetime(2026, 9, 7),
            updated_at=NOW,
        )
