from datetime import UTC, datetime
from uuid import uuid4

import pytest

from pdi.scope_sync_state import ScopeSyncState


def test_scope_state_identity_has_no_provider_principal_or_credential() -> None:
    state = ScopeSyncState(
        observation_scope_id=uuid4(),
        mechanism="activity_v2_hint_v1",
        checkpoint=None,
        version=0,
        reconciliation_required=False,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    assert set(state.__dataclass_fields__) == {
        "observation_scope_id",
        "mechanism",
        "checkpoint",
        "version",
        "reconciliation_required",
        "created_at",
        "updated_at",
    }


@pytest.mark.parametrize("mechanism", ["", " "])
def test_scope_state_rejects_empty_mechanism(mechanism: str) -> None:
    with pytest.raises(ValueError, match="mechanism"):
        ScopeSyncState(
            observation_scope_id=uuid4(),
            mechanism=mechanism,
            checkpoint=None,
            version=0,
            reconciliation_required=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
