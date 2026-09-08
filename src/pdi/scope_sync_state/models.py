from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


def validate_mechanism(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("mechanism must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class ScopeSyncState:
    observation_scope_id: UUID
    mechanism: str
    checkpoint: str | None
    version: int
    reconciliation_required: bool
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "mechanism", validate_mechanism(self.mechanism))
        if type(self.version) is not int or self.version < 0:
            raise ValueError("version must be a non-negative integer")
        if type(self.reconciliation_required) is not bool:
            raise ValueError("reconciliation_required must be boolean")
