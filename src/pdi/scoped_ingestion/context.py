from dataclasses import dataclass
from uuid import UUID

from pdi.principal import PrincipalId


@dataclass(frozen=True, slots=True)
class ObservationContext:
    principal_id: PrincipalId
    observation_scope_id: UUID
    provider_instance_id: UUID
    provider_account_id: UUID | None
    provider_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, PrincipalId):
            raise TypeError("principal_id must be a PrincipalId")
        for name in ("observation_scope_id", "provider_instance_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if self.provider_account_id is not None and not isinstance(
            self.provider_account_id, UUID
        ):
            raise TypeError("provider_account_id must be a UUID when present")
        if not isinstance(self.provider_type, str) or not self.provider_type:
            raise ValueError("provider_type must be a non-empty string")
