"""Immutable identities and read capabilities for trusted consumers."""

from dataclasses import dataclass

from pdi.principal import PrincipalId


@dataclass(frozen=True, slots=True)
class TrustedPrincipalContext:
    """Authentication result supplied by a trusted host, never by a model."""

    principal_id: PrincipalId

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, PrincipalId):
            raise TypeError("principal_id must be a PrincipalId")
