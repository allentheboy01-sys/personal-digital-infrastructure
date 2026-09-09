"""Protocol-neutral Principal-bound read-only consumer contract."""

from .models import TrustedPrincipalContext
from .runtime import (
    ObservationReader,
    PrincipalBoundConsumerRuntime,
    PrincipalBoundConsumerRuntimeFactory,
)

__all__ = [
    "ObservationReader",
    "PrincipalBoundConsumerRuntime",
    "PrincipalBoundConsumerRuntimeFactory",
    "TrustedPrincipalContext",
]
