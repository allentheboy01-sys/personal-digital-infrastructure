class ScopedIngestionError(RuntimeError):
    """Base error for trusted Scope-aware ingestion composition."""


class ScopedIdentityUnavailableError(ScopedIngestionError):
    """Required Scope, Instance, or Account identity is unavailable."""


class ScopedProviderMismatchError(ScopedIngestionError):
    """A Provider value does not match the bound Observation Scope."""


class CrossScopeSourceWriteError(ScopedIngestionError):
    """A Source action attempted to cross the bound Scope boundary."""
