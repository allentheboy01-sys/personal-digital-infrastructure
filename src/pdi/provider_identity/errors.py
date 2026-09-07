class ProviderIdentityError(RuntimeError):
    """Base error for Provider identity persistence."""


class ProviderIdentityConflictError(ProviderIdentityError):
    """A stable identity key already exists in its namespace."""


class ProviderIdentityNotFoundError(ProviderIdentityError):
    """A referenced Provider identity does not exist."""


class ProviderIdentityRelationshipError(ProviderIdentityError):
    """Provider identity relationships violate their instance boundary."""
