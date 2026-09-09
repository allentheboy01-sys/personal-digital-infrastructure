"""Immich authenticated-account identity validation."""

from uuid import UUID


class ImmichAccountMismatchError(RuntimeError):
    """A valid credential belongs to a different Immich account."""


def canonical_immich_user_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Immich User identity must be a UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise ValueError("Immich User identity must be a UUID") from None
    if str(parsed) != value:
        raise ValueError("Immich User identity must be canonical")
    return value


def authenticated_immich_user_id(payload: object) -> str:
    if not isinstance(payload, dict):
        raise ValueError("Immich current-user response must be an object")
    return canonical_immich_user_id(payload.get("id"))
