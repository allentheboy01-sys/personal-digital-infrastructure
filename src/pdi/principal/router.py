"""Fail-closed routing from authenticated Principal to Personal PDI DB."""

from .errors import (
    DisabledPrincipalError,
    MissingPrincipalError,
    UnknownDatabaseBindingError,
    UnknownPrincipalError,
)
from .models import (
    DatabaseBindingRecord,
    PersonalDatabaseBinding,
    PrincipalId,
    PrincipalRecord,
)
from .registry import DatabaseBindingRegistry, PrincipalRegistry


class PrincipalDatabaseRouter:
    def __init__(
        self,
        principals: PrincipalRegistry,
        databases: DatabaseBindingRegistry,
    ) -> None:
        self._principals = principals
        self._databases = databases

    def resolve(
        self,
        principal_id: PrincipalId | str | None,
    ) -> PersonalDatabaseBinding:
        if principal_id is None:
            raise MissingPrincipalError("authenticated Principal is required")
        try:
            parsed_id = (
                principal_id
                if isinstance(principal_id, PrincipalId)
                else PrincipalId(principal_id)
            )
        except (TypeError, ValueError):
            raise UnknownPrincipalError("Principal is unknown") from None
        principal = self._principals.get(parsed_id)
        if principal is None:
            raise UnknownPrincipalError(f"Principal is unknown: {parsed_id}")
        if not principal.enabled:
            raise DisabledPrincipalError(f"Principal is disabled: {parsed_id}")
        binding = self._databases.resolve(principal.database_ref)
        if binding is None:
            raise UnknownDatabaseBindingError(
                f"database binding is unknown: {principal.database_ref}"
            )
        return binding

    @classmethod
    def explicit_single_user(
        cls,
        *,
        principal_id: PrincipalId | str,
        database_url: str,
    ) -> "PrincipalDatabaseRouter":
        """Build an intentionally selected legacy single-database route."""

        parsed_id = (
            principal_id
            if isinstance(principal_id, PrincipalId)
            else PrincipalId(principal_id)
        )
        database_ref = "single-user-database"
        principals = PrincipalRegistry(
            (PrincipalRecord(parsed_id, database_ref),)
        )
        databases = DatabaseBindingRegistry(
            (DatabaseBindingRecord(database_ref, "PDI_SINGLE_USER_DATABASE_URL"),),
            {"PDI_SINGLE_USER_DATABASE_URL": database_url},
        )
        return cls(principals, databases)
