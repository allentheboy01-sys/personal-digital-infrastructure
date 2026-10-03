"""Trusted, file-backed Principal and database-binding registries."""

from collections.abc import Mapping
from pathlib import Path
import tomllib

from .errors import InvalidPrincipalConfigurationError
from .models import (
    DatabaseBindingRecord,
    PersonalDatabaseBinding,
    PrincipalId,
    PrincipalRecord,
)


class PrincipalRegistry:
    def __init__(self, records: tuple[PrincipalRecord, ...]) -> None:
        by_id: dict[PrincipalId, PrincipalRecord] = {}
        database_refs: set[str] = set()
        for record in records:
            if record.principal_id in by_id:
                raise InvalidPrincipalConfigurationError(
                    f"duplicate principal: {record.principal_id}"
                )
            if record.database_ref in database_refs:
                raise InvalidPrincipalConfigurationError(
                    "a Personal DB binding may belong to only one Principal"
                )
            by_id[record.principal_id] = record
            database_refs.add(record.database_ref)
        self._records = by_id

    def get(self, principal_id: PrincipalId) -> PrincipalRecord | None:
        return self._records.get(principal_id)

    def list_enabled(self) -> tuple[PrincipalRecord, ...]:
        return tuple(
            record
            for record in self._records.values()
            if record.enabled
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "PrincipalRegistry":
        raw_records = data.get("principals")
        if not isinstance(raw_records, list):
            raise InvalidPrincipalConfigurationError(
                "principal configuration requires a principals list"
            )
        try:
            records = tuple(
                PrincipalRecord(
                    principal_id=PrincipalId(item["id"]),
                    database_ref=item["database_ref"],
                    enabled=item.get("enabled", True),
                    display_label=item.get("display_label"),
                )
                for item in raw_records
                if isinstance(item, dict)
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidPrincipalConfigurationError(
                "principal configuration is malformed"
            ) from error
        if len(records) != len(raw_records):
            raise InvalidPrincipalConfigurationError(
                "principal configuration is malformed"
            )
        return cls(records)


class DatabaseBindingRegistry:
    def __init__(
        self,
        records: tuple[DatabaseBindingRecord, ...],
        environment: Mapping[str, str],
    ) -> None:
        self._records: dict[str, DatabaseBindingRecord] = {}
        self._environment = environment
        for record in records:
            if record.database_ref in self._records:
                raise InvalidPrincipalConfigurationError(
                    f"duplicate database binding: {record.database_ref}"
                )
            self._records[record.database_ref] = record

    def resolve(self, database_ref: str) -> PersonalDatabaseBinding | None:
        record = self._records.get(database_ref)
        if record is None:
            return None
        raw_url = self._environment.get(record.url_env)
        if raw_url is None:
            raise InvalidPrincipalConfigurationError(
                f"database binding {database_ref} has no configured secret"
            )
        try:
            return PersonalDatabaseBinding(database_ref, raw_url)
        except ValueError as error:
            raise InvalidPrincipalConfigurationError(
                f"database binding {database_ref} is malformed"
            ) from error

    def url_env(self, database_ref: str) -> str | None:
        """Return the protected environment-key name, never its value."""
        record = self._records.get(database_ref)
        return None if record is None else record.url_env

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, object],
        environment: Mapping[str, str],
    ) -> "DatabaseBindingRegistry":
        raw_records = data.get("databases")
        if not isinstance(raw_records, list):
            raise InvalidPrincipalConfigurationError(
                "principal configuration requires a databases list"
            )
        try:
            records = tuple(
                DatabaseBindingRecord(
                    database_ref=item["ref"],
                    url_env=item["url_env"],
                )
                for item in raw_records
                if isinstance(item, dict)
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidPrincipalConfigurationError(
                "database binding configuration is malformed"
            ) from error
        if len(records) != len(raw_records):
            raise InvalidPrincipalConfigurationError(
                "database binding configuration is malformed"
            )
        return cls(records, environment)


def load_registries(
    path: str | Path,
    *,
    environment: Mapping[str, str],
) -> tuple[PrincipalRegistry, DatabaseBindingRegistry]:
    try:
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InvalidPrincipalConfigurationError(
            "principal registry cannot be loaded"
        ) from error
    return (
        PrincipalRegistry.from_mapping(data),
        DatabaseBindingRegistry.from_mapping(data, environment),
    )
