"""Read-only Personal PDI database fleet revision projection."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from .models import PrincipalId
from .registry import DatabaseBindingRegistry, PrincipalRegistry


class FleetDatabaseHealth(StrEnum):
    HEALTHY = "healthy"
    BEHIND = "behind"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PersonalDatabaseStatus:
    principal_id: PrincipalId
    database_ref: str
    reachable: bool
    current_revision: str | None
    expected_revision: str
    health: FleetDatabaseHealth
    error_code: str | None = None


def repository_schema_head(repository_root: str | Path) -> str:
    config = Config(str(Path(repository_root) / "alembic.ini"))
    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()
    if len(heads) != 1:
        raise RuntimeError("PDI requires exactly one Alembic head")
    return heads[0]


class PersonalDatabaseFleetInspector:
    def __init__(
        self,
        principals: PrincipalRegistry,
        databases: DatabaseBindingRegistry,
        *,
        expected_revision: str,
        engine_factory: Callable[[str], Engine] = create_engine,
    ) -> None:
        self._principals = principals
        self._databases = databases
        self._expected_revision = expected_revision
        self._engine_factory = engine_factory

    def inspect(self) -> tuple[PersonalDatabaseStatus, ...]:
        return tuple(
            self._inspect_principal(principal.principal_id, principal.database_ref)
            for principal in self._principals.list_enabled()
        )

    def _inspect_principal(
        self,
        principal_id: PrincipalId,
        database_ref: str,
    ) -> PersonalDatabaseStatus:
        try:
            binding = self._databases.resolve(database_ref)
            if binding is None:
                return self._failed(principal_id, database_ref, "binding_unknown")
            engine = self._engine_factory(binding.database_url)
            try:
                with engine.connect() as connection:
                    revision = connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
            finally:
                engine.dispose()
        except (SQLAlchemyError, RuntimeError, ValueError):
            return self._failed(principal_id, database_ref, "database_unavailable")

        return PersonalDatabaseStatus(
            principal_id=principal_id,
            database_ref=database_ref,
            reachable=True,
            current_revision=revision,
            expected_revision=self._expected_revision,
            health=(
                FleetDatabaseHealth.HEALTHY
                if revision == self._expected_revision
                else FleetDatabaseHealth.BEHIND
            ),
        )

    def _failed(
        self,
        principal_id: PrincipalId,
        database_ref: str,
        error_code: str,
    ) -> PersonalDatabaseStatus:
        return PersonalDatabaseStatus(
            principal_id=principal_id,
            database_ref=database_ref,
            reachable=False,
            current_revision=None,
            expected_revision=self._expected_revision,
            health=FleetDatabaseHealth.FAILED,
            error_code=error_code,
        )
