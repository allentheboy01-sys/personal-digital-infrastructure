"""Restricted administrative provisioning for disposable Personal PDI DBs."""

from dataclasses import dataclass
from pathlib import Path
import re

from alembic import command
from alembic.config import Config
import psycopg
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from .fleet import repository_schema_head
from .models import PersonalDatabaseBinding


_DATABASE_NAME = re.compile(r"^pdi_mu3_[a-z0-9_]+_test$")
_ROLE_NAME = re.compile(r"^pdi_mu3_[a-z0-9_]+_runtime$")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True, slots=True)
class PersonalDatabaseProvisioningSpec:
    database_name: str
    runtime_role: str
    runtime_password: str
    database_ref: str

    def __post_init__(self) -> None:
        if not _DATABASE_NAME.fullmatch(self.database_name):
            raise ValueError("Personal DB must be a disposable pdi_mu3_*_test database")
        if not _ROLE_NAME.fullmatch(self.runtime_role):
            raise ValueError("runtime role must be a disposable pdi_mu3_*_runtime role")
        if not isinstance(self.runtime_password, str) or len(self.runtime_password) < 20:
            raise ValueError("runtime password must contain at least 20 characters")


@dataclass(frozen=True, slots=True)
class PersonalDatabaseProvisioningResult:
    binding: PersonalDatabaseBinding
    schema_revision: str
    runtime_role: str


class PersonalDatabaseProvisioner:
    """Provision only explicitly disposable, loopback MU3 databases."""

    def __init__(self, admin_url: str, *, repository_root: str | Path) -> None:
        parsed = make_url(admin_url)
        if (
            parsed.get_backend_name() != "postgresql"
            or (parsed.host or "").lower() not in _LOOPBACK_HOSTS
            or not (parsed.database or "").endswith("_test")
        ):
            raise ValueError(
                "provisioning requires an explicit loopback *_test control database"
            )
        self._admin_url = parsed
        self._psycopg_admin_url = parsed.set(drivername="postgresql")
        self._repository_root = Path(repository_root)
        self._provisioned: set[tuple[str, str]] = set()

    def provision(
        self,
        spec: PersonalDatabaseProvisioningSpec,
    ) -> PersonalDatabaseProvisioningResult:
        created_role = False
        created_database = False
        try:
            with psycopg.connect(
                self._psycopg_admin_url.render_as_string(hide_password=False),
                autocommit=True,
            ) as connection:
                connection.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(spec.runtime_role),
                        sql.Literal(spec.runtime_password),
                    )
                )
                created_role = True
                connection.execute(
                    sql.SQL("CREATE DATABASE {}").format(
                        sql.Identifier(spec.database_name)
                    )
                )
                created_database = True
                connection.execute(
                    sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                        sql.Identifier(spec.database_name)
                    )
                )
                connection.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                        sql.Identifier(spec.database_name),
                        sql.Identifier(spec.runtime_role),
                    )
                )

            admin_target_url = self._admin_url.set(database=spec.database_name)
            engine = create_engine(admin_target_url, poolclass=NullPool)
            try:
                with engine.connect() as connection:
                    config = Config(str(self._repository_root / "alembic.ini"))
                    config.attributes["connection"] = connection
                    command.upgrade(config, "head")
                with psycopg.connect(
                    admin_target_url.set(drivername="postgresql").render_as_string(
                        hide_password=False
                    ),
                    autocommit=True,
                ) as connection:
                    connection.execute(
                        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                            sql.Identifier(spec.runtime_role)
                        )
                    )
                    connection.execute(
                        sql.SQL(
                            "GRANT SELECT, INSERT, UPDATE, DELETE "
                            "ON ALL TABLES IN SCHEMA public TO {}"
                        ).format(sql.Identifier(spec.runtime_role))
                    )
                    connection.execute(
                        sql.SQL(
                            "GRANT USAGE, SELECT ON ALL SEQUENCES "
                            "IN SCHEMA public TO {}"
                        ).format(sql.Identifier(spec.runtime_role))
                    )
                with engine.connect() as connection:
                    revision = connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
            finally:
                engine.dispose()

            expected = repository_schema_head(self._repository_root)
            if revision != expected:
                raise RuntimeError("provisioned Personal DB revision is incompatible")
            runtime_url = admin_target_url.set(
                username=spec.runtime_role,
                password=spec.runtime_password,
            )
            result = PersonalDatabaseProvisioningResult(
                binding=PersonalDatabaseBinding(
                    spec.database_ref,
                    runtime_url.render_as_string(hide_password=False),
                ),
                schema_revision=revision,
                runtime_role=spec.runtime_role,
            )
            self._provisioned.add((spec.database_name, spec.runtime_role))
            return result
        except Exception:
            if created_database or created_role:
                self._cleanup_created(
                    spec,
                    drop_database=created_database,
                    drop_role=created_role,
                )
            raise

    def drop(
        self,
        spec: PersonalDatabaseProvisioningSpec,
        *,
        missing_ok: bool = False,
    ) -> None:
        """Remove exactly one provisioner's validated disposable DB and role."""

        identity = (spec.database_name, spec.runtime_role)
        if identity not in self._provisioned:
            if missing_ok:
                return
            raise RuntimeError(
                "refusing to remove a database not created by this provisioner"
            )
        self._cleanup_created(spec, drop_database=True, drop_role=True)
        self._provisioned.remove(identity)

    def _cleanup_created(
        self,
        spec: PersonalDatabaseProvisioningSpec,
        *,
        drop_database: bool,
        drop_role: bool,
    ) -> None:
        with psycopg.connect(
            self._psycopg_admin_url.render_as_string(hide_password=False),
            autocommit=True,
        ) as connection:
            if drop_database:
                connection.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                        sql.Identifier(spec.database_name)
                    )
                )
            if drop_role:
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(
                        sql.Identifier(spec.runtime_role)
                    )
                )
