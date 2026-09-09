from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, create_engine, pool

from pdi.config.settings import load_database_url
from pdi.repository.orm.base import Base

import pdi.repository.orm.asset
import pdi.repository.orm.asset_source
import pdi.repository.orm.blob
import pdi.repository.orm.observation
import pdi.repository.orm.person
import pdi.repository.orm.pipeline_run
import pdi.repository.orm.provider_identity
import pdi.repository.orm.provider_sync_state
import pdi.repository.orm.resource_person_relation
import pdi.repository.orm.scope_sync_state


config = context.config

if config.config_file_name is not None:
    fileConfig(
        config.config_file_name,
        disable_existing_loggers=False,
    )

target_metadata = Base.metadata

_EXPECTED_TABLES = {
    "assets",
    "blobs",
    "asset_sources",
    "resource_statements",
    "resource_enrichments",
    "pipeline_runs",
    "provider_sync_state",
    "provider_instances",
    "provider_accounts",
    "observation_scopes",
    "observation_scope_sync_state",
    "persons",
    "person_sources",
    "resource_person_relations",
    "observation_scope_person_sources",
    "observation_scope_resource_person_relations",
}

if set(target_metadata.tables) != _EXPECTED_TABLES:
    raise RuntimeError(
        "Alembic ORM registration mismatch: "
        f"expected {sorted(_EXPECTED_TABLES)}, "
        f"got {sorted(target_metadata.tables)}"
    )


def _configure_context(**kwargs: object) -> None:
    context.configure(
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        transaction_per_migration=True,
        **kwargs,
    )


def run_migrations_offline() -> None:
    """Generate SQL without opening a database connection."""

    _configure_context(
        url=load_database_url(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def _run_migrations_with_connection(
    connection: Connection,
) -> None:
    _configure_context(connection=connection)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations through an explicit PostgreSQL connection."""

    supplied_connection = config.attributes.get("connection")

    if supplied_connection is not None:
        _run_migrations_with_connection(supplied_connection)
        return

    connectable = create_engine(
        load_database_url(),
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        _run_migrations_with_connection(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
