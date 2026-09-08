import logging
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
import pytest
from sqlalchemy import Connection, Engine, create_engine, inspect, text
from sqlalchemy.pool import NullPool
from sqlalchemy.sql.sqltypes import BigInteger, Text

from pdi.database.schema_preflight import (
    BASELINE_REVISION,
    assert_v0_1_schema,
)
from pdi.repository.orm.base import Base
from tests.integration.database_guard import (
    require_safe_test_database_url,
)

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


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_SQL = ROOT / "src/pdi/database/schema.sql"
QUERY_V0_2_REVISION = "1c7b2f9e4a6d"
OBSERVATION_V0_1_REVISION = "8f3a1d2c4b5e"
DATA_STATUS_V0_1_REVISION = "4d8a2c6e9f10"
PERSON_IDENTITY_V0_1_REVISION = "6a7c8d9e0f12"
RESOURCE_PERSON_RELATION_V0_1_REVISION = "9c4e1a7b2d30"
TYPED_RESOURCE_V0_1_REVISION = "3b1e6f8a4c20"
PERSON_LABEL_RETRIEVAL_V0_1_REVISION = "7d2f4a6b8c10"
SOURCE_OBSERVATION_FOUNDATION_REVISION = "2f6a8c1d4e90"
PROVIDER_SYNC_STATE_REVISION = "5e7a9c2d1f30"
PROVIDER_IDENTITY_REVISION = "b8d4f2a6c901"
SOURCE_PROVENANCE_REVISION = "c3e5a7b9d102"
SCOPE_SYNC_STATE_REVISION = "d4f6a8c0e213"


def _alembic_config(connection) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


def _run_alembic(
    engine: Engine,
    operation,
    revision: str,
) -> None:
    with engine.connect() as connection:
        operation(
            _alembic_config(connection),
            revision,
        )


def _drop_test_schema(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS observation_scope_sync_state"))
        connection.execute(text("DROP TABLE IF EXISTS asset_sources"))
        connection.execute(text("DROP TABLE IF EXISTS observation_scopes"))
        connection.execute(text("DROP TABLE IF EXISTS provider_accounts"))
        connection.execute(text("DROP TABLE IF EXISTS provider_instances"))
        connection.execute(text("DROP TABLE IF EXISTS provider_sync_state"))
        connection.execute(text("DROP TABLE IF EXISTS resource_person_relations"))
        connection.execute(text("DROP TABLE IF EXISTS person_sources"))
        connection.execute(text("DROP TABLE IF EXISTS persons"))
        connection.execute(text("DROP TABLE IF EXISTS pipeline_runs"))
        connection.execute(text("DROP TABLE IF EXISTS resource_enrichments"))
        connection.execute(text("DROP TABLE IF EXISTS resource_statements"))
        connection.execute(
            text("DROP INDEX IF EXISTS ix_blobs_hash")
        )
        connection.execute(
            text("DROP TABLE IF EXISTS blobs")
        )
        connection.execute(
            text("DROP TABLE IF EXISTS assets")
        )
        connection.execute(
            text("DROP TABLE IF EXISTS alembic_version")
        )


def _business_snapshot(connection: Connection) -> dict:
    tables = {
        "assets": (
            "id, title, metadata, created_at, updated_at"
        ),
        "blobs": (
            "id, asset_id, hash, size, mime_type"
        ),
        "asset_sources": (
            "id, blob_id, provider, external_id, path, name, "
            "version_tag, metadata, is_active, deleted_at"
        ),
    }

    counts = {
        table_name: connection.execute(
            text(f"SELECT count(*) FROM {table_name}")
        ).scalar_one()
        for table_name in tables
    }
    rows = {
        table_name: [
            dict(row)
            for row in connection.execute(
                text(
                    f"SELECT {columns} FROM {table_name} "
                    "ORDER BY id"
                )
            ).mappings()
        ]
        for table_name, columns in tables.items()
    }

    return {
        "counts": counts,
        "rows": rows,
    }


@pytest.fixture
def migration_engine() -> Engine:
    engine = create_engine(
        require_safe_test_database_url(),
        poolclass=NullPool,
    )

    _drop_test_schema(engine)

    try:
        yield engine
    finally:
        _drop_test_schema(engine)
        _run_alembic(
            engine,
            command.upgrade,
            "head",
        )
        engine.dispose()


def test_metadata_registration() -> None:
    assert set(Base.metadata.tables) == {
        "assets",
        "blobs",
        "asset_sources",
        "resource_statements",
        "resource_enrichments",
        "pipeline_runs",
        "provider_sync_state",
        "persons",
        "person_sources",
        "resource_person_relations",
        "provider_instances",
        "provider_accounts",
        "observation_scopes",
        "observation_scope_sync_state",
    }


def test_alembic_logging_preserves_existing_loggers(
    monkeypatch,
) -> None:
    logger = logging.getLogger(
        "pdi.adapters.immich.adapter"
    )
    logger.disabled = False
    monkeypatch.setenv(
        "DATABASE__URL",
        "postgresql+psycopg://user:password@localhost/pdi_test",
    )

    command.upgrade(
        Config(str(ROOT / "alembic.ini")),
        "head",
        sql=True,
    )

    assert logger.disabled is False


def test_empty_database_upgrade_and_schema(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        "head",
    )

    with migration_engine.connect() as connection:
        assert "resource_type" in {
            column["name"]
            for column in inspect(connection).get_columns("assets")
        }
        assert connection.execute(
            text(
                "SELECT version_num "
                "FROM alembic_version"
            )
        ).scalar_one() == SCOPE_SYNC_STATE_REVISION


def test_mu5_source_provenance_upgrade_preserves_legacy_source(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, PROVIDER_IDENTITY_REVISION)
    asset_id, blob_id, source_id = uuid4(), uuid4(), uuid4()
    with migration_engine.begin() as connection:
        connection.execute(text("INSERT INTO assets (id,resource_type,title,metadata,created_at,updated_at) VALUES (:id,'file','MU5','{}',now(),now())"), {"id": asset_id})
        connection.execute(text("INSERT INTO blobs (id,asset_id,hash) VALUES (:id,:asset,:hash)"), {"id": blob_id, "asset": asset_id, "hash": f"mu5-{blob_id}"})
        connection.execute(text("INSERT INTO asset_sources (id,blob_id,provider,external_id,metadata) VALUES (:id,:blob,'nextcloud','legacy','{}')"), {"id": source_id, "blob": blob_id})
    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        row = connection.execute(text("SELECT id,blob_id,provider,external_id,observation_scope_id FROM asset_sources WHERE id=:id"), {"id": source_id}).one()
        assert row == (source_id, blob_id, "nextcloud", "legacy", None)
        indexes = {item["name"]: item for item in inspect(connection).get_indexes("asset_sources")}
        assert indexes["uq_asset_sources_scope_external_id"]["unique"] is True
        assert indexes["uq_asset_sources_legacy_provider_external_id"]["unique"] is True


def test_mu5_downgrade_fails_before_ddl_when_legacy_namespace_collides(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, "head")
    instance, scope_a, scope_b = uuid4(), uuid4(), uuid4()
    with migration_engine.begin() as connection:
        connection.execute(text("INSERT INTO provider_instances (id,provider_type,instance_key,enabled,created_at,updated_at) VALUES (:id,'nextcloud',:key,true,now(),now())"), {"id": instance, "key": f"mu5-{instance}"})
        for scope, key in ((scope_a, "a"), (scope_b, "b")):
            connection.execute(text("INSERT INTO observation_scopes (id,provider_instance_id,scope_key,enabled,created_at,updated_at) VALUES (:id,:instance,:key,true,now(),now())"), {"id": scope, "instance": instance, "key": f"scope-{key}"})
        for scope in (scope_a, scope_b):
            asset, blob, source = uuid4(), uuid4(), uuid4()
            connection.execute(text("INSERT INTO assets (id,resource_type,title,metadata,created_at,updated_at) VALUES (:id,'file','MU5','{}',now(),now())"), {"id": asset})
            connection.execute(text("INSERT INTO blobs (id,asset_id,hash) VALUES (:id,:asset,:hash)"), {"id": blob, "asset": asset, "hash": f"mu5-{blob}"})
            connection.execute(text("INSERT INTO asset_sources (id,blob_id,provider,external_id,observation_scope_id,metadata) VALUES (:id,:blob,'nextcloud','123',:scope,'{}')"), {"id": source, "blob": blob, "scope": scope})
    with pytest.raises(Exception, match="downgrade blocked"):
        _run_alembic(migration_engine, command.downgrade, PROVIDER_IDENTITY_REVISION)
    with migration_engine.connect() as connection:
        assert "observation_scope_id" in {column["name"] for column in inspect(connection).get_columns("asset_sources")}


def test_query_v0_2_indexes_upgrade_reflection_and_downgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        "head",
    )

    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        asset_indexes = {
            index["name"]: index
            for index in inspector.get_indexes("assets")
        }
        source_indexes = {
            index["name"]: index
            for index in inspector.get_indexes("asset_sources")
        }
        asset_index = asset_indexes["ix_assets_created_at_id"]
        source_index = source_indexes[
            "ix_asset_sources_active_blob_id"
        ]

        assert asset_index["column_names"] == ["created_at", "id"]
        assert asset_index["unique"] is False
        assert "desc" in asset_index["column_sorting"]["created_at"]
        assert source_index["column_names"] == ["blob_id"]
        assert source_index["unique"] is False
        assert source_index["dialect_options"][
            "postgresql_where"
        ] is not None

    _run_alembic(
        migration_engine,
        command.downgrade,
        BASELINE_REVISION,
    )

    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        assert "ix_assets_created_at_id" not in {
            index["name"]
            for index in inspector.get_indexes("assets")
        }
        assert "ix_asset_sources_active_blob_id" not in {
            index["name"]
            for index in inspector.get_indexes("asset_sources")
        }
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == BASELINE_REVISION


def test_observation_schema_constraints_indexes_and_downgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, "head")

    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        assert {
            "resource_statements",
            "resource_enrichments",
        }.issubset(inspector.get_table_names())
        statement_checks = {
            check["name"]
            for check in inspector.get_check_constraints(
                "resource_statements"
            )
        }
        assert statement_checks == {
            "ck_resource_statements_confidence",
            "ck_resource_statements_exactly_one_value",
            "ck_resource_statements_generator_name_nonempty",
            "ck_resource_statements_generator_type_nonempty",
            "ck_resource_statements_generator_version_nonempty",
            "ck_resource_statements_predicate_nonempty",
            "ck_resource_statements_source_kind",
            "ck_resource_statements_source_kind_nonempty",
            "ck_resource_statements_source_locator_nonempty",
            "ck_resource_statements_value_discriminator",
            "ck_resource_statements_value_type",
        }
        enrichment_checks = {
            check["name"]
            for check in inspector.get_check_constraints(
                "resource_enrichments"
            )
        }
        assert enrichment_checks == {
            "ck_resource_enrichments_fingerprint_nonempty",
            "ck_resource_enrichments_name_nonempty",
            "ck_resource_enrichments_status",
            "ck_resource_enrichments_type_nonempty",
            "ck_resource_enrichments_version_nonempty",
        }
        statement_fks = {
            foreign_key["name"]: foreign_key["options"].get(
                "ondelete"
            )
            for foreign_key in inspector.get_foreign_keys(
                "resource_statements"
            )
        }
        assert statement_fks == {
            "fk_resource_statements_resource_value_asset": "RESTRICT",
            "fk_resource_statements_subject_asset": "RESTRICT",
        }
        assert {
            foreign_key["name"]: foreign_key["options"].get(
                "ondelete"
            )
            for foreign_key in inspector.get_foreign_keys(
                "resource_enrichments"
            )
        } == {"fk_resource_enrichments_subject_asset": "RESTRICT"}
        indexes = {
            index["name"]: index
            for index in inspector.get_indexes("resource_statements")
        }
        assert {
            "ix_resource_statements_current_subject_predicate",
            "ix_resource_statements_current_generator",
            "ix_resource_statements_subject_history",
        }.issubset(indexes)
        assert indexes[
            "ix_resource_statements_current_subject_predicate"
        ]["dialect_options"]["postgresql_where"] is not None
        assert indexes[
            "ix_resource_statements_current_generator"
        ]["dialect_options"]["postgresql_where"] is not None

    _run_alembic(
        migration_engine,
        command.downgrade,
        QUERY_V0_2_REVISION,
    )
    with migration_engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        assert "resource_statements" not in tables
        assert "resource_enrichments" not in tables
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == QUERY_V0_2_REVISION


def test_data_status_schema_constraints_indexes_and_downgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, "head")

    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        assert "pipeline_runs" in inspector.get_table_names()
        assert {
            check["name"]
            for check in inspector.get_check_constraints("pipeline_runs")
        } == {
            "ck_pipeline_runs_error_code",
            "ck_pipeline_runs_key_nonempty",
            "ck_pipeline_runs_kind",
            "ck_pipeline_runs_lifecycle",
            "ck_pipeline_runs_status",
        }
        columns = {
            column["name"]: column
            for column in inspector.get_columns("pipeline_runs")
        }
        assert set(columns) == {
            "id",
            "pipeline_key",
            "kind",
            "status",
            "started_at",
            "finished_at",
            "error_code",
        }
        assert "error_message" not in columns
        indexes = {
            index["name"]: index
            for index in inspector.get_indexes("pipeline_runs")
        }
        assert set(indexes) == {
            "ix_pipeline_runs_key_started_at",
            "uq_pipeline_runs_running_key",
        }
        assert indexes["uq_pipeline_runs_running_key"]["unique"] is True
        assert indexes["uq_pipeline_runs_running_key"][
            "dialect_options"
        ]["postgresql_where"] is not None

    _run_alembic(
        migration_engine,
        command.downgrade,
        OBSERVATION_V0_1_REVISION,
    )
    with migration_engine.connect() as connection:
        assert "pipeline_runs" not in inspect(connection).get_table_names()
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == OBSERVATION_V0_1_REVISION


def test_person_identity_schema_constraints_and_downgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, "head")

    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        assert {"persons", "person_sources"}.issubset(
            inspector.get_table_names()
        )
        assert {
            column["name"] for column in inspector.get_columns("persons")
        } == {"id", "created_at"}
        source_columns = {
            column["name"]
            for column in inspector.get_columns("person_sources")
        }
        assert source_columns == {
            "provider",
            "external_id",
            "person_id",
            "display_name",
            "inactive_at",
        }
        assert "id" not in source_columns
        assert {
            check["name"]
            for check in inspector.get_check_constraints("person_sources")
        } == {
            "ck_person_sources_display_name_nonempty",
            "ck_person_sources_external_id_nonempty",
            "ck_person_sources_provider_nonempty",
        }
        assert inspector.get_pk_constraint("person_sources")[
            "constrained_columns"
        ] == ["provider", "external_id"]
        assert {
            foreign_key["name"]: foreign_key["options"].get("ondelete")
            for foreign_key in inspector.get_foreign_keys("person_sources")
        } == {"fk_person_sources_person": "RESTRICT"}
        assert inspector.get_indexes("persons") == []
        source_indexes = {
            index["name"]: index
            for index in inspector.get_indexes("person_sources")
        }
        label_index = source_indexes[
            "ix_person_sources_active_display_name"
        ]
        assert label_index["unique"] is False
        assert label_index["column_names"] == [None, "person_id"]
        assert label_index["dialect_options"][
            "postgresql_where"
        ] is not None

    _run_alembic(
        migration_engine, command.downgrade, DATA_STATUS_V0_1_REVISION
    )
    with migration_engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        assert "persons" not in tables
        assert "person_sources" not in tables
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == DATA_STATUS_V0_1_REVISION


def test_upgrade_downgrade_upgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        "head",
    )
    _run_alembic(
        migration_engine,
        command.downgrade,
        "base",
    )

    with migration_engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) == {
            "alembic_version",
        }
        assert connection.execute(
            text("SELECT count(*) FROM alembic_version")
        ).scalar_one() == 0

    _run_alembic(
        migration_engine,
        command.upgrade,
        "head",
    )

    with migration_engine.connect() as connection:
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == SCOPE_SYNC_STATE_REVISION


def test_provider_identity_upgrade_preserves_existing_data_and_downgrades(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        PROVIDER_SYNC_STATE_REVISION,
    )
    asset_id = uuid4()
    blob_id = uuid4()
    source_id = uuid4()
    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO assets "
                "(id, resource_type, title, metadata, created_at, updated_at) "
                "VALUES (:id, 'file', 'MU4 preserved', '{}'::jsonb, now(), now())"
            ),
            {"id": asset_id},
        )
        connection.execute(
            text(
                "INSERT INTO blobs (id, asset_id, hash, size, mime_type) "
                "VALUES (:id, :asset, :hash, 7, 'text/plain')"
            ),
            {"id": blob_id, "asset": asset_id, "hash": f"mu4-{blob_id}"},
        )
        connection.execute(
            text(
                "INSERT INTO asset_sources "
                "(id, blob_id, provider, external_id, metadata) "
                "VALUES (:id, :blob, 'mu4-provider', :external, '{}'::jsonb)"
            ),
            {"id": source_id, "blob": blob_id, "external": f"mu4-{source_id}"},
        )
        connection.execute(
            text(
                "INSERT INTO provider_sync_state "
                "(provider, mechanism, checkpoint, version, "
                "reconciliation_required, created_at, updated_at) "
                "VALUES ('mu4-provider', 'mu4-mechanism', 'opaque-test', 3, "
                "true, now(), now())"
            )
        )
    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        assert connection.execute(
            text("SELECT title FROM assets WHERE id = :id"),
            {"id": asset_id},
        ).scalar_one() == "MU4 preserved"
        assert connection.execute(
            text("SELECT asset_id FROM blobs WHERE id = :id"),
            {"id": blob_id},
        ).scalar_one() == asset_id
        assert connection.execute(
            text("SELECT blob_id FROM asset_sources WHERE id = :id"),
            {"id": source_id},
        ).scalar_one() == blob_id
        assert connection.execute(
            text(
                "SELECT checkpoint, version, reconciliation_required "
                "FROM provider_sync_state "
                "WHERE provider = 'mu4-provider' AND mechanism = 'mu4-mechanism'"
            )
        ).one() == ("opaque-test", 3, True)
        assert {
            "provider_instances",
            "provider_accounts",
            "observation_scopes",
        }.issubset(inspect(connection).get_table_names())
        assert connection.execute(
            text("SELECT count(*) FROM provider_instances")
        ).scalar_one() == 0

    _run_alembic(
        migration_engine,
        command.downgrade,
        PROVIDER_SYNC_STATE_REVISION,
    )
    with migration_engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        assert "provider_instances" not in tables
        assert "provider_accounts" not in tables
        assert "observation_scopes" not in tables
        assert connection.execute(
            text("SELECT title FROM assets WHERE id = :id"),
            {"id": asset_id},
        ).scalar_one() == "MU4 preserved"
        assert connection.execute(
            text("SELECT blob_id FROM asset_sources WHERE id = :id"),
            {"id": source_id},
        ).scalar_one() == blob_id
        assert connection.execute(
            text(
                "SELECT checkpoint, version, reconciliation_required "
                "FROM provider_sync_state "
                "WHERE provider = 'mu4-provider' AND mechanism = 'mu4-mechanism'"
            )
        ).one() == ("opaque-test", 3, True)

    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == SCOPE_SYNC_STATE_REVISION


def test_provider_sync_state_upgrade_downgrade_reupgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        SOURCE_OBSERVATION_FOUNDATION_REVISION,
    )
    with migration_engine.connect() as connection:
        assert "provider_sync_state" not in inspect(connection).get_table_names()

    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        columns = {
            column["name"]: column
            for column in inspector.get_columns("provider_sync_state")
        }
        assert set(columns) == {
            "provider",
            "mechanism",
            "checkpoint",
            "version",
            "reconciliation_required",
            "created_at",
            "updated_at",
        }
        assert columns["checkpoint"]["nullable"] is True
        assert columns["version"]["nullable"] is False
        assert columns["reconciliation_required"]["nullable"] is False
        assert inspector.get_pk_constraint("provider_sync_state")[
            "constrained_columns"
        ] == ["provider", "mechanism"]
        constraint_names = {
            constraint["name"]
            for constraint in inspector.get_check_constraints(
                "provider_sync_state"
            )
        }
        assert constraint_names == {
            "ck_provider_sync_state_mechanism_nonempty",
            "ck_provider_sync_state_provider_nonempty",
            "ck_provider_sync_state_version_nonnegative",
        }

    _run_alembic(
        migration_engine,
        command.downgrade,
        SOURCE_OBSERVATION_FOUNDATION_REVISION,
    )
    with migration_engine.connect() as connection:
        assert "provider_sync_state" not in inspect(connection).get_table_names()
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == SOURCE_OBSERVATION_FOUNDATION_REVISION

    _run_alembic(migration_engine, command.upgrade, "head")


def test_source_observation_foundation_upgrade_downgrade_reupgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        PERSON_LABEL_RETRIEVAL_V0_1_REVISION,
    )
    asset_id = uuid4()
    blob_id = uuid4()
    source_id = uuid4()
    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO assets "
                "(id, resource_type, title, metadata, created_at, updated_at) "
                "VALUES (:id, 'file', 'Legacy Source', '{}'::jsonb, now(), now())"
            ),
            {"id": asset_id},
        )
        connection.execute(
            text(
                "INSERT INTO blobs (id, asset_id, hash, size, mime_type) "
                "VALUES (:id, :asset_id, :hash, 7, 'text/plain')"
            ),
            {
                "id": blob_id,
                "asset_id": asset_id,
                "hash": f"legacy-{blob_id}",
            },
        )
        connection.execute(
            text(
                "INSERT INTO asset_sources "
                "(id, blob_id, provider, external_id, metadata) "
                "VALUES (:id, :blob_id, 'test', :external_id, '{}'::jsonb)"
            ),
            {
                "id": source_id,
                "blob_id": blob_id,
                "external_id": f"legacy-{source_id}",
            },
        )

    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        columns = {
            column["name"]: column
            for column in inspect(connection).get_columns("asset_sources")
        }
        assert isinstance(columns["provider_mime_type"]["type"], Text)
        assert columns["provider_mime_type"]["nullable"] is True
        assert isinstance(columns["provider_size"]["type"], BigInteger)
        assert columns["provider_size"]["nullable"] is True
        indexed_columns = {
            column
            for index in inspect(connection).get_indexes("asset_sources")
            for column in index.get("column_names") or ()
        }
        assert "provider_mime_type" not in indexed_columns
        assert "provider_size" not in indexed_columns
        observations = connection.execute(
            text(
                "SELECT provider_mime_type, provider_size "
                "FROM asset_sources WHERE id = :id"
            ),
            {"id": source_id},
        ).one()
        assert observations == (None, None)
        blob_state = connection.execute(
            text("SELECT hash, size, mime_type FROM blobs WHERE id = :id"),
            {"id": blob_id},
        ).one()
        assert blob_state == (f"legacy-{blob_id}", 7, "text/plain")

    _run_alembic(
        migration_engine,
        command.downgrade,
        PERSON_LABEL_RETRIEVAL_V0_1_REVISION,
    )
    with migration_engine.connect() as connection:
        columns = {
            column["name"]
            for column in inspect(connection).get_columns("asset_sources")
        }
        assert "provider_mime_type" not in columns
        assert "provider_size" not in columns
        assert connection.execute(
            text("SELECT count(*) FROM asset_sources WHERE id = :id"),
            {"id": source_id},
        ).scalar_one() == 1

    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT provider_mime_type, provider_size "
                "FROM asset_sources WHERE id = :id"
            ),
            {"id": source_id},
        ).one() == (None, None)


def test_resource_person_relation_schema_constraints_and_downgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        columns = {
            column["name"]
            for column in inspector.get_columns("resource_person_relations")
        }
        assert columns == {"resource_id", "person_id", "provider", "inactive_at"}
        assert inspector.get_pk_constraint("resource_person_relations")[
            "constrained_columns"
        ] == ["resource_id", "person_id", "provider"]
        assert {
            check["name"]
            for check in inspector.get_check_constraints("resource_person_relations")
        } == {"ck_resource_person_relations_provider_nonempty"}
        assert {
            key["name"]: key["options"].get("ondelete")
            for key in inspector.get_foreign_keys("resource_person_relations")
        } == {
            "fk_resource_person_relations_person": "RESTRICT",
            "fk_resource_person_relations_resource": "RESTRICT",
        }
        relation_indexes = {
            index["name"]: index
            for index in inspector.get_indexes(
                "resource_person_relations"
            )
        }
        reverse_index = relation_indexes[
            "ix_resource_person_relations_active_person_resource"
        ]
        assert reverse_index["column_names"] == [
            "person_id",
            "resource_id",
        ]
        assert reverse_index["unique"] is False
        assert reverse_index["dialect_options"][
            "postgresql_where"
        ] is not None

    _run_alembic(
        migration_engine, command.downgrade, PERSON_IDENTITY_V0_1_REVISION
    )
    with migration_engine.connect() as connection:
        assert "resource_person_relations" not in inspect(connection).get_table_names()
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == PERSON_IDENTITY_V0_1_REVISION


def test_person_label_migration_preserves_identity_and_relations(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        TYPED_RESOURCE_V0_1_REVISION,
    )
    person_id = uuid4()
    asset_id = uuid4()
    blob_id = uuid4()
    source_id = uuid4()
    with migration_engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO persons (id, created_at) VALUES (:id, now())"
        ), {"id": person_id})
        connection.execute(text(
            "INSERT INTO person_sources "
            "(provider, external_id, person_id, inactive_at) "
            "VALUES ('immich', 'person-a', :person_id, NULL)"
        ), {"person_id": person_id})
        connection.execute(text(
            "INSERT INTO assets "
            "(id, resource_type, title, metadata, created_at, updated_at) "
            "VALUES (:id, 'file', 'photo.jpg', '{}'::jsonb, now(), now())"
        ), {"id": asset_id})
        connection.execute(text(
            "INSERT INTO blobs (id, asset_id, hash, size, mime_type) "
            "VALUES (:id, :asset_id, 'hash-a', 1, 'image/jpeg')"
        ), {"id": blob_id, "asset_id": asset_id})
        connection.execute(text(
            "INSERT INTO asset_sources "
            "(id, blob_id, provider, external_id, metadata, is_active) "
            "VALUES (:id, :blob_id, 'immich', 'asset-a', "
            "'{}'::jsonb, TRUE)"
        ), {"id": source_id, "blob_id": blob_id})
        connection.execute(text(
            "INSERT INTO resource_person_relations "
            "(resource_id, person_id, provider, inactive_at) "
            "VALUES (:resource_id, :person_id, 'immich', NULL)"
        ), {"resource_id": asset_id, "person_id": person_id})

    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        assert connection.execute(text(
            "SELECT person_id, display_name, inactive_at "
            "FROM person_sources WHERE provider = 'immich' "
            "AND external_id = 'person-a'"
        )).one() == (person_id, None, None)
        assert connection.execute(text(
            "SELECT resource_id, person_id, provider, inactive_at "
            "FROM resource_person_relations"
        )).one() == (asset_id, person_id, "immich", None)

    _run_alembic(
        migration_engine,
        command.downgrade,
        TYPED_RESOURCE_V0_1_REVISION,
    )
    with migration_engine.connect() as connection:
        assert "display_name" not in {
            column["name"]
            for column in inspect(connection).get_columns("person_sources")
        }
        assert connection.execute(text(
            "SELECT person_id, inactive_at FROM person_sources "
            "WHERE provider = 'immich' AND external_id = 'person-a'"
        )).one() == (person_id, None)
        assert connection.execute(text(
            "SELECT resource_id, person_id, provider, inactive_at "
            "FROM resource_person_relations"
        )).one() == (asset_id, person_id, "immich", None)


def test_typed_resource_schema_backfill_constraints_and_downgrade(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        RESOURCE_PERSON_RELATION_V0_1_REVISION,
    )
    existing_id = uuid4()
    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO assets "
                "(id, title, metadata, created_at, updated_at) "
                "VALUES (:id, 'Existing File', '{}'::jsonb, now(), now())"
            ),
            {"id": existing_id},
        )

    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        inspector = inspect(connection)
        columns = {
            column["name"]: column
            for column in inspector.get_columns("assets")
        }
        assert columns["resource_type"]["nullable"] is False
        assert columns["resource_type"]["default"] is None
        assert connection.execute(
            text(
                "SELECT resource_type FROM assets WHERE id = :id"
            ),
            {"id": existing_id},
        ).scalar_one() == "file"
        assert {
            check["name"]
            for check in inspector.get_check_constraints("assets")
        } == {"ck_assets_resource_type"}
        with pytest.raises(Exception):
            connection.execute(
                text(
                    "INSERT INTO assets "
                    "(id, resource_type, title, metadata, "
                    "created_at, updated_at) VALUES "
                    "(:id, 'other', 'Invalid', '{}'::jsonb, now(), now())"
                ),
                {"id": uuid4()},
            )
        connection.rollback()

    _run_alembic(
        migration_engine,
        command.downgrade,
        RESOURCE_PERSON_RELATION_V0_1_REVISION,
    )
    with migration_engine.connect() as connection:
        assert "resource_type" not in {
            column["name"]
            for column in inspect(connection).get_columns("assets")
        }
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == RESOURCE_PERSON_RELATION_V0_1_REVISION

    _run_alembic(migration_engine, command.upgrade, "head")


def test_stamp_existing_v0_1_schema_preserves_data(
    migration_engine: Engine,
) -> None:
    schema_sql = SCHEMA_SQL.read_text(encoding="utf-8")

    asset_id = uuid4()
    blob_id = uuid4()
    source_id = uuid4()

    with migration_engine.connect() as connection:
        connection.exec_driver_sql(schema_sql)

    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO assets "
                "(id, title, metadata, created_at, updated_at) "
                "VALUES "
                "(:id, :title, CAST(:metadata AS jsonb), "
                "now(), now())"
            ),
            {
                "id": asset_id,
                "title": "Migration Test Asset",
                "metadata": (
                    '{"source": "migration-test", "version": 1}'
                ),
            },
        )
        connection.execute(
            text(
                "INSERT INTO blobs "
                "(id, asset_id, hash, size, mime_type) "
                "VALUES "
                "(:id, :asset_id, :hash, :size, :mime_type)"
            ),
            {
                "id": blob_id,
                "asset_id": asset_id,
                "hash": f"migration-test-{blob_id}",
                "size": 1,
                "mime_type": "text/plain",
            },
        )
        connection.execute(
            text(
                "INSERT INTO asset_sources "
                "(id, blob_id, provider, external_id, path, name, "
                "version_tag, metadata) "
                "VALUES "
                "(:id, :blob_id, :provider, :external_id, "
                ":path, :name, :version_tag, "
                "CAST(:metadata AS jsonb))"
            ),
            {
                "id": source_id,
                "blob_id": blob_id,
                "provider": "migration-test",
                "external_id": f"source-{source_id}",
                "path": "/migration/test.txt",
                "name": "test.txt",
                "version_tag": "v1",
                "metadata": (
                    '{"source": "migration-test-source", '
                    '"version": 1}'
                ),
            },
        )

    with migration_engine.connect() as connection:
        assert_v0_1_schema(connection)
        tables_before_stamp = set(
            inspect(connection).get_table_names()
        )
        snapshot_before_stamp = _business_snapshot(connection)

    assert snapshot_before_stamp["counts"] == {
        "assets": 1,
        "blobs": 1,
        "asset_sources": 1,
    }

    asset_before = snapshot_before_stamp["rows"]["assets"][0]
    blob_before = snapshot_before_stamp["rows"]["blobs"][0]
    source_before = snapshot_before_stamp["rows"][
        "asset_sources"
    ][0]

    assert asset_before["id"] == asset_id
    assert asset_before["title"] == "Migration Test Asset"
    assert asset_before["metadata"] == {
        "source": "migration-test",
        "version": 1,
    }
    assert blob_before["id"] == blob_id
    assert blob_before["asset_id"] == asset_before["id"]
    assert source_before["id"] == source_id
    assert source_before["blob_id"] == blob_before["id"]
    assert source_before["metadata"] == {
        "source": "migration-test-source",
        "version": 1,
    }

    _run_alembic(
        migration_engine,
        command.stamp,
        BASELINE_REVISION,
    )

    with migration_engine.connect() as connection:
        tables_after_stamp = set(
            inspect(connection).get_table_names()
        )
        snapshot_after_stamp = _business_snapshot(connection)

        assert connection.execute(
            text(
                "SELECT version_num "
                "FROM alembic_version"
            )
        ).scalar_one() == BASELINE_REVISION

    assert tables_after_stamp == (
        tables_before_stamp | {"alembic_version"}
    )
    assert snapshot_after_stamp == snapshot_before_stamp


def test_autogenerate_has_zero_diff(
    migration_engine: Engine,
) -> None:
    _run_alembic(
        migration_engine,
        command.upgrade,
        "head",
    )

    with migration_engine.connect() as connection:
        migration_context = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "compare_server_default": True,
            },
        )

        assert compare_metadata(
            migration_context,
            Base.metadata,
        ) == []


def test_mu6_additive_scope_state_preserves_legacy_state(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, SOURCE_PROVENANCE_REVISION)
    with migration_engine.begin() as connection:
        connection.execute(text("INSERT INTO provider_sync_state (provider,mechanism,checkpoint,version,reconciliation_required,created_at,updated_at) VALUES ('nextcloud','activity_v2_hint_v1','synthetic-opaque',7,true,'2026-09-08T01:00:00+00:00','2026-09-08T02:00:00+00:00')"))
        before = dict(connection.execute(text("SELECT * FROM provider_sync_state")).mappings().one())
    _run_alembic(migration_engine, command.upgrade, "head")
    with migration_engine.connect() as connection:
        after = dict(connection.execute(text("SELECT * FROM provider_sync_state")).mappings().one())
        assert after == before
        assert connection.execute(text("SELECT count(*) FROM observation_scope_sync_state")).scalar_one() == 0


def test_mu6_downgrade_rejects_nonempty_scope_state_before_drop(
    migration_engine: Engine,
) -> None:
    _run_alembic(migration_engine, command.upgrade, "head")
    instance_id, scope_id = uuid4(), uuid4()
    with migration_engine.begin() as connection:
        connection.execute(text("INSERT INTO provider_instances (id,provider_type,instance_key,enabled,created_at,updated_at) VALUES (:id,'nextcloud',:key,true,now(),now())"), {"id": instance_id, "key": f"mu6-{instance_id}"})
        connection.execute(text("INSERT INTO observation_scopes (id,provider_instance_id,scope_key,enabled,created_at,updated_at) VALUES (:id,:instance,:key,true,now(),now())"), {"id": scope_id, "instance": instance_id, "key": f"mu6-{scope_id}"})
        connection.execute(text("INSERT INTO observation_scope_sync_state (observation_scope_id,mechanism,checkpoint,version,reconciliation_required,created_at,updated_at) VALUES (:scope,'synthetic-v1','synthetic',0,false,now(),now())"), {"scope": scope_id})
    with pytest.raises(Exception, match="downgrade blocked"):
        _run_alembic(migration_engine, command.downgrade, SOURCE_PROVENANCE_REVISION)
    with migration_engine.connect() as connection:
        assert "observation_scope_sync_state" in inspect(connection).get_table_names()
