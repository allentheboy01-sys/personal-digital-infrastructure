from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from pdi.database import create_postgres_engine
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.production_ops.p3d_evidence import postgresql_read_only_transaction
from pdi.scoped_enrichment_profiles import derive_enabled_scope_ids
from tests.integration.database_guard import require_safe_test_database_url


def test_verified_read_only_transaction_allows_select_and_rejects_insert():
    engine = create_postgres_engine(require_safe_test_database_url())
    probe = uuid4().hex
    try:
        with postgresql_read_only_transaction(engine) as connection:
            assert connection.scalar(text("SELECT 1")) == 1
            repository = PostgreSQLProviderIdentityRepository(connection)
            repository.list_instances()
            derive_enabled_scope_ids(connection)
            assert connection.scalar(text("SHOW transaction_read_only")) == "on"
            with pytest.raises(DBAPIError):
                connection.execute(
                    text("INSERT INTO alembic_version (version_num) VALUES (:probe)"),
                    {"probe": probe},
                )
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT count(*) FROM alembic_version WHERE version_num=:probe"),
                {"probe": probe},
            ) == 0
    finally:
        engine.dispose()
