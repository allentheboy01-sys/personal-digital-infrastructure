from pathlib import Path

from sqlalchemy import create_engine

from pdi.principal import (
    DatabaseBindingRecord,
    DatabaseBindingRegistry,
    FleetDatabaseHealth,
    PersonalDatabaseFleetInspector,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
    repository_schema_head,
)


ROOT = Path(__file__).resolve().parents[1]


def test_repository_has_exactly_one_schema_head() -> None:
    assert repository_schema_head(ROOT) == "d4f6a8c0e213"


def test_fleet_reports_unavailable_database_without_exposing_url() -> None:
    principals = PrincipalRegistry(
        (PrincipalRecord(PrincipalId("mu3-harry"), "harry-db"),)
    )
    databases = DatabaseBindingRegistry(
        (DatabaseBindingRecord("harry-db", "HARRY_DATABASE_URL"),),
        {
            "HARRY_DATABASE_URL": (
                "postgresql+psycopg://user:topsecret@127.0.0.1:1/db_test"
            )
        },
    )
    inspector = PersonalDatabaseFleetInspector(
        principals,
        databases,
        expected_revision="b8d4f2a6c901",
        engine_factory=create_engine,
    )
    status = inspector.inspect()[0]
    assert status.health is FleetDatabaseHealth.FAILED
    assert status.reachable is False
    assert status.error_code == "database_unavailable"
    assert "topsecret" not in repr(status)
