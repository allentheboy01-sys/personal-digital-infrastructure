from pathlib import Path
import secrets
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

from pdi.decision import Action, ActionType, Decision
from pdi.models import Asset
from pdi.principal import (
    DatabaseBindingRecord,
    DatabaseBindingRegistry,
    FleetDatabaseHealth,
    PersonalDatabaseFleetInspector,
    PersonalDatabaseProvisioner,
    PersonalDatabaseProvisioningSpec,
    PersonalQueryContextFactory,
    PrincipalDatabaseRouter,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.repository import PostgreSQLRepository
from tests.integration.database_guard import require_safe_test_database_url


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def personal_database_fleet():
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = (
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_harry_{token}_test",
            runtime_role=f"pdi_mu3_harry_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu3-harry-db",
        ),
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mother_{token}_test",
            runtime_role=f"pdi_mu3_mother_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref="mu3-mother-db",
        ),
    )
    results = []
    try:
        for spec in specs:
            results.append(provisioner.provision(spec))
        yield provisioner, specs, tuple(results)
    finally:
        for spec in reversed(specs[: len(results)]):
            provisioner.drop(spec, missing_ok=True)


def _insert_asset(database_url: str, asset: Asset) -> None:
    engine = create_engine(database_url, poolclass=NullPool)
    try:
        PostgreSQLRepository(engine).execute(
            Decision(actions=[Action(ActionType.CREATE_ASSET, asset=asset)])
        )
    finally:
        engine.dispose()


def test_two_principal_routing_roles_queries_and_resource_refs(
    personal_database_fleet,
) -> None:
    _, specs, results = personal_database_fleet
    harry, mother = results
    shared_uuid = str(uuid4())
    harry_private = Asset(title="MU3 Harry Private")
    mother_private = Asset(title="MU3 Mother Private")
    _insert_asset(harry.binding.database_url, harry_private)
    _insert_asset(mother.binding.database_url, mother_private)
    _insert_asset(
        harry.binding.database_url,
        Asset(id=shared_uuid, title="MU3 Harry Same UUID"),
    )

    # Provider identities are Personal-DB-local: equal logical keys coexist.
    harry_identity_engine = create_engine(
        harry.binding.database_url, poolclass=NullPool
    )
    mother_identity_engine = create_engine(
        mother.binding.database_url, poolclass=NullPool
    )
    try:
        harry_instance = PostgreSQLProviderIdentityRepository(
            harry_identity_engine
        ).create_instance(
            provider_type="nextcloud", instance_key="same-logical-key"
        )
        mother_instance = PostgreSQLProviderIdentityRepository(
            mother_identity_engine
        ).create_instance(
            provider_type="nextcloud", instance_key="same-logical-key"
        )
        assert harry_instance.instance_key == mother_instance.instance_key
    finally:
        harry_identity_engine.dispose()
        mother_identity_engine.dispose()
    _insert_asset(
        mother.binding.database_url,
        Asset(id=shared_uuid, title="MU3 Mother Same UUID"),
    )

    principals = PrincipalRegistry(
        (
            PrincipalRecord(PrincipalId("mu3-harry"), "mu3-harry-db"),
            PrincipalRecord(PrincipalId("mu3-mother"), "mu3-mother-db"),
        )
    )
    environment = {
        "MU3_HARRY_DATABASE_URL": harry.binding.database_url,
        "MU3_MOTHER_DATABASE_URL": mother.binding.database_url,
    }
    databases = DatabaseBindingRegistry(
        (
            DatabaseBindingRecord("mu3-harry-db", "MU3_HARRY_DATABASE_URL"),
            DatabaseBindingRecord("mu3-mother-db", "MU3_MOTHER_DATABASE_URL"),
        ),
        environment,
    )
    factory = PersonalQueryContextFactory(
        PrincipalDatabaseRouter(principals, databases)
    )

    with factory.create("mu3-harry") as context:
        titles = {asset.title for asset in context.query_service.list_assets()}
        assert "MU3 Harry Private" in titles
        assert "MU3 Mother Private" not in titles
        assert context.query_service.get_asset(mother_private.id) is None
        assert context.query_service.get_asset(shared_uuid).title == "MU3 Harry Same UUID"

    with factory.create("mu3-mother") as context:
        titles = {asset.title for asset in context.query_service.list_assets()}
        assert "MU3 Mother Private" in titles
        assert "MU3 Harry Private" not in titles
        assert context.query_service.get_asset(harry_private.id) is None
        assert context.query_service.get_asset(shared_uuid).title == "MU3 Mother Same UUID"

    for result, other_spec in ((harry, specs[1]), (mother, specs[0])):
        own_engine = create_engine(result.binding.database_url, poolclass=NullPool)
        try:
            with own_engine.connect() as connection:
                assert connection.exec_driver_sql("SELECT 1").scalar_one() == 1
        finally:
            own_engine.dispose()
        other_url = make_url(result.binding.database_url).set(
            database=other_spec.database_name
        )
        other_engine = create_engine(other_url, poolclass=NullPool)
        try:
            with pytest.raises(OperationalError):
                other_engine.connect()
        finally:
            other_engine.dispose()

    fleet = PersonalDatabaseFleetInspector(
        principals,
        databases,
        expected_revision=harry.schema_revision,
    ).inspect()
    assert len(fleet) == 2
    assert all(item.health is FleetDatabaseHealth.HEALTHY for item in fleet)
    assert all(item.current_revision == harry.schema_revision for item in fleet)


def test_provisioning_cleanup_after_failure(monkeypatch) -> None:
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    spec = PersonalDatabaseProvisioningSpec(
        database_name=f"pdi_mu3_failure_{token}_test",
        runtime_role=f"pdi_mu3_failure_{token}_runtime",
        runtime_password=secrets.token_urlsafe(32),
        database_ref="mu3-failure-db",
    )
    monkeypatch.setattr(
        "pdi.principal.provisioning.repository_schema_head",
        lambda _: "not-the-installed-head",
    )
    with pytest.raises(RuntimeError, match="revision is incompatible"):
        provisioner.provision(spec)
    # Failed provisioning cleaned only the objects it created. A second
    # cleanup is a safe no-op, never a broad name-based deletion.
    provisioner.drop(spec, missing_ok=True)
