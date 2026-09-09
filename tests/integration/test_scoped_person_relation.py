from datetime import UTC, datetime, timedelta
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from pdi.person_identity import ProviderPersonIdentity, ScopedPersonRepository
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.resource_person_relation import ScopedResourcePersonRelationRepository
from pdi.repository import PostgreSQLRepository
from pdi.observation import PostgreSQLObservationRepository
from pdi.rich_retrieval import PersonLabelPrimary
from tests.integration.database_guard import require_safe_test_database_url


NOW = datetime(2026, 9, 9, tzinfo=UTC)


@pytest.fixture
def scoped_world():
    engine = create_engine(require_safe_test_database_url(), poolclass=NullPool)
    config = Config("alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    tables = (
        "observation_scope_resource_person_relations",
        "resource_person_relations",
        "observation_scope_person_sources",
        "person_sources",
        "persons",
        "asset_sources",
        "blobs",
        "assets",
        "observation_scope_sync_state",
        "observation_scopes",
        "provider_accounts",
        "provider_instances",
    )
    with engine.begin() as connection:
        for table in tables:
            connection.execute(text(f"DELETE FROM {table}"))
    identities = PostgreSQLProviderIdentityRepository(engine)
    instance = identities.create_instance(
        provider_type="immich", instance_key="mu11-immich"
    )
    account_a = identities.create_account(
        provider_instance_id=instance.id, account_key="account-a"
    )
    account_b = identities.create_account(
        provider_instance_id=instance.id, account_key="account-b"
    )
    scope_a = identities.create_scope(
        provider_instance_id=instance.id,
        provider_account_id=account_a.id,
        scope_key="scope-a",
    )
    scope_b = identities.create_scope(
        provider_instance_id=instance.id,
        provider_account_id=account_b.id,
        scope_key="scope-b",
    )
    try:
        yield engine, scope_a, scope_b
    finally:
        with engine.begin() as connection:
            for table in tables:
                connection.execute(text(f"DELETE FROM {table}"))
        engine.dispose()


def _asset(engine, scope_id, external_id):
    asset_id, blob_id, source_id = uuid4(), uuid4(), uuid4()
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO assets (id,resource_type,title,metadata,created_at,updated_at) VALUES (:id,'file',:title,'{}',:now,:now)"),
            {"id": asset_id, "title": external_id, "now": NOW},
        )
        connection.execute(
            text("INSERT INTO blobs (id,asset_id,hash,size,mime_type) VALUES (:id,:asset,:hash,1,'image/jpeg')"),
            {"id": blob_id, "asset": asset_id, "hash": str(blob_id)},
        )
        connection.execute(
            text("INSERT INTO asset_sources (id,blob_id,provider,external_id,path,name,version_tag,metadata,is_active,deleted_at,observation_scope_id) VALUES (:id,:blob,'immich',:external,NULL,NULL,NULL,'{}',TRUE,NULL,:scope)"),
            {"id": source_id, "blob": blob_id, "external": external_id, "scope": scope_id},
        )
    return asset_id


def _people(*items):
    return tuple(ProviderPersonIdentity(*item) for item in items)


def test_scoped_person_identity_reconciliation_and_reactivation(scoped_world):
    engine, scope_a, scope_b = scoped_world
    a = ScopedPersonRepository(engine, scope_a.id)
    b = ScopedPersonRepository(engine, scope_b.id)
    a.reconcile_inventory(_people(("same", "Alex A"), ("a-only", "A Only")), now=NOW)
    b.reconcile_inventory(_people(("same", "Alex B"), ("b-only", "B Only")), now=NOW)
    assert a.find_source("same").person_id != b.find_source("same").person_id
    a_only_id = a.find_source("a-only").person_id
    result = a.reconcile_inventory(_people(("same", "Alex A")), now=NOW + timedelta(minutes=1))
    assert result.inactivated == 1
    assert b.find_source("same").inactive_at is None
    assert b.find_source("b-only").inactive_at is None
    result = a.reconcile_inventory(
        _people(("same", "Alex A"), ("a-only", "A Again")),
        now=NOW + timedelta(minutes=2),
    )
    assert result.reactivated == 1
    assert a.find_source("a-only").person_id == a_only_id


def test_scoped_relation_mapping_reconciliation_and_reactivation(scoped_world):
    engine, scope_a, scope_b = scoped_world
    asset_a = _asset(engine, scope_a.id, "same-asset")
    asset_b = _asset(engine, scope_b.id, "same-asset")
    people_a = ScopedPersonRepository(engine, scope_a.id)
    people_b = ScopedPersonRepository(engine, scope_b.id)
    people_a.reconcile_inventory(_people(("same-person", "Alex")), now=NOW)
    people_b.reconcile_inventory(_people(("same-person", "Alex")), now=NOW)
    relation_a = ScopedResourcePersonRelationRepository(engine, scope_a.id)
    relation_b = ScopedResourcePersonRelationRepository(engine, scope_b.id)
    assert relation_a.reconcile_relations((("same-asset", "same-person"),), now=NOW).created == 1
    assert relation_b.reconcile_relations((("same-asset", "same-person"),), now=NOW).created == 1
    assert relation_a.reconcile_relations((), now=NOW + timedelta(minutes=1)).inactivated == 1
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT observation_scope_id,resource_id,inactive_at FROM observation_scope_resource_person_relations")
        ).all()
    by_scope = {row.observation_scope_id: row for row in rows}
    assert by_scope[scope_a.id].resource_id == asset_a
    assert by_scope[scope_a.id].inactive_at is not None
    assert by_scope[scope_b.id].resource_id == asset_b
    assert by_scope[scope_b.id].inactive_at is None
    assert relation_a.reconcile_relations((("same-asset", "same-person"),), now=NOW + timedelta(minutes=2)).reactivated == 1


def test_scoped_person_label_participates_without_label_merge(scoped_world):
    engine, scope_a, scope_b = scoped_world
    _asset(engine, scope_a.id, "asset-a")
    _asset(engine, scope_b.id, "asset-b")
    people_a = ScopedPersonRepository(engine, scope_a.id)
    people_b = ScopedPersonRepository(engine, scope_b.id)
    people_a.reconcile_inventory(_people(("person-a", "Alex")), now=NOW)
    people_b.reconcile_inventory(_people(("person-b", "Alex")), now=NOW)
    ScopedResourcePersonRelationRepository(engine, scope_a.id).reconcile_relations(
        (("asset-a", "person-a"),), now=NOW
    )
    ScopedResourcePersonRelationRepository(engine, scope_b.id).reconcile_relations(
        (("asset-b", "person-b"),), now=NOW
    )
    results = PostgreSQLRepository(engine).search_current_person_label(
        primary=PersonLabelPrimary(kind="person_label", label="Alex"), limit=10
    )
    assert {candidate.resource.display_name for candidate in results} == {
        "asset-a",
        "asset-b",
    }
    assert people_a.find_source("person-a").person_id != people_b.find_source(
        "person-b"
    ).person_id


def test_enrichment_projection_carries_actual_source_scope(scoped_world):
    engine, scope_a, scope_b = scoped_world
    _asset(engine, scope_a.id, "asset-a")
    _asset(engine, scope_b.id, "asset-b")
    resources = PostgreSQLObservationRepository(engine).list_enrichment_resources(
        provider="immich"
    )
    assert {
        source.observation_scope_id
        for resource in resources
        for source in resource.sources
    } == {str(scope_a.id), str(scope_b.id)}
