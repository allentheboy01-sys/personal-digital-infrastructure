from pathlib import Path
import secrets
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from pdi.person_identity import ProviderPersonIdentity, ScopedPersonRepository
from pdi.principal import (
    DatabaseBindingRecord,
    DatabaseBindingRegistry,
    PersonalDatabaseProvisioner,
    PersonalDatabaseProvisioningSpec,
    PrincipalDatabaseRouter,
    PrincipalId,
    PrincipalRecord,
    PrincipalRegistry,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.repository import PostgreSQLRepository
from pdi.resource_person_relation import ScopedResourcePersonRelationRepository
from pdi.rich_retrieval import PersonLabelPrimary
from tests.integration.database_guard import require_safe_test_database_url
from tests.integration.test_scoped_person_relation import NOW, _asset


ROOT = Path(__file__).resolve().parents[2]


def test_person_relation_and_label_retrieval_are_personal_database_local():
    admin_url = require_safe_test_database_url()
    token = uuid4().hex[:8]
    provisioner = PersonalDatabaseProvisioner(admin_url, repository_root=ROOT)
    specs = tuple(
        PersonalDatabaseProvisioningSpec(
            database_name=f"pdi_mu3_mu11{label}_{token}_test",
            runtime_role=f"pdi_mu3_mu11{label}_{token}_runtime",
            runtime_password=secrets.token_urlsafe(32),
            database_ref=f"mu11-{label}-db",
        )
        for label in ("a", "b")
    )
    results = []
    engines = []
    try:
        results = [provisioner.provision(spec) for spec in specs]
        router = PrincipalDatabaseRouter(
            PrincipalRegistry(
                tuple(
                    PrincipalRecord(
                        PrincipalId(f"mu11-{label}"), f"mu11-{label}-db"
                    )
                    for label in ("a", "b")
                )
            ),
            DatabaseBindingRegistry(
                tuple(
                    DatabaseBindingRecord(
                        f"mu11-{label}-db", f"MU11_{label.upper()}_DATABASE_URL"
                    )
                    for label in ("a", "b")
                ),
                {
                    "MU11_A_DATABASE_URL": results[0].binding.database_url,
                    "MU11_B_DATABASE_URL": results[1].binding.database_url,
                },
            ),
        )
        engines = [
            create_engine(
                router.resolve(f"mu11-{label}").database_url,
                poolclass=NullPool,
            )
            for label in ("a", "b")
        ]
        for label, engine in zip(("A", "B"), engines, strict=True):
            identities = PostgreSQLProviderIdentityRepository(engine)
            instance = identities.create_instance(
                provider_type="immich", instance_key="same-instance-key"
            )
            scope = identities.create_scope(
                provider_instance_id=instance.id, scope_key="same-scope-key"
            )
            _asset(engine, scope.id, "same-asset-id")
            people = ScopedPersonRepository(engine, scope.id)
            people.reconcile_inventory(
                (ProviderPersonIdentity("same-person-id", f"Alex {label}"),),
                now=NOW,
            )
            ScopedResourcePersonRelationRepository(
                engine, scope.id
            ).reconcile_relations((("same-asset-id", "same-person-id"),), now=NOW)

        for label, engine in zip(("A", "B"), engines, strict=True):
            results_for_label = PostgreSQLRepository(
                engine
            ).search_current_person_label(
                primary=PersonLabelPrimary(
                    kind="person_label", label=f"Alex {label}"
                ),
                limit=10,
            )
            other = "B" if label == "A" else "A"
            results_for_other = PostgreSQLRepository(
                engine
            ).search_current_person_label(
                primary=PersonLabelPrimary(
                    kind="person_label", label=f"Alex {other}"
                ),
                limit=10,
            )
            assert len(results_for_label) == 1
            assert results_for_other == ()
    finally:
        for engine in engines:
            engine.dispose()
        for spec in reversed(specs[: len(results)]):
            provisioner.drop(spec, missing_ok=True)
