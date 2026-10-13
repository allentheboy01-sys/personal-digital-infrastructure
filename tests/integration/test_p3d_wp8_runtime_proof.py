from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
import secrets
import traceback
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.pool import NullPool

from pdi.data_status import PipelineKind, PipelineRunRepository
from pdi.observation import (
    Evidence,
    EvidenceSourceKind,
    EnrichmentSource,
    GeneratorIdentity,
    ObservationBatch,
    PostgreSQLObservationRepository,
    StatementDraft,
    StatementValueType,
    TypedStatementValue,
)
from pdi.observation.errors import ObservationLifecycleError
from pdi.principal import (
    PersonalDatabaseProvisioner,
    PersonalDatabaseProvisioningSpec,
    PrincipalDatabaseRouter,
)
from pdi.production_ops.p3d_evidence import (
    context_fingerprint,
    postgresql_read_only_transaction,
)
from pdi.production_ops.p3d_preparation_contracts import contract_fingerprint
from pdi.production_ops.p3d_wp8_contracts import (
    WP8_CANONICAL_PIPELINE_KEYS,
    WP8InvariantSnapshotV1,
    WP8PhaseAEvidenceV1,
)
from pdi.production_ops.p3d_wp8_runtime_proof import (
    WP8RuntimeProofError,
    WP8RuntimeProofReader,
)
from pdi.production_ops.p3d_wp8_preflight import _binding_fingerprint
from pdi.production_ops.p3d_wp8_systemd import (
    _ExecutionAttestationV1,
    _Outcome,
    _SERVICE_UNITS,
    _ServiceResult,
)
from pdi.provider_identity import PostgreSQLProviderIdentityRepository
from pdi.query import format_resource_ref
from pdi.scoped_enrichment_profiles import derive_enabled_scope_ids
from tests.integration.database_guard import require_safe_test_database_url
from tests.test_p3d_wp8_contracts import (
    CANDIDATE,
    GATE_A,
    GATE_B,
    GATE_C,
    H1,
    H2,
    H3,
    H4,
    H5,
    H8,
    H9,
    HA,
    HB,
    HC,
    OPERATION,
    ROLLBACK,
    snapshot,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 12, 8, tzinfo=UTC)
PRINCIPAL = "synthetic-runtime-proof"
GENERATORS = {
    "enrichment.nextcloud_text": (
        "deterministic_extractor", "nextcloud_text", "1"
    ),
    "enrichment.nextcloud_documents": (
        "deterministic_extractor", "nextcloud_pdf", "1"
    ),
    "enrichment.file_metadata": (
        "deterministic_extractor", "file_metadata", "1"
    ),
    "enrichment.immich_geo": (
        "deterministic_extractor", "immich_geo", "1"
    ),
    "enrichment.immich_metadata": (
        "deterministic_extractor", "immich_metadata", "1"
    ),
    "enrichment.immich_ocr": (
        "provider_native_ml", "immich_ocr", "1"
    ),
}


@pytest.fixture
def runtime_database():
    token = uuid4().hex[:10]
    spec = PersonalDatabaseProvisioningSpec(
        database_name=f"pdi_mu3_wp8proof_{token}_test",
        runtime_role=f"pdi_mu3_wp8proof_{token}_runtime",
        runtime_password=secrets.token_urlsafe(32),
        database_ref="wp8-runtime-proof",
    )
    provisioner = PersonalDatabaseProvisioner(
        require_safe_test_database_url(), repository_root=ROOT
    )
    result = provisioner.provision(spec)
    engine = create_engine(result.binding.database_url, poolclass=NullPool)
    try:
        yield engine, result.binding.database_url
    finally:
        engine.dispose()
        provisioner.drop(spec, missing_ok=True)


def _identity_fixture(engine):
    repository = PostgreSQLProviderIdentityRepository(engine)
    enabled_scopes = {}
    for provider in ("nextcloud", "immich"):
        instance = repository.create_instance(
            provider_type=provider, instance_key=f"{provider}-runtime-proof"
        )
        account = repository.create_account(
            provider_instance_id=instance.id,
            account_key=f"{provider}-runtime-proof",
        )
        enabled_scopes[provider] = repository.create_scope(
            provider_instance_id=instance.id,
            provider_account_id=account.id,
            scope_key=f"{provider}-runtime-proof",
        )
    for provider in ("gmail", "integration-test"):
        instance = repository.create_instance(
            provider_type=provider,
            instance_key=f"{provider}-runtime-proof",
            enabled=False,
        )
        repository.create_scope(
            provider_instance_id=instance.id,
            scope_key=f"{provider}-runtime-proof",
            enabled=False,
        )
    return enabled_scopes


def _insert_asset(engine, *, provider, scope_id, label):
    asset_id = uuid4()
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO assets "
            "(id,resource_type,title,metadata,created_at,updated_at) "
            "VALUES (:id,'file',:title,'{}'::jsonb,:now,:now)"
        ), {"id": asset_id, "title": label, "now": NOW})
    source = _insert_source(
        engine,
        asset_id=asset_id,
        provider=provider,
        scope_id=scope_id,
        label=label,
    )
    return asset_id, source


def _insert_source(engine, *, asset_id, provider, scope_id, label):
    blob_id, source_id = uuid4(), uuid4()
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO blobs (id,asset_id,hash,size,mime_type) "
            "VALUES (:id,:asset,:hash,1,'text/plain')"
        ), {"id": blob_id, "asset": asset_id, "hash": f"proof-{blob_id}"})
        connection.execute(text(
            "INSERT INTO asset_sources "
            "(id,blob_id,provider,external_id,metadata,is_active,"
            "observation_scope_id) VALUES "
            "(:id,:blob,:provider,:external,'{}'::jsonb,true,:scope)"
        ), {
            "id": source_id,
            "blob": blob_id,
            "provider": provider,
            "external": label,
            "scope": scope_id,
        })
    return EnrichmentSource(
        str(source_id),
        provider,
        {},
        is_active=True,
        observation_scope_id=str(scope_id),
    )


def _database_bindings(engine, database_url, *, route_fingerprint_override=None):
    router = PrincipalDatabaseRouter.explicit_single_user(
        principal_id=PRINCIPAL, database_url=database_url
    )
    binding = router.resolve(PRINCIPAL)
    with engine.connect() as connection:
        instances = [tuple(row) for row in connection.execute(text(
            "SELECT id,provider_type,instance_key,enabled "
            "FROM provider_instances ORDER BY id"
        ))]
        accounts = [tuple(row) for row in connection.execute(text(
            "SELECT id,provider_instance_id,account_key,provider_native_id,enabled "
            "FROM provider_accounts ORDER BY id"
        ))]
        scopes = [tuple(row) for row in connection.execute(text(
            "SELECT id,provider_instance_id,provider_account_id,scope_key,enabled "
            "FROM observation_scopes ORDER BY id"
        ))]
        scope_ids = sorted(map(str, derive_enabled_scope_ids(connection)))
    identity_state = []
    for instance_id, provider, _, enabled in instances:
        related = [row for row in scopes if row[1] == instance_id]
        assert len(related) == 1
        scope = related[0]
        identity_state.append({
            "provider_type": provider,
            "instance_id": str(instance_id),
            "instance_enabled": enabled,
            "account_ids": sorted(
                str(row[0]) for row in accounts if row[1] == instance_id
            ),
            "scope_id": str(scope[0]),
            "scope_enabled": scope[4],
        })
    identity = context_fingerprint({
        "principal": PRINCIPAL,
        "database_ref": binding.database_ref,
        "scopes": scope_ids,
        "identity_state": sorted(
            identity_state, key=lambda item: item["provider_type"]
        ),
    })
    scope_fingerprint = contract_fingerprint({
        "principal_ref": PRINCIPAL,
        "enabled_scope_ids": scope_ids,
    })
    baseline_mapping = snapshot().to_mapping()
    binding = router.resolve(PRINCIPAL)
    with engine.connect() as connection:
        target = tuple(connection.execute(text(
            "SELECT current_database(),current_user,"
            "inet_server_addr()::text,inet_server_port()"
        )).one())
    route_fingerprint = _binding_fingerprint(
        "route",
        {
            "principal": PRINCIPAL,
            "database_ref": binding.database_ref,
            "url_env": router.database_environment_key(PRINCIPAL),
            "connected_target": target,
        },
    )
    baseline_mapping["principal_route_fingerprint"] = (
        route_fingerprint
        if route_fingerprint_override is None
        else route_fingerprint_override
    )
    baseline_mapping["db_identity_fingerprint"] = identity
    baseline_mapping["enabled_scope_fingerprint"] = scope_fingerprint
    baseline = WP8InvariantSnapshotV1.from_mapping(baseline_mapping)
    phase_a = WP8PhaseAEvidenceV1.build(
        candidate_sha=CANDIDATE,
        rollback_source_sha=ROLLBACK,
        gate_a_operation_id=GATE_A,
        gate_a_authority_binding_fingerprint=H1,
        gate_b_operation_id=GATE_B,
        gate_b_authority_binding_fingerprint=H2,
        gate_c_operation_id=GATE_C,
        gate_c_marker_fingerprint=H3,
        gate_c_authority_binding_fingerprint=H4,
        wp6_context_fingerprint=H5,
        db_identity_fingerprint=identity,
        enabled_scope_count=len(scope_ids),
        enabled_scope_fingerprint=scope_fingerprint,
        unit_profile_asset_fingerprint=H8,
        p3c_state_fingerprint=H9,
        p3c_systemd_fingerprint=HA,
        protected_environment_fingerprint=HB,
        registry_fingerprint=HC,
        invariant_baseline=baseline,
    )
    return router, phase_a


def _service_result(key, invocation_fingerprint, phase_a):
    manager = hashlib.sha256(f"manager:{key}".encode()).hexdigest()
    unit_contract = hashlib.sha256(f"unit:{key}".encode()).hexdigest()
    values = {
        "candidate": phase_a.candidate_sha,
        "context": phase_a.phase_a_context_fingerprint,
        "pipeline": key,
        "manager": manager,
        "contract": unit_contract,
        "start": 10,
        "exit": 20,
        "invocation_hash": invocation_fingerprint,
        "result": "success",
        "exit_status": 0,
    }
    service_fingerprint = contract_fingerprint(values)
    attestation = _ExecutionAttestationV1(
        version=1,
        pipeline_key=key,
        unit=_SERVICE_UNITS[key],
        candidate_sha=phase_a.candidate_sha,
        phase_a_context_fingerprint=phase_a.phase_a_context_fingerprint,
        manager_fingerprint=manager,
        unit_contract_fingerprint=unit_contract,
        start_monotonic_usec=10,
        exit_monotonic_usec=20,
        invocation_fingerprint=invocation_fingerprint,
        result="success",
        exit_status=0,
        service_result_fingerprint=service_fingerprint,
    )
    return _ServiceResult(
        key,
        _SERVICE_UNITS[key],
        _Outcome.SUCCESS,
        manager,
        unit_contract,
        service_fingerprint,
        "INACTIVE",
        attestation,
    )


def _publish_six(
    engine,
    scopes,
    phase_a,
    *,
    deletion_key=None,
    no_effect_key=None,
):
    runs = PipelineRunRepository(engine)
    results = []
    for index, key in enumerate(WP8_CANONICAL_PIPELINE_KEYS):
        invocation = hashlib.sha256(f"invocation:{key}".encode()).hexdigest()
        run = runs.begin_run(
            key,
            PipelineKind.ENRICHMENT,
            started_at=NOW + timedelta(seconds=index),
            invocation_fingerprint=invocation,
        )
        provider = "nextcloud" if key.startswith("enrichment.nextcloud") else "immich"
        asset_id, effect_source = _insert_asset(
            engine,
            provider=provider,
            scope_id=scopes[provider].id,
            label=f"runtime-proof-{index}",
        )
        generator = GeneratorIdentity(*GENERATORS[key])
        statement = StatementDraft(
            "media.camera_make",
            TypedStatementValue(StatementValueType.STRING, f"value-{index}"),
            Evidence(EvidenceSourceKind.PROVIDER_METADATA, "synthetic.proof"),
        )
        if key == deletion_key:
            PostgreSQLObservationRepository(engine).publish(
                ObservationBatch(
                    format_resource_ref(asset_id),
                    generator,
                    ("media.camera_make",),
                    hashlib.sha256(f"initial:{key}".encode()).hexdigest(),
                    (statement,),
                ),
                completed_at=NOW - timedelta(minutes=1),
            )
        batch = ObservationBatch(
            format_resource_ref(asset_id),
            generator,
            ("media.camera_make",),
            hashlib.sha256(f"input:{key}".encode()).hexdigest(),
            () if key == deletion_key else (statement,),
        )
        if key != no_effect_key:
            receipt_repository = PostgreSQLObservationRepository(
                engine,
                effect_run_id=run.id,
                effect_pipeline_key=key,
            )
            published = receipt_repository.publish(
                batch,
                completed_at=NOW + timedelta(minutes=1, seconds=index),
                effect_sources=(effect_source,),
            )
            assert published.statement_writes == (0 if key == deletion_key else 1)
            assert published.deactivated_statements == (
                1 if key == deletion_key else 0
            )
        runs.complete_run(
            run.id, finished_at=NOW + timedelta(minutes=2, seconds=index)
        )
        results.append(_service_result(key, invocation, phase_a))
    return tuple(results)


def test_runtime_proof_exactly_binds_invocation_run_receipts_and_effect_rows(
    runtime_database,
) -> None:
    engine, database_url = runtime_database
    scopes = _identity_fixture(engine)
    router, phase_a = _database_bindings(engine, database_url)
    service_results = _publish_six(engine, scopes, phase_a)
    reader = WP8RuntimeProofReader(
        router=router,
        engine=engine,
        principal_ref=PRINCIPAL,
        phase_a_evidence=phase_a,
    )
    with engine.connect() as connection:
        before = connection.execute(text(
            "SELECT "
            "(SELECT count(*) FROM pipeline_runs),"
            "(SELECT count(*) FROM pipeline_run_effect_receipts),"
            "(SELECT count(*) FROM resource_statements),"
            "(SELECT count(*) FROM resource_enrichments)"
        )).one()
    proof = reader.collect(
        service_results,
        rehearsal_operation_id=OPERATION,
        runtime_boundary_fingerprint=H3,
    )
    assert proof.runtime_pipeline_coverage == "6/6"
    assert tuple(record.pipeline_key for record in proof.pipeline_records) == (
        WP8_CANONICAL_PIPELINE_KEYS
    )
    assert all(record.completed_enrichment_count == 1 for record in proof.pipeline_records)
    assert all(record.current_statement_count == 1 for record in proof.pipeline_records)
    wrong_outcome = list(service_results)
    wrong_outcome[0] = replace(
        wrong_outcome[0], outcome=_Outcome.COMMAND_FAILED
    )
    with pytest.raises(WP8RuntimeProofError):
        reader.collect(
            wrong_outcome,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE resource_statements SET string_value='semantic-tamper' "
            "WHERE id=(SELECT id FROM resource_statements ORDER BY id LIMIT 1)"
        ))
    with pytest.raises(WP8RuntimeProofError):
        reader.collect(
            service_results,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )
    with engine.connect() as connection:
        after = connection.execute(text(
            "SELECT "
            "(SELECT count(*) FROM pipeline_runs),"
            "(SELECT count(*) FROM pipeline_run_effect_receipts),"
            "(SELECT count(*) FROM resource_statements),"
            "(SELECT count(*) FROM resource_enrichments)"
        )).one()
    assert after == before

    with pytest.raises(DBAPIError):
        with postgresql_read_only_transaction(engine) as connection:
            connection.execute(text(
                "INSERT INTO assets "
                "(id,resource_type,title,metadata,created_at,updated_at) "
                "VALUES (:id,'file','forbidden','{}'::jsonb,now(),now())"
            ), {"id": uuid4()})


def test_receipt_write_is_atomic_append_only_and_context_bound(
    runtime_database,
) -> None:
    engine, _ = runtime_database
    scopes = _identity_fixture(engine)
    run = PipelineRunRepository(engine).begin_run(
        "enrichment.file_metadata",
        PipelineKind.ENRICHMENT,
        invocation_fingerprint="a" * 64,
    )
    asset_id, effect_source = _insert_asset(
        engine,
        provider="immich",
        scope_id=scopes["immich"].id,
        label="atomic-rejection",
    )
    batch = ObservationBatch(
        format_resource_ref(asset_id),
        GeneratorIdentity("deterministic_extractor", "file_metadata", "1"),
        ("media.camera_make",),
        "b" * 64,
        (StatementDraft(
            "media.camera_make",
            TypedStatementValue(StatementValueType.STRING, "must-roll-back"),
            Evidence(EvidenceSourceKind.PROVIDER_METADATA, "synthetic.proof"),
        ),),
    )
    wrong_context = PostgreSQLObservationRepository(
        engine,
        effect_run_id=run.id,
        effect_pipeline_key="enrichment.immich_geo",
    )
    with pytest.raises(DBAPIError):
        wrong_context.publish(
            batch,
            completed_at=NOW,
            effect_sources=(effect_source,),
        )
    with engine.connect() as connection:
        assert connection.scalar(text(
            "SELECT count(*) FROM resource_statements WHERE subject_asset_id=:id"
        ), {"id": asset_id}) == 0
        assert connection.scalar(text(
            "SELECT count(*) FROM resource_enrichments WHERE subject_asset_id=:id"
        ), {"id": asset_id}) == 0
        assert connection.scalar(text(
            "SELECT count(*) FROM pipeline_run_effect_receipts "
            "WHERE pipeline_run_id=:id"
        ), {"id": run.id}) == 0

    valid = PostgreSQLObservationRepository(
        engine,
        effect_run_id=run.id,
        effect_pipeline_key="enrichment.file_metadata",
    )
    valid.publish(
        batch,
        completed_at=NOW,
        effect_sources=(effect_source,),
    )
    PipelineRunRepository(engine).complete_run(run.id)
    with engine.connect() as connection:
        receipt_id = connection.scalar(text(
            "SELECT id FROM pipeline_run_effect_receipts "
            "WHERE pipeline_run_id=:id"
        ), {"id": run.id})
    with pytest.raises(DBAPIError), engine.begin() as connection:
        connection.execute(text(
            "UPDATE pipeline_run_effect_receipts SET current_statement_count=0 "
            "WHERE id=:id"
        ), {"id": receipt_id})
    with pytest.raises(DBAPIError), engine.begin() as connection:
        connection.execute(text(
            "DELETE FROM pipeline_run_effect_receipts WHERE id=:id"
        ), {"id": receipt_id})


def test_runtime_proof_rejects_missing_invocation_run_without_fallback(
    runtime_database,
) -> None:
    engine, database_url = runtime_database
    scopes = _identity_fixture(engine)
    router, phase_a = _database_bindings(engine, database_url)
    service_results = list(_publish_six(engine, scopes, phase_a))
    missing = "f" * 64
    service_results[0] = _service_result(
        WP8_CANONICAL_PIPELINE_KEYS[0], missing, phase_a
    )
    reader = WP8RuntimeProofReader(
        router=router,
        engine=engine,
        principal_ref=PRINCIPAL,
        phase_a_evidence=phase_a,
    )
    with pytest.raises(WP8RuntimeProofError):
        reader.collect(
            service_results,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )


def test_runtime_proof_rejects_completed_run_without_effect_receipt(
    runtime_database,
) -> None:
    engine, database_url = runtime_database
    scopes = _identity_fixture(engine)
    router, phase_a = _database_bindings(engine, database_url)
    key = "enrichment.immich_ocr"
    service_results = _publish_six(
        engine,
        scopes,
        phase_a,
        no_effect_key=key,
    )
    with pytest.raises(WP8RuntimeProofError):
        WP8RuntimeProofReader(
            router=router,
            engine=engine,
            principal_ref=PRINCIPAL,
            phase_a_evidence=phase_a,
        ).collect(
            service_results,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )


def test_invocation_binding_is_unique_at_database_boundary(runtime_database) -> None:
    engine, _ = runtime_database
    runs = PipelineRunRepository(engine)
    bound = runs.begin_run(
        "enrichment.file_metadata",
        PipelineKind.ENRICHMENT,
        invocation_fingerprint="c" * 64,
    )
    with pytest.raises(IntegrityError):
        runs.begin_run(
            "enrichment.immich_geo",
            PipelineKind.ENRICHMENT,
            invocation_fingerprint="c" * 64,
        )
    manual = runs.begin_run(
        "enrichment.nextcloud_text",
        PipelineKind.ENRICHMENT,
    )
    for run_id, replacement in (
        (bound.id, None),
        (bound.id, "d" * 64),
        (manual.id, "e" * 64),
    ):
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(text(
                "UPDATE pipeline_runs SET invocation_fingerprint=:value WHERE id=:id"
            ), {"id": run_id, "value": replacement})
    assert runs.complete_run(bound.id).status.value == "completed"
    assert runs.complete_run(manual.id).status.value == "completed"


def test_runtime_proof_accepts_exact_deactivation_only_effect(runtime_database) -> None:
    engine, database_url = runtime_database
    scopes = _identity_fixture(engine)
    router, phase_a = _database_bindings(engine, database_url)
    key = "enrichment.file_metadata"
    service_results = _publish_six(
        engine, scopes, phase_a, deletion_key=key
    )
    proof = WP8RuntimeProofReader(
        router=router,
        engine=engine,
        principal_ref=PRINCIPAL,
        phase_a_evidence=phase_a,
    ).collect(
        service_results,
        rehearsal_operation_id=OPERATION,
        runtime_boundary_fingerprint=H3,
    )
    record = next(item for item in proof.pipeline_records if item.pipeline_key == key)
    assert record.current_statement_count == 0
    with engine.connect() as connection:
        assert connection.execute(text(
            "SELECT statement_write_count,deactivated_statement_count,"
            "current_statement_count FROM pipeline_run_effect_receipts "
            "WHERE pipeline_key=:key"
        ), {"key": key}).one() == (0, 1, 0)


def test_effect_receipt_rejects_wrong_provider_and_disabled_scope(
    runtime_database,
) -> None:
    engine, _ = runtime_database
    scopes = _identity_fixture(engine)
    cases = (
        ("enrichment.nextcloud_text", "immich", scopes["immich"].id, False),
        (
            "enrichment.nextcloud_documents",
            "nextcloud",
            scopes["nextcloud"].id,
            True,
        ),
    )
    for index, (key, provider, scope_id, disable_scope) in enumerate(cases):
        invocation = hashlib.sha256(f"wrong-scope:{index}".encode()).hexdigest()
        run = PipelineRunRepository(engine).begin_run(
            key,
            PipelineKind.ENRICHMENT,
            invocation_fingerprint=invocation,
        )
        asset_id, source = _insert_asset(
            engine,
            provider=provider,
            scope_id=scope_id,
            label=f"wrong-scope-{index}",
        )
        if disable_scope:
            with engine.begin() as connection:
                connection.execute(text(
                    "UPDATE observation_scopes SET enabled=false WHERE id=:id"
                ), {"id": scope_id})
        batch = ObservationBatch(
            format_resource_ref(asset_id),
            GeneratorIdentity(*GENERATORS[key]),
            ("media.camera_make",),
            hashlib.sha256(f"wrong-scope-input:{index}".encode()).hexdigest(),
            (StatementDraft(
                "media.camera_make",
                TypedStatementValue(StatementValueType.STRING, "rejected"),
                Evidence(EvidenceSourceKind.PROVIDER_METADATA, "synthetic.proof"),
            ),),
        )
        with pytest.raises(ObservationLifecycleError):
            PostgreSQLObservationRepository(
                engine,
                effect_run_id=run.id,
                effect_pipeline_key=key,
            ).publish(batch, completed_at=NOW, effect_sources=(source,))
        with engine.connect() as connection:
            assert connection.scalar(text(
                "SELECT count(*) FROM pipeline_run_effect_receipts "
                "WHERE pipeline_run_id=:id"
            ), {"id": run.id}) == 0
            assert connection.scalar(text(
                "SELECT count(*) FROM resource_statements "
                "WHERE subject_asset_id=:id"
            ), {"id": asset_id}) == 0
        if disable_scope:
            with engine.begin() as connection:
                connection.execute(text(
                    "UPDATE observation_scopes SET enabled=true WHERE id=:id"
                ), {"id": scope_id})


def test_effect_receipt_commits_exact_multi_source_scope_set(runtime_database) -> None:
    engine, _ = runtime_database
    scopes = _identity_fixture(engine)
    key = "enrichment.file_metadata"
    invocation = hashlib.sha256(b"multi-source").hexdigest()
    run = PipelineRunRepository(engine).begin_run(
        key,
        PipelineKind.ENRICHMENT,
        invocation_fingerprint=invocation,
    )
    asset_id, immich_source = _insert_asset(
        engine,
        provider="immich",
        scope_id=scopes["immich"].id,
        label="multi-source-immich",
    )
    nextcloud_source = _insert_source(
        engine,
        asset_id=asset_id,
        provider="nextcloud",
        scope_id=scopes["nextcloud"].id,
        label="multi-source-nextcloud",
    )
    batch = ObservationBatch(
        format_resource_ref(asset_id),
        GeneratorIdentity(*GENERATORS[key]),
        ("media.camera_make",),
        hashlib.sha256(b"multi-source-input").hexdigest(),
        (),
    )
    PostgreSQLObservationRepository(
        engine,
        effect_run_id=run.id,
        effect_pipeline_key=key,
    ).publish(
        batch,
        completed_at=NOW,
        effect_sources=(nextcloud_source, immich_source),
    )
    with engine.connect() as connection:
        source_ids, fingerprint = connection.execute(text(
            "SELECT source_ids,source_binding_fingerprint "
            "FROM pipeline_run_effect_receipts WHERE pipeline_run_id=:id"
        ), {"id": run.id}).one()
    assert source_ids == sorted(
        [UUID(nextcloud_source.source_id), UUID(immich_source.source_id)],
        key=str,
    )
    assert len(fingerprint) == 64


def test_runtime_proof_rejects_phase_a_route_mismatch(runtime_database) -> None:
    engine, database_url = runtime_database
    scopes = _identity_fixture(engine)
    router, phase_a = _database_bindings(
        engine,
        database_url,
        route_fingerprint_override="d" * 64,
    )
    service_results = _publish_six(engine, scopes, phase_a)
    with pytest.raises(WP8RuntimeProofError):
        WP8RuntimeProofReader(
            router=router,
            engine=engine,
            principal_ref=PRINCIPAL,
            phase_a_evidence=phase_a,
        ).collect(
            service_results,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )


def test_runtime_proof_normalizes_secret_bearing_router_error(runtime_database) -> None:
    engine, database_url = runtime_database
    _identity_fixture(engine)
    _, phase_a = _database_bindings(engine, database_url)

    class FailingRouter:
        def resolve(self, _principal):
            raise RuntimeError("password=never-emit-this-value")

    service_results = tuple(
        _service_result(
            key,
            hashlib.sha256(f"safe-error:{key}".encode()).hexdigest(),
            phase_a,
        )
        for key in WP8_CANONICAL_PIPELINE_KEYS
    )
    with pytest.raises(WP8RuntimeProofError) as captured:
        WP8RuntimeProofReader(
            router=FailingRouter(),
            engine=engine,
            principal_ref=PRINCIPAL,
            phase_a_evidence=phase_a,
        ).collect(
            service_results,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )
    assert str(captured.value) == WP8RuntimeProofError.code
    assert "never-emit" not in str(captured.value)
    assert captured.value.__suppress_context__ is True
    assert "never-emit" not in "".join(traceback.format_exception(
        captured.type,
        captured.value,
        captured.tb,
    ))

    class FailingEngine:
        url = engine.url

        def execution_options(self, **_kwargs):
            raise RuntimeError(
                "postgresql://principal:never-emit-this-password@invalid/db"
            )

    with pytest.raises(WP8RuntimeProofError) as captured:
        WP8RuntimeProofReader(
            router=_database_bindings(engine, database_url)[0],
            engine=FailingEngine(),
            principal_ref=PRINCIPAL,
            phase_a_evidence=phase_a,
        ).collect(
            service_results,
            rehearsal_operation_id=OPERATION,
            runtime_boundary_fingerprint=H3,
        )
    assert str(captured.value) == WP8RuntimeProofError.code
    assert "never-emit" not in str(captured.value)
    assert captured.value.__suppress_context__ is True
    assert "never-emit" not in "".join(traceback.format_exception(
        captured.type,
        captured.value,
        captured.tb,
    ))
