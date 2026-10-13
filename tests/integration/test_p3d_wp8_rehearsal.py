"""Real isolated PG16, synthetic manager/filesystem. NOT real-systemd proof."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
from types import SimpleNamespace

import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from pdi.data_status import PipelineKind, PipelineRunRepository
from pdi.observation import (PostgreSQLObservationRepository, ObservationBatch,
    GeneratorIdentity, StatementDraft, TypedStatementValue, StatementValueType,
    Evidence, EvidenceSourceKind)
from pdi.query import format_resource_ref
from pdi.production_ops import p3d_wp8_contracts as c
from pdi.production_ops import p3d_wp8_preflight as a
from pdi.production_ops.p3d_wp8_operation_store import OperationStore
from pdi.production_ops.p3d_wp8_rehearsal import _Coordinator, _Adapters
from pdi.production_ops.p3d_wp8_runtime_proof import WP8RuntimeProofReader
from pdi.production_ops.p3d_wp8_postflight import PostflightReader
from tests.test_p3d_wp8_contracts import OPERATION, timestamp
from tests.test_p3d_wp8_operation_store import install_inputs
from tests.test_p3d_wp8_rehearsal import SyntheticBackend, result
from tests.integration.test_p3d_wp8_runtime_proof import (
    runtime_database, _identity_fixture, _insert_asset, _database_bindings,
    NOW, PRINCIPAL, GENERATORS,
)


def _setup(tmp_path, runtime_database):
    engine, url = runtime_database
    with engine.connect() as connection:
        assert connection.scalar(text("SHOW server_version_num")).startswith("16")
    scopes = _identity_fixture(engine)
    assets = {}
    for index, key in enumerate(c.WP8_CANONICAL_PIPELINE_KEYS):
        provider = "nextcloud" if key.startswith("enrichment.nextcloud") else "immich"
        assets[key] = _insert_asset(engine, provider=provider, scope_id=scopes[provider].id, label=f"closure-{index}")
    with engine.begin() as connection:
        for scope in scopes.values():
            connection.execute(text("INSERT INTO observation_scope_sync_state "
                "(observation_scope_id,mechanism,checkpoint,version,reconciliation_required,created_at,updated_at) "
                "VALUES (:scope,'synthetic','ready',0,false,:now,:now)"), {"scope": scope.id, "now": NOW})
    router, evidence = _database_bindings(engine, url)
    configuration = SimpleNamespace(router=router)
    def observe():
        db = a._project_database(configuration, PRINCIPAL, engine_factory=lambda _: engine)
        mapping = evidence.invariant_baseline.to_mapping()
        mapping.update(schema_fingerprint=db.schema, principal_route_fingerprint=db.route,
            db_identity_fingerprint=db.identity, provider_identity_fingerprint=db.providers,
            enabled_scope_fingerprint=db.enabled_scopes, source_identity_fingerprint=db.sources,
            sync_state_fingerprint=db.sync, alembic_revision=db.revision)
        return c.WP8InvariantSnapshotV1.from_mapping(mapping)
    # Rebuild through the frozen constructor, never rehash an invalid binding.
    baseline = observe()
    evidence = c.WP8PhaseAEvidenceV1.build(candidate_sha=evidence.candidate_sha, rollback_source_sha=evidence.rollback_source_sha,
        gate_a_operation_id=evidence.gate_a_operation_id, gate_a_authority_binding_fingerprint=evidence.gate_a_authority_binding_fingerprint,
        gate_b_operation_id=evidence.gate_b_operation_id, gate_b_authority_binding_fingerprint=evidence.gate_b_authority_binding_fingerprint,
        gate_c_operation_id=evidence.gate_c_operation_id, gate_c_marker_fingerprint=evidence.gate_c_marker_fingerprint,
        gate_c_authority_binding_fingerprint=evidence.gate_c_authority_binding_fingerprint,
        wp6_context_fingerprint=evidence.wp6_context_fingerprint, db_identity_fingerprint=evidence.db_identity_fingerprint,
        enabled_scope_count=evidence.enabled_scope_count, enabled_scope_fingerprint=evidence.enabled_scope_fingerprint,
        unit_profile_asset_fingerprint=evidence.unit_profile_asset_fingerprint, p3c_state_fingerprint=evidence.p3c_state_fingerprint,
        p3c_systemd_fingerprint=evidence.p3c_systemd_fingerprint, protected_environment_fingerprint=evidence.protected_environment_fingerprint,
        registry_fingerprint=evidence.registry_fingerprint, invariant_baseline=baseline)
    root = tmp_path / "synthetic-protected-operation"
    install_inputs(root, evidence=evidence)
    store = OperationStore._for_tests(root)
    class Backend(SyntheticBackend):
        def start_service(self, key):
            self.starts.append(key)
            returned = result(key, self.evidence)
            run_repo = PipelineRunRepository(engine)
            run = run_repo.begin_run(key, PipelineKind.ENRICHMENT, started_at=NOW,
                invocation_fingerprint=returned.execution_attestation.invocation_fingerprint)
            asset, source = assets[key]
            PostgreSQLObservationRepository(engine, effect_run_id=run.id, effect_pipeline_key=key).publish(
                ObservationBatch(format_resource_ref(asset), GeneratorIdentity(*GENERATORS[key]), ("media.camera_make",),
                    hashlib.sha256(key.encode()).hexdigest(), (StatementDraft("media.camera_make",
                        TypedStatementValue(StatementValueType.STRING, "synthetic-content"),
                        Evidence(EvidenceSourceKind.PROVIDER_METADATA, "synthetic.closure")),)),
                completed_at=NOW + timedelta(seconds=1), effect_sources=(source,))
            run_repo.complete_run(run.id, finished_at=NOW + timedelta(seconds=2))
            self.results.append(returned)
            return returned
    backend = Backend(evidence)
    reader = WP8RuntimeProofReader(router=router, engine=engine, principal_ref=PRINCIPAL, phase_a_evidence=evidence)
    post = PostflightReader(evidence=evidence, router=router, engine=engine, principal=PRINCIPAL, observe_final=observe, backend=backend)
    coordinator = _Coordinator(store, _Adapters(backend, lambda: evidence, lambda: "EXACT_CANDIDATE", reader, post),
                               clock=lambda: timestamp(4))
    return coordinator, backend, engine, post


def test_pg16_same_call_receipts_protected_journal_full_closure(tmp_path, runtime_database):
    coordinator, backend, engine, post = _setup(tmp_path, runtime_database)
    before = post.capture_business()
    outcome = coordinator.run(OPERATION)
    assert outcome.status == "REVIEWABLE_COMPLETE", outcome
    assert len(backend.starts) == 6 and backend.stops == 1
    state, events, refs = coordinator.store.load(OPERATION)
    runtime = coordinator.store.proof(OPERATION, "runtime", refs["runtime"])
    assert runtime.runtime_pipeline_coverage == "6/6"
    assert runtime.runtime_boundary_fingerprint == coordinator.store.boundary(OPERATION)[1]
    assert before.fingerprint == coordinator.store.boundary(OPERATION)[0]["business_fingerprint"]
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM pipeline_runs")) == 6
        assert connection.scalar(text("SELECT count(*) FROM pipeline_run_effect_receipts")) == 6
    with pytest.raises(c.WP8ContractError):
        coordinator.run(OPERATION)
    assert len(backend.starts) == 6


def test_pg16_read_only_connection_rejects_insert(tmp_path, runtime_database):
    coordinator, backend, engine, post = _setup(tmp_path, runtime_database)
    with pytest.raises(DBAPIError) as rejected:
        with a._baseline_connection(engine) as connection:
            assert connection.scalar(text("SHOW transaction_read_only")) == "on"
            assert connection.scalar(text("SHOW transaction_isolation")) == "repeatable read"
            connection.execute(text("INSERT INTO alembic_version(version_num) VALUES ('synthetic-denied')"))
    assert rejected.value.orig.sqlstate == "25006"
    assert backend.starts == []


@pytest.mark.parametrize("attack", ("unreceipted", "source", "payload", "old_run", "route"))
def test_pg16_false_business_closure_never_completes(tmp_path, runtime_database, attack):
    coordinator, backend, engine, post = _setup(tmp_path, runtime_database)
    if attack == "old_run":
        previous = {key: backend.start_service(key) for key in c.WP8_CANONICAL_PIPELINE_KEYS}
        backend.starts.clear()
        backend.results.clear()
        def replay_old(key):
            backend.starts.append(key)
            backend.results.append(previous[key])
            return previous[key]
        backend.start_service = replay_old
    original = coordinator.adapters.runtime.collect
    def inject(results, **kwargs):
        proof = original(results, **kwargs)
        if attack == "route":
            post.principal = "foreign-principal"
        elif attack == "old_run":
            pass  # The protected pre-boundary already contains all these runs.
        else:
            with engine.begin() as connection:
                if attack == "source":
                    connection.execute(text("UPDATE asset_sources SET external_id=external_id||'-changed'"))
                elif attack == "payload":
                    connection.execute(text("UPDATE resource_statements SET string_value='tampered'"))
                else:
                    connection.execute(text("INSERT INTO resource_statements SELECT "
                        "gen_random_uuid(),subject_asset_id,predicate,value_type,string_value,integer_value,float_value,boolean_value,"
                        "datetime_value,resource_value_asset_id,generator_type,generator_name,generator_version,source_kind,"
                        "source_locator,confidence,created_at,is_current FROM resource_statements LIMIT 1"))
        return proof
    coordinator.adapters = replace(coordinator.adapters, runtime=SimpleNamespace(collect=inject))
    assert coordinator.run(OPERATION).status != "REVIEWABLE_COMPLETE"
    assert backend.stops == 1
