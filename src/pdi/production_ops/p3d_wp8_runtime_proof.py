"""Read-only WP8 Runtime Proof over invocation-bound effect receipts.

This module evaluates already-produced evidence. It does not authorize or start
services, contact Providers, mutate a database, persist operation state, or
reconstruct execution authority from a mapping or digest.
"""

from __future__ import annotations

from collections.abc import Sequence
from types import MappingProxyType
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.engine import Engine, make_url

from pdi.observation.models import GeneratorIdentity
from pdi.observation.postgres import (
    _EFFECT_PIPELINE_PROVIDERS,
    _enrichment_state_fingerprint,
    _receipt_fingerprint,
    _receipt_fragment_payload,
    _source_binding_fingerprint,
    _statement_effect_fingerprint,
)
from pdi.repository.orm.asset_source import AssetSourceORM
from pdi.repository.orm.blob import BlobORM
from pdi.repository.orm.observation import (
    ResourceEnrichmentORM,
    ResourceStatementORM,
)
from pdi.repository.orm.pipeline_run_effect_receipt import (
    PipelineRunEffectReceiptORM,
)
from pdi.repository.orm.provider_identity import (
    ObservationScopeORM,
    ProviderAccountORM,
    ProviderInstanceORM,
)
from pdi.scoped_enrichment_profiles import derive_enabled_scope_ids

from .contracts import HEAD as CANDIDATE_ALEMBIC_HEAD
from .p3d_evidence import context_fingerprint, postgresql_read_only_transaction
from .p3d_preparation_contracts import contract_fingerprint
from .p3d_wp8_preflight import _binding_fingerprint
from .p3d_wp8_contracts import (
    WP8_CANONICAL_PIPELINE_KEYS,
    WP8PhaseAEvidenceV1,
    WP8PipelineRunProofV1,
    WP8RuntimeLedgerProofV1,
)
from .p3d_wp8_systemd import _ExecutionAttestationV1, _Outcome, _ServiceResult


class WP8RuntimeProofError(RuntimeError):
    """Fixed, non-sensitive rejection from the read-only proof evaluator."""

    code = "P3D_WP8_RUNTIME_PROOF_REJECTED"

    def __init__(self) -> None:
        super().__init__(self.code)


def _fail() -> None:
    raise WP8RuntimeProofError() from None


_EXPECTED_GENERATORS = MappingProxyType({
    "enrichment.nextcloud_text": frozenset({
        ("deterministic_extractor", "nextcloud_text", "1"),
    }),
    "enrichment.nextcloud_documents": frozenset({
        ("deterministic_extractor", "nextcloud_pdf", "1"),
        ("deterministic_extractor", "nextcloud_odt", "1"),
        ("deterministic_extractor", "nextcloud_docx", "1"),
    }),
    "enrichment.file_metadata": frozenset({
        ("deterministic_extractor", "file_metadata", "1"),
    }),
    "enrichment.immich_geo": frozenset({
        ("deterministic_extractor", "immich_geo", "1"),
    }),
    "enrichment.immich_metadata": frozenset({
        ("deterministic_extractor", "immich_metadata", "1"),
    }),
    "enrichment.immich_ocr": frozenset({
        ("provider_native_ml", "immich_ocr", "1"),
    }),
})


class WP8RuntimeProofReader:
    """Build the frozen runtime-ledger proof in one routed read-only snapshot."""

    def __init__(
        self,
        *,
        router,
        engine: Engine,
        principal_ref: str,
        phase_a_evidence: WP8PhaseAEvidenceV1,
    ) -> None:
        if type(phase_a_evidence) is not WP8PhaseAEvidenceV1:
            _fail()
        self._router = router
        self._engine = engine
        self._principal_ref = principal_ref
        self._phase_a = phase_a_evidence

    def collect(
        self,
        service_results: Sequence[_ServiceResult],
        *,
        rehearsal_operation_id: str,
        runtime_boundary_fingerprint: str,
    ) -> WP8RuntimeLedgerProofV1:
        try:
            return self._collect(
                service_results,
                rehearsal_operation_id=rehearsal_operation_id,
                runtime_boundary_fingerprint=runtime_boundary_fingerprint,
            )
        except WP8RuntimeProofError:
            raise
        except Exception:
            _fail()

    def _collect(
        self,
        service_results: Sequence[_ServiceResult],
        *,
        rehearsal_operation_id: str,
        runtime_boundary_fingerprint: str,
    ) -> WP8RuntimeLedgerProofV1:
        results = tuple(service_results)
        if (
            len(results) != len(WP8_CANONICAL_PIPELINE_KEYS)
            or any(type(item) is not _ServiceResult for item in results)
            or tuple(item.pipeline_key for item in results)
            != WP8_CANONICAL_PIPELINE_KEYS
        ):
            _fail()
        binding = self._router.resolve(self._principal_ref)
        if make_url(binding.database_url) != make_url(self._engine.url):
            _fail()

        snapshot_engine = self._engine.execution_options(
            isolation_level="REPEATABLE READ"
        )
        with postgresql_read_only_transaction(snapshot_engine) as connection:
            if connection.scalar(text("SHOW transaction_isolation")) != "repeatable read":
                _fail()
            self._verify_routed_identity(connection, binding)
            records = tuple(
                self._verify_pipeline(connection, result)
                for result in results
            )
            fresh_ids = tuple(record.pipeline_run_id for record in records)
            rows = connection.execute(text(
                "SELECT id,pipeline_key,status,error_code,invocation_fingerprint "
                "FROM pipeline_runs WHERE id = ANY(:run_ids) ORDER BY pipeline_key,id"
            ), {"run_ids": [UUID(item) for item in fresh_ids]}).all()
            if (
                len(rows) != 6
                or len({row[0] for row in rows}) != 6
                or {row[1] for row in rows} != set(WP8_CANONICAL_PIPELINE_KEYS)
                or any(
                    row[2] != "completed"
                    or row[3] is not None
                    or row[4] is None
                    for row in rows
                )
            ):
                _fail()

        return WP8RuntimeLedgerProofV1.build(
            candidate_sha=self._phase_a.candidate_sha,
            phase_a_context_fingerprint=self._phase_a.phase_a_context_fingerprint,
            rehearsal_operation_id=rehearsal_operation_id,
            runtime_boundary_fingerprint=runtime_boundary_fingerprint,
            pipeline_records=records,
        )

    def _verify_routed_identity(self, connection, binding) -> None:
        revisions = list(connection.execute(text(
            "SELECT version_num FROM alembic_version"
        )))
        if [tuple(row) for row in revisions] != [(CANDIDATE_ALEMBIC_HEAD,)]:
            _fail()
        target = tuple(connection.execute(text(
            "SELECT current_database(),current_user,"
            "inet_server_addr()::text,inet_server_port()"
        )).one())
        if target[0] != make_url(binding.database_url).database:
            _fail()
        route = _binding_fingerprint("route", {
            "principal": self._principal_ref,
            "database_ref": binding.database_ref,
            "url_env": self._router.database_environment_key(
                self._principal_ref
            ),
            "connected_target": target,
        })
        if (
            route
            != self._phase_a.invariant_baseline.principal_route_fingerprint
        ):
            _fail()

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
        expected_providers = {
            "nextcloud", "immich", "gmail", "integration-test"
        }
        for instance_id, provider, _, enabled in instances:
            if provider not in expected_providers:
                continue
            related_scopes = [row for row in scopes if row[1] == instance_id]
            if len(related_scopes) != 1:
                _fail()
            scope = related_scopes[0]
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
        if {item["provider_type"] for item in identity_state} != expected_providers:
            _fail()
        identity = context_fingerprint({
            "principal": self._principal_ref,
            "database_ref": binding.database_ref,
            "scopes": scope_ids,
            "identity_state": sorted(
                identity_state, key=lambda item: item["provider_type"]
            ),
        })
        scope_fingerprint = contract_fingerprint({
            "principal_ref": self._principal_ref,
            "enabled_scope_ids": scope_ids,
        })
        invalid_source = connection.scalar(text(
            "SELECT EXISTS(SELECT 1 FROM asset_sources source "
            "LEFT JOIN observation_scopes scope "
            "ON scope.id=source.observation_scope_id "
            "LEFT JOIN provider_instances instance "
            "ON instance.id=scope.provider_instance_id "
            "WHERE scope.id IS NULL OR instance.id IS NULL "
            "OR source.provider<>instance.provider_type)"
        ))
        if (
            invalid_source
            or identity != self._phase_a.db_identity_fingerprint
            or len(scope_ids) != self._phase_a.enabled_scope_count
            or scope_fingerprint != self._phase_a.enabled_scope_fingerprint
        ):
            _fail()

    def _verify_pipeline(
        self,
        connection,
        result: _ServiceResult,
    ) -> WP8PipelineRunProofV1:
        attestation = result.execution_attestation
        if type(attestation) is not _ExecutionAttestationV1:
            _fail()
        attestation.validate_binding(
            self._phase_a,
            pipeline_key=result.pipeline_key,
        )
        if (
            result.outcome is not _Outcome.SUCCESS
            or result.final_state != "INACTIVE"
            or result.service_result_fingerprint
            != attestation.service_result_fingerprint
            or result.pipeline_key != attestation.pipeline_key
            or result.unit != attestation.unit
            or result.manager_fingerprint != attestation.manager_fingerprint
            or result.unit_contract_fingerprint
            != attestation.unit_contract_fingerprint
        ):
            _fail()
        runs = connection.execute(text(
            "SELECT id,pipeline_key,kind,status,finished_at,error_code,"
            "invocation_fingerprint FROM pipeline_runs "
            "WHERE invocation_fingerprint=:invocation"
        ), {"invocation": attestation.invocation_fingerprint}).all()
        if len(runs) != 1:
            _fail()
        run = runs[0]
        if (
            run.pipeline_key != result.pipeline_key
            or run.kind != "enrichment"
            or run.status != "completed"
            or run.finished_at is None
            or run.error_code is not None
            or run.invocation_fingerprint != attestation.invocation_fingerprint
        ):
            _fail()

        receipts = list(connection.execute(
            select(PipelineRunEffectReceiptORM.__table__)
            .where(PipelineRunEffectReceiptORM.pipeline_run_id == run.id)
            .order_by(PipelineRunEffectReceiptORM.id)
        ).mappings())
        if not receipts:
            _fail()
        fragments = tuple(
            self._verify_receipt(connection, run.id, result.pipeline_key, row)
            for row in receipts
        )
        effect_fingerprint = contract_fingerprint({
            "pipeline_key": result.pipeline_key,
            "pipeline_run_id": str(run.id),
            "invocation_fingerprint": attestation.invocation_fingerprint,
            "receipt_fragment_fingerprints": sorted(fragments),
        })
        return WP8PipelineRunProofV1.from_mapping({
            "pipeline_key": result.pipeline_key,
            "pipeline_run_id": str(run.id),
            "status": "COMPLETED",
            "service_result_fingerprint": result.service_result_fingerprint,
            "business_effect_fingerprint": effect_fingerprint,
            "completed_enrichment_count": len(receipts),
            "current_statement_count": sum(
                int(row["current_statement_count"]) for row in receipts
            ),
        })

    def _verify_receipt(
        self,
        connection,
        run_id: UUID,
        pipeline_key: str,
        row,
    ) -> str:
        receipt = row
        generator_tuple = (
            receipt["generator_type"],
            receipt["generator_name"],
            receipt["generator_version"],
        )
        if (
            receipt["version"] != 1
            or receipt["pipeline_run_id"] != run_id
            or receipt["pipeline_key"] != pipeline_key
            or generator_tuple not in _EXPECTED_GENERATORS[pipeline_key]
        ):
            _fail()
        created = tuple(receipt["created_statement_ids"])
        deactivated = tuple(receipt["deactivated_statement_ids"])
        current = tuple(receipt["current_statement_ids"])
        source_ids = tuple(receipt["source_ids"])
        if (
            tuple(sorted(created, key=str)) != created
            or tuple(sorted(deactivated, key=str)) != deactivated
            or tuple(sorted(current, key=str)) != current
            or len(set(created)) != len(created)
            or len(set(deactivated)) != len(deactivated)
            or len(set(current)) != len(current)
            or tuple(sorted(source_ids, key=str)) != source_ids
            or not source_ids
            or len(set(source_ids)) != len(source_ids)
            or set(created) & set(deactivated)
            or set(current) & set(deactivated)
            or receipt["statement_write_count"] != len(created)
            or receipt["deactivated_statement_count"] != len(deactivated)
            or receipt["current_statement_count"] != len(current)
            or (created and set(created) != set(current))
            or (not created and deactivated and current)
        ):
            _fail()

        generator = GeneratorIdentity(*generator_tuple)
        enrichment = connection.execute(
            select(ResourceEnrichmentORM.__table__).where(
                ResourceEnrichmentORM.subject_asset_id == receipt["subject_asset_id"],
                ResourceEnrichmentORM.extractor_type == receipt["generator_type"],
                ResourceEnrichmentORM.extractor_name == receipt["generator_name"],
                ResourceEnrichmentORM.extractor_version == receipt["generator_version"],
            )
        ).mappings().one_or_none()
        expected_enrichment = _enrichment_state_fingerprint(
            asset_id=receipt["subject_asset_id"],
            generator=generator,
            input_fingerprint=receipt["input_fingerprint"],
            completed_at=receipt["completed_at"],
        )
        if (
            enrichment is None
            or enrichment["status"] != "completed"
            or enrichment["input_fingerprint"] != receipt["input_fingerprint"]
            or enrichment["completed_at"] != receipt["completed_at"]
            or enrichment["updated_at"] != receipt["completed_at"]
            or enrichment["started_at"] is None
            or enrichment["started_at"] > receipt["completed_at"]
            or enrichment["error_code"] is not None
            or enrichment["error_message"] is not None
            or receipt["enrichment_state_fingerprint"] != expected_enrichment
        ):
            _fail()

        all_ids = tuple(sorted(set((*created, *deactivated, *current)), key=str))
        statement_rows = list(connection.execute(
            select(
                ResourceStatementORM.id,
                ResourceStatementORM.subject_asset_id,
                ResourceStatementORM.generator_type,
                ResourceStatementORM.generator_name,
                ResourceStatementORM.generator_version,
                ResourceStatementORM.predicate,
                ResourceStatementORM.value_type,
                ResourceStatementORM.string_value,
                ResourceStatementORM.integer_value,
                ResourceStatementORM.float_value,
                ResourceStatementORM.boolean_value,
                ResourceStatementORM.datetime_value,
                ResourceStatementORM.resource_value_asset_id,
                ResourceStatementORM.source_kind,
                ResourceStatementORM.source_locator,
                ResourceStatementORM.confidence,
                ResourceStatementORM.created_at,
                ResourceStatementORM.is_current,
            ).where(ResourceStatementORM.id.in_(all_ids))
        ).mappings()) if all_ids else []
        by_id = {item["id"]: item for item in statement_rows}
        if set(by_id) != set(all_ids):
            _fail()
        for statement_id, statement in by_id.items():
            if (
                statement["subject_asset_id"] != receipt["subject_asset_id"]
                or (
                    statement["generator_type"],
                    statement["generator_name"],
                    statement["generator_version"],
                ) != generator_tuple
                or (
                    statement_id in created
                    and statement["created_at"] != receipt["completed_at"]
                )
                or (
                    statement_id in deactivated
                    and statement["is_current"] is not False
                )
                or (
                    statement_id in current
                    and statement["is_current"] is not True
                )
            ):
                _fail()
        if (
            _statement_effect_fingerprint(tuple(statement_rows))
            != receipt["statement_effect_fingerprint"]
        ):
            _fail()

        expected_providers = _EFFECT_PIPELINE_PROVIDERS.get(pipeline_key)
        source_rows = list(connection.execute(
            select(
                AssetSourceORM.id.label("source_id"),
                AssetSourceORM.provider,
                AssetSourceORM.observation_scope_id,
                ObservationScopeORM.provider_instance_id,
                ObservationScopeORM.provider_account_id,
                BlobORM.asset_id,
                AssetSourceORM.is_active,
                AssetSourceORM.deleted_at,
                ObservationScopeORM.enabled.label("scope_enabled"),
                ProviderInstanceORM.provider_type.label("instance_provider"),
                ProviderInstanceORM.enabled.label("instance_enabled"),
                ProviderAccountORM.enabled.label("account_enabled"),
            )
            .join(BlobORM, BlobORM.id == AssetSourceORM.blob_id)
            .join(
                ObservationScopeORM,
                ObservationScopeORM.id == AssetSourceORM.observation_scope_id,
            )
            .join(
                ProviderInstanceORM,
                ProviderInstanceORM.id == ObservationScopeORM.provider_instance_id,
            )
            .outerjoin(
                ProviderAccountORM,
                ProviderAccountORM.id == ObservationScopeORM.provider_account_id,
            )
            .where(AssetSourceORM.id.in_(source_ids))
        ).mappings())
        if (
            expected_providers is None
            or {row["source_id"] for row in source_rows} != set(source_ids)
            or any(
                row["asset_id"] != receipt["subject_asset_id"]
                or row["provider"] not in expected_providers
                or row["instance_provider"] != row["provider"]
                or row["is_active"] is not True
                or row["deleted_at"] is not None
                or row["scope_enabled"] is not True
                or row["instance_enabled"] is not True
                or (
                    row["provider_account_id"] is not None
                    and row["account_enabled"] is not True
                )
                for row in source_rows
            )
            or _source_binding_fingerprint(source_rows)
            != receipt["source_binding_fingerprint"]
        ):
            _fail()

        payload = _receipt_fragment_payload(
            receipt_id=receipt["id"],
            pipeline_run_id=receipt["pipeline_run_id"],
            pipeline_key=receipt["pipeline_key"],
            asset_id=receipt["subject_asset_id"],
            generator=generator,
            input_fingerprint=receipt["input_fingerprint"],
            completed_at=receipt["completed_at"],
            created_statement_ids=created,
            deactivated_statement_ids=deactivated,
            current_statement_ids=current,
            source_ids=source_ids,
            source_binding_fingerprint=receipt["source_binding_fingerprint"],
            enrichment_state_fingerprint=receipt["enrichment_state_fingerprint"],
            statement_effect_fingerprint=receipt["statement_effect_fingerprint"],
        )
        if _receipt_fingerprint(payload) != receipt["fragment_fingerprint"]:
            _fail()
        return receipt["fragment_fingerprint"]


__all__ = ["WP8RuntimeProofError", "WP8RuntimeProofReader"]
