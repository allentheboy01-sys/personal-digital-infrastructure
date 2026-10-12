from datetime import UTC, datetime
import hashlib
from types import SimpleNamespace
from uuid import UUID

import pytest

from pdi.data_status import PipelineKind
from pdi.data_status.repository import (
    PipelineRunLifecycleError,
    PipelineRunRepository,
)
from pdi.observation.models import GeneratorIdentity
from pdi.observation.postgres import (
    PostgreSQLObservationRepository,
    _enrichment_state_fingerprint,
    _receipt_fingerprint,
    _receipt_fragment_payload,
    _source_binding_fingerprint,
    _statement_effect_fingerprint,
)
from pdi.production_ops import enrichment as entrypoint


NOW = datetime(2026, 10, 12, 3, 4, 5, 678901, tzinfo=UTC)
RUN_ID = UUID("11111111-2222-4333-8444-555555555555")
ASSET_ID = UUID("21111111-2222-4333-8444-555555555555")
RECEIPT_ID = UUID("31111111-2222-4333-8444-555555555555")
STATEMENT_ID = UUID("41111111-2222-4333-8444-555555555555")
SOURCE_ID = UUID("51111111-2222-4333-8444-555555555555")
SCOPE_ID = UUID("61111111-2222-4333-8444-555555555555")
INSTANCE_ID = UUID("71111111-2222-4333-8444-555555555555")


def test_systemd_invocation_is_digest_only_and_absence_is_unqualified() -> None:
    raw = "a" * 32
    assert entrypoint._systemd_invocation_fingerprint({}) is None
    assert entrypoint._systemd_invocation_fingerprint({"INVOCATION_ID": raw}) == (
        hashlib.sha256(raw.encode("ascii")).hexdigest()
    )
    with pytest.raises(ValueError, match="invalid systemd invocation identity"):
        entrypoint._systemd_invocation_fingerprint({"INVOCATION_ID": "unsafe"})


def test_entrypoint_passes_invocation_digest_without_exposing_raw_value(
    monkeypatch,
    capsys,
) -> None:
    raw = "b" * 32
    expected = hashlib.sha256(raw.encode("ascii")).hexdigest()
    calls = []

    class Runner:
        def run(self, principal, pipeline, **kwargs):
            calls.append((principal, pipeline, kwargs))
            return 0

    monkeypatch.setattr(entrypoint, "load_scoped_operator_configuration", lambda _: object())
    monkeypatch.setattr(entrypoint, "build_executable_scoped_runner", lambda _: Runner())
    monkeypatch.setattr(entrypoint.os, "environ", {"INVOCATION_ID": raw})
    assert entrypoint.main([
        "--config", "/synthetic/config.toml",
        "--principal-ref", "synthetic-a",
        "--pipeline-key", "enrichment.file_metadata",
    ]) == 0
    assert calls == [(
        "synthetic-a",
        "enrichment.file_metadata",
        {"lock_timeout": 300, "invocation_fingerprint": expected},
    )]
    assert raw not in capsys.readouterr().out


def test_malformed_invocation_fails_with_fixed_safe_output(
    monkeypatch,
    capsys,
) -> None:
    raw = "not-a-systemd-invocation-token"
    monkeypatch.setattr(entrypoint, "load_scoped_operator_configuration", lambda _: object())
    monkeypatch.setattr(
        entrypoint,
        "build_executable_scoped_runner",
        lambda _: pytest.fail("runner must not be built before identity validation"),
    )
    monkeypatch.setattr(entrypoint.os, "environ", {"INVOCATION_ID": raw})
    assert entrypoint.main([
        "--config", "/synthetic/config.toml",
        "--principal-ref", "synthetic-a",
        "--pipeline-key", "enrichment.file_metadata",
    ]) == 1
    output = capsys.readouterr().out
    assert output == "PDI_SCOPED_ENRICHMENT=FAIL\n"
    assert raw not in output


@pytest.mark.parametrize("value", ["A" * 64, "a" * 63, "a" * 65, 7])
def test_pipeline_run_repository_rejects_noncanonical_invocation_digest(value) -> None:
    repository = PipelineRunRepository(object())
    with pytest.raises(PipelineRunLifecycleError):
        repository.begin_run(
            "enrichment.file_metadata",
            PipelineKind.ENRICHMENT,
            invocation_fingerprint=value,
        )


def test_receipt_fingerprint_is_canonical_and_contains_no_business_value() -> None:
    generator = GeneratorIdentity("deterministic_extractor", "file_metadata", "1")
    enrichment = _enrichment_state_fingerprint(
        asset_id=ASSET_ID,
        generator=generator,
        input_fingerprint="a" * 64,
        completed_at=NOW,
    )
    payload = _receipt_fragment_payload(
        receipt_id=RECEIPT_ID,
        pipeline_run_id=RUN_ID,
        pipeline_key="enrichment.file_metadata",
        asset_id=ASSET_ID,
        generator=generator,
        input_fingerprint="a" * 64,
        completed_at=NOW,
        created_statement_ids=(STATEMENT_ID,),
        deactivated_statement_ids=(),
        current_statement_ids=(STATEMENT_ID,),
        source_ids=(SOURCE_ID,),
        source_binding_fingerprint="c" * 64,
        enrichment_state_fingerprint=enrichment,
        statement_effect_fingerprint="b" * 64,
    )
    assert _receipt_fingerprint(payload) == _receipt_fingerprint(dict(reversed(tuple(payload.items()))))
    assert set(payload) == {
        "version", "receipt_id", "pipeline_run_id", "pipeline_key",
        "subject_asset_id", "generator_type", "generator_name",
        "generator_version", "input_fingerprint", "completed_at",
        "created_statement_ids", "deactivated_statement_ids",
        "current_statement_ids", "source_ids", "statement_write_count",
        "deactivated_statement_count", "current_statement_count",
        "source_binding_fingerprint",
        "enrichment_state_fingerprint",
        "statement_effect_fingerprint",
    }


def test_statement_effect_fingerprint_commits_to_semantic_content() -> None:
    base = {
        "id": STATEMENT_ID,
        "subject_asset_id": ASSET_ID,
        "predicate": "media.camera_make",
        "value_type": "string",
        "string_value": "synthetic-a",
        "integer_value": None,
        "float_value": None,
        "boolean_value": None,
        "datetime_value": None,
        "resource_value_asset_id": None,
        "generator_type": "deterministic_extractor",
        "generator_name": "file_metadata",
        "generator_version": "1",
        "source_kind": "provider_metadata",
        "source_locator": "synthetic.proof",
        "confidence": 1.0,
        "created_at": NOW,
        "is_current": True,
    }
    changed = dict(base, string_value="synthetic-b")
    first = _statement_effect_fingerprint((base,))
    second = _statement_effect_fingerprint((changed,))
    assert len(first) == 64
    assert first != second
    assert "synthetic-a" not in first


def test_source_binding_fingerprint_commits_exact_scope_and_provider() -> None:
    base = {
        "source_id": SOURCE_ID,
        "provider": "nextcloud",
        "observation_scope_id": SCOPE_ID,
        "provider_instance_id": INSTANCE_ID,
        "provider_account_id": None,
    }
    changed = dict(base, provider="immich")
    first = _source_binding_fingerprint((base,))
    second = _source_binding_fingerprint((changed,))
    assert len(first) == 64
    assert first != second


def test_receipt_repository_context_is_all_or_nothing() -> None:
    with pytest.raises(ValueError, match="context must be complete"):
        PostgreSQLObservationRepository(
            SimpleNamespace(), effect_run_id=RUN_ID
        )
    with pytest.raises(ValueError, match="pipeline key"):
        PostgreSQLObservationRepository(
            SimpleNamespace(),
            effect_run_id=RUN_ID,
            effect_pipeline_key="not valid",
        )
