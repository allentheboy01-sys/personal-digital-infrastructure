from __future__ import annotations

import ast
from dataclasses import replace
import inspect
from pathlib import Path
from uuid import UUID

import pytest

from pdi.production_ops import p3d_wp8_postflight as module
from pdi.production_ops.p3d_wp8_contracts import WP8ContractError


def row(table, identity, value, *, stable=None):
    return table, module._digest_value(identity), module._digest_value(value), module._digest_value(value if stable is None else stable)


def boundary(*rows):
    return module._BusinessBoundary(tuple(sorted(rows)))


def receipt():
    return {"id": UUID(int=2), "pipeline_run_id": UUID(int=1), "subject_asset_id": UUID(int=3),
            "generator_type": "deterministic_extractor", "generator_name": "file_metadata", "generator_version": "1",
            "created_statement_ids": [UUID(int=4)], "deactivated_statement_ids": [UUID(int=5)]}


def allowed_rows():
    r = receipt()
    return (row("pipeline_runs", str(r["pipeline_run_id"]), "completed"),
            row("pipeline_run_effect_receipts", str(r["id"]), "receipt"),
            row("resource_statements", str(UUID(int=4)), "new"),
            row("resource_statements", str(UUID(int=5)), "inactive", stable="original"),
            row("resource_enrichments", [str(r["subject_asset_id"]), r["generator_type"], r["generator_name"], "1"], "completed"))


def test_exact_receipted_changes_allowed_and_boundary_contains_hashes_only():
    before = boundary(row("resource_statements", str(UUID(int=5)), "active", stable="original"))
    after = boundary(*allowed_rows())
    module._verify_business_diff(before, after, receipts=(receipt(),), run_ids={str(UUID(int=1))})
    assert "original" not in str(before.to_mapping())
    assert before.fingerprint == boundary(*before.rows).fingerprint


@pytest.mark.parametrize("attack", ("unreceipted_statement", "old_run", "wrong_run", "source_write", "delete", "old_payload", "old_receipt", "missing_run"))
def test_exhaustive_diff_rejects_unapproved_or_historical_changes(attack):
    old = row("resource_statements", str(UUID(int=5)), "active", stable="original")
    before, rows, receipts, ids = boundary(old), list(allowed_rows()), [receipt()], {str(UUID(int=1))}
    if attack == "unreceipted_statement":
        rows.append(row("resource_statements", "foreign", "secret-content"))
    elif attack == "old_run":
        before = boundary(old, rows[0])
    elif attack == "wrong_run":
        ids = {str(UUID(int=9))}
    elif attack == "source_write":
        rows.append(row("asset_sources", "foreign", "unapproved"))
    elif attack == "delete":
        rows.pop(3)
    elif attack == "old_payload":
        rows[3] = row("resource_statements", str(UUID(int=5)), "inactive", stable="tamper")
    elif attack == "old_receipt":
        before = boundary(old, rows[1])
    elif attack == "missing_run":
        rows.pop(0)
    with pytest.raises(WP8ContractError):
        module._verify_business_diff(before, boundary(*rows), receipts=receipts, run_ids=ids)


def test_duplicate_row_identity_fails_closed():
    selected = row("assets", "asset", "one")
    with pytest.raises(WP8ContractError):
        module._verify_business_diff(boundary(selected, selected), boundary(selected), receipts=(), run_ids=set())


def test_postflight_is_read_only_and_does_not_copy_phase_a_to_after():
    tree = ast.parse(inspect.getsource(module))
    attrs = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not attrs & {"commit", "flush", "write_bytes", "write_text", "mkdir", "start_service", "stop_all_services", "run"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add":
            assert isinstance(node.func.value, ast.Name) and node.func.value.id in {"receipt_ids", "enrichment"}
    source = inspect.getsource(module._final_projection)
    assert "ProtectedPrerequisiteReader" not in source and "evidence.invariant_baseline" not in source
    assert "expected_source=inputs.candidate_sha" in source
    assert "_read_frozen_p3c_pass_state" in source


def test_postflight_reuses_frozen_read_only_validators_on_same_connection():
    source = inspect.getsource(module.PostflightReader.verify)
    assert "reader._verify_pipeline(connection, result)" in source
    assert "_capture_business(connection)" in source
    assert "reader.collect(" not in source
    assert source.count("with a._baseline_connection") == 1


@pytest.mark.parametrize("attack", (None, "active", "job", "missing", "before_manager", "after_manager"))
def test_final_service_facts_independently_require_same_manager_six_inactive(attack):
    from types import SimpleNamespace
    from pdi.production_ops.p3d_wp8_systemd import _ServiceState, _ServiceStates
    from pdi.production_ops.p3d_wp8_contracts import WP8_CANONICAL_PIPELINE_KEYS
    from tests.test_p3d_wp8_contracts import H1, H2
    states = tuple(_ServiceState(key, "INACTIVE") for key in WP8_CANONICAL_PIPELINE_KEYS)
    if attack == "active":
        states = (replace(states[0], state="NOT_CONFIRMED"), *states[1:])
    elif attack == "missing":
        states = states[:-1]
    calls = []
    def manager():
        calls.append(True)
        drift = attack == "before_manager" or (attack == "after_manager" and len(calls) > 1)
        return SimpleNamespace(fingerprint=H2 if drift else H1)
    def inactive():
        if attack == "job":
            raise WP8ContractError(module.c.WP8FailureCode.CLEANUP_FAILED)
        return _ServiceStates(states, "INACTIVE")
    backend = SimpleNamespace(manager_identity=manager, verify_all_services_inactive=inactive)
    reader = module.PostflightReader(evidence=None, router=None, engine=None, principal=None,
                                    observe_final=None, backend=backend)
    if attack is None:
        reader._verify_final_services(H1)
        assert len(calls) == 2
    else:
        with pytest.raises(WP8ContractError):
            reader._verify_final_services(H1)


@pytest.mark.parametrize("damage", ("raw", "unknown_table", "duplicate", "bool_version", "unknown_field"))
def test_business_boundary_parser_has_no_free_form_payloads(damage):
    from tests.test_p3d_wp8_contracts import H1
    value = module._BusinessBoundary((("assets", H1, H1, H1),)).to_mapping()
    if damage == "raw":
        value["rows"][0][2] = "arbitrary business payload"
    elif damage == "unknown_table":
        value["rows"][0][0] = "unknown"
    elif damage == "duplicate":
        value["rows"].append(value["rows"][0])
    elif damage == "bool_version":
        value["version"] = True
    else:
        value["extra"] = True
    with pytest.raises(WP8ContractError):
        module._BusinessBoundary.from_mapping(value)
