"""All paths/approval records here are synthetic, not production evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from pdi.production_ops import p3d_wp8_contracts as c
from pdi.production_ops.p3d_preparation_contracts import canonical_json_bytes
from pdi.production_ops.p3d_wp8_operation_store import OperationStore
from tests.test_p3d_wp8_contracts import phase_a, timestamp, OPERATION, NORMAL_PHASES


def write(path, value):
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    path.chmod(0o600)


def install_inputs(root, *, evidence=None, operation=OPERATION):
    root.mkdir(mode=0o700)
    approvals = root / "approvals"
    approvals.mkdir(mode=0o700)
    selected = approvals / operation
    selected.mkdir(mode=0o700)
    evidence = evidence or phase_a()
    record = b"Synthetic independent review fixture. Not production approval.\n"
    reviewed = c.WP8AReviewResultV1.build(evidence, reviewed_at_utc=timestamp(1),
                                         review_record_sha256=hashlib.sha256(record).hexdigest())
    authorized = c.WP8RehearsalAuthorizationV1.build(evidence, reviewed, rehearsal_operation_id=operation,
        issued_at_utc=timestamp(2), not_before_utc=timestamp(3), expires_at_utc=timestamp(59))
    for name, value in (("phase-a.json", evidence), ("a-review.json", reviewed), ("b-authorization.json", authorized)):
        write(selected / name, value.to_mapping())
    (selected / "review-record").write_bytes(record)
    (selected / "review-record").chmod(0o600)
    return evidence, reviewed, authorized


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "protected"
    install_inputs(root)
    return OperationStore._for_tests(root)


def test_inputs_are_protected_and_review_bytes_bound(store):
    assert store.inputs(OPERATION)[0] == phase_a()
    record = store.root / "approvals" / OPERATION / "review-record"
    record.write_bytes(b"changed")
    with pytest.raises(c.WP8ContractError):
        store.inputs(OPERATION)


@pytest.mark.parametrize("name", ("phase-a.json", "a-review.json", "b-authorization.json", "review-record"))
def test_approval_permissions_and_symlinks_rejected(store, name):
    path = store.root / "approvals" / OPERATION / name
    path.chmod(0o644)
    with pytest.raises(c.WP8ContractError):
        store.inputs(OPERATION)
    path.chmod(0o600)
    source = path.with_name(name + ".original")
    path.rename(source)
    path.symlink_to(source)
    with pytest.raises(c.WP8ContractError):
        store.inputs(OPERATION)


def test_wrong_owner_rejected(store, monkeypatch):
    from dataclasses import replace
    store._policy = replace(store._policy, uid=os.geteuid() + 1)
    with pytest.raises(c.WP8ContractError):
        store.inputs(OPERATION)


@pytest.mark.parametrize("when", (timestamp(0), timestamp(59)))
def test_window_rejects_without_consumption(store, when):
    with store.serialized():
        with pytest.raises(c.WP8ContractError):
            store.begin(OPERATION, at_utc=when)
    assert not (store.root / "consumptions").exists()


def test_single_use_and_no_unlocked_persistence(store):
    with pytest.raises(c.WP8ContractError):
        store.begin(OPERATION, at_utc=timestamp(4))
    with store.serialized():
        state = store.begin(OPERATION, at_utc=timestamp(4))
        assert store.load(OPERATION)[0] == state
        with pytest.raises(c.WP8ContractError):
            store.begin(OPERATION, at_utc=timestamp(4))
    assert len(list((store.root / "consumptions").iterdir())) == 1


def test_consumption_survives_crash_before_initial_commit(store, monkeypatch):
    def crash(*args):
        raise OSError("synthetic crash")
    monkeypatch.setattr(store, "_commit", crash)
    with store.serialized():
        with pytest.raises(OSError):
            store.begin(OPERATION, at_utc=timestamp(4))
        with pytest.raises(c.WP8ContractError) as rejected:
            store.begin(OPERATION, at_utc=timestamp(4))
        assert rejected.value.code is c.WP8FailureCode.AUTHORIZATION_REPLAY


def test_commit_is_authority_missing_projection_rebuilds(store, monkeypatch):
    with store.serialized():
        store.begin(OPERATION, at_utc=timestamp(4))
        original = store._put
        def fail_projection(path, value):
            if path.name == "state-000001.json":
                raise OSError("synthetic projection crash")
            return original(path, value)
        monkeypatch.setattr(store, "_put", fail_projection)
        state = store.advance(OPERATION, c.WP8RehearsalPhase.AUTHORIZATION_VERIFIED, at_utc=timestamp(4))
        assert store.load(OPERATION)[0] == state
        assert not (store._operation(OPERATION) / "state-000001.json").exists()
        monkeypatch.setattr(store, "_put", original)
        assert store.load(OPERATION, rebuild=True)[0] == state
        assert (store._operation(OPERATION) / "state-000001.json").exists()


@pytest.mark.parametrize("damage", ("gap", "partial", "projection", "authority", "extra"))
def test_torn_conflicting_and_rehashed_foreign_frames_fail(store, damage):
    with store.serialized():
        store.begin(OPERATION, at_utc=timestamp(4))
        store.advance(OPERATION, c.WP8RehearsalPhase.AUTHORIZATION_VERIFIED, at_utc=timestamp(4))
        path = store._operation(OPERATION) / "commit-000001.json"
        if damage == "gap":
            path.rename(path.with_name("commit-000002.json"))
        elif damage == "partial":
            path.write_bytes(b'{"version":')
        elif damage == "projection":
            write(path.with_name("state-000001.json"), {})
        else:
            value = json.loads(path.read_bytes())
            if damage == "extra":
                value["unknown"] = True
            else:
                value["state"]["authorization_fingerprint"] = "f" * 64
            write(path, value)
        with pytest.raises((c.WP8ContractError, ValueError)):
            store.load(OPERATION)


def test_contending_store_and_legacy_lock_excluded(store):
    import fcntl
    lock = store.root / "legacy.lock"
    write(lock, {})
    contender = OperationStore._for_tests(store.root, locks=(lock,))
    with store.serialized():
        with pytest.raises(c.WP8ContractError):
            with contender.serialized():
                pytest.fail("lock collision accepted")
    with lock.open("r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(c.WP8ContractError):
            with contender.serialized():
                pytest.fail("legacy collision accepted")
    with contender.serialized():
        pass


def test_unknown_legacy_lock_is_not_created(store):
    missing = store.root / "missing.lock"
    contender = OperationStore._for_tests(store.root, locks=(missing,))
    with pytest.raises((OSError, c.WP8ContractError)):
        with contender.serialized():
            pass
    assert not missing.exists()


def test_production_has_fixed_root_and_exact_four_legacy_control_locks():
    from pdi.production_ops.p3d_wp8_operation_store import _ROOT, _LOCKS
    assert str(_ROOT) == "/var/lib/pdi-p3d-wp8"
    assert len(_LOCKS) == 4
    assert all("sync.lock" not in str(path) for path in _LOCKS)
