"""Independent final facts and exhaustive receipt-scoped business diff.

All database observations are read-only. Payloads are hashed in memory; only
identity/digest projections can be persisted. No Provider or mutation API.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import make_url

from . import p3d_wp8_contracts as c
from . import p3d_wp8_preflight as a
from .p3d_preparation_contracts import contract_fingerprint
from .p3d_wp8_runtime_proof import WP8RuntimeProofReader


def _fail():
    raise c.WP8ContractError(c.WP8FailureCode.INVARIANT_FAILED) from None


def _digest_value(value):
    # Private typed DB projection, not a free-form public contract serializer.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class _BusinessBoundary:
    # table, hashed primary key, complete row hash, immutable semantic hash
    rows: tuple[tuple[str, str, str, str], ...]

    @classmethod
    def from_mapping(cls, value):
        import re
        if (type(value) is not dict or set(value) != {"version", "domain", "rows"}
                or type(value["version"]) is not int or value["version"] != 1
                or value["domain"] != "WP8_BUSINESS_BOUNDARY" or type(value["rows"]) is not list):
            _fail()
        rows = value["rows"]
        if any(type(row) is not list or len(row) != 4 or row[0] not in a._PDI_RELATIONS
                or any(type(item) is not str or re.fullmatch(r"[a-f0-9]{64}", item) is None for item in row[1:]) for row in rows):
            _fail()
        result = cls(tuple(tuple(row) for row in rows))
        if result.rows != tuple(sorted(result.rows)) or len({row[:2] for row in result.rows}) != len(result.rows):
            _fail()
        return result

    @property
    def fingerprint(self):
        return contract_fingerprint({"version": 1, "domain": "WP8_BUSINESS_BOUNDARY", "rows": self.rows})

    def to_mapping(self):
        return {"version": 1, "domain": "WP8_BUSINESS_BOUNDARY", "rows": [list(row) for row in self.rows]}


def _row_key(table, row):
    if table == "resource_enrichments":
        key = [row[name] for name in ("subject_asset_id", "extractor_type", "extractor_name", "extractor_version")]
    elif "id" in row:
        key = row["id"]
    else:
        # Composite/no-id immutable tables are compared as complete multisets.
        key = row
    return _digest_value(key)


def _capture_business(connection):
    rows = []
    # Exact candidate schema domain: no caller-controlled SQL identifiers.
    for table in a._PDI_RELATIONS:
        for (raw,) in connection.execute(text(f'SELECT row_to_json(t)::text FROM public."{table}" t')):
            row = json.loads(raw)
            immutable = {key: value for key, value in row.items() if key != "is_current"} if table == "resource_statements" else row
            rows.append((table, _row_key(table, row), _digest_value(row), _digest_value(immutable)))
    return _BusinessBoundary(tuple(sorted(rows)))


def _verify_business_diff(before, after, *, receipts, run_ids):
    if type(before) is not _BusinessBoundary or type(after) is not _BusinessBoundary:
        _fail()
    def index(snapshot):
        values = {(table, key): (whole, stable) for table, key, whole, stable in snapshot.rows}
        if len(values) != len(snapshot.rows):
            _fail()
        return values
    old, new = index(before), index(after)
    created, deactivated, enrichment, receipt_ids = set(), set(), set(), set()
    for row in receipts:
        if str(row["pipeline_run_id"]) not in run_ids:
            _fail()
        receipt_ids.add(_digest_value(str(row["id"])))
        created.update(_digest_value(str(value)) for value in row["created_statement_ids"])
        deactivated.update(_digest_value(str(value)) for value in row["deactivated_statement_ids"])
        enrichment.add(_digest_value([str(row["subject_asset_id"]), row["generator_type"], row["generator_name"], row["generator_version"]]))
    allowed_new = {
        "pipeline_runs": {_digest_value(value) for value in run_ids},
        "pipeline_run_effect_receipts": receipt_ids,
        "resource_statements": created,
        "resource_enrichments": enrichment,
    }
    for identity in old.keys() | new.keys():
        table, key = identity
        if old.get(identity) == new.get(identity):
            continue
        if identity not in new:  # no deletion, including old runs/receipts
            _fail()
        if identity not in old:
            if key not in allowed_new.get(table, set()):
                _fail()
        elif table == "resource_statements":
            if key not in deactivated or old[identity][1] != new[identity][1]:
                _fail()
        elif table == "resource_enrichments":
            if key not in enrichment:
                _fail()
        else:
            _fail()
    # Bound runs/receipts must be fresh relative to the protected boundary.
    for table in ("pipeline_runs", "pipeline_run_effect_receipts"):
        if any((table, key) in old for key in allowed_new[table]):
            _fail()
        if {key for t, key in new.keys() - old.keys() if t == table} != allowed_new[table]:
            _fail()


def _final_projection(policy, inputs, systemd):
    """Recollect Gate/current/asset authority without Phase A's source-current rule."""
    from . import p3d_pre_rehearsal_evidence as wp6
    from .p3d_preparation_contracts import (PreparationGate, RollbackReleasePinV1,
        asset_installation_fingerprint, rollback_metadata_fingerprint,
        validate_rollback_release_pin, CANONICAL_P3D_INSTALL_PATH_MODES)
    from .p3d_rollback_qualification import parse_metadata
    from .p3d_inert_asset_install import _read_frozen_p3c_pass_state, InstallMode
    from .p3d_release_bootstrap import BootstrapPolicy, BootstrapMode, _verify_release_tree

    gates = [wp6._explicit_gate(policy, op, gate=gate, candidate=inputs.candidate_sha)
             for op, gate in ((inputs.gate_a_operation_id, PreparationGate.ROLLBACK_QUALIFICATION),
                              (inputs.gate_b_operation_id, PreparationGate.RELEASE_STAGING),
                              (inputs.gate_c_operation_id, PreparationGate.INERT_ASSET_INSTALL))]
    (ga, gae, ar), (gb, gbe, br), (gc, gce, cr) = gates
    marker, marker_hash, marker_snapshot, _ = wp6._read_gate_c_marker(policy, inputs)
    paths = {policy.environment: (0o600, policy.owner_gid), policy.registry: (0o640, policy.runtime_gid),
             policy.p3c_state: (0o600, policy.owner_gid), cr / "complete.json": (0o600, policy.owner_gid),
             ar / "p3d-pre-enrichment.env": (0o600, policy.owner_gid)}
    metadata_bytes = wp6._read_protected_bytes(ar / "p3d-pre-enrichment.env", policy=policy, mode=0o600, gid=policy.owner_gid)
    metadata = parse_metadata(metadata_bytes.payload)
    pin_path = ar / f"rollback-release-pin-{metadata.snapshot_id}.json"
    paths[pin_path] = (0o600, policy.owner_gid)
    for logical, mode in CANONICAL_P3D_INSTALL_PATH_MODES.items():
        paths[policy.physical(logical)] = (int(mode, 8), policy.owner_gid)
    for _, _, root in gates:
        for pattern in ("state-*.json", "journal-*.json"):
            for path in root.glob(pattern):
                paths[path] = (0o600, policy.owner_gid)
    def anchors():
        return tuple((str(path), wp6._read_protected_bytes(path, policy=policy, mode=mode, gid=gid).identity)
                     for path, (mode, gid) in sorted(paths.items()))
    before = anchors()
    configuration, principal, env, registry = wp6._load_protected_configuration(policy)
    pin = RollbackReleasePinV1.from_mapping(json.loads(wp6._read_protected_bytes(pin_path, policy=policy,
        mode=0o600, gid=policy.owner_gid).payload))
    validate_rollback_release_pin(metadata, pin)
    if (metadata.target_candidate_sha != inputs.candidate_sha or metadata.source_release_sha != inputs.rollback_source_cross_check
            or rollback_metadata_fingerprint(metadata) not in gae[-1].evidence_fingerprints
            or len(gbe[-1].evidence_fingerprints) != 1):
        _fail()
    release = policy.candidate_releases_root / inputs.candidate_sha
    bootstrap = BootstrapPolicy(mode=BootstrapMode.PRODUCTION if policy.mode is InstallMode.PRODUCTION else BootstrapMode.QUALIFICATION,
        trust_root=policy.root, filesystem_owner_uid=policy.owner_uid, filesystem_owner_gid=policy.owner_gid,
        runtime_uid=policy.runtime_uid, runtime_gid=policy.runtime_gid,
        expected_authority_class="PRODUCTION_RELEASE" if policy.mode is InstallMode.PRODUCTION else "QUALIFICATION_ONLY",
        approved_external_runtime_roots=(Path("/usr"),))
    release_hash = _verify_release_tree(release, candidate=inputs.candidate_sha, policy=bootstrap,
        approved_python=(release / ".venv/bin/python").resolve(strict=True), home=cr / "home")
    if release_hash != gbe[-1].evidence_fingerprints[0]:
        _fail()
    wp6._current_target(policy, expected_source=inputs.candidate_sha)
    p3c = _read_frozen_p3c_pass_state(policy.p3c_state, policy=policy,
        expected_sha=metadata.source_release_sha, expected_context=metadata.p3c_context_fingerprint)
    live = systemd.snapshot(post_install=True)
    assets = asset_installation_fingerprint(wp6._fresh_installed_manifest(policy))
    if not live.p3d_quiet or registry.sha256 != marker.registry_fingerprint or assets != marker.unit_profile_asset_fingerprint or live.p3c_fingerprint != marker.p3c_systemd_state_after_fingerprint:
        _fail()
    writers, enrichments = a._legacy_states(systemd)
    db = a._project_database(configuration, principal)
    baseline = c.WP8InvariantSnapshotV1.from_mapping({
        "version": 1, "schema_fingerprint": db.schema, "migration_tree_fingerprint": a._migration_fingerprint(policy, inputs.candidate_sha),
        "alembic_revision": db.revision, "principal_route_fingerprint": db.route, "db_identity_fingerprint": db.identity,
        "provider_identity_fingerprint": db.providers, "enabled_scope_fingerprint": db.enabled_scopes,
        "source_identity_fingerprint": db.sources, "sync_state_fingerprint": db.sync,
        "protected_environment_fingerprint": env.sha256, "registry_fingerprint": registry.sha256,
        "unit_profile_asset_fingerprint": assets,
        "gate_a_authority_binding_fingerprint": a._gate_binding("gate_a", ga, gae, {"metadata": rollback_metadata_fingerprint(metadata), "pin": contract_fingerprint(pin)}),
        "gate_b_authority_binding_fingerprint": a._gate_binding("gate_b", gb, gbe, {"release": release_hash}),
        "gate_c_authority_binding_fingerprint": a._gate_binding("gate_c", gc, gce, {"marker": marker_hash, "assets": assets}),
        "p3c_state_fingerprint": p3c.state_sha256, "p3c_systemd_fingerprint": live.p3c_fingerprint,
        "p3d_timer_state": "DISABLED_INACTIVE", "legacy_writer_state": writers, "legacy_enrichment_state": enrichments,
        "gmail_state": "DISABLED", "integration_test_state": "DISABLED"})
    after = anchors()
    observed = dict(after)
    for path, snapshot in ((policy.environment, env), (policy.registry, registry), (cr / "complete.json", marker_snapshot),
                           (ar / "p3d-pre-enrichment.env", metadata_bytes)):
        if observed[str(path)] != snapshot.identity:
            _fail()
    if before != after:
        _fail()
    return baseline


class PostflightReader:
    """Internal composition; production dependencies originate in protected config."""
    def __init__(self, *, evidence, router, engine, principal, observe_final, backend):
        self.evidence = evidence
        self.router, self.engine, self.principal = router, engine, principal
        self._observe_final = observe_final
        self._backend = backend

    def _verify_final_services(self, expected_manager):
        from .p3d_wp8_systemd import _ServiceStates, _ServiceState
        if self._backend.manager_identity().fingerprint != expected_manager:
            _fail()
        facts = self._backend.verify_all_services_inactive()
        if (type(facts) is not _ServiceStates or facts.service_state != "INACTIVE"
                or tuple(item.pipeline_key for item in facts.services) != c.WP8_CANONICAL_PIPELINE_KEYS
                or any(type(item) is not _ServiceState or item.state != "INACTIVE" for item in facts.services)):
            _fail()
        if self._backend.manager_identity().fingerprint != expected_manager:
            _fail()

    def capture_business(self):
        binding = self.router.resolve(self.principal)
        if make_url(binding.database_url) != make_url(self.engine.url):
            _fail()
        with a._baseline_connection(self.engine) as connection:
            return _capture_business(connection)

    def verify(self, *, operation_id, boundary, service_results, runtime):
        try:
            # Revalidate the real effects, not just the previously built proof hash.
            reader = WP8RuntimeProofReader(router=self.router, engine=self.engine,
                principal_ref=self.principal, phase_a_evidence=self.evidence)
            binding = self.router.resolve(self.principal)
            if make_url(binding.database_url) != make_url(self.engine.url):
                _fail()
            from .p3d_wp8_systemd import _ServiceResult
            if (tuple(result.pipeline_key for result in service_results) != c.WP8_CANONICAL_PIPELINE_KEYS
                    or any(type(result) is not _ServiceResult for result in service_results)):
                _fail()
            managers = {result.manager_fingerprint for result in service_results}
            if len(managers) != 1:
                _fail()
            manager = next(iter(managers))
            self._verify_final_services(manager)
            ids = {record.pipeline_run_id for record in runtime.pipeline_records}
            with a._baseline_connection(self.engine) as connection:
                # Reuse the frozen query validators on THIS same verified read-only
                # connection; do not reopen a pool connection between semantic
                # receipt verification and the exhaustive diff.
                reader._verify_routed_identity(connection, binding)
                records = tuple(reader._verify_pipeline(connection, result) for result in service_results)
                repeated = c.WP8RuntimeLedgerProofV1.build(candidate_sha=self.evidence.candidate_sha,
                    phase_a_context_fingerprint=self.evidence.phase_a_context_fingerprint,
                    rehearsal_operation_id=operation_id, runtime_boundary_fingerprint=runtime.runtime_boundary_fingerprint,
                    pipeline_records=records)
                if repeated != runtime:
                    _fail()
                after = _capture_business(connection)
                receipts = connection.execute(text("SELECT * FROM pipeline_run_effect_receipts WHERE pipeline_run_id=ANY(:ids)"),
                    {"ids": list(map(UUID, ids))}).mappings().all()
                _verify_business_diff(boundary, after, receipts=receipts, run_ids=ids)
            # Two independent final projections, including database and protected files.
            first, second = self._observe_final(), self._observe_final()
            if first != second:
                _fail()
            self._verify_final_services(manager)
            return c.WP8InvariantProofV1.build(self.evidence, rehearsal_operation_id=operation_id,
                before=self.evidence.invariant_baseline, after=second)
        except Exception:
            _fail()


__all__ = []
