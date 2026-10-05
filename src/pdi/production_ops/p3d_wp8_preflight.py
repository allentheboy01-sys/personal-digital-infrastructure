"""WP8 Phase A: frozen WP6 readiness plus non-persisting drift bindings.

Only ``collect_phase_a_evidence`` is an operator API. Supplemental facts have
no readiness authority. Separate observations are bracketed and compared; this
is not a distributed atomic snapshot or an unobservable-ABA guarantee.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

from .p3d_wp8_contracts import (
    EXPECTED_ALEMBIC_REVISION,
    WP8ContractError,
    WP8FailureCode,
    WP8InvariantSnapshotV1,
    WP8PhaseAEvidenceV1,
    wp8_contract_bytes,
)


# This is the candidate's fixed PDI schema domain, not an operator selector.
_PDI_RELATIONS = (
    "alembic_version", "assets", "asset_sources", "blobs", "persons",
    "person_sources", "observation_scope_person_sources", "pipeline_runs",
    "provider_instances", "provider_accounts", "observation_scopes",
    "provider_sync_state", "observation_scope_sync_state",
    "resource_statements", "resource_enrichments", "resource_person_relations",
    "observation_scope_resource_person_relations",
)
_DOMAINS = frozenset({
    "schema", "route", "providers", "sources", "sync", "gate_a", "gate_b", "gate_c",
})
_CATALOG_PREFIX = (
    " FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
)
_CATALOG_FILTER = " WHERE n.nspname='public' AND c.relname::text=ANY(:relations) "
_SCHEMA_QUERIES = (
    ("relations", "SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity"
     + _CATALOG_PREFIX + _CATALOG_FILTER + "ORDER BY c.relname"),
    ("columns", "SELECT c.relname,a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),"
     "a.attnotnull,a.attidentity,a.attgenerated,pg_catalog.pg_get_expr(d.adbin,d.adrelid)"
     + _CATALOG_PREFIX + " JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid "
     "LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
     + _CATALOG_FILTER + "AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum"),
    ("constraints", "SELECT c.relname,k.conname,k.contype,pg_catalog.pg_get_constraintdef(k.oid),"
     "k.convalidated,k.condeferrable,k.condeferred" + _CATALOG_PREFIX
     + " JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid " + _CATALOG_FILTER
     + "ORDER BY c.relname,k.conname"),
    ("indexes", "SELECT c.relname,i.relname,pg_catalog.pg_get_indexdef(x.indexrelid),"
     "x.indisunique,x.indisvalid,x.indisready" + _CATALOG_PREFIX
     + " JOIN pg_catalog.pg_index x ON x.indrelid=c.oid "
     "JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid " + _CATALOG_FILTER
     + "ORDER BY c.relname,i.relname"),
    ("triggers", "SELECT c.relname,t.tgname,pg_catalog.pg_get_triggerdef(t.oid),t.tgenabled,"
     "pg_catalog.pg_get_functiondef(t.tgfoid)" + _CATALOG_PREFIX
     + " JOIN pg_catalog.pg_trigger t ON t.tgrelid=c.oid " + _CATALOG_FILTER
     + "AND NOT t.tgisinternal ORDER BY c.relname,t.tgname"),
    ("policies", "SELECT c.relname,p.polname,p.polpermissive,p.polcmd,"
     "ARRAY(SELECT CASE WHEN role_id=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(role_id)::text END "
     "FROM unnest(p.polroles) role_id ORDER BY 1),"
     "pg_catalog.pg_get_expr(p.polqual,p.polrelid),pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)"
     + _CATALOG_PREFIX + " JOIN pg_catalog.pg_policy p ON p.polrelid=c.oid "
     + _CATALOG_FILTER + "ORDER BY c.relname,p.polname"),
    ("types", "SELECT DISTINCT ns.nspname,t.typname,t.typtype,"
     "pg_catalog.format_type(t.typbasetype,t.typtypmod),"
     "ARRAY(SELECT e.enumlabel::text FROM pg_catalog.pg_enum e WHERE e.enumtypid=t.oid ORDER BY e.enumsortorder),"
     "ARRAY(SELECT pg_catalog.pg_get_constraintdef(k.oid) FROM pg_catalog.pg_constraint k "
     "WHERE k.contypid=t.oid ORDER BY k.conname)" + _CATALOG_PREFIX
     + " JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid "
     "JOIN pg_catalog.pg_type t ON t.oid=a.atttypid JOIN pg_catalog.pg_namespace ns ON ns.oid=t.typnamespace "
     + _CATALOG_FILTER + "AND a.attnum>0 AND NOT a.attisdropped AND ns.nspname<>'pg_catalog' ORDER BY 1,2"),
)


def _fail(code: WP8FailureCode = WP8FailureCode.PREREQUISITE_DRIFT) -> None:
    raise WP8ContractError(code) from None


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _binding_fingerprint(domain: str, facts: Any) -> str:
    """Private typed-observation hash; never serialize raw facts as evidence.

    Catalog definitions/identity keys are not credential-value contracts. The
    outer evidence still uses the unchanged frozen secret-checking serializer.
    """
    if domain not in _DOMAINS:
        _fail()
    return _digest(json.dumps(
        {"projection_version": 1, "domain": domain, "facts": facts},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8"))


def _verify_runtime(policy, candidate: str, *, executable=None, module_file=None,
                    preparation_module_file=None, contract_module_file=None, runner=None) -> str:
    """Bind an API invocation, without impersonating the WP6 standalone script."""
    from . import p3d_pre_rehearsal_evidence as wp6
    from . import p3d_wp8_contracts as contracts
    from .cutover import trusted_path
    from .p3d_inert_asset_install import GIT, GIT_READ_ONLY_ENV

    wp6._git_sha(candidate)
    release = policy.candidate_releases_root / candidate
    interpreter = Path(sys.executable if executable is None else executable).absolute()
    installed = (
        Path(__file__ if module_file is None else module_file).absolute(),
        Path(wp6.__file__ if preparation_module_file is None else preparation_module_file).absolute(),
        Path(contracts.__file__ if contract_module_file is None else contract_module_file).absolute(),
    )
    sources = tuple(release / "src/pdi/production_ops" / name for name in (
        "p3d_wp8_preflight.py", "p3d_pre_rehearsal_evidence.py", "p3d_wp8_contracts.py",
    ))
    try:
        interpreter_info = interpreter.lstat()
        if (interpreter != release / ".venv/bin/python" or
                not trusted_path(release, expected_kind="directory", require_root_group=True) or
                not trusted_path(interpreter.parent, expected_kind="directory", require_root_group=True) or
                interpreter_info.st_uid != 0 or interpreter_info.st_gid != 0 or
                (not stat.S_ISLNK(interpreter_info.st_mode) and
                 not trusted_path(interpreter, expected_kind="file", require_root_group=True)) or
                not trusted_path(interpreter.resolve(strict=True), expected_kind="file", require_root_group=True)):
            _fail(WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)
        venv = (release / ".venv").resolve(strict=True)
        for imported, source in zip(installed, sources, strict=True):
            if (venv not in imported.resolve(strict=True).parents or
                    not trusted_path(imported, expected_kind="file", require_root_group=True) or
                    not trusted_path(source, expected_kind="file", require_root_group=True) or
                    imported.read_bytes() != source.read_bytes()):
                _fail(WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)
        for args in (("rev-parse", "HEAD"), ("status", "--porcelain", "--untracked-files=no")):
            result = (subprocess.run if runner is None else runner)(
                (str(GIT), "-C", str(release), *args), capture_output=True,
                text=True, timeout=30, shell=False, env=dict(GIT_READ_ONLY_ENV),
            )
            if result.returncode or (result.stdout.strip() != candidate if args[0] == "rev-parse"
                                     else bool(result.stdout.strip())):
                _fail(WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)
        return _digest(installed[1].read_bytes())
    except BaseException:
        _fail(WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)


@contextmanager
def _baseline_connection(engine):
    from sqlalchemy import text
    from .p3d_evidence import postgresql_read_only_transaction

    snapshot_engine = engine.execution_options(isolation_level="REPEATABLE READ")
    with postgresql_read_only_transaction(snapshot_engine) as connection:
        if connection.scalar(text("SHOW transaction_isolation")) != "repeatable read":
            _fail(WP8FailureCode.INVARIANT_FAILED)
        yield connection


def _schema_fingerprint(connection) -> str:
    from sqlalchemy import text

    facts = {
        label: [tuple(row) for row in connection.execute(text(sql), {"relations": list(_PDI_RELATIONS)})]
        for label, sql in _SCHEMA_QUERIES
    }
    if {row[0] for row in facts["relations"]} != set(_PDI_RELATIONS):
        _fail(WP8FailureCode.INVARIANT_FAILED)
    return _binding_fingerprint("schema", facts)


@dataclass(frozen=True)
class _DatabaseProjection:
    schema: str
    route: str
    identity: str
    providers: str
    enabled_count: int
    enabled_scopes: str
    sources: str
    sync: str
    revision: str


def _project_database(configuration, principal_ref: str, *, engine_factory=None) -> _DatabaseProjection:
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from pdi.database import create_postgres_engine
    from pdi.scoped_enrichment_profiles import derive_enabled_scope_ids
    from .p3d_evidence import context_fingerprint
    from .p3d_preparation_contracts import contract_fingerprint

    binding = configuration.router.resolve(principal_ref)
    engine = (create_postgres_engine if engine_factory is None else engine_factory)(binding.database_url)
    try:
        if make_url(engine.url) != make_url(binding.database_url):
            _fail()
        with _baseline_connection(engine) as connection:
            revisions = list(connection.execute(text("SELECT version_num FROM alembic_version")))
            if [tuple(row) for row in revisions] != [(EXPECTED_ALEMBIC_REVISION,)]:
                _fail(WP8FailureCode.INVARIANT_FAILED)
            target = tuple(connection.execute(text(
                "SELECT current_database(),current_user,inet_server_addr()::text,inet_server_port()"
            )).one())
            if target[0] != make_url(binding.database_url).database:
                _fail()
            schema = _schema_fingerprint(connection)
            instances = [tuple(row) for row in connection.execute(text(
                "SELECT id,provider_type,instance_key,enabled FROM provider_instances ORDER BY id"))]
            accounts = [tuple(row) for row in connection.execute(text(
                "SELECT id,provider_instance_id,account_key,provider_native_id,enabled FROM provider_accounts ORDER BY id"))]
            scopes = [tuple(row) for row in connection.execute(text(
                "SELECT id,provider_instance_id,provider_account_id,scope_key,enabled FROM observation_scopes ORDER BY id"))]
            scope_ids = sorted(map(str, derive_enabled_scope_ids(connection)))
            # Reproduce only the frozen WP6 identity fingerprint representation,
            # not its readiness checks. All authority comparisons happen below.
            identity_state = []
            for instance_id, provider, _, enabled in instances:
                if provider not in {"nextcloud", "immich", "gmail", "integration-test"}:
                    continue
                related_scopes = [row for row in scopes if row[1] == instance_id]
                if len(related_scopes) != 1:
                    _fail()
                scope = related_scopes[0]
                identity_state.append({
                    "provider_type": provider, "instance_id": str(instance_id),
                    "instance_enabled": enabled,
                    "account_ids": sorted(str(row[0]) for row in accounts if row[1] == instance_id),
                    "scope_id": str(scope[0]), "scope_enabled": scope[4],
                })
            identity = context_fingerprint({
                "principal": principal_ref, "database_ref": binding.database_ref,
                "scopes": scope_ids,
                "identity_state": sorted(identity_state, key=lambda item: item["provider_type"]),
            })
            for provider in ("gmail", "integration-test"):
                matched = [row for row in instances if row[1] == provider]
                if len(matched) != 1 or matched[0][3] is not False:
                    _fail()
                if any(row[4] is not False for row in scopes if row[1] == matched[0][0]):
                    _fail()
            provenance = [tuple(row) for row in connection.execute(text(
                "SELECT DISTINCT source.provider,source.observation_scope_id,scope.provider_instance_id,"
                "scope.provider_account_id,instance.provider_type FROM asset_sources source "
                "LEFT JOIN observation_scopes scope ON scope.id=source.observation_scope_id "
                "LEFT JOIN provider_instances instance ON instance.id=scope.provider_instance_id "
                "ORDER BY 1,2,3,4,5"))]
            integrity = tuple(connection.execute(text(
                "SELECT EXISTS(SELECT 1 FROM asset_sources WHERE observation_scope_id IS NULL),"
                "EXISTS(SELECT 1 FROM asset_sources GROUP BY observation_scope_id,external_id HAVING count(*)>1),"
                "EXISTS(SELECT 1 FROM asset_sources s LEFT JOIN observation_scopes o ON o.id=s.observation_scope_id "
                "LEFT JOIN provider_instances i ON i.id=o.provider_instance_id "
                "WHERE o.id IS NULL OR i.id IS NULL OR s.provider<>i.provider_type)"
            )).one())
            sync = [tuple(row) for row in connection.execute(text(
                "SELECT observation_scope_id,mechanism,checkpoint IS NOT NULL,reconciliation_required "
                "FROM observation_scope_sync_state ORDER BY observation_scope_id,mechanism"))]
            if any(integrity) or set(str(row[0]) for row in sync) != set(scope_ids):
                _fail()
            route = {
                "principal": principal_ref, "database_ref": binding.database_ref,
                "url_env": configuration.router.database_environment_key(principal_ref),
                "connected_target": target,
            }
            # UUIDs are identity-only in-memory facts; raw rows never leave this function.
            normalize = lambda rows: [[str(v) if hasattr(v, "hex") else v for v in row] for row in rows]
            return _DatabaseProjection(
                schema, _binding_fingerprint("route", route), identity,
                _binding_fingerprint("providers", {
                    "instances": normalize(instances), "accounts": normalize(accounts), "scopes": normalize(scopes),
                }), len(scope_ids), contract_fingerprint({"principal_ref": principal_ref, "enabled_scope_ids": scope_ids}),
                _binding_fingerprint("sources", {"relationships": normalize(provenance), "integrity": integrity}),
                _binding_fingerprint("sync", normalize(sync)), EXPECTED_ALEMBIC_REVISION,
            )
    finally:
        engine.dispose()


def _migration_fingerprint(policy, candidate: str) -> str:
    from .cutover import trusted_path
    from .p3d_preparation_contracts import contract_fingerprint

    release = policy.candidate_releases_root / candidate
    root = release / "migrations"
    if not trusted_path(root, expected_kind="directory", require_root_group=True):
        _fail()
    entries = []
    # Inspect only candidate migration authority, without executing its files
    # or following links to other trees. Compiled cache bytes are not projected.
    def visit(directory):
        for path in sorted(directory.iterdir()):
            if path.is_symlink():
                _fail()
            if path.is_dir():
                if not trusted_path(path, expected_kind="directory", require_root_group=True):
                    _fail()
                visit(path)
            elif path.suffix == ".py":
                if not trusted_path(path, expected_kind="file", require_root_group=True):
                    _fail()
                entries.append((str(path.relative_to(release)), _digest(path.read_bytes())))
    visit(root)
    if not entries:
        _fail()
    return contract_fingerprint({"migrations": sorted(entries)})


def _gate_binding(domain, state, events, artifacts) -> str:
    from .p3d_preparation_contracts import contract_fingerprint, preparation_journal_fingerprint

    return _binding_fingerprint(domain, {
        "operation_id": state.operation_id, "candidate_sha": state.candidate_sha,
        "state_fingerprint": contract_fingerprint(state),
        "journal_fingerprint": preparation_journal_fingerprint(events),
        "artifacts": artifacts,
    })


def _legacy_states(systemd) -> tuple[str, str]:
    from .contracts import LEGACY

    for name in LEGACY:
        unit = name + ".timer"
        enabled = systemd._read("is-enabled", unit)
        active = systemd._read("is-active", unit)
        if (enabled.returncode != 1 or enabled.value != "disabled" or
                active.returncode != 3 or active.value != "inactive"):
            _fail()
    return "DISABLED_INACTIVE", "DISABLED_INACTIVE"


@dataclass(frozen=True)
class _Projection:
    baseline: WP8InvariantSnapshotV1
    rollback_source: str
    marker: str
    wp6_context: str
    scope_count: int
    anchors: tuple


def _project(policy, inputs, systemd, result) -> _Projection:
    from . import p3d_pre_rehearsal_evidence as wp6
    from .p3d_inert_asset_install import InertAssetInputs, ProtectedPrerequisiteReader
    from .p3d_preparation_contracts import (
        CANONICAL_P3D_INSTALL_PATH_MODES, PreparationGate, PreparationPrerequisiteEvidenceV1,
        asset_installation_fingerprint, contract_fingerprint, rollback_metadata_fingerprint,
    )

    a, ae, ar = wp6._explicit_gate(policy, inputs.gate_a_operation_id,
        gate=PreparationGate.ROLLBACK_QUALIFICATION, candidate=inputs.candidate_sha)
    b, be, br = wp6._explicit_gate(policy, inputs.gate_b_operation_id,
        gate=PreparationGate.RELEASE_STAGING, candidate=inputs.candidate_sha)
    c, ce, cr = wp6._explicit_gate(policy, inputs.gate_c_operation_id,
        gate=PreparationGate.INERT_ASSET_INSTALL, candidate=inputs.candidate_sha)
    marker, marker_hash, marker_snapshot, _ = wp6._read_gate_c_marker(policy, inputs)
    prereq_inputs = InertAssetInputs(inputs.candidate_sha, inputs.gate_a_operation_id,
        inputs.gate_b_operation_id, marker.unit_profile_asset_fingerprint, marker.gate_c_tool_identity)
    prereqs = ProtectedPrerequisiteReader(policy, prereq_inputs, systemd).collect(home=cr / "home")
    metadata = prereqs.rollback_metadata
    configuration, principal, env, registry = wp6._load_protected_configuration(policy)
    paths = {policy.environment: (0o600, policy.owner_gid),
             policy.registry: (0o640, policy.runtime_gid), policy.p3c_state: (0o600, policy.owner_gid),
             cr / "complete.json": (0o600, policy.owner_gid),
             ar / "p3d-pre-enrichment.env": (0o600, policy.owner_gid),
             ar / f"rollback-release-pin-{metadata.snapshot_id}.json": (0o600, policy.owner_gid)}
    for logical, mode in CANONICAL_P3D_INSTALL_PATH_MODES.items():
        paths[policy.physical(logical)] = (int(mode, 8), policy.owner_gid)
    for root in (ar, br, cr):
        for pattern in ("state-*.json", "journal-*.json"):
            for path in root.glob(pattern):
                paths[path] = (0o600, policy.owner_gid)

    def anchors():
        return tuple((str(path.relative_to(policy.root)),
                      wp6._read_protected_bytes(path, policy=policy, mode=mode, gid=gid).identity)
                     for path, (mode, gid) in sorted(paths.items()))

    before = anchors()
    observed = dict(before)
    for path, snapshot in ((policy.environment, env), (policy.registry, registry),
                           (cr / "complete.json", marker_snapshot)):
        if observed[str(path.relative_to(policy.root))] != snapshot.identity:
            _fail()
    if observed[str(policy.p3c_state.relative_to(policy.root))][-1] != prereqs.p3c_state_sha256:
        _fail()
    db = _project_database(configuration, principal)
    assets = asset_installation_fingerprint(wp6._fresh_installed_manifest(policy))
    current = wp6._current_target(policy, expected_source=metadata.source_release_sha)
    live_systemd = systemd.snapshot(post_install=True)
    if not live_systemd.p3d_quiet:
        _fail()
    writer_state, enrichment_state = _legacy_states(systemd)
    live = PreparationPrerequisiteEvidenceV1(
        inputs.candidate_sha, metadata.snapshot_id, rollback_metadata_fingerprint(metadata),
        metadata.source_release_sha, registry.sha256, db.identity, db.enabled_scopes,
        assets, current, live_systemd.p3c_fingerprint, "DISABLED_INACTIVE",
    )
    context = contract_fingerprint(wp6._live_context_mapping(live))
    if (inputs.rollback_source_cross_check != metadata.source_release_sha or
            db.identity != result.db_identity_fingerprint or db.enabled_count != result.enabled_scope_count or
            db.enabled_scopes != result.enabled_scope_fingerprint or assets != result.asset_fingerprint or
            marker_hash != result.marker_fingerprint or context != result.context_fingerprint or
            registry.sha256 != marker.registry_fingerprint or
            live_systemd.p3c_fingerprint != marker.p3c_systemd_state_after_fingerprint):
        _fail()
    baseline = WP8InvariantSnapshotV1.from_mapping({
        "version": 1, "schema_fingerprint": db.schema,
        "migration_tree_fingerprint": _migration_fingerprint(policy, inputs.candidate_sha),
        "alembic_revision": db.revision, "principal_route_fingerprint": db.route,
        "db_identity_fingerprint": db.identity, "provider_identity_fingerprint": db.providers,
        "enabled_scope_fingerprint": db.enabled_scopes, "source_identity_fingerprint": db.sources,
        "sync_state_fingerprint": db.sync, "protected_environment_fingerprint": env.sha256,
        "registry_fingerprint": registry.sha256, "unit_profile_asset_fingerprint": assets,
        "gate_a_authority_binding_fingerprint": _gate_binding("gate_a", a, ae, {
            "metadata": prereqs.rollback_metadata_sha256, "pin": contract_fingerprint(prereqs.release_pin)}),
        "gate_b_authority_binding_fingerprint": _gate_binding("gate_b", b, be, {"release": prereqs.gate_b_release_fingerprint}),
        "gate_c_authority_binding_fingerprint": _gate_binding("gate_c", c, ce, {"marker": marker_hash, "assets": assets}),
        "p3c_state_fingerprint": prereqs.p3c_state_sha256,
        "p3c_systemd_fingerprint": live_systemd.p3c_fingerprint,
        "p3d_timer_state": "DISABLED_INACTIVE", "legacy_writer_state": writer_state,
        "legacy_enrichment_state": enrichment_state, "gmail_state": "DISABLED", "integration_test_state": "DISABLED",
    })
    after = anchors()
    if before != after:
        _fail()
    return _Projection(baseline, metadata.source_release_sha, marker_hash, context, db.enabled_count, after)


def _collect(policy, inputs, systemd, *, runtime_verifier=None, collector=None, projector=None) -> WP8PhaseAEvidenceV1:
    """Private DI seam; it is not an operator-selectable production mode."""
    from . import p3d_pre_rehearsal_evidence as wp6

    try:
        inputs.validate()
        if (inputs.rollback_source_cross_check is None or
                len({inputs.gate_a_operation_id, inputs.gate_b_operation_id, inputs.gate_c_operation_id}) != 3):
            _fail()
        runtime_verifier = _verify_runtime if runtime_verifier is None else runtime_verifier
        collector = wp6.collect_pre_rehearsal_evidence if collector is None else collector
        projector = _project if projector is None else projector
        runtime_verifier(policy, inputs.candidate_sha)

        def embedded_runtime(selected_policy, candidate):
            if selected_policy != policy or candidate != inputs.candidate_sha:
                _fail(WP8FailureCode.CANDIDATE_RUNTIME_DRIFT)
            return runtime_verifier(policy, candidate)

        def ready():
            result = collector(policy=policy, inputs=inputs, systemd=systemd, runtime_verifier=embedded_runtime)
            if type(result) is not wp6.PreRehearsalEvidenceResult or result.candidate_sha != inputs.candidate_sha:
                _fail()
            return result

        first = ready()  # No projector may execute until frozen WP6 has passed.
        before = projector(policy, inputs, systemd, first)
        second = ready()
        if first != second:
            _fail()
        after = projector(policy, inputs, systemd, second)
        if (type(before) is not _Projection or type(after) is not _Projection or before != after or
                after.rollback_source != inputs.rollback_source_cross_check or
                after.marker != first.marker_fingerprint or after.wp6_context != first.context_fingerprint or
                after.scope_count != first.enabled_scope_count):
            _fail()
        baseline = after.baseline
        evidence = WP8PhaseAEvidenceV1.build(
            candidate_sha=first.candidate_sha, rollback_source_sha=after.rollback_source,
            gate_a_operation_id=inputs.gate_a_operation_id,
            gate_a_authority_binding_fingerprint=baseline.gate_a_authority_binding_fingerprint,
            gate_b_operation_id=inputs.gate_b_operation_id,
            gate_b_authority_binding_fingerprint=baseline.gate_b_authority_binding_fingerprint,
            gate_c_operation_id=inputs.gate_c_operation_id,
            gate_c_marker_fingerprint=first.marker_fingerprint,
            gate_c_authority_binding_fingerprint=baseline.gate_c_authority_binding_fingerprint,
            wp6_context_fingerprint=first.context_fingerprint,
            db_identity_fingerprint=first.db_identity_fingerprint,
            enabled_scope_count=first.enabled_scope_count, enabled_scope_fingerprint=first.enabled_scope_fingerprint,
            unit_profile_asset_fingerprint=first.asset_fingerprint,
            p3c_state_fingerprint=baseline.p3c_state_fingerprint, p3c_systemd_fingerprint=baseline.p3c_systemd_fingerprint,
            protected_environment_fingerprint=baseline.protected_environment_fingerprint,
            registry_fingerprint=baseline.registry_fingerprint, invariant_baseline=baseline,
        )
        wp8_contract_bytes(evidence)
        return evidence
    except BaseException:
        _fail()


def collect_phase_a_evidence(*, candidate_sha: str, gate_a_operation_id: str,
                             gate_b_operation_id: str, gate_c_operation_id: str,
                             rollback_source_sha: str) -> WP8PhaseAEvidenceV1:
    """Read-only Phase A API. No resource overrides, CLI, persistence or B authority."""
    from .p3d_inert_asset_install import InertAssetPolicy, ProductionReadOnlySystemdStateProvider
    from .p3d_pre_rehearsal_evidence import PreparationEvidenceInputs

    try:
        inputs = PreparationEvidenceInputs(candidate_sha, gate_a_operation_id, gate_b_operation_id,
                                          gate_c_operation_id, rollback_source_sha)
        inputs.validate()
        if rollback_source_sha is None:
            _fail()
        return _collect(InertAssetPolicy.production(), inputs, ProductionReadOnlySystemdStateProvider())
    except BaseException:
        _fail()
