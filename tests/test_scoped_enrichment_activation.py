from pathlib import Path

import pytest

from pdi.scoped_enrichment_activation import (
    ActivationState,
    CANONICAL_SCOPED_ENRICHMENTS,
    ENRICHMENT_SCHEDULES,
    EnrichmentActivationRefused,
    ScopedEnrichmentActivation,
)
from pdi.scoped_operational import ENRICHMENT_BATCH_SIZES, SCOPED_FORMAL_PIPELINES
from pdi.scoped_enrichment_profiles import (
    build_enrichment_profile,
    build_profile_from_binding_refs,
    profile_keys,
    render_environment_file,
)
from pdi.production_ops.enrichment_cutover import (
    P3DControl, P3DControlRefused, P3D_TIMER_UNITS, SystemdScopedEnrichmentActions,
    validate_rollback_metadata,
    install_systemd_assets,
)


class Actions:
    def __init__(self, *, preflight=True, qualify=True, fail_enable=False):
        self.preflight_result = preflight
        self.qualify_result = qualify
        self.events = []
        self.fail_enable = fail_enable

    def preflight(self):
        self.events.append("preflight")
        return self.preflight_result

    def qualify(self, keys):
        self.events.append(("qualify", keys))
        return self.qualify_result

    def enable_scoped_enrichments(self, keys):
        self.events.append(("enable", keys))
        if self.fail_enable:
            raise RuntimeError("synthetic enable failure")

    def disable_scoped_enrichments(self, keys):
        self.events.append(("disable", keys))


def test_canonical_registry_and_batch_sizes_are_aligned():
    assert tuple(ENRICHMENT_BATCH_SIZES) == CANONICAL_SCOPED_ENRICHMENTS
    assert set(CANONICAL_SCOPED_ENRICHMENTS) <= set(SCOPED_FORMAL_PIPELINES)
    assert "enrichment.local" not in SCOPED_FORMAL_PIPELINES
    assert ENRICHMENT_BATCH_SIZES == {
        "enrichment.nextcloud_text": 100,
        "enrichment.nextcloud_documents": 100,
        "enrichment.file_metadata": 20000,
        "enrichment.immich_geo": 20000,
        "enrichment.immich_metadata": 20000,
        "enrichment.immich_ocr": 20000,
    }


def test_schedule_is_canonical_and_deferred_gmail_is_absent():
    assert ENRICHMENT_SCHEDULES == {
        "enrichment.nextcloud_text": "03:00",
        "enrichment.nextcloud_documents": "03:15",
        "enrichment.immich_geo": "05:30",
        "enrichment.file_metadata": "05:45",
        "enrichment.immich_metadata": "06:00",
        "enrichment.immich_ocr": "06:30",
    }
    assert "enrichment.gmail_metadata" not in ENRICHMENT_SCHEDULES


def test_unit_profile_contract_is_exact_and_local_profiles_have_no_provider_secret():
    common = {"NEXTCLOUD__PASSWORD": "synthetic-nextcloud", "IMMICH__API_KEY": "synthetic-immich"}
    for key in CANONICAL_SCOPED_ENRICHMENTS:
        profile = build_enrichment_profile(
            key, principal_ref="synthetic-primary", database_url="postgresql://isolated",
            secrets=common,
        )
        assert set(profile) == set(profile_keys(key))
        assert profile["PDI_SCOPED_PIPELINE_KEY"] == key
    for key in ("enrichment.file_metadata", "enrichment.immich_geo", "enrichment.immich_metadata"):
        assert "NEXTCLOUD__PASSWORD" not in profile_keys(key)
        assert "IMMICH__API_KEY" not in profile_keys(key)


def test_multi_scope_profile_uses_exact_secret_refs_and_renders_safely():
    environment = {"NC_A_SECRET": "a\\quote\"", "NC_B_SECRET": "b"}
    profile = build_profile_from_binding_refs(
        "enrichment.nextcloud_text", principal_ref="primary", database_url="postgresql://isolated",
        binding_secret_refs={"scope-a": "NC_A_SECRET", "scope-b": "NC_B_SECRET"},
        environment=environment,
    )
    rendered = render_environment_file(profile)
    assert 'NC_A_SECRET="a\\\\quote\\\""' in rendered
    assert "IMMICH__API_KEY" not in rendered
    with pytest.raises(ValueError, match="UNRELATED_PROVIDER_SECRET"):
        build_profile_from_binding_refs(
            "enrichment.file_metadata", principal_ref="primary", database_url="postgresql://isolated",
            binding_secret_refs={"scope-a": "NC_A_SECRET"}, environment=environment,
        )


def test_activation_is_fail_closed_and_abort_only_disables_scoped_enrichments():
    actions = Actions()
    activation = ScopedEnrichmentActivation(actions)
    with pytest.raises(EnrichmentActivationRefused, match="QUALIFICATION"):
        activation.activate()
    activation.preflight()
    assert activation.state is ActivationState.PREFLIGHT_PASSED
    activation.qualify()
    activation.activate()
    assert activation.state is ActivationState.ACTIVE
    activation.abort()
    assert activation.state is ActivationState.ABORTED
    assert actions.events[-1] == ("disable", CANONICAL_SCOPED_ENRICHMENTS)
    assert all("legacy" not in repr(event) for event in actions.events)


def test_failed_qualification_never_enables_timers():
    actions = Actions(qualify=False)
    activation = ScopedEnrichmentActivation(actions)
    activation.preflight()
    with pytest.raises(EnrichmentActivationRefused, match="QUALIFICATION_FAILED"):
        activation.qualify()
    assert activation.state is ActivationState.PREFLIGHT_PASSED
    assert not any(event[0] == "enable" for event in actions.events if isinstance(event, tuple))


def test_qualification_requires_successful_preflight():
    activation = ScopedEnrichmentActivation(Actions())
    with pytest.raises(EnrichmentActivationRefused, match="QUALIFICATION_ORDER_INVALID"):
        activation.qualify()


def test_failed_preflight_cannot_qualify():
    activation = ScopedEnrichmentActivation(Actions(preflight=False))
    with pytest.raises(EnrichmentActivationRefused, match="PREFLIGHT_FAILED"):
        activation.preflight()
    with pytest.raises(EnrichmentActivationRefused, match="QUALIFICATION_ORDER_INVALID"):
        activation.qualify()


def test_partial_activation_failure_cleans_all_scoped_timers():
    actions = Actions(fail_enable=True)
    activation = ScopedEnrichmentActivation(actions)
    activation.preflight()
    activation.qualify()
    with pytest.raises(EnrichmentActivationRefused, match="ACTIVATION_FAILED"):
        activation.activate()
    assert activation.state is ActivationState.ABORTED
    assert actions.events[-1] == ("disable", CANONICAL_SCOPED_ENRICHMENTS)


def test_cleanup_failure_is_not_reported_as_aborted():
    actions = Actions(fail_enable=True)
    def failing_disable(_keys):
        raise RuntimeError("synthetic cleanup failure")
    actions.disable_scoped_enrichments = failing_disable
    activation = ScopedEnrichmentActivation(actions)
    activation.preflight()
    activation.qualify()
    with pytest.raises(EnrichmentActivationRefused, match="ABORT_NOT_CONFIRMED"):
        activation.activate()
    assert activation.state is ActivationState.ABORT_NOT_CONFIRMED


def test_p3d_control_requires_preflight_and_records_fail_closed_abort(tmp_path):
    control = P3DControl(tmp_path / "state.json", tmp_path / "journal", "abc", tmp_path / "release", tmp_path / "cutover.lock")
    with pytest.raises(P3DControlRefused, match="QUALIFICATION_ORDER_INVALID"):
        control.qualify({key: True for key in CANONICAL_SCOPED_ENRICHMENTS})
    evidence = {
        "release_sha": "abc", "release_path": str(tmp_path / "release"),
        "p3c_pass": True, "writers_healthy": True, "legacy_enrichment_disabled": True,
        "p3d_timers_off": True, "gmail_disabled": True, "rollback_qualified": True,
    }
    control.preflight(evidence)
    control.qualify({key: True for key in CANONICAL_SCOPED_ENRICHMENTS})
    with pytest.raises(P3DControlRefused, match="ABORT_NOT_CONFIRMED"):
        control.abort(all_disabled=False)
    assert '"state": "ABORT_NOT_CONFIRMED"' in (tmp_path / "state.json").read_text()


@pytest.mark.parametrize("failure_index", (0, 2, 5))
def test_systemd_cleanup_attempts_all_timers_after_any_disable_failure(failure_index):
    calls = []
    disabled = set()
    units = tuple(P3D_TIMER_UNITS.values())
    def runner(argv, **_kwargs):
        calls.append(argv)
        action, unit = argv[1], argv[-1]
        if action == "disable":
            index = units.index(unit)
            if index == failure_index:
                return type("R", (), {"returncode": 1})()
            disabled.add(unit)
            return type("R", (), {"returncode": 0})()
        if action == "is-enabled":
            return type("R", (), {"returncode": 0 if unit not in disabled else 1})()
        if action == "is-active":
            return type("R", (), {"returncode": 0 if unit not in disabled else 1})()
        return type("R", (), {"returncode": 0})()
    backend = SystemdScopedEnrichmentActions(runner)
    assert backend.disable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS) is False
    attempted = [call[-1] for call in calls if call[1] == "disable"]
    assert attempted == list(units)


def test_rollback_source_sha_is_separate_from_candidate():
    assert validate_rollback_metadata({
        "SNAPSHOT_ID": "snapshot", "SOURCE_SHA": "a" * 40,
        "ALEMBIC": "e5a7b9d1f324", "POSTGRES_MAJOR": "16",
        "P3C_PRODUCTION_ENABLED": "YES", "P3C_SOAK": "PASS",
        "RESTORE_TESTED": "YES", "RESTORED_COUNTS_MATCH": "YES",
        "BACKUP_FS_UUID": "uuid", "RESTIC_REPOSITORY": "repo",
    }, rollback_source_sha="a" * 40)


def test_active_state_can_be_verified_with_active_context(tmp_path):
    control = P3DControl(tmp_path / "state.json", tmp_path / "journal", "abc", tmp_path / "release", tmp_path / "lock")
    context = {"release_sha": "abc", "release_path": str(tmp_path / "release"), "p3c_pass": True,
               "writers_healthy": True, "legacy_enrichment_disabled": True,
               "p3d_timers_off": True, "gmail_disabled": True, "rollback_qualified": True}
    control.preflight(context)
    control.qualify({key: True for key in CANONICAL_SCOPED_ENRICHMENTS}, context=context)
    control.activation_result(enabled=True, all_disabled=False, context=context)
    control.verify({"p3c_healthy": True, "p3d_healthy": True})
    assert '"verified": true' in (tmp_path / "state.json").read_text()


def test_systemd_assets_install_without_activation(tmp_path):
    source = Path(__file__).parents[1] / "deployment/systemd"
    units = tmp_path / "units"
    profiles = tmp_path / "profiles"
    values = {key: {"PDI_PRINCIPAL_REF": "primary", "PDI_SCOPED_PIPELINE_KEY": key,
                    "DATABASE__URL": "postgresql://synthetic"}
              for key in CANONICAL_SCOPED_ENRICHMENTS}
    calls = []
    def runner(argv, **_kwargs):
        calls.append(argv)
        return type("R", (), {"returncode": 0})()
    assert install_systemd_assets(source, units, profiles, values, runner=runner, allow_test_root=True)
    assert (units / "pdi-scoped-pipeline@.service").exists()
    assert len(list(profiles.glob("*.env"))) == 6
    assert calls and calls[0][0:2] == ("systemd-analyze", "verify")


def test_abort_is_idempotent_from_qualified_state():
    actions = Actions()
    activation = ScopedEnrichmentActivation(actions)
    activation.preflight()
    activation.qualify()
    activation.abort()
    activation.abort()
    assert activation.state is ActivationState.ABORTED
    assert actions.events[-1] == ("disable", CANONICAL_SCOPED_ENRICHMENTS)


def test_scoped_timer_assets_reuse_generic_pipeline_boundary():
    root = Path(__file__).parents[1] / "deployment/systemd"
    expected = {
        "pdi-scoped-enrichment-nextcloud-text.timer": ("03:00:00", "enrichment.nextcloud_text"),
        "pdi-scoped-enrichment-nextcloud-documents.timer": ("03:15:00", "enrichment.nextcloud_documents"),
        "pdi-scoped-enrichment-immich-geo.timer": ("05:30:00", "enrichment.immich_geo"),
        "pdi-scoped-enrichment-file-metadata.timer": ("05:45:00", "enrichment.file_metadata"),
        "pdi-scoped-enrichment-immich-metadata.timer": ("06:00:00", "enrichment.immich_metadata"),
        "pdi-scoped-enrichment-immich-ocr.timer": ("06:30:00", "enrichment.immich_ocr"),
    }
    for filename, (clock, instance) in expected.items():
        text = (root / filename).read_text()
        assert f"OnCalendar=*-*-* {clock}" in text
        assert f"Unit=pdi-scoped-pipeline@{instance}.service" in text
        assert "Persistent=true" in text
