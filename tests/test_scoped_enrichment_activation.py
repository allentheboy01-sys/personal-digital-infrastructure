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
from pdi.scoped_enrichment_profiles import build_enrichment_profile, profile_keys


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
