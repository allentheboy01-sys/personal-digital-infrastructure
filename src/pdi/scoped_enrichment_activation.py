"""Fail-closed design primitives for the future scoped-enrichment gate.

This module is deliberately an orchestration boundary, not a production
installer.  Callers supply side-effecting operations; the state machine never
touches systemd by itself and never enables legacy enrichment units.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


CANONICAL_SCOPED_ENRICHMENTS = (
    "enrichment.nextcloud_text",
    "enrichment.nextcloud_documents",
    "enrichment.file_metadata",
    "enrichment.immich_geo",
    "enrichment.immich_metadata",
    "enrichment.immich_ocr",
)

ENRICHMENT_SCHEDULES = {
    "enrichment.nextcloud_text": "03:00",
    "enrichment.nextcloud_documents": "03:15",
    "enrichment.immich_geo": "05:30",
    "enrichment.file_metadata": "05:45",
    "enrichment.immich_metadata": "06:00",
    "enrichment.immich_ocr": "06:30",
}


class ActivationState(StrEnum):
    PRECHECK = "precheck"
    PREFLIGHT_PASSED = "preflight_passed"
    QUALIFIED = "qualified"
    ACTIVATING = "activating"
    ACTIVE = "active"
    ABORTED = "aborted"
    ABORT_NOT_CONFIRMED = "abort_not_confirmed"


class EnrichmentActivationRefused(RuntimeError):
    """A fail-closed activation precondition was not met."""


class EnrichmentActivationActions(Protocol):
    def preflight(self) -> bool: ...
    def pre_rehearsal_qualify(self, pipeline_keys: tuple[str, ...]) -> bool: ...
    def enable_scoped_enrichments(self, pipeline_keys: tuple[str, ...]) -> None: ...
    def disable_scoped_enrichments(self, pipeline_keys: tuple[str, ...]) -> bool | None: ...


@dataclass
class ScopedEnrichmentActivation:
    """Fail-closed P3D state machine with injected side effects."""

    actions: EnrichmentActivationActions
    state: ActivationState = ActivationState.PRECHECK

    def preflight(self) -> None:
        if self.state is not ActivationState.PRECHECK:
            raise EnrichmentActivationRefused("PRECHECK_ALREADY_CONSUMED")
        if not self.actions.preflight():
            raise EnrichmentActivationRefused("PREFLIGHT_FAILED")
        self.state = ActivationState.PREFLIGHT_PASSED

    def qualify(self) -> None:
        if self.state is not ActivationState.PREFLIGHT_PASSED:
            raise EnrichmentActivationRefused("QUALIFICATION_ORDER_INVALID")
        if not self.actions.pre_rehearsal_qualify(CANONICAL_SCOPED_ENRICHMENTS):
            raise EnrichmentActivationRefused("QUALIFICATION_FAILED")
        self.state = ActivationState.QUALIFIED

    def activate(self) -> None:
        if self.state is not ActivationState.QUALIFIED:
            raise EnrichmentActivationRefused("ACTIVATION_REQUIRES_QUALIFICATION")
        self.state = ActivationState.ACTIVATING
        try:
            self.actions.enable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
        except BaseException as error:
            try:
                confirmed = self.actions.disable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
            except BaseException as cleanup_error:
                self.state = ActivationState.ABORT_NOT_CONFIRMED
                raise EnrichmentActivationRefused("ABORT_NOT_CONFIRMED") from cleanup_error
            if confirmed is False:
                self.state = ActivationState.ABORT_NOT_CONFIRMED
                raise EnrichmentActivationRefused("ABORT_NOT_CONFIRMED")
            self.state = ActivationState.ABORTED
            raise EnrichmentActivationRefused("ACTIVATION_FAILED") from error
        self.state = ActivationState.ACTIVE

    def abort(self) -> None:
        if self.state in {
            ActivationState.PREFLIGHT_PASSED,
            ActivationState.QUALIFIED,
            ActivationState.ACTIVATING,
            ActivationState.ACTIVE,
            ActivationState.ABORTED,
            ActivationState.ABORT_NOT_CONFIRMED,
        }:
            try:
                confirmed = self.actions.disable_scoped_enrichments(CANONICAL_SCOPED_ENRICHMENTS)
            except BaseException as error:
                self.state = ActivationState.ABORT_NOT_CONFIRMED
                raise EnrichmentActivationRefused("ABORT_NOT_CONFIRMED") from error
            if confirmed is False:
                self.state = ActivationState.ABORT_NOT_CONFIRMED
                raise EnrichmentActivationRefused("ABORT_NOT_CONFIRMED")
        self.state = ActivationState.ABORTED


if set(ENRICHMENT_SCHEDULES) != set(CANONICAL_SCOPED_ENRICHMENTS):
    raise RuntimeError("scoped enrichment schedule/registry mismatch")
