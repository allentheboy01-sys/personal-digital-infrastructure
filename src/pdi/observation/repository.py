from datetime import datetime, timedelta
from typing import Protocol

from .models import (
    EnrichmentResource,
    EnrichmentSource,
    EnrichmentState,
    GeneratorIdentity,
    ObservationBatch,
    PublishResult,
    StatementView,
)


class ObservationRepository(Protocol):
    def publish(
        self,
        batch: ObservationBatch,
        *,
        completed_at: datetime,
        exclusive_generator_family: tuple[str, ...] = (),
        effect_sources: tuple[EnrichmentSource, ...] = (),
    ) -> PublishResult: ...

    def get_enrichment_state(
        self, resource_ref: str, generator: GeneratorIdentity
    ) -> EnrichmentState | None: ...

    def mark_running(
        self,
        resource_ref: str,
        generator: GeneratorIdentity,
        input_fingerprint: str,
        *,
        now: datetime,
        stale_after: timedelta,
    ) -> bool: ...

    def mark_failed(
        self,
        resource_ref: str,
        generator: GeneratorIdentity,
        input_fingerprint: str,
        *,
        now: datetime,
        error_code: str,
        error_message: str,
    ) -> None: ...

    def list_enrichment_resources(
        self,
        *,
        provider: str | tuple[str, ...],
        resource_type: str = "file",
    ) -> tuple[EnrichmentResource, ...]: ...

    def get_resource_statements(
        self,
        resource_ref: str,
        *,
        predicate: str | None,
        include_history: bool,
        limit: int,
    ) -> tuple[StatementView, ...] | None: ...
