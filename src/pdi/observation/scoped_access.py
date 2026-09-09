"""Scope-bound remote enrichment credential composition."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from uuid import UUID

from pdi.adapters.base import ProviderFact
from pdi.provider_identity import ProviderIdentityRepository

from .errors import ObservationExtractionError
from .models import EnrichmentSource


EnrichmentFactory = Callable[[object, object, str | None], object]


class ScopedEnrichmentAccessResolver:
    """Resolve one exact Principal/Scope remote reader without fallback."""

    def __init__(
        self,
        principal_id: object,
        identities: ProviderIdentityRepository,
        bindings: object,
        secrets: object,
        factories: Mapping[str, EnrichmentFactory],
    ) -> None:
        self._principal_id = principal_id
        self._identities = identities
        self._bindings = bindings
        self._secrets = secrets
        self._factories = dict(factories)

    def resolve(self, source: EnrichmentSource) -> object:
        if source.observation_scope_id is None:
            raise ObservationExtractionError(
                "Legacy Source has no remote enrichment Scope provenance"
            )
        try:
            scope_id = UUID(source.observation_scope_id)
        except (TypeError, ValueError, AttributeError):
            raise ObservationExtractionError(
                "Enrichment Source Scope provenance is invalid"
            ) from None
        scope = self._identities.get_scope(scope_id)
        if scope is None or not scope.enabled:
            raise ObservationExtractionError(
                "Observation Scope is missing or disabled"
            )
        instance = self._identities.get_instance(scope.provider_instance_id)
        if instance is None or not instance.enabled:
            raise ObservationExtractionError(
                "Provider Instance is missing or disabled"
            )
        if instance.provider_type != source.provider:
            raise ObservationExtractionError(
                "Enrichment Source Provider does not match Scope"
            )
        native_id = None
        if scope.provider_account_id is not None:
            account = self._identities.get_account(scope.provider_account_id)
            if (
                account is None
                or not account.enabled
                or account.provider_instance_id != instance.id
            ):
                raise ObservationExtractionError(
                    "Provider Account is missing, disabled, or inconsistent"
                )
            native_id = account.provider_native_id
        binding = self._bindings.resolve(
            self._principal_id, scope.id, instance.provider_type
        )
        factory = self._factories.get(instance.provider_type)
        if factory is None:
            raise ObservationExtractionError(
                "Scoped remote enrichment is not configured"
            )
        try:
            material = self._secrets.resolve(binding.binding_ref)
            if not hasattr(material, "value"):
                raise TypeError
            return factory(binding, material, native_id)
        except ObservationExtractionError:
            raise
        except Exception:
            raise ObservationExtractionError(
                "Scoped remote enrichment adapter is unavailable"
            ) from None


@dataclass(frozen=True)
class ScopedImmichOCRReader:
    resolver: ScopedEnrichmentAccessResolver

    def get_source_ocr(self, source: EnrichmentSource):
        reader = self.resolver.resolve(source)
        method = getattr(reader, "get_asset_ocr", None)
        if method is None:
            raise ObservationExtractionError("Immich OCR reader is invalid")
        return method(source.provider_locator)


@dataclass(frozen=True)
class ScopedNextcloudContentReader:
    resolver: ScopedEnrichmentAccessResolver

    def open(self, source: EnrichmentSource) -> Iterable[bytes]:
        adapter = self.resolver.resolve(source)
        connect = getattr(adapter, "connect", None)
        open_provider = getattr(adapter, "open", None)
        if connect is None or open_provider is None:
            raise ObservationExtractionError("Nextcloud content reader is invalid")
        connect()
        fact = ProviderFact(
            provider=source.provider,
            kind="file",
            external_id=source.provider_locator,
            name=source.name,
            attributes={
                "path": source.path,
                "size": source.size,
                "mime_type": source.mime_type,
                "version_tag": source.version_tag,
                "content_hash": None,
            },
            raw=dict(source.metadata),
        )
        yield from open_provider(fact)
