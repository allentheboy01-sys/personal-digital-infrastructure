from typing import Protocol

from .models import ProviderRelationInventory, RelationSyncResult
from .repository import (
    ResourcePersonRelationRepository,
    ScopedResourcePersonRelationRepository,
)


class RelationInventoryAdapter(Protocol):
    provider: str

    def connect(self) -> None: ...
    def scan(
        self, person_external_ids: tuple[str, ...]
    ) -> ProviderRelationInventory: ...


class ResourcePersonRelationSyncService:
    def __init__(
        self,
        adapter: RelationInventoryAdapter,
        repository: ResourcePersonRelationRepository,
    ) -> None:
        self._adapter = adapter
        self._repository = repository

    def sync_once(self) -> RelationSyncResult:
        self._adapter.connect()
        identities = self._repository.list_active_person_external_ids(
            self._adapter.provider
        )
        inventory = self._adapter.scan(identities)
        if inventory.provider != self._adapter.provider:
            raise ValueError("relation inventory provider mismatch")
        return self._repository.reconcile_provider_relations(
            inventory.provider, inventory.pairs
        )


class ScopedResourcePersonRelationSyncService:
    def __init__(
        self,
        adapter: RelationInventoryAdapter,
        repository: ScopedResourcePersonRelationRepository,
        provider_type: str,
    ) -> None:
        if adapter.provider != provider_type:
            raise ValueError("Relation adapter Provider does not match Scope")
        self._adapter = adapter
        self._repository = repository

    def sync_once(self) -> RelationSyncResult:
        self._adapter.connect()
        identities = self._repository.list_active_person_external_ids()
        inventory = self._adapter.scan(identities)
        if inventory.provider != self._adapter.provider:
            raise ValueError("relation inventory Provider mismatch")
        return self._repository.reconcile_relations(inventory.pairs)
