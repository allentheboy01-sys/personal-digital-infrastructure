from typing import Protocol

from .models import EnumerablePersonInventory, PersonSyncResult
from .repository import PersonRepository, ScopedPersonRepository


class EnumerablePeopleAdapter(Protocol):
    provider: str

    def connect(self) -> None: ...
    def scan(self) -> EnumerablePersonInventory: ...


class PersonSyncService:
    def __init__(
        self,
        adapter: EnumerablePeopleAdapter,
        repository: PersonRepository,
    ) -> None:
        self._adapter = adapter
        self._repository = repository

    def sync_once(self) -> PersonSyncResult:
        self._adapter.connect()
        inventory = self._adapter.scan()
        return self._repository.reconcile_inventory(
            inventory.provider,
            inventory.identities,
        )


class ScopedPersonSyncService:
    def __init__(
        self,
        adapter: EnumerablePeopleAdapter,
        repository: ScopedPersonRepository,
        provider_type: str,
    ) -> None:
        if adapter.provider != provider_type:
            raise ValueError("Person adapter Provider does not match Scope")
        self._adapter = adapter
        self._repository = repository
        self._provider_type = provider_type

    def sync_once(self) -> PersonSyncResult:
        self._adapter.connect()
        inventory = self._adapter.scan()
        if inventory.provider != self._provider_type:
            raise ValueError("Person inventory Provider does not match Scope")
        return self._repository.reconcile_inventory(inventory.identities)
