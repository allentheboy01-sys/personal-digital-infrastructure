# PDI Scope-Aware Ingestion Runtime v0.1

MU7 adds an internal composition path: authenticated Principal → fail-closed Personal DB router → Scope lookup inside that database → immutable `ObservationContext` → trusted Provider adapter → Scope-bound Source and incremental-state repositories → existing Matcher and SyncEngine.

`ProviderFact` remains Provider-native data. `ScopeBoundRepository` translates existing Provider-oriented Source lookups/listings into one Scope namespace and copies Source actions through a write firewall: NULL provenance is bound to the current Scope, matching provenance is accepted, and cross-Scope or Provider-mismatched writes fail. Consequently authoritative full reconciliation and tombstones can affect only the bound Scope.

`ScopeBoundProviderSyncStateRepository` exposes the legacy state interface expected by existing algorithms but reads and writes only `observation_scope_sync_state`. It validates Provider Type and never reads, writes, or falls back to `provider_sync_state`; dual write is forbidden. Bootstrap and recovery therefore retain existing explicit semantics inside one Scope.

Runtime construction rejects missing, disabled, or inconsistent Scope/Instance/Account identities and adapter Provider mismatch before scanning. Adapter credentials remain trusted application-composition input: MU7 proves Provider Type alignment, not generic remote credential ownership.

The production `pdi.main`, `pdi.operational`, timers, DataStatus, Resource Access credential routing, and legacy runtime remain unchanged. Scope IDs and databases are not AI-selectable. Production scoped ingestion remains disabled pending later orchestration and credential-binding Gates.
