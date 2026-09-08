# PDI Source Observation Provenance v0.1

MU5 transitions Source identity from the legacy `(provider, external_id)` namespace to `(observation_scope_id, external_id)` within one Personal PDI database. `provider` remains a Provider Type compatibility/query projection; it is not authoritative identity for scoped Sources.

`asset_sources.observation_scope_id` is temporarily nullable. NULL means only “legacy Source not yet provenance-migrated”; it never means global, shared, or authorization-free. Scoped identities use a unique partial index on Scope and external ID. Legacy NULL rows retain a separate unique partial index on Provider Type and external ID.

The administrative backfill accepts a complete Provider Type to approved Scope mapping, locks and validates the whole Source set, and updates only `observation_scope_id` in one transaction. Missing mappings, mismatched Provider Instances, identity collisions, or conflicting existing provenance abort the whole operation. Repeating the exact mapping is idempotent. Source, Asset, Blob, relationship, activity, deletion, and metadata identities remain unchanged.

MU5 does not change ProviderFact, adapters, SyncEngine, provider sync state, formal pipelines, Resource Access, or public query contracts. Live ingestion therefore remains legacy/unscoped. A later controlled Harry procedure must create approved Instance/Account/Scope records, preflight provider counts, atomically backfill every Source, prove zero NULL rows and stable Source IDs, and leave incremental state untouched.

NULL support may be removed only after every production Source is backfilled, every ingestion and lookup/reactivation path supplies Scope, Resource Access binds the correct Scope credential, no formal pipeline can create an unscoped Source, and qualification proves new NULL Sources are impossible.
