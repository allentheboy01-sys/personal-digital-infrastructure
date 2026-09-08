# PDI Scope Incremental State v0.1

MU6 adds an expansion table whose authoritative identity is `(observation_scope_id, mechanism)`. The existing `provider_sync_state` table and its runtime repository remain unchanged. There is no dual write and live Nextcloud/Immich incremental execution remains legacy Provider-scoped.

Each Scope state owns an opaque checkpoint, optimistic version, reconciliation latch, and original timestamps. CAS affects exactly one Scope and mechanism. Credential rotation, endpoint changes, and physical Provider relocation do not change Scope identity. A new Scope starts with no row; `get_or_create` produces checkpoint NULL, version 0, and reconciliation false. This is not bootstrap, and no checkpoint is inherited from another Scope or legacy state.

The administrative copy operation requires an exact mapping of every existing legacy `(provider, mechanism)` row to an approved Scope. It locks and validates the complete set in one transaction, verifies Scope Provider Type, copies state and timestamps without decoding the checkpoint, leaves legacy rows untouched, and treats an exactly equivalent existing target as idempotent. Any mismatch aborts without overwriting state.

Production cutover must stop the legacy writer, prove stable legacy state, copy and verify exact equivalence, start only the Scope-aware writer, and never operate both writers for one logical stream. No automatic bootstrap or recovery is allowed.

Legacy state may be retired only after Source provenance is backfilled, every ingestion context has a stable Scope, live ingestion and formal pipelines select Principal and Scope safely, Resource Access uses Scope credentials where required, all legacy state is verified copied, legacy writers are disabled, rollback criteria are satisfied, and no runtime can recreate legacy state.
