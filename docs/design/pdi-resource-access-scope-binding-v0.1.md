# PDI Resource Access Scope Binding v0.1

Status: MU8 implementation contract. Production remains disabled.

## Authorization boundary

Legacy Resource Access selects an adapter from a Provider Type mapping. That
composition remains available for the current single-user runtime, but it is
not safe for multi-account use: Provider Type is a compatibility projection,
not an authorization identity.

Scoped Resource Access uses this fixed order:

1. the authentication/runtime layer supplies a Principal;
2. the fail-closed Principal router selects exactly one Personal PDI database;
3. `resource_ref` resolves an Asset and an active Source in that database;
4. the Source supplies its persisted Observation Scope ID;
5. the Scope, Instance, optional Account, enabled state, and Provider Type are
   validated in the same Personal database;
6. the exact `(Principal, Observation Scope)` control-plane binding is resolved;
7. protected secret material constructs the Provider-specific adapter;
8. that adapter opens only the already-selected Source.

The consumer cannot supply a database, Scope, binding, account, credential, or
Provider adapter. `pdi:resource:<asset UUID>` remains unchanged and is not an
authorization capability.

## Control-plane and secret boundary

`ProviderAccessBinding` is non-secret metadata: Principal, Scope, Provider
Type, an opaque binding reference, and enabled state. Scope UUIDs are
Personal-database-local, so the registry key is `(Principal, Scope)`, never a
bare Scope UUID.

Actual API keys, passwords, OAuth tokens, endpoints containing secrets, and
authorization headers are supplied by a protected injected secret resolver.
They are absent from Personal World tables, Source metadata, committed binding
records, representations, and sanitized errors. Provider-specific factories
own interpretation of this protected material. Resource Access orchestration
does not implement Immich or Nextcloud authentication.

Changing protected material for an existing binding rotates credentials while
preserving Principal, Scope, Source, Asset, and resource-ref identity. A newly
composed runtime sees the new material. Authentication failure does not cause
fallback to another Scope, another Principal, or a legacy/global adapter.

## Source selection and adapter selection

Representation and text Source projections privately include Source ID and
nullable Observation Scope ID. The value always comes from the selected Source
row, never consumer input. A NULL value denotes an unbackfilled legacy Source
and is rejected by scoped access. The separately composed legacy runtime may
continue to serve transition traffic until production cutover is qualified.

Representation access preserves the existing single-eligible-Source rule. Text
access preserves deterministic same-content Source selection. After either
path selects a Source, its Scope permanently fixes the credential path; the
resolver cannot choose a different Source or Scope.

The existing byte limits, Content-Type and Content-Length checks, Range rules,
hash verification, UTF-8 window semantics, concurrency bounds, cancellation,
and stream-close behavior are unchanged.

## Lifecycle and isolation

Active access is denied when the Scope, Instance, optional Account, or access
binding is missing, disabled, or inconsistent. A Source/Instance Provider Type
mismatch is denied before secret resolution or Provider contact. Account-less
Scopes remain valid and may have bindings.

The scoped runtime is built only after Principal database routing. Reusing the
same Scope UUID in two Personal databases therefore cannot cross-select a
credential: each Principal resolves a distinct database and registry namespace.
A resource ref absent from the routed database is not searched elsewhere.

Provider adapters created by the scoped resolver are owned by the scoped
runtime and closed deterministically. Concurrency remains bounded by the two
existing service-level limits rather than multiplied per Scope.

## Deferred boundaries

MU8 uses synthetic adapters and secrets and makes no real Provider calls. It
proves that PDI selects the configured adapter for the exact Source Scope; it
cannot prove that a remote secret belongs to the claimed remote account.
Nextcloud and Immich user-scoped credential/visibility qualification belongs to
MU9 and MU10.

MU8 does not change schema, ResourceRef, Query, MCP tools, `pdi.main`, formal
pipelines, production configuration, Source backfill, checkpoint copy, or
production runtime composition. Production scoped Resource Access remains off.
