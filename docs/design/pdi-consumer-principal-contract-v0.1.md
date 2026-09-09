# Principal-bound PDI consumer contract v0.1

MU12 defines the authorization boundary between an authenticated host session
and one Personal PDI World. The trusted host establishes a
`TrustedPrincipalContext`; the model never constructs it. The
`PrincipalBoundConsumerRuntimeFactory` resolves that Principal through the MU3
registry/router, opens exactly the configured Personal database, and returns an
immutable, read-only runtime. There is no default Principal, database URL
fallback, global current Principal, thread-local authorization, or runtime
switch operation.

The generic contract lives in `pdi.consumer`, below protocol adapters. It
contains no MCP dependency and can later be consumed by DeepSeek Harness or
another trusted application. A host must authenticate the user, resolve the
Principal, and bind the runtime before exposing capabilities. An HTTP header or
model-produced field is not trusted merely because it contains a Principal ID.

## Read capabilities and MCP

The runtime exposes DB-local Query, Resource Query, Rich Retrieval, Observation
reads, and optionally MU8 Scope-bound text/representation access. It does not
expose repositories, engines, routing registries, ingestion, sync, bootstrap,
recovery, reconciliation, enrichment execution, provisioning, or credential
operations. `create_principal_bound_server` adapts an already-bound runtime;
its tools retain business arguments and expose no Principal, database, Scope,
account, binding, or credential selector.

For stdio, one process/session owns exactly one bound runtime. A future
multiplexed host must authenticate each request/session before selecting a
runtime, and must never accept an unauthenticated client header as sufficient
Principal proof. DeepSeek Harness should receive only these read capabilities,
not the Principal router, database registry, Scope registry, or secret
registry.

`pdi:resource:<asset UUID>` remains unchanged and is interpreted only inside
the bound Personal database. Equal Resource, Person, or Scope UUIDs in two
Personal databases do not cross that physical boundary.

## Provider access and unavailable capabilities

When configured, Resource Access is supplied by the existing MU8
Principal-plus-Scope runtime. Source provenance fixes the Scope, whose trusted
binding selects the Provider credential; authentication failure has no other
Principal, Scope, or global Provider fallback. The new consumer composition
never loads global database, Immich, or Nextcloud settings.

Provider-native Immich semantic retrieval is `FAIL_CLOSED_DISABLED` in MU12.
The legacy adapter is Provider-global and therefore is not instantiated. Local
Rich Retrieval remains available; a provider-semantic primary reports the
existing explicit capability-unavailable error.

DataStatus is also `FAIL_CLOSED_DISABLED`: legacy status depends on formal
single-user pipeline and provider-scoped checkpoint semantics. MU13 may expose
a Scope-aware status after formal pipeline promotion. The new runtime never
uses `PostgreSQLProviderSyncStateRepository`.

Legacy `create_runtime_server` and `python -m pdi_mcp` remain explicit
single-user composition paths and are not silently promoted. MU12 changes no
production orchestration, schema, authentication system, or deployment.
