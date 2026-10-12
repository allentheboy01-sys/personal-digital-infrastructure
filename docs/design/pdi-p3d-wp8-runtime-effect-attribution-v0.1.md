# PDI P3D WP8 Runtime Effect Attribution V0.1

Status: implementation candidate. This design adds a causal database binding
for WP8 Runtime Proof. It does not authorize rehearsal, consume an operation
authorization, start systemd, contact a Provider, or backfill historical
evidence.

## Causal chain

The proof uses an exact chain rather than time or count correlation:

```text
systemd InvocationID
  -> SHA-256 invocation fingerprint in the same successful service result
  -> unique pipeline_runs.invocation_fingerprint
  -> run UUID passed to the enrichment publisher
  -> append-only effect receipt committed in the same transaction as effects
  -> receipt statement/enrichment identities re-read from one read-only DB snapshot
```

The raw InvocationID is never persisted. The service backend's typed
attestation remains only a same-call verified handoff; it is not an
authorization, signature, persistence record, or causality proof by itself.
Runtime Proof requires the database chain above in addition to that
attestation.

Historical `pipeline_runs` receive a null invocation fingerprint and no
receipt. They remain valid historical health records but are unproven for WP8
causal attribution. There is no time-window, count-equality, nearest-run, or
synthetic backfill fallback.

## Invocation binding

The scoped production enrichment entrypoint accepts only systemd's canonical
32-lowercase-hex `INVOCATION_ID`, immediately hashes it, and passes only that
digest into the formal runner. Absence preserves manual/development execution
compatibility but makes the run ineligible for WP8 Runtime Proof. A present
malformed value fails with the fixed safe entrypoint result.

`pipeline_runs.invocation_fingerprint` is nullable for historical and manual
runs, exactly 64 lowercase hexadecimal characters when present, and unique
across the Personal DB. A database trigger rejects every attempt to change an
existing row's invocation fingerprint, including null-to-value, value-to-null,
and value-to-different-value transitions; terminal status updates remain
allowed. The existing run domain/read APIs stay unchanged.
The formal runner supplies a frozen internal run context containing run UUID,
pipeline key, and invocation digest to its configured executor.

## Same-transaction effect receipt

`pipeline_run_effect_receipts` contains one V1 row for each successful
`PostgreSQLObservationRepository.publish()` performed with a qualified run
context. It contains only UUIDs (including the exact Source IDs supplied to
the extractor), canonical pipeline/generator keys, fixed counts, timestamps,
and SHA-256 fingerprints. It contains no statement value,
Provider payload, Source locator, credential, raw invocation, DSN, or exception
text.

The receipt is added to the exact SQLAlchemy Session that creates/deactivates
statements and completes `resource_enrichments`; one commit makes all of them
durable or none of them durable. A database trigger locks and validates that
the bound run is a running enrichment run with the same pipeline key and a
non-null invocation fingerprint. A second trigger rejects receipt update or
delete. Foreign keys use `RESTRICT`.

The receipt commits sorted statement UUID sets, exact cardinalities, the
completed enrichment identity/fingerprint, and a SHA-256 commitment over every
semantic field of all affected statement rows: predicate, typed value,
generator, evidence source kind/locator, confidence, timestamps and current
state. Those potentially personal values are hashed in-process and are never
stored in the receipt or emitted. An idempotent publish records zero
created/deactivated statements and the exact current statement identities. A
deactivation-only publish records the exact old rows and an empty current set.
A failed publish cannot retain a receipt or partial business effects from that
transaction.

An entire run in which every resource is skipped before `publish()` has no
receipt. Runtime Proof deliberately rejects that run: absence of a committed
effect fragment is not converted into claimed business-effect evidence.

The worker also passes the exact `EnrichmentResource.sources` tuple used for
extraction into the same publish call. Before inserting a receipt, that
transaction locks and verifies every supplied Source against the receipt
subject, its enabled Scope, enabled Provider Instance, optional enabled
Account, and the pipeline's fixed Provider set. The receipt stores the sorted
Source UUID set and a commitment to its Provider/Scope/Instance/Account
identity. Missing, stale, disabled, cross-Provider or substituted Source
bindings roll back the receipt and business effects together.

## Read-only Runtime Proof

`WP8RuntimeProofReader` accepts the actual six private backend service results
in canonical order plus the already-authoritative rehearsal operation UUID and
runtime-boundary fingerprint. It never constructs authorization from those
values.

The reader resolves the trusted Principal route, recomputes the exact Phase A
route projection (Principal, database ref, environment-key identity and
connected database/user/address/port), then performs every database query
through one PostgreSQL
`REPEATABLE READ, READ ONLY` connection. It verifies candidate Alembic head,
Phase A database identity, DB-derived enabled Scopes and Source provenance.
For each service it requires:

- a successful inactive same-call service result and exact typed attestation;
- exactly one completed enrichment run with the attested invocation digest;
- at least one append-only receipt bound to that run and pipeline;
- an allowlisted generator for that canonical pipeline;
- exact receipt canonical fingerprint and sorted unique identity sets;
- exact current enrichment state and actual statement UUID/state/timestamp;
- a recomputed semantic commitment over the actual statement contents and
  provenance fields;
- the exact receipt Source set, pipeline Provider allowlist, enabled
  Scope/Instance/Account identity and recomputed Source binding commitment.

It then builds the existing frozen `WP8PipelineRunProofV1` records and
`WP8RuntimeLedgerProofV1`. It neither creates a `PipelineRun` nor writes a proof
or operation journal. Missing, stale, duplicate, malformed, foreign-principal,
cross-route, wrong-context, or unreceipted evidence fails closed. Public reader
failures normalize routing, URL and database exceptions to one fixed
non-sensitive rejection code.

## Migration and rollback-source separation

Live candidate schema head is `f6b8d0e2a435`. Upgrade from
`e5a7b9d1f324` is additive and preserves historical rows as unproven null
bindings. Downgrade is allowed only while both invocation bindings and receipts
are empty; otherwise it stops before destructive DDL.

Gate A's already-qualified rollback source still expects
`e5a7b9d1f324`. That source authority is intentionally not rebound to the new
candidate head. Candidate/live schema authority and rollback-source authority
remain separate.

Existing Personal DB runtime roles already have explicit table grants. The
candidate migration copies the existing `pipeline_runs` table ACL to the new
receipt table without assuming a role name; a newly provisioned database still
receives the provisioner's normal post-migration all-table grant. Trigger
functions use schema-qualified relations and a fixed `pg_catalog, public`
search path.

A disposable full schema+data PostgreSQL archive round-trip restores data
before post-data triggers and is part of qualification evidence. A data-only
restore into an already migrated schema is not established by this change;
the completed-run insert guard intentionally remains active. Any future
trigger-management restore procedure is a separately reviewed restore
authority boundary, not a runtime exception.

## Non-authorities

Receipt hashes are commitments, not signatures. The receipt is not an
operation/journal authorization or a general anti-replay mechanism. Runtime
Proof does not prove Provider freshness, does not permit activation/cutover,
and cannot turn pre-migration historical data into causal evidence. Production
migration and rehearsal remain separately reviewed and authorized gates.
