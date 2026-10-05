# PDI P3D Governed Production Rehearsal V0.1

Status: Workstream A public-contract repair candidate, awaiting independent
re-review. This document defines the
interfaces consumed by later WP8 implementation workstreams. It authorizes no
production operation by itself.

## Scope and end boundary

WP8 contains two ordered authorities:

1. **A — read-only production preflight.** A observes the frozen production
   context without persistent state, workload execution, Provider contact, or
   database writes. Its evidence says that the exact candidate is eligible for
   independent review.
2. **B — explicitly authorized production rehearsal.** A separately issued,
   single-use and time-bounded authorization binds the reviewed A evidence to
   one operation UUID and the exact six canonical enrichment pipelines. B may
   promote the already-qualified candidate, reload inert systemd assets, run
   each service exactly once, verify the resulting runtime ledger and
   invariants, and stop every service while timers remain disabled.

The B execution boundary is `WP8_REHEARSAL_REVIEWABLE_COMPLETE`: runtime,
invariant, and cleanup evidence is ready for a **separate B independent
review**. It is not the final WP8 lifecycle boundary. The authorized final
boundary is `AFTER_B_RUNTIME_LEDGER_INVARIANT_PROOF_AND_INDEPENDENT_REVIEW`.
The completion marker always records `independent_b_review_state=PENDING`
and `wp8_final_end_boundary_reached=false`; it cannot declare WP8 fully
complete, frozen, or activation-ready. No B review operational mechanism is
implemented in Workstream A.

Future production activation or cutover is **C**, is excluded from WP8, and
requires its own design, review,
authorization, state machine, and rollback policy. WP8 has no `ACTIVE`,
`ACTIVATED`, `READY_FOR_CUTOVER`, or `CUTOVER_COMPLETE` state or marker.

## Frozen authority chain

WP8 composes, but does not redefine, frozen authorities:

- Gate A supplies the qualified rollback source and protected rollback
  authority binding. WP8 does not create a new backup, restore, or Gate A.
- Gate B supplies the exact immutable candidate release authority.
- Gate C supplies inert systemd assets, profiles, registry, and its complete
  marker. WP8 does not rebind or reinstall them through this contract module.
- WP6 supplies the read-only pre-rehearsal context fingerprint.
- WP7 proves the six-service real-systemd path in a disposable environment.
- P3C remains an independent frozen production layer and must remain healthy.

Phase A evidence binds the exact Gate A/B/C operation identities and authority
fingerprints, candidate and rollback SHAs, WP6 context, routed database
identity, DB-derived enabled scopes, assets, P3C state, protected environment,
and registry. It also includes a strict `invariant_baseline` snapshot in both
the context hash and evidence hash. Thus A review and B authorization bind the
pre-B schema, route, Provider, Source, and sync facts rather than allowing B
to invent its own baseline. Collection time is intentionally absent so Phase
B can compare stable facts deterministically.

## Workstream A contracts

`pdi.production_ops.p3d_wp8_contracts` is an inert, pure module. It defines:

- `WP8PhaseAEvidenceV1` — deterministic A evidence and stable context hashes;
- `WP8AReviewResultV1` — an independent PASS review bound to exact A evidence;
- `WP8RehearsalAuthorizationV1` — one single-use B authorization;
- `WP8RehearsalStateV1` and `WP8RehearsalJournalEventV1` — strict state and
  tamper-evident journal contracts;
- `WP8RuntimeLedgerProofV1` — exact fresh 6/6 runtime proof shape;
- `WP8InvariantSnapshotV1` — the exact unchanged-authority schema used by A
  baseline and independently collected B final evidence;
- `WP8InvariantProofV1` — strict `before`/`after` equality proof bound to A;
- `WP8CleanupProofV1` — explicit six-service cleanup confirmation;
- `WP8RehearsalCompleteV1` — reviewable-complete marker bound to the terminal
  state and journal head;
- fixed enums, canonical fingerprints, and pure validation helpers.

The module performs no filesystem, database, Git, subprocess, systemd,
network, Provider, persistence, promotion, PipelineRun, or backup operation.
Operational workstreams must collect facts and then pass strict mappings into
these interfaces.

## Exact pipeline authority

The only accepted ordered pipeline tuple is imported from the frozen P3D
preparation authority:

1. `enrichment.nextcloud_text`
2. `enrichment.nextcloud_documents`
3. `enrichment.file_metadata`
4. `enrichment.immich_geo`
5. `enrichment.immich_metadata`
6. `enrichment.immich_ocr`

Missing, extra, duplicate, or reordered keys fail closed. Gmail,
integration-test, and caller-selected pipeline lists are outside the contract.

## Review and authorization separation

An A evidence object does not authorize B. An independent review record binds
the exact evidence and context fingerprints plus Gate A/B/C authority
bindings. The B authorization then binds that review to one canonical UUID,
candidate, rollback source, six-pipeline fingerprint, issue time, validity
window, and `single_use=true`.

Validation rejects evidence drift, wrong candidate or rollback source, changed
Gate binding, wrong pipeline set, replay, premature use, expiration, extra
fields, unsupported versions, and malformed identifiers. The review record is
not a self-declared reviewer identity and this contract does not invent PKI or
generic IAM.

Consumption status is mandatory and must be an exact boolean: `False` may
be eligible, `True` is replay, and `None`, missing, integers, strings, or other
unknown representations are rejected. This module neither reads nor writes
the later protected consumption store. Completion revalidates the exact
authorization against A and A review (including rollback, review-record hash,
all Gate identities/bindings and pipeline authority) at the execution start
and completion times. This eligibility recheck is not a new authorization or
a replay: it is bound to the already executed state and journal's exact
authorization fingerprint and operation UUID.

## State machine and failure terminals

The normal state order is:

`NEW` → `AUTHORIZATION_VERIFIED` → `PREREQUISITES_VERIFIED` →
`PRE_MUTATION_REVALIDATED` → `CURRENT_PROMOTED` → `SYSTEMD_RELOADED` →
`SERVICES_VERIFIED` → six ordered `SERVICE_N_EXECUTING` /
`SERVICE_N_VERIFIED` pairs → `SERVICES_EXECUTED` →
`RUNTIME_LEDGER_VERIFIED` → `INVARIANTS_VERIFIED` → `SERVICES_STOPPED` →
`REHEARSAL_COMPLETE`.

Before `CURRENT_PROMOTED`, a failure may terminate only as `FAILED`. From the
first mutation onward, a failure may terminate only as `ABORTED` after cleanup
is confirmed, or `ABORT_NOT_CONFIRMED` when it is not. The latter permits only
retryable cleanup recovery to itself or `ABORTED`. `REHEARSAL_COMPLETE`,
`FAILED`, and `ABORTED` are terminal.

Proof fingerprints cannot appear before their corresponding verified phase.
Completion is constructible only from a `REHEARSAL_COMPLETE` state whose
runtime, invariant, and cleanup fingerprints match the supplied strict proof
objects. Cleanup transitions take an exact `WP8CleanupProofV1`, not an opaque
fingerprint. The validated proof content and its hash are carried in state
and cleanup journal events. `ABORTED`, `SERVICES_STOPPED`, and the normal
`REHEARSAL_COMPLETE` require a PASS proof; `ABORT_NOT_CONFIRMED` requires a
FAIL/non-confirmed proof. Hash presence, clearing a failure code, or reusing
a failed proof cannot manufacture cleanup success.

On first failure, state and journal preserve `primary_failure_code`,
`failed_phase`, `failed_pipeline_key`, and `failure_mutation_boundary`
(`PRE_MUTATION` or `POST_MUTATION`). Recovery from `ABORT_NOT_CONFIRMED` may
update cleanup proof, cleanup failure, sequence/time/hash only. The first
failure identity and already verified runtime/invariant references cannot be
replaced; no normal workload transition can be replayed. Even individually
rehashed retry/state mappings are checked against the first failure event.

## Journal and failure boundary

Every journal event binds its sequence, operation UUID, candidate, A context,
authorization, transition, previous event hash, timestamp, evidence hashes,
and optional canonical pipeline. `pipeline_key` is exclusively the normal
service transition key implied by `SERVICE_N_EXECUTING`/`SERVICE_N_VERIFIED`;
`failed_pipeline_key` is exclusively failure provenance. A per-service
failure must bind the pipeline implied by its original failed phase. Outside
a service pair, only the fixed service-contract or runtime-ledger failure
categories may name a canonical pipeline identified by validation; other
authority failures have no failed pipeline. All twelve normal service
prefixes are valid recovery boundaries and require no failed pipeline.
The chain starts at sequence one, advances by
one, cannot regress in time, and cannot drift across authority identities.

Failures use fixed `WP8FailureCode` values. Raw exceptions, stderr, URLs,
credentials, Provider payloads, database rows, and personal content never
enter state, journal, or proof contracts. Cleanup failure is recorded
separately from the primary failure so a failed cleanup cannot erase or
rewrite the original cause.

## Runtime, invariant, and cleanup proof boundary

The runtime proof contains exactly six unique completed run UUIDs in canonical
pipeline order, six safe service/business-effect fingerprints and counts, and
zero failed, running, or unknown fresh runs. Candidate/context binding is
provided by the protected WP8 operation and journal; it does not assume those
columns exist in `pipeline_runs`.

The invariant proof requires exact equality of separately collected `before`
and `after` snapshots. The before snapshot must equal the snapshot already
bound into A evidence; matching two foreign snapshots is not sufficient.
The exact Alembic revision comes from the frozen P3C `contracts.HEAD`, not a
new migration authority. Snapshot facts are:

- schema and migration-tree fingerprints, exact Alembic revision;
- Principal/router, DB, Provider identities, enabled Scopes, Source/provenance,
  and sync-state fingerprints;
- protected environment, registry, unit/profile assets, and Gate A/B/C binding
  fingerprints;
- P3C state and systemd fingerprints (stable authority/health only, excluding
  ongoing writer counts, timestamps, or last-run metadata);
- disabled/inactive P3D, legacy writer and legacy enrichment timers;
- disabled Gmail and integration-test state.

Snapshot fixed states are validated on both sides; arbitrary rehashed after
values or wrong Alembic revision reject. P3D service inactivity, exact
promoted current and immutable candidate, and approved enrichment-only writes
are post-B requirements. They are not misrepresented as before/after
equality: current promotion and expected observation/enrichment writes are
explicitly authorized B changes. B must collect actual final facts; the
invariant builder does not copy A authorities into final observations.

Cleanup records an attempt for every canonical pipeline service and succeeds
only when all are inactive, all timers are disabled/inactive, and P3C remains
healthy. A non-confirmed cleanup remains a failure proof and cannot satisfy the
completion contract. `WP8RehearsalCompleteV1.build` requires the complete
validated journal chain in addition to strict proof objects; it binds the
execution authorization and all referenced identities. Parsing a completion
mapping alone proves its schema/self-hash, not actual authority. Later
consumers must resolve the protected referenced evidence and call
`validate_rehearsal_completion` to revalidate the entire closure. A is not an
operational evidence collector and creates no production proof.

## Canonical serialization and no-secret boundary

Every V1 mapping has an exact field set and is validated before use. Hashes are
lowercase SHA-256, candidate identities are lowercase 40-character Git SHAs,
operation identities are canonical UUID strings, and times are second-precise
UTC `Z` values. Canonical serialization reuses the frozen JSON rules: sorted
keys, compact separators, UTF-8, no floats, no NaN/Infinity, and no
`default=str` fallback. `wp8_contract_bytes` accepts only exact allowlisted
WP8 types (no duck typing or subclasses) and invokes that type's strict
parser before serialization. A raw mapping must go through its explicit
schema parser first. Malformed typed objects and stale self-hashes reject.
Journal builders sort unique evidence hashes; parsers require already sorted
unique input and reject an unsorted rehashed list. Every parse-successful
contract must preserve canonical bytes through parse/serialize/parse.

The frozen secret-material rejection remains defense in depth. No Principal or
Scope identifier, DSN, endpoint, password, token, OAuth value, protected raw
file, mail content, Provider content, or arbitrary exception text belongs in a
WP8 contract. Identity is represented only by reviewed non-secret counts,
fixed enums, canonical keys, UUIDs, SHAs, and fingerprints.
