# PDI P3D Governed Production Rehearsal V0.1

Status: Workstream A public-contract design. This document defines the
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

WP8 ends at `WP8_REHEARSAL_REVIEWABLE_COMPLETE`. Future production activation
or cutover is **C**, is excluded from WP8, and requires its own design, review,
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
and registry. Collection time is intentionally absent so Phase B can compare
stable facts deterministically.

## Workstream A contracts

`pdi.production_ops.p3d_wp8_contracts` is an inert, pure module. It defines:

- `WP8PhaseAEvidenceV1` — deterministic A evidence and stable context hashes;
- `WP8AReviewResultV1` — an independent PASS review bound to exact A evidence;
- `WP8RehearsalAuthorizationV1` — one single-use B authorization;
- `WP8RehearsalStateV1` and `WP8RehearsalJournalEventV1` — strict state and
  tamper-evident journal contracts;
- `WP8RuntimeLedgerProofV1` — exact fresh 6/6 runtime proof shape;
- `WP8InvariantProofV1` — post-rehearsal production invariant proof shape;
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
objects.

## Journal and failure boundary

Every journal event binds its sequence, operation UUID, candidate, A context,
authorization, transition, previous event hash, timestamp, evidence hashes,
and optional canonical pipeline. The chain starts at sequence one, advances by
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

The invariant proof requires disabled/inactive P3D timers, inactive P3D
services, healthy unchanged P3C, disabled legacy enrichment, exact current and
immutable candidate, unchanged protected environment/registry/assets and Gate
bindings, unchanged schema and routed identities, disabled Gmail and
integration-test, and only approved enrichment business writes.

Cleanup records an attempt for every canonical pipeline service and succeeds
only when all are inactive, all timers are disabled/inactive, and P3C remains
healthy. A non-confirmed cleanup remains a failure proof and cannot satisfy the
completion contract.

## Canonical serialization and no-secret boundary

Every V1 mapping has an exact field set and is validated before use. Hashes are
lowercase SHA-256, candidate identities are lowercase 40-character Git SHAs,
operation identities are canonical UUID strings, and times are second-precise
UTC `Z` values. Canonical serialization reuses the frozen JSON rules: sorted
keys, compact separators, UTF-8, no floats, no NaN/Infinity, and no
`default=str` fallback.

The frozen secret-material rejection remains defense in depth. No Principal or
Scope identifier, DSN, endpoint, password, token, OAuth value, protected raw
file, mail content, Provider content, or arbitrary exception text belongs in a
WP8 contract. Identity is represented only by reviewed non-secret counts,
fixed enums, canonical keys, UUIDs, SHAs, and fingerprints.
