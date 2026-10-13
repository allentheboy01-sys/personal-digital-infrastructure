# WP8 protected operation and proof closure V0.1

Status: development implementation; independent review and isolated test evidence
are separate from real-systemd qualification and production authorization.
This design composes the frozen WP8 contracts; it changes none of their shapes,
the eight backend methods, receipt schema, Phase A or Runtime Proof.

## Authorities and non-authorities

The human/operator installs root-controlled Phase A, independent A review,
the exact review record and a separately issued B authorization in a fixed
approval directory. The store never issues approvals. Their actual bytes,
ownership, modes, parent chain, exact operation UUID and review-record digest
are verified. A valid typed object, SHA commitment or `consumed=False` argument
does not establish this input authority. Root compromise is outside this model.

The production store root is `/var/lib/pdi-p3d-wp8` (root:root 0700); approval,
operation and consumption leaves are root:root 0600. Installation and permission
changes are not performed by these modules. Internal test roots are synthetic
fixtures, not production CLI overrides. There is no new CLI or activation API.

## Serialization and one commit point

`p3d_wp8_operation_store` coordinates its operation lock plus the existing P3C,
P3D, Gate B and Gate C control locks, in fixed nonblocking order. Missing or
untrusted legacy locks reject; they are not installed or replaced. It does not
hold the worker's formal sync lock while waiting for a service. Manual/root
maintenance exclusion still requires an authorized operational window; locks
do not make systemd atomic or prevent arbitrary privileged external mutation.

Authorization consumption is persisted before initial execution. A crash after
consumption burns the grant, including a crash before operation initialization.
Immutable, fsynced `commit-N.json` frames (strict state, journal event and proof
references) are the single authoritative commit point. Proof bytes precede their
establishing frame. Numbered state files are projections: missing ones can be
rebuilt; conflicting or corrupted ones reject. This is not an atomic transaction
across several files. Frozen serialization and no-replace creation are reused.

## Execution handoff and uncertainty

The thin internal coordinator rereads preflight twice before mutation. Every
promotion, reload, start and stop has a durable intent before the one actual
call, followed by a result commitment. START records the actual successful
same-call attestation; its live result object, not a parsed mapping, is passed
to the frozen Runtime Proof reader. Candidate/context, canonical order,
manager identity, invocation uniqueness, existing service hash and inactive
success are checked. Completion resolves sidecars and compares their commitments
to the actual establishing journal events and ledger service hashes.

The runtime boundary commits operation, consumed authorization, candidate,
Phase A context, pre-start journal head, manager and a independently captured
business baseline. Caller-selected hashes cannot supply it. Parsed sidecars
are only stored commitments and are never reconstructed as live service results.

A command and a journal write cannot be atomic. If promotion was issued but
not confirmed into the journal, the frozen state stays at its last verified
phase and a private uncertainty record forbids workload replay. It must not
fabricate CURRENT_PROMOTED or PRE_MUTATION FAILED. Known post-mutation failures
use independently verified cleanup and frozen ABORTED/ABORT_NOT_CONFIRMED.
An uncertain stop is not automatically reissued. Explicit cleanup-only recovery
is available only from validated ABORT_NOT_CONFIRMED; normal workload never
resumes from an interrupted operation. Expired grants cannot start new work.
Before the first mutation, an immutable manager/boot/continuity anchor binds
the pre-mutation journal state. Every mutation and explicit cleanup recovery
must match that original epoch. A new manager cannot stop same-named services
and claim cleanup for this old operation.

## Independent final facts

`p3d_wp8_postflight` independently rereads Gate A/B/C, rollback pin, immutable
candidate, promoted current, protected environment/registry/assets and P3C;
it does not call Phase A's rollback-current prerequisite collector as postflight.
It reuses the frozen schema/route/provider/source/sync projections. Final reads
are independently bracketed; matching hashes are not an atomic distributed
snapshot or proof against unobserved privileged ABA.

A pre-mutation business boundary contains only table/hashed-primary-key/row
digest projections. Final semantic receipt validation and exhaustive table diff
share one verified REPEATABLE READ / READ ONLY connection. Existing rows may
not disappear; old runs and receipts stay unchanged. Exactly the six bound new
runs and their new receipts are admitted. New statements and enrichment changes
must be receipt-scoped; old statements may only undergo their receipted
deactivation, not semantic replacement. Other observed PDI table changes reject.
No raw row, personal payload, credential or source locator is persisted.
This conservative boundary may reject concurrent unrelated writes; it does not
silently attribute them to this operation. There is no historical backfill.

Final authority is recollected independently twice, and the invariant check is
repeated after cleanup. Full proof objects, journal and completion references
are resolved, not treated as authority merely because their hashes are valid.
Six fresh inactive service facts are bracketed by same-manager observations
both before and after database/final projections, including after cleanup.
`load_completion()` is a non-persisting parser which resolves the protected
marker, journal, full proofs, intent/result sidecars, original manager anchor
and business boundary. It neither updates completion time nor replays work.
Completion is only `WP8_REHEARSAL_REVIEWABLE_COMPLETE`: independent B review
remains PENDING and the final WP8 boundary remains false.

## Qualification and stopping boundary

Deterministic filesystem/manager fixtures and real disposable PostgreSQL 16
exercise the coordinator and database semantics. They are explicitly NOT a
real WP8 systemd execution. The existing offline host-safe image is reused.
No production path, DB, Provider, service, VM or timer is used during this stage.

Next gate remains a separately authorized full-VM/dedicated-host qualification
on the backend's exact Debian/systemd identity. Docker/nspawn and WP7's 6/6
proof do not qualify this backend. Production installation, approval issuance,
human maintenance exclusion and production Phase B require separate authority.

Preserved open issues:

- BLOB_HASH_ACTIVE_CALL_PATH_AUDIT: required before Phase B workload.
- RESOURCE_ACCESS_ADAPTER_LIFECYCLE_AUDIT: open.
- FUTURE_C_APPLY_PARTIAL_TIMER_ENABLE_RISK: hard blocker before C.
