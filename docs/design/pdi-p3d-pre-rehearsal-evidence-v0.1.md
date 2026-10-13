# P3D pre-rehearsal evidence V0.1

## Boundary

WP6 joins the three frozen preparation authorities to fresh live evidence:

```text
Gate A rollback qualification
  -> Gate B immutable release staging
  -> Gate C inert asset installation
  -> fresh protected configuration, routed Personal DB, files, current, and systemd reads
  -> validate_pre_rehearsal_preparation_contract()
```

WP6 does not execute a rehearsal. It does not promote `current`, reload or
mutate systemd, start a service or timer, execute a pipeline, create a
`PipelineRun`, persist cutover state, or create post-rehearsal ledger evidence.

## Explicit authority selection

`collect-evidence` requires canonical Gate A, Gate B, and Gate C operation
UUIDs. It never selects an operation by directory order, modification time, or
`latest` semantics. Production maps those IDs only below the fixed preparation
root:

- Gate A: `/var/lib/pdi-p3d/preparation/operation-<id>/authority`
- Gate B: `/var/lib/pdi-p3d/preparation/<id>`
- Gate C: `/var/lib/pdi-p3d/preparation/inert-assets/<id>`

The candidate release is fixed to `/opt/pdi/releases/<expected-sha>`. The
rollback source comes from the Gate A metadata and is cross-checked against the
Gate C marker. A caller-supplied rollback SHA, when present for compatibility,
is only an exact cross-check.

## Frozen authority revalidation

The collector validates every immutable state/event chain through `COMPLETE`.
Gate A metadata and its active release pin are revalidated. Gate B's final
release fingerprint is compared to a fresh immutable-tree verification. Gate
C's root-owned `0600` `complete.json` is parsed as
`P3DAssetInstallationCompleteV1`; its fingerprint must be carried by both the
`COMPLETE_MARKER_COMMITTED` and final `COMPLETE` events.

The frozen P3C authority remains `/var/lib/pdi-p3c/state.json`. It must remain
an exact frozen `PASS` state for the rollback source and Gate A P3C context. No
JSONL fallback exists, and private P3C baseline, verification, and old-target
values never enter WP6 output.

## Fresh evidence

Production configuration comes only from protected `/etc/pdi/pdi.env` and
`/etc/pdi/scoped/registry.toml`. The process environment cannot select the
Principal, database, credentials, or enabled scopes. Exactly one enabled
Principal is routed through the protected registry.

All Personal DB evidence is collected on one PostgreSQL connection after
`SET TRANSACTION READ ONLY` and verification that
`transaction_read_only=on`. Enabled scopes are freshly derived from the DB
identity repository. Gmail and integration-test must remain disabled.

The collector freshly reads the canonical seven unit files and six protected
profiles, verifies root ownership and exact modes, and recomputes the frozen
Gate C asset fingerprint. It also requires `current` to remain on the rollback
source, P3C systemd state to match Gate C, and all six P3D timers to be exactly
disabled and inactive.

Before returning PASS, the collector rechecks the protected environment,
registry, frozen P3C state, Gate C marker, and final Gate C journal authority
for drift.

## Runtime and output safety

Production execution is bound to the exact candidate interpreter, installed
module bytes, operator script, Git HEAD, and clean Git worktree. Git identity
checks run with a fixed environment including `GIT_OPTIONAL_LOCKS=0`.

The output is an allowlisted, non-secret schema of fixed states, counts, and
fingerprints. It never includes raw journals, markers, environment values,
database URLs, Provider secrets, profile bytes, Principal/Scope identifiers,
or private P3C evidence. Failure output remains the fixed
`EVIDENCE_REJECTED` category.

At this boundary runtime coverage is deliberately `0/6` and the
post-rehearsal ledger proof is `NOT_APPLICABLE_PRE_REHEARSAL`.
