# PDI P3D Preparation Contracts V0.1

Status: WP1 contract and design layer only. This document does not authorize or
implement a backup, release build, production install, cutover, evidence read,
or rehearsal.

## Boundary

P3D preparation has three independent gates:

1. Gate A qualifies the rollback database snapshot and its matching runtime.
2. Gate B stages an exact, inert, immutable release.
3. Gate C installs inert systemd/configuration assets while proving that the
   active release and P3C writer state did not change.

Preparation state is not `P3DControl` cutover state. Preparation never promotes
`/opt/pdi/current`, starts or enables units, invokes a pipeline, or creates a
`PipelineRun`. Later operational work packages may consume these contracts, but
WP1 contains no production wiring.

The normative Python definitions are in
`pdi.production_ops.p3d_preparation_contracts`.

## Version and field policy

Every authoritative V1 object has an explicit version field. A V1 parser
requires the exact V1 field set: a missing field, an additional field, or an
unsupported version fails closed. A future major version needs a distinct
parser and migration policy; it cannot silently widen V1.

The versioned authorities are:

- `P3DRollbackMetadataV1`
- `OSRuntimeManifestV1`
- `WheelhouseManifestV1`
- `ReleaseInputBundleManifestV1`
- `RollbackReleasePinV1`
- `PreparationOperationStateV1`
- `PreparationJournalEventV1`
- `P3DAssetInstallationCompleteV1`

Git identities are lowercase 40-character hex strings. Content identities are
lowercase 64-character SHA-256 strings. UUIDs use lowercase canonical text.
Timestamps use second-precision UTC `YYYY-MM-DDTHH:MM:SSZ`. Package versions
are pinned values rather than comparison expressions.

## Tool identity

`OperatorToolIdentity` separates four authorities:

- allowlisted tool name;
- semantic tool version;
- tool artifact SHA-256;
- tool source Git SHA.

Artifact and source identities are never interchangeable. The allowlist covers
backup export, restore qualification, release bundle build, release bootstrap,
and inert asset installation. Rollback metadata also checks the expected tool
role for export and restore. Candidate identity and operator-tool identity are
separate authorities bound by the preparation contract: Gate A requires the
complete external `BACKUP_EXPORT` plus `RESTORE_QUALIFY` authority set, Gate B
requires the external `RELEASE_BOOTSTRAP` authority, and Gate C requires only
`INERT_ASSET_INSTALL`, whose source SHA must equal the candidate. Release bundle
builder and Gate C marker tools remain exact-candidate-bound.

## Gate A: rollback qualification

`P3DRollbackMetadataV1` binds the exact snapshot, dump and aggregate evidence,
source release/runtime/system-runtime fingerprints, target candidate, database
and P3C context fingerprints, restore invariants, repository identity, and the
export/restore tool identities. `ROLLBACK_METADATA_READY=YES` is accepted only
when every fixed qualification conclusion is present and equal to its required
value. The rollback source release must equal `SOURCE_SHA` and must differ from
the target candidate.

The Gate A state path is:

```
NEW -> SOURCE_VERIFIED -> SNAPSHOT_EXPORTED -> DUMP_COMPLETED
    -> BACKUP_SNAPSHOT_CREATED -> RESTORE_STARTED -> RESTORE_COMPLETED
    -> RESTORE_QUALIFIED -> RUNTIME_QUALIFIED -> DB_RUNTIME_COMPATIBLE
    -> SOURCE_RELEASE_PINNED -> METADATA_COMMITTED -> COMPLETE
```

Any nonterminal phase may transition to `FAILED` using only a
`P3D_ROLLBACK_*` code. `FAILED` and `COMPLETE` are terminal. Because metadata
can only follow `SOURCE_RELEASE_PINNED`, it cannot be committed before restore,
runtime, compatibility, and pin proof are complete.

`RollbackReleasePinV1` records an explicit `ACTIVE` or `RETIRED` state. There
is no implicit garbage collection, automatic deletion, or implicit retirement.

## Gate B: inert release staging

`OSRuntimeManifestV1` is a deterministic, exact inventory of the approved OS,
architecture, package versions, system Python/ABI, native packages, and runtime
file fingerprint. The native-package set is nonempty, duplicate-free, and a
subset of the exact approved package-name/version authority. `WheelhouseManifestV1`
binds the OS manifest and a sorted,
duplicate-free wheel inventory containing exact package versions, filenames,
hashes, and compatibility tags.

`ReleaseInputBundleManifestV1` binds the Git bundle, wheel, sdist, wheelhouse,
OS runtime, systemd assets, build workflow, artifact, provenance, and builder
tool to one candidate SHA. Mixed-candidate input is rejected.

The Gate B state path is:

```
NEW -> ARTIFACT_VERIFIED -> OS_RUNTIME_VERIFIED -> STAGING_CREATED
    -> SOURCE_CHECKED_OUT -> VENV_BUILT -> RUNTIME_VERIFIED
    -> IMMUTABILITY_VERIFIED -> FINAL_RENAME_COMMITTED
    -> FINAL_VERIFIED -> COMPLETE
```

Final rename cannot precede immutability proof. Gate B has no `PROMOTED` or
`ACTIVE` phase and cannot modify the active release pointer. Failures use only
`P3D_RELEASE_STAGE_*` codes.

## Gate C: inert asset installation

The Gate C state path is:

```
NEW -> PREREQUISITES_VERIFIED -> REGISTRY_VERIFIED
    -> DB_EVIDENCE_VERIFIED -> PROFILES_RENDERED
    -> OFFLINE_STATIC_VERIFIED -> FILES_PARTIALLY_INSTALLED|FILES_INSTALLED
    -> FILES_INSTALLED -> FINAL_STATIC_VERIFIED
    -> SYSTEMD_QUIET_VERIFIED -> COMPLETE_MARKER_COMMITTED -> COMPLETE
```

`FILES_PARTIALLY_INSTALLED` permits convergence retry for the same operation
and candidate only. A different candidate cannot take over that state. The
complete marker is unreachable until DB evidence, final static verification,
and systemd quietness have all been recorded. Failures use only
`P3D_ASSET_INSTALL_*` codes.

`P3DAssetInstallationCompleteV1` binds rollback metadata, registry, routed DB,
enabled Scope, installed unit/profile assets, operation and tool identity. It
requires:

- active symlink before and after both equal
  `/opt/pdi/releases/<rollback_source_sha>`;
- P3C systemd fingerprint before equals fingerprint after;
- P3D timers are `DISABLED_INACTIVE`;
- the installed manifest is the exact canonical 13-file set: the generic
  scoped-pipeline service, six canonical enrichment timers, and six canonical
  pipeline profiles, with no missing, duplicate, extra, or arbitrary paths;
- service/timer assets are root-owned `0644`, while profiles are root-owned
  `0600`;
- candidate and rollback source identities differ.

The asset fingerprint covers that complete canonical manifest, so a self-consistent
subset is not an installation authority.

## Preparation prerequisite for collect-evidence

`validate_pre_rehearsal_preparation_contract()` is a pure comparison. It does
not read a path, database, unit, or process and does not mutate control state.
A later work package must supply freshly collected authoritative evidence. The
function compares the marker against the live candidate, rollback snapshot and
metadata hash, registry, routed DB, enabled Scope, asset, active symlink, P3C
systemd, and P3D timer fingerprints. Marker existence alone is insufficient.

WP1 does not wire this comparison into `collect-evidence`.

## Canonical serialization and fingerprints

`canonical_json_bytes()` is the only authority serialization for this layer:

- UTF-8 JSON;
- keys sorted recursively;
- fixed compact separators;
- enums represented by their value;
- UTC timestamps and UUIDs in canonical text;
- sets represented as sorted arrays;
- integers and booleans preserve their JSON types;
- floats, NaN, infinity, arbitrary objects, and `default=str` are rejected.

The following functions SHA-256 that canonical representation:

- `rollback_metadata_fingerprint`
- `os_runtime_manifest_fingerprint`
- `wheelhouse_manifest_fingerprint`
- `release_bundle_fingerprint`
- `release_pin_fingerprint`
- `source_release_fingerprint`
- `source_runtime_fingerprint`
- `asset_installation_fingerprint`
- `preparation_journal_fingerprint`

Ordering changes do not change a fingerprint; semantic changes do.

## State and journal envelope

`PreparationOperationStateV1` binds one operation, preparation gate, candidate,
phase, timestamps, the complete gate-specific operator-tool authority set,
evidence fingerprint, and optional fixed failure code. Gate A records both
external export and restore tools; Gate B records its external bootstrap tool;
only Gate C requires its operator source SHA to equal the candidate. Time cannot
move backward.

`PreparationJournalEventV1` adds a positive sequence, from/to phases, sorted
unique evidence fingerprints, a phase-compatible operator-tool identity, and a
gate-specific failure code. Gate A export phases require `BACKUP_EXPORT`, its
restore/qualification phases require `RESTORE_QUALIFY`, Gate B permits only
`RELEASE_BOOTSTRAP`, and Gate C permits only its candidate-bound installer. A journal
writer in a later package must append events and persist current state using
the atomic contract. Raw exceptions are never journal values.

`validate_preparation_journal_chain()` is a pure whole-chain validator. Sequence
starts at 1 and advances by one; operation, gate, and candidate remain fixed;
phase transitions are continuous; timestamps may be equal at second precision
but never regress; and no event follows `COMPLETE` or `FAILED`. The final event
must match persisted phase, failure, timestamp, tool authority, and the persisted
full-journal evidence fingerprint.

Nonterminal states describe crash recovery points. `COMPLETE` and `FAILED` are
terminal; a failed operation cannot continue magically. A separately reviewed
operation/retry policy must create or resume only a phase explicitly identified
as retryable.

## Failure codes and no-secret rule

The closed `FailureCode` registry contains four namespaces:

- `P3D_PREP_CONTRACT_*`
- `P3D_ROLLBACK_*`
- `P3D_RELEASE_STAGE_*`
- `P3D_ASSET_INSTALL_*`

Schemas use strict field allowlists as the primary no-secret boundary. A second
defense rejects keys or values containing credential/data markers such as
`DATABASE_URL`, `PASSWORD`, `TOKEN`, `SECRET`, `OAUTH`, `MAIL_BODY`, or
`MAIL_SUBJECT`. Contracts contain hashes, counts, stable identifiers, and state
only—not DSNs, credentials, raw database rows, mail data, or snapshot transaction
IDs.

## Atomic persistence contract

`atomic_create_no_replace()` is an inert helper until explicitly called. Its
production-default policy requires root ownership. It requires an absolute
target below a trusted, root-controlled, non-writable, non-symlink directory
chain; writes an exact-mode temporary file; applies owner/mode; flushes and
fsyncs it; rereads the bytes and metadata; links it into place without replace;
revalidates the result; and fsyncs the parent directory.

An existing exact equivalent is idempotent success only after the parent
directory is fsynced again. This closes the retry case where the first link
succeeded but its parent fsync failed. Any non-equivalent object,
symlink, weak parent, wrong owner/mode, or race is a fixed conflict/refusal.
There is no silent overwrite. Tests use an injected temporary trust root and
current test UID/GID; production defaults are not weakened.

## Operational side-effect boundary

Importing the contract module performs no filesystem, database, subprocess,
Git, systemd, Provider, backup, or pipeline operation. It imports no PDI runtime
composition and creates no `PipelineRun`. The only filesystem-mutating function
is the explicitly invoked atomic persistence helper, which is exercised solely
against test temporary directories in WP1.
