# PDI P3D Release Bootstrap V0.1

Status: WP4 candidate. This design stages a release only. It cannot promote
`current`, install systemd assets, access a database or Provider, or run a PDI
workload.

## Authority boundary

The bootstrap is an independently reviewed tool identified by
`ToolName.RELEASE_BOOTSTRAP`. Its artifact digest and source SHA are explicit
operator inputs and are not read from the candidate bundle. The bootstrap tool
SHA and candidate SHA may differ. Candidate bytes cannot replace or import the
bootstrap before trust has been established. A future production bootstrap is
expected to be a separately pinned, attested, standard-library `.pyz`; building
that artifact is deferred from WP4.

The bundle path, candidate SHA, outer bundle SHA-256, OS/runtime manifest
fingerprint, authority class, roots, and lock are explicit. Qualification also
uses an explicit synthetic runtime identity. Production instead pins runtime
authority to the systemd service identity `pdi:pdi`; the caller cannot select a
different production user or group. There is no "latest" discovery. The frozen
WP3 verifier is called offline with `perform_offline_install=False` before
release staging. The input is copied once, hash-checked and fsynced into the
protected operation directory, avoiding a caller-writable bundle race.

`QUALIFICATION` accepts only `QUALIFICATION_ONLY` in an explicit disposable
trust root and may use an explicit synthetic identity such as `nobody:nogroup`.
`PRODUCTION` requires effective UID 0, `/opt/pdi/releases`, fixed protected
state and lock locations, the fixed non-root `pdi:pdi` identity, and the
separate `PRODUCTION_RELEASE` authority class. Policy construction resolves
that fixed account locally, and input validation independently re-resolves and
cross-checks both UID and GID. Therefore the current WP3 qualification artifact
can never stage into the production release root.

## Gate B state and recovery

The implementation composes the frozen WP1 state machine without adding
phases:

`NEW → ARTIFACT_VERIFIED → OS_RUNTIME_VERIFIED → STAGING_CREATED →
SOURCE_CHECKED_OUT → VENV_BUILT → RUNTIME_VERIFIED → IMMUTABILITY_VERIFIED →
FINAL_RENAME_COMMITTED → FINAL_VERIFIED → COMPLETE`.

Every transition creates an immutable `journal-NNNNNN.json` followed by an
immutable `state-NNNNNN.json`, fsyncs via the frozen no-replace primitive and
validates the entire chain. Evidence contains hashes only. Resume is accepted
only for the seven WP1 retryable phases and revalidates the artifact, host
authority, Git checkout, venv/runtime, and immutable tree. If a rename happened
before its journal record was durable, a missing staging tree plus an existing
final release refuses resume. A new operation must take the idempotent path.

## Offline host and build boundary

`DebianHostRuntimeAuthorityProvider` is read-only. It compares `/etc/os-release`,
architecture, exact package versions, the approved system Python identity and
hash, and native package closure to `OSRuntimeManifestV1`. The synthetic
provider is accepted only by qualification policy and is impossible under
production policy. Neither provider installs or upgrades host software.

The bootstrap has no network client. Git uses `/usr/bin/git`, a minimal fixed
environment, no remotes and `GIT_OPTIONAL_LOCKS=0`. Source comes only from the
verified Git bundle. The approved Python creates `.venv`; pip receives
`--no-index`, `--find-links`, `--require-hashes`, and
`--only-binary=:all:` with configuration and user-site discovery disabled.

Candidate imports, `pip check`, and Alembic head discovery run as the explicit
non-root runtime UID/GID. A root bootstrap uses `/usr/bin/setpriv`, clears
supplementary groups, and sets `no_new_privs`. The child receives an allowlisted
environment containing no database or Provider configuration.

## Filesystem commit model

The exclusive lock is a protected, no-follow regular file held with `flock`.
Staging is a new `0700` directory under the release root, on the same device as
the final path. Before runtime verification the tree is normalized to trusted
ownership and canonical non-writable modes so the runtime identity can read but
cannot modify it.

Recursive verification covers source, `.git`, `.venv`, installed packages and
entry points. It rejects foreign ownership, group/other writes, special files,
and external symlinks except the explicitly approved system Python authority.
The deterministic `source_release_fingerprint` excludes `.git` bytes but is
bound to exact clean HEAD; it excludes inode, mtime, PID and staging path.

All regular files and directories are fsynced before commit. Linux
`renameat2(RENAME_NOREPLACE)` performs the same-filesystem atomic final commit.
An existing same-SHA release is never overwritten: exact runtime and fingerprint
equivalence yields `IDEMPOTENT`; any drift yields
`P3D_RELEASE_STAGE_FINAL_CONFLICT`. Final verification repeats from the final
path. The `current` symlink is only snapshotted and compared; this module has no
mutation operation for it.

Pre-rename failure removes only this operation's quarantine and staging tree
and preserves its journal. Post-rename failure preserves the final release for
human diagnosis. No path enables legacy writers, systemd, a database, a
Provider, promotion, activation, or rehearsal.
