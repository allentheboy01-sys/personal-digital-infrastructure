# PDI P3D Rollback Qualification V0.1

Status: WP2 disposable implementation for preparation Gate A. It has no
production CLI, cannot select production configuration from the environment,
and does not authorize WP3, `collect-evidence`, or a systemd rehearsal. The
frozen schemas and state machine remain defined by
`pdi.production_ops.p3d_preparation_contracts`.

## Module boundary

`pdi.production_ops.p3d_rollback_qualification` contains one orchestration
core and explicit adapters for:

1. source release/runtime qualification;
2. PostgreSQL exported-snapshot baseline and custom-format dump;
3. content-addressed test backup or disposable local Restic;
4. isolated PostgreSQL 16 restore and read-only compatibility qualification;
5. release-pin and rollback-metadata persistence;
6. immutable Gate A state/journal files.

All effects are constructor-injected. There is no `__main__`, argument parser,
production command, implicit `DATABASE__URL`, or Provider client. Operation
roots are explicit existing disposable directories; broad roots such as `/`,
`/tmp`, `/opt`, `/srv`, and `/var` are rejected. Database restore targets must
be loopback `*_test` databases.

## Source runtime authority

The expected rollback SHA is only an expectation. The concrete reader verifies
that `/opt/pdi/current` is a root-owned symlink resolving to the canonical
`/opt/pdi/releases/<SOURCE_SHA>` directory. It then requires an exact clean Git
HEAD, fixed-env import of PDI plus its PostgreSQL/SQLAlchemy drivers, the P3C
cutover script and scoped runtime files, a Python runtime, and a root-owned tree
with no group/other-writable runtime content.

Git verification uses a fixed environment including `GIT_OPTIONAL_LOCKS=0`.
The release fingerprint covers relative runtime paths, type, mode, root uid/gid,
file SHA-256 and approved symlink targets. It excludes unstable mtime, inode,
absolute staging paths, and Git administrative files. Symlinks may resolve only
inside the immutable release or an explicitly approved root-controlled external
runtime root. The runtime fingerprint additionally binds Python version/ABI,
implementation/platform, Python binary hash, migration tree, and a canonical
installed-distribution inventory whose names are normalized and whose RECORD
files are hashed.

## One exported snapshot

The coordinator executes the following order on two independent connections:

```text
exporter: BEGIN REPEATABLE READ READ ONLY
exporter: SELECT pg_export_snapshot()
importer: BEGIN REPEATABLE READ READ ONLY
importer: SET TRANSACTION SNAPSHOT <validated token>
importer: SHOW transaction_read_only == on
importer: collect fixed baseline evidence
pg_dump: --format=custom --no-owner --no-acl --snapshot=<same token>
fsync dump
hash dump, baseline counts and exported-snapshot evidence
exporter: ROLLBACK and close
```

The importer performs no evidence query before `SET TRANSACTION SNAPSHOT`.
The exporter remains open through dump fsync and all evidence hashing. The raw
snapshot token remains process-local; only its SHA-256 enters evidence.
PostgreSQL commands use fixed argv, `shell=False`, a minimal environment,
password-only `PGPASSWORD`, and clients that identify themselves as major 16.
There is no non-snapshot fallback.

## Baseline and restore invariants

`RollbackBaselineEvidenceV1` is an exact-field internal WP2 value. It contains
only aggregate counts and invariants: the fixed core-table counts, four Provider
source counts and identity cardinalities, Alembic and PostgreSQL major,
NULL/duplicate Scope identities, NULL/empty external IDs, missing Blob links,
the exact legacy and scoped sync-state mechanisms, checkpoint/reconciliation
aggregates, and required identity/Scope constraints. It contains no row values,
checkpoint content, labels, paths, external IDs, or credentials.

The backup payload is exactly:

- `pdi-core.dump`;
- `baseline.json`;
- `exported-snapshot-evidence.json`.

Qualification always restores those bytes from the newly created backup
snapshot. Direct use of the source staging dump is forbidden. The recovered
file set, dump hash, baseline fingerprint and exported-evidence fingerprint
must match before `pg_restore` runs.

The restore adapter creates a unique loopback `*_test` database and a unique
temporary login/owner credential, restores with PostgreSQL 16 tools, and runs
all validation in a repeatable-read read-only transaction. Counts, Provider
identity state, Source/Scope hygiene, sync state and constraints must equal the
exported baseline. A representative read-only query and the source migration/
runtime evidence form the DB/runtime compatibility fingerprint. Cleanup drops
both database and temporary role; cleanup failure fails the Gate.

## Backup adapters

`BackupAdapter` exposes only `create_snapshot` and `restore_snapshot`.
`FilesystemBackupAdapter` is a content-addressed faithful unit-test backend.
`ResticBackupAdapter` is restricted to a disposable root and exposes only an
explicit disposable init, backup with fixed tags, and exact-snapshot restore.
It has no forget, prune, migrate, delete, or password-change operation. The
backend-produced 64-hex snapshot ID and backup filesystem UUID must match the
qualified context; neither can be supplied as a success assertion.

## Authority ordering and persistence

The orchestrator follows every frozen Gate A transition and tool role. It
persists immutable sequence-numbered state and journal records, validates the
whole WP1 chain, and exposes only fixed failure codes. The two operator tool
source identities must equal the target candidate SHA.

After restore/runtime compatibility succeeds, disposable dump and restore
directories are removed *before* authority artifacts are created. The active
`RollbackReleasePinV1` is atomically created before the deterministic
`P3DRollbackMetadataV1` representation. Metadata uses sorted `KEY=<JSON>`
lines, an explicit parser, exact round-trip bytes and no shell evaluation.
Only then can Gate A reach `METADATA_COMMITTED` and `COMPLETE`.

## Failure and crash policy

Every known failure becomes a fixed `P3D_ROLLBACK_*` code and a terminal
`FAILED` journal state. No metadata or release pin is produced before its
prerequisites. A backend snapshot already created is retained as unqualified;
WP2 never prunes it. Temporary dumps, restored files, databases and credentials
are cleaned without touching the source.

Only `NEW` and `SOURCE_VERIFIED` are retryable. The immutable loader validates
state/journal cardinality and the complete chain before returning either phase.
`SNAPSHOT_EXPORTED` and every later phase are refused because an exported
snapshot cannot survive a process crash. An incomplete backup snapshot cannot
be promoted to authority; a new operation must reproduce and requalify all
evidence.

## Verification

Unit tests cover ordering, exporter lifetime, strict evidence schemas,
metadata round trips, fixed command environments, backup recovery, exact
payload verification, pin-before-metadata, full multi-tool journal authority,
failure codes, cleanup, and retry refusal.

The PostgreSQL integration test uses an explicit isolated
`PDI_TEST_DATABASE_URL`, creates a unique synthetic source database, mutates the
source after export, and proves both baseline and restored dump retain the old
snapshot. It uses real PostgreSQL 16 `pg_dump`/`pg_restore`, a disposable real
Restic repository, a unique restore database/credential, and deletes all
disposable database resources. CI treats missing PostgreSQL or Restic clients
as a failure; a developer host without them skips only that integration test.
