# PDI Data Status & Freshness V0.1

## Scope

Data Status is a read-only application capability for PDI's own batch data
maintenance state. It is separate from World/Domain facts,
`ResourceEnrichment`, Resource Core, and infrastructure monitoring.

V0.1 never persists or returns a `fresh` or `stale` boolean. It returns the
objective signals `last_success_at`, `success_age_seconds`, and
`validated_after_dependencies`.

## Pipeline identity and ledger

The ordinary health catalog identifies Provider full and incremental syncs and
the enrichment pipelines independently of systemd. A separate formal registry
also admits explicit bootstrap and recovery operator actions. Those actions
receive the shared lock and PipelineRun audit history, but are not recurring
health entries and have no timers. The registry owns
kind, dependencies, and current enrichment generator identity. It validates
unique keys, registered dependencies, no self dependency, and no cycles. It is
not a scheduler or workflow engine.

`pipeline_runs` retains health history with `id`, `pipeline_key`, `kind`,
`status`, `started_at`, `finished_at`, `error_code`, and a nullable
`invocation_fingerprint`. The latter is a unique SHA-256 digest used only for
new WP8-qualified systemd runs; historical/manual rows remain null and are not
causal proof. Kinds are
`provider_sync` and `enrichment`; states are `running`, `completed`, and
`failed`; error codes are limited to `execution_failed` and
`interrupted_previous_run`. Raw exceptions, messages, metrics, InvocationIDs,
paths, URLs, and credentials are not persisted.

Run creation and terminal updates use independent short transactions. They do
not span provider scan or enrichment work. A terminal timestamp earlier than
the start timestamp is allowed because wall-clock correction must not prevent
terminal persistence. History begins at rollout; journal history is not
backfilled.

The separate `pipeline_run_effect_receipts` table is not part of the ordinary
Data Status API. For an invocation-bound enrichment run it records only
append-only effect identities/fingerprints committed in the same transaction
as each successful observation publish. It exists for WP8 Runtime Proof and
does not change health freshness semantics.

## Formal operational runner

```text
scheduler
  -> pdi.operational --pipeline-key ... --lock-timeout ...
  -> /run/lock/pdi-sync.lock
  -> interrupted-run recovery
  -> durable begin_run
  -> existing pdi.main or pdi.enrichment command
  -> durable complete_run or fail_run
```

The runner is the only owner of the shared flock. Formal units must not wrap it
in an outer flock. Recovery happens only after lock acquisition. The lock proves
that no other tracked formal pipeline is executing; the database partial unique
index separately prevents two running rows for the same key.

Lock timeout and database failure before `begin_run` create no row. If terminal
persistence fails after pipeline execution, the running row may remain; the
next formal run recovers it as `interrupted_previous_run` after acquiring the
lock.

Bare `python -m pdi.main` and `python -m pdi.enrichment` remain development and
debug entrypoints. They do not acquire the formal lock, write PipelineRun, or
recover interrupted runs, and must not substitute for the formal production
runner.

The existing exit contract is authoritative: exit 0 is `completed`; nonzero or
an uncaught top-level exception is `failed/execution_failed`. Resource-level
state remains in `ResourceEnrichment`; its timestamps are never pipeline
success timestamps. Counts are deferred because historical states do not equal
current active eligible coverage.

The runner starts the application child in its own process group. For SIGTERM,
SIGINT, or interactive `KeyboardInterrupt`, it forwards termination to that
whole group, waits for the child to exit, escalates to SIGKILL after a bounded
grace period if necessary, and reaps it before the ledger terminal update and
lock release. A catchable interruption therefore cannot release the formal
lock while an orphan pipeline continues.

Python cannot clean up after SIGKILL or host power loss. Under the formal
systemd path, the effective `KillMode=control-group`, `KillSignal=SIGTERM`, and
`SendSIGKILL=yes` contract also covers runner descendants. A direct manual
`pdi.operational` process killed with SIGKILL has no equivalent cgroup promise;
production manual runs must use `systemctl start` for the corresponding formal
service. Any stale running ledger row remains recoverable on the next
lock-owning formal run.

## Snapshot and MCP semantics

`DataStatusService` takes one aware UTC `generated_at`, performs one batched
latest-run read and one batched last-success read plus bounded reads of the two
incremental state targets, and returns all health registry entries.
`last_success_at` is the latest completed `finished_at`.
`success_age_seconds` is derived; if success is in the future, the raw timestamp
is preserved and age is `null`.

Dependency validation is `null` without dependencies. A Provider dependency is
established only after at least one successful formal mutation. Its mutation
watermark is the newest timestamp among the latest full, incremental,
bootstrap, and recovery attempts: `started_at` for running attempts and
`finished_at` for completed or failed attempts. An enrichment validates only
when its last success is at or after every dependency watermark. Running and
failed attempts conservatively invalidate older enrichment because they may
have durably changed the world model before completion or failure. This is not
a `fresh` assertion. Direct manual/debug commands are absent from this formal
ledger and therefore cannot contribute to the guarantee.

The snapshot separately exposes Nextcloud and Immich incremental state as a
bounded health view: Provider, mechanism, row existence, checkpoint
initialization, version, reconciliation latch, and update time. Opaque raw
checkpoint values are never returned. A missing row and a row with a null,
uninitialized checkpoint remain distinct.

`pdi_get_data_status()` exposes only the bounded snapshot. Provider sync success
means PDI last completed observation/sync, not guaranteed current identity with
the live Provider. The formal MCP surface has eight read-only Tools; the
separately constrained Jarvis/Hermes profile is unchanged.

CPU, memory, disk, network, Docker, PostgreSQL/systemd/service health, Resource
Access process health, alerts, notifications, and retries are outside V0.1. If
PostgreSQL is unavailable, the ledger and Tool may be unavailable; systemd and
journald remain infrastructure diagnostic authorities.

## Production freeze

The implementation candidate `2fd531dd7d77dad7b5040dad7253e28ccbc33528`
was promoted on 2026-08-18. Production was migrated once to Alembic head
`4d8a2c6e9f10`; no history was backfilled. The eight committed service units
were installed without an outer flock and retained their existing timers.

The eight pipelines were then run through their formal systemd services in
dependency-safe order. All completed successfully. A second formal
`enrichment.immich_geo` run processed and wrote no business data while still
adding one completed ledger entry. The resulting production ledger contained
nine completed rows, no running rows, and no failed rows.

The resulting bounded snapshot contained all eight registry entries. Both
provider pipelines had not-applicable dependency validation and all six
enrichment pipelines validated after their upstream successes, including
`enrichment.file_metadata` after both provider syncs. Fifty production
read-only samples used two batched database reads each, with 2.301 ms p50,
3.087 ms p95, and a 3,173-byte serialized payload. Local stdio MCP exposed
exactly eight Tools and the prior seven passed smoke validation. The
Hermes/Jarvis profile was not changed.
