# PDI production multi-user orchestration v0.1

Status: development and staging foundation only. Production remains on the
legacy single-user composition.

## Trusted formal boundary

`PrincipalFormalPipelineRunner` is an additive operator-facing boundary. A
trusted unit, protected configuration, or operator supplies a Principal ID
before execution. The router fixes one Personal database; the runner discovers
every enabled Scope of the requested Provider inside that database and invokes
the explicitly configured operation for each Scope. Principal and Scope are
not AI inputs. There is no database URL, default Principal, first-Scope, global
Provider credential, or legacy executable fallback.

The host-global `pdi-sync.lock` remains the V1 serialization boundary. A run is
recorded in `pipeline_runs` in the routed Personal database. Scope iteration is
deterministic and stops on the first failure; the ledger records failure, and
partial work is never reported as success. Bootstrap and recovery are distinct
operator operations. Incremental execution never silently performs either.

Provider-specific callbacks are trusted composition. Nextcloud callbacks must
retain user-scoped WebDAV qualification and use Scope state. Immich callbacks
must bind an API key to the Account's remote user UUID and use Scope state.
Person and relation callbacks use the MU11 scoped repositories. Remote
enrichment callbacks reuse Source-to-Scope access binding; local extractors run
only in the routed Personal database. A credential failure is terminal and
cannot cause another Scope, Principal, or legacy credential to be tried.

## Transition order and tools

The required production order is:

1. Source provenance backfill.
2. Person-source provenance transition.
3. Resource-person relation provenance transition.
4. Exact legacy incremental-state copy.

Person and relation planning functions are read-only. Their apply functions
lock the complete legacy inventory, repeat validation, and insert all new rows
in one transaction. Legacy rows remain unchanged. Equivalent targets make a
repeat idempotent; conflicting targets abort the whole transaction. Person IDs,
resource IDs, labels, and inactivity state are preserved.

Relation transition additionally requires actual Source provenance and scoped
Person-source provenance in the mapped Scope. Provider type alone is never
enough evidence. Missing or ambiguous evidence aborts before writes.

Existing Source and incremental-state tools retain exact-plan behavior. Every
legacy Source Provider and every legacy state key must be explicitly mapped;
there is no default Scope.

## Production inventory decisions

The audited `integration-test` Sources require a separate production decision.
They must either receive an explicitly approved quarantine/legacy Scope or be
proven disposable and retired in a separately authorized cleanup gate. Omitting
their mapping fails Source transition. This gate makes neither choice.

Gmail is `LEGACY_SINGLE_PRINCIPAL_DEFERRED`. Existing production Gmail full sync
must be preserved during a single-Principal transition, but Gmail is excluded from scoped
multi-user formal promotion until its OAuth credential is bound to a stable
account identity and qualified. A second Gmail Principal is blocked. Gmail
incremental remains `NOT_IMPLEMENTED_EXISTING_BEHAVIOR`; scheduling must not
silently drop the legacy full sync.

At the future Source transition, every existing Gmail Source must receive an
explicitly approved preservation Scope. The data remains queryable, but the
legacy Gmail writer must be disabled before Source cutover and must never resume
writing NULL-Scope Sources. The scoped runner exposes no Gmail capability and
never falls back to the legacy writer. New Gmail ingestion remains disabled
until a dedicated scoped Gmail qualification gate.

## Future systemd design

Future units should bind one trusted Principal and pipeline key per protected
unit-profile instance and load only
non-secret registry paths plus protected secret references. The Principal may
be a fixed environment value in a protected unit environment file; credentials
must never occur in `ExecStart`. The runner resolves the Personal database via
`PrincipalDatabaseRouter`, retains the global lock, emits deterministic exit
status, and writes the ledger locally. Existing legacy units and CLIs remain
unchanged until a separately authorized cutover.

## Staging and production boundary

Qualification uses disposable PostgreSQL databases and synthetic adapters. It
must cover two Principals, multiple same-Provider Scopes, exact-plan refusal,
idempotent Source→Person→Relation→state transition, and post-transition scoped
reconciliation. No production configuration, identifier, secret, migration,
backfill, backup, service, or Provider is changed here.

The next production-safety gate must independently establish and rehearse PDI
Core database backup and restore before any production Alembic upgrade.
