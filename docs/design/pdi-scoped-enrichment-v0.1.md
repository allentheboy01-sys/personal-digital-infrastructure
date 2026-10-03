# PDI Scoped Enrichment V0.1

P3D uses the existing `pdi-scoped-pipeline@.service` boundary.  Six
canonical enrichment keys are scheduled through that template; no second
writer/orchestration abstraction is introduced.

| pipeline | reader boundary | batch |
| --- | --- | ---: |
| `enrichment.nextcloud_text` | scoped Nextcloud content reader | 100 |
| `enrichment.nextcloud_documents` | scoped Nextcloud content reader | 100 |
| `enrichment.file_metadata` | local stored metadata | 20000 |
| `enrichment.immich_geo` | local stored metadata | 20000 |
| `enrichment.immich_metadata` | local stored metadata | 20000 |
| `enrichment.immich_ocr` | scoped Immich OCR reader | 20000 |

`enrichment.gmail_metadata` remains deferred/disabled.  `enrichment.local` is
not a production ledger or scheduling key.

Every run is routed through a trusted Principal and its exact Personal DB.
Remote readers resolve Source provenance to an enabled Scope, Instance,
Account, binding, and secret; missing or mismatched elements fail closed with
no fallback.  Local enrichment still runs only in the routed Personal DB and
does not require Provider secrets.

The formal lock remains `/run/lock/pdi-sync.lock`.  Future activation is a
separate fail-closed state machine: preflight, pre-rehearsal qualification,
activation, verify, abort.  The pre-rehearsal qualification is a static,
side-effect-free proof of the candidate, routed database authority, canonical
pipeline registry, and installed unit/profile bindings.  It does not start a
service, run an enrichment worker, or require a `PipelineRun`.

Real six-pipeline `PipelineRun` coverage is a distinct post-rehearsal proof.
It is accepted only after an independently authorized runtime rehearsal and
must cover all six canonical keys for the exact candidate/context.  A normal
pre-rehearsal state therefore has runtime coverage `0/6`.  Abort disables only
the P3D timers and never restores legacy enrichment timers or disables healthy
P3C writers.

Before a production activation, a fresh PostgreSQL 16 / Alembic
`e5a7b9d1f324` rollback snapshot must be created after P3C SOAK; the older
pre-P3B snapshot is not sufficient.
