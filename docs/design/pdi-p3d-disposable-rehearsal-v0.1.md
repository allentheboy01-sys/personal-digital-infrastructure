# PDI P3D Disposable Real-Systemd Rehearsal V0.1

Status: WP7 qualification-only design. It has no production execution mode.

## Boundary

WP7 consumes the frozen WP6 pre-rehearsal preparation authority and proves the
runtime path in one disposable root. It never targets the host systemd manager,
never enables a timer, and never accepts a database URL or pipeline list from
the operator CLI. Its only stateful actions are inside the disposable root and
the dedicated `pdi_wp7_*_test` PostgreSQL database.

The ordered authority chain is:

1. exact WP3 qualification bundle;
2. frozen WP4 root bootstrap;
3. frozen Gate A and P3C qualification evidence;
4. frozen WP5 inert asset installation;
5. frozen WP6 pre-rehearsal evidence collection;
6. isolated `systemd-nspawn` manager identity proof;
7. atomic `current` promotion inside the disposable root;
8. real `daemon-reload` against that manager;
9. six sequential real oneshot service starts;
10. PostgreSQL 16 runtime ledger and workload-effect verification;
11. timer, identity, Source, and sync-state invariants;
12. service, manager, database, and filesystem cleanup.

The complete marker is written only after all six services and the exact 6/6
ledger have passed and every service has been stopped. Cleanup success cannot
turn a failed workload into a successful rehearsal.

## Pipeline reconnaissance

| Pipeline key | Runtime code | Provider network | Expected writes | Minimal synthetic fixture |
| --- | --- | --- | --- | --- |
| `enrichment.nextcloud_text` | `NextcloudTextExtractor` through `ScopedNextcloudContentReader` | WebDAV `PROPFIND` plus content `GET` | one completed `PipelineRun`, `resource_enrichments`, current text statement | one scoped Markdown Source with matching Blob hash |
| `enrichment.nextcloud_documents` | PDF, ODT, and DOCX extractors through `ScopedNextcloudContentReader` | WebDAV `PROPFIND` plus content `GET` | one completed `PipelineRun`, completed DOCX enrichment, current document statement | one scoped minimal DOCX Source with matching Blob hash |
| `enrichment.file_metadata` | `FileMetadataExtractor` | none | one completed `PipelineRun`, completed enrichments, current modification-time statements | persisted Nextcloud and Immich timestamps |
| `enrichment.immich_geo` | `ImmichGeoExtractor` | none | one completed `PipelineRun`, completed enrichment, current geo statements | persisted synthetic EXIF coordinates and labels |
| `enrichment.immich_metadata` | `ImmichMetadataExtractor` | none | one completed `PipelineRun`, completed enrichment, current metadata statements | persisted synthetic EXIF timestamp, coordinates, make, and model |
| `enrichment.immich_ocr` | `ImmichOCRExtractor` through `ScopedImmichOCRReader` | Immich `/api/users/me` and `/api/assets/<id>/ocr` | one completed `PipelineRun`, completed OCR enrichment, current OCR statement | one scoped Immich Source and local HTTP responses |

The HTTP fixtures exercise the real provider readers and request stack. They do
not patch adapters, workers, repositories, or ledger code. Credentials and all
payloads are synthetic.

## Systemd isolation

Every WP7 `systemctl` command contains the derived
`--machine=pdi-p3d-<operation>` selector. The backend allowlist is limited to:

- `daemon-reload`;
- `show`, `is-enabled`, and `is-active`;
- `start` for one exact canonical P3D service;
- `stop` for those services during cleanup.

The manager is accepted only when `machinectl` identifies a `systemd` process
whose namespace PID is 1, whose root is the disposable root, and whose boot ID
differs from the host boot ID. Bare host `systemctl`, timer starts, and all
enable/disable operations have no API.

The six timers must be `disabled` and `inactive` before the first workload,
after each workload, and before completion. Services must load from the exact
template with `User=pdi`, `Group=pdi`, `Type=oneshot`, `NoNewPrivileges=yes`,
the candidate `current` path, and no drop-ins.

## Database and ledger authority

The database binding is derived from the protected scoped configuration. The
database name must match `pdi_wp7_*_test`. Before any service starts, PostgreSQL
must report server major 16 and provides the rehearsal boundary with
`clock_timestamp()` and the baseline run count. WP7 only selects ledger and
invariant data; it never manually inserts or updates a `PipelineRun`.

After each start, exactly one fresh row for that canonical key must be
`completed`, have `finished_at`, and have no `error_code`. The corresponding
extractor must also have at least one completed enrichment and one current
statement after the boundary. At completion:

- total run count is baseline plus six;
- the pipeline set is exactly the frozen canonical six;
- all run IDs are unique;
- Provider identity, enabled Scope, Source identity, and sync-state
  fingerprints are unchanged.

Candidate SHA and the frozen WP6 context fingerprint are attached by the WP7
authority to the six observed run IDs. They are not represented as nonexistent
database columns.

## CI qualification

The dedicated CI job fails if PID 1 on the disposable host is not systemd, if
`systemd-nspawn`/`machinectl` are unavailable, or if the integration test is
skipped. It bootstraps the exact release bundle, installs Gate C assets, runs
WP6, starts the isolated manager, then executes the exact candidate WP7 CLI.
The rehearsal root contains no network package installation or editable
workspace mount. The candidate services execute
`/opt/pdi/current/.venv/bin/python -m pdi.production_ops.enrichment` from the
bootstrapped immutable release.

The final CI markers require a real isolated manager, six real service starts,
zero timer activations, exact 6/6 runtime coverage, and a complete marker.
