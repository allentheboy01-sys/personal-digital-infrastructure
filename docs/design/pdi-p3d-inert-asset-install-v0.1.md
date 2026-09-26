# PDI P3D Inert Asset Install V0.1

## Scope

Gate C installs the reviewed P3D enrichment scheduling assets without making
them visible to the live systemd manager. It owns exactly seven unit files and
six protected EnvironmentFiles. It does not reload systemd, change unit
enablement, run a pipeline, call a Provider, or change `/opt/pdi/current`.

The production tool is candidate-bound: its `INERT_ASSET_INSTALL` source SHA
must equal the candidate SHA. Production paths are fixed in code. A
qualification policy may map the same logical paths below a disposable root;
the authority manifest always records the canonical `/etc/...` paths.

## Authority chain

The installer fails closed unless all of these facts are independently read
and validated:

1. The explicit Gate A operation is `COMPLETE`; its full immutable journal,
   rollback metadata, and active release pin agree.
2. The explicit Gate B operation is `COMPLETE`; its full immutable journal and
   final release fingerprint agree with the immutable candidate release.
3. `/opt/pdi/current` still names the rollback-source release.
4. The protected P3C PASS record matches the rollback source and P3C context.
5. P3C writer timers are healthy and P3D enrichment timers are already quiet.
6. The protected environment and registry are trusted and unchanged.
7. The selected Principal and enabled Scope IDs come from the routed Personal
   DB in one PostgreSQL READ ONLY transaction.

Caller input never supplies a Principal, database URL, secret, profile body,
or enabled Scope ID.

## Rendering and verification

Profiles are built with `build_trusted_enrichment_profile()` and serialized by
`render_environment_file()`. Local enrichment profiles receive only the routed
database binding. Nextcloud text/document profiles receive only exact enabled
Nextcloud binding secrets; Immich OCR receives only exact enabled Immich
binding secrets. Raw profile bytes never enter output, state, journal, or the
complete marker.

The seven unit bytes come from the exact immutable candidate release. Their
frozen WP3 fingerprint must match the operator-approved fingerprint. Before
any canonical target is created, the complete 13-file set is checked for its
service/timer/profile contract and passed through real offline
`/usr/bin/systemd-analyze verify`. The final installed bytes receive the same
independent checks again.

## No-replace convergence

Every canonical target is created with the frozen
`atomic_create_no_replace()` semantic:

- missing: create exact root-controlled bytes;
- exact existing: accept idempotently;
- any byte, type, owner, group, or mode difference: refuse without replacing.

After the first new file, the journal enters `FILES_PARTIALLY_INSTALLED`.
Only that frozen phase may resume. Resume re-reads every authority, re-renders
profiles, re-runs offline verification, and converges the same candidate. A
failure never removes an already-created canonical file.

## Completion

Completion requires a freshly read exact 13-file manifest, unchanged P3C
systemd evidence, six disabled/inactive P3D timers, unchanged current symlink,
and unchanged registry/environment authorities. The root-owned 0600 complete
marker is created without replacement under the explicit Gate C operation.

Installing files is intentionally not activation. `daemon-reload`, enable,
start, stop, restart, promotion, workload execution, and real systemd
rehearsal belong to later, separately authorized gates.
