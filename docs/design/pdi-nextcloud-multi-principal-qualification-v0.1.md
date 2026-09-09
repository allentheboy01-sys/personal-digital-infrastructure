# PDI Nextcloud Multi-Principal Qualification v0.1

Status: MU9 real-Provider qualification passed. Production remains disabled.

## Disposable topology

MU9 uses a loopback-only, removable Nextcloud stack with an isolated Docker
network, PostgreSQL 16, Redis, named disposable storage, and exactly two
synthetic ordinary users. The locally available production Nextcloud image
digest is reused without pulling, upgrading, restarting, or otherwise changing
production containers. A separate development PostgreSQL instance provisions
two disposable Personal PDI databases and least-privilege runtime roles.

Generated credentials live only in mode-0600 temporary files. The Nextcloud
administrator is used only to create, disable, re-enable, and rotate the two
test accounts. PDI scanning, Activity calls, content access, file creation, and
sharing use only ordinary user credentials.

The opt-in qualification test requires explicit `PDI_MU9_*` inputs and a
guarded `PDI_TEST_DATABASE_URL`. Without them it skips rather than selecting a
default Provider or database. It contains no credentials, checkpoints,
production endpoints, or private data.

## User-scoped credential proof

`NextcloudAdapter.connect()` previously requested public `/status.php` with
Basic Auth. That endpoint does not establish access to a configured user's
file world. MU9 hardens connection validation to perform an authenticated
WebDAV `PROPFIND` with `Depth: 0` on the configured user's Files root and to
require one valid root collection.

The real qualification proves:

- each correct username/password pair opens its own WebDAV root;
- crossed username/password pairs fail;
- a wrong password and nonexistent user fail;
- direct ordinary-user access to the other user's private DAV path is denied;
- no status-only success is accepted as credential qualification.

Passwords are credentials, not Provider Account or Observation Scope identity.
Rotating a password leaves the Account, Scope, Source IDs, Asset IDs,
resource refs, and Scope incremental-state identity unchanged.

## Private worlds and sharing

Each user creates a distinctive private file. Provider scans prove that neither
ordinary account observes the other's private file. Scoped ingestion then
routes each adapter through its Principal, Personal database, and Observation
Scope. Persisted Sources have non-NULL Scope provenance and no private Source
appears in the other Personal database.

Bounded Nextcloud text reads select the exact Source Scope binding and return
only that user's synthetic content. Deliberately binding an A Source to B's
ordinary credential fails at the real Provider with no credential fallback.
Existing full-read hash verification, UTF-8 validation, stale-content
detection, and bounded-window behavior remain unchanged.

An A-owned file is shared through Nextcloud's ordinary-user sharing API. B then
observes and independently materializes it in B's Personal database, and opens
it with B's own credential. A and B have independent Source and Asset IDs; no
shared database, cross-database canonicalization, or Principal column is used.

After A revokes the share, authoritative B full sync inactivates only B's
Source. A's Personal World snapshot remains unchanged and A retains access.
B's previous resource ref no longer yields Provider text.

## Incremental and lifecycle qualification

The disposable Activity app supports explicit bootstrap for both Scopes using
`activity_v2_hint_v1`. Each Personal database receives independent
`observation_scope_sync_state`. Updating A and running only A incremental sync
advances A while B's world and state remain unchanged; the symmetric B case
also passes. No legacy `provider_sync_state` row is created or modified.

Disabling user B makes B's credential fail while A remains functional.
Re-enabling B restores it without replacing PDI identity. Rotating B's
credential invalidates the old secret and enables the new secret; a subsequent
real full sync and bounded text read preserve the existing Source, Asset,
Scope, resource-ref, and incremental-state identities.

## Boundaries

MU9 does not modify PDI schema, Query, ResourceRef, formal pipelines,
`pdi.main`, production Provider configuration, production databases, tunnels,
or systemd. It does not bind Harry's production account and creates no family
account. The disposable stack and PDI databases are removed after the gate.

This qualification is specific to real Nextcloud user-scoped behavior. Immich
multi-principal Provider qualification remains MU10. Production promotion and
real household onboarding require later explicit gates.
