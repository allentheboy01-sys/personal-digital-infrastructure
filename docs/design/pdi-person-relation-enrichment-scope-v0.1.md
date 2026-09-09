# Person, relation, and enrichment Scope isolation v0.1

MU11 extends the DB-per-Principal architecture to derived Person, relation, and
remote-enrichment provenance. It is an additive foundation; production workers,
formal pipelines, credentials, and existing legacy tables remain unchanged.

## Scoped Person observations

`observation_scope_person_sources` records Provider-observed Person identity as
`(observation_scope_id, external_id)`. Each row references a DB-local `Person`.
The same external ID or display label in two Scopes may create two Persons;
automatic cross-Scope merging is deliberately absent. Reconciliation is locked
and restricted to one immutable repository Scope, and reappearance in that same
Scope reactivates the existing observation and Person ID.

Principal and Person remain unrelated concepts. Principal routing selects the
Personal database; it neither creates nor identifies a Person.

The legacy `person_sources` table and workers remain intact and are not
dual-written.

## Scoped resource–Person relations

`observation_scope_resource_person_relations` identifies an observed relation
as `(observation_scope_id, resource_id, person_id)`. Mapping uses only active
Asset Sources and active scoped Person Sources from that exact Scope. An
external asset or Person identifier from another Scope cannot satisfy a missing
mapping. Authoritative reconciliation, inactivation, and reactivation are
Scope-local. The legacy `resource_person_relations` table remains unchanged.

Rich Person-label retrieval unions legacy and scoped observations internally.
Resource results are distinct, and a future backfill that preserves Person and
resource IDs does not double-count the same pair. Scope is not exposed as an AI
authorization filter; Principal-to-database routing remains the authorization
boundary.

## Remote enrichment access

`EnrichmentSource` now carries the actual Asset Source's
`observation_scope_id`. Local extractors continue operating only on persisted
Personal-World data. The additive scoped remote-reader composition validates
Source → Scope → Instance → optional Account and reuses the MU8
Principal-plus-Scope binding registry and secret resolver.

Once an enrichment Source is selected, its Scope is frozen. Missing/NULL Scope,
disabled or inconsistent identity, absent binding, secret failure, Provider
mismatch, remote authentication failure, or wrong valid user credential fails
without trying another Source, Scope, or Provider-global credential.

Immich OCR factories receive the Provider Account native user ID and use the
MU10 `/api/users/me` account proof. Nextcloud text/PDF/ODT/DOCX use the same
scoped content reader and retain the MU9 user-scoped connection proof. Existing
size, hash, decoding, parser, truncation, pagination, and response checks remain
unchanged.

Scoped remote fingerprints include stable Source and Scope provenance in
addition to existing content/version evidence. Credential values are excluded;
rotation within one Scope does not change identity. Legacy NULL-Scope inputs
retain their prior fingerprint contract.

## Migration and lifecycle

The single MU11 migration only adds the two scoped tables and indexes. It does
not rewrite Persons, legacy Person Sources, relations, observations, enrichment
state, Assets, or Sources. Downgrade is allowed only when both scoped tables are
empty; otherwise it fails before destructive DDL.

A later Harry migration must stop legacy Person/relation writers, establish the
approved Immich Scope, copy Person observations while preserving Person IDs,
copy relations into that Scope, verify counts/IDs and retrieval, switch workers
and remote readers, retain legacy rows through a rollback hold, and prohibit
dual-write. Legacy retirement requires a separate Gate after no writer can
recreate legacy state.

MU11 does not perform that backfill, enable scoped production enrichment, alter
production, or equate Principal with Person.
