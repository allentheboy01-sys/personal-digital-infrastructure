# PDI Provider Instance, Account, and Observation Scope V0.1

## Purpose and boundary

Each Personal PDI database now has a Provider-neutral identity foundation for
the configured worlds it will eventually observe. This is provenance and
configuration identity, not authentication or user authorization.

`Provider Type`, `Provider Instance`, `Provider Account`, `Credential`, and
`Observation Scope` are distinct concepts. Person remains unrelated to an
authenticated Principal. All records in this design are local to one Personal
PDI database; equal keys in another Principal database do not create shared
identity.

MU4 is additive. It does not connect Sources, Provider facts, incremental
state, formal pipelines, resource access, or current Provider configuration to
these records. Existing single-user execution therefore continues unchanged.

## Identity graph

```text
Provider Type string
  -> Provider Instance
       -> Provider Account (zero or more)
       -> Observation Scope (one or more)
            -> optional Account on the same Instance
```

Provider Type remains a canonical string on Provider Instance. A separate
catalog table supplies no required V0.1 invariant and is intentionally absent.

A Provider Instance is one stable logical backend and external-ID namespace.
Its opaque `instance_key` is unique inside one Personal database. Endpoint,
hostname, port, physical host, container, and credential are not persisted and
cannot determine Instance identity. Moving the same logical service does not
replace its row.

A Provider Account is a stable Provider-recognized account. Its opaque
`account_key` is unique within one Instance. An optional Provider-native ID is
descriptive provenance, not identity. Multiple Accounts may belong to one
Instance.

An Observation Scope is one stable authoritative ingestion boundary. Its
opaque `scope_key` is unique within one Instance. Every Scope references an
Instance and may reference an Account. A composite foreign key guarantees that
a referenced Account belongs to the same Instance. Account-less Providers,
such as a future local-directory Provider, use a Scope with no Account.

## Credentials

MU4 stores neither raw credentials nor credential-binding references. Secrets
remain in protected control/runtime configuration. Rotating a password, API
key, or OAuth token does not replace Instance, Account, or Scope identity.
Whether incremental continuity remains trustworthy after a rotation is a
later operational decision.

## Lifecycle

Instance, Account, and Scope each have a non-destructive enabled flag and
created/updated timestamps. Disabled records remain readable as provenance.
Foreign keys use `RESTRICT`; routine lifecycle does not cascade-delete stable
identity.

## Deferred transitions

`asset_sources` remains uniquely identified by `(provider, external_id)` in
MU4. MU5 will introduce Scope-aware Source observation provenance and the
deterministic current-personal-database backfill. `provider_sync_state` remains
identified by `(provider, mechanism)` until MU6. ProviderFact and Adapter
signatures are unchanged.

The future single-user backfill will create one deterministic Instance,
Account, and Scope for each currently configured account-bearing Provider in
the existing Personal database, and an account-less Scope where appropriate.
It will then attach existing Sources and sync state without printing secrets or
opaque checkpoints. MU4 deliberately chooses no real installation keys.
