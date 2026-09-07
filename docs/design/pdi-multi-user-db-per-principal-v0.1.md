# PDI DB-per-Principal Foundation V0.1

## Boundary

PDI V0.1 isolates each authenticated Principal in one Personal PDI database.
There is no shared household database, household-global Asset identity, or
ordinary cross-Principal query. `Person` remains a Provider-observed person and
is not an authentication Principal.

MU3 adds only the control-plane foundation. Existing Provider ingestion,
`provider_sync_state`, Sources, formal pipelines, and production deployment
remain single-user. Provider Instance, Account, and Observation Scope
persistence are deferred.

## Trusted routing

The runtime authentication layer supplies an opaque Principal identity. A
trusted registry maps it to a database binding reference, and a separate
binding registry resolves that reference from protected connection
configuration. Registry files contain environment-variable names, not database
passwords or arbitrary consumer-provided URLs.

Routing occurs before `QueryService` or a future write pipeline is composed:

```text
authenticated Principal
  -> fail-closed PrincipalDatabaseRouter
  -> fixed PersonalDatabaseBinding
  -> Personal-DB-specific Repository and QueryService
```

Missing, unknown, disabled, malformed, or incompletely configured routes fail
closed. There is no first-entry, Harry, or `DATABASE__URL` fallback. AI tools
must never accept database names, URLs, roles, or Principal selection as query
arguments.

The legacy single-user path remains unchanged. Compatibility with the new
router requires an explicit Principal and explicit existing database URL; it
is not activated by a missing Principal.

## PostgreSQL fleet

The target deployment is one PostgreSQL cluster with one database and one
least-privilege runtime role per Principal. Runtime roles receive access only
to their database. Migration, provisioning, and backup use separately governed
administrative authority.

All enabled Personal databases must use the repository's single Alembic head
outside a controlled rollout. Fleet status is a control-plane projection of
registry membership, reachability, installed revision, and compatibility; it
is distinct from Personal World DataStatus.

MU3's provisioner is deliberately restricted to loopback control databases
whose names end in `_test`, and targets named `pdi_mu3_*_test` with matching
disposable runtime roles. It creates an empty database, applies the existing
Alembic history, grants runtime data access, validates the revision, and can
clean up only those validated targets. It is not a production-family database
onboarding command.

## Resource references

`pdi:resource:<asset UUID>` remains unchanged and is interpreted only inside
the authenticated session's routed Personal database. It is not portable
across Principal contexts and is not an authorization capability. Equal UUIDs
in two databases resolve independently.

## Deferred work

MU3 does not add Provider Instance, Account, Credential, or Observation Scope
records; scope-qualified Source or checkpoint identity; multi-user formal
pipelines; multi-user DataStatus; Provider credential routing; authentication;
ACL/RBAC; a shared database; or production deployment. Existing
`pdi.operational` remains a single-user path using the explicitly configured
`DATABASE__URL` until a later Gate makes formal operations Principal- and
Scope-aware.
