# PDI Roadmap

The roadmap records product delivery order. Architecture and current contracts
live in their dedicated documents; operational validation chronology belongs in
release or archived reference records.

PDI is the product. Consumer runtimes are optional integrations over stable
public boundaries and do not define PDI Core.

## Completed milestones

- **v0.1 — Write Pipeline MVP:** Provider-independent identity decisions and
  persistence.
- **v0.2 — Multi-provider Sync MVP:** incremental, idempotent Nextcloud and
  Immich synchronization.
- **v0.3 — Read Pipeline MVP:** stable query services and immutable Resource
  read models.
- **v0.4 — Jarvis Tool Execution MVP:** the first validated reference-consumer
  integration over PDI; Jarvis remains optional.
- **v0.5 — Personal Retrieval Runtime:** Resource projection, deterministic
  observations, structured/Provider/rich retrieval, bounded representations,
  and read-only MCP.

## Current — v0.6.0 public release line

**v0.6.0** adds operational hardening, typed
Resources, bounded Data Status, minimal Person identity, one explicit
Provider-derived `Resource depicts Person` relation, and the limited/manual
Gmail Provider. Its detailed engineering evidence is archived separately.

Public Readiness Phases A-E establish:

- privacy and private-operations boundaries;
- PDI-first repository identity and Jarvis reference-consumer positioning;
- a public product README, Provider maturity matrix, consumer-interface map,
  and honest pre-1.0 status; and
- host-neutral contributor documentation and navigation; and
- Provider-independent configuration, stable public commands, and a portable
  manual self-host reference with PostgreSQL and generic systemd assets; and
- contribution/security guidance, reviewed Python 3.13 constraints, automated
  host-safe and PostgreSQL 16 checks, package validation, and secret scanning.

## Release policy

Scoped writer promotion tooling is a development candidate, not production
enablement. [MU13-P3C](../releases/mu13-p3c-development.md) prepares an explicit
human-controlled cutover with fail-closed abort. Consumer cutover, enrichment
scheduling and scoped Gmail remain separate future gates.

- Package metadata, the public release note, and the annotated Git tag must
  agree. Only the exact commit carrying `v0.6.0` is the public release.
- Evaluate any PyPI publication separately; it is not required for the
  source/self-host release.

## Future product work

- Stabilize proven Provider, observation, retrieval, access, and consumer
  contracts toward **v1.0 — Stable Personal Digital Infrastructure**.
- Evaluate additional Provider and consumer integrations independently, without
  making PDI Core depend on one AI runtime.
- Consider broader relationship retrieval, Provider-derived media relations,
  and user-controlled memory only after separate architecture review.
- Define explicit permission and write/action boundaries before introducing any
  write-capable consumer Tool.
- Review whether the optional Jarvis reference implementation should move to a
  separate repository once the public PDI package boundary is stable.

Future milestones are directional and subject to architecture review.
