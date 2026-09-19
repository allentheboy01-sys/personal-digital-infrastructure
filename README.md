# PDI — Personal Digital Infrastructure

> Own your digital world independently of your AI model, agent, interface, and
> storage provider.

Personal data normally lives inside changing applications. PDI normalizes data
from those Providers into a durable Personal Digital World with stable
identity, provenance, deterministic observations, retrieval, and controlled
content access.

AI runtimes and other software consume PDI through public boundaries instead
of owning the user's digital world. PDI remains useful when a storage Provider,
model, agent, or user interface is replaced.

PDI is the product. Jarvis is an optional reference consumer included in this
repository; it is not required to install, extend, or use PDI.

**Status:** active development / pre-1.0. The architecture and current
capabilities have real self-hosted validation. A portable manual installation
path, automated correctness checks, and reviewed dependency snapshot now exist;
general-user polish and package publication remain future work.

Scoped multi-user writer cutover [automation is a development candidate](docs/releases/mu13-p3c-development.md);
production enablement and Consumer cutover require separate explicit gates.

## Architecture

```text
                Optional consumers
       Jarvis / MCP clients / future runtimes
                         |
        Query / Retrieval / Resource Access / MCP
                         |
                      PDI Core
       Resource / Source / Blob / Observation
                         |
                      Adapters
                    ProviderFacts
                         |
        Nextcloud / Immich / Gmail / future Providers
```

Provider-specific behavior terminates at an Adapter. Consumers depend on
stable public boundaries. PDI Core has no dependency on Jarvis, an LLM, or any
other consumer runtime.

## What PDI is — and is not

| PDI is | PDI is not |
| --- | --- |
| Personal digital infrastructure | An AI agent, LLM, or chatbot |
| A Provider normalization layer | A replacement for a NAS or cloud drive |
| Stable identity and provenance for a personal digital world | An AI Memory or RAG wrapper |
| Deterministic observation and evidence infrastructure | An automation or task framework |
| A consumer-independent retrieval and access layer | A UI owned by one AI runtime |

A NAS or cloud drive stores files. PDI models identity, provenance,
observations, and retrieval across Providers, including systems that are not
plain filesystems.

RAG is a technique for selecting model context. AI Memory commonly stores
information selected or generated for one runtime. PDI is the durable user-data
layer beneath those choices: it can serve different retrieval strategies and
consumers without becoming their memory store.

## Current Provider support

Maturity labels describe repository evidence, not a general availability SLA.

| Provider | Sync and identity | Observations / special semantics | Consumer access | Maturity |
| --- | --- | --- | --- | --- |
| **Nextcloud** | Recursive WebDAV inventory, stable Provider identity, streaming traversal, mutable-resource safety | File metadata, text, PDF, DOCX, and ODT extraction | Query, structured/rich retrieval over stored metadata and observations | **Validated (self-hosted)** |
| **Immich** | Paginated asset inventory and original-content hashing | Provider metadata, OCR, geo labels, file metadata, bounded Person identity and `depicts` relations | Provider-semantic retrieval plus bounded image/video representations | **Validated (self-hosted)** |
| **Gmail** | Read-only, single-account full-message inventory with RAW RFC 2822 Blob content | Deterministic Subject, From, To, and internal-date observations | Query and observation boundaries; no Gmail Resource Access or semantic retrieval | **Limited / manual pilot** |

Gmail is explicitly selected, has no scheduler, and is not ready for unattended
operation while its OAuth lifecycle remains a controlled-pilot constraint.
Provider-specific limitations are documented in the
[design records](docs/README.md#providers).

## Consumer interfaces

PDI exposes application boundaries rather than persistence internals:

| Boundary | Purpose |
| --- | --- |
| **Query** | Deterministic listing, search, filters, detail, and aggregation |
| **Retrieval** | Provider-semantic retrieval and statement-aware rich retrieval |
| **Observation** | Typed, evidenced statements attached to Resources |
| **Resource Access** | Approved, bounded representations without Provider credentials or filesystem paths |
| **MCP** | A read-only consumer surface composed from the public services |

Public Resource references use `pdi:resource:<uuid>`. Consumers do not receive
SQLAlchemy objects, sessions, engines, concrete repositories, database
authority, or Provider credentials.

Jarvis validates one replaceable-consumer pattern. Future integrations can use
the same boundaries; no additional agent-runtime integration is currently
claimed as supported.

## Core concepts

| Concept | Meaning |
| --- | --- |
| **Resource** | A durable, independently addressable object in the Personal Digital World |
| **Source** | Provider-specific provenance and lifecycle for a Resource |
| **Blob** | Content identity and metadata associated with a Resource |
| **ProviderFact** | An Adapter's normalized observation of one Provider object; not itself World Model state |
| **Observation** | A deterministic, typed statement with generator and evidence metadata |
| **Relation** | A narrowly defined Provider-derived link; the current model includes `Resource depicts Person`, not a generic graph |
| **ResourceRef** | The public opaque reference form, `pdi:resource:<uuid>` |

See the [architecture](ARCHITECTURE.md) for lifecycle, identity, evidence, and
trust-boundary details.

## Project maturity

PDI is active, pre-1.0 software:

- core write, observation, read/retrieval, and Resource Access boundaries have
  real self-hosted validation;
- multiple Providers and a read-only MCP consumer boundary exist;
- the World Model and Provider/consumer separation are implemented rather than
  aspirational; and
- a manual public self-host path and Provider-independent configuration exist;
  automated host-safe, PostgreSQL 16, package, and secret checks cover the
  public repository boundary.

Package metadata declares `0.6.0`. PDI uses exact-tag release authority: a
commit is the `v0.6.0` public release only when that exact commit carries the
annotated tag `v0.6.0`; otherwise it remains unreleased. Detailed chronology
belongs in the
[project status and records](docs/README.md#project-status-and-records), not in
the product introduction.

## Self-host quick start

PDI requires Python 3.13, PostgreSQL 16, and one Provider. Nextcloud is the
primary example; Immich works independently, and Gmail remains an explicit
manual pilot.

```bash
git clone <repository-url> pdi
cd pdi
python3.13 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install \
  -c constraints/python3.13.txt -e .
cp .env.example .env
# Configure DATABASE__URL and exactly the Provider you want to use.
.venv/bin/alembic -c alembic.ini upgrade head
.venv/bin/pdi sync --provider nextcloud
.venv/bin/pdi mcp
```

Replace `<repository-url>` with the HTTPS or SSH clone URL you intend to use.
The repository includes an optional loopback-only PostgreSQL 16 Compose
reference; Docker is not required when PostgreSQL already exists. Follow the
[complete self-host guide](docs/getting-started/self-host.md) before using real
credentials or installing reference systemd units.

For contributor setup and isolated test rules, see
[local development](docs/development/local-development.md). Jarvis is not part
of the installation path.

The tested dependency snapshot is optional for supported-range installs but
recommended when reproducing the tested release line; its maintenance policy is
documented in [Dependency reproducibility](docs/development/dependencies.md).

## Extending PDI with a Provider

A Provider integration implements an Adapter that translates external objects
into `ProviderFact` values and opens content only when the Sync Engine requests
it. API-specific identifiers and metadata remain behind that boundary; adding
a Provider does not require changing the World Model merely because its API is
different.

Start with:

- [Provider](docs/architecture/02-provider.md)
- [Provider Adapter](docs/architecture/03-provider-adapter.md)
- [ProviderFact](docs/architecture/04-provider-fact.md)
- [Sync Engine](docs/architecture/05-sync-engine.md)

## Security and privacy

PDI is self-hostable, but it does not prescribe one network-exposure product or
topology. Provider credentials stay at Adapter or controlled access boundaries.
Consumers must not bypass PDI services to access databases, ORM objects, or
credentials. Tests must never use production data.

Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities or adding
fixtures, and see the
[private operations boundary](docs/security/private-operations-boundary.md)
before publishing deployment material.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the focused contribution flow,
isolated test requirements, and architecture boundary rules. Continuous
integration uses no live Provider or production credentials.

## Repository map

```text
src/pdi/                  PDI Core, application services, and Adapters
src/pdi_mcp/              read-only MCP consumer boundary
src/pdi_resource_access/  bounded Resource Access process boundary
apps/jarvis-web/           optional reference-consumer frontend
src/jarvis/                optional reference-consumer runtime/backend
docs/                      architecture, design, and reference documentation
deployment/                portable reference deployment assets
tests/                     host-safe and explicitly gated integration tests
```

## Documentation

The [documentation index](docs/README.md) separates getting started,
architecture, Providers, consumer interfaces, security, deployment,
development, reference consumers, and historical records.

## License

PDI is available under the terms in [LICENSE](LICENSE).
