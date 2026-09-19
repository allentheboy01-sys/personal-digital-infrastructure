# MU13-P3C writer cutover tooling — development candidate

This unpromoted engineering milestone adds operator-only scoped writer cutover
automation, an exact-release human command, deterministic daily chaining,
protected configuration generation, explicit lock handoff, and fail-closed
abort. It does not declare production cutover complete or change the public
package version.

Development qualification uses synthetic operational state and temporary
filesystem/systemd substitutes, including real inter-process lock tests.
Unavailable PostgreSQL integration prerequisites are reported separately.

No deployment, migration, backfill, production Provider access or push is part
of this milestone. Consumer promotion, enrichment cadence and scoped Gmail
remain separate gates. See the [operations contract](../design/pdi-scoped-writer-cutover-v0.1.md).
