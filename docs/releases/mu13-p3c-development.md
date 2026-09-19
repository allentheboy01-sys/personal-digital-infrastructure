# MU13-P3C writer cutover tooling — development candidate

This unpromoted engineering milestone adds operator-only scoped writer cutover
automation, an exact-release human command, deterministic daily chaining,
protected configuration generation, explicit lock handoff, and fail-closed
abort. It does not declare production cutover complete or change the public
package version.

Development qualification uses synthetic operational state and temporary
filesystem/systemd substitutes, including real inter-process lock tests.
Unavailable PostgreSQL integration prerequisites are reported separately.

A disposable real-systemd rehearsal exposed an empty-pattern inventory refusal
in preflight. The corrected preflight requires a successful unfiltered unit-file
inventory, then checks only the scoped/P3C name prefixes and their actual state
column. An empty matching set is valid; enabled or enabled-runtime units,
active scoped writers, and command failures still refuse cutover. This correction
requires a fresh real rehearsal and does not establish production readiness.

No deployment, migration, backfill, production Provider access or push is part
of this milestone. Consumer promotion, enrichment cadence and scoped Gmail
remain separate gates. See the [operations contract](../design/pdi-scoped-writer-cutover-v0.1.md).
