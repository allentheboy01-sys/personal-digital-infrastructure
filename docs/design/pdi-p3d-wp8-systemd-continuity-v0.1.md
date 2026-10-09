# WP8 systemd mutation-authority continuity

This backend-only protocol refines Phase B of the frozen WP8 production
rehearsal contract. It does not authorize Phase B, production access, real
systemd qualification, promotion, activation, or the future orchestrator.
The eight public backend methods and frozen WP1–WP8 contracts are unchanged.

## Caller and threat-model boundary

The future protected orchestrator owns the cross-process Phase-B operation
lock and mutation journal. Before calling backend mutation methods, it must
exclude concurrent PDI operations (including P3D apply/activate/abort, P3C
cutover and Gate B/C), manual/config-management systemd/current changes, and
package maintenance affecting authority. The backend's in-process single
flight is not that lock; no persistent backend lock or caller-provided
`operation_lock_held` assertion is implemented.

Root compromise/adversarial root is outside this trust model. Debian systemd
257.13-1~deb13u1 offers neither the reviewed atomic compare-and-mutate primitive
nor an atomic WP8 multi-interface snapshot. Consequently:

```text
SYSTEMD_FINAL_AUTHORITY_ATOMIC_SNAPSHOT_CLAIM=NO
RESIDUAL_PRIVILEGED_EXTERNAL_MUTATION_RACE=UNAVOIDABLE_WITH_AVAILABLE_SYSTEMD_API
ROOT_ADVERSARY_INSIDE_TRUST_MODEL=NO
PDI_CONTROLLED_CONCURRENCY_MUST_SERIALIZE=YES
MANUAL_SYSTEMD_MUTATION_DURING_PHASE_B=PROHIBITED
```

## Complete independent observations

Each START and each individual STOP uses:

```text
complete A -> complete B -> exact domain -> equal stable fingerprint
           -> bounded runtime prerequisites -> one fixed command
           -> independent post-authority and post-state verification
```

B does not take A as an input. Both independently read full manager authority
(PID1/boot/namespaces/root, trusted local transport, exact package version and
ordered twelve-root UnitPath), immutable candidate/current/Gate B binding,
current Gate C asset/profile binding, loaded timers, and current frozen P3C
stable authority and expected health.

START independently reads all six canonical services, their normalized stable
text, all five typed execution hooks and Conditions/Asserts, mount/path and
directed transaction authority. It walks the bounded START closure, including
induced STOP conflicts and VERIFY-active edges. Every reachable reviewed
default contributes its loaded stable properties, relation members and
trusted fragment identity. Reachable emergency.service contributes its exact
identity and freshly typed ExecStop/ExecStopPost in both A and B; an unreachable
emergency service is not queried.

STOP independently reads the exact target with the same reviewed text/typed
contract and walks that target's directed STOP propagation closure. It never
uses a START closure or another target's observations as stop authority.
Existing policy rejects foreign stop propagation, even to P3C or timers.
Unrelated unsafe/active cleanup targets do not prevent processing the other
independently safe targets.

The private canonical domain enumerates all fields, typed schema members,
service/timer/P3C members, manager/context members, reachable unit/job members,
directed edges and path/mount relation members. Domain identity is checked
before aggregate fingerprint equality. Stable relation sets are sorted and
ExecStart is normalized to executable/argv, not its embedded invocation data.
No Activity, Job, InvocationID, result, exit status or runtime timestamp enters
the stable fingerprint. Private snapshot objects and raw transport output are
not exposed as public results.

## Final runtime gate and post-state

After A/B equality, bounded reads recheck the cheap manager continuity token,
current candidate, six disabled/inactive/no-job timers, current P3C health,
reachable default activity/pending jobs, and canonical service activity/jobs.
START requires all six inactive/dead/no-job, captures the selected prior
InvocationID/start time, and takes its monotonic fence immediately before the
fixed start. STOP checks its own target runtime state; an outstanding target
job may be stopped, but the final confirmation must prove Job empty. No full
manager/content hash, tree walk, profile scan or recursive graph traversal
occurs between completion of this gate and the command.

START is never retried. Its independent post-observations require a fresh,
nonzero, distinct InvocationID, a start at/after the final fence, ordered start
and exit timestamps, successful exit/result and inactive/dead/no-job, unchanged
stable domain/authority, quiet timers and expected P3C health. Each STOP is
issued at most once. It independently recollects complete authority and target
post-state; failed authority/continuity is never promoted to confirmed cleanup
by a later merely inactive read. All six cleanup targets are attempted only
when individually authorized, with no short circuit.

## Honest adversarial test categories

CATEGORY_A observes drift/incomplete evidence during A/B or the final runtime
gate: reject before start, or skip the unsafe STOP target while independently
processing remaining targets. Existing text/typed/emergency/graph/mount/manager/
current attacks retain pre-mutation rejection and are not blanket reclassified.

CATEGORY_B injects privileged external mutation after B and the final runtime
gate, before systemd processes the command: an issued command is possible.
Observable independent post-inconsistency must fail; it must not report a
successful start or confirmed cleanup. This is not an atomic-CAS guarantee,
continuous monitoring, or proof that an unobserved ABA did not happen.

## Preserved future gates

```text
FUTURE_C_APPLY_PARTIAL_TIMER_ENABLE_RISK=OPEN_HARD_BLOCKER_BEFORE_C
BLOB_HASH_ACTIVE_CALL_PATH_AUDIT=REQUIRED_BEFORE_PHASE_B_WORKLOAD
RESOURCE_ACCESS_ADAPTER_LIFECYCLE_AUDIT=OPEN
```

Real-systemd qualification remains a separately authorized gate on Debian 13
with systemd 257.13-1~deb13u1. Synthetic transport tests do not constitute it.
