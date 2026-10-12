# WP8 same-invocation runtime-proof handoff V0.1

Status: local backend implementation candidate; independent review and real
systemd qualification remain separate gates. This document implements only
Resolution A's private backend handoff. It does not implement Runtime Proof,
an orchestrator, operation persistence, or authorization consumption, and
authorizes no production access or workload.

The supplied Runtime Proof Handoff Resolution is proposed design evidence
`[R]`, not current execution evidence. The backend implementation here is a
separate development change to the reviewed backend baseline
`84000a34ce9a0c278e04cfc264e02ba1e4847e23`. Synthetic test results do not
establish disposable or production real-systemd qualification.

## Private return boundary

The eight public methods of `WP8ProductionSystemdBackend`, their call
signatures and exports remain unchanged. The private `_ServiceResult` gains
`execution_attestation: _ExecutionAttestationV1`; its private return shape
therefore changes. Frozen WP8 contracts and Phase A do not change.

`start_service()` constructs the attestation only after its existing full
authority A/B comparison, final runtime fence, exactly one fixed start,
fresh invocation and successful exit validation, independent post-authority
comparison, all-service inactivity, quiet timers and expected P3C health.
Failure, timeout, uncertain execution or post-check drift returns no successful
attestation and does not retry. The handoff copies verified locals from this
invocation; it adds no post-hoc systemd read, persistence or mutable result
cache. Timer mutation remains forbidden.

## Exact private schema

The private dataclass is `frozen=True, slots=True`. All fields are primitive
values; `to_mapping()` returns a fresh, validated mapping, not mutable internal
state. The exact thirteen fields are:

| Field | Requirement / origin |
| --- | --- |
| `version` | Exact integer `1`, not boolean |
| `pipeline_key` | One frozen canonical pipeline key |
| `unit` | Fixed canonical service mapping for that key |
| `candidate_sha` | Bound Phase A candidate, forty lowercase hex characters |
| `phase_a_context_fingerprint` | Same bound Phase A context SHA-256 |
| `manager_fingerprint` | Verified second full snapshot's manager SHA-256 |
| `unit_contract_fingerprint` | Second **full mutation-authority snapshot** SHA-256 |
| `start_monotonic_usec` | Same verified execution's positive integer start |
| `exit_monotonic_usec` | Same verified execution's integer exit, at/after start |
| `invocation_fingerprint` | SHA-256 of the fresh verified InvocationID |
| `result` | Fixed `success` after successful result validation |
| `exit_status` | Exact integer `0`, not boolean |
| `service_result_fingerprint` | Existing ten-key commitment, reproduced below |

Every fingerprint is exactly sixty-four lowercase hexadecimal characters.
Raw InvocationID, ExecStart, environment, subprocess output, credentials,
paths and business payload are absent. `unit_contract_fingerprint` must not
be substituted with the standalone `verify_service_contract()` result.

## Unchanged service-result fingerprint

`recompute_service_result_fingerprint()` uses the frozen
`contract_fingerprint()` over exactly the existing ten keys:

```python
{
    "candidate": attestation.candidate_sha,
    "context": attestation.phase_a_context_fingerprint,
    "pipeline": attestation.pipeline_key,
    "manager": attestation.manager_fingerprint,
    "contract": attestation.unit_contract_fingerprint,
    "start": attestation.start_monotonic_usec,
    "exit": attestation.exit_monotonic_usec,
    "invocation_hash": attestation.invocation_fingerprint,
    "result": attestation.result,
    "exit_status": attestation.exit_status,
}
```

No key, canonical serialization rule or hash algorithm changes. Construction
and serialization validate schema and recomputed digest equality.
`validate_binding()` additionally compares candidate, Phase A context and
expected canonical pipeline to the supplied validated Phase A binding; a
self-consistent foreign hash is insufficient. Both methods are pure.
`contract_fingerprint(attestation)` can canonically fingerprint the validated
thirteen-field mapping for a future protected sidecar; it does not replace
the existing service-result fingerprint.

## Authority limitations and deferred work

Frozen Python objects prevent ordinary mutation, not adversarial construction,
low-level reflection or replay. SHA-256 is a commitment, not a signature. A
caller can construct a self-consistent object, so recomputation or successful
context comparison alone does not prove producer origin or authorize work.
Consumers must receive the actual same-call result through the protected
orchestrator's verified execution/persistence chain. No bare mapping or hash
may reconstruct lost execution authority.

Operation identity, reviewed A/B authorization, single-use consumption,
journal sequence, protected pre/post read-only DB boundaries, unique fresh
PipelineRun/effect attribution and replay rejection remain the future
orchestrator/Runtime Proof responsibilities. No such module or database query
is added here. Phase A runtime coverage remains `0/6`; these synthetic backend
tests cannot create runtime ledger proof. Manager/boot continuity and clock
domain separation remain required by the existing design.

The existing non-atomic systemd observation/race limitations in
[the continuity design](pdi-p3d-wp8-systemd-continuity-v0.1.md) remain unchanged.
Real-systemd qualification is pending before production Phase B. The future
activation timer-enable risk, active blob-hash call-path audit and resource
access lifecycle audit remain open at their existing gates.
