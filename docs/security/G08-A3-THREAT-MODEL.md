
# G08 A3 Security Threat Model

Status: design and review baseline; NOT a completed independent security assessment.
Scope: G08 coordinator persistence, trusted time, worker identity, replay protection,
registry lifecycle, event history, and the SQLite adapter boundary.

## Assets and security invariants

- Tenant isolation: a principal may read or mutate only workflows in a currently
  authoritative tenant scope.
- Workflow integrity: idempotency, DAG structure, state versions, leases, retries,
  cancellation markers, and events must commit atomically.
- Worker authenticity: only an active worker key, bound to the exact worker identity
  and operation scope, may claim, renew, or complete work.
- Replay resistance: a worker/key sequence is strictly monotonic across process
  restarts and concurrent verifier processes sharing the same persistence authority.
- Time integrity: authorization freshness, lease expiry, retry not-before, event
  ordering, and persisted timestamps must use a trusted clock, never caller input.
- Audit integrity: event history is append-only and state changes have matching
  event records in the same transaction.

## Adversaries and trust boundaries

1. Malicious tenant member: changes tenant selectors, replays idempotency keys,
   guesses resource IDs, races state transitions, or submits stale versions.
2. Compromised or malicious worker: forges identity, reuses signed proofs,
   replays sequence values, renews expired leases, or operates after revocation.
3. Malicious or faulty time source: signs stale, future, divergent, duplicated,
   expired, or rolled-back time attestations.
4. Database fault or partial write: disk full, I/O error, lock contention,
   constraint/trigger failure, failed commit, or corrupted rows.
5. Privileged database rollback: restores an older SQLite file or snapshot,
   erasing replay high-water marks, registry versions, or clock watermarks.
6. Compromised Owner root: signs malicious worker registry contents or revocations.
7. Dependency/build compromise: alters cryptographic, serialization, SQLite, or
   compiler behavior, or introduces a development-only bypass into production.

## Controls and required evidence

| Threat | Control | Required verification |
|---|---|---|
| Cross-tenant access | G01 principal + authoritative G01/G02 tenant scope; resource-scoped queries | negative cross-tenant contract tests and live issuer adapter review |
| Stale membership | freshness-bounded tenant resolution | clock-backed tests; fail closed on stale resolver |
| Worker forgery | Ed25519 proof, canonical JCS payload, exact scope and registry key | forged signature, wrong scope, unknown key, expired key tests |
| Worker replay | durable atomic monotonic sequence per worker/key | independent OS-process race, restart, database rollback threat analysis |
| Time rollback | signed distinct-source quorum, source sequences, global high-water, monotonic in-process anchor | quorum divergence, stale source, restart, DB rollback and source outage tests |
| Partial state/event writes | single SQLite transaction for state and append-only event | injected insert failure and failed-commit rollback tests |
| Registry partial rotation | signed versioned snapshot replacement in one transaction | injected mid-install failure; prior version remains wholly intact |
| Revocation | live fail-closed registry check at each authenticated operation | separate-process revocation visibility and cache invalidation tests |
| DB snapshot rollback | external monotonic anchor or independent witness | restore attack test against production anchor; SQLite alone is insufficient |
| Audit gaps | canonical G11 outbox and independent receipt/witness | delivery, idempotency, retry and tamper-evidence integration review |

## Known limitations / explicit exclusions

- SQLite WAL and BEGIN IMMEDIATE serialize writers sharing one database file; they do
  not provide consensus across independent database files or hosts.
- A privileged actor able to restore the complete database can roll back SQLite-only
  sequence and version state. Production deployment requires an independently
  protected monotonic anchor or remote witness.
- Test keys are deterministic fixtures only. They are not production Owner root keys,
  time-source keys, or worker credentials.
- No production time-source adapter, Owner root custody procedure, issuer-side G01
  registry, or live key lifecycle service is established by these tests.
- Android, host OS, filesystem, hypervisor, cloud control plane, and physical access
  are outside this coordinator's enforcement boundary.
- No availability guarantee is made when trusted time, registry state, replay storage,
  or tenant authority is unavailable; operations must fail closed.

## A4 entry criteria

1. Every public coordinator mutation obtains one TrustedClock observation internally
   and removes caller-supplied time fields from public request types.
2. The exact same observation is used for authority freshness, state writes, lease
   comparisons, retry scheduling, cancellation, event timestamps, and event IDs.
3. Mutation and append-only event commit atomically; tests cover failed inserts and
   failed commits and prove no partial state/event pair survives.
4. Genuine subprocess tests prove replay serialization, restart persistence, and
   revocation visibility against a shared database file.
5. G01/G02/G05/G11 integration boundaries are reconciled and independently reviewed.
6. An independent security reviewer records findings against an immutable exact head;
   all critical/high findings are fixed and retested before A4.
7. Production anti-rollback and key custody designs are independently reviewed.

## Review record

Independent review: NOT PERFORMED.
Reviewer identity, review date, reviewed commit SHA, scope, findings, severity,
remediation evidence, and sign-off must be recorded by a reviewer who did not author
the implementation. CI success is not a substitute for this review.
