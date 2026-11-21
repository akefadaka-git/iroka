# G08 Temporal Integration — A2 Contract Proposal

**Document ID:** IROKA-G08-TEMPORAL-A2-001  
**Version:** 1.0.0-proposal  
**Status:** A2 PROPOSAL — pending Owner disposition; NOT APPROVED  
**Domain:** G08 — Orchestration, with G01/G02/G11 dependencies  
**Parent work:** INNIA A2 reconciliation PR #135  
**Repository baseline:** `main` at `1aea1447eadf1d827d702fd6c4034fa058aac21e`  
**Candidate evidence:** G08 durable coordinator PR #63, branch `feat/g08-a3-durable-coordinator`, documented head `716cb7c50047179fb02a04f3f35b52cd2e634deb`; workflow run `43226262482` concluded `action_required`  
**Prepared:** 2026-11-21

## 1. Purpose

Define the temporal trust boundary required for IROKA's durable orchestration and for any later neural task lifecycle integration. This proposal closes the design gap between the G08 trusted-time primitive and the G08 coordinator APIs that still accept caller-provided timestamps.

This is an A2 specification proposal only. It authorizes no source implementation, dependency adoption, merge, deployment, production activation, clock-source enrollment, key provisioning or model-runtime work.

## 2. Normative principles

The terms MUST, MUST NOT, SHOULD and MAY are normative.

1. Security decisions use an internally obtained trusted UTC instant, never a caller-supplied timestamp.
2. Each public state-changing operation MUST obtain exactly one trusted-time observation and use that same observation for all time-dependent checks and writes in that operation.
3. Failure to obtain valid trusted time MUST fail closed before any protected state mutation.
4. Wall-clock UTC instants, process-monotonic elapsed time and logical event sequence numbers are separate domains and MUST NOT be substituted for one another.
5. A workflow, task, lease, retry or temporal schedule is not an authorization grant and MUST NOT bypass G01, G02 or G09.
6. Temporal evidence MUST be auditable through G11, without representing local database evidence as externally witnessed.

## 3. Time domains and representation

### 3.1 Canonical persisted instant

- Canonical machine instant: unsigned Unix seconds since 1970-01-01T00:00:00Z, subject to the selected storage integer range.
- Persistence and comparison: UTC only.
- Serialization at API boundaries: RFC 3339 UTC with explicit `Z`; reject ambiguous local timestamps for security-sensitive inputs.
- Precision: the initial coordinator contract uses whole seconds. Higher precision requires a versioned contract change and explicit database/evidence compatibility review.
- Overflow, negative conversion, zero/sentinel misuse and out-of-range values MUST be rejected.

### 3.2 Monotonic process time

A process-monotonic clock such as Rust `Instant` MAY advance a recently authenticated UTC anchor within the current process. It MUST NOT be persisted, compared across processes, or treated as a UTC instant. Restart invalidates the process anchor and requires a fresh trusted-time quorum before time-sensitive recovery or mutation.

### 3.3 Logical ordering

Every workflow/task event has a durable monotonic sequence within its defined scope and a unique event ID. Sequence defines causal order when two events share the same second; timestamps alone do not establish total order.

### 3.4 Civil calendar and localization

User-facing dates are a presentation layer:
- Persist canonical UTC instants.
- Resolve local display using an explicit IANA timezone (default locale preference may be Africa/Addis_Ababa, but must be supplied/configured rather than inferred from a device timestamp).
- Carry a calendar identifier separately from timezone. Gregorian and Ethiopian-calendar rendering may be supported by the UI/calendar adapter.
- Calendar conversion MUST NOT change the underlying UTC instant, deadline comparison, lease expiry, retry schedule, audit order or signature payload.
- A future local-time scheduler must define DST gaps/folds and Ethiopian-calendar month/day conversion as a separate versioned contract. Scheduling/cron is not silently added to this coordinator slice.

## 4. Trusted-time observation contract

### 4.1 Clock authority

The G08 trusted clock is an injected trusted-computing-base adapter. It MUST have no host-wall-clock or caller-time fallback. It MUST return unavailable/invalid when:
- fresh authenticated quorum is absent;
- attestation signature, source/key binding or validity window is invalid;
- source identity is duplicated within one quorum;
- configured quorum is not met;
- source skew exceeds policy;
- source sequence or global high-water monotonicity fails;
- the attestation anchor expires;
- required persistence or integrity checks fail.

### 4.2 Source independence

Distinct source IDs alone do not establish independent time authorities. Before production use, the trust roster MUST document:
- legal/operational controller of each source;
- infrastructure and network failure-domain separation;
- key custody, issuance, rotation, expiry and revocation;
- source health and compromise response;
- quorum size, tolerated failures and maximum skew;
- authenticated configuration provenance and version.

The initial SQLite quorum clock is a candidate reference adapter only. It is not production time infrastructure.

### 4.3 Observation envelope

The clock SHOULD expose a structured immutable observation rather than only a bare integer. The envelope should bind:
- accepted UTC Unix instant;
- observation ID;
- attestation-set digest;
- accepted source IDs, key IDs and source sequence numbers;
- quorum and skew policy version;
- earliest attestation expiry;
- persisted high-water value or reference;
- monotonic-anchor generation (process-local; not a persisted timestamp).

The exact schema and privacy-safe evidence fields require G08/G11 review. No private key material is included.

## 5. Coordinator API boundary

### 5.1 Public request types

Caller-facing mutation requests MUST NOT contain authoritative `now`, `created_at`, `updated_at`, `occurred_at`, `claimed_at`, `expires_at`, `not_before` or equivalent fields.

Callers MAY provide bounded intent values such as:
- requested deadline duration or deadline policy identifier;
- requested lease duration within a server-owned hard maximum;
- idempotency key;
- task retry-safe failure class;
- cancellation request and reason code.

The server computes absolute instants internally. If an absolute deadline is required by a future API, it must be derived from a signed, versioned policy or explicitly authorized scheduling contract—not trusted merely because a client submitted it.

### 5.2 One observation per mutation

At entry to each public state-changing operation:
1. authenticate principal/worker through the proper G01/G08 path;
2. obtain one trusted-time observation;
3. use its accepted instant for tenant-membership freshness and worker-proof time validation;
4. perform all deadline, lease, retry, cancellation and state-transition checks using that same instant;
5. persist state and transition evidence atomically with that same instant and observation reference.

If identity verification itself requires time, the composition boundary must ensure the same observation is passed into G01 verification rather than sampling a second clock. No transaction may continue with a stale observation beyond the policy's operation-duration bound; the bound must be specified and tested.

### 5.3 Mutation inventory requiring conversion

The inspected PR #63 candidate exposes caller-time inputs in:
- workflow creation (`CreateWorkflow.now`);
- task-graph creation (`now` argument);
- task transition (`TaskTransitionRequest.now`);
- legacy task claim (`TaskClaimRequest.now`);
- lease renewal and completion requests (`now`);
- retry scheduling (`TaskRetryRequest.now`);
- workflow cancellation (`WorkflowCancellationRequest.now`).

All public mutation entry points, including alternate authenticated-worker methods, recovery methods and future API handlers, MUST be included in the final inventory. Removing a field from one struct while leaving a parallel method accepting caller time does not satisfy this contract.

## 6. Temporal lifecycle rules

### 6.1 Workflow deadlines

- Deadline policy is versioned and bounded by a server-defined maximum horizon.
- Workflow expiry is evaluated against the operation's trusted observation.
- Terminal state cannot be reopened by a late client request.
- A deadline crossing during a transaction is evaluated consistently against the one captured observation; a later observation applies to the next operation.

### 6.2 Worker leases

- Lease duration is server-bounded and validated before persistence.
- `expires_at = trusted_now + bounded_lease_duration`, with checked arithmetic.
- Renewal requires current worker proof, exact task/lease version, valid lease token and a lease that has not expired at the captured instant.
- Renewal rotates the bearer lease token and increments the lease version atomically with its event.
- Expired leases are reclaimed only by an explicit recovery transition, never by silently changing the owner.

### 6.3 Retry

- Only explicitly retry-safe task types and transient failure classes may retry.
- Both maximum attempts and maximum total elapsed retry horizon are bounded.
- `not_before = trusted_now + bounded_backoff`, using checked arithmetic.
- A task is eligible only when the captured trusted instant is at or after `not_before`.
- Permanent, integrity, authority and cancellation failures are terminal.
- Retry never repeats an external side effect; G09 idempotency/reconciliation is a separate prerequisite.

### 6.4 Cancellation and races

- Cancellation is an authenticated request, not a client-supplied cancellation timestamp.
- The coordinator captures one trusted instant, atomically records cancellation intent and transition evidence, and applies documented precedence against task completion/lease expiry.
- Concurrent completion/cancellation is resolved by transaction serialization plus expected state versions; exactly one valid transition wins.
- A cancellation receipt records the accepted event sequence and observation reference.

### 6.5 Recovery

- Time-sensitive recovery MUST NOT run before a fresh trusted quorum is available after restart.
- It identifies expired leases/deadlines against one captured observation and writes all recovery state/event pairs atomically.
- Repeated recovery over unchanged state is idempotent.
- Clock unavailable means recovery is deferred; no host clock or persisted caller time is used to guess.
- Recovery MUST NOT infer whether an excluded external side effect occurred.

## 7. Atomicity and G11 evidence

For each accepted mutation:
- mutable state projection, transition event, event sequence, trusted UTC instant and observation reference commit in one transaction;
- append-only constraints reject ordinary update/delete of prior event rows;
- audit/outbox failure follows the G11 fail-closed rule;
- event payload digest binds the canonical transition data, policy version, actor reference, state versions and temporal observation reference;
- independent checkpoint/retention is required for production anti-rollback; SQLite hash/high-water state alone is insufficient.

A successful local transaction is not proof of external witness receipt.

## 8. Failure semantics

| Failure | Required result |
|---|---|
| Trusted clock unavailable/expired | Reject mutation; no state/event write |
| Invalid signature, source or quorum | Reject; record bounded security diagnostic if trusted audit path is available |
| Source sequence or global high-water rollback | Reject and escalate; do not reset watermark |
| Membership freshness cannot be checked | Deny tenant-scoped mutation |
| Arithmetic overflow or invalid duration | Reject before transaction |
| Persistence/commit failure | Roll back state and event together |
| Audit/outbox failure | Fail closed / ESCALATE according to G11 |
| Clock expires during process lifetime | Stop time-sensitive operations until fresh quorum |
| Restart without fresh quorum | Defer lease/deadline recovery |

## 9. Required acceptance matrix

The exact A3 candidate must include deterministic tests for at least:

1. Every public mutation succeeds with trusted clock and has no caller-time field.
2. Forged/future/expired/duplicate-source attestations fail closed.
3. Missing quorum, excessive skew, expired anchor and unavailable clock produce no state change.
4. Source-sequence and global high-water rollback are rejected.
5. Restart requires fresh quorum before lease/deadline recovery.
6. Tenant-membership freshness and worker proof validation use the same captured observation as the transaction.
7. Lease claim, renewal, completion and expiry races are serialized; stale versions fail.
8. Retry backoff and total elapsed retry horizon are bounded; overflow fails.
9. Cancellation/completion race has exactly one winner and one event.
10. Event timestamps and event sequence match the committed state transition.
11. Injected event insert and transaction commit failures roll back state and event.
12. Repeated recovery produces no duplicate transitions or regressions.
13. Clock outage after restart causes no guessed recovery action.
14. No use of `SystemTime`, `Utc::now`, caller timestamps or a test clock in production paths.
15. UTC persistence and Ethiopian/Gregorian display conversion preserve the same underlying instant.

Tests must run against the exact PR head and include formatting, locked workspace compile, no-default-features compile, full workspace tests and Clippy. Independent review remains separate from CI.

## 10. Security and operational blockers

Before production consideration:
- approve a genuinely independent time-source roster and key custody;
- establish protected external monotonic anti-rollback anchoring for clock and replay state;
- review SQLite file permissions, backup/restore and failure recovery;
- define operational quorum monitoring and safe outage response;
- independently review the temporal threat model and exact immutable source SHA;
- integrate G01 tenant authority and G11 audit/checkpoint evidence;
- verify multi-node behavior separately; SQLite shared-file behavior is not consensus.

## 11. Relationship to neural infrastructure

INNIA/BRAIN/INGA/native cognition task envelopes may carry:
- task creation and deadline policy references;
- submission and execution observation references;
- bounded duration budgets;
- completion/cancellation event references.

They MUST NOT create their own clock, infer trusted time from model output, override deadlines, extend leases, schedule retries, or bypass G08. Model-generated timestamps are untrusted content. A model's proposed deadline is only an intent requiring G08 policy validation.

G03 model/runtime evaluation and G10/G12 training promotion remain distinct. This temporal contract does not authorize neural runtime code.

## 12. Open A2 decisions

- Confirm the trusted-time source operators and independent failure domains.
- Approve quorum size, maximum skew, attestation TTL and refresh policy.
- Select the external anti-rollback anchor and G11 evidence destination.
- Approve hard maxima for workflow deadlines, lease duration, retry attempts and total retry horizon.
- Confirm whether all time-sensitive G01/G02 checks can share one observation at the service boundary.
- Approve the UTC persistence and Ethiopian/Gregorian calendar presentation split.
- Approve the versioned temporal observation evidence schema.

## 13. Gate disposition

| Gate | Status |
|---|---|
| Existing candidate primitive inspected | PASS / READ-ONLY |
| Caller-time API gap identified | PASS / DOCUMENTED |
| Temporal contract proposal authored | PROPOSED / NOT APPROVED |
| Exact-head coordinator temporal compliance | FAIL / NOT SATISFIED |
| Production time-source roster and custody | MISSING |
| External anti-rollback anchor | MISSING |
| Independent security review | NOT PERFORMED |
| A2 temporal integration closure | NOT READY |
| A3 implementation authorization | NOT GRANTED BY THIS DOCUMENT |
| Merge, deployment or production activation | NOT AUTHORIZED |

**Conclusion:** G08 has a promising signed-quorum trusted-time primitive, but the coordinator still accepts caller-supplied time and therefore does not yet enforce one authoritative temporal observation across its public mutations. Approve and freeze this contract before any temporal API refactor. This proposal is not a claim of production readiness.

---
**End of G08 Temporal Integration A2 Contract Proposal**
