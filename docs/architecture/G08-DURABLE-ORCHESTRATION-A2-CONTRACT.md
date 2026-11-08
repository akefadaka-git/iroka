# G08 Durable Orchestration — A2 Contract and Readiness Specification

**Document ID:** IROKA-G08-A2-001  
**Version:** 0.1.0  
**Status:** A2 contract draft for Owner disposition  
**Domain:** G08 — Orchestration  
**Architecture authority:** `docs/IMPLEMENTATION_STRATEGY.md` (initial approved strategy)  
**Repository baseline:** `main` at `143311a655be68acea2700650b7f88c9fb085526`  
**Prepared:** 2026-11-08

## 1. Purpose and scope

Define the smallest safe G08 vertical slice: durable workflow and task state, dependency ordering, idempotent submission, bounded worker leases, deterministic retry/cancellation, recovery after process restart, and auditable state transitions.

This is an A2 contract/specification artifact. It does not itself authorize code implementation, dependency adoption, merge, deployment, production data migration, or runtime activation. A separate Owner disposition of this contract is required before G08 A3 implementation.

### Included in the first G08 slice

- Tenant-scoped workflow and task records.
- Versioned state transitions with optimistic concurrency.
- A dependency DAG for task ordering, with cycle rejection.
- Idempotent workflow/task creation.
- Durable claim leases and bounded lease renewal.
- Bounded retry policy with explicit terminal outcomes.
- Cancellation and safe-stop semantics.
- Restart recovery for expired leases and interrupted tasks.
- Append-only transition evidence and correlation identifiers.
- Deterministic in-memory and local durable-store contract tests.

### Explicitly excluded

- Executing tools, commands, external API calls, payments, deployments, or other side effects.
- G09 execution grants or capability issuance.
- Agent identities/delegation (G07).
- Model calls, planning, or model-provider selection (G03).
- Knowledge ingestion/retrieval (G04).
- User-facing UI, scheduling/cron, distributed queue, multi-region operation, or production deployment.
- Live independent-witness enrollment or remote checkpoint publication.
- Production trust-root, Owner key, Genesis, or runtime activation changes.

The orchestrator is initially a durable coordinator of task records, not an autonomous executor.

## 2. Dependencies and baseline constraints

### 2.1 Kernel dependency

The eventual implementation may consume the verified Kernel's typed identity, policy-decision and audit contracts. It must not duplicate identity, Owner approval, policy, revocation, or audit authority.

Current relevant work is on unmerged feature branches:

- IGACMS A3 branch: `feat/igacms-a3-implementation`, observed HEAD `813b24cbf81f049f2675fbb5492bdc9f262a9d87`.
- A4-03 integration branch: `feat/a4-03-external-audit-checkpoint`, observed HEAD `810127ab8f5acc4614ad3ac62f8a565311b37817`.

These branches remain separate and unmerged. Any future G08 implementation branch must explicitly identify its base SHA and dependency relationship. This document does not authorize merging either branch.

### 2.2 Authorization boundary

- A workflow record, task record, task claim, successful state transition, or model-generated plan is never an authorization grant.
- The G08 layer cannot convert an `ALLOW` decision into permission to perform a side effect.
- G08 v0 must not invoke G09 adapters because G09 execution grants and protected-effect execution are not implemented/authorized in this scope.
- A task requiring approval may enter `WAITING_APPROVAL`; only the established governance path may record an approval decision. The orchestrator must not manufacture or infer approval.
- Missing, stale, revoked, ambiguous, or unavailable authorization evidence must prevent any future protected execution integration.

### 2.3 Witness boundary

The external checkpoint/witness adapter remains implemented but inactive. G08 must work with the existing local audit interface and exact-SHA CI. No live witness endpoint, mTLS enrollment, operator identity, or remote durability claim is a dependency or acceptance condition for this G08 slice. Audit records must not be described as externally anchored until live witness evidence exists.

## 3. Domain model

### 3.1 Workflow

A workflow is a tenant-scoped, versioned container for one bounded unit of work.

Required fields:

- `workflow_id`: globally unique opaque identifier.
- `tenant_id`: mandatory tenant boundary; never inferred from caller-controlled task payload.
- `owner_subject`: authenticated principal subject that submitted the workflow.
- `workflow_type` and `contract_version`: allowlisted type and schema version.
- `idempotency_key`: caller-supplied stable key, unique within tenant and workflow type.
- `input_ref` or bounded input payload: validated, classified reference/payload; secrets excluded.
- `state`, `version`, `created_at`, `updated_at`.
- `correlation_id`: stable trace identifier.
- `deadline_at` and resource budget where specified by the workflow contract.

A duplicate create with the same tenant, workflow type and idempotency key returns the original workflow identity and current state if the canonical request digest matches. Reuse with a different digest returns an explicit idempotency conflict and must not mutate the original workflow.

### 3.2 Task

A task is one typed step within a workflow.

Required fields:

- `task_id`, `workflow_id`, `tenant_id`.
- `task_type`, `task_contract_version`.
- `state`, monotonically increasing `version`.
- `attempt_count`, `max_attempts`, `next_attempt_at`.
- `lease_owner`, `lease_token_digest`, `lease_expires_at` when claimed.
- `input_ref`, optional `result_ref`, bounded error code (no secret-bearing raw error text).
- `created_at`, `updated_at`, `correlation_id`.

Task inputs and outputs are data, not instructions to the Kernel. They require classification, schema validation and tenant-scoped access checks.

### 3.3 Dependency

Dependencies form a directed acyclic graph (DAG). A task becomes eligible only when all prerequisite tasks have reached an explicitly acceptable terminal state. The initial contract supports success-only prerequisites; conditional branches and compensation graphs are deferred.

Cycle detection occurs before workflow activation. Cycles, missing prerequisite IDs, cross-workflow references, duplicate edges and tenant mismatches are rejected.

### 3.4 Transition evidence

Every accepted state transition appends a transition record containing:

- Event ID and sequence within the workflow.
- Workflow/task ID and tenant ID.
- Previous state/version and resulting state/version.
- Actor/service identity and transition reason code.
- Occurrence time and correlation ID.
- Relevant idempotency/lease token digest (never raw secret token).
- Canonical transition payload digest.

Transition records are append-only through the application interface. The mutable current-state projection and its transition record must be committed atomically. G08 local transition evidence is not a substitute for independent remote witness retention.

## 4. State machines

### 4.1 Workflow states

- `DRAFT`: definition accepted but not activated.
- `READY`: dependencies and required metadata validated.
- `RUNNING`: at least one task is actively claimed or executing a non-side-effecting handler.
- `WAITING_APPROVAL`: an explicit governance approval is required before further progression.
- `PAUSED`: Owner or authorized controller has paused the workflow.
- `SUCCEEDED`: all required tasks succeeded.
- `FAILED`: terminal failure policy reached.
- `CANCELLED`: cancellation completed with no unsafe active work remaining.
- `EXPIRED`: workflow deadline passed before completion.

Only documented transitions are accepted. Terminal states cannot be reopened by ordinary task updates. A new attempt requires a new workflow or a separately versioned recovery operation.

### 4.2 Task states

- `PENDING`
- `READY`
- `CLAIMED`
- `RUNNING`
- `WAITING_APPROVAL`
- `RETRY_WAIT`
- `SUCCEEDED`
- `FAILED`
- `CANCELLED`
- `SKIPPED`

A task handler may only update a task using the current state version and valid lease token. Stale versions, expired leases, mismatched lease owners, invalid transitions and duplicate completion submissions fail without state mutation.

### 4.3 Transition invariants

1. Every transition increments the relevant version exactly once.
2. State update and transition event are one atomic transaction.
3. Event IDs and idempotency keys are unique within their defined scope.
4. A task cannot become `READY` until all prerequisites satisfy the dependency contract.
5. A task cannot be claimed by two workers concurrently.
6. A lease token is high entropy, returned only to the claimant, stored only as a cryptographic digest, and never logged.
7. A lease renewal requires the current token, owner, version and an unexpired lease; renewal cannot extend beyond the configured maximum lease horizon.
8. An expired lease can be reclaimed only through a recovery transition that records the previous claim as expired.
9. A terminal task cannot be completed, retried or cancelled again through ordinary worker APIs.
10. A workflow cannot report `SUCCEEDED` while any required task is non-terminal or unsuccessful.

## 5. Claiming, retry and recovery semantics

### 5.1 Claim leases

- Claim is atomic and selects only an eligible `READY` task.
- Lease duration and renewal interval are configuration values with safe upper bounds; callers cannot supply arbitrary unbounded durations.
- Lease ownership is a service/worker identity, not a user-provided string.
- Lease tokens are random, opaque, single-claim credentials; persist only a digest.
- Claim and transition evidence commit together.

### 5.2 Retry policy

- Retry is allowed only for task types explicitly declared retry-safe.
- The workflow contract defines `max_attempts`, allowed error classes and bounded backoff.
- No unbounded retries; attempts and elapsed time are both bounded.
- Non-retryable errors become terminal `FAILED`.
- Repeated idempotent submission returns the existing state; it does not create a new attempt.
- No blind retry of external side effects. Such effects are excluded from G08 v0 and require future G09 idempotency/reconciliation contracts.

### 5.3 Restart recovery

On startup or explicit recovery invocation:

1. Read a consistent snapshot of non-terminal workflow/task state.
2. Identify expired claims and elapsed deadlines using a trusted clock abstraction.
3. Record recovery transitions atomically.
4. Return expired claimed tasks to `READY` or `RETRY_WAIT` only when their task contract permits retry.
5. Mark non-retryable interrupted tasks `FAILED`.
6. Recompute workflow projections from durable task state and append reconciliation evidence.
7. Never infer that a handler's external side effect did or did not occur; external effects are out of scope and require future reconciliation support.

Recovery must be idempotent: repeated recovery passes over unchanged state produce no duplicate transitions or state regression.

## 6. Persistence and concurrency contract

The first implementation may use a replaceable repository interface and a local SQLite adapter, subject to A2 dependency/license review and explicit single-node limitation.

Required semantics:

- Atomic transaction for workflow/task state plus transition evidence.
- Unique constraints for IDs, idempotency keys and per-workflow event sequence.
- Compare-and-swap state version updates.
- Foreign keys and tenant-consistency constraints.
- Explicit busy/lock timeout and fail-closed behavior on storage errors.
- WAL recovery and process restart tests.
- No partial activation if a transaction fails.
- No silent repair or destructive migration of existing production data.

A production multi-node deployment would require a separately assessed shared transactional backend with equivalent semantics. SQLite local durability must not be represented as distributed durability.

## 7. API / Rust interface contract (provider-neutral)

The initial domain API should be expressed as typed Rust traits/structs and domain errors, with persistence hidden behind a repository trait. Exact names are provisional until implementation review.

Conceptual operations:

- `create_workflow(request) -> WorkflowSnapshot`
- `get_workflow(tenant, workflow_id) -> WorkflowSnapshot`
- `activate_workflow(tenant, workflow_id, expected_version) -> WorkflowSnapshot`
- `claim_next_task(worker_identity, lease_policy) -> Option<ClaimedTask>`
- `renew_lease(claim, renewal_request) -> LeaseSnapshot`
- `complete_task(claim, result_ref) -> WorkflowSnapshot`
- `fail_task(claim, error_code) -> WorkflowSnapshot`
- `cancel_workflow(actor, workflow_id, expected_version) -> WorkflowSnapshot`
- `recover_expired_leases(now) -> RecoveryReport`

All operations must carry or derive authenticated tenant context. Public methods must not accept a caller-selected tenant without verifying it against the authenticated principal. No method in G08 v0 performs a protected external side effect.

Domain errors must distinguish at least: not found, tenant mismatch, invalid state transition, version conflict, idempotency conflict, dependency cycle, dependency not satisfied, lease expired, lease mismatch, retry exhausted, deadline elapsed, invalid payload, and storage unavailable.

## 8. Security and abuse cases

| Threat | Required control / test |
|---|---|
| Cross-tenant workflow lookup or mutation | Tenant-scoped queries and negative isolation tests |
| Duplicate create/replay | Stable idempotency key plus canonical digest comparison |
| Concurrent workers claim same task | Atomic claim and race test; exactly one winner |
| Stale worker completes after lease expiry | Lease token/version validation; reject without mutation |
| Lease theft or token disclosure | High-entropy token, digest-only persistence, no logging |
| Dependency cycle or forged dependency | DAG validation and cross-workflow/tenant rejection |
| Retry storm/resource exhaustion | Max attempts, deadline, bounded backoff and task quotas |
| Process crash mid-transition | Atomic transaction; reopen/recovery test |
| Malicious task payload / prompt injection | Strict typed payload; untrusted content cannot alter policy or authority |
| Storage unavailable or corrupt | Fail closed; no false success; recovery/error surfaced |
| Audit/transition event mutation | Append-only application API, integrity checks and mutation-detection tests |
| Unauthorized cancellation/pause | Authenticated actor and explicit policy/approval boundary |

## 9. Acceptance matrix

| ID | Acceptance requirement | Evidence |
|---|---|---|
| G08-A2-01 | Workflow/task schemas are versioned and tenant-scoped | Schema/contract tests |
| G08-A2-02 | DAG is acyclic and dependencies are workflow-local | Positive and negative graph tests |
| G08-A2-03 | Duplicate create is idempotent; changed payload conflicts | Replay/conflict tests |
| G08-A2-04 | State transition and event append are atomic | Transaction fault-injection tests |
| G08-A2-05 | Concurrent task claim has one winner | Multi-connection race test |
| G08-A2-06 | Stale/expired lease cannot mutate task | Expiry, token and version tests |
| G08-A2-07 | Retry is bounded and only enabled for declared retry-safe types | Retry exhaustion/backoff tests |
| G08-A2-08 | Restart recovery is idempotent and never infers external-effect status | Crash/reopen/recovery tests |
| G08-A2-09 | Cross-tenant access is denied | Isolation matrix |
| G08-A2-10 | Audit transition evidence is complete and correlated | Event-chain and transition trace tests |
| G08-A2-11 | Storage errors fail closed without partial state | Busy, disk-full and transaction-abort tests |
| G08-A2-12 | G08 cannot invoke protected side effects or issue execution grants | API surface review and compile-time boundary tests |
| G08-A2-13 | Local persistence limitation is explicit; no distributed durability claim | Architecture and operations documentation |

## 10. Risks and open decisions

| ID | Risk / decision | Current disposition |
|---|---|---|
| G08-R01 | Kernel A3/A4 branches are unmerged | Preserve stack relationship; do not silently rebase or merge |
| G08-R02 | No G09 execution grant exists | Keep G08 coordinator-only |
| G08-R03 | Multi-node persistence not qualified | SQLite limited to local/single-node development |
| G08-R04 | Clock anomalies affect lease expiry | Inject clock; define monotonic runtime behavior and wall-clock persistence semantics |
| G08-R05 | Cancellation races with claim/complete | Serialize transitions; race-test |
| G08-R06 | Task payload may contain sensitive data | Prefer references; classification and bounded storage required |
| G08-R07 | Live independent witness is deferred | No external assurance claim; not a G08 blocker |
| G08-R08 | Workflow type/schema registry governance | Require allowlisted versioned task contracts; no dynamic executable workflow code |

Unresolved before A3:
- Exact Rust module placement and trait names.
- Clock abstraction and maximum lease policy defaults.
- Whether initial SQLite schema is a standalone new module or an extension to an existing persistence module.
- Exact task input size and per-tenant quota defaults.
- Final domain error naming and API visibility.
- Trace/audit adapter wiring against the approved Kernel branch.

No external framework, queue, database server, model provider or paid service is selected by this specification.

## 11. A2 exit criteria and Owner disposition

A2 may be considered ready for closure when:

1. The Owner accepts the coordinator-only scope and exclusions.
2. The Kernel integration boundary is reconciled against exact approved A3/A4 branch SHAs.
3. The persistence and dependency choices are reviewed; no dependency is adopted by this document.
4. The acceptance matrix and threat controls are accepted.
5. The open decisions in Section 10 are either resolved or explicitly deferred with rationale.
6. A3 implementation authorization is separately recorded for the selected exact scope.

**Current status: PARTIAL — contract draft prepared; Owner disposition and final interface reconciliation are pending.**

## 12. Governance and assurance boundary

- This document is a proposed G08 A2 contract, not an implementation, merge or deployment authorization.
- Existing independent code-review waiver remains applicable to the previously authorized A3 work; no independent review is claimed.
- No live witness integration is required for this work package. The A4-03 live witness status remains `DEFERRED / NOT RUN / UNVERIFIED`.
- The external checkpoint adapter must remain inactive until separately provisioned and tested.
- No production trust roots, Owner private keys, Genesis activation, production data migration, deployment, merge or runtime promotion is authorized or performed.
- Any future G08 implementation must preserve the existing Kernel authority boundary and must not add an execution path around it.

**Operating rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.
