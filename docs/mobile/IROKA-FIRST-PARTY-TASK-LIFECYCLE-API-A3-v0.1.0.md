# IROKA first-party task lifecycle API — A3 contract

Status: PostgreSQL lifecycle and canonical G02 tenant-resolution tests pass. Durable worker lease claim/renew/completion/cancellation-acknowledgement, bounded retry/reclaim, and expiry-sweeper primitives are implemented and require exact-head CI. No live HTTP task route, worker process, model invocation, or protected-effect dispatcher is enabled.

## Routes

All routes are under `/api/v1`, require HTTPS at the trusted transport boundary, and return `Cache-Control: no-store`.

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/v1/tasks` | Submit a metadata-only task envelope |
| GET | `/api/v1/tasks/{task_id}` | Read task state |
| GET | `/api/v1/tasks/{task_id}/events?after={sequence}&limit={n}` | Read durable ordered event history |
| POST | `/api/v1/tasks/{task_id}/cancel` | Request cancellation |

The transport-neutral route adapter obtains the principal from the existing G01 ingress. It never accepts caller-authored subject, tenant membership, role, permission, policy version, or authorization booleans. The production `G02G09TaskAuthorizer` composes current G02 tenant membership/emergency-stop checks with a G09 capability decision against one signed policy snapshot. The exact policy version returned by that decision is persisted with the task. Deployment-owned capability/version/risk grants are allowlisted; Android cannot choose risk, grant permissions, or supply policy versions. Read and cancel require separate `iroka.task.read` and `iroka.task.cancel` G09 capabilities and are currently owner-only. If no compliant adapter is configured, task operations must fail closed.

## Submission and idempotency

The request contains a tenant selector, idempotency key, client request ID, correlation ID, capability ID/version, expiry, and opaque input references. It does not accept prompt text, document bodies, credentials, or result payloads.

The server resolves the tenant selector by exact match against the active Owner-authorized G02 `tenant_ref` membership key and stores only the reference returned by G02. G02 currently defines no tenant-alias mapping: a selector that is not the exact canonical reference is denied. G09 then rechecks active membership and evaluates the deployment-granted capability and risk against one current signed policy snapshot. The policy evaluator currently enforces capability, risk, and emergency-stop state; task ownership is enforced separately by the task authorizer. Idempotency is scoped by `(tenant_ref, principal_ref, idempotency_key)`. A byte-identical semantic request replay returns the original task; reuse with a different request digest returns HTTP 409.

## G11 audit envelope

The shared PostgreSQL G11 chain now supports a domain-neutral, content-free audit envelope alongside the existing G05 memory event domain. Task events retain their own task/tenant/principal/capability/resource identifiers and are not represented as memory records. G11 acceptance remains idempotent by event ID and envelope digest; both domains share the serialized chain head and append-only receipt ledger. Task terminal completion and cancellation acknowledgement now require a matching G11 receipt. A typed pre-effect G11 permit gate is implemented and tested. A protected-effect executor, worker-service authentication, and live worker host remain unimplemented; no external effect is enabled.

## Worker lease boundary

The PostgreSQL worker repository supports atomic claim, lease renewal, lease-token-guarded completion, and durable cancellation acknowledgement. Claim uses `FOR UPDATE SKIP LOCKED`; the database generates each lease token. These are internal repository operations only: no worker HTTP endpoint, worker-service authentication, model invocation, or protected-effect dispatcher is enabled. Lease-expiry reclaim, bounded retry scheduling, and the expiry sweeper remain open.

## Durable state and events

Task state is versioned and updated using a row lock plus compare-and-swap. Each successful transition and its append-only event commit in one PostgreSQL transaction. Events have stable IDs and monotonic per-task sequence numbers. Clients resume by sequence cursor.

States: `accepted`, `queued`, `running`, `awaiting_authorization`, `succeeded`, `failed`, `cancel_requested`, `cancelled`, `expired`.

Cancellation of queued work can become `cancelled`; cancellation of running work becomes `cancel_requested` and requires worker acknowledgment before `cancelled`. Terminal states cannot be reopened.

The database stores task metadata, input-reference identifiers, request digests, result references, and content-free event metadata only. It does not store user prompts, generated output, model credentials, or bearer tokens. Event metadata keys are allowlisted. The task event log is operational lifecycle evidence; it does not replace G11 audit receipts for protected effects.

## A3 gates still open

- Exact-head CI for the canonical G02 tenant-resolution adapter and its PostgreSQL integration test.
- PostgreSQL migration execution and integration tests for create/replay/conflict, transition CAS, event ordering, append-only enforcement, and cancellation races.
- Worker-service identity and authenticated internal host wiring.
- A4 verification of G02 signed-membership projection integrity and database runtime-role restrictions.
- Result storage/encryption and result-reference authorization.
- G11 audit integration before any protected external effect.
- HTTP listener wiring, TLS/proxy trust configuration, rate limits, and load/concurrency tests.
- No model/provider is selected or invoked by this task lifecycle slice.

This contract is not a deployment approval. Merge and deployment remain separately gated.
