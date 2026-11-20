# IROKA first-party task lifecycle API — A3 contract

Status: implementation in progress; no production task worker or protected-effect dispatcher is enabled.

## Routes

All routes are under `/api/v1`, require HTTPS at the trusted transport boundary, and return `Cache-Control: no-store`.

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/v1/tasks` | Submit a metadata-only task envelope |
| GET | `/api/v1/tasks/{task_id}` | Read task state |
| GET | `/api/v1/tasks/{task_id}/events?after={sequence}&limit={n}` | Read durable ordered event history |
| POST | `/api/v1/tasks/{task_id}/cancel` | Request cancellation |

The transport-neutral route adapter obtains the principal from the existing G01 ingress. It never accepts caller-authored subject, tenant membership, role, permission, policy version, or authorization booleans. A server-side `TaskAuthorizer` must resolve G02 tenant authority and G09 capability policy at request time. If no compliant adapter is configured, task operations must fail closed.

## Submission and idempotency

The request contains a tenant selector, idempotency key, client request ID, correlation ID, capability ID/version, expiry, and opaque input references. It does not accept prompt text, document bodies, credentials, or result payloads.

The server resolves the canonical tenant and policy version. Idempotency is scoped by `(tenant_ref, principal_ref, idempotency_key)`. A byte-identical semantic request replay returns the original task; reuse with a different request digest returns HTTP 409.

## Durable state and events

Task state is versioned and updated using a row lock plus compare-and-swap. Each successful transition and its append-only event commit in one PostgreSQL transaction. Events have stable IDs and monotonic per-task sequence numbers. Clients resume by sequence cursor.

States: `accepted`, `queued`, `running`, `awaiting_authorization`, `succeeded`, `failed`, `cancel_requested`, `cancelled`, `expired`.

Cancellation of queued work can become `cancelled`; cancellation of running work becomes `cancel_requested` and requires worker acknowledgment before `cancelled`. Terminal states cannot be reopened.

The database stores task metadata, input-reference identifiers, request digests, result references, and content-free event metadata only. It does not store user prompts, generated output, model credentials, or bearer tokens. Event metadata keys are allowlisted. The task event log is operational lifecycle evidence; it does not replace G11 audit receipts for protected effects.

## A3 gates still open

- Concrete production `TaskAuthorizer` adapter backed by current G02 and G09 authority.
- PostgreSQL migration execution and integration tests for create/replay/conflict, transition CAS, event ordering, append-only enforcement, and cancellation races.
- Worker lease/claim, bounded retries, expiry sweeper, and durable cancellation acknowledgment.
- Result storage/encryption and result-reference authorization.
- G11 audit integration before any protected external effect.
- HTTP listener wiring, TLS/proxy trust configuration, rate limits, and load/concurrency tests.
- No model/provider is selected or invoked by this task lifecycle slice.

This contract is not a deployment approval. Merge and deployment remain separately gated.
