# ADR: Shared G05/G11 persistence on PostgreSQL

- Status: Accepted for implementation; not a production approval.
- Date: 2026-11-12
- Decision owner: IROKA Owner approval in project conversation.
- Supersedes: the single-process SQLite-only deployment assumption.

## Decision

PostgreSQL is the shared multi-instance persistence target for G05 memory
records and the G11 delivery outbox. SQLite remains a local development and
single-process test adapter. It must not be described as a shared multi-node
production store.

G05 record mutation and creation of its content-free G11 outbox event MUST
share one PostgreSQL transaction. Optimistic state transitions MUST include
the expected record version and expected lifecycle state in the UPDATE
predicate; exactly one affected row is required. PendingAudit -> Active is
reserved for the receipt-verified finalization path.

## G11 worker protocol

Workers claim bounded batches inside a short transaction using
SELECT ... FOR UPDATE SKIP LOCKED, then persist a unique lease token, owner,
and expiry before committing. The external G11 append happens outside that
transaction. A worker may acknowledge only while it owns the current
unexpired lease and only when event ID and payload digest match the durable
G11 acknowledgment.

A crash after claim is recovered when the lease expires. A crash after G11
acceptance but before local acknowledgment causes at-least-once redelivery;
G11 MUST deduplicate on stable event ID and reject a changed payload digest.
Retries use bounded exponential backoff with jitter and a maximum attempt
policy; exhaustion remains visible and must not silently discard the event.
Database time, not worker wall clocks, determines lease expiry and retry
eligibility.

## Checkpoint anchoring

G11 checkpoint envelopes are signed by a key held outside the database.
The database stores the signed envelope and publication receipt, not signing
secrets. Publication is idempotent by stream and sequence. Independent
verification checks the signature against an independently distributed trust
root, checkpoint digest, sequence continuity, and previous-digest linkage.
A database row alone is not proof of external publication.

## Production ingress boundary

The service boundary must derive the principal from G01 verification and
resolve tenant membership and organization authority from G02. It must not
accept caller-supplied principal, tenant, reviewer, or authorization booleans
as authority. G09 policy is re-evaluated immediately before each external
effect, against current revocation and authority state. Failures are deny /
defer, never allow.

## Operational constraints

- Separate migration and runtime database roles; runtime role is least privilege.
- TLS with certificate verification is required for remote PostgreSQL.
- No credentials, private keys, or live personal content belong in repository fixtures.
- SQLite tests remain useful but cannot substitute for PostgreSQL concurrency,
  restart, transaction rollback, or multi-process tests.
- This ADR does not authorize merge, deployment, production activation, or
  independent security assurance.
