# G11 — Durable Audit and Integrity Contract

## Scope

G11 provides a durable append-only audit sink for authorization and governance decisions. It is distinct from G01 trust-bundle history, credential/key revocations, G02 approval receipts and security-command records. Those registries remain authoritative for their own state transitions; G11 is the cross-cutting decision/event record.

## Event contract

Every event binds a unique event ID, correlation ID, subject, capability, resource, policy version, decision code and occurrence timestamp. The current kernel event type is intentionally narrow; later domain event types must extend the schema through a versioned contract rather than overloading these fields.

The sink rejects blank or oversized fields, timestamps outside SQLite's signed integer range and duplicate event IDs. Append uses one SQLite IMMEDIATE transaction with FULL synchronous durability. The existing authorization pipeline converts audit failure to ESCALATE, preventing a positive decision from proceeding when audit append fails.

## Integrity model

Each row stores the previous row hash and a SHA-256 digest over a domain separator, previous hash and length-prefixed canonical event fields. Sequence order is part of the chain. The adapter verifies the complete chain on open; operators can explicitly call `verify_integrity` and retrieve `head` for checkpointing. SQLite triggers reject ordinary UPDATE and DELETE statements.

This is tamper-evident, not tamper-proof. An administrator able to replace the database and recompute every hash can forge an unanchored chain. Production operation MUST periodically sign and export the sequence/head-hash checkpoint to an independently administered immutable store or Owner-controlled signing service. Checkpoint verification, retention/restore drills, alerting and independent access controls are deployment gates, not capabilities silently assumed by this adapter.

## Adapter boundary

`SqliteAuditSink` is a single-node reference adapter. It creates Unix database files with mode 0600 and rejects symlinks or group/world-readable existing files. Non-Unix deployments must apply equivalent ACLs and encrypted storage. Multi-node operation requires a shared transactional adapter with globally unique event IDs, serializable chain-head updates, durable commits and fail-closed behavior; do not share or load-balance independent SQLite copies.

The adapter stores no credentials or private keys. Audit access, export, backup, retention, external checkpoint signing and alerting require separate operational controls. The current schema does not claim to capture every application event or protected side effect; G09 must separately record execution grants and execution outcomes.

## Verification contract

Tests cover append ordering, duplicate-ID rejection, integrity verification, row modification detection and deletion detection. Production readiness additionally requires externally anchored checkpoints, restore/recovery testing, a selected multi-node backend where applicable, and G11 integration at every required decision/side-effect boundary.
