# IROKA G11 External Audit Checkpoint Implementation and Operations v1.0.0

**Status:** A3.10.3 software implementation scope  
**Production witness status:** NOT PROVISIONED / LIVE VERIFICATION NOT RUN  
**Deployment:** Not authorized

## 1. Security objective

A local SQLite hash chain detects edits to rows while its original history remains available. It cannot independently prove that an attacker with database-file control has not replaced or truncated the entire database. IROKA therefore needs signed checkpoints of the verified local audit head and independently operated witnesses that durably accept monotonic checkpoint history.

This implementation separates:
- Local audit-chain integrity.
- Checkpoint signer identity and signature.
- Witness identity and signed receipt.
- Quorum policy.
- External operator durability and retention.
- Local/external reconciliation.

A successful local hash calculation is not an external anchor. A valid signature proves the signing key signed the canonical payload; it does not prove the payload's substantive truth or the witness operator's organizational independence.

## 2. Protocol contracts

The kernel implements versioned `SignedCheckpoint` and `WitnessReceipt` envelopes in `external_checkpoint.rs`.

Checkpoint payload binds:
- Protocol/version and Ed25519 algorithm.
- Stable audit stream ID.
- Monotonic checkpoint sequence.
- Local audit event sequence and SHA-256 event-head digest.
- Previous checkpoint digest.
- Checkpoint signer key ID and issued-at time.

Witness receipt binds:
- Witness identity and key ID.
- Stream and checkpoint sequence.
- Digest of the exact signed checkpoint envelope.
- Previous checkpoint digest.
- Witness acceptance time and algorithm.

All payloads reject unknown fields, use RFC 8785/JCS canonical JSON and distinct NUL-terminated signature domains. The checkpoint signer and witness signer are separate injected trust boundaries; no production private key is stored in the kernel.

## 3. Safe local-head binding

Checkpoint creation uses `SqliteAuditSink::verified_head()`, which verifies the entire event chain and reads the terminal sequence/digest inside one SQLite read transaction. This prevents a check-then-read race between separate integrity and head calls.

`create_audit_checkpoint` refuses an empty or corrupted audit chain. `verify_and_reconcile_head`:
1. Verifies the checkpoint signature against Owner-governed checkpoint signer roots.
2. Verifies each witness receipt against the exact checkpoint and witness trust roots.
3. Requires a configurable quorum of distinct witness identities and distinct witness key IDs.
4. Verifies the local audit chain and terminal head in one consistent snapshot.
5. Distinguishes exact match, local-ahead unanchored tail, local-behind-anchor rollback, and same-sequence fork.

The low-level comparison helper is private; callers use the verification-and-reconciliation entry point. A `VerifiedCheckpointEvidence` value can only be created after checkpoint signature and witness-quorum verification. The local sink persists that evidence in a separate append-only SQLite table, verifies the referenced local audit prefix in the same immediate transaction, and permits only exact idempotent re-persistence. Recovery reads return canonical bytes that must be parsed and signature/quorum-verified again before use.

## 4. Witness monotonicity and quorum

A conforming witness service must durably enforce per-stream:
- Genesis checkpoint sequence and predecessor rules.
- Exactly-next checkpoint sequence with overflow rejection.
- Strictly increasing event sequence.
- Exact previous-checkpoint digest linkage.
- Idempotent retry for the exact same signed envelope/digest.
- Rejection of conflicting replay, sequence gaps, sequence regression and predecessor mismatch.
- Durable commit of checkpoint and signed receipt before success.
- Append-only history and independent backup/retention.

The kernel's deterministic test witness exercises sequence, event-sequence, predecessor, replay, digest and quorum rules. It is a test fixture, not a production service.

The HTTPS/mTLS client adapter:
- Requires HTTPS and TLS 1.2 or newer.
- Authenticates the witness server against a configured CA bundle.
- Uses a dedicated mTLS client certificate and private key.
- Rejects POSIX private-key paths that are symlinks or have group/other permissions.
- Disables ambient curl configuration and proxy inheritance; invokes curl without a shell.
- Bounds connect/total time and response size.
- Verifies checkpoint signatures before publishing and receipt signatures/identity before counting success.
- Uses the checkpoint digest as an idempotency key.
- Requires valid receipts from distinct identities and distinct keys for quorum.

The client adapter does not prove that two URLs are independent. Organizational independence requires separate controlling operators, accounts, infrastructure, credentials, backups and retention controls.

## 5. HTTP witness contract

The API contract for independent operators is defined in `docs/security/IROKA-G11-HTTPS-WITNESS-API-CONTRACT-v1.0.0.md`. Required server behavior:
- `POST /v1/checkpoints`: validate signer trust, envelope, stream, sequence and predecessor; durably commit checkpoint and receipt before returning success; return the original receipt for an exact idempotent retry; reject conflicting content.
- `GET /v1/streams/{stream-id}/latest`: return both the latest signed checkpoint and its witness receipt, or both null; never return a partial pair.
- Return errors for malformed envelopes, authentication failures, replay/conflict, gaps and unavailable storage. A successful response must never represent volatile/in-memory-only acceptance.

The repository contains the client contract and test fixtures, not an independently administered production witness server or its durable backend.

## 6. Failure and recovery semantics

- Invalid checkpoint signature, unknown signer, invalid witness signature, identity mismatch, duplicate witness, insufficient quorum, fork, local rollback or local audit corruption must fail closed.
- A witness outage is tolerated only if the configured verified quorum is still met.
- A local tail beyond the latest external checkpoint is explicitly `LocalAheadUnanchored`; it is not silently represented as anchored.
- A local head behind the external anchor is `LocalBehindAnchor` and requires incident response and restore/reconciliation.
- A same-sequence digest mismatch is `ForkDetected`.
- Never overwrite an external checkpoint or truncate local history to make the two sides match.
- Restore must compare local verified head with independently retrieved signed checkpoint/receipt evidence before protected operations resume.

## 7. Required live operational gates

Before production activation:
1. Owner selects at least two separately administered witness operators and approves evidence of their independence.
2. Each operator supplies a production endpoint, mTLS client enrollment process, witness public-key fingerprint, durable-commit contract and retention/restore evidence through a secure channel.
3. Owner approves checkpoint signer trust roots, witness key enrollment and quorum threshold.
4. Provision mTLS client credentials and signer keys outside Git; verify private-key permissions and rotation/revocation.
5. Run live publish/readback, idempotent retry, replay/conflict, sequence gap/regression, outage/quorum, restore and key-rotation tests against the real services.
6. Independently verify exported checkpoint and receipt evidence from a separate environment.
7. Conduct an external restore drill and record the results.

No endpoint URLs, private keys, mTLS credentials or production witness keys are present in this branch. No live service was contacted or provisioned. No provider was selected.

## 8. Evidence required for closure

- Exact source SHAs and blob SHAs for audit snapshot, checkpoint protocol and HTTPS adapter.
- Passing exact-source Rust format, compile, production-feature, unit/contract and Clippy CI.
- Tests for tampering, invalid signatures, wrong identity, duplicate key/identity, insufficient quorum, replay, gap, regression, predecessor mismatch, corrupted local chain, fork, rollback, local unanchored tail and audit storage failure.
- Live evidence from independently operated witness services, including durable readback and restore.
- Independent security review of signer custody, witness protocol, HTTPS adapter and operational independence.
- No unresolved critical/high findings.

Software CI alone does not close the operational witness or independent-review gates.


## 9. Durable SQLite witness reference backend (A3.10 implementation)

The kernel now includes `SqliteCheckpointWitness` in `crates/iroka-kernel/src/sqlite_checkpoint_witness.rs`. It is a durable reference backend for an operator's witness service, implementing the existing `CheckpointWitness` contract.

The backend:
- Uses a dedicated SQLite database, WAL journaling, `synchronous=FULL`, foreign-key enforcement, a bounded busy timeout and an immediate write transaction for acceptance.
- Verifies checkpoint signatures against the configured checkpoint-signer trust set before accepting a checkpoint.
- Enforces per-stream genesis, exactly-next checkpoint sequence, strictly increasing event sequence, exact predecessor digest and exact-envelope idempotent retry.
- Persists the signed checkpoint envelope and signed witness receipt in the same transaction before returning success.
- Returns the original persisted receipt for an exact retry; conflicting same-sequence content, gaps, regressions and predecessor mismatches fail closed.
- Adds SQLite triggers rejecting UPDATE and DELETE against the witness history table.
- Supports process restart and readback of the latest checkpoint/receipt pair.

The adapter deliberately does not claim to be a network-facing HTTPS/mTLS service. An operator must expose it only behind a separately reviewed authenticated service boundary, protect the database and signing key, and operate independent backups. Separate operator control, infrastructure, credentials and retention remain necessary; two local database instances do not prove organizational independence.

The backend's automated persistence/restart tests are part of the Rust kernel suite. They are synthetic tests, not live external operator evidence.

## 10. Updated closure boundary

**Software:** Durable witness acceptance backend, signed receipt creation, persistent readback, append-only enforcement and restart tests are implemented. Exact-head CI for this addition is required before marking the source implementation verified.

**Operational:** NOT CLOSED. No independently administered operator endpoints, mTLS enrollment, production keys, retention evidence, external backup/restore or cross-operator independence evidence are claimed.

**A3.10.3 closure rule:** The software portion may be marked VERIFIED after exact-head tests pass. The operational workstream remains PARTIAL until the live operator and Owner/custodian ceremony evidence in Sections 7–8 is attached and independently checked.
