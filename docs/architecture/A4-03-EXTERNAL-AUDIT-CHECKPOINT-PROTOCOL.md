# A4-03 — External Audit Checkpoint and Independent Witness
## A1 assessment and A2 protocol proposal

**Status:** A1 assessment complete; A2 proposal prepared for Owner freeze. No implementation, production key provisioning, witness registration, remote publication, or deployment is claimed.

**Parent baseline:** `813b24cbf81f049f2675fbb5492bdc9f262a9d87`  
**Workstream branch:** `feat/a4-03-external-audit-checkpoint`  
**Existing PR:** #13 remains the separate A3/A4 implementation PR; this workstream is deliberately isolated.

## 1. Verified starting point

The existing `SqliteAuditSink` in `crates/iroka-kernel/src/audit_store.rs`:
- stores ordered events with a domain-separated SHA-256 hash chain;
- exposes `head() -> (sequence, hash)` and `verify_integrity()`;
- uses SQLite transactions, WAL and FULL synchronous mode;
- rejects ordinary row updates/deletes through triggers;
- detects modified/deleted rows when the remaining local chain is verified.

It does not retain a stable externally verifiable log identity, create a signed checkpoint envelope, publish to an independent trust domain, verify a witness receipt, or compare the local head against an independently retained checkpoint. A privileged actor able to replace or truncate the local database can therefore rebuild a self-consistent local chain.

## 2. Proposed provider-neutral protocol

The implementation should define stable, versioned contracts and adapters without selecting a cloud vendor, hosted notary, HSM, KMS, or production key custody model.

### 2.1 Signed checkpoint envelope

A checkpoint envelope should bind at minimum:
- protocol/schema identifier and version;
- stable audit-stream identifier (not inferred from a file path);
- monotonically increasing checkpoint sequence;
- audit event sequence and 32-byte event-chain head hash;
- digest of the immediately preceding accepted checkpoint (genesis uses an explicit null/zero predecessor);
- checkpoint signer key identifier;
- issuance time and algorithm identifiers.

The envelope is serialized using the repository's existing RFC 8785/JCS profile and signed with Ed25519. The signed bytes must be domain-separated from other IROKA signatures. The verifier rejects unknown versions/algorithms, malformed hashes, missing identity fields, invalid signatures, and non-monotonic checkpoint history.

### 2.2 Independent witness receipt

A witness is a separate trust domain from the audit database and checkpoint signer. It accepts a signed envelope only after validating its signature and stream identity, then durably records the envelope digest and monotonic checkpoint position. It returns a witness-signed receipt binding:
- witness identity and key identifier;
- audit-stream identifier;
- checkpoint sequence and envelope digest;
- the witness's accepted predecessor/position;
- receipt time and protocol version.

The witness must reject duplicate conflicting positions, replayed/stale checkpoints, sequence gaps where policy requires contiguous checkpoints, and a predecessor mismatch. A successful HTTP response alone is not a receipt; the caller must verify the witness signature and exact envelope digest.

### 2.3 Adapter boundaries

Use explicit traits/interfaces for:
- checkpoint signing (production implementation supplied later by a governed signer adapter);
- witness publication and retrieval (transport/storage implementation supplied later);
- witness receipt verification;
- local-vs-external checkpoint reconciliation.

The core must not contain production private keys, embedded credentials, a hard-coded provider, or a silent local-file fallback presented as independent retention. Test adapters may use deterministic test-only keys and in-memory storage, clearly excluded from production builds/configuration.

### 2.4 Verification and recovery

A verifier must:
1. verify the local event chain;
2. fetch the latest independently retained witness checkpoint(s);
3. verify checkpoint signer and witness signatures against explicitly supplied trust roots;
4. verify stream identity, envelope digest, predecessor linkage and monotonic sequence;
5. compare the local chain head with the anchored event sequence/hash.

If the local chain is behind an accepted checkpoint, it must report truncation/rollback and fail closed for integrity-sensitive operations. If local state is ahead of the witness, it must report an unanchored tail, not silently treat it as externally protected. Network, timeout, invalid-signature, stale-receipt and witness-unavailable conditions must remain distinguishable and fail closed where policy requires an anchored audit record.

## 3. Proposed implementation slices

- **A3.1 Contracts:** versioned envelope, witness receipt, canonicalization, domain-separated signing/verification.
- **A3.2 Witness protocol:** provider-neutral publisher/retriever traits and strict receipt validation.
- **A3.3 Reconciliation:** compare local audit head to externally witnessed history; detect truncation, rollback, fork, stale witness and unanchored tail.
- **A3.4 Test adapters:** deterministic test-only signer and independent in-memory witness; no production secrets.
- **A3.5 Adversarial tests:** signature tampering, envelope mutation, replay, duplicate/conflicting sequence, predecessor mismatch, fork, stream substitution, truncation, stale witness, witness outage, partial publication and recovery/retry.
- **A3.6 Documentation and exact-head CI:** threat model, protocol vectors, operational boundary, full Rust gates and exact SHA evidence.

## 4. Owner decisions required before A3

These decisions are intentionally not guessed:

1. **Witness independence model:** one independently administered witness, or a configurable quorum of multiple witnesses? The protocol can represent multiple receipts, but a production quorum threshold must be explicit.
2. **Signer custody boundary:** an Owner-controlled external signing service/HSM/KMS, or a separately administered organizational signer? No production private key is created in this workstream.
3. **Retention authority:** Owner-controlled immutable object retention, independent notary service, or another independently administered durable store? No vendor is selected.
4. **Checkpoint policy:** time/event-count cadence, maximum unanchored tail, and behavior during witness outage. Safe implementation defaults should fail closed for operations requiring a fresh anchor, but the service-level availability policy needs Owner approval.
5. **Production activation:** separate approval for production trust-root registration, witness onboarding, key ceremony, retention configuration, restore drill and runtime activation.

## 5. Security invariants

- The local audit database is never treated as its own external witness.
- Checkpoint signer and witness identities/keys are distinct trust roles.
- Every signature is over a versioned, canonical, domain-separated representation.
- Witness acceptance is durable and monotonic; accepted history is append-only.
- A receipt is bound to the exact envelope digest, stream and sequence.
- A missing witness response never becomes a successful checkpoint.
- No production secret, provider credential, or production trust root is stored in source or CI.
- No change to A4-05 production custody, Genesis activation, runtime promotion, merge or deployment is implied.

## 6. Exit criteria for A4-03

A4-03 can be marked implementation-verified only after:
- the signed envelope and receipt contracts are implemented;
- an independent witness adapter contract and test witness exercise durable monotonic acceptance semantics;
- a verifier detects local truncation/rewrite against a previously witnessed checkpoint;
- adversarial, concurrency, retry and recovery tests pass;
- the full Rust verification workflow passes on the exact final HEAD;
- production limitations and the unprovisioned operational boundary are explicitly recorded.

A test-only in-memory witness proves protocol behavior, not real-world independence, immutable retention, key custody, or production availability. Those remain separately gated deployment evidence.

## 7. Current disposition

**A1:** VERIFIED — current adapter and threat boundary inspected at the exact parent baseline.  
**A2:** PROPOSED — protocol contract above awaits Owner freeze of the five decision areas.  
**A3:** NOT STARTED — no production or test implementation has been added yet.  
**A4 verification:** NOT RUN for this workstream.  
**A5 deployment:** NOT AUTHORIZED / NOT RUN.

No external service was selected or contacted. No production keys were generated. No payment, top-up, deposit, merge, or deployment was performed.
