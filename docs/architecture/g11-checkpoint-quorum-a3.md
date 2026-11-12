# G11 external checkpoint quorum — A3 implementation

## Frozen architecture preserved

This implementation follows IGACMS A4-03's frozen external checkpoint architecture. A checkpoint is not considered externally anchored by a single provider receipt.

The verifier requires all of the following:

- A valid Ed25519 signature from the pinned checkpoint signer over the existing G11 checkpoint payload.
- At least **two distinct witnesses out of exactly three configured witness identities**.
- Exactly **two distinct immutable-retention domains**, each returning a signed receipt in Compliance WORM mode.
- Distinct operator identities and distinct Ed25519 public keys across the signer, witness and retention roles.
- Both retention receipts bind the same checkpoint digest, segment-manifest digest and witness-receipt-set digest.
- Each retention deadline must extend at least `minimum_retention_secs` beyond verification time.

The trust-policy constructor rejects duplicate operator identities, key identifiers and public keys across roles. Production policy provisioning must additionally establish that operator IDs represent genuinely independent organizations and that key custody is separate. Distinct strings alone are not proof of operational independence.

## Signed evidence format

All receipt signing payloads use RFC 8785 JSON Canonicalization Scheme (JCS) and separate domain prefixes:

- `IROKA:G11:WITNESS-RECEIPT:V1\0`
- `IROKA:G11:RETENTION-RECEIPT:V1\0`
- `IROKA:G11:SEGMENT-MANIFEST:V1\0`
- `IROKA:G11:WITNESS-RECEIPT-SET:V1\0`

Witness receipts bind the checkpoint digest, segment-manifest digest, sequence, previous checkpoint digest, witness/operator/key identities and verification time. Retention receipts bind the same checkpoint and manifest, the canonical digest of the signed witness receipt set, the immutable object reference, retention mode and retention interval.

Offline verification uses only the checkpoint package, receipts and a separately pinned `CheckpointQuorumPolicy`. It does not trust provider HTTP responses or database state as cryptographic evidence. The verifier checks sequence continuity, stream identity, previous digest, signatures, unique identities, key-validity windows and retention deadlines.

## HTTPS provider protocol

The G05 provider adapters use native TLS with system certificate-chain and hostname validation. They:

- Accept HTTPS URLs only.
- Send bearer tokens only to the configured origin.
- Reject redirects; credentials and signed evidence are not forwarded to a second origin.
- Require HTTP/1.1 JSON responses with a bounded Content-Length.
- Reject chunked transfer encoding, duplicate response headers and oversized responses.
- Return provider receipts for separate offline signature/quorum verification.

Configured endpoint contract:

| Role | Request | Response |
|---|---|---|
| Witness | `POST` serialized `CheckpointPackage` | `WitnessReceipt` |
| Immutable retention | `POST` `{ package, witness_receipts }` | `RetentionReceipt` |

The endpoint path and bearer token are supplied at runtime. No provider URLs, tokens, operator keys or production secrets are embedded in source code.

## G02 authority outbox delivery

G02 signed-command processing commits immutable command evidence, authority projection changes and a G02 authority outbox event in one PostgreSQL transaction. The outbox worker uses database time, expiring leases and `FOR UPDATE SKIP LOCKED` to support multiple workers.

Delivery is **at least once**. A sink must deduplicate by immutable `event_id`; the worker records a SHA-256 acknowledgement digest only after the sink reports durable acceptance. Failed delivery schedules a retry and releases the lease. Payload fields are append-only; delivered rows cannot be mutated or deleted.

Migration `0004_g02_authority_outbox_delivery.sql` adds acknowledgement/retry state and the payload immutability trigger.

## Verification evidence

Exact-head CI for the implementation branch runs the Rust formatter, locked workspace compilation, production-feature safeguard, full workspace tests against ephemeral PostgreSQL 16 and Clippy with warnings denied. The tests cover signed receipt verification, 2-of-3 witness quorum, two retention domains, tampered receipts, cross-role key reuse, outbox claim/ack/retry and immutable payload enforcement.

## Explicit production gates

The code supplies protocol implementations and HTTPS clients; it does **not** claim that real independent operators have been engaged or that live external publication has occurred.

Still required before production:

1. Owner-approved provisioning of the checkpoint signer, three witness keys/operators and two retention keys/operators from the canonical G02 trust/revocation source.
2. Independent evidence that all five witness/retention operators and their key custody are administratively independent.
3. Two real immutable-retention services configured in Compliance WORM mode, with independently verified object-lock/retention settings.
4. Runtime secret provisioning, endpoint allowlists, TLS/egress policy and failure/restore runbooks.
5. Live publication and offline verification against actual provider receipts.
6. Independent third-party security review and production operational rehearsal.

No endpoint, secret, external retention account, production database or deployment has been configured by this change. No merge or deployment is authorized by this implementation record.
