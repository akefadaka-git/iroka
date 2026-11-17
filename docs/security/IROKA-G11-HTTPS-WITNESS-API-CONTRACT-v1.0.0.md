# IROKA G11 HTTPS Witness API Contract v1.0.0

**Status:** Normative external operator interface for A3.10 SEC-05  
**Implementation:** Rust client adapter in `crates/iroka-kernel/src/external_checkpoint_https.rs`  
**Production status:** No live witness service, endpoint, mTLS credential or operator is provisioned by this document.

## 1. Trust boundary

Each `HttpsCheckpointWitness` instance represents one independently administered witness operator. The client is configured with:
- HTTPS endpoint.
- Stable witness identity and key ID.
- Dedicated mTLS client certificate and private key.
- CA bundle used to authenticate the server.
- Owner-governed checkpoint signer trust roots.
- Expected Ed25519 public key for this witness.

A witness receipt counts only if it is signed by the configured witness key and bound to the exact signed checkpoint. Two URLs do not establish independence. Independent operation requires different controlling operators, accounts, infrastructure, signing keys, backup administration and retention controls.

## 2. Wire encoding

All requests and responses are UTF-8 JSON. The Rust protocol structs use strict unknown-field rejection. Ed25519 signatures are represented by JSON arrays of unsigned byte values (64 values for a valid Ed25519 signature); public keys are arrays of 32 unsigned byte values. The server must reject out-of-range, wrong-length or malformed values.

The signed bytes are RFC 8785/JCS canonical JSON preceded by the protocol-specific NUL-terminated domain:
- Checkpoint: `IROKA:G11:EXTERNAL-CHECKPOINT:V1\0`
- Witness receipt: `IROKA:G11:WITNESS-RECEIPT:V1\0`

The idempotency key is the lowercase hexadecimal SHA-256 digest of the canonical serialized `SignedCheckpoint` envelope, matching `SignedCheckpoint::digest()`.

## 3. Publish checkpoint

**Request**

`POST {base}/v1/checkpoints`

Headers:
- `Accept: application/json`
- `Content-Type: application/json`
- `Idempotency-Key: {checkpoint-envelope-sha256}`
- Mutual TLS client authentication.

Body: one `SignedCheckpoint` envelope with:
- protocol `iroka.g11.audit-checkpoint`
- version `1`
- stable `stream_id`
- positive `checkpoint_sequence`
- positive `event_sequence`
- 64-character lowercase/uppercase hexadecimal event-head SHA-256
- optional 64-character previous-checkpoint SHA-256
- signer key ID
- positive issued-at timestamp
- algorithm `Ed25519`
- 64-byte signature.

**Success**

Return HTTP 200 for exact idempotent retry or HTTP 201 for first durable acceptance. Body: one `WitnessReceipt` signed by this witness, binding witness ID/key ID, stream ID, checkpoint sequence, exact checkpoint digest, predecessor digest, positive acceptance time and Ed25519 algorithm.

The server must:
1. Authenticate the mTLS client and authorize it to publish for the requested stream.
2. Verify the checkpoint signature against the server's enrolled checkpoint-signer roots.
3. Validate protocol, field constraints, stream policy, checkpoint sequence, event sequence and predecessor digest.
4. In one durable transaction, enforce strictly increasing checkpoint sequence and event sequence per stream, exact predecessor continuity, and unique checkpoint identity.
5. If the same idempotency key and exact signed envelope were already committed, return the original receipt unchanged.
6. Reject a reused sequence/idempotency key with different content.
7. Persist the checkpoint and signed receipt before acknowledging success.
8. Retain append-only history and independently administered backups; a volatile in-memory receipt is never success.

## 4. Read latest checkpoint

**Request**

`GET {base}/v1/streams/{percent-encoded-stream-id}/latest`

The stream ID path segment must be percent-encoded as UTF-8 bytes. The server must not interpret encoded slashes or traversal sequences as path structure.

**Success**

HTTP 200 with both fields null if no checkpoint exists:

```json
{
  "checkpoint": null,
  "receipt": null
}
```

Otherwise both fields contain the latest `SignedCheckpoint` and its corresponding `WitnessReceipt`. A partial pair is invalid. The client verifies the checkpoint signature, receipt signature, witness identity and requested stream ID before returning data.

## 5. Error contract

- 400 — malformed/unsupported protocol or field.
- 401 — missing or invalid mTLS identity.
- 403 — authenticated client is not authorized for the stream.
- 409 — replay, conflicting content, sequence gap/regression, or predecessor mismatch.
- 413 — request body too large.
- 429 — rate limit; no acceptance implied.
- 5xx — unavailable; no acceptance implied unless the client can retrieve and verify the exact idempotent receipt.
- Any ambiguous network outcome is resolved by retrying the exact envelope with the same idempotency key, then reading latest and verifying the receipt. Never issue a new checkpoint sequence solely because a response was lost.

The server must not return 2xx before durable commit. Error responses must not disclose private key material, authentication secrets or internal storage paths.

## 6. Client requirements

The IROKA adapter:
- Requires HTTPS and TLS 1.2 or newer.
- Authenticates the witness server with the configured CA bundle.
- Uses a dedicated mTLS client identity.
- On POSIX, rejects client private-key paths that are symlinks or grant group/other permissions.
- On non-POSIX systems, currently fails closed pending platform-specific ACL verification.
- Disables ambient curl configuration and proxy inheritance.
- Invokes curl without a shell.
- Bounds connect/total request time and response size.
- Verifies checkpoint signatures before publication.
- Verifies each returned receipt before counting it toward quorum.
- Ignores invalid/unavailable witness responses but requires the configured number of distinct valid witness identities and distinct witness keys.
- Uses the checkpoint envelope digest as the idempotency key.

The adapter does not create or store production signer keys. Its private-key paths and trust roots must be provisioned through the Owner-governed ceremony, outside source control.

## 7. Quorum policy

`publish_witness_quorum` receives:
1. Signed checkpoint.
2. Configured witness adapters.
3. Trusted checkpoint signer roots.
4. Trusted witness public keys.
5. Required quorum count.

It verifies the checkpoint signer before contacting witnesses, verifies receipts against both trust sets, rejects duplicate witness identities or duplicate witness key IDs, and succeeds only if the threshold is met. The helper does not select a production threshold or prove operator independence.

The minimum production design should use at least two separately administered operators. Owner must approve the actual operator identities, trust fingerprints and quorum threshold.

## 8. Mandatory operator tests

Before production enrollment, each operator must demonstrate:
- First publish and durable readback.
- Exact idempotent retry returns the original receipt.
- Same sequence with different digest is rejected.
- Sequence gap and event-sequence regression are rejected.
- Wrong predecessor is rejected.
- Restart and backup restore preserve latest checkpoint and receipt.
- Corruption, disk-full and transaction-commit failure do not return success.
- Revoked/rotated witness key is rejected.
- mTLS client revocation and endpoint certificate rotation work.
- Retention and deletion controls are independently reviewed.

## 9. Current implementation boundary

The repository contains the client adapter, canonical checkpoint/receipt types, deterministic in-memory test witness, quorum verification, and local audit-chain reconciliation. It does not contain a live independent operator service or prove the durability/retention of an external endpoint.

No endpoint, production mTLS certificate/private key, checkpoint signing key, witness key or provider has been selected or provisioned. Live publish/readback, restore, failover and independent operator verification remain required before production activation and before SEC-05 can be claimed operationally complete.
