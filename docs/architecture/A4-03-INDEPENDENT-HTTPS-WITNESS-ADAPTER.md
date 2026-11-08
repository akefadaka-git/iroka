# A4-03 — Independent HTTPS Witness Adapter Contract

## Purpose and trust boundary

`HttpsCheckpointWitness` is the production client adapter for one independently administered witness service. Each instance is bound to one operator identity, one endpoint, one mTLS client identity, one expected Ed25519 witness key and the Owner-governed checkpoint signer trust roots. Multiple instances can be passed to `publish_witness_quorum`; receipts count only when their signatures validate and their witness identities are distinct.

The adapter is provider-neutral. It does not claim that two URLs, accounts or virtual machines are independent. Independence requires different controlling operators and separately administered credentials, infrastructure, backups and retention controls. The IROKA client cannot cryptographically prove an operator's organizational independence.

## Client requirements

- HTTPS only; TLS 1.2 or newer; certificate validation against an explicitly configured CA bundle.
- Mutual TLS using a dedicated client certificate and private key. Key files must be provisioned outside the repository, readable only by the IROKA service identity, rotated and revocable by the relevant authority.
- Curl is an operating-system runtime dependency. No shell is invoked; arguments are passed directly to the process. Response size, connect time and total request time are bounded.
- Checkpoint signatures are validated before publication. Witness receipt signatures and configured witness identity/key IDs are validated before returning success.
- No automatic retry is performed. The checkpoint digest is sent as an idempotency key so an operator can safely implement exact-request retry semantics without accepting conflicting sequence content.

## HTTP API v1

All bodies are UTF-8 JSON using the existing versioned IROKA checkpoint/receipt structures. Unknown fields are rejected by the Rust deserializers.

### Publish

`POST {base}/v1/checkpoints`

Headers:
- `Content-Type: application/json`
- `Accept: application/json`
- `Idempotency-Key: <lowercase SHA-256 digest of canonical signed checkpoint envelope>`
- mTLS client authentication

Body: one `SignedCheckpoint`.

Success: HTTP 200 or 201, body is one `WitnessReceipt` signed by this witness.

Required server behavior:
1. Verify the checkpoint signature against the server's enrolled checkpoint-signer trust roots.
2. Verify protocol/version, stream, sequence, predecessor and digest.
3. In one durable transaction, enforce strictly monotonic sequence per stream and exact predecessor continuity.
4. For an exact already-accepted envelope and idempotency key, return the original receipt (idempotent success).
5. Reject replay, conflicting content at an occupied sequence, sequence gaps and wrong predecessor; do not overwrite history.
6. Persist the checkpoint and signed receipt before acknowledging success. A receipt must never be issued for volatile/in-memory-only state.
7. Keep append-only history and independently administered backups/retention. A successful HTTP response alone does not prove immutable retention.

### Read latest

`GET {base}/v1/streams/{percent-encoded-stream-id}/latest`

Success: HTTP 200, body:
```json
{
  "checkpoint": null,
  "receipt": null
}
```
when no checkpoint exists, or both fields populated with the latest `SignedCheckpoint` and corresponding `WitnessReceipt`.

A partial pair is invalid. The client verifies checkpoint and receipt signatures and checks the requested stream ID before returning data.

### Error semantics

- 400: malformed or unsupported envelope.
- 401/403: mTLS identity or authorization failure.
- 409: replay, sequence conflict, gap or predecessor mismatch.
- 429/5xx: unavailable; caller must fail closed if the required quorum is not met.
- A witness must not return success before durable commit.

## Multi-witness quorum

`publish_witness_quorum(checkpoint, witnesses, trusted_witnesses, required)` attempts each configured adapter, gathers successful receipts, cryptographically verifies them, rejects duplicate witness identities, and returns success only when the threshold is met. A failed endpoint does not erase another endpoint's valid receipt, but insufficient quorum is a hard failure. The caller must persist returned receipts with the local checkpoint evidence.

Production threshold and trust-root enrollment remain Owner-governed; the helper does not pick a production quorum.

## Verification and limits

Automated checks cover endpoint policy (HTTPS-only, no embedded user credentials/query/fragment), safe stream path encoding, compilation, production feature compilation, test suite and Clippy. The deterministic test witness continues to cover protocol signatures, receipt binding, sequence/replay/gap/predecessor rules and quorum identity checks.

**Live independent-service verification is still outstanding** until at least two separately administered witness operators provide real endpoint URLs, mTLS client enrollment and public witness keys. Then run publish/readback, replay/conflict, outage/quorum, failover and restore tests against both services. The repository contains no endpoint URLs, client certificates, private keys or production trust roots. No provider is selected and no external service has been contacted or provisioned.

## Owner-governed production gates

1. Select two or more independent operators and approve their independence/retention evidence.
2. Exchange endpoint URLs, mTLS enrollment material and witness public-key fingerprints through a secure channel.
3. Approve checkpoint signer trust roots, witness key IDs and quorum threshold.
4. Provision secrets outside source control; verify file permissions, rotation and revocation.
5. Execute the live test matrix and independent restore drill.
6. Approve runtime activation separately. This adapter implementation does not authorize merge, deployment or production activation.
