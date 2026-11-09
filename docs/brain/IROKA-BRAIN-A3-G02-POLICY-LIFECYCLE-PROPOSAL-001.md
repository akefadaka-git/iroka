# IROKA G02 Signed Policy Lifecycle — A3 Design Proposal 001

**Status:** OWNER-APPROVED — A3 IMPLEMENTATION AUTHORIZED  
**Version:** 0.1.0  
**Date:** 2026-11-09  
**Scope:** B02 policy authority; no runtime implementation or activation is authorized by this document alone.

## 1. Purpose and current gap

The current Kernel `Policy` is an in-memory evaluation input. The G02 contract establishes direct Owner authority and cryptographically signed, short-lived, replay-protected approvals, but does not yet define signed policy publication, durable activation, policy rollback protection, or policy revocation.

The Brain A2 contract assigns policy ownership to G02 and prohibits a Brain-owned policy engine or trust root. This proposal keeps policy authority in the Kernel and reuses the existing explicitly provisioned G02 Owner-key authority.

## 2. Proposed trust model

1. Only a currently trusted G02 Owner key may sign a policy snapshot.
2. A policy snapshot is a complete immutable replacement, not a patch or merge.
3. No principal, tenant, model, plugin, workflow or application may create or activate policy.
4. The signed payload binds the Owner subject, key ID, policy epoch, policy version, complete policy body, issuance time and expiry.
5. Policy activation does not authorize execution. G09 remains the only protected-effect authority.
6. Policy verification, persistence and selection belong to G02/Kernel. Brain receives only an opaque verified policy context.

## 3. Proposed signed payload

The proposed envelope contains:
- `schema_id = iroka.g02.policy-snapshot`;
- `contract_version = 1.0`;
- `owner_subject` and `key_id`;
- strictly increasing unsigned `policy_epoch`;
- non-empty immutable `policy_version`;
- complete sorted capability allowlist;
- complete sorted approval-required capability list, which must be a subset of the allowlist;
- maximum risk level;
- explicit emergency-stop state;
- `issued_at` and finite `expires_at`.

Reject unknown fields, duplicate capabilities, empty/oversized identifiers, invalid risk values, expiry at or before verification time, future issuance beyond the approved clock-skew allowance, expired/revoked Owner keys and malformed signatures.

## 4. Canonical encoding — Owner decision required

**Proposal:** JSON Canonicalization Scheme (RFC 8785 / JCS), using the already-present `serde_jcs` dependency. The detached Ed25519 signature covers the canonical UTF-8 bytes of the complete payload. The stored digest is SHA-256 over those exact bytes.

This differs from the current Owner approval payload's deterministic Rust-struct JSON serialization. Policy signatures must use a separately named domain separator and canonical format; never reinterpret old approval signatures as policy signatures.

**Owner must approve or replace this canonicalization choice before implementation.**

## 5. Version and activation semantics

- Epoch starts at 1 and must strictly increase.
- Lower epochs are rejected as rollback.
- Same epoch plus identical digest is an idempotent retry; same epoch with a different digest is a conflict.
- Each activation stores immutable signed payload, signature, digest, signer key ID, Owner subject, activation timestamp and previous epoch reference.
- Active policy must be re-verified on process start and before selection; missing, expired, revoked, malformed or unverifiable active policy means no policy context and fail-closed authorization.
- Expired active policy does not silently fall back to an older snapshot.
- Policy revocation requires an explicit Owner-signed G02 command and cannot be initiated by G03.

## 6. G11 audit ordering

G11 audit is a separate authority and must not be duplicated inside Brain or G02. The existing G02 security store and G11 audit sink use separate SQLite connections, so claiming a cross-store atomic transaction would be false.

**Proposed safe activation protocol:**
1. Verify signature, Owner key status, payload schema, time bounds and epoch without changing active policy.
2. Persist a pending immutable activation record and deterministic G11 event ID.
3. Append the G11 policy-activation event. G11 failure leaves policy pending and unavailable.
4. Only after G11 confirms the event, atomically mark the pending epoch active in the G02 policy store.
5. On recovery, retry the same event ID and complete activation idempotently; never activate an unaudited pending epoch.
6. Audit event binds digest, epoch, policy version, Owner subject/key ID and prior active epoch. It excludes secrets.

This is an ordered fail-closed protocol, not a distributed atomic transaction. Multi-node deployment still requires a shared transactional persistence adapter and tested recovery semantics.

## 7. API boundary proposal

- `SignedPolicySnapshot`: untrusted signed envelope.
- `OwnerApprovalVerifier::verify_policy_snapshot`: validates signature and Owner-key state; does not itself activate.
- `PolicyActivationCoordinator`: persists pending state, obtains G11 receipt, then activates.
- `VerifiedPolicyContext`: opaque, immutable, versioned result returned only after successful activation and current validity checks.
- `load_active_policy_context(now)`: re-verifies persisted signature and expiry; never trusts a caller-supplied policy object or version string.

No public API may accept a bare `Policy` as proof that it is the active G02 policy in a production Brain composition root.

## 8. Required security tests

- Valid signature, tampered payload, unknown/expired/revoked Owner key.
- Wrong Owner subject/key binding and wrong schema/contract version.
- Duplicate/unsorted capabilities, approval capability outside allowlist, malformed policy body.
- Lower epoch rollback; same-epoch identical retry; same-epoch digest conflict.
- Expired, future-issued and revoked active policy.
- Crash between pending write, G11 append and activation; idempotent recovery.
- G11 unavailable or duplicate event ID: no active policy until verified audit completion.
- Concurrent activation attempts: exactly one monotonic epoch wins.
- Cross-tenant policy selector spoofing; no caller-selected policy version.
- Emergency-stop activation and clearing require valid Owner signatures and auditable transitions.
- G03 cannot alter policy, self-approve, execute G09 effects or claim G11 assurance.

## 9. Operational constraints

- No real Owner key, secret, trust root or production data in repository or test fixtures.
- Synthetic signing keys only in tests.
- Production activation remains blocked until the Owner key ceremony, protected key provisioning, multi-node persistence, G11 ordering/recovery and independent A4 review are complete.
- SQLite remains a development/single-node adapter; it is not represented as multi-node production authority.

## 10. Owner decision — APPROVED 2026-11-09

The Owner explicitly approved the complete proposal as written:

1. **JCS / RFC 8785 canonical JSON:** APPROVED. Signatures use the distinct `IROKA:G02:POLICY-SNAPSHOT:V1\0` domain separator.
2. **Activation protocol:** APPROVED. Pending persistence → G11 append-only audit confirmation → active policy. Audit failure leaves the new snapshot pending and unavailable; identical event retries are idempotent.
3. **Emergency stop:** APPROVED inside the immutable signed policy snapshot. Both activation and clearing require a valid Owner signature, a strictly higher epoch, and G11 audit confirmation.
4. **Policy revocation:** APPROVED as an explicit Owner-signed G02 command; G11 confirmation precedes disabling the active policy. Pending revocation makes the active policy unavailable.

Implementation is authorized on isolated A3 branches. This approval does not authorize merge, deployment, production key provisioning, production policy activation or release. B02 remains PARTIAL until implementation, exact-HEAD verification, integration and A4 gates are complete.
