# IROKA G09 Protected Effect Execution Contract v1.0.0

**Status:** A3.10.4 implementation contract  
**Scope:** Owner-authorized, operation-specific protected effects  
**Production activation:** Not authorized

## 1. Security invariant

A policy decision of `ALLOW` is not itself permission to execute a protected side effect. The G09 path requires a policy decision of `REQUIRE_APPROVAL`, a valid Owner-signed effect grant bound to the exact operation, atomic one-time nonce consumption, an identified executor, a signed executor result, a durable receipt, and audit events.

No protected effect may execute if identity, Genome baseline, policy, Owner grant, admission audit or nonce consumption cannot be verified.

## 2. Operation digest

`ProtectedEffectRequest::operation_digest` computes SHA-256 over RFC 8785/JCS canonical JSON with protocol `iroka.g09.protected-effect` version 1. The digest binds:
- Verified principal subject, issuer and credential ID.
- Executor subject.
- Capability and target resource.
- Effect type and risk class.
- Policy version.
- Verified Genome digest.
- Exact operation JSON object.

The operation payload is limited to 1 MiB and must be an object. The digest is not caller-supplied; the kernel recomputes it before grant verification. Any change to amount, destination, resource, executor, capability, risk, policy, Genome or operation data changes the digest.

## 3. Owner effect grant

The Owner signs `OwnerEffectGrantPayload` under the distinct domain `IROKA:G09:PROTECTED-EFFECT-GRANT:V1\0` using RFC 8785/JCS canonical JSON.

The grant binds:
- Unique nonce (also the single-use approval ID).
- Owner subject and Owner signing key ID.
- Request subject and executor subject.
- Capability, resource, effect type and risk class.
- Policy version and Genome digest.
- Exact operation digest.
- Issued-at and expiry timestamps.

The kernel requires a maximum 300-second grant lifetime, checks Owner key validity through the grant expiry, verifies signature and revocation, and then atomically consumes the nonce using the security store. The existing immediate SQLite transaction rechecks signer-key and approval revocation and prevents replay.

A nonce is never reusable, including after an audit or executor failure. A new operation requires a new Owner-signed grant.

## 4. Admission sequence

1. Validate the verified principal and epoch-zero approved Genome baseline.
2. Evaluate the policy with the emergency-stop state.
3. Require the decision to be exactly `REQUIRE_APPROVAL`; deny, escalate, or non-approval-gated allow cannot enter this protected path.
4. Recompute the operation digest from verified principal, policy, Genome and exact operation.
5. Verify Owner signature, subject, executor, capability, resource, effect type, risk, policy, Genome, digest, key validity, expiry and revocation.
6. Atomically consume the nonce.
7. Append the admission audit event.
8. Only after successful admission audit, invoke the executor.

If the admission audit sink is unavailable, the nonce remains consumed and the executor is not called. This is fail-closed and requires a fresh Owner grant after investigation.

## 5. Executor contract

A production `ProtectedEffectExecutor` must:
- Treat the grant nonce as a durable idempotency key.
- Reject the same nonce bound to a different operation digest.
- Persist its operation outcome before returning success.
- Provide a durable lookup by nonce after ambiguous network/process failures.
- Return a signed `ExecutionResultPayload` bound to nonce, operation digest, executor subject, executor key ID, outcome, result digest and completion time.
- Sign with a dedicated executor key under `IROKA:G09:EXECUTION-RESULT:V1\0`.
- Never reuse Owner, trust-root, checkpoint-signer or witness keys.

The kernel verifies executor identity, key validity, signature, nonce, operation digest, completion time and result-digest requirements. Executor keys must be Owner-governed trust configuration; this branch provides the verification interface and synthetic test executor, not production executor key provisioning.

## 6. Ambiguous outcomes and recovery

If execution returns an ambiguous/unavailable result, the kernel queries the executor by the same nonce:
- Valid signed result found: reconcile to the signed outcome.
- No result or lookup unavailable: record `INDETERMINATE`.
- Invalid result signature or mismatched binding: record `INDETERMINATE`, never success.
- Explicit rejection before any effect: record `FAILED`.

Never retry a protected side effect with a new nonce to work around an ambiguous outcome. Recover using the same idempotency key and executor lookup.

## 7. Execution receipt

The kernel creates an `ExecutionReceipt` with:
- Owner, request subject and executor identities.
- Nonce, operation digest, capability, resource and effect type.
- Risk, policy version and Genome digest.
- Grant expiry and admission/completion times.
- Outcome: `SUCCEEDED`, `FAILED`, `PARTIAL` or `INDETERMINATE`.
- Executor key ID/signature and result digest when an executor attestation exists.
- Failure code where applicable.
- Canonical domain-separated receipt digest.

Only an opaque `VerifiedExecutionReceipt` created inside the kernel can be persisted. The security store writes it to an append-only table; exact retry is idempotent and conflicting receipt reuse for the same nonce is rejected. Recovery reads are raw canonical bytes and must be parsed and re-verified.

The audit sink records both admission and final outcome. Non-success outcomes produce an escalation decision. Later external G11 checkpoints anchor the audit history.

## 8. Required adversarial and recovery tests

- Wrong subject, issuer or credential identity.
- Wrong executor, capability, resource, effect type or risk.
- Altered operation amount/destination/payload.
- Wrong policy version or Genome digest.
- Expired/not-yet-valid grant and grant extending beyond Owner key validity.
- Forged signature, unknown/revoked Owner key and revoked grant nonce.
- Duplicate nonce and concurrent replay.
- Emergency stop, policy deny and capability not approval-gated.
- Audit admission failure prevents executor invocation.
- Executor key unknown, expired, wrong subject or revoked.
- Invalid executor signature and operation-digest substitution.
- Executor timeout with durable lookup result.
- Executor timeout with no result; receipt remains `INDETERMINATE`.
- Partial and failed execution outcomes.
- Receipt corruption, duplicate persistence and conflicting nonce reuse.
- Process interruption between admission, side effect and receipt persistence.
- Audit receipt event failure and reconciliation using executor idempotency key.

## 9. Current implementation boundary

The kernel implementation provides the grant type, canonical operation digest, Owner signature/revocation/nonce verification, approval-gated admission, executor trait, signed-result verification, ambiguous-outcome lookup, execution receipt, append-only receipt storage, and synthetic tests.

Not performed:
- No production finance/banking/payment executor.
- No production executor key enrollment or HSM/KMS adapter.
- No live side effect or production credential.
- No multi-process executor recovery drill.
- No independent review of a real executor integration.

A production executor must be separately integrated and tested before protected effects are enabled. No deployment or runtime activation is authorized by this contract.
