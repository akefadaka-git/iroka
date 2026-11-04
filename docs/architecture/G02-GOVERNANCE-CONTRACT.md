# G02 — Owner Authority and Signed Approval Contract

## Authority model

The first concrete authority model is direct Owner authority only. The kernel has no default Owner identity, no self-registration, no model-created authority, and no implicit delegation. An Owner public key is provisioned out-of-band and bound to one exact Owner subject, key ID and validity window. Multiple overlapping public keys support controlled Owner-key rotation; compromised keys are revoked through a separately signed Owner security command.

Delegation, quorum, multi-party approval, emergency succession and policy for Owner incapacity are intentionally not implemented in this slice. They require separate Owner decisions and a later governance contract.

## Signed approval payload

Every approval is an Ed25519 signature over a deterministic serialized payload binding:
- unique approval ID;
- exact Owner subject and signing key ID;
- requesting principal subject;
- exact capability and resource;
- exact policy version;
- issuance and expiry timestamps.

The signature is detached from the payload. The kernel accepts only explicitly provisioned Owner keys. The private key remains in an offline signer, hardware token or KMS; the kernel receives only the signature and public-key configuration.

## Verification sequence

1. Verify requester principal was produced by the concrete G01 credential verifier.
2. Evaluate capability, risk and emergency-stop policy.
3. If approval is required, validate all payload fields and exact request/policy binding.
4. Enforce Owner key validity at issuance and verification, a maximum 900-second approval lifetime, future-issued checks and strict expiry.
5. Verify the Ed25519 signature.
6. Check Owner-key and approval revocation state.
7. Atomically consume the approval ID once and persist a receipt containing the payload digest and bound scope.
8. Append the authorization decision through the configured audit sink. Audit failure converts a positive decision to ESCALATE.

Replay, invalid signatures, wrong scope, expired approvals, revoked keys/approvals, unknown keys and registry failures never produce ALLOW.

## Signed Owner security commands

The same Owner key can sign short-lived commands to revoke an issuer credential, issuer signing key, or approval. Each command is replay-protected. Its command digest, Owner subject/key ID, target, reason and timestamp are recorded atomically with the revocation effect.

## Authorization API

Production integrations use `authorize_authenticated_with_owner_approval`. The method only decides and records; it does not execute the requested action. A successful ALLOW is not an execution credential. G09 must independently authorize and issue any short-lived execution grant.

Legacy unsigned approval evidence and generic assertion verifier adapters remain available only inside crate tests, not in production builds.

## Verification and operational boundary

Cryptographic unit and contract tests cover valid signatures, tampering, scope mismatch, unknown/revoked Owner keys, revoked approvals, expiry, overlong TTL, replay and the end-to-end authorization decision path. See [PR #2](https://github.com/akefadaka-git/iroka/pull/2) for exact run evidence.

No real Owner public key or private key has been provisioned. Production use remains blocked until the Owner key ceremony is completed and the public-key allowlist is installed through a protected deployment configuration channel.