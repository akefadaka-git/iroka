# G01 — Identity Contract v0.2

## Purpose
Establish the identity boundary between untrusted request data and a principal that has passed cryptographic credential verification.

## Concrete credential profile
The kernel now provides an Ed25519 compact-JWS verifier. It accepts only `alg=EdDSA`, `typ=IROKA-CREDENTIAL`, a trusted issuer and exact `kid`, and signed claims for issuer, subject, exact audience, issued-at, expiry, optional not-before and credential ID. Unknown fields and unsupported algorithms are rejected. Credential lifetime is capped at one hour and clock skew at 30 seconds.

## Trust roots and lifecycle
Trust roots are explicitly provisioned Ed25519 public keys pinned to an issuer and key ID. Key rotation uses immutable trust snapshots with an intentional overlap window. Removing a key from the active snapshot blocks it; the revocation adapter separately supports immediate key and credential revocation.

Revocation backend failures fail closed. Production revocation adapters must define authoritative source, maximum cache staleness, propagation objectives and recovery behavior.

## Contract
- Subject, issuer, audience, expiry, issued-at and credential ID are signed claims.
- Expired, malformed, not-yet-valid, wrong-audience, unknown-key, untrusted-issuer, revoked or signature-invalid credentials are rejected.
- Only Ed25519 EdDSA is accepted; no algorithm downgrade or unsigned token path exists.
- Authorization requests must bind exactly to the verified subject.
- Subject strings supplied by agents or callers are never identity proof.
- Verified identity does not grant capabilities or authorize execution.

## Trust boundary and limitations
The public keys and issuer allowlist must be established through a protected provisioning ceremony. The `RevocationChecker` is part of the trusted computing base. The `NoRevocations` adapter is test/development-only. Automated issuer discovery, OIDC integration, key issuance, hardware-backed private-key custody, production revocation storage, tenant trust administration and operational key distribution are not implemented.

The legacy `IdentityVerifier` trait remains an adapter boundary and must only be implemented by reviewed trusted code. Production paths must use the concrete `Ed25519CredentialVerifier`; test mocks must never be wired into production.

## Verification
Cryptographic positive and negative contract tests have been executed successfully in GitHub Actions run [41788340345](https://github.com/akefadaka-git/iroka/actions/runs/41788340345) on commit `4353742e14143cc1cbca4c86aa6e8813a09ab95a`. Rust 1.99.1: formatting, workspace compilation, 19 unit tests, 2 integration tests and Clippy all PASS. This remains a verified implementation contract, not a production identity service; production trust-root provisioning and authoritative revocation infrastructure remain outstanding.
