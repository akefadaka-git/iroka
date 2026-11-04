# G01 — Concrete Credential Verification v0.2

## Credential profile

IROKA Kernel accepts compact JWS credentials with exactly three base64url segments:
- protected header: `alg=EdDSA`, `typ=IROKA-CREDENTIAL`, non-empty `kid`;
- claims: `iss`, `sub`, exact string `aud`, `exp`, `iat`, optional `nbf`, and unique `jti`;
- signature: Ed25519 over the exact ASCII `header.payload` signing input.

Unknown header/claim fields are rejected. Algorithm negotiation, `none`, algorithm fallback, key URL headers, embedded JWKs, and implicit issuer discovery are not supported. Tokens are size-limited to 16 KiB. Maximum credential lifetime is one hour; clock skew is bounded to 30 seconds.

## Trust roots and issuer binding

Trust is direct public-key pinning, not ambient WebPKI discovery. Provision an explicit issuer allowlist and a set of Ed25519 public keys keyed by the exact pair `(issuer, kid)`. Invalid keys, duplicate key IDs for an issuer, empty trust sets, malformed validity windows, and keys for untrusted issuers fail configuration.

The caller must provision trust material through a separate secure channel. Private signing keys must never be placed in this repository, application configuration committed to source control, logs, or model context.

## Rotation

Publish a new immutable TrustStore snapshot containing both old and new public keys with deliberate overlapping validity windows. Issue credentials with the new `kid`; retain the old key only for the bounded migration interval. After the overlap, publish a snapshot without the old key. Emergency compromise response removes the compromised key immediately and also revokes its key ID in the authoritative revocation service.

TrustStore replacement and key distribution are operational responsibilities not implemented by this crate. A deployment must make snapshot rollout atomic and observable.

## Revocation

The `RevocationChecker` is a required runtime adapter. It checks both issuer-scoped credential IDs (`jti`) and issuer-scoped key IDs. Backend errors return `RevocationUnavailable` and fail closed. Production implementations must use authoritative state or a cache with a documented maximum staleness; stale/unavailable state must never silently become "not revoked".

The included `NoRevocations` implementation is for local tests and development only. It must not be wired into a production service.

## Security boundaries and limitations

- Signature verification proves possession of the key corresponding to a configured public key; it does not itself prove that the issuer's identity-proofing process is adequate.
- The issuer allowlist and public keys must be established by a protected provisioning ceremony.
- This implementation does not yet provide OIDC discovery, certificate-chain validation, hardware-backed key storage, signing-key issuance, automated rotation, a production revocation database, tenant-specific trust administration, or service-to-service mTLS.
- A verified principal is passed to `authorize_authenticated`, which binds the exact subject and continues through G02 policy/approval and G11 audit checks. Credential verification alone never grants a capability or authorizes execution.
- The legacy `IdentityVerifier` trait remains a test/adapter boundary. Production callers should use the concrete verifier to create a `VerifiedPrincipal`; arbitrary caller-created assertions must not be trusted.

## Verification status

## Executed verification\n\nGitHub Actions run [41788244260](https://github.com/akefadaka-git/iroka/actions/runs/41788244260) passed on commit `583befbab5af2ed299054db0cf30ab4a8ff625c0` using Rust/Cargo 1.99.1. Results: `cargo fmt --all -- --check` PASS; `cargo check --workspace --all-targets` PASS; `cargo test --workspace --all-targets` PASS (19 unit tests and 2 integration/contract tests; 21 total); `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic` PASS.\n\nSecurity negative tests exercised algorithm substitution, signature tampering, unknown key ID, revoked credential, revoked signing key, revocation-service unavailability, malformed and oversized tokens, wrong audience, expired credentials, and key validity-window rejection. Rotation-overlap acceptance was also tested.\n\nNo production deployment, production trust-root provisioning, or production revocation-store provisioning has occurred.
