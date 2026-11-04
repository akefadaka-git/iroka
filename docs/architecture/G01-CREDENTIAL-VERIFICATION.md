# G01 — Operational Credential Trust Lifecycle

## Credential verification

The kernel accepts compact JWS credentials with exactly three base64url segments. The protected header is fixed to `alg=EdDSA`, `typ=IROKA-CREDENTIAL`, and a non-empty `kid`. Claims require `iss`, `sub`, exact string `aud`, `exp`, `iat`, and `jti`; `nbf` is optional. Unknown fields, malformed segments, algorithm substitution, unsupported types, invalid signatures, incorrect audiences, future/expired time claims and overlong credentials are rejected.

Limits: 16 KiB token size, 3,600-second maximum credential lifetime, 30-second credential clock skew. Approval expiry is strict and does not receive an expiry grace period.

## Trust roots and signed trust bundles

Trust is explicit Ed25519 public-key pinning. A trust bundle contains a monotonically increasing version, issuance/expiry, sorted issuer allowlist and sorted issuer/key-ID public-key records with validity windows. The bundle signature covers both the selected trust-root key ID and the serialized payload. Unknown fields and non-canonical ordering are rejected.

The deployment pins one or more trust-root public keys out-of-band. A root-key overlap set allows a new root to sign a later bundle while the old and new root anchors overlap. Root-set changes themselves remain a separately controlled Owner provisioning ceremony; a root key must never be rotated by an untrusted bundle.

`verify_and_install_trust_bundle` / `verify_and_install_trust_bundle_with_roots` verify the root signature and bundle validity, validate the issuer/key records, and persist the version/digest before returning the new trust snapshot. The SQLite registry rejects version rollback and same-version digest conflicts. Identical same-version installation is idempotent. `TrustSnapshotManager` publishes a verified snapshot atomically in-process.

## Issuer signing-key rotation

1. Prepare a new Ed25519 key pair outside the application and protect the private key in an offline signer/HSM/KMS.
2. Publish a higher-version root-signed bundle containing both old and new public keys with explicit overlapping validity windows.
3. Begin issuing credentials with the new `kid`; monitor adoption and verifier errors.
4. Publish a later signed bundle removing the old key after the bounded overlap.
5. For compromise, issue an Owner-signed revocation command immediately and publish a replacement bundle without the key. Do not wait for normal overlap expiry.

The verifier checks the exact `(issuer, kid)` pair, key validity window, signature, and issuer-scoped credential/key revocation before creating a `VerifiedPrincipal`.

## Revocation and durable registry

`SqliteSecurityStore` provides a single-node durable reference adapter:
- WAL journaling and FULL synchronous commits;
- private file creation mode 0600 on Unix; symlink and group/world-readable files are rejected;
- issuer-scoped credential and signing-key revocations;
- approval revocations and single-use approval consumption;
- atomic signed-command replay record plus revocation effect;
- append-only trust-bundle history, approval receipts and security-command log.

Database errors fail closed. Back up and protect the database and its directory as security-critical state. On non-Unix platforms, enforce equivalent restrictive filesystem ACLs and encrypted-volume controls operationally.

SQLite is not a multi-node consensus store. A multi-node deployment must replace it with a shared transactional adapter preserving atomic anti-rollback, unique consumption, revocation consistency and fail-closed behavior. Do not run independent SQLite copies behind a load balancer.

## Runtime integration

Production verifier construction requires a successfully verified signed trust bundle and an authoritative `RevocationChecker`. `NoRevocations` is compiled only for tests or when the explicit `dev-no-revocations` feature is enabled; it is not part of the default production feature set.

The public assertion-to-principal forgery route is closed: legacy unsigned assertion adapters are test-only. Production callers use `Ed25519CredentialVerifier::from_signed_bundle` or `from_signed_bundle_with_roots` and pass the resulting opaque principal into governed authorization.

## Owner-signed revocation commands

The Owner signs a bounded-lifetime command binding command ID, Owner subject, Owner key ID, issue/expiry and one exact action: revoke credential, signing key or approval. The kernel verifies the signature and Owner key status, then atomically records the command and revocation effect. Replays are rejected. Emergency removal of a compromised trust-root private key requires the out-of-band root ceremony because a compromised root cannot be trusted to authorize its own replacement.

## Boundaries

- No private key is stored in this repository or in the kernel.
- Issuer identity proofing and credential issuance are upstream responsibilities.
- Trust-root public keys and Owner public keys require secure out-of-band provisioning.
- Service clock synchronization, encrypted disks, backups, access controls and alerting are deployment responsibilities.
- G11's general-purpose tamper-evident audit sink remains a separate interface; the SQLite trust history and command/approval receipts are operational records, not a claim that G11 is fully closed.
- Credential authentication and an ALLOW decision do not execute protected side effects. G09 execution grants remain separate.

## Verification

Verification status is recorded on [PR #2](https://github.com/akefadaka-git/iroka/pull/2) and its linked GitHub Actions run. Production activation remains blocked until real public trust roots/Owner public keys are provisioned and a production revocation backend is selected and exercised.