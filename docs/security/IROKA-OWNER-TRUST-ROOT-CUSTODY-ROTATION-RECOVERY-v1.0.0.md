# IROKA Owner Trust-Root Custody, Rotation and Recovery Runbook v1.0.0

**Status:** A3.10.3 operational security procedure  
**Applies to:** G01 identity trust, G11 checkpoint signing/witness trust, and Owner-governed trust-bundle lifecycle  
**Code baseline:** A3.10 security branch; exact code and tests are recorded in PR #88  
**Production key status:** NOT GENERATED / NOT PROVISIONED by this work

## 1. Purpose and authority boundary

This runbook defines how IROKA trust roots and signing keys are generated, enrolled, rotated, revoked, backed up and recovered. It does not create keys, appoint custodians, select an HSM/KMS provider, or authorize production activation.

The Owner remains the sole authority for approving the trust policy and root-set changes. Key custodians operate the approved ceremony but do not gain policy, execution or governance authority from possession of key material. A valid signature authenticates the signer and signed bytes; it does not establish the substantive truth of the payload.

## 2. Key hierarchy and purpose separation

Use separate cryptographic identities for each purpose:

| Key class | Purpose | Required custody |
|---|---|---|
| Offline bootstrap/recovery root | Approve initial trust-root configuration and emergency recovery | Offline, Owner-controlled, dual-control custody |
| Trust-bundle root | Sign versioned issuer/key trust bundles | Offline or hardware-backed signing boundary |
| Owner authority key | Sign Owner approvals and security commands | Protected signing boundary; never stored in the repository |
| Checkpoint signer key | Sign local audit checkpoints | Dedicated HSM/KMS or isolated signer service |
| Witness key | Sign one operator's witness receipts | Controlled by that independent witness operator |
| Issuer credential key | Sign user/service credentials | Separate issuer-controlled signing boundary |

Do not reuse one Ed25519 key across these roles. Do not use a witness key as a checkpoint signer, Owner key, issuer key, or bootstrap root. Every key ID is globally unique within its purpose and is never reused after retirement or compromise.

## 3. Generation and custody controls

1. Generate production private keys only in an approved offline environment or hardware-backed key service.
2. Generate cryptographically random Ed25519 key material using a reviewed cryptographic provider. Never derive production keys from names, dates, repository IDs, passwords, or synthetic test fixtures.
3. Record public-key fingerprints, key ID, purpose, owner/custodian, creation time, validity window, algorithm, provenance reference, and recovery classification.
4. Require two-person presence for bootstrap/root ceremonies: the Owner approves the operation and an independently designated custodian witnesses the ceremony. The custodian cannot approve on the Owner's behalf.
5. Store private keys in HSM/KMS or offline encrypted media under split custody. Require hardware-backed access controls, access logging, and tested recovery.
6. Do not export private keys unless the approved recovery design explicitly requires it. If export is unavoidable, encrypt under independently held recovery material and record every custody transfer.
7. Store only public keys, fingerprints and non-secret provenance references in repository configuration. Never commit private keys, mTLS client keys, seed phrases, recovery shares, passphrases, or unredacted key-service responses.

## 4. Bootstrap and root enrollment ceremony

Before enabling any production trust root:

1. Freeze the proposed root-set manifest with protocol/version, unique key IDs, public-key bytes/fingerprints, purpose, validity interval, provenance reference and predecessor-manifest digest.
2. Verify every public-key fingerprint through a second authenticated channel independent of the repository change.
3. Confirm the root purpose and validity window; reject duplicate IDs, duplicate public keys, malformed keys, expired keys and overlapping windows that do not have an approved rotation reason.
4. Record the Owner's explicit approval reference and the two-person ceremony record.
5. Provision the approved root set through protected deployment configuration. The runtime must not accept a root set supplied by an untrusted request, model output, ordinary configuration update, or trust bundle that the root set itself is supposed to authorize.
6. Independently read back the configured fingerprints and compare them with the signed ceremony record.
7. Run a synthetic-key verification in CI; never substitute the synthetic fixture for production enrollment evidence.

The current `TrustRootSet` API validates key IDs, public-key encodings, validity windows and provenance references. Root-set replacement remains an out-of-band Owner ceremony; this library does not itself prove that an external operator performed the ceremony. Deployment must therefore enforce protected configuration delivery and record the approved manifest/fingerprint evidence.

## 5. Trust-bundle signing and activation

The kernel's `SignedTrustBundle` path now uses RFC 8785/JCS canonical JSON and the domain separator `IROKA:G01:TRUST-BUNDLE:V1\0`.

A trust-bundle release must:
- Increase the persisted monotonic bundle version.
- Bind the signing root key ID and canonical payload.
- Contain sorted, unique issuer and issuer-key entries.
- Include valid issued-at/expiry windows and no key that outlives the bundle.
- Be signed by an enrolled, currently valid root.
- Persist the anti-rollback high-water mark before the in-process trust snapshot is published.
- Be published atomically through `TrustSnapshotManager`; storage or lock failure must leave the prior snapshot active and return a fail-closed error.

The trust-bundle signing bytes are protocol-versioned. A future serialization/domain change requires a new protocol version and migration plan; do not silently reinterpret existing signed bundles.

## 6. Rotation and overlap

For routine rotation:

1. Generate the replacement key under the same custody controls.
2. Verify the new fingerprint out of band.
3. Publish a higher-version trust bundle signed by an already trusted root.
4. Include the new key and, only for the explicitly approved overlap interval, the old key.
5. Set non-overlapping future validity/retirement boundaries where feasible.
6. Confirm the new key authenticates a synthetic credential and the retired key is rejected after its end time.
7. Record the new bundle digest, version, root key ID and verification results.
8. Retire the old private key from active signing and retain only the minimum public verification material required by the retention policy.

Root rotation is a separate ceremony: provision old and new root public keys during an explicit overlap, sign the new root-set manifest under the approved recovery authority, verify the new root fingerprint out of band, then remove the old root only after dependent bundles and recovery paths have been reconciled. Never allow an ordinary issuer key to add or replace a root.

## 7. Revocation and compromise response

For a suspected or confirmed compromise:

1. Declare the affected key ID and purpose; do not delete historical audit records.
2. Suspend affected signing operations and fail closed where the key is required.
3. Use an unaffected recovery authority to authorize revocation and replacement.
4. Publish a higher-version trust state that rejects the compromised key; verify durable anti-rollback persistence and active snapshot publication.
5. Rotate dependent Owner, issuer, checkpoint or witness keys as applicable.
6. Reissue credentials or checkpoints only under the new approved key and preserve historical signatures for forensic verification.
7. Verify that old signatures remain attributable to the old key and that revocation does not silently convert historical evidence into current trust.
8. Record incident timeline, affected artifacts, fingerprints, approvals, revocation receipts, recovery test results and residual risk.

Never restore a revoked key under the same key ID. Never lower the persisted trust version to make an older bundle load.

## 8. Backup and recovery

- Back up encrypted key-service metadata, public root manifests, trust-bundle digests, version high-water evidence, and recovery instructions separately from application databases.
- Keep recovery copies under separate administration and geographic failure domains where practical.
- Test restoration using synthetic keys before production.
- After restoring a database, verify its integrity, highest trust-bundle version, revocation state, approval-consumption receipts and audit checkpoints against independently retained evidence.
- If local state is behind an externally anchored checkpoint or conflicts with a signed root/trust version, stop protected operations and escalate; do not auto-repair by lowering external state.
- A recovery operator must not be able to mint a new root solely by restoring a backup.

## 9. Operational verification checklist

- [ ] Owner approval reference and two-person ceremony record exist.
- [ ] Public-key fingerprints verified through a second channel.
- [ ] Purpose separation and unique key IDs confirmed.
- [ ] Private keys are outside source control and ordinary configuration.
- [ ] HSM/KMS or offline custody and access logging verified.
- [ ] Rotation overlap and retirement tested with synthetic keys.
- [ ] Revocation and rollback tests pass.
- [ ] Backup restoration and compromise recovery drill pass.
- [ ] Runtime root configuration read-back matches the approved manifest.
- [ ] Independent security reviewer has examined the custody and recovery process.

## 10. Current implementation boundary

Software support verified or being verified in this A3.10 increment:
- Ed25519 root-signed trust-bundle verification.
- Validity, expiry, canonical ordering, signature and provenance checks.
- Persistent monotonic bundle versions and rollback rejection.
- Thread-safe trust snapshot publication after durable persistence.
- Explicit overlapping root-set selection and root-rotation regression tests.
- Canonical, domain-separated trust-bundle signing bytes.

Not performed or claimed:
- No production key generation or provisioning.
- No HSM/KMS selection, enrollment or attestation.
- No Owner/custodian identities appointed by this document.
- No production root-set read-back, backup restore or compromise drill.
- No production runtime activation.

These are required before A5. The software work does not authorize A5 deployment.
