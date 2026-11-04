# IROKA Owner and Trust-Root Provisioning Runbook

## Purpose and safety

This runbook provisions public trust anchors only. Private keys must be generated and retained on an Owner-controlled offline device, hardware security module or approved key-management service. Never paste private keys, seed phrases, recovery codes or signing secrets into ChatGPT, GitHub issues, source files, CI variables or logs.

No default key is shipped. The repository contains no live Owner identity key or trust-root key.

## Key roles

- **Offline trust root:** signs versioned G01 trust bundles. It is not used for routine user approvals.
- **Issuer signing keys:** sign short-lived G01 credentials. Each is identified by issuer plus `kid`.
- **Owner approval key:** signs G02 approvals and Owner security commands. Its public key is bound to the canonical Owner subject.
- **Owner recovery/root ceremony:** handles replacement of a compromised Owner or trust-root key out-of-band.

Use separate keys for these roles. Do not reuse an issuer credential key as the Owner approval key or trust root.

## Provisioning sequence

1. Select an offline signing device/HSM/KMS and an independent backup/recovery procedure.
2. Generate Ed25519 key pairs for the trust root and Owner approval identity on that controlled device.
3. Export only the raw 32-byte Ed25519 public keys and assign unique, immutable key IDs.
4. Record the Owner subject exactly (for example, an organization-controlled subject URI); do not infer it from a GitHub username or email address.
5. Configure trust-root public keys and Owner public keys in the deployment secret/configuration channel with their validity windows. Do not commit these deployment values to this public repository.
6. Create trust-bundle version 1 with sorted issuer names and sorted issuer/key-ID entries. Set a bounded bundle expiry and key validity windows. Sign the trust-bundle envelope bytes produced by `SignedTrustBundle::signing_bytes_for(root_key_id, payload)`.
7. Deploy the signed bundle and configured root set. Initialize the durable security registry, verify the bundle and confirm the stored highest version equals 1.
8. Issue a test credential from an authorized issuer and verify successful authentication. Revoke a test credential using an Owner-signed security command and verify the same credential is rejected.
9. Sign a short-lived test Owner approval binding requester, capability, resource and policy version. Confirm one successful authorization, then confirm replay is rejected.
10. Record public key IDs, fingerprints, validity windows, ceremony operator, witness, timestamp and recovery location in the organization's controlled security register. Do not record private key material there.

## Rotation

### Issuer key
Publish a higher-version trust bundle containing old and new keys with an intentional overlap. Switch issuance to the new key ID. Monitor adoption. Publish a subsequent bundle removing the old key. For compromise, immediately revoke the key ID and affected credential IDs, then publish a bundle excluding the key.

### Owner approval key
Provision the replacement public key in the protected Owner-key configuration with a bounded overlap. Confirm test signing with the replacement. Revoke the compromised/retired key using a different uncompromised Owner key. If no trusted Owner key remains, use the independent recovery ceremony; do not bypass the kernel.

### Trust root
A trust-root rotation requires an out-of-band update of the pinned `TrustRootSet`. During the planned overlap, deploy both old and new public roots; sign the next bundle with the new root; then remove the old root after confirmation. If the old root is compromised, the recovery process must rely on the independently held recovery authority and deployment access controls, not on a signature from the compromised key.

## Operational requirements

- Keep system clocks synchronized; all payload timestamps are Unix seconds.
- Restrict database and parent-directory permissions; encrypt disks and backups.
- Back up the SQLite security registry and test restoration. SQLite is for a single-node service; multi-node production requires a shared transactional backend.
- Monitor bundle expiry, key expiry, revocation-store availability, replay rejections, signature failures and trust-version changes.
- Never deploy `NoRevocations` or the `dev-no-revocations` feature in production.
- Keep G11's general tamper-evident audit service and G09 execution authorization as independent gates.

## Current status

Code and tests are being verified in PR #2. This runbook does not mean real Owner/trust-root keys have been provisioned or production trust activated.