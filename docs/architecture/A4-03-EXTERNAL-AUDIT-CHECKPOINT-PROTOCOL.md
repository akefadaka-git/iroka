# A4-03 — External Audit Checkpoint and Independent Witness

## Status

- **A1 assessment:** VERIFIED at parent baseline `813b24cbf81f049f2675fbb5492bdc9f262a9d87`.
- **A2 architecture:** VERIFIED-CLOSED by Owner approval on 2026-11-08.
- **A3 implementation:** IN PROGRESS; protocol contracts and deterministic test witness implemented; exact-head CI pending.
- **A4 verification:** NOT RUN / pending CI.
- **A5 deployment:** NOT AUTHORIZED / NOT RUN.

Owner approved a provider-neutral core, configurable multi-witness quorum, and deterministic test-only witness. This approval freezes the architecture, not production custody or operational configuration.

## Verified starting boundary

The existing `SqliteAuditSink` provides ordered local SHA-256 hash chaining, `head()`, full-chain integrity verification, SQLite transactional writes and ordinary update/delete triggers. It does not independently anchor its history. A privileged actor able to replace or truncate the local database can rebuild a self-consistent unanchored chain.

## Implemented protocol contracts

Implementation lives in `crates/iroka-kernel/src/external_checkpoint.rs`, exported from `lib.rs`.

1. **Checkpoint envelope:** versioned protocol identifier, stable stream ID, checkpoint sequence, event sequence and 32-byte head digest, predecessor checkpoint digest, signer key ID, timestamp and Ed25519 algorithm.
2. **Canonical signatures:** RFC 8785/JCS serialization and domain-separated Ed25519 signing bytes for checkpoints and witness receipts.
3. **Signer adapter:** injected `CheckpointSigner` trait. No production private key or provider credential is embedded.
4. **Witness adapter:** `CheckpointWitness` publish/retrieve contract. Production implementations must durably enforce monotonic acceptance and independent retention.
5. **Witness receipt:** binds witness identity/key, stream, checkpoint sequence, exact signed-envelope digest, predecessor and acceptance time; caller verifies receipt signature against supplied witness trust roots.
6. **Quorum verification:** configurable threshold; receipts must be valid and represent distinct witness identities. Threshold is not hard-coded as a production policy.
7. **Reconciliation:** exact local head, local truncation/rollback behind the anchor, same-position fork, and unanchored local tail are distinguished.
8. **Test witness:** deterministic test-only signer/witness fixture validates checkpoint signatures and enforces per-stream sequence, predecessor, replay and gap rules. It is not a real independent service or durable production store.

## Owner-frozen architecture and remaining operational decisions

The following architecture choices are frozen:
- provider-neutral signer and witness interfaces;
- configurable multi-witness quorum;
- deterministic in-memory witness for automated tests;
- no production secrets or provider-specific implementation in the kernel.

The following remain separate Owner-governed deployment decisions:
- production signer custody (Owner-controlled signing service/HSM/KMS or other independently administered signer);
- witness operator(s), independent retention authority and provider selection;
- production quorum threshold and trust-root registration;
- checkpoint cadence, maximum unanchored tail and witness-outage availability policy;
- key generation/rotation/revocation ceremonies, backup/restore drills and runtime activation.

No production keys, external services, witness registrations, remote retention or runtime activation have been provisioned.

## A3 verification plan

Required automated coverage:
- checkpoint and receipt signature tampering;
- exact receipt-to-envelope binding and stream separation;
- duplicate witness identity and insufficient quorum;
- witness replay, conflicting sequence, sequence gap and predecessor mismatch;
- local exact-head, rollback/truncation, fork and unanchored-tail reconciliation;
- full Rust format, locked compile, production-feature, unit/contract and Clippy gates at exact HEAD.

A deterministic in-memory witness verifies protocol semantics only. It cannot establish real-world witness independence, immutable retention, production key custody, service availability or restore readiness.

## Governance boundary

No merge, deployment, production Genesis activation, trust-root provisioning, production signer creation, external provider selection or payment is authorized by this work. No top-up, deposit or paid service is required or requested.
