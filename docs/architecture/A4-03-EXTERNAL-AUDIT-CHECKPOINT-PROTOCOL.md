# A4-03 — External Audit Checkpoint and Independent Witness

## Status

- **A1 assessment:** VERIFIED at parent baseline `813b24cbf81f049f2675fbb5492bdc9f262a9d87`.
- **A2 architecture:** VERIFIED-CLOSED by Owner approval on 2026-11-08.
- **A3 implementation:** IMPLEMENTED; exact-head software gates passed on code commit `ed969bf2fe6e336e7678e2fe7458080a52f2c60a`.
- **A4 software verification:** PASS on that exact code commit; see evidence below.
- **A4-03 closure:** PARTIAL / NOT CLOSED. Production witness independence, durable remote retention, signer custody and operational controls are not implemented or verified.
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

## A4-03 verification evidence — 2026-11-08

The initial exact-head run on `ecfb2f81e3fb03633425f095acd02e15a612f774` passed formatting, compilation, production-feature checks and all 73 tests, but Clippy failed on three clone-related lints. Those findings were remediated in `ed969bf2fe6e336e7678e2fe7458080a52f2c60a` by removing a clone of the Copy `VerifyingKey` and using `std::slice::from_ref` for single-receipt quorum assertions.

**Successful exact-head run:** [GitHub Actions run #341](https://github.com/akefadaka-git/iroka/actions/runs/42473737412), checked out commit `ed969bf2fe6e336e7678e2fe7458080a52f2c60a`.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets --locked` | PASS |
| `cargo check --workspace --all-targets --no-default-features` | PASS |
| `cargo test --workspace --all-targets --locked` | PASS — 71 unit + 2 integration; 73 passed, 0 failed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic` | PASS |

Workflow job `128710325540` completed successfully. No compile, test, formatting or Clippy failures remain on the verified code commit.

## Closure-readiness assessment — NOT CLOSED

Software protocol gates are green, but this is not evidence that a real independent external checkpoint system exists. Closure remains blocked on the following distinct work and Owner decisions:

1. **Production signer custody:** select and approve an Owner-controlled signing boundary; define key generation, rotation, revocation, backup and recovery.
2. **Independent witness service(s):** select operators under separate administration, implement authenticated publish/retrieve adapters, and prove durable monotonic acceptance.
3. **Immutable retention:** demonstrate independently administered retention, retrieval, tamper resistance and restore/recovery; the in-memory test witness is not durable or independent.
4. **Production trust policy:** approve witness identity enrollment, trust roots and quorum threshold; test key-to-identity binding and revocation lifecycle.
5. **Operational policy:** approve checkpoint cadence, maximum unanchored tail, outage behavior, monitoring and incident response.
6. **End-to-end A4 evidence:** integration tests against isolated witness instances, concurrency/race tests, network partition/retry/idempotency tests, restore drill and independent security review of the deployed adapter and trust model.

Until these items are separately implemented and verified, classify the delivered work as **A4 software gates PASS / A4-03 closure PARTIAL**. A5 remains NOT AUTHORIZED / NOT RUN. PR #15 remains draft, open and unmerged. No production keys, external provider, paid service, top-up or deposit were used or requested.
