# IROKA A4 Security Evidence Reconciliation v1.0.0

**Status:** OPEN — SOFTWARE EVIDENCE PARTIALLY VERIFIED; EXTERNAL AND INDEPENDENT GATES OUTSTANDING  
**Scope:** A3.10.3, A3.10.5, A3.10.7 and integrated security baseline  
**Deployment:** Not authorized

## 1. Reconciliation rule

A stage is closed only when implementation, exact-head verification, required operational evidence and independent review (where applicable) are all present. A successful CI run on an earlier SHA is historical evidence, not proof for a later commit. A written procedure is not proof that a ceremony, restore or external operation occurred.

## 2. Exact-head automated evidence

The last fully reconciled three-workflow baseline is PR #88 head:

`8022e4b6e31e6f090996a22b321d4b177e20aa17`

- Rust kernel run #1842: https://github.com/akefadaka-git/iroka/actions/runs/44005373711 — SUCCESS.
- Security supply-chain run #55: https://github.com/akefadaka-git/iroka/actions/runs/44005373731 — SUCCESS.
- GENESIS schema closure run #140: https://github.com/akefadaka-git/iroka/actions/runs/44005373636 — SUCCESS.

The Rust run included formatting, compilation, production feature guard, complete tests, optimized build and Clippy. At that baseline, 106 unit tests and 2 integration tests passed.

**Later changes are not covered by those runs.** Subsequent commits added strict SPDX package-set/graph reconciliation, SBOM regression tests, actionlint validation, release tag/main ancestry checks, provenance/SBOM verification commands, a witness SQLite backup/restore test and updated architecture/operational documents. Current-head CI must be rerun on the final branch head before any further software-closure claim.

## 3. SBOM artifact reconciliation

The SBOM from supply-chain run #55 was downloaded and independently inspected.

- SPDX 2.3 document.
- 63 package records: one workspace crate and 62 registry crates.
- Cargo.lock also contains 63 package records: one workspace crate and 62 registry crates.
- All 62 registry packages have Cargo.lock SHA-256 checksums.
- 63 package URLs.
- 96 unique DEPENDS_ON relationships and one DESCRIBES relationship.
- All SPDX package IDs unique; no dangling relationship references.
- SBOM artifact ZIP digest: `sha256:e863147e201e7e8a0a2581edd4c4f173eb57b3e80626ed62b5b6fc29b79824f0`.
- Artifact retention expiry: 2027-02-15.

The generator was subsequently strengthened to require exact equality between Cargo metadata and Cargo.lock package identities, require a complete resolved graph, validate every registry checksum and reject unknown dependency-edge endpoints. Regression tests were added. These later changes require a fresh supply-chain run and SBOM artifact before final A3.10.5 software closure.

## 4. A3.10.3 — Trust roots and audit checkpoints

**Software implementation:** Durable SQLite witness reference backend implemented. It verifies checkpoint signatures, binds a database to one witness identity/key, enforces immediate transactional sequence/predecessor rules, exact idempotent retry, append-only triggers and persisted signed receipts. POSIX database paths reject symlinks and unsafe permissions; non-POSIX operation fails closed.

**New local recovery test:** A SQLite VACUUM INTO backup/restore test was added to prove checkpoint/receipt chain readback, signature verification and idempotent retry after restore. This test is not yet exact-head verified.

**Operational status:** OPEN. No independently administered witness endpoints, live mTLS enrollment, operator independence evidence, production trust-root ceremony, HSM/KMS custody, external backup/restore drill or production credential provisioning has been supplied or performed.

Required external evidence:
- At least two Owner-appointed, separately administered witness operators.
- Operator identity, legal/control and infrastructure independence evidence.
- Live signed challenge, checkpoint, receipt, replay/conflict, outage/quorum and key-rotation tests.
- Owner/custodian trust-root ceremony and protected signing boundary evidence.
- Independent external backup and restore/reconciliation drill.

## 5. A3.10.5 — Supply-chain security

**Previously verified controls:** RustSec audit, cargo-deny policies, locked optimized build, Gitleaks full-history scan and dependency remediation passed on the historical exact head above.

**SBOM:** The generated artifact's package inventory and relationships were checked against the Cargo.lock record count and its internal SPDX graph. The updated generator now rejects any package-set mismatch and incomplete resolution graph.

**Release workflow:** `.github/workflows/release-attest.yml` builds the kernel library from a stable release tag on main, creates provenance and SPDX SBOM attestations using the pinned GitHub attestation action, verifies both attestations and uploads release assets. Official action documentation supports the configured `id-token: write`, `attestations: write`, `artifact-metadata: write`, `subject-path` and `sbom-path` contract. The workflow has not been executed because no release has been authorized. YAML/actionlint and exact-head CI must pass before release behavior is considered verified; real attestation verification requires a separately authorized stable release.

**Status:** PARTIAL pending new exact-head CI for the hardened generator, regression tests and actionlint checks, plus an authorized real release attestation run.

## 6. A3.10.7 — Independent assessment

**Status:** NOT CLOSED / NOT STARTED.

The assessment package defines reviewer independence, scope, adversarial test cases, report format and closure criteria. No independent assessor has been appointed by the Owner. No independent review, authenticated report, finding register or independent retest exists. The implementation author and automated CI cannot satisfy this gate.

## 7. Runtime architecture and G09 production integration

The hybrid runtime reference architecture is documented at:

`docs/architecture/IROKA-HYBRID-RUNTIME-REFERENCE-ARCHITECTURE-v1.0.0.md`

The proposed G09 production executor transport contract is documented at:

`docs/security/IROKA-G09-PRODUCTION-EXECUTOR-INTEGRATION-PROPOSAL-v1.0.0.md`

The actual production executor is NOT integrated. No first protected-effect domain, business system/API, staging endpoint, mTLS credentials, executor signing key, operator, transaction/idempotency guarantees or recovery owner has been selected/provisioned. The architecture names logical components, not implemented service binaries. The repository still builds a kernel library, not a complete runtime.

## 8. External operational exercises

The runbook `docs/security/IROKA-EXTERNAL-WITNESS-KEY-CUSTODY-AND-RESTORE-EXERCISE-v1.0.0.md` defines staging tests, key ceremony, backup/restore and pass criteria.

No real external operator, HSM/KMS custody ceremony, independent backup account or witnessed restore drill has occurred. Local synthetic SQLite tests are not a substitute.

## 9. A4 closure checklist

- [x] Final current-head Rust, GENESIS and supply-chain workflows pass on frozen PR #88 head `d504c54fab04fe36866894c6c1f7f79eea516337` (runs #1872, #170 and #74).
- [x] Hardened SPDX generator regression tests pass; the exact-head SBOM generator enforced equality of Cargo metadata/Cargo.lock package identities, complete resolved graph coverage and registry checksum validity; the generated artifact was independently inspected (Section 11).
- [x] Release workflow YAML/actionlint validation and static permissions/input review pass (Section 12); actual release attestation execution remains pending.
- [ ] Authorized stable release produces library, SBOM, provenance and SBOM attestations; both attestations verify against exact artifact digest.
- [x] Witness backend backup/restore test passes on exact code-verification head `d504c54fab04fe36866894c6c1f7f79eea516337` (Rust run #1872; named test evidence in Section 11).
- [ ] Two independent witness operators are appointed and organizational independence is evidenced.
- [ ] Live publish/readback, replay/conflict, sequence, outage/quorum, key rotation and restore tests pass.
- [ ] Owner/custodian trust-root ceremony and protected signing boundary evidence are recorded.
- [ ] Independent external backup/restore/reconciliation drill passes with measured RPO/RTO.
- [ ] Independent security assessment completed on a frozen exact commit; no unresolved Critical/High findings; remediations independently retested.
- [ ] Production G09 executor selected, implemented, tested against its staging system and key lifecycle.
- [ ] Runtime service binaries, environment, deployment controls, monitoring and rollback are implemented and verified.
- [ ] Owner accepts residual risks and signs the A4 closure decision.

## 10. Closure decision

**A4: NOT CLOSED.** This document is the formal evidence reconciliation and closure submission, but the gate fails because independent assessment, external witness operations, production trust-root custody/recovery, production G09 integration and complete runtime deployment evidence are absent. Do not represent A4 as closed.

No merge, release, production key provisioning, runtime activation or deployment follows from this evidence report. A5 remains a separate Owner decision.


## 11. Latest exact-head CI and SBOM evidence — 2026-11-17

**Frozen verification commit:** `d504c54fab04fe36866894c6c1f7f79eea516337` on PR #88 branch `feat/a3-security-workstreams`, base `architecture/genesis-gene-contract-amendment-proposal` at `8e4a8b5582d47d430539ae7b56aac75f0991c8a4`.

All three required workflows completed successfully on this exact commit:

- Rust kernel verification run #1872: https://github.com/akefadaka-git/iroka/actions/runs/44106810503 — PASS. Job 134121268946; 111 unit tests and 2 integration tests passed, 0 failed; named test `sqlite_checkpoint_witness::tests::durable_witness_backup_restore_preserves_checkpoint_and_receipt_chain` passed; formatting, all-target compilation, production feature guard, optimized workspace build and Clippy passed.
- GENESIS gene schema closure run #170: https://github.com/akefadaka-git/iroka/actions/runs/44106811083 — PASS. Job 134121277394; all 72/72 Genome schema references resolved; all schemas passed Draft 2020-12/unique-ID/closed-object checks; 0 generic array fields lacked approved item contracts; all 53 item-schema references resolved. The workflow also completed cross-collection semantic integration conformance. Schema validation alone is not represented as proof of graph invariants beyond the integration checks.
- Security supply-chain verification run #74: https://github.com/akefadaka-git/iroka/actions/runs/44106810736 — PASS. Job 134121278966; locked graph, RustSec, cargo-deny, syn-version disposition, optimized build, full-history Gitleaks, actionlint v1.7.12, SPDX generator regression tests, SBOM generation and artifact upload all passed.

### 11.1 Actual SBOM artifact inspection

- Workflow artifact ID: `14337619679`.
- Artifact name: `iroka-cargo-sbom-d504c54fab04fe36866894c6c1f7f79eea516337`.
- Artifact ZIP size: 7,280 bytes.
- Artifact ZIP SHA-256: `677c93bb73b076c54e723e34beff6d61cf27e554cea9809abb4d0dcc4608aeb9` (matches GitHub artifact metadata digest).
- Artifact created: 2026-11-17 14:53:35 UTC; expires: 2027-02-15 14:46:37 UTC.
- Contained file: `iroka-cargo.spdx.json`.
- SBOM file SHA-256: `712b909082b78e34572bf9a576cfc80e121c57a05c8687b375ba524d306cb990`.
- SPDX version: 2.3; document name: `IROKA ZERO Cargo workspace`.
- Package records: 63 total — 1 workspace crate and 62 registry crates; 63 unique SPDX package IDs and 63 unique Cargo package URLs.
- Every one of the 62 registry package records contains a 64-character SHA-256 checksum.
- Relationships: 96 unique `DEPENDS_ON` plus 1 `DESCRIBES`; zero dangling relationship references.
- Document namespace embeds Cargo.lock SHA-256: `bdfdaa7838e5d5f1ad2c377cc5bcbd6bfff6e7dff6a3963b4a9aa55704f81980`; Cargo.lock Git blob SHA at this commit: `17f972f5c55f63f41ca92bdaf6bbe1b1803b56d1`.
- The successful generator step enforced exact Cargo metadata/Cargo.lock package identity-set equality, complete resolved graph coverage, and valid registry checksums before emitting the artifact. The downloaded SBOM was independently parsed and its package IDs, PURLs, checksum presence and relationship endpoints were checked. This is artifact-content reconciliation, not a claim that a separate third-party SPDX conformance validator was run.

**A3.10.5 software evidence:** VERIFIED on the frozen commit above. Release-attestation execution remains a separate uncompleted gate.

## 12. Release-attestation workflow semantic review

Reviewed `.github/workflows/release-attest.yml` at the frozen commit; Git blob SHA `3251b9d081e4094876b7cf361153ad87f07908bb`. The pinned `actions/attest` action commit is `1e69f48acb82d1966a394da916b4c1698aa569d6`; its pinned `action.yml` declares both `subject-path` and `sbom-path` inputs.

- Exact-head supply-chain run #74 successfully parsed the YAML and passed actionlint v1.7.12.
- The workflow only starts for a published release, then excludes drafts and prereleases; it checks that the tag resolves to `GITHUB_SHA` and that the commit is an ancestor of `origin/main`.
- The build step uses locked Cargo commands, tests and Clippy, creates the SPDX JSON, and copies `libiroka_kernel.rlib` as the attestation subject.
- The first attestation action call supplies `subject-path` only, selecting the action's provenance mode. The second supplies the same subject plus `sbom-path`, selecting SPDX SBOM attestation mode. Both inputs are supported by the exact pinned action metadata.
- `id-token: write` and `attestations: write` are present. `contents: write` is needed for release asset upload. `artifact-metadata: write` is broader than this file-only workflow currently appears to require because `push-to-registry` is not enabled; consider removing it before release unless artifact storage-record functionality is intentionally added.
- The two `gh attestation verify` calls are semantically aligned: default provenance verification for the library, then SPDX predicate verification using `https://spdx.dev/Document/v2.3`. GitHub's documentation specifies the predicate-type flag for SPDX SBOM attestation verification.
- The workflow attaches the library and SBOM to the published release. It does not build a deployable IROKA runtime; the subject remains a Rust kernel `.rlib`.

**Static workflow semantics:** PASS, with the least-privilege note above. **End-to-end release/attestation behavior:** NOT RUN — no release was created or published, consistent with the Owner's deployment/release restrictions. Do not describe attestations as generated or verified until a separately authorized release run produces and verifies them.

## 13. Updated A4 decision

The exact-head software verification and SBOM artifact reconciliation items are evidenced on code-verification commit `d504c54fab04fe36866894c6c1f7f79eea516337`. The A4 evidence update was committed separately as documentation-only commit `9f589502de9c40ba1f572541209d0a8fb70e47dc`; no workflow runs were returned for that documentation-only commit, and it changed only this reconciliation document. The tested code did not change after `d504c54`. This does not close A4. Independent assessment, external witness operations, production trust-root custody/recovery, external restore evidence, production G09 integration, a deployable runtime, and an authorized end-to-end release-attestation run remain outstanding. The workflow/document update itself may advance the PR head and require a fresh exact-head CI reconciliation before a later closure decision.
