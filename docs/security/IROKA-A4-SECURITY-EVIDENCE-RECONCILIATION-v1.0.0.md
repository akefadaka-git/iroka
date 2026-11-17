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

- [ ] Final current-head Rust, GENESIS and supply-chain workflows pass on one frozen exact PR #88 head.
- [ ] Hardened SPDX generator regression tests pass; generated SBOM matches complete Cargo metadata, Cargo.lock and resolved dependency graph.
- [ ] Release workflow passes actionlint and its YAML/permissions/inputs are reviewed.
- [ ] Authorized stable release produces library, SBOM, provenance and SBOM attestations; both attestations verify against exact artifact digest.
- [ ] Witness backend backup/restore test passes on exact head.
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
