# IGACMS A3 implementation record

**Authorization:** Owner authorization received 2026-11-07 for A3.1–A3.8 in `akefadaka-git/iroka`.
**Baseline:** IGACMS v1.0 A2 at `a709fc473b23494839417449e34bebf4cb8be77a`.
**Branch:** `feat/igacms-a3-implementation`.
**Merge/deployment:** not authorized; not performed.

## Work packages
1. A3.1 — Machine-readable DNA/Genome/chromosome/gene/marker schemas and complete manifest.
2. A3.2 — Canonical validator including all eight historical domains, explicitly including `reasoning`, 12 chromosomes, 36 core genes, 14 principles, 14 invariants, 27 markers, uniqueness and acyclic dependencies.
3. A3.3 — SHA-256 fingerprint over deterministic canonical JSON. This initial implementation is restricted to the integer-only manifest profile; it is not claimed as a general RFC 8785 implementation for arbitrary floating-point JSON.
4. A3.4 — Ed25519 attestation and trust-root verification, epoch-zero genesis and anti-rollback. No production keys are created or provisioned.
5. A3.5 — M0–M5 evidence gates, Owner approval and independent review controls, M5 dual control.
6. A3.6 — Kernel integration gate before Owner-approved authorization decisions.
7. A3.7 — Historical digest-preserving migration evidence; DNA-045 remains extension-review and outside genesis.
8. A3.8 — Positive/negative conformance tests and exact-SHA verification. Independent review is not an Owner-mandated closure prerequisite following the Owner's explicit waiver on 2026-11-08.

## Known limitations to close before A3 completion
- Trust-root provenance metadata is not a production custody ceremony; operational custody, dual-control signing and production key provisioning remain separate gates.
- Historical Git blob SHA-1 is checked using the Git `blob <length>\\0` object preamble; SHA-256 is separately recorded for content integrity. SHA-1 is used only for Git object compatibility, not as a security primitive.
- RESOLVED: the 39-character value `1224bb8298f9ef21d2590dd6e70273501281cd9` is a valid unique Git object prefix and resolves in `akeayu/iroka` to full commit `1224bb8298f9ef21d2590dd6e70273501281cd9c` ([source commit](https://github.com/akeayu/iroka/commit/1224bb8298f9ef21d2590dd6e70273501281cd9c)). At that exact commit, the fetched Git blob IDs for DNA-001 (`7206f07941455c976af889884ec873da73349737`), DNA-012 (`a6446ea08890da3ea195b1d977d0a9aed0c4ba64`), DNA-013 (`d3fd1fcfaee32e3a13ca123c3f319ae8df750696`) and DNA-045 (`edd58b38fb2f2098aeea9716d0eba0897a753811`) match the A2 disposition register. The original register is preserved unchanged; this A3 record documents the prefix-to-full-SHA resolution.
- Source tests are not PASS evidence until run at the exact final SHA.


## Exact-SHA verification evidence

**Verified implementation commit:** `046656d602eddadf647895f0e7c9ef24b4bd6749`  
**Workflow run:** [#42452827086](https://github.com/akefadaka-git/iroka/actions/runs/42452827086)  
**Result:** PASS — all five automated gates passed on this exact commit.  
**Pinned v1.0 Genome SHA-256:** `a89e2b5bdb3519201268cf087b84df676e34f932c33c888de00794362864351c`

| Gate | Evidence |
|---|---|
| Rust formatting | PASS — `cargo fmt --all -- --check` |
| Workspace compilation | PASS — `cargo check --workspace --all-targets --locked` |
| Production feature set | PASS — `cargo check --workspace --all-targets --no-default-features` |
| Unit and contract tests | PASS — 55 unit tests and 2 documentation tests; zero failures |
| Clippy | PASS — `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic` |
| Dependency lockfile | PASS — locked build resolves `serde_jcs 0.2.0` and `sha1 0.10.6` |

The Rust formatter corrections were committed in `acf09a5962803b7ec1b7876b4f8ff6cf71da27e0`. The validator was then corrected to preserve the distinct `MissingDomain` error for absent historical domains while rejecting duplicate and unknown domains as malformed; that correction is included in the verified commit above.

## A3 completion assessment

- **A3.1:** VERIFIED — DNA, Genome, chromosome, gene, marker-definition, marker-assertion, Genesis, attestation, mutation-evidence and migration-evidence schemas committed.
- **A3.2:** VERIFIED — strict duplicate-key parser; exact eight-domain set with distinct missing-domain semantics; exact 12 chromosome IDs, 36 core genes and 27 marker IDs; dependency-cycle checks. All changes pass the exact-SHA verification run.
- **A3.3:** VERIFIED — RFC 8785 JCS canonicalization and SHA-256 fingerprint pinned to the approved manifest.
- **A3.4:** IMPLEMENTED — Ed25519 Genesis envelope signing/verification against the configured Owner-controlled trust-root set, with provenance, validity and revocation behavior. Production root provisioning and genesis activation are NOT RUN.
- **A3.5:** VERIFIED — M0–M5 evidence gates and fail-closed tests.
- **A3.6:** VERIFIED — protected Owner-approval authorization requires a verified Genesis token and the pinned embedded Genome.
- **A3.7:** PARTIAL — source commit prefix resolved to full SHA and four representative historical blob IDs matched the A2 register; full 48-artifact blob-by-blob reconciliation has not yet been completed. DNA-045 remains `EXTENSION-REVIEW` by the A2 disposition.
- **A3.8:** VERIFIED — all five automated gates PASS on `046656d602eddadf647895f0e7c9ef24b4bd6749`, workflow run [#42452827086](https://github.com/akefadaka-git/iroka/actions/runs/42452827086), including 55 unit tests and 2 documentation tests. Independent review is waived by the Owner on 2026-11-08 and is not an A3 closure prerequisite.

**Overall A3 status: PARTIAL — implementation and all five automated gates are VERIFIED at the exact implementation SHA. Full 48-artifact historical blob reconciliation remains open. Independent review is waived by the Owner and is not a blocker.**

## Explicitly not performed

- No production private key or trust root created or provisioned.
- No Genesis activation or runtime promotion.
- No deployment.
- PR #13 remains draft and unmerged; A2 PR #12 remains open and unmerged.
- No production security claim is made from unit-test evidence alone.


## Preliminary security hardening (internal pre-review; not an independent review)

A separate adversarial pass over the implementation identified and remediated these issues on the A3 branch:

1. Genome validation previously checked that all eight historical domains were present but did not reject duplicates or extra entries. It now enforces the exact eight-domain set.
2. Marker validation previously checked only count and uniqueness. It now enforces the exact 27 v1.0 marker IDs.
3. Epoch transition used saturating addition, which could accept a non-increment at `u64::MAX`. It now uses checked addition and fails closed on overflow.
4. The public direct trust-bundle installation path did not require non-empty root provenance or validate the root public key before bundle processing. It now rejects missing provenance and invalid root keys.
5. The Rust workflow previously ran `cargo fmt --all` before the formatting check, potentially formatting the checkout before asserting it. The mutating step was removed; CI now checks the committed formatting without modifying it.

These are implementation remediations from an internal review pass. They do not satisfy the independent-review requirement.

## Current verification boundary

- Latest verified implementation SHA: `046656d602eddadf647895f0e7c9ef24b4bd6749`.
- Exact-SHA workflow run [#42452827086](https://github.com/akefadaka-git/iroka/actions/runs/42452827086) — SUCCESS; formatting, locked workspace compilation, production feature gate, 55 unit tests, 2 documentation tests and Clippy all passed.
- The workflow was restored to read-only permissions after the one-time formatting correction. Its push path filter includes this A3 implementation record so subsequent record updates receive CI verification.
- PR #13 remains open and draft; no merge or deployment.
- Full 48-artifact historical blob reconciliation remains outstanding.
- Independent security review is explicitly waived by the Owner on 2026-11-08. This is a governance waiver, not a claim that an independent review occurred.



## Owner governance decision — independent review waiver

On 2026-11-08, the Owner explicitly instructed: "No need for independent review." Accordingly:
- Independent security review is waived as a prerequisite for A3.8 and A3 closure.
- No external reviewer access or review request is required.
- This waiver does not convert internal review into independent review and does not certify the implementation as independently audited.
- Exact-head automated verification and the remaining historical reconciliation evidence are still required for an evidence-complete A3 closure.
- Merge, deployment, production trust-root provisioning and Genesis activation remain separately unauthorized.


## A3.7 — Complete historical artifact blob reconciliation (2026-11-08)

**Disposition: VERIFIED-CLOSED for the A3.7 byte-provenance reconciliation.**

The A2 register was read from `architecture/igacms-a2-owner-approved`. Each of its 48 inventory entries was fetched individually from historical repository `akeayu/iroka` at exact commit `1224bb8298f9ef21d2590dd6e70273501281cd9c`. GitHub's returned Git blob SHA was compared to the corresponding registered blob SHA.

**Result: 48/48 MATCH; 0 MISMATCH; 0 MISSING; 0 UNRESOLVED.** This verifies byte-level Git object identity for the inventoried files at that source commit. It does not assert that historical code is active, safe to promote, or suitable for direct reuse.

| Historical ID | Historical path | A2 registered blob SHA | Observed blob SHA | Result |
|---|---|---|---|---|
| DNA-001 | `src/core/_legacy/dna/dna.ts` | `7206f07941455c976af889884ec873da73349737` | `7206f07941455c976af889884ec873da73349737` | MATCH |
| DNA-002 | `src/core/_legacy/dna/identity-genome.ts` | `38f6b86151d8f85c7a32d9dfbd48c0795cbe4ee3` | `38f6b86151d8f85c7a32d9dfbd48c0795cbe4ee3` | MATCH |
| DNA-003 | `src/core/_legacy/dna/principles.ts` | `1b358313b4d1c7612d9938a150f1b6061ababa1e` | `1b358313b4d1c7612d9938a150f1b6061ababa1e` | MATCH |
| DNA-004 | `src/core/_legacy/dna/invariants.ts` | `012a25088b021036ff14288dc53913b01966ab01` | `012a25088b021036ff14288dc53913b01966ab01` | MATCH |
| DNA-005 | `src/core/_legacy/dna/capabilities.ts` | `867dcc311604e717258e034ab3589b382ff02dce` | `867dcc311604e717258e034ab3589b382ff02dce` | MATCH |
| DNA-006 | `src/core/_legacy/dna/authority.ts` | `a46aec19423a0b2abfc1e7fc6e5f0b36fabae2a5` | `a46aec19423a0b2abfc1e7fc6e5f0b36fabae2a5` | MATCH |
| DNA-007 | `src/core/_legacy/dna/evidence.ts` | `a913d5bdb88c39a5ece6e29591dfd35cf329e862` | `a913d5bdb88c39a5ece6e29591dfd35cf329e862` | MATCH |
| DNA-008 | `src/core/_legacy/dna/assurance.ts` | `3e622b9b5fc442efa6b71720fcf14ff394202614` | `3e622b9b5fc442efa6b71720fcf14ff394202614` | MATCH |
| DNA-009 | `src/core/_legacy/dna/security.ts` | `dc9d7cedc99c5b0eb68d20cf6e458c911cd4996a` | `dc9d7cedc99c5b0eb68d20cf6e458c911cd4996a` | MATCH |
| DNA-010 | `src/core/_legacy/dna/execution.ts` | `8f9db5db279f78b74af36c95a142935fd293bea4` | `8f9db5db279f78b74af36c95a142935fd293bea4` | MATCH |
| DNA-011 | `src/core/_legacy/dna/evolution.ts` | `919e6cfc4f37b5196aac6a4ebfba3970c47e2994` | `919e6cfc4f37b5196aac6a4ebfba3970c47e2994` | MATCH |
| DNA-012 | `src/core/_legacy/dna/validator.ts` | `a6446ea08890da3ea195b1d977d0a9aed0c4ba64` | `a6446ea08890da3ea195b1d977d0a9aed0c4ba64` | MATCH |
| DNA-013 | `src/core/_legacy/dna/fingerprint.ts` | `d3fd1fcfaee32e3a13ca123c3f319ae8df750696` | `d3fd1fcfaee32e3a13ca123c3f319ae8df750696` | MATCH |
| DNA-014 | `src/core/_legacy/dna/registry.ts` | `bed353b724e4adf82e3d707eb793fa880be83656` | `bed353b724e4adf82e3d707eb793fa880be83656` | MATCH |
| DNA-015 | `src/core/_legacy/dna/runtime-guard.ts` | `08110f25282731af107ab11af2aaf4f6d4f4dec7` | `08110f25282731af107ab11af2aaf4f6d4f4dec7` | MATCH |
| DNA-016 | `src/core/_legacy/dna/authorization.ts` | `714faec0d7bc5c704e72101feb069b1857365133` | `714faec0d7bc5c704e72101feb069b1857365133` | MATCH |
| DNA-017 | `src/core/_legacy/dna/admission.ts` | `16bc3c5975950d23f3f0fde6e8b7afe367a613dc` | `16bc3c5975950d23f3f0fde6e8b7afe367a613dc` | MATCH |
| DNA-018 | `src/core/_legacy/dna/audit.ts` | `ef22b347977d2cd0a7a4f30ac72a78a3c408682c` | `ef22b347977d2cd0a7a4f30ac72a78a3c408682c` | MATCH |
| DNA-019 | `src/core/_legacy/dna/knowledge.ts` | `798de6c52a90f5b0ff4ade48cac59bb7aa57b89a` | `798de6c52a90f5b0ff4ade48cac59bb7aa57b89a` | MATCH |
| DNA-020 | `src/core/_legacy/dna/reasoning.ts` | `c29a948508c113e609f5b4e254b540da374ae018` | `c29a948508c113e609f5b4e254b540da374ae018` | MATCH |
| DNA-021 | `src/core/_legacy/dna/orchestration.ts` | `346a98560c0d21276dd2d1074c1e4bd9b789e87b` | `346a98560c0d21276dd2d1074c1e4bd9b789e87b` | MATCH |
| DNA-022 | `src/core/_legacy/dna/subject.ts` | `40c23b5fd022d5bd947bfea6d2ebcd5b0af8112f` | `40c23b5fd022d5bd947bfea6d2ebcd5b0af8112f` | MATCH |
| DNA-023 | `src/core/_legacy/dna/policy.ts` | `1a333e95ebda9701e25c6b489b05191097023087` | `1a333e95ebda9701e25c6b489b05191097023087` | MATCH |
| DNA-024 | `src/core/_legacy/dna/goal.ts` | `47e6af6e9ff9134e451e0fd180eb8a656ad790f0` | `47e6af6e9ff9134e451e0fd180eb8a656ad790f0` | MATCH |
| DNA-025 | `src/core/_legacy/dna/value.ts` | `6f08c8fcd2257587116f4c464a443f262e48f8e1` | `6f08c8fcd2257587116f4c464a443f262e48f8e1` | MATCH |
| DNA-026 | `src/core/_legacy/dna/temporal.ts` | `b0fbdbdd6ecee21b964a580098bf97aec71340fe` | `b0fbdbdd6ecee21b964a580098bf97aec71340fe` | MATCH |
| DNA-027 | `src/core/_legacy/dna/uncertainty.ts` | `44b84bc71f6735fe43c4acd115fc84b1b1b006f0` | `44b84bc71f6735fe43c4acd115fc84b1b1b006f0` | MATCH |
| DNA-028 | `src/core/_legacy/dna/contradiction.ts` | `1587fb402f7a1c05227a4254dcf84dcbfe29dcf8` | `1587fb402f7a1c05227a4254dcf84dcbfe29dcf8` | MATCH |
| DNA-029 | `src/core/_legacy/dna/oversight.ts` | `1d68376bfb2d36195238f459caf6dce50f32b389` | `1d68376bfb2d36195238f459caf6dce50f32b389` | MATCH |
| DNA-030 | `src/core/_legacy/dna/memory.ts` | `8debe3de23b31281db7756e7fa7cace639931a39` | `8debe3de23b31281db7756e7fa7cace639931a39` | MATCH |
| DNA-031 | `src/core/_legacy/dna/learning.ts` | `73eec3bb9ef1c31a0f22d3cc4b227713b89efa44` | `73eec3bb9ef1c31a0f22d3cc4b227713b89efa44` | MATCH |
| DNA-032 | `src/core/_legacy/dna/model-governance.ts` | `220179935acc2ef63c28f4864978d84751482dfd` | `220179935acc2ef63c28f4864978d84751482dfd` | MATCH |
| DNA-033 | `src/core/_legacy/dna/incident.ts` | `83d117c3d946369c46c0f86b6552e1a6106af9a6` | `83d117c3d946369c46c0f86b6552e1a6106af9a6` | MATCH |
| DNA-034 | `src/core/_legacy/dna/amendment.ts` | `57b259ea5cb8a8b08e40647c3e007e8892b49e65` | `57b259ea5cb8a8b08e40647c3e007e8892b49e65` | MATCH |
| DNA-035 | `src/core/_legacy/dna/privacy.ts` | `c8dd7456c20a1ec36715146dece32880fec23b5f` | `c8dd7456c20a1ec36715146dece32880fec23b5f` | MATCH |
| DNA-036 | `src/core/_legacy/dna/notarization.ts` | `e8d16fbaaf6d1ed516ed4f1c87741e54612d1ebb` | `e8d16fbaaf6d1ed516ed4f1c87741e54612d1ebb` | MATCH |
| DNA-037 | `src/core/_legacy/dna/attestation.ts` | `bdf4fd6dd11ca7678078a2b89d65145f482a6d21` | `bdf4fd6dd11ca7678078a2b89d65145f482a6d21` | MATCH |
| DNA-038 | `src/core/_legacy/dna/replay.ts` | `b150c6f205da67fb9f144d706f042c79d3007455` | `b150c6f205da67fb9f144d706f042c79d3007455` | MATCH |
| DNA-039 | `src/core/_legacy/dna/interoperability.ts` | `d42f562cad3e0d04efea0ce56e281e28147988e0` | `d42f562cad3e0d04efea0ce56e281e28147988e0` | MATCH |
| DNA-040 | `src/core/_legacy/dna/sandbox.ts` | `1f25888ecc3088c835aa5db96e40a0bb2bb0bb10` | `1f25888ecc3088c835aa5db96e40a0bb2bb0bb10` | MATCH |
| DNA-041 | `src/core/_legacy/dna/boundary.ts` | `5157d5f2ed1bfae3edb178cc58ef55efae957b72` | `5157d5f2ed1bfae3edb178cc58ef55efae957b72` | MATCH |
| DNA-042 | `src/core/_legacy/dna/observability.ts` | `f521cbdb2098289599481081d3a8501c41d2b466` | `f521cbdb2098289599481081d3a8501c41d2b466` | MATCH |
| DNA-043 | `src/core/_legacy/dna/errors.ts` | `b795dcbbee4533942a0d551ca20600be7551dc3e` | `b795dcbbee4533942a0d551ca20600be7551dc3e` | MATCH |
| DNA-044 | `src/core/_legacy/dna/genesis.ts` | `3e16d2943889eca647a50b568f327261b94f1efd` | `3e16d2943889eca647a50b568f327261b94f1efd` | MATCH |
| DNA-045 | `src/core/_legacy/dna/consensus.ts` | `edd58b38fb2f2098aeea9716d0eba0897a753811` | `edd58b38fb2f2098aeea9716d0eba0897a753811` | MATCH |
| TEST | `src/core/_legacy/dna/dna.validation.spec.ts` | `e3727afb62fb646eb1d1610a85d54936e49e3ac3` | `e3727afb62fb646eb1d1610a85d54936e49e3ac3` | MATCH |
| TEST | `src/core/_legacy/dna/smoke.spec.ts` | `a1c5b655d097be366dcea25fde0bb42e1c43ed1b` | `a1c5b655d097be366dcea25fde0bb42e1c43ed1b` | MATCH |
| TEST | `src/core/_legacy/dna/validator.contract.spec.ts` | `d0e1d390bb2998ff7fdf586c9cfb9f9e81077cb5` | `d0e1d390bb2998ff7fdf586c9cfb9f9e81077cb5` | MATCH |

### A3.7 interpretation and boundaries

- DNA-001 through DNA-044: historical artifacts retained under the A2 dispositions; blob identity confirmed.
- DNA-045: blob identity confirmed; remains `EXTENSION-REVIEW`, outside the DNA-044 genesis sequence. This reconciliation does not promote it into genesis.
- Three historical test specifications: blob identity confirmed; remain `TEST-EVIDENCE-ONLY`, not current test-pass evidence.
- The A2 disposition register was not modified. The historical repository was read only.
- This closes the outstanding 48-artifact provenance comparison only. It does not close production trust-root custody, key provisioning, Genesis activation, runtime promotion, A4 assurance, merge or deployment.

**Supersession:** This dated A3.7 reconciliation section supersedes earlier statements in this record and PR description that the full 48-artifact comparison remained outstanding. Earlier implementation and CI evidence remains subject to its own exact-SHA references.

## A3 phase status after A3.7 reconciliation

- A3.1 — VERIFIED
- A3.2 — VERIFIED
- A3.3 — VERIFIED
- A3.4 — IMPLEMENTED; production trust-root provisioning and Genesis activation NOT RUN
- A3.5 — VERIFIED
- A3.6 — VERIFIED
- A3.7 — VERIFIED-CLOSED for 48/48 Git blob reconciliation
- A3.8 — VERIFIED at exact implementation SHA `bb50271544a04e3c00ee0987ac3237224b3812d1`, workflow run [#42453012427](https://github.com/akefadaka-git/iroka/actions/runs/42453012427), all five gates PASS.

**Overall A3: IMPLEMENTATION WORK PACKAGES VERIFIED; operational trust-root/Genesis steps remain NOT RUN and separately gated.** A4 verification is the next phase. No merge, deployment, production key provisioning or Genesis activation is authorized or performed. The Owner's independent-review waiver dated 2026-11-08 remains in force; no independent review is claimed.


## A4 remediation evidence — Owner approval/revocation atomicity (2026-11-08)

**Finding A4-01: VERIFIED-REMEDIATED.** The previous verification identified a time-of-check/time-of-use gap between preliminary revocation reads and one-time Owner approval consumption.

### Implemented correction

- `SqliteSecurityStore::consume_approval` now opens an SQLite `IMMEDIATE` transaction before checking revocation state.
- Within that same transaction it checks the Owner signing key in `revoked_keys`, checks the approval ID in `revoked_approvals`, inserts the one-time consumption marker, inserts the approval receipt, and commits.
- A competing revocation serializes before or after the consumption transaction. If revocation commits first, consumption fails closed; if consumption commits first, the later revocation is ordered after that authorization decision.
- Revoked-key and revoked-approval outcomes map to `OwnerApprovalError::Revoked`; database failures fail closed; duplicate use remains `OwnerApprovalError::Replay`.

### Regression coverage

Added three tests:
1. `approval_consumption_rechecks_signing_key_revocation_atomically`
2. `approval_consumption_rechecks_approval_revocation_atomically`
3. `concurrent_key_revocation_and_approval_consumption_are_serializable` — uses two independent SQLite connections against one database and races key revocation against approval consumption, asserting only valid serial outcomes.

### Exact-head verification

- Source commits: `c4710a58cd5846bdedd46583ee8095970e1cfdc3`, `5c12ad868d4a9c50419a1cc67c452403b4c59299`, `36d900b76a77242479300c843872ef65e51656df`, `ffc9aafd36a71e4eea613e6bf7e4d51672264c8b`, `753e6fcdb629c6113b01cc428fa0f33a31920e0b`, `bb8ce3dec81dcbd2601658321bea6af9fbe4ffa9`.
- Final code/test SHA: `bb8ce3dec81dcbd2601658321bea6af9fbe4ffa9`.
- Workflow run [#42459388552](https://github.com/akefadaka-git/iroka/actions/runs/42459388552): **SUCCESS**.
- PASS: `cargo fmt --all -- --check`.
- PASS: `cargo check --workspace --all-targets --locked`.
- PASS: `cargo check --workspace --all-targets --no-default-features`.
- PASS: `cargo test --workspace --all-targets --locked` — 58 unit tests and 2 documentation tests; zero failures.
- PASS: `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic`.

**A4-01 disposition: VERIFIED-CLOSED.** This closes the identified approval/revocation TOCTOU finding only. It does not constitute A4 overall closure. Remaining A4 work includes broader trust-lifecycle and adversarial review, audit-chain/external-checkpoint assessment, rollback/failure-path verification and operational boundary confirmation. Production trust-root provisioning and Genesis activation remain NOT RUN and separately gated. No merge or deployment was performed.


## A4 verification assessment — trust lifecycle, audit chain, rollback and failure paths (2026-11-08)

**Assessment baseline:** source tree at parent SHA `a1b92959011c88a7b732f81a40187f2e0667a868`; exact-head workflow run [#42459440729](https://github.com/akefadaka-git/iroka/actions/runs/42459440729) checked out that exact SHA and completed successfully. This assessment is a verification record, not a declaration that A4 is closed.

### A4-01 — Owner approval/revocation atomicity

**VERIFIED-CLOSED.** The SQLite `IMMEDIATE` transaction rechecks signing-key and approval revocation state in the same transaction that inserts the one-time consumption marker and receipt. Three focused regression tests cover both revoked cases and a two-connection key-revocation race. Exact-head CI passed.

### A4-02 — Trust snapshot publication ordering

**OPEN — remediation and regression test required.**

Static review of `TrustSnapshotManager::install` and `install_with_roots` found that each method calls `verify_and_install_trust_bundle*` (including durable monotonic-version persistence) before acquiring the in-memory snapshot write lock. Two concurrent installers can therefore persist version N, then N+1, publish N+1, and subsequently publish the delayed N snapshot. The SQLite high-water mark remains N+1 while the active in-memory trust snapshot can regress to N. Existing tests cover sequential monotonic installation and explicit root overlap, but do not exercise concurrent snapshot publication.

**Required correction:** serialize each manager installation across verification, durable anti-rollback persistence and snapshot replacement (or compare the persisted generation under the publication lock); add a deterministic concurrent regression test proving the active snapshot cannot move behind the durable high-water mark. Do not infer that current sequential tests cover this interleaving.

### A4-03 — Audit-chain integrity and external checkpoint

**LOCAL CHAIN VERIFIED; EXTERNAL ANCHOR NOT IMPLEMENTED.**

`SqliteAuditSink` implements an append-only SQLite event table, SHA-256 hash chaining with domain separation and length-prefixed fields, duplicate event-ID rejection, and verification of previous-hash/event-hash continuity. Update/delete triggers protect ordinary application paths. Exact-head tests passed for append/verify, duplicate IDs, modified-row detection, deleted-row detection, and persistence/reopen.

The source explicitly states that production must externally anchor signed checkpoints. The implemented API exposes only the local sequence/hash head; no signed checkpoint format, external witness/notary publication, remote retention or independent checkpoint verification is present in the inspected implementation. A local attacker able to replace the database or truncate its tail can reconstruct a self-consistent local chain unless a previously published checkpoint is checked.

**Disposition:** local tamper-evidence is VERIFIED; tamper-evident external anchoring is **OPEN / NOT IMPLEMENTED**. Production audit claims must remain bounded until a separately governed checkpoint signer and independent external retention/verification path exist.

### A4-04 — Rollback and failure-path verification

**PARTIAL.**

Verified in source and exact-head tests:
- Trust-bundle installation uses an SQLite `IMMEDIATE` transaction and enforces monotonic versions.
- Same-version/same-digest installation is idempotent; lower versions are rejected; conflicting same-version digests are rejected by the store contract.
- Trust-bundle rollback is covered by `rejects_bundle_version_rollback`; epoch rollback/overflow is covered by the IGACMS conformance test.
- Owner approval consumption is single-use; revoked key/approval is rejected; replay is rejected.
- Signed Owner revocation command effect and command-log insert share one transaction; command replay is rejected.
- Audit append failures prevent a positive authorization result; audit-chain tampering is detected on reopen/verification.
- SQLite uses WAL, FULL synchronous mode, a five-second busy timeout and private file permissions in the file-store test.

Not verified by a dedicated fault-injection test:
- SQLite busy/locked exhaustion, disk-full/I/O failure, commit failure, process termination between transaction operations, WAL recovery under abrupt termination, and concurrent trust snapshot publication.
- The SQLite security store documents itself as a single-node adapter; multi-node deployment requires a shared transactional adapter with equivalent guarantees.

### A4-05 — Operational boundary

**NOT RUN / SEPARATELY GATED.** No production root keys or Owner private keys were created or provisioned; no custody ceremony, production key rotation, Genesis activation, runtime promotion or deployment was performed. Test fixtures and in-memory keys are not production custody evidence. The Owner's independent-review waiver remains in force; no independent review is claimed or required by that waiver.

### Exact-head automated verification evidence

Workflow run [#42459440729](https://github.com/akefadaka-git/iroka/actions/runs/42459440729) checked out exact SHA `a1b92959011c88a7b732f81a40187f2e0667a868`; job `Format, compile, test and lint` completed **SUCCESS**. All steps passed:
1. `cargo fmt --all -- --check`
2. `cargo check --workspace --all-targets --locked`
3. `cargo check --workspace --all-targets --no-default-features`
4. `cargo test --workspace --all-targets --locked` — 58 unit tests + 2 integration/contract tests, zero failures.
5. `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic`

The test log explicitly confirms the audit-chain integrity tests, trust lifecycle tests, rollback tests, approval revocation tests and the two-connection revocation race all passed. These results do not cover the untested interleavings and fault-injection cases listed above.

### A4 disposition at this assessment baseline

| Work package | Status |
|---|---|
| A4-01 approval/revocation atomicity | VERIFIED-CLOSED |
| A4-02 concurrent trust snapshot publication | OPEN |
| A4-03 local audit-chain integrity | VERIFIED |
| A4-03 external signed checkpoint / witness | NOT IMPLEMENTED |
| A4-04 rollback controls | PARTIAL — listed rollback tests PASS |
| A4-04 database/process failure injection | NOT RUN |
| A4-05 operational custody / production activation | NOT RUN; separately gated |

**Overall A4: PARTIAL — NOT CLOSED.** Closure requires resolving A4-02 with a deterministic regression test, implementing or explicitly deferring the externally anchored audit checkpoint through a separate Owner decision, completing the remaining failure-injection coverage, and rerunning the full verification suite against the exact resulting HEAD. No merge, deployment, production key provisioning or Genesis activation is authorized or performed.


## A4-02 remediation and exact-head verification (2026-11-08)

**Finding A4-02: VERIFIED-REMEDIATED.**

### Root cause and correction

The trust snapshot manager previously performed signed-bundle verification and durable anti-rollback persistence before acquiring the in-memory snapshot write lock. Two concurrent manager installations could therefore persist versions in one order and publish snapshots in the reverse order, leaving the durable high-water mark newer than the active in-memory trust snapshot.

The correction adds a manager-wide installation mutex and holds it across the complete operation:
1. Signed-bundle verification and durable monotonic-version persistence.
2. Acquisition of the active snapshot write lock.
3. Publication of the verified immutable snapshot.

Both `install` and `install_with_roots` use the same serialized path. Lock poisoning fails closed with `TrustBundleError::StoreUnavailable`.

### Regression tests added

1. `concurrent_snapshot_installation_serializes_persistence_and_publication` — deterministically pauses the first installation after its durable version-2 write and before snapshot publication. A second installation is shown unable to enter its verification/persistence closure until the first publishes. The final durable high-water mark is version 3 and the active snapshot accepts the version-3 key while rejecting the version-2 key.
2. `poisoned_installation_lock_fails_closed_without_persisting_or_publishing` — proves a poisoned installation mutex rejects a new install, leaves the durable version unchanged, and leaves the prior active snapshot intact.
3. `rollback_rejection_leaves_active_snapshot_unchanged` — proves a lower-version bundle is rejected without replacing the active snapshot or changing the durable high-water mark.

### Exact-head verification

- Implementation commits: `39f671036c70f7ac1d43344b188264b6a76ecc48`, `755b35d0c2506a269314fc2d790d3a60a40de4e2`, `7caaf18211107b383728653b4699eb0352983f5f`.
- Exact source SHA checked out by successful workflow: `7caaf18211107b383728653b4699eb0352983f5f`.
- Workflow run [#42460964752](https://github.com/akefadaka-git/iroka/actions/runs/42460964752): **SUCCESS**.
- PASS: `cargo fmt --all -- --check`.
- PASS: `cargo check --workspace --all-targets --locked`.
- PASS: `cargo check --workspace --all-targets --no-default-features`.
- PASS: `cargo test --workspace --all-targets --locked` — 61 unit tests + 2 contract tests; zero failures.
- PASS: `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic`.

An earlier CI attempt at `755b35d0c2506a269314fc2d790d3a60a40de4e2` stopped at the formatting gate. Formatting was corrected in `7caaf18211107b383728653b4699eb0352983f5f`; the successful run above checked out that corrected exact SHA.

### Scope boundary and A4 disposition

- A4-02 is **VERIFIED-CLOSED**.
- Local audit-chain integrity remains verified. External signed checkpointing, witness publication and independent retention remain **NOT IMPLEMENTED / SEPARATELY GOVERNED**, and were not introduced by this remediation.
- SQLite busy/locked exhaustion, disk-full/I/O injection, commit failure and abrupt process/WAL recovery remain **NOT RUN**.
- Production trust-root provisioning, Owner key custody, Genesis activation, runtime promotion and deployment remain **NOT RUN** and separately gated.
- No merge or deployment was performed.

**Overall A4 remains PARTIAL — NOT CLOSED.** This change closes the identified trust snapshot publication race and adds deterministic concurrency and failure-path regression coverage; it does not close the separately scoped external audit checkpoint or remaining database/process fault-injection work.


## A4-04 database and process failure-injection verification (2026-11-08)

**A4-04 targeted SQLite failure paths: VERIFIED for the scenarios below.** The tests exercise fail-closed behavior and transactional rollback; they do not imply hardware-level fault certification.

### Added regression tests

File: \`crates/iroka-kernel/src/security_store.rs\`

1. \`busy_lock_exhaustion_fails_closed_without_partial_trust_write\`
   - Holds a competing \`BEGIN IMMEDIATE\` transaction on a second SQLite connection until the configured five-second busy timeout is exhausted.
   - The trust installation returns \`SecurityStoreError::Unavailable\`; no trust high-water mark or history row is committed.
2. \`sqlite_page_limit_disk_full_fails_closed_without_advancing_trust_state\`
   - Uses SQLite \`PRAGMA max_page_count\` to reach the engine's \`SQLITE_FULL\` condition while growing the trust history table.
   - A subsequent trust installation fails closed; its state update is rolled back and the pre-existing history count remains unchanged.
3. \`injected_storage_write_failure_rolls_back_all_trust_state\`
   - An injected SQLite trigger aborts the history insert after the state-row write.
   - The operation returns unavailable and the transaction leaves no partially advanced trust state.
4. \`deferred_constraint_commit_failure_rolls_back_trust_state\`
   - A deferred foreign-key violation is injected by a trigger and surfaces at transaction commit.
   - Commit failure is mapped to unavailable and neither trust state nor history is partially committed.
5. \`abrupt_process_exit_recovers_wal_without_uncommitted_trust_state\`
   - A child test process exits immediately after writing trust state and history inside an uncommitted \`IMMEDIATE\` transaction.
   - Reopening the database performs WAL recovery; the uncommitted version and history row are absent.

### Exact-head verification

- Test implementation commits: \`88b2133a550ef85d6ae427ebf300b91086452201\`, \`d24d00283a93c464954bfdf3252e3a2324510f62\`, \`845724cd26818f1001fa96265e03ada340f4e5bd\`, \`7bb57b13ee4b0927ce9124cd7553ac09c113c682\`, \`c4b5408618122fc868cd43b3bc127c8034e42d24\`.
- Exact code/test SHA: \`c4b5408618122fc868cd43b3bc127c8034e42d24\`.
- Workflow run [#42462303853](https://github.com/akefadaka-git/iroka/actions/runs/42462303853): **SUCCESS**; checked out the exact code/test SHA above.
- PASS: \`cargo fmt --all -- --check\`.
- PASS: \`cargo check --workspace --all-targets --locked\`.
- PASS: \`cargo check --workspace --all-targets --no-default-features\`.
- PASS: \`cargo test --workspace --all-targets --locked\` — **66 unit tests + 2 contract tests; zero failures**.
- PASS: \`cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic\`.
- The five new failure-path tests all passed, including SQLite busy timeout, \`SQLITE_FULL\`, injected write abort, deferred commit failure and abrupt child-process termination/WAL recovery.

### Boundaries and disposition

- A4-04 is **VERIFIED for the explicit SQLite busy/locked, SQLite page-limit disk-full, transactional write-abort, deferred commit-failure and abrupt-process/WAL-recovery scenarios tested above**.
- This is deterministic SQLite-level fault injection. It is not evidence of physical storage-device failure, host power loss, filesystem corruption or every possible I/O error mode; those remain outside this test harness.
- A4-01 approval/revocation atomicity remains **VERIFIED-CLOSED**.
- A4-02 trust snapshot publication ordering remains **VERIFIED-CLOSED**.
- A4-03 local audit-chain integrity remains **VERIFIED**. External signed checkpointing, witness publication and independent retention remain **NOT IMPLEMENTED / SEPARATELY GOVERNED**; no checkpoint implementation was added.
- A4-05 operational custody, production trust-root provisioning, Genesis activation, runtime promotion and deployment remain **NOT RUN / SEPARATELY GATED**.
- No merge or deployment was performed.

**Overall A4 remains PARTIAL — NOT CLOSED.** The targeted A4-04 database/process fault scenarios are now covered and pass exact-head CI. The external checkpoint and operational activation work remain separate Owner-governed decisions.


## Consolidated A4 closure package index (2026-11-08)

The authoritative consolidated assessment is now maintained in [IGACMS A4 Consolidated Closure Package](IGACMS-A4-CONSOLIDATED-CLOSURE-PACKAGE.md).

- Package creation commit: `559710c4c9b8f963b340a8120b0ff2b5706a3bc8`.
- A4-01 approval/revocation atomicity: VERIFIED-CLOSED.
- A4-02 trust snapshot publication ordering: VERIFIED-CLOSED.
- A4-03 local audit chain: VERIFIED; external signed checkpoint/witness/retention: NOT IMPLEMENTED and requires a separate Owner decision.
- A4-04 enumerated SQLite busy-lock, disk-full, write-abort, deferred commit-failure and abrupt-process/WAL-recovery scenarios: VERIFIED at code/test SHA `c4b5408618122fc868cd43b3bc127c8034e42d24`, workflow [#42462303853](https://github.com/akefadaka-git/iroka/actions/runs/42462303853), 66 unit tests + 2 contract tests, zero failures.
- A4-05 production custody, production trust-root provisioning, Genesis activation, runtime promotion and deployment: NOT RUN; separately Owner-gated.
- Overall A4 remains **PARTIAL — NOT CLOSED**. The package is an evidence consolidation, not merge or deployment authorization.
- Final package/index documentation HEAD requires its own exact-head workflow verification; no pass is claimed until that run succeeds.
