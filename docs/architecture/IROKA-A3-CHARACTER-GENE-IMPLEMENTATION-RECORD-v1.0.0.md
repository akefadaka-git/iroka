# A3 Character Gene Implementation — Initial Record

**Stage:** A3 — implementation authorized by Owner  
**Branch:** `implementation/a3-character-genome-v1`  
**Parent A2 head:** `5916cab5d56162e7b666c5d67def6e2e2b5df806`  
**Frozen gene IO source:** `architecture/genesis-gene-contract-amendment-proposal`  
**Frozen gene IO commit:** `8e4a8b5582d47d430539ae7b56aac75f0991c8a4`

## Scope and invariants

- Preserve exactly 12 chromosomes and 36 existing genes.
- Implement only the approved A2 semantic gaps and their mapped schema/conformance changes.
- Preserve the A2 branch and frozen gene IO source; all A3 changes remain isolated on this implementation branch.
- No contract may grant authority or permit protected execution by itself.
- Unknown, missing, stale, replayed or conflicting evidence fails closed.
- No merge or deployment is authorized.

## A3 work packages

1. Schema and contract amendments mapped to each approved semantic gap.
2. Shared version-bound evidence enforcement across all 36 input/output gene schemas.
3. Owner approval, delegation, revocation and rollback boundary enforcement.
4. Executable positive, negative, boundary and adversarial conformance tests.
5. Exact-head regression/security verification and final pre-deployment independent assessment evidence.
6. A3 evidence and closure report.

## First implementation increment

The A3 branch imports the 72 read-only schema baselines from the frozen gene IO commit without changing their contents and adds a deterministic static reconciliation test. This makes the schema inputs and A2 traceability locally inspectable before applying gene-specific amendments.

**Initial status:** schema baseline import prepared; gene-specific amendments pending; runtime conformance NOT RUN; final integrated independent assessment DEFERRED UNTIL PRE-DEPLOYMENT; merge NOT AUTHORIZED; deployment NOT AUTHORIZED.

## Acceptance gates

- All 72 schema IDs, required fields, properties, closed-object rules and local references reconcile to the A2 inventory.
- Every gene has exactly one positive and one negative case mapped to its exact contract and review.
- All approved semantic gaps are addressed by explicit schema/implementation behavior and adversarial tests.
- The 12/36 genome invariant remains unchanged.
- Exact-head tests pass; unresolved high/critical findings are zero or explicitly Owner-accepted.

## Exact-head CI evidence — initial increment

**Tested head:** `c2c5f9d4e9f0e00bd99386c5797320913e376cc5`  
**Workflow:** Rust kernel verification, run `43851995795`  
**Result:** PASS (completed 2026-11-16)

- `cargo fmt --all -- --check`: PASS
- `cargo check --workspace --all-targets --locked`: PASS
- `cargo check --workspace --all-targets --no-default-features`: PASS
- `cargo test --workspace --all-targets --locked`: PASS — 71 unit tests and 2 integration/contract tests; 0 failures
- `python3 scripts/a3_schema_baseline_audit.py`: PASS — 12 chromosome scope assertion, 36 contracts, 72 schemas, 72 conformance cases, 36 review records, required version-bound evidence in 72/72 schemas, local references resolved, case mapping PASS
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic`: PASS

This verifies the imported baseline and existing Rust kernel tests only. It does **not** establish that the 36 gene-specific semantic amendments, stronger evidence semantics, or all 72 character conformance scenarios are implemented or executed.

## G12 rollback-guard — A3 implementation increment

**Implemented code head:** `7256107e81e2697f478f9af1a98998f8db6944a1`  
**Workflow:** [Rust kernel verification run #1659](https://github.com/akefadaka-git/iroka/actions/runs/43901502640) — **PASS**

The original A2 v1.0.0 input/output schema files remain unchanged. Additive A3 v1.1.0 schemas and ten gene-specific conformance vectors are under `igacms/schemas/a3/genes/` and `docs/architecture/a3/`.

Implemented in this increment:
- Non-negative epoch and floor domain in the A3 schema.
- SHA-256 over RFC 8785 JCS canonical artifact bytes; current and candidate digests are recomputed.
- Exact binding of provenance and version-bound evidence to current state, candidate state, revocation-floor revision and policy version.
- A typed evidence-verifier boundary; invalid, stale, missing, replayed or mismatched evidence denies.
- Existing signed Owner approval verifier reused for one-time rollback approval, scoped to a canonical transition commitment that includes the explicit rollback reason.
- Candidate below the verified revocation floor is denied before Owner approval is checked or consumed.
- Same-epoch/different-digest conflict is denied.
- Denial preserves verified current state only when it is at/above the floor; otherwise effective state is unresolved.
- Canonical decision envelope and reproducible SHA-256 guard digest.
- Serialized output fields checked against the A3 v1.1.0 output shape.

### Exact-head verification

At tested code head `829c565d6a4a124bb6db0a8aa86463f8bca0666f`:
- Formatting: PASS
- Workspace compile: PASS
- No-default-features compile: PASS
- Rust unit tests: **102 passed, 0 failed**
- Integration/contract tests: **2 passed, 0 failed**
- Static A2/A3 schema and traceability audit: PASS
  - 12 chromosome scope assertion
  - 36 gene contracts
  - 72 frozen A2 schemas
  - 72 A2 conformance cases
  - 36 A2 review records
  - version-bound evidence inventory 72/72
  - G12 A3 v1.1.0 schema and ten-vector static audit PASS
- Clippy: PASS

All ten G12 catalog vectors have runtime coverage and PASS: `RG-A3-P01`, `RG-A3-P02`, `RG-A3-N01`, `RG-A3-N02`, `RG-A3-N03`, `RG-A3-N04`, `RG-A3-N05`, `RG-A3-N06`, `RG-A3-B01`, and `RG-A3-B02`.

### Production evidence verification

The production `Ed25519RollbackEvidenceVerifier` adapter is implemented. It verifies Ed25519 signatures against the credential verifier's signed trust snapshot, enforces subject-specific issuer allowlists, checks live key revocation, consumes evidence nonces durably in SQLite, and advances a persistent monotonic revocation-floor high-water mark. Tests cover signature acceptance, unauthorized issuer rejection, invalid signatures, expired receipts, key revocation, nonce replay, concurrent single-use nonce consumption, nonce expiry cleanup and floor rollback. The exact-head run also confirms all ten G12 rollback-guard catalog vectors pass. Application-level provisioning of the signed trust snapshot and subject issuer policy, multi-node transactional storage, and independent security review remain deployment gates. This is **kernel implementation and CI verified**, not production deployment authorization.

Independent external security review: DEFERRED TO ONE INTEGRATED PRE-DEPLOYMENT ASSESSMENT under Owner Directive OD-2026-11-17-IR-01. It is not an A3 implementation-step blocker.  
A3 overall: IN PROGRESS.  
Merge: NOT AUTHORIZED. Deployment: NOT AUTHORIZED.

## G12 version-lineage — A3 runtime evaluator increment

**Tested code head:** `0d630178807ceabc3e189a5d935395020b2da349`  
**Workflow:** [Rust kernel verification run #1665](https://github.com/akefadaka-git/iroka/actions/runs/43902351760) — **PASS**

Implemented:
- Read-only `evaluate_version_lineage` with canonical MAJOR.MINOR.PATCH parsing and SHA-256/RFC 8785 JCS artifact digest recomputation.
- One canonical GENESIS tuple and strict non-root parent version/digest pairing.
- Registry resolution contract that rejects unknown, ambiguous, unavailable and inconsistent results.
- Oldest-to-candidate ancestry verification, exact parent links, duplicate/cycle detection and strictly increasing SemVer/epoch progression.
- Immutable mutation record checks for exact source/target versions and digests, approval, gates and approval commitment.
- Candidate, every ancestor, mutation record and registry snapshot evidence bindings; version, digest, epoch and registry revision are committed.
- Subject-specific issuer policy supports constrained dynamic lineage evidence subjects.
- Derived `linked`/`epoch_monotonic` flags and deterministic versioned lineage digest; no mutation or authority effects.

### Exact-head verification
- Rust unit tests: **102 passed, 0 failed**
- Integration/contract tests: **2 passed, 0 failed**
- Formatting, workspace compile, no-default-features check, static schema/traceability audit and Clippy: PASS
- Static audit: 12 chromosomes, 36 genes, 72 frozen A2 schemas, 72 A2 cases, 36 closed reviews, version-bound evidence 72/72, G12 rollback-guard 10 vectors, G12 version-lineage 12 vectors.

All 12 version-lineage vectors have unit-test coverage and PASS using a static test registry and test evidence verifier. Production Ed25519 evidence verification is separately implemented and tested, including dynamic subject issuer patterns. A read-only SQLite-backed `VersionLineageRegistry` adapter is implemented in `SqliteSecurityStore`. It resolves the candidate, ancestry, immutable mutation record and registry revision from one deferred read transaction, so the evaluator sees a consistent database snapshot; unknown versions, cycles, malformed ancestry, missing mutation records and storage failures fail closed. Adapter tests cover valid immutable ancestry/mutation resolution, registry revision, unknown versions and cyclic ancestry. The evaluator's 12 conformance vectors remain unit-tested and PASS. However, a governed registry provisioning/write pipeline, signed registry snapshot publication, operational persistence/recovery tests and production application wiring remain outstanding. The adapter is implemented; operational provisioning and deployment integration are not yet complete.

G12 version-lineage A3 status: **IMPLEMENTED / UNIT-TESTED / PRODUCTION-ADAPTER-PENDING**.  
Independent external security review: NOT RECEIVED.  
Merge and deployment: NOT AUTHORIZED.
