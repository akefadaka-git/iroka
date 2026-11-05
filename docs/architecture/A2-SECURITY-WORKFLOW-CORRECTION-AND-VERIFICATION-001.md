# A2 Technical Correction and Verification Addendum

**Contract ID:** IROKA-A2-RECON-EVIDENCE-002  
**Version:** 1.0.0  
**Snapshot date:** 2026-11-05  
**Repository:** `akefadaka-git/iroka`  
**Working branch:** `fix/a2-trust-concurrency-workflow`  
**Implementation head before this report:** `24a0a1a64e0894457b9e94649ce1ace80d1a00ae`  
**Controlling A2 baseline:** `8709a710a96f102faa181726ddc853f1e94a933e`  
**Main baseline:** `143311a655be68acea2700650b7f88c9fb085526`

## 1. Scope and authority

This addendum records the Owner-authorized corrections to the two trust/concurrency findings and the Rust workflow write-permission finding, plus source-level verification of the exact resulting Git objects.

The work was isolated to `fix/a2-trust-concurrency-workflow`. The A2 baseline and `main` were not modified. No pull request was opened, no branch was merged, no branch was deleted, and no deployment was performed.

The nine Owner architecture decisions OD-01 through OD-09 remain approved by the separate approval record. Those decisions do not constitute A2 closure or production approval.

## 2. Exact branch comparison

The correction branch is exactly 9 commits ahead and 0 behind the controlling A2 baseline:

- Base: `8709a710a96f102faa181726ddc853f1e94a933e`
- Head before this addendum: `24a0a1a64e0894457b9e94649ce1ace80d1a00ae`
- Comparison: `ahead`, 9 ahead, 0 behind.
- Changed paths: 7.

The main ref was independently compared with the known main baseline and was identical:

- `main`: `143311a655be68acea2700650b7f88c9fb085526`
- Comparison result: identical, 0 ahead, 0 behind.

## 3. Corrections applied

### K-02 — Owner-key revocation TOCTOU

**Implementation status: SOURCE CORRECTION PRESENT; RUNTIME VERIFICATION NOT RUN.**

The security-store transaction now rechecks the Owner signing key's revocation state inside the same SQLite `IMMEDIATE` transaction that:
- consumes and persists an Owner approval; or
- records a signed security command and applies its revocation effect.

Approval consumption also rechecks approval revocation inside that transaction. A revoked signer returns the explicit `SecurityStoreError::Revoked`, mapped to `OwnerApprovalError::Revoked`. The earlier preflight checks remain as early rejection, but are no longer the final security boundary.

A regression test covers revoked signer rejection for both approval consumption and signed security-command application and asserts that neither receipt nor command/effect is committed.

### K-03 — Trust snapshot publication race

**Implementation status: SOURCE CORRECTION PRESENT; RUNTIME VERIFICATION NOT RUN.**

`TrustSnapshotManager` now holds its write lock across:
1. active-version comparison;
2. bundle signature and payload validation;
3. durable anti-rollback persistence; and
4. active snapshot publication.

The manager tracks its active bundle version and rejects publication of a version older than the active version. The durable store continues to enforce monotonic version installation. Both direct-root and root-set installation paths use the same serialized publication boundary.

A concurrent-install regression test starts version 2 and version 3 installation concurrently and asserts that the active snapshot and durable store both end at version 3.

### W-01 — Workflow write authority

**Implementation status: SOURCE CONFIGURATION PRESENT; WORKFLOW EXECUTION NOT VERIFIED.**

The Rust workflow now declares only `contents: read`. It no longer:
- regenerates `Cargo.lock`;
- applies formatting as a mutating step;
- commits formatting changes; or
- pushes to a pull-request branch.

Checkout also has `persist-credentials: false`. Formatting is check-only.

### W-02 — Reproducible verification inputs

**Implementation status: IMPROVED; HOSTED RUNNER IMAGE STILL MUTABLE.**

- Rust toolchain pinned to 1.85.1 in `rust-toolchain.toml`.
- Runner pinned to `ubuntu-24.04` rather than `ubuntu-latest`.
- Cargo check, test and Clippy use `--locked`.
- Lockfile regeneration removed.

The GitHub-hosted `ubuntu-24.04` image is still maintained and updated by GitHub; this is not a fully immutable runner image. A pinned container image or controlled self-hosted runner would be required for stronger environment reproducibility.

### W-03 — Development-only revocation bypass

**Implementation status: RELEASE GUARD PRESENT; NEGATIVE BUILD TEST NOT RUN.**

Non-test builds that enable `dev-no-revocations` now fail at compile time with the explicit diagnostic:
`dev-no-revocations is restricted to test builds`.

The workflow includes a negative build check that requires this exact diagnostic. The check has not executed because the workflow could not be dispatched during this verification session.

### K-01 — Crate role classification

**Implementation status: SOURCE DESCRIPTION CORRECTED.**

The Rust crate documentation and package description now identify the crate as a trusted authorization/trust service foundation, not as a completed native microkernel. This is a classification correction; it does not implement the missing native microkernel.

## 4. Exact file blob SHAs

The following blobs were fetched again from the correction branch after the source updates:

| Path | Blob SHA |
|---|---|
| `crates/iroka-kernel/src/trust_lifecycle.rs` | `764f8d23aa2e30d511c1b4562ec03e24441167ce` |
| `crates/iroka-kernel/src/security_store.rs` | `cbc496fda934afcae8e115c84b0c405bd5c3202b` |
| `crates/iroka-kernel/src/owner_approval.rs` | `2cdc4292caf8a9bcef7666b5e745c1d6cc2b0aca` |
| `crates/iroka-kernel/src/lib.rs` | `135d8de172faaf38eed33eee29d17be3d3eed3c6` |
| `crates/iroka-kernel/Cargo.toml` | `b60954954431768c7452b50416a22745a7636ecf` |
| `.github/workflows/rust-kernel.yml` | `587e80e7afcc470a321e1235eb3731cf4134f9e2` |
| `rust-toolchain.toml` | `b8a736cea6165501dec29fc8cc9d3b5c1fc02337` |

## 5. Verification evidence

| Check | Status | Evidence |
|---|---|---|
| Correction branch exists | PASS | GitHub branch read-back |
| Exact correction branch comparison | PASS | 9 ahead / 0 behind from A2 baseline |
| Main unchanged | PASS | Main equals `143311a655be68acea2700650b7f88c9fb085526` |
| Changed file SHA read-back | PASS | Seven exact blob SHAs above |
| Trust publication serialization inspected | PASS | Write lock spans version check, durable install and publication |
| Owner revocation transaction boundary inspected | PASS | Revocation queries execute inside `IMMEDIATE` transactions |
| Workflow write permission removed | PASS | Workflow declares `contents: read`; no push/commit steps |
| Rust toolchain and locked commands inspected | PASS | Exact workflow and toolchain file read-back |
| Development feature release guard inspected | PASS | Compile-time guard and exact-diagnostic negative check present |
| Rust formatting check | NOT RUN | No workflow execution |
| Cargo check | NOT RUN | No workflow execution |
| Unit/contract tests, including new concurrency regressions | NOT RUN | No workflow execution |
| Clippy | NOT RUN | No workflow execution |
| Negative development-feature build | NOT RUN | No workflow execution |
| GitHub combined status on implementation head | UNKNOWN / NO STATUS ENTRIES | Status query returned an empty list |
| Workflow runs associated with implementation head | NONE FOUND | Commit workflow-run query returned an empty list |
| Native hardware / bare-metal boot | NOT RUN | No target hardware evidence |

### CI dispatch limitation

A manual workflow dispatch was attempted through the available authenticated browser-runner service. The service did not start the run because its wallet balance was `-$0.04`. No GitHub Actions run was created. This is an execution limitation, not a passing or failing Rust result.

## 6. Remaining A2 gaps — explicitly open

The following gaps are not closed by these corrections:

1. **K-04 — Independent audit anchoring:** externally signed, independently retained checkpoints and tamper testing against full database rewrite/reconstruction remain unimplemented. The separate security-command log still requires an independently protected integrity mechanism.
2. **Native microkernel (OD-01):** boot chain, HAL, scheduler, address-space/process isolation, kernel IPC, capability handles, driver isolation, resource enforcement and recovery remain absent from the inspected Rust crate.
3. **IROKA Intermediate Representation / VM (OD-02):** typed deterministic IR and capability-restricted VM implementation/conformance remain absent.
4. **Native platforms (OD-03):** x86_64 and AArch64 native backends, boot qualification and hardware-specific evidence remain absent.
5. **INL (OD-04/OD-05):** executable language/compiler/verifier/bootstrap and conformance evidence remain absent.
6. **VYRAQON interoperability (OD-06):** IROKA-side specifications exist, but bilateral interoperability against a separately versioned VYRAQON release is not verified.
7. **Canonical interchange (OD-07):** signed deterministic CBOR envelope, JSON diagnostics and byte-preservation implementation are not evidenced in the inspected crate.
8. **Regional runtime profiles (OD-08):** the Amharic-first Ethiopia and independent African profile contracts exist, but runtime locale/calendar/identity/document/knowledge profile conformance is not established.
9. **Assurance (OD-09):** exact-SHA CI, reproducible provenance, external audit anchoring, and the complete conformance suite have not run. The existing 40-case conformance catalog remains NOT RUN.
10. **Production trust provisioning:** live Owner/trust-root key provisioning, HSM/offline ceremony evidence, multi-node transactional guarantees and operational recovery evidence remain outstanding.

These are architecture or operational evidence gaps, not reasons to mislabel the three corrected source findings as still unmodified. They prevent A2 closure and all production-readiness claims.

## 7. Gate disposition

- K-02 source correction: IMPLEMENTED / NOT RUNTIME-VERIFIED.
- K-03 source correction: IMPLEMENTED / NOT RUNTIME-VERIFIED.
- W-01 workflow permission correction: IMPLEMENTED / NOT WORKFLOW-VERIFIED.
- W-02 reproducibility improvement: IMPLEMENTED / PARTIAL (hosted runner image mutable).
- W-03 release guard: IMPLEMENTED / NOT BUILD-VERIFIED.
- K-01 crate classification: CORRECTED.
- K-04 audit anchoring: OPEN.
- Native kernel / IR / INL / VYRAQON / regional runtime / conformance: OPEN or NOT VERIFIED as detailed above.

**A2 status: PARTIAL — NOT CLOSED.**  
**A3 source corrections: committed on the isolated correction branch.**  
**A4 exact-SHA source inspection: PASS.**  
**A4 executable verification: NOT RUN.**  
**Main: unchanged.**  
**Merge: NOT AUTHORIZED / NOT PERFORMED.**  
**Deployment: NOT AUTHORIZED / NOT PERFORMED.**

The next evidence gate is to run the workflow on this exact correction branch head, inspect every job result, and repair any failures against the resulting exact SHA before considering A2 closure.
