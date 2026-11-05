# A2/A4 Executable Verification Results

**Record:** IROKA-A2-A4-VERIFY-003  
**Date:** 2026-11-05  
**Repository:** `akefadaka-git/iroka`  
**Branch:** `fix/a2-trust-concurrency-workflow`  
**Verified code SHA:** `d7a7e9d8f9736e6145457103470c0070d2851112`  
**Controlling A2 baseline:** `8709a710a96f102faa181726ddc853f1e94a933e`

## Result

**GitHub Actions run #78: SUCCESS**

- Run ID: `41983074683`
- URL: https://github.com/akefadaka-git/iroka/actions/runs/41983074683
- Event: `push`
- Runner label: `ubuntu-24.04`
- Exact checked-out commit: `d7a7e9d8f9736e6145457103470c0070d2851112`
- Rust: `rustc 1.85.1 (4eb161250 2025-03-15)`
- Cargo: `cargo 1.85.1 (d73d2caf9 2024-12-31)`
- Workflow token permissions reported by runner: `Contents: read`, `Metadata: read`.

## Job steps

| Step | Result |
|---|---|
| Checkout exact SHA | PASS |
| Install pinned Rust 1.85.1 | PASS |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --locked --workspace --all-targets` | PASS |
| `cargo check --locked --workspace --all-targets --no-default-features` | PASS |
| Negative non-test build with `dev-no-revocations` | PASS — compilation rejected with the expected diagnostic |
| `cargo test --locked --workspace --all-targets` | PASS |
| `cargo clippy --locked --workspace --all-targets --no-default-features -- -D warnings -A clippy::pedantic` | PASS |

## Test totals

- Unit tests: **43 passed, 0 failed, 0 ignored**.
- Integration/contract tests: **2 passed, 0 failed, 0 ignored**.
- Total: **45 passed, 0 failed, 0 ignored**.

The passing unit-test output explicitly includes:
- `security_store::tests::owner_revocation_is_rechecked_inside_approval_and_command_transactions`
- `trust_lifecycle::tests::concurrent_installs_never_publish_below_the_durable_or_active_version`

These are regression tests executed on the exact SHA above, not merely source-inspection claims.

## First-run failure and correction

The first push-triggered run (#77, SHA `dff04641a619b66ca8cd503c9e280039b6101f00`) failed at the formatting gate because the newly added revocation regression test had one rustfmt layout difference. All subsequent steps were skipped in that run.

The test formatting was corrected in `security_store.rs`, producing the verified code SHA `d7a7e9d8f9736e6145457103470c0070d2851112`. Run #78 then passed all steps above. No source behavior change was made to resolve that formatting-only failure.

## Exact verified source blob SHAs

| Path | Blob SHA at verified code SHA |
|---|---|
| `crates/iroka-kernel/src/trust_lifecycle.rs` | `764f8d23aa2e30d511c1b4562ec03e24441167ce` |
| `crates/iroka-kernel/src/security_store.rs` | `de2f90d9160b07f0f80e30c252dd010470fcaaee` |
| `crates/iroka-kernel/src/owner_approval.rs` | `2cdc4292caf8a9bcef7666b5e745c1d6cc2b0aca` |
| `.github/workflows/rust-kernel.yml` | `3551fba3b61f46c25606addbb4246cc2a5d8aed4` |
| `rust-toolchain.toml` | `b8a736cea6165501dec29fc8cc9d3b5c1fc02337` |

## Branch and main disposition

At the verified code SHA, the branch comparison against the controlling A2 baseline was:
- 12 commits ahead
- 0 commits behind
- 8 changed paths

The extra push trigger is restricted to `fix/a2-trust-concurrency-workflow` and retains read-only permissions. It exists so this branch can execute verification without paid browser automation or a broad PR into `main`.

The `main` ref remained identical to `143311a655be68acea2700650b7f88c9fb085526` when independently compared.

## Gate status

- K-02 Owner-key revocation race: **SOURCE FIX + REGRESSION TEST VERIFIED**.
- K-03 trust snapshot publication race: **SOURCE FIX + CONCURRENCY REGRESSION TEST VERIFIED**.
- W-01 workflow write permission: **VERIFIED READ-ONLY**.
- W-02 locked dependencies and pinned Rust toolchain: **VERIFIED BY WORKFLOW**.
- W-03 development bypass release guard: **VERIFIED BY NEGATIVE BUILD CHECK**.
- A4 Rust CI verification: **PASS** for exact SHA above.
- K-04 independent audit anchoring: **OPEN**.
- Native microkernel, native platforms, IR/VM, INL, bilateral VYRAQON interoperability, canonical interchange, regional runtime profile conformance, hardware/bare-metal qualification and full 40-case system assurance: **OPEN / NOT VERIFIED**.

**A2 remains PARTIAL and is not closed.** The three requested corrections are now executable-verified, but the remaining architecture and assurance gaps listed above still prevent A2 closure and production-readiness claims.

No merge or deployment was performed. `main` remains unchanged.
