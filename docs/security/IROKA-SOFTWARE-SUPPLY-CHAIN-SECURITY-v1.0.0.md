# IROKA Software Supply-Chain Security Baseline v1.0.0

**Status:** A3.10.5 implementation baseline  
**Deployment:** Not authorized  
**CI execution:** Pending workflow activation on the protected default branch or authorized manual dispatch

## 1. Objective

Establish a reproducible, read-only security gate for dependency integrity, known vulnerabilities, license policy, source provenance, unsafe-code policy and repository secret scanning. The gate uses public/free tooling and requires no repository secrets, paid CI minutes, private registry or external deployment credentials.

## 2. Repository dependency inventory

The exact `Cargo.lock` at the A3.10 baseline was fetched and parsed:
- Blob SHA: `ad864ae2b098c1cdea7a81d2d2fc8cdcf9fddf63`
- 62 locked package records.
- 61 external packages plus the `iroka-kernel` workspace package.
- 0 Git-sourced dependencies.
- 0 non-crates.io registry sources.
- All external packages resolve from the canonical crates.io index.
- Two versions of `syn` are present: 2.0.119 and 3.0.9. The initial duplicate-version policy reports this as a warning pending dependency-graph review; wildcard dependencies are denied.

The lockfile is committed and all security/build workflows use `--locked` for Cargo resolution.

## 3. Pinned toolchain and scanner versions

- Rust toolchain: 1.100.0, minimal profile, with rustfmt and Clippy.
- RustSec cargo-audit: 0.23.0, installed with `--locked`.
- cargo-deny: 0.20.2, installed with `--locked`.
- Gitleaks: 8.30.1, installed at an exact Go module version.
- GitHub checkout action: `actions/checkout` v7.0.1, pinned to commit `3d3c42e5aac5ba805825da76410c181273ba90b1`.

The Rust workspace declares `unsafe_code = "forbid"` and the kernel crate opts into workspace lints. This prevents new unsafe Rust blocks unless the policy is explicitly changed and reviewed.

## 4. Dependency and license policy

`deny.toml`:
- Denies wildcard dependency requirements.
- Warns on multiple versions so duplicate dependencies are visible for review.
- Allows only the enumerated permissive licenses.
- Ignores license checks for the private workspace package itself.
- Denies unknown registries and unknown Git sources.
- Allows only the canonical crates.io registry.
- Enables advisory checking.

The policy is intentionally explicit. Any future license exception must be documented, reviewed and separately approved; do not add broad wildcard exceptions merely to make CI green.

## 5. Security workflow

`.github/workflows/security-supply-chain.yml` is read-only and has no secrets or write permissions. It performs:
1. Full-history checkout with persisted credentials disabled.
2. Pinned Rust toolchain installation and version reporting.
3. Locked Cargo metadata resolution and duplicate dependency inventory.
4. RustSec advisory audit with warnings denied.
5. cargo-deny advisory, duplicate, license and source checks.
6. Locked optimized workspace build.
7. Full Git history and working-tree secret scanning with Gitleaks.

The existing Rust kernel workflow is also updated to:
- Use the pinned checkout action and Rust toolchain.
- Run formatting, all-target compile, production-feature guard, tests, optimized release build and Clippy with `--locked`.
- Include the A3 security branch and PR #85's architecture branch in the intended workflow filters.

## 6. CI activation constraint

GitHub Actions does not execute a newly introduced workflow from a PR head until the workflow is available on the base/default branch or it is explicitly dispatched through an authorized workflow-dispatch path. This branch-only implementation has not been merged, and no paid browser automation or wallet top-up is authorized.

Therefore:
- The supply-chain workflow definition and policies are committed in the implementation branch.
- Its actual `cargo audit`, `cargo deny`, Gitleaks and release-build results remain **NOT RUN**.
- Existing exact-source Rust kernel CI evidence is separate and does not count as execution of this new supply-chain workflow.
- No clean vulnerability, license or secret-scan result is claimed until the workflow has actually run.

## 7. Required acceptance evidence

A3.10.5 can be marked verified only after the exact implementation head has:
- Passed cargo metadata and locked release build.
- Passed cargo-audit with no unaccepted advisories.
- Passed cargo-deny advisory, source and license checks.
- Had duplicate dependencies reviewed and explicitly dispositioned.
- Passed full-history Gitleaks with no unaccepted findings.
- Passed the updated Rust kernel workflow.
- Produced run URLs, exact head SHA, tool versions and complete logs.

## 8. Scope limits

No dependency was upgraded solely to silence a scanner. No vulnerability is declared fixed without a tested version change. No secret is added to the repository. No workflow is given write permissions. No release, deployment, production key handling or runtime activation is included.
