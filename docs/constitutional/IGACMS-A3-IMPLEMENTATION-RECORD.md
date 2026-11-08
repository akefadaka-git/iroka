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

**Verified implementation SHA:** `72296b5e3c78fa8c3cf3b782dd8caff22045ba27`  
**Workflow run:** [#42390862217](https://github.com/akefadaka-git/iroka/actions/runs/42390862217)  
**Result:** PASS  
**Pinned v1.0 Genome SHA-256:** `a89e2b5bdb3519201268cf087b84df676e34f932c33c888de00794362864351c`

| Gate | Evidence |
|---|---|
| Rust formatting | PASS |
| `cargo check --workspace --all-targets --locked` | PASS |
| Production feature set without development bypasses | PASS |
| `cargo test --workspace --all-targets --locked` | PASS — 52 unit tests and 2 documentation tests |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| Dependency lockfile | PASS — committed lockfile resolves `serde_jcs 0.2.0` and `sha1 0.10.6` |

## A3 completion assessment

- **A3.1:** VERIFIED — DNA, Genome, chromosome, gene, marker-definition, marker-assertion, Genesis, attestation, mutation-evidence and migration-evidence schemas committed.
- **A3.2:** IMPLEMENTED — strict duplicate-key parser; exact eight-domain set; exact 12 chromosome IDs, 36 core genes and 27 marker IDs; dependency-cycle checks. The additional hardening changes have not yet been rerun through CI at the current head.
- **A3.3:** VERIFIED — RFC 8785 JCS canonicalization and SHA-256 fingerprint pinned to the approved manifest.
- **A3.4:** IMPLEMENTED — Ed25519 Genesis envelope signing/verification against the configured Owner-controlled trust-root set, with provenance, validity and revocation behavior. Production root provisioning and genesis activation are NOT RUN.
- **A3.5:** VERIFIED — M0–M5 evidence gates and fail-closed tests.
- **A3.6:** VERIFIED — protected Owner-approval authorization requires a verified Genesis token and the pinned embedded Genome.
- **A3.7:** PARTIAL — source commit prefix resolved to full SHA and four representative historical blob IDs matched the A2 register; full 48-artifact blob-by-blob reconciliation has not yet been completed. DNA-045 remains `EXTENSION-REVIEW` by the A2 disposition.
- **A3.8:** PARTIAL — prior automated conformance tests PASS at `72296b5e3c78fa8c3cf3b782dd8caff22045ba27`; current hardening head `43b180bf65fcb1e19c9d2f4ead18ca3111d2511e` has no fresh workflow result returned yet. Independent review requirement explicitly waived by Owner on 2026-11-08; no independent review is required for A3 closure under this waiver.

**Overall A3 status: PARTIAL — historical commit reference resolved; implementation hardening applied. Fresh exact-head verification and full 48-artifact blob reconciliation remain open. Independent review is waived by the Owner and is not a blocker.**

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

- Last verified implementation SHA: `72296b5e3c78fa8c3cf3b782dd8caff22045ba27`, workflow run [#42390862217](https://github.com/akefadaka-git/iroka/actions/runs/42390862217) — PASS.
- Current branch head after hardening: `134ed29c087831fd81ea6f0ff07748133f45c3c9`.
- No workflow run was returned for the current head by the available PR-run lookup. Current-head format, compile, test and Clippy status is therefore **NOT VERIFIED**.
- PR #13 has no submitted reviews, review threads, requested reviewers, CODEOWNERS file or SECURITY.md review instructions.
- Independent security review is explicitly waived by the Owner on 2026-11-08. This is a governance waiver, not a claim that an independent review occurred.


## Owner governance decision — independent review waiver

On 2026-11-08, the Owner explicitly instructed: "No need for independent review." Accordingly:
- Independent security review is waived as a prerequisite for A3.8 and A3 closure.
- No external reviewer access or review request is required.
- This waiver does not convert internal review into independent review and does not certify the implementation as independently audited.
- Exact-head automated verification and the remaining historical reconciliation evidence are still required for an evidence-complete A3 closure.
- Merge, deployment, production trust-root provisioning and Genesis activation remain separately unauthorized.
