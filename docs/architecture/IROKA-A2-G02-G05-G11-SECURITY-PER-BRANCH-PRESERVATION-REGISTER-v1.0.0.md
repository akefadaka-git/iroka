# IROKA A2 — G02/G05/G11 and Security Branch Preservation & Integration Register

**Audit date:** 2026-11-21  
**Canonical base:** `main` — `6b7004c897907f5ca40de58fee7222732fd7cde0` (A1 Owner-ratified merge)  
**Scope:** G02, G05, G11, G01/G02 security, and G08 time/orchestration branches returned by targeted GitHub branch searches.  
**Mode:** Read-only source/branch audit. This document is the audit deliverable; no implementation source was changed.

## 1. Executive determination

- **77 unique branch references** were found across the five targeted search families (G02: 24, G05: 38, G11: 9, security: 22, G08: 6; overlaps deduplicated).
- **77/77 branch refs were compared against the canonical main SHA** for ancestry, ahead/behind counts and changed-file inventory.
- The branch families are highly stacked and interdependent. Most active candidate branches are **4 commits behind current main** because they were based before the A1 merge. This is baseline drift, not evidence that their work is replaceable.
- G05 activation revisions v2–v10 and v11–v12 repeatedly modify the same source files. G02 PostgreSQL authority candidates are separate, non-identical generations. G11 provider-adapter branches share exact source blobs in key files, while earlier quorum work is a distinct precursor.
- Security validation branches r10–r13 share the same `security_store.rs` blob; r11–r13 share the same `owner_approval.rs` blob. r10 has a different owner-approval blob.
- **No branch is deleted, rebased, merged, closed, or retargeted by this audit.** The 77 branch references are preserved.
- A complete, all-path blob-hash matrix for every file in every branch was not exposed by the available comparison interface. Exact blob checks were performed on representative overlapping implementation files and are listed in §4. Therefore the branch ancestry register is complete for the 77 refs, while exhaustive all-file blob equivalence remains **PARTIAL**, not falsely declared complete.

## 2. Per-branch ancestry and preservation register

Counts are GitHub compare results against canonical main. `ahead` is commits unique to the branch relative to the merge base; `behind` is commits on main not in that branch. `diverged` means both lines contain unique commits. These values are not a deletion recommendation.

### G02 / G05 / G11 implementation and integration branches

| Branch | Ahead | Behind | Preservation / integration disposition |
|---|---:|---:|---|
| `architecture/g05-g01-g02-g11-integration-contracts` | 4 | 4 | Preserve; contract-only amendment; reconcile to A1 |
| `ci/g05-g01-g02-g11-e2e-verify` | 221 | 4 | Preserve as validation lineage; not an implementation merge target |
| `feat/a3-8-g02-owner-organization-authority` | 49 | 4 | Preserve; G02 authority source candidate |
| `feat/a3-g02-authority-migration-reconciliation` | 419 | 4 | Preserve; migration reconciliation; latest exact-head CI failed |
| `feat/brain-a3-g05-g01-g02-g11-integration` | 231 | 4 | Preserve; stacked cross-domain integration |
| `feat/g02-owner-signed-commands-checkpoint-http-a3` | 360 | 4 | Preserve; alternate G02 command path |
| `feat/g02-postgres-authority-a3` | 337 | 4 | Preserve; PostgreSQL authority schema/adapter candidate |
| `feat/g02-postgres-command-processor-a3` | 394 | 4 | Preserve; G02 command processor source |
| `feat/g02-postgres-g09-resolver-a3` | 344 | 4 | Preserve; resolver prerequisite in dependency chain |
| `feat/g05-g02-canonical-activation-integration` | 158 | 4 | Preserve; earlier G05/G02 integration generation |
| `feat/g05-g02-canonical-activation-v2` | 157 | 4 | Preserve; superseding iteration, distinct source blobs |
| `feat/g05-g02-canonical-activation-v3` | 165 | 4 | Preserve; superseding iteration |
| `feat/g05-g02-canonical-activation-v4` | 167 | 4 | Preserve; superseding iteration |
| `feat/g05-g02-canonical-activation-v5` | 168 | 4 | Preserve; superseding iteration |
| `feat/g05-g02-canonical-activation-v6` | 169 | 4 | Preserve; superseding iteration |
| `feat/g05-g02-canonical-activation-v7` | 175 | 4 | Preserve; superseding iteration |
| `feat/g05-g02-canonical-activation-v8` | 177 | 4 | Preserve; superseding iteration |
| `feat/g05-g02-canonical-activation-v9` | 178 | 4 | Preserve; exact blob evidence recorded in §4 |
| `feat/g05-g02-canonical-activation-v10` | 206 | 4 | Preserve; exact blob evidence recorded in §4 |
| `feat/g05-g02-g11-activation-v11` | 211 | 4 | Preserve; exact blob evidence recorded in §4 |
| `feat/g05-g02-g11-activation-v12` | 224 | 4 | Preserve; current PR #65 integration candidate |
| `implementation/a3-g02-authority-source` | 276 | 4 | Preserve; G02 authority-source implementation line |
| `implementation/a3-g02-owner-governance` | 289 | 4 | Preserve; Owner-governance implementation line |
| `security/g01-trust-lifecycle-g02-owner-approval` | 0 | 150 | Ancestor-only/behind; preserve pending PR and source-ownership review |
| `architecture/g05-owner-approved-contract-v1` | 1 | 4 | Preserve; approved G05 contract baseline |
| `ci/a3-8-g05-reviewer-integration-base` | 175 | 4 | Preserve; validation/base lineage |
| `ci/g05-e2e-v2` | 223 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v3` | 224 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v4` | 225 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v5` | 226 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v6` | 227 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v7` | 228 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v8` | 229 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v9` | 230 | 4 | Preserve; validation-only lineage |
| `ci/g05-e2e-v10` | 230 | 4 | Preserve; validation-only lineage |
| `ci/g05-final-head-verify` | 224 | 4 | Preserve; validation-only mirror of PR #65 head |
| `feat/a3-8-g05-verified-reviewer-integration` | 214 | 4 | Preserve; reviewer proof integration |
| `feat/brain-a3-b04-g05-memory-core` | 163 | 4 | Preserve; G05 memory core stacked on G04 |
| `feat/g05-g01-reviewer-proof-integration` | 155 | 4 | Preserve; G01 proof/G05 lifecycle integration |
| `feat/g05-http-host-a3` | 378 | 4 | Preserve; HTTP host implementation prerequisite |
| `feat/g05-postgres-g11-multiworker-a3` | 334 | 4 | Preserve; shared PostgreSQL G05/G11 adapter line |
| `fix/g05-clippy-argument-count` | 151 | 4 | Preserve; compatibility/fix lineage pending source comparison |
| `implementation/a3-g05-memory-classification` | 357 | 4 | Preserve; broad character implementation line |
| `verify/g05-70fe085-ci` | 151 | 4 | Preserve; exact-source verification lineage |
| `verify/g05-current-head-ci` | 147 | 4 | Preserve; exact-source verification lineage |
| `verify/g05-latest-head-ci` | 147 | 4 | Preserve; exact-source verification lineage |
| `verify/g05-pr34-exact-head-ci` | 141 | 4 | Preserve; PR #34 verification lineage |
| `feat/g11-checkpoint-quorum-a3` | 386 | 4 | Preserve; distinct G11 checkpoint quorum candidate |
| `feat/g11-provider-adapters-a3-rebased` | 391 | 4 | Preserve; PR #83 provider-adapter line |
| `feat/g11-provider-adapters-a3` | 428 | 4 | Preserve; later/non-rebased provider-adapter line |

### Security and G08 branches

| Branch | Ahead | Behind | Preservation / integration disposition |
|---|---:|---:|---|
| `ci/a3-security-audit-current-head` | 17 | 4 | Preserve; security validation candidate |
| `ci/a3-security-verification` | 4 | 4 | Preserve; verification-only branch |
| `ci/a3-security-verification-r2` | 6 | 4 | Preserve; verification-only revision |
| `ci/a3-security-verification-r3` | 6 | 4 | Preserve; verification-only revision |
| `ci/a3-security-verification-r4` | 7 | 4 | Preserve; verification-only revision |
| `ci/a3-security-workstreams-validation` | 7 | 4 | Preserve; security validation baseline |
| `ci/a3-security-workstreams-validation-r2` | 14 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r3` | 16 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r4` | 19 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r5` | 26 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r6` | 30 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r7` | 31 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r8` | 35 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r9` | 38 | 4 | Preserve; validation revision |
| `ci/a3-security-workstreams-validation-r10` | 39 | 4 | Preserve; blob comparison in §4 |
| `ci/a3-security-workstreams-validation-r11` | 41 | 4 | Preserve; blob comparison in §4 |
| `ci/a3-security-workstreams-validation-r12` | 42 | 4 | Preserve; blob comparison in §4 |
| `ci/a3-security-workstreams-validation-r13` | 43 | 4 | Preserve; latest inspected validation revision |
| `feat/a3-security-ci-foundation` | 7 | 4 | Preserve; toolchain/supply-chain CI foundation |
| `feat/a3-security-workstreams` | 350 | 4 | Preserve; PR #88 implementation source |
| `fix/k04-a3-security-remediation` | 75 | 126 | Preserve; divergent historical security remediation |
| `architecture/g08-orchestration-a2-contract` | 3 | 303 | Preserve; old contract branch; reconcile against ratified A1 |
| `feat/g08-a3-durable-coordinator` | 81 | 4 | Preserve; PR #63 durable coordinator candidate |
| `governance/g08-a2-owner-approved-closure` | 1 | 4 | Preserve; G08 A2 closure evidence |
| `implementation/a3-g08-character-workflow-graph` | 445 | 4 | Preserve; broad character implementation stack |
| `implementation/a3-g08-scheduler-policy` | 445 | 4 | Preserve; same broad implementation stack; distinct branch ref |
| `implementation/a3-g08-workflow-graph` | 378 | 4 | Preserve; workflow-graph implementation line |

## 3. Pull-request lineage and exact-head evidence

All PRs below remain unmerged unless stated otherwise. Their branches are preserved.

| PR | Branch / exact head | Base / dependency | Evidence and disposition |
|---|---|---|---|
| [#34](https://github.com/akefadaka-git/iroka/pull/34) | `feat/brain-a3-b04-g05-memory-core` — `b27816c1c3b172c0a7503d6602cddeaa6008c6cb` | G04 adapter PR #32 | Open draft; preserve; not integrated into main |
| [#42](https://github.com/akefadaka-git/iroka/pull/42) | `architecture/g05-g01-g02-g11-integration-contracts` — `0e8009bee94b321211636656448837a0636232fd` | G05 approved contract branch | Open draft; D1–D6 proposal recorded; D2 canonical organization-authority provider/source remains unresolved |
| [#50](https://github.com/akefadaka-git/iroka/pull/50) | `feat/a3-8-g01-tenant-reconciliation` — `c46f2b5876c0294481ee22dc0786fded1cdad9a6` | G02 Owner organization authority | Open draft; dependency for #65 |
| [#51](https://github.com/akefadaka-git/iroka/pull/51) | `feat/a3-8-g05-verified-reviewer-integration` — `10aca6e4fc5ed3a85d7218d6473f72f0c155d154` | G05/G01/G02 integration | Open draft; preserve |
| [#65](https://github.com/akefadaka-git/iroka/pull/65) | `feat/g05-g02-g11-activation-v12` — `b12739de686ac466dde02ad089f14e898eadffe9` | G01 tenant reconciliation #50 | Open draft; exact-head run #43216600529 SUCCESS; candidate source, not mainline integrated |
| [#76](https://github.com/akefadaka-git/iroka/pull/76) | `ci/g05-final-head-verify` — same source head `b12739de686ac466dde02ad089f14e898eadffe9` | Validation mirror of #65 | Closed, unmerged validation PR; do not treat as implementation merge |
| [#77](https://github.com/akefadaka-git/iroka/pull/77) | `feat/g05-postgres-g11-multiworker-a3` — `2bfac619b9601330b3343f86277bb5ba29ae22b2` | #65 head `b12739de...` | Open draft; exact-head runs #43240878046 and #43240392654 SUCCESS |
| [#78](https://github.com/akefadaka-git/iroka/pull/78) | `feat/g02-postgres-authority-a3` — `be1bd77b290a4561d9f67f2752d0bfd70af88a39` | #77 | Open draft; no exact-head PR workflow run returned |
| [#79](https://github.com/akefadaka-git/iroka/pull/79) | `feat/g02-postgres-g09-resolver-a3` — `3e6273e592eb1c5d15cda398d51939cd19f0a7b5` | #78 | Open draft; exact-head runs #43272969758 and #43272528554 SUCCESS |
| [#80](https://github.com/akefadaka-git/iroka/pull/80) | `feat/g02-postgres-command-processor-a3` — `7290142ba083f77f565d4d1b0922a158b391d1d8` | #79 | Open draft; run #43357789397 SUCCESS; run #43357761138 CANCELLED |
| [#81](https://github.com/akefadaka-git/iroka/pull/81) | `feat/g05-http-host-a3` — `c8991fc61170bc04d7aeaea390a76a85900c2232` | #80 | Open draft; exact-head run #43280580981 SUCCESS |
| [#83](https://github.com/akefadaka-git/iroka/pull/83) | `feat/g11-provider-adapters-a3-rebased` — `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810` | #81 | Open draft; no exact-head workflow run returned |
| [#84](https://github.com/akefadaka-git/iroka/pull/84) | `feat/a3-g02-authority-migration-reconciliation` — `6bec405058ee26d4961c1da99dda4f37d431f6be` | #80 | Open draft; exact-head run #43528719647 FAILURE: PostgreSQL ingress test `postgres_g02_ingress_adapter_denies_inactive_membership_and_emergency_stop`; 45 passed, 1 failed |
| [#88](https://github.com/akefadaka-git/iroka/pull/88) | `feat/a3-security-workstreams` — `86a96cd4bf6abf0eaea6b87917a94d6819fb9566` | GENESIS gene contract amendment proposal | Open draft; mergeable false; exact-head workflow not returned |
| [#63](https://github.com/akefadaka-git/iroka/pull/63) | `feat/g08-a3-durable-coordinator` — `2cfcf8db9437824cc8181ad8af1e8d819b936e2c` | main at pre-A1 SHA | Open draft; run #43230367894 SUCCESS; caller-controlled time remains a security defect |
| [#133](https://github.com/akefadaka-git/iroka/pull/133) | `feat/a3-android-integration-unification` — `683da7e3f39fcb27a50f46d440fdddcf4d0dde79` | main at pre-A1 SHA | Open draft; run #44678590336 SUCCESS; 453 commits ahead/4 behind, 57 files changed; not integrated and not authorized for merge |

### Dependency chain

The PostgreSQL G05/G11 and G02 integration path is explicitly stacked:

`#65 → #77 → #78 → #79 → #80 → #81 → #83`

PR #84 is an alternative migration-reconciliation increment stacked on #80; its current exact-head test fails. These branches must not be independently cherry-picked or merged out of order. PR #133 consumes the #80 G02 command processor and #81 HTTP host as an isolated A3 composition; its passing workflow is not evidence that its parent chain has been integrated into main.

## 4. Exact blob-hash reconciliation (representative shared source paths)

These checks use GitHub content blob SHA, not filenames or line counts.

### G05 activation generations

| Ref | `crates/iroka-g05-memory/src/authority.rs` | `.../src/registry.rs` |
|---|---|---|
| v9 | `b947521a9ae69732775a93ca84f5fa77d76fab79` | `bc3746bcebe8519d1ef8b7d8bc52697772f0a17d` |
| v10 | `da8f279916e0e202be9f225334fccbce3ede0d64` | `bc3746bcebe8519d1ef8b7d8bc52697772f0a17d` |
| v11 | `deb088226e81aad128a2566378311c1733b9327e` | `bc3746bcebe8519d1ef8b7d8bc52697772f0a17d` |
| v12 | `deb088226e81aad128a2566378311c1733b9327e` | `bc3746bcebe8519d1ef8b7d8bc52697772f0a17d` |
| G05 HTTP host | `deb088226e81aad128a2566378311c1733b9327e` | `bc3746bcebe8519d1ef8b7d8bc52697772f0a17d` |

**Finding:** registry content is byte-identical across all five refs. The authority implementation changes from v9 to v10 and again from v10 to v11; v11 and v12 and the HTTP-host branch carry identical authority blobs. This establishes duplicate content in selected paths, not branch equivalence: other files and commits remain unique.

### G02 PostgreSQL authority generations

| Ref | `g02_postgres.rs` blob | `owner_authority_postgres.rs` blob |
|---|---|---|
| #80 command processor | `235de40f5651e22ca8fa25502ec7b58589d5f66d` | `dbb30780b1bf7635c523bdcda1918a9df6d026de` |
| #82 owner-signed command branch | `1a4d073407db79ed86b1a45293a817dd033a6dda` | Not present at that ref |
| #79 G09 resolver | `1a4d073407db79ed86b1a45293a817dd033a6dda` | Not present at that ref |
| #84 migration reconciliation | `0ca9f88ed57c3fd615d3d93b9f308564c2b3714e` | `c3c239d6a11f1b2e54ef46db3d00846bcb0cfe5c` |

**Finding:** #79 and the owner-signed command branch share the same `g02_postgres.rs` blob, while #80 and #84 have distinct blobs. #84 also has a distinct Owner authority PostgreSQL implementation. This is not a single interchangeable G02 source line; preserve all candidates until the failed #84 test is resolved and the chosen source is explicitly verified.

### G11 provider adapter generations

| Ref | `checkpoint_https.rs` blob | `g02_outbox_worker.rs` blob |
|---|---|---|
| #83 rebased provider adapters | `b83452e87e12e05ff3fe2d4f157010b13cddde6b` | `eb2f20f01430c230fb289a12c0b1d35f68926dcb` |
| non-rebased provider adapters | `b83452e87e12e05ff3fe2d4f157010b13cddde6b` | `eb2f20f01430c230fb289a12c0b1d35f68926dcb` |
| checkpoint-quorum precursor | Files absent | Files absent |

**Finding:** the two provider-adapter branches share identical blobs for these two G11/G02 outbox files. The quorum precursor is not a duplicate of the later provider-adapter implementation.

### Security workstream validation revisions

| Ref | `owner_approval.rs` blob | `security_store.rs` blob |
|---|---|---|
| validation r10 | `4a38aaa15e6bb4c39b00d6e7ab185de0199f62cc` | `1f16fca12b5d5323ab39c96bf1d82412a05a4069` |
| validation r11 | `f4ce6534a3369f72318e69c313d6e12570bffb0d` | `1f16fca12b5d5323ab39c96bf1d82412a05a4069` |
| validation r12 | `f4ce6534a3369f72318e69c313d6e12570bffb0d` | `1f16fca12b5d5323ab39c96bf1d82412a05a4069` |
| validation r13 | `f4ce6534a3369f72318e69c313d6e12570bffb0d` | `1f16fca12b5d5323ab39c96bf1d82412a05a4069` |
| A3.10 implementation PR #88 | `3fad265a0809701a2f1d75a286807240dc5c4b23` | `1f16fca12b5d5323ab39c96bf1d82412a05a4069` |

**Finding:** r11–r13 are exact duplicates for both checked files; r10 differs only in the checked Owner approval file. PR #88 shares the security-store blob but has a distinct Owner approval blob. Validation branches are not interchangeable with the implementation source without full changed-path and workflow-context comparison.

## 5. Security and integration blockers

1. **G08 trusted time:** PR #63's public mutation request structures still accept caller-supplied `now` values for workflow creation, graph creation, transitions, claims, lease renewal/completion, retry and cancellation. Worker-proof use of `TrustedClock` does not prove all coordinator mutations use one trusted internal observation. Exact-head CI success does not close this defect.
2. **G02 canonical authority:** the approved integration amendment PR #42 still records the canonical organization-authority provider/source as unresolved. No provider is to be invented or activated.
3. **G02 migration reconciliation:** PR #84 exact-head run #43528719647 fails one PostgreSQL ingress test (45 pass / 1 fail). Do not treat this increment as verified.
4. **G11 external checkpoint:** PR #83 has no exact-head run returned. A passing ancestor or sibling does not verify its current head.
5. **G01/G02/G05/G11 transaction chain:** the #65→#77→#78→#79→#80→#81→#83 stack is not merged into main. The branch CI evidence is branch-local only.
6. **Security A4:** PR #88 is draft, mergeability false and has no exact-head workflow evidence returned. Independent security review remains NOT RUN.
7. **Mainline:** current main contains only the kernel baseline; these candidate crates/implementations are not established as integrated production functionality.

## 6. Preservation / deletion eligibility decision

**PRESERVE ALL 77 BRANCH REFERENCES.**

Reasons:
- The active implementation branches contain unique commits relative to main.
- Several branches are stacked dependencies or source-of-truth candidates.
- Validation branches may preserve exact CI evidence for specific source blobs and cannot be assumed redundant from branch names alone.
- Blob equality in selected files does not establish whole-tree equivalence.
- Closed validation PRs and superseded PRs do not imply that their branch contents are safe to delete.
- No deletion authorization was included in this A2 task.

No PR was merged/closed/rebased/retargeted, no branch was deleted, no source or workflow was edited, and no CI rerun was triggered.

## 7. A2 completion status

| Check | Status |
|---|---|
| Canonical main SHA revalidated | PASS |
| Targeted branch inventory and deduplication | PASS — 77 unique refs |
| Ahead/behind and changed-file comparison | PASS — 77/77 |
| Key G02/G05/G11/security blob comparisons | PASS — representative overlapping paths |
| Exhaustive blob hash comparison for every changed file across every branch | PARTIAL — not exposed as a single tree-diff operation; full per-path expansion remains |
| PR dependency and exact-head workflow register | PARTIAL — several candidate heads have no exact-head run |
| G02 migration test | BLOCKED — PR #84 exact-head test failure |
| G08 trusted-time boundary | BLOCKED |
| G01/G02/G05/G11 integrated production chain | NOT INTEGRATED |
| A4 independent security assurance | NOT RUN |
| Branch deletion | NOT AUTHORIZED / NONE PERFORMED |
| A2 overall closure | **PARTIAL — NOT CLOSED** |

### Required next gate

Before A2 can be closed: resolve the remaining all-path blob-hash coverage for branch-only files, establish the authoritative G02 source and G05/G11 integration candidate, obtain passing exact-head verification for #83 and #84 after owner-authorized remediation, and close the G08 trusted-time design gap. No A3 implementation, merge, branch deletion, release or deployment is authorized by this register.
