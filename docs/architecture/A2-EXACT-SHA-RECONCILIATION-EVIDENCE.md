# A2 — Exact-SHA Repository Reconciliation Evidence

**Contract ID:** IROKA-A2-RECON-EVIDENCE-001  
**Version:** 0.1.0  
**Status:** Read-only repository snapshot and proposed dispositions  
**Snapshot date:** 2026-11-04  
**Repository:** `akefadaka-git/iroka`  
**A1 baseline:** `IROKA-A1-REGIONAL-001 v1.0.0`  
**A2 working branch:** `architecture/a2-reconciliation-contracts` (initial inspected head `49cf214323f6faed913a50707cc656fbeca69a91`; two audit documents were then added in this workstream)

## 1. Evidence method and boundary

Read-only GitHub API inspection of repository metadata, all discovered branch heads, exact commit/tree objects, recursive Git trees, branch comparisons and all open/closed PR metadata. Recursive tree responses for all five active branches reported `truncated=false`.

This establishes reachable current branch snapshots and their current tracked files. It does not establish unpushed local changes, unreachable/deleted Git objects, private external repositories, linked services not present in the repository, or runtime behavior not tested at an exact SHA.

## 2. Branch, ancestry and PR register

| Ref | Exact head | Relationship to main | Disposition |
|---|---|---|---|
| `main` | `143311a655be68acea2700650b7f88c9fb085526` | Baseline | Preserve unchanged |
| `foundation/kernel-v0.1` | `8f848a59a354334a26a2af508ba5e482b347d811` | 55 ahead / 0 behind | Historical kernel source; preserve |
| `security/g01-trust-lifecycle-g02-owner-approval` | `710b36a506d3277c7b307a01522629db43b4698f` | 153 ahead / 0 behind | Security continuation and current A1 canonical-path source; preserve |
| `architecture/a1-amharic-first-african-contracts` | `72be8040283acd31ce90050a5b03d59c55b38b89` | 4 ahead / 0 behind | Independent A1 source; preserve pending canonicalization |
| `architecture/a2-reconciliation-contracts` | `49cf214323f6faed913a50707cc656fbeca69a91` | 158 ahead / 0 behind | A2 working branch; preserve |

Ancestry comparisons:
- Foundation → security: security is 98 commits ahead, 0 behind. The security branch is a direct continuation of the kernel foundation.
- Security → A2: A2 is 5 commits ahead, 0 behind. Those five commits are A2 documentation changes; no runtime source changed in this delta.
- A1 architecture branch versus security: divergent from main; security is 153 commits ahead and 4 commits behind the A1 branch.
- A2 versus A1 architecture branch: divergent from main; A2 is 158 commits ahead and 4 commits behind.

Open draft PRs:
- [PR #1 — Foundation](https://github.com/akefadaka-git/iroka/pull/1), head `8f848a59a354334a26a2af508ba5e482b347d811`, base `main`.
- [PR #2 — Security](https://github.com/akefadaka-git/iroka/pull/2), head `710b36a506d3277c7b307a01522629db43b4698f`, base `main`.
- [PR #3 — A1 architecture](https://github.com/akefadaka-git/iroka/pull/3), head `72be8040283acd31ce90050a5b03d59c55b38b89`, base `main`.

All three were open, draft and unmerged at snapshot time. PR #3 exists; any older register statement that no A1 PR existed is superseded by this snapshot. No PR metadata, branch or main ref was changed during this inspection.

## 3. Complete tracked-file inventory by active branch snapshot

### 3.1 Main — 2 files

- `README.md`
- `docs/IMPLEMENTATION_STRATEGY.md`

Disposition: preserve baseline. No runtime implementation is present on main at this SHA.

### 3.2 Foundation — 19 files

- `.github/workflows/rust-kernel.yml`
- `Cargo.toml`
- `README.md`
- `crates/iroka-kernel/Cargo.toml`
- `crates/iroka-kernel/src/assurance.rs`
- `crates/iroka-kernel/src/decision.rs`
- `crates/iroka-kernel/src/governance.rs`
- `crates/iroka-kernel/src/identity.rs`
- `crates/iroka-kernel/src/identity_crypto.rs`
- `crates/iroka-kernel/src/lib.rs`
- `crates/iroka-kernel/src/policy.rs`
- `crates/iroka-kernel/src/request.rs`
- `crates/iroka-kernel/src/service.rs`
- `crates/iroka-kernel/tests/authorization_contract.rs`
- `docs/IMPLEMENTATION_STRATEGY.md`
- `docs/architecture/G01-CREDENTIAL-VERIFICATION.md`
- `docs/architecture/G01-IDENTITY-CONTRACT.md`
- `docs/architecture/G02-GOVERNANCE-CONTRACT.md`
- `docs/architecture/G11-ASSURANCE-CONTRACT.md`
- `docs/architecture/GOVERNED-AUTHORIZATION-PIPELINE.md`
- `docs/kernel/FOUNDATION_CONTRACT.md`

Disposition: `RETAIN` as historical kernel foundation and provenance. Rust source is not to be copied as a second kernel; security branch descends from this history. Review each source module in the security continuation before any implementation changes.

### 3.3 Security/A1 — 31 files

- `.github/workflows/rust-kernel.yml`
- `Cargo.lock`, `Cargo.toml`
- `README.md`
- `crates/iroka-kernel/Cargo.toml`
- `crates/iroka-kernel/src/assurance.rs`
- `crates/iroka-kernel/src/audit_store.rs`
- `crates/iroka-kernel/src/decision.rs`
- `crates/iroka-kernel/src/governance.rs`
- `crates/iroka-kernel/src/identity.rs`
- `crates/iroka-kernel/src/identity_crypto.rs`
- `crates/iroka-kernel/src/lib.rs`
- `crates/iroka-kernel/src/owner_approval.rs`
- `crates/iroka-kernel/src/policy.rs`
- `crates/iroka-kernel/src/request.rs`
- `crates/iroka-kernel/src/security_store.rs`
- `crates/iroka-kernel/src/service.rs`
- `crates/iroka-kernel/src/trust_lifecycle.rs`
- `crates/iroka-kernel/tests/authorization_contract.rs`
- `docs/IMPLEMENTATION_STRATEGY.md`
- `docs/architecture/A1-AMHARIC-FIRST-REGIONAL-ARCHITECTURE-CONTRACT.md`
- `docs/architecture/A1-IMPLEMENTATION-INVENTORY.md`
- `docs/architecture/A1-REQUIREMENTS-TRACEABILITY-AND-DECISIONS.md`
- `docs/architecture/G01-CREDENTIAL-VERIFICATION.md`
- `docs/architecture/G01-IDENTITY-CONTRACT.md`
- `docs/architecture/G02-GOVERNANCE-CONTRACT.md`
- `docs/architecture/G11-ASSURANCE-CONTRACT.md`
- `docs/architecture/G11-AUDIT-INTEGRITY-CONTRACT.md`
- `docs/architecture/GOVERNED-AUTHORIZATION-PIPELINE.md`
- `docs/architecture/REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md`
- `docs/kernel/FOUNDATION_CONTRACT.md`
- `docs/operations/G01-G02-OWNER-TRUST-PROVISIONING.md`

Disposition:
- `RETAIN`: kernel, security store, trust lifecycle, Owner approval, audit and workflow files as the current security implementation line.
- `RETAIN`: G01/G02/G11 contracts and operational provisioning documentation as security control contracts.
- `RETAIN`: A1 regional contract, traceability, inventory and strategy as the current canonical-path candidate.
- `REVIEW`: README and strategy changes before future public-facing consolidation.
- No runtime localization implementation is evidenced by this tree.

### 3.4 Independent A1 architecture branch — 5 files

- `README.md`
- `docs/IMPLEMENTATION_STRATEGY.md`
- `docs/architecture/A1-AMHARIC-FIRST-ETHIOPIAN-AFRICAN-CONTRACT.md`
- `docs/architecture/A1-REQUIREMENTS-TRACEABILITY-AND-DECISIONS.md`
- `docs/architecture/REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md`

Disposition:
- `ADAPT`: parent A1 contract content into a semantic-union candidate at the security branch's canonical path, subject to Owner review for material changes.
- `ADAPT`: traceability and profile contracts by combining unique requirements; preserve one canonical file/contract ID per concept.
- `REVIEW`: README and strategy changes independently.
- `RETAIN` source branch unchanged until explicit branch disposition approval. Do not delete or force-push.

### 3.5 A2 branch — 36 files at the post-audit tree

The A2 branch contains the same 31-file security/A1 tree plus five A2 documents:
- `docs/architecture/A2-ACCEPTANCE-TEST-PLAN.md`
- `docs/architecture/A2-API-DATA-AND-EVENT-CONTRACTS.md` (blob `189c1c1663a66ec459437088b6a9b476d4558bd3`)
- `docs/architecture/A2-EXACT-SHA-RECONCILIATION-EVIDENCE.md`
- `docs/architecture/A2-IMPLEMENTATION-CONTRACTS.md`
- `docs/architecture/A2-RECONCILIATION-AND-DISPOSITION-REGISTER.md`

A2 delta versus security is documentation-only (five added files, seven commits at post-audit verification). The A2 working branch head after the two audit-document additions is recorded in the final progress report for this run.

## 4. Per-domain code disposition against A1

| Domain / files | Current evidence | A2 disposition |
|---|---|---|
| Kernel identity/crypto/trust: `identity.rs`, `identity_crypto.rs`, `trust_lifecycle.rs` | Credential/principal and trust lifecycle, not human multilingual person identity | `RETAIN`; keep principal identity separate from IDN person records |
| Governance/approval: `governance.rs`, `owner_approval.rs`, `policy.rs` | Owner-signed approval and policy control | `RETAIN`; localization must not alter authority |
| Audit/assurance: `audit_store.rs`, `assurance.rs` | Kernel audit and assurance facilities | `RETAIN`; extend only through separately specified audit contracts |
| Request/service: `request.rs`, `service.rs`, `decision.rs`, `lib.rs` | Authorization request/decision/service kernel | `RETAIN`; platform domain APIs remain separate |
| Language catalog / Amharic UI | No tracked client or language-resource runtime | `MISSING` at inspected refs; design L10N boundary before A3 |
| Ethiopic fonts/rendering | No client, font assets or renderer | `MISSING` at inspected refs |
| Locale/numerals | No runtime LOC module | `MISSING` at inspected refs |
| Regional profile registry/resolver | A1/A2 documentation only | `MISSING` at inspected refs |
| Ethiopian/Gregorian calendar | No CAL module or conformance vectors | `MISSING` at inspected refs |
| Person-name directory/search | Kernel principal is not a person record | `MISSING` at inspected refs |
| Document/records/rendering | No DOC runtime | `MISSING` at inspected refs |
| Amharic OCR | No OCR runtime or corpus | `MISSING` at inspected refs |
| Knowledge ingestion/retrieval | No KNOW runtime, index or corpus | `MISSING` at inspected refs |
| Speech recognition/synthesis | No adapter or benchmark | `NOT VERIFIED` at inspected refs |
| Second African profile runtime | No profile resolver or runtime fixture | `MISSING` at inspected refs |
| Cross-profile security invariance | Kernel controls exist; no locale/profile regression suite in tracked code | `NOT VERIFIED` |

The inventory is complete for the current tracked Git trees inspected, but does not cover external products or unpushed work. These are not claims that no such work exists elsewhere.

## 5. Duplicate A1 contract reconciliation

Both A1 branches use the same IDs for non-identical documents:
- Parent: `IROKA-A1-REGIONAL-001`
- Profile: `IROKA-A1-REG-002`
- Traceability: `IROKA-A1-TRACE-001`

The parent contracts are materially complementary, not byte-identical duplicates. The semantic union MUST retain:
- all stronger explicit language preference, fallback, translation review and accessibility rules;
- Ethiopic shaping, Unicode normalization and original-source preservation;
- typed temporal semantics and Ethiopian/Gregorian boundaries;
- richer person-name components, source order, aliases, transliteration provenance and non-automatic merge rules;
- document/OCR source-to-derivative provenance and human review;
- knowledge citations, conflicts, access inheritance and cross-language limits;
- Kernel invariants, legal/data-residency review, speech limitations and deferred decisions.

The security branch path remains the provisional canonical path because the security strategy and inventory reference it. This A2 report does not overwrite either source or assert Owner approval of an A1 v1.1 amendment. The semantic-union candidate and exact section mapping require separate review before replacing v1.0.0.

## 6. A2 contract and test-plan assessment

Existing artifacts:
- `A2-IMPLEMENTATION-CONTRACTS.md` defines logical service boundaries, resource/profile/temporal/person/document/OCR/knowledge semantics, cross-cutting rules and dependency-selection gates.
- `A2-ACCEPTANCE-TEST-PLAN.md` defines deterministic pass thresholds for Unicode, rendering, text interaction, numerals, calendar conversion, time semantics, identity, translations, documents, security, regional profiles and provenance; it also defines OCR CER/WER and retrieval metrics.
- `A2-RECONCILIATION-AND-DISPOSITION-REGISTER.md` records branch history and duplicate A1 semantic reconciliation.

Gaps before A2 closure:
1. Existing logical contracts did not fully define common request/error envelopes, concrete operation semantics, event envelopes, idempotency and migration compatibility. A2 interface supplement is added in this workstream; machine-readable OpenAPI/JSON Schema remains an A3-entry prerequisite.
2. Corpus IDs, hashes, licensing/consent files, annotation protocols and held-out splits are not yet supplied.
3. Independent Ethiopian calendar oracle and authoritative reference vectors are not yet selected.
4. OCR/retrieval numerical thresholds are proposed/frozen as pre-implementation targets in the plan but still require Owner approval and dataset feasibility review before any evaluation.
5. Speech thresholds are explicitly deferred to a separately versioned annex; speech cannot be claimed supported.
6. Named Amharic terminology/translation reviewers and regional legal/data-governance reviewers are not yet assigned.
7. Dependency candidates, versions, license review, security review and maintenance comparison are not yet recorded.
8. No complete external product/client/integration inventory or unpushed-work attestation is available in this repository snapshot.

## 7. Non-actions

- `main` remains unchanged at `143311a655be68acea2700650b7f88c9fb085526`.
- No branch was deleted, rewritten, rebased or merged.
- PRs #1, #2 and #3 remain draft and unmerged.
- No runtime implementation, dependency selection, test execution, deployment or production-readiness claim is made.
- No A1 requirement was weakened to match existing code.

## 8. A2 status and exit gates

**A2 status: PARTIAL — repository snapshots reconciled; implementation contracts and acceptance plan established; evidence and approvals remain open.**

A2 can become VERIFIED-CLOSED only after:
- the A1 semantic-union mapping is reviewed and Owner-approved where it changes normative presentation or strength;
- a complete per-file disposition is reviewed, including commit-history changes, scripts/config/workflow consumers and license/provenance;
- external/unpushed product surfaces are attested or explicitly excluded from the A2 scope;
- logical interface supplement is reviewed and machine-readable schemas are approved before A3;
- dataset provenance, corpus hashes, annotation protocols and held-out splits are frozen;
- calendar oracle/reference vectors are selected and independently reviewed;
- numeric acceptance thresholds and feasibility are Owner-approved before any evaluation;
- Amharic terminology, translation and regional reviewers are assigned;
- dependency shortlist has license, security, maintenance and reproducibility evidence;
- all A1 requirements have an accountable owner, contract, test, evidence artifact and release gate;
- Owner explicitly authorizes A3 implementation.

A2 closure is not implementation readiness, runtime conformance, legal compliance, production readiness or deployment authorization.
