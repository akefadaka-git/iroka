# IROKA BRAIN — Implementation Work Breakdown and Verification Plan

**Document ID:** IROKA-BRAIN-PLAN-001  
**Version:** 0.3.0  
**Status:** Planning artifact; A1 FROZEN; A2 PARTIAL; A3 NOT AUTHORIZED  
**Depends on:** IROKA-BRAIN-A1-001 and IROKA-BRAIN-A2-001  
**Target:** `akefadaka-git/iroka`

## 1. Purpose and constraints

This plan decomposes the proposed Brain architecture into reviewable work packages. It is not an implementation authorization. No runtime source, dependency, workflow, production configuration, model provider or trust material is changed by this plan.

The first A3 increment, if separately authorized, is a synthetic-only, non-side-effecting cognitive contract/runtime slice. It must not add a second identity, policy, audit, knowledge, memory, perception, orchestration or execution authority.

## 2. Work package register

| ID | Work package | Owner boundary | Deliverable | Entry dependency |
|---|---|---|---|---|
| BRAIN-01 | Cognitive task/result/evidence contracts | G03 | Versioned typed schemas and validation | A1/A2 approved |
| BRAIN-02 | Deterministic task lifecycle and bounds | G03; G08 contract only | State model, limits, cancellation/stop semantics | BRAIN-01 |
| BRAIN-03 | Reasoning coordinator | G03 | Strategy interface and structured result | BRAIN-01/02 |
| BRAIN-04 | Planner and critic interfaces | G03 | Typed plan, critique and abstention outcomes | BRAIN-03 |
| BRAIN-05 | Model gateway abstraction | G03 | Provider-neutral adapter, fake deterministic provider | BRAIN-01/03; data-flow policy |
| BRAIN-06 | Evidence/knowledge adapter | G04 | Provenance-preserving evidence interface | G04 contract approval |
| BRAIN-07 | Memory context adapter | G05 | Consent/purpose/classification-aware context interface | G05 contract approval |
| BRAIN-08 | Perception adapter boundary | G06 | Normalized untrusted observation interface | G06 contract approval |
| BRAIN-09 | Evaluation harness | G10 | Synthetic benchmark fixtures, scorer and regression report | BRAIN-01/03 |
| BRAIN-10 | Assurance and trace integration | G11 | Correlated events and assurance evidence | G11 contract approval |
| BRAIN-11 | Workflow integration | G08 | Durable workflow adapter, no private workflow state | G08 tenant-context and lineage closure |
| BRAIN-12 | Agent integration | G07 | Scoped cognitive worker contract | G07 approval and separate scope |
| BRAIN-13 | Protected action proposal bridge | G02/G08/G09 | Proposal-only interface; no direct execution | Separate approval and G09 contract |
| BRAIN-14 | Governed learning proposal | G10/G12 | Evaluation-backed improvement proposals | Evaluation evidence and G12 approval |

## 3. Dependency graph

`A1 freeze → A2 contract closure → separate A3 authorization → BRAIN-01 → BRAIN-02 → BRAIN-03 → BRAIN-04`

Parallel work after contract approval:
- BRAIN-05 depends on task/result contracts and provider/data-flow policy.
- BRAIN-06/07/08 depend on their respective domain-owner contracts.
- BRAIN-09 depends on stable schemas and evaluation oracle governance.
- BRAIN-10 depends on G11 event/evidence contracts.
- BRAIN-11 is blocked until G08 tenant context and integration lineage are resolved.
- BRAIN-12/13/14 are later scopes and require their own domain approvals.

No dependency may be bypassed by adding caller-supplied tenant IDs, direct SQL to another domain's store, direct tool invocation or model-generated authorization.

## 4. First authorized-scope candidate (proposal only)

If separately authorized, BRAIN-01 through BRAIN-05 plus synthetic tests are the recommended first vertical slice.

Included:
- task/result/evidence schema validation;
- bounded deterministic lifecycle;
- reasoning coordinator interfaces;
- planner and critic interfaces;
- fake model adapter with deterministic fixtures;
- explicit error, timeout, cancellation, budget-exhaustion and abstention outcomes;
- exact-HEAD formatting, compilation, unit, contract and security regression checks.

Excluded:
- external or paid provider activation;
- production data, secrets or credentials;
- persistent memory implementation;
- knowledge ingestion or independent source registry;
- voice, image, audio or video runtime;
- multi-agent delegation;
- G09 tool execution or external side effects;
- autonomous self-modification or model training;
- deployment, merge or production release.

## 5. Contract and test matrix

| Test family | Required positive cases | Required negative/adversarial cases | Acceptance |
|---|---|---|---|
| Schema | Valid versioned task/result/evidence | Unknown version, duplicate/unknown fields, malformed types | Exact schema outcomes |
| Identity context | Verified principal reference propagated | Forged subject/tenant, missing auth context | Reject; no caller-derived authority |
| Bounds | Within deadline/iteration/budget | Oversized input, unbounded loop, budget overrun | Deterministic bounded termination |
| Reasoning | Supported task returns structured result | Contradictory inputs, missing evidence, unsupported task | Uncertainty/abstention; no fabricated verification |
| Planning | Valid acyclic dependency plan | Cycles, missing prerequisites, out-of-scope targets | Reject invalid plan |
| Critique | Detect seeded contradictions/unsupported claims | Critic falsely marks model output as verified | Critique cannot confer assurance status |
| Model gateway | Fake adapter success/cancel | Timeout, malformed output, provider failure, refusal | Stable normalized errors; no unapproved fallback |
| Data policy | Allowed synthetic input routed to fake adapter | Restricted data routed to unapproved provider | Block before transmission |
| Evidence | Source references preserved | Fabricated/missing/stale source references | Cannot claim supported citation |
| Memory adapter | Permitted context reference accepted | Cross-tenant, expired, revoked, deleted memory | Deny and preserve lifecycle semantics |
| Perception adapter | Normalized observation accepted | Modality spoofing, malicious embedded instructions | Treat content as untrusted data |
| Audit | Correlated task events emitted | Missing event, sink outage, sensitive content leakage | Fail closed where required; minimize content |
| Reliability | Cancellation/restart behavior as contracted | Crash, duplicate event, concurrency race | Idempotent or explicit unresolved outcome |
| Localization | Amharic and English synthetic cases | Ethiopic corruption, lossy transliteration, ambiguous calendar | Preserve source and label conversions |
| Regression | Fixed defect test repeats | Prior bypass reproduced | Zero recurrence in required suite |

## 6. Benchmark and quality reporting

Every benchmark run must record:
- benchmark ID/version and fixture digest;
- task provenance, license and classification;
- exact code SHA and configuration;
- model/provider and exact version, or deterministic fake adapter;
- policy and schema versions;
- hardware/runtime and resource budget;
- evaluator/scoring version and sample size;
- raw outcomes, pass/fail/blocked/not-run counts;
- confidence intervals where meaningful;
- failure taxonomy, examples and limitations.

Report at least:
- task success and exact/graded accuracy;
- citation support precision and source freshness;
- plan validity and constraint adherence;
- calibration and abstention quality;
- Amharic native-review quality and Ethiopic fidelity;
- unauthorized side-effect count (target: zero);
- cross-tenant disclosure count (target: zero);
- p50/p95/p99 latency where sufficient samples exist;
- resource/cost per successful task.

Do not invent latency, throughput, WER or cost targets before selecting representative hardware, datasets and workloads. A safety/privacy/authorization failure blocks release regardless of aggregate score.

## 7. A4 verification package

For every implementation increment:
1. Pin exact repository, branch and head SHA.
2. Run formatting and static checks without mutating the checkout.
3. Run locked compilation and feature-matrix checks.
4. Run unit and contract tests.
5. Run adversarial and negative authorization/data-isolation tests.
6. Run fault-injection and cancellation/recovery tests where applicable.
7. Run localization and provenance tests.
8. Run dependency/license/SBOM and secret scanning.
9. Obtain independent review for security-critical changes.
10. Record workflow URLs, artifacts, logs, environment and known limitations.
11. Verify the branch head after CI; evidence must match the exact current SHA.
12. Record findings and remediation commits; rerun affected and full required gates.

A green workflow alone does not establish production readiness or close independent assurance.

## 8. A5 release prerequisites

A5 is not included in this work authorization. A future release proposal must include:
- accepted A4 exact-HEAD evidence;
- explicit Owner release approval;
- signed/versioned artifact and dependency provenance;
- environment/data-flow configuration;
- approved provider and operating-cost controls;
- secrets/key custody and revocation operations;
- observability, incident response and emergency stop;
- tested backup, restore and rollback;
- privacy, legal and language acceptance appropriate to deployment;
- staged rollout and rollback triggers.

## 9. Progress and gate status

| Gate | Status | Evidence / next condition |
|---|---|---|
| A1 assessment | PASS | Destination, constitutional baseline and relevant workstreams inspected |
| A1 Brain specification | VERIFIED-CLOSED | Owner approved D2; IROKA-BRAIN-A1-001 v1.0.0 frozen on proposal branch |
| A2 read-only reconciliation | PASS | IROKA-BRAIN-A2-001 records inspected branches/PRs, final repository state and D1/D2 decisions |
| A2 contracts | PARTIAL | Cognitive contract proposal drafted; B-A2-01/02 approved; formal schema acceptance, G01/G02 context, G04/G05/G06 interfaces, G08/CIW lineage, corpus governance and A3 increment scope remain open |
| A3 implementation | NOT AUTHORIZED | Requires A1 freeze, A2 closure and separate explicit authorization |
| A4 verification | NOT RUN | No Brain runtime implementation exists in this workstream |
| A5 release | NOT AUTHORIZED | Separate release gate |

## 10. Preservation and change-control rules

- No Brain changes are to be made to `main` during A1/A2; all Brain work remains isolated on its proposal branch.
- Do not modify existing PR branches or rewrite their history.
- PR #12 and #13 are already merged with Owner-confirmed D1 authorization; do not alter their merge commits. PR #24 is also recorded as merged on main during the assessment window; do not alter it. Do not merge PR #16, #17, #18, #19–#23 as part of this work.
- Do not force-push, delete or rename existing branches.
- Do not duplicate G01/G02/G04/G05/G06/G08/G09/G11/G12 state or authority.
- Preserve existing CI and workflow permissions; no new workflow permissions without explicit review.
- No production keys, secrets, personal data or paid provider dependencies.
- Every new implementation increment must be isolated, reviewable and exact-SHA verifiable.

**Disposition:** planning only. A1 is VERIFIED-CLOSED / FROZEN by D2. A2 remains PARTIAL; the A2 cognitive contract proposal is not yet Owner-approved. A3 implementation is NOT AUTHORIZED and requires separate explicit Owner authorization after A2 closure. A4 verification and A5 release remain separate gates.


---

## 10. Owner decision update — A2 approved; broader A3 proposed (2026-11-09)

**A2:** Owner approved `IROKA-BRAIN-A2-COGNITIVE-CONTRACTS-001.md` v1.0.0. The A2 design/contract gate is VERIFIED-CLOSED. This does not close implementation readiness for adapters whose authoritative contracts or branch ancestry remain unresolved.

**A3 direction:** broader cross-domain cognitive runtime integration, not a G03-only isolated demonstration. The following work packages are proposed in dependency order:

| Work package | Scope | Mandatory entry condition / boundary |
|---|---|---|
| A3-B01 — Cognitive core | Rust G03 task/result envelopes, bounded reasoning loop, deterministic planner, critic, abstention, typed errors, correlation and resource accounting | Build against approved A2 contracts; synthetic fixtures and deterministic fake model only |
| A3-B02 — Trusted composition | Integrate verified principal, tenant context, policy decision, revocation and audit through the authoritative Kernel | Exact Kernel baseline and G01/G02 interfaces pinned; no caller-derived tenant or policy authority |
| A3-B03 — Knowledge/evidence | G04 retrieval/evidence adapter, provenance, freshness and conflict handling | Exact G04 contract and source provenance verified; no G03-owned knowledge store |
| A3-B04 — Memory | G05 context retrieval/write-request adapter with consent, classification, retention and deletion semantics | Exact G05 API and policy lifecycle verified; no duplicate memory persistence |
| A3-B05 — Perception | G06 normalized observation adapter and untrusted-content handling | Exact G06 interface and modality safety contracts verified; no G03-owned media pipeline |
| A3-B06 — Conversation integration | Reconcile the existing CIW implementation as a candidate; integrate G03 gateway and browser/API surfaces only after security review and branch-lineage resolution | PR #23 is a candidate, not an adopted baseline; exact diff and ancestry must be reconciled against current main |
| A3-B07 — Durable orchestration | G08 task/workflow adapter for long-running cognitive tasks, cancellation and recovery | G08 contract approval, tenant context and branch ancestry resolved; no G09 execution |
| A3-B08 — Evaluation and assurance | G10 evaluation harness, Amharic/English synthetic conformance, G11 evidence export and independent-review handoff | Corpus licences and benchmark workload approved before real data or release thresholds; G03 critique is never independent assurance |
| A3-B09 — Evolution boundary | G12 version/change proposal metadata and compatibility checks | G12 remains the sole evolution/release authority; G03 cannot self-approve or self-deploy |

### 10.1 Global A3 restrictions

- No duplicate identity, trust, tenant, policy, approval, audit, knowledge, memory, perception, orchestration, execution, assurance or evolution authority.
- No G07 agent delegation, G09 protected effects, tool execution, autonomous external actions or production data in this A3 scope.
- No external/paid model provider activation. Use deterministic fake adapters until a separately approved provider/data-flow/cost review.
- No unlicensed or unverified Amharic corpus. Synthetic data only until source-by-source approval.
- Every work package has its own exact base SHA, branch, acceptance tests, workflow evidence and rollback boundary.
- Existing PRs/branches are read-only inputs unless separately authorized. No rebasing, force-push, merge, branch deletion or deployment under this plan.

### 10.2 A3 sequencing and stop conditions

1. **B01 first:** implement the isolated cognitive core only after separate A3 authorization.
2. **B02 before authenticated integration:** if Kernel/tenant/policy contracts cannot be pinned, keep the core offline and deny authenticated execution.
3. **B03–B05 adapters:** each adapter is independently blocked until its owner contract is exact and verified; unavailable domains produce typed abstention.
4. **B06 CIW:** do not transplant the current PR #23 branch wholesale. Its head is 172 commits ahead and 22 commits behind current main, with a stale base; conduct file-level provenance/security review and create a clean integration branch only after Owner-approved baseline selection.
5. **B07 orchestration:** no G08 composition until tenant-context and lineage blockers are resolved.
6. **B08/B09:** quality, assurance and evolution evidence are mandatory before A4; they do not confer release authority.

A failed dependency gate stops only the dependent work package; it does not justify bypassing or duplicating the authoritative domain.

### 10.3 Current stage status

| Gate | Status |
|---|---|
| A1 | VERIFIED-CLOSED / FROZEN |
| A2 | VERIFIED-CLOSED — design/contracts only |
| A3 scope | BROADER PROPOSAL RECORDED; implementation authorization still required |
| A3 implementation | NOT STARTED / NOT AUTHORIZED |
| A4 | NOT RUN |
| A5 | NOT AUTHORIZED |

**No merge, deployment, production activation, signing, publication or paid-service activation is authorized.**


---

## 11. A3 execution record — B01 implementation and exact-HEAD CI (2026-11-09)

**Owner authorization:** Explicit YES for A3 implementation of B01–B09 on isolated branches, with dependency gates. Merge and deployment remain separately unauthorized.

### 11.1 B01 implementation record

- PR: https://github.com/akefadaka-git/iroka/pull/27
- Branch: `feat/brain-a3-b01-cognitive-core`
- Base: `main` at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`
- Exact verified HEAD: `9d68b580e06bb8335a626524d64b345c3a5a38aa`
- PR state: OPEN / DRAFT / UNMERGED.
- Compare: branch is 6 commits ahead of main, 0 behind (verify against latest comparison before any later integration).
- Added isolated `iroka-brain` workspace crate with serde/serde_json only; no new external dependency.
- Implemented v1 task/result envelope structures, strict schema/version validation, full serialized-input byte budget, fail-closed iteration/output limits, offline context/domain-adapter denial, deterministic plan proposal and structural validator, critic recommendation and model-adapter trait.
- Deterministic fake adapter is the only adapter. No network or model provider is contacted.
- Caller-supplied principal/tenant/policy references are rejected; G04/G05/G06/CIW references are rejected until authoritative adapters exist.
- External provider, persistence, agent delegation and protected-effect flags are rejected.
- Evidence-required tasks abstain instead of fabricating citations.
- Result attribution is explicit; no G03 critic can claim G11 independent assurance.
- Locale tags are preserved, but language generation/translation quality is not implemented or asserted. Output bounds are conservative whitespace/byte guards, not tokenizer-exact token accounting.

### 11.2 Exact-HEAD CI evidence

Workflow: **Rust kernel verification**, run **#649**, run ID `42576912231`:
https://github.com/akefadaka-git/iroka/actions/runs/42576912231

Head SHA matched `9d68b580e06bb8335a626524d64b345c3a5a38aa`. Final conclusion: **SUCCESS**.

| Check | Result |
|---|---|
| cargo fmt --all -- --check | PASS |
| cargo check --workspace --all-targets --locked | PASS |
| no-default-features compile | PASS |
| cargo test --workspace --all-targets --locked | PASS |
| iroka-brain unit tests | 15 passed, 0 failed |
| iroka-kernel unit tests | 71 passed, 0 failed |
| other conformance tests | 2 passed, 0 failed |
| cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic | PASS |

### 11.3 B01 disposition and next dependency gates

**B01 code and CI verification: VERIFIED for the isolated synthetic increment.** This is not A4 security acceptance, independent assurance, merge approval, or production readiness. B01 remains an unmerged draft PR pending separate review and A4 evidence.

**B02 trusted composition remains BLOCKED** until exact authoritative G01/G02 APIs, tenant membership/revocation semantics, policy decision lifecycle, and Kernel integration baseline are reconciled. Do not add local substitute identity, tenant, policy or audit authorities.

B03–B05 remain gated on exact G04/G05/G06 contracts. B06 remains gated on PR #23's diverged ancestry and selective security review. B07 remains gated on G08 tenant-context and lineage closure. B08/B09 remain gated on G10/G11/G12 authoritative contracts, approved evaluation provenance and independent assurance.

No other package is represented as implemented by this record. No existing PR was merged or rebased; `main` was not modified. No deployment, signing, publication, production data, external provider or paid service was activated.
