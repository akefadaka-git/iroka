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
- Compare: branch is 10 commits ahead of main, 0 behind (verify against latest comparison before any later integration).
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


## 12. A3-B02 trusted-composition read-only reconciliation — 2026-11-09

**Disposition: BLOCKED — authoritative tenant context and complete policy lifecycle are not available in the current main baseline. No B02 runtime code is authorized for composition until these gaps are closed.**

Exact inspected baseline: `main` at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`.

### 12.1 G01 identity findings

- `Ed25519CredentialVerifier::authenticate` is a public concrete verifier and returns opaque `VerifiedPrincipal` only after Ed25519 signature, issuer/key trust, exact audience, time claims and revocation checks.
- Trust-store construction is rooted in signed trust-bundle verification and anti-rollback storage. Revocation backend errors fail closed.
- `NoRevocations` is test/development-only.
- `docs/architecture/G01-IDENTITY-CONTRACT.md` explicitly states tenant trust administration is not implemented.
- No tenant membership resolver, tenant-context object, membership revocation contract, or principal-to-tenant binding API exists in the inspected main tree.

### 12.2 G02 governance findings

- `authorize_authenticated_with_owner_approval` is the production authorization-decision entry point. It checks the IGACMS baseline, exact principal/request subject binding, policy evaluation, optional signed Owner approval, approval replay/revocation and audit append.
- G02's signed Owner approval binds requester, capability, resource and exact policy version. Approval consumption is durable and replay-protected.
- `Policy` is explicitly an in-memory policy input. No signed/versioned policy publication, persistence, rollback protection, policy-owner lifecycle or policy retrieval interface is exposed by the inspected API.
- No live Owner public key or trust-root provisioning is recorded; the provisioning runbook says those ceremonies remain outstanding.
- An ALLOW is a decision only, not an execution grant. G09 remains the separate protected-effect authority.

### 12.3 Exact current API surface and limitations

Verified public Kernel surface includes:
- `Ed25519CredentialVerifier::authenticate(compact_token, expected_audience, now) -> VerifiedPrincipal`;
- `Policy::new(...)` and `evaluate(...)` as a deterministic in-memory policy primitive;
- `authorize_authenticated_with_owner_approval(...)` as the signed Owner-approval decision path;
- `SqliteSecurityStore` for trust/revocation/approval state;
- `SqliteAuditSink` as a local G11 audit adapter.

Not present in the inspected main tree:
- tenant membership resolver/context issuance and revocation;
- server-side tenant membership source-of-truth contract;
- signed/persisted policy lifecycle and policy snapshot loader;
- production provisioning evidence for actual trust roots, issuer keys, Owner keys and revocation service;
- approved Brain composition-root API that atomically binds principal, tenant, policy and audit context.

### 12.4 B02 stop conditions and acceptance gates

B02 must remain disabled until all of the following are supplied and reconciled against exact SHAs:

1. G01 tenant membership contract: authoritative membership source, tenant resolution from verified principal, membership revocation, freshness/cache rules, cross-tenant denial and failure behavior.
2. G02 policy lifecycle contract: signed immutable policy snapshots, signer authority, version monotonicity/rollback protection, activation/revocation, emergency-stop semantics and deterministic policy selection.
3. Kernel integration contract: one trusted composition root that obtains verified principal, resolves tenant, selects current policy, calls the signed Owner-approval decision path and appends G11 evidence without exposing constructors or bypass paths.
4. Production trust provisioning evidence: no secrets in repository; public key IDs/fingerprints, issuer/audience mapping, Owner subject/key validity and revocation backend operational evidence only.
5. Negative tests: caller-supplied tenant spoofing, missing/expired/revoked membership, stale policy, rollback, wrong audience, revoked credentials, unavailable revocation, approval replay, audit failure and tenant-isolation attacks.
6. G09 exclusion: G03 may receive a typed decision outcome, but cannot execute protected effects or treat ALLOW as an execution token.

**Current B02 status:** design reconciliation PARTIAL; implementation NOT STARTED / BLOCKED. Do not create a Brain-owned tenant resolver, policy engine, approval store, trust store or audit store as a workaround.


## 13. A3-B06 CIW candidate security and lineage review — 2026-11-09

**Disposition: NOT ADOPTED — PR #23 remains a review candidate.** The following findings are based on read-only inspection of PR #23's current head `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1`. No source changes were made to that branch.

### 13.1 High-severity authorization findings

**B06-F01 — Cancellation occurs before authorization (HIGH).**
- File: `crates/iroka-conversation/src/http.rs`, approximately lines 638–655.
- The cancel route calls `generations.cancel(turn_id)` before `service.cancel_turn(...)`.
- `service.cancel_turn` performs session, tenant, conversation ownership and Kernel authorization checks only after the in-memory cancellation signal has already been set.
- Impact: a caller who can identify an active generation ID may cancel it even when subsequent authorization denies the request. This is an authorization-before-effect ordering defect.
- Required remediation: authenticate, resolve tenant, verify conversation and turn ownership, and obtain the Kernel decision before signaling cancellation; preserve race-safe state transition and idempotent terminal handling.

**B06-F02 — Turn state mutation is not scoped to the authorized conversation (HIGH).**
- File: `crates/iroka-conversation/src/lib.rs`, approximately lines 575–600 and 1160–1188.
- `cancel_turn` verifies ownership of the supplied conversation but then calls `finish_turn(assistant_turn_id,...)`; the SQL update selects by turn ID alone and does not bind `conversation_id`, tenant, owner or assistant role.
- Impact: if a caller learns another conversation's turn ID, a request against a conversation they do own may mutate that other turn's state. The resource string passed to Kernel authorization does not repair the missing database predicate.
- Required remediation: perform one atomic conditional update joining/binding turn ID, conversation ID, tenant, owner and assistant role; verify exactly one authorized row changed. Add cross-tenant and cross-conversation negative tests.

### 13.2 Trust-authority and architecture findings

**B06-F03 — Tenant membership source is not cryptographically or monotonically bound (HIGH / ARCHITECTURE BLOCKER).**
- File: `crates/iroka-conversation/src/tenant_session.rs`, approximately lines 41–68 and 71–101.
- Public `provision_membership` accepts subject, tenant, state, version and checked_at directly. It does not authenticate the authoritative source, enforce monotonic version progression, or reject stale-version replacement. The version is stored but not used by `resolve_active_tenant`.
- Impact: the implementation relies on a comment and trusted host discipline for membership authority; stale or unauthorized provisioning can replace current membership. This is not yet the missing G01 tenant resolver contract.
- Required remediation: define an authenticated server-side membership synchronization contract, monotonic version/rollback protection, revocation/freshness rules and a non-request-facing provisioning boundary; do not treat this SQLite table as authoritative until those gates are proven.

**B06-F04 — Conversation crate introduces a second signed policy authority (HIGH / ARCHITECTURE BLOCKER).**
- File: `crates/iroka-conversation/src/policy.rs`, approximately lines 35–58 and 177 onward; `kernel_adapter.rs`.
- `PolicyTrustRoot::provisioned` accepts a public key and free-form provenance string; it does not itself verify Owner authorization for the policy root. The conversation crate defines its own signed policy bundle and epoch store, then constructs the Kernel's in-memory `Policy`.
- Impact: this creates a parallel policy-signing/version authority outside G02. The asserted Owner provenance is not cryptographically established by this API. It must not be adopted as a substitute for a Kernel-owned G02 policy lifecycle.
- Required remediation: move policy trust-root provisioning, signed policy verification, version/rollback controls and revocation into the authoritative G02/Kernel contract, or obtain a separately approved architecture amendment proving non-overlapping ownership. Do not simply accept the PR's `VerifiedPolicy` type as G02 authority.

### 13.3 Additional A4 security and operational gates

- **B06-F05 — Origin validation discards the scheme.** `http.rs` around lines 484–491 compares authority with Host but ignores the Origin scheme. Reconcile scheme/port against trusted ingress metadata and test HTTPS termination, non-default ports and malformed origins.
- **B06-F06 — Listener exposure is host-controlled.** `HttpServer::serve` accepts an arbitrary listener; loopback-only binding is a comment/runbook requirement, not an enforced invariant. Production host composition must enforce trusted bind address and TLS termination.
- **B06-F07 — Membership/session provisioning and policy-root provisioning need deployment-boundary controls.** No production membership synchronization source, Owner policy-root ceremony or live trust provisioning evidence is present in this PR.
- **B06-F08 — Budget state is process-local.** `BudgetGuard` keeps concurrency, rate and spend counters in memory. Restart resets these controls; it is not a durable production quota authority.
- **B06-F09 — G01 contract changes require reconciliation.** PR #23 modifies Kernel credential claims/session fields to add revocation-version semantics. Reconcile the changed wire contract, issuer migration, old-token behavior, key rotation and rollback against the canonical G01 contract before adoption.
- **B06-F10 — Browser/HTTP A4 remains incomplete.** The manual HTTP transport, cookie issuer, trusted TLS proxy, browser mutation routes, cancellation race, SSE reconnect/replay, retention and deployment host are not production-verified by a successful compile/test workflow alone.

### 13.4 Candidate CI and lineage

- PR #23: https://github.com/akefadaka-git/iroka/pull/23
- Current head: `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1`
- Current main at review: `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`
- Comparison: 172 commits ahead / 22 behind; merge base `813b24cbf81f049f2675fbb5492bdc9f262a9d87`.
- Exact-head workflow run #614 / ID `42562324737`: SUCCESS, but does not close the findings above or the stale-lineage issue.
- Candidate changes 19 files, including Kernel identity/security-store modifications, a new conversation domain, manual HTTP transport, session/membership/policy/budget code, browser UI and workflow changes.

**Stop condition:** do not merge, rebase, cherry-pick or transplant PR #23. First resolve B06-F01/F02, settle B06-F03/F04 against G01/G02 authority, complete F05–F10, reconcile exact lineage, and rerun exact-HEAD CI plus route-level security tests on a clean branch from the current approved main. Independent A4 review remains a separate gate.


### 12.5 Prior Owner-approved tenant authority decision carried forward

A prior Owner-approved D01 decision establishes that IROKA itself owns identity, sessions, tenants, authorization and audit. Tenant membership is server-resolved; client-supplied tenant IDs are selectors only and never authority; tenant binding on a created resource is immutable. AbayFlow is a reference implementation only, not IROKA's source of truth.

This resolves **ownership of the authoritative membership domain**: B02 must implement the tenant-membership authority inside IROKA's shared tenant-authorization layer, not adopt a standalone Conversation-owned directory or depend on AbayFlow. It does not yet supply the production membership lifecycle API, persistence semantics, administrative authorization, revocation behavior, multi-node store or atomic G11 audit integration. Those are B02 implementation requirements, not grounds to invent an external source.


## 14. A3-B02 tenant-authority implementation record — 2026-11-09

**Status: tenant-membership sub-slice IMPLEMENTED / exact-HEAD CI VERIFIED; overall B02 remains PARTIAL.**

- PR: https://github.com/akefadaka-git/iroka/pull/28
- Branch: `feat/brain-a3-b02-tenant-authority`
- Exact HEAD: `98b7f8c00d5bdcceb2d1588541f06924b039bb43`
- Base: `main` at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`
- Compare: 13 commits ahead / 0 behind main.
- Exact-head CI: Rust kernel verification #653 / run ID `42578543444`: SUCCESS.

### Implemented

1. Added Owner-signed `SetTenantMembership` command using the existing G02 Owner-key verifier and replay-protected command envelope.
2. Membership mutation and security-command ledger entry share one SQLite transaction.
3. Per-subject/per-tenant versions must strictly increase; stale versions fail closed.
4. `TenantMembershipResolver` accepts only G01 `VerifiedPrincipal` and resolves a requested tenant selector against the Kernel-owned membership ledger.
5. Opaque `TenantContext` is constructed only after active membership and freshness checks. Client tenant selectors cannot grant authority.
6. Negative and positive tests cover owner-signed provisioning, missing membership, tenant spoofing, inactive membership, stale/future timestamps, version rollback and command replay.

### Exact-head verification

- rustfmt: PASS
- workspace compile (all targets, locked): PASS
- no-default-features compile: PASS
- workspace tests: PASS — 78 Kernel tests and 2 conformance tests, zero failures
- Clippy with warnings denied: PASS

### Remaining B02 blockers

- Policy snapshots remain an in-memory `Policy`; signed policy publication, trusted policy lifecycle, monotonic activation/revocation, rollback protection and emergency-stop persistence are NOT IMPLEMENTED.
- Membership administration and policy changes are not yet atomically integrated with the G11 append-only audit chain.
- SQLite is single-node only; multi-node shared transactional authority is NOT IMPLEMENTED.
- No production Owner key/trust-root provisioning has been performed; only synthetic keys are used in tests.
- The single composition root binding verified principal → tenant context → active signed policy → Owner approval → G11 audit is NOT IMPLEMENTED.
- Independent security review and formal A4 verification are NOT RUN.

PR #28 remains OPEN / DRAFT / UNMERGED. No merge, deployment or production activation is authorized. B02 must not be marked closed until all remaining contracts, integration and A4 gates are satisfied.


### 14.1 Atomic Owner-key revocation hardening

A follow-up review found that the pre-existing Owner-key revocation check in `apply_security_command` was outside the transaction that consumed the command ID and applied the membership mutation. The check has now been repeated inside the same `BEGIN IMMEDIATE` transaction. A revoked Owner signing key therefore cannot race a membership update between verification and commit.

- New negative test: a revoked Owner key cannot subsequently change tenant membership.
- The command replay record, revocation check, membership mutation and security-command ledger row share the same transaction.
- Exact-head CI #653 includes this test and passed all checks.


## 14.2 A3-B02 G02 signed policy lifecycle — Owner-approved and CI-verified

**Owner approval:** 2026-11-09 — JCS/RFC 8785, distinct policy-signature domain, pending → G11 audit → active sequence, emergency stop inside signed snapshots, and Owner-signed G11-audited policy revocation all APPROVED.

**Implementation PR:** https://github.com/akefadaka-git/iroka/pull/29  
**Branch:** `feat/brain-a3-b02-signed-policy-lifecycle`  
**Base:** `feat/brain-a3-b02-tenant-authority` (PR #28)  
**Exact HEAD:** `7e925e49383864944ecad3eea7b790e3f3bc031d`  
**Compare:** 50 commits ahead / 0 behind the B02 base.

### Implemented and exact-HEAD verified

1. Immutable, versioned signed policy snapshot contract with unknown-field rejection.
2. RFC 8785 JCS canonical payload and `IROKA:G02:POLICY-SNAPSHOT:V1\0` signature domain separation.
3. G02 Owner-key verification, current revocation check, key validity, policy expiry and clock-skew enforcement.
4. Sorted unique capability allowlist and approval-required subset validation; empty allowlist is a valid explicit deny-all policy.
5. Monotonic epoch persistence; identical retry idempotency, conflicting digest rejection, rollback rejection, and higher-epoch supersession of abandoned pending snapshots.
6. G11 activation event binds epoch, canonical digest, Owner subject/key ID, policy version and previous active epoch. The G11 event is idempotent; active state is written only after the audit receipt succeeds.
7. Active reload validates persisted canonical bytes, digest, Owner metadata, signature, expiry and key revocation. A pending policy revocation makes active policy unavailable.
8. Owner-signed policy revocation stages, records a deterministic G11 event, then disables the active policy. Emergency-stop clearing requires a new higher-epoch signed snapshot and G11 confirmation.
9. `VerifiedPolicyContext` is opaque and the coordinator uses the same security store held by the Owner verifier; callers cannot supply a different store.

### Exact-head CI

- Workflow: [Rust kernel verification #686](https://github.com/akefadaka-git/iroka/actions/runs/42580872001)
- Run ID: `42580872001`
- Exact HEAD: `7e925e49383864944ecad3eea7b790e3f3bc031d`
- Conclusion: SUCCESS.
- rustfmt: PASS.
- Workspace compile (all targets, locked): PASS.
- No-default-features compile: PASS.
- Workspace tests: PASS — 90 Kernel tests + 2 conformance tests, zero failures.
- Clippy with warnings denied: PASS.

### Remaining blockers — B02 remains PARTIAL

- Current policy store defines one global active policy per Kernel instance. Tenant-specific policy partitioning and selection semantics are not yet specified or implemented.
- The end-to-end composition root binding G01 verified principal → G02 tenant context → active policy → Owner approval → G11 decision audit is NOT IMPLEMENTED.
- SQLite is a single-node adapter; shared multi-node transactional persistence and cross-node recovery are NOT IMPLEMENTED.
- Production Owner-key ceremony/provisioning and live policy activation are NOT DONE; tests use synthetic keys only.
- G11 external checkpoint anchoring and production recovery drills are NOT DONE.
- Independent security review and formal A4 acceptance are NOT RUN. Passing CI is not A4 assurance.

PR #29 remains OPEN / DRAFT / UNMERGED and depends on PR #28. No merge, deployment, production key provisioning or production policy activation is authorized.
