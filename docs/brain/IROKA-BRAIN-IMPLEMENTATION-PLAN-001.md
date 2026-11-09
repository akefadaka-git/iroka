# IROKA BRAIN — Implementation Work Breakdown and Verification Plan

**Document ID:** IROKA-BRAIN-PLAN-001  
**Version:** 0.1.0-draft  
**Status:** Planning artifact; A3 NOT AUTHORIZED  
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
| A1 Brain specification | PARTIAL | Draft IROKA-BRAIN-A1-001 created; Owner review and freeze required |
| A2 read-only reconciliation | PARTIAL | IROKA-BRAIN-A2-001 records inspected branches/PRs and gaps |
| A2 contracts | NOT CLOSED | B-A2-01 through B-A2-10 and domain interface dependencies remain |
| A3 implementation | NOT AUTHORIZED | Requires A1 freeze, A2 closure and separate explicit authorization |
| A4 verification | NOT RUN | No Brain runtime implementation exists in this workstream |
| A5 release | NOT AUTHORIZED | Separate release gate |

## 10. Preservation and change-control rules

- Do not modify `main` during A1/A2.
- Do not modify existing PR branches or rewrite their history.
- Do not merge PR #12, #13, #16, #17, #18, #19–#24 as part of this work.
- Do not force-push, delete or rename existing branches.
- Do not duplicate G01/G02/G04/G05/G06/G08/G09/G11/G12 state or authority.
- Preserve existing CI and workflow permissions; no new workflow permissions without explicit review.
- No production keys, secrets, personal data or paid provider dependencies.
- Every new implementation increment must be isolated, reviewable and exact-SHA verifiable.

**Disposition:** planning only. A1 freeze, A2 closure, A3 authorization, A4 verification and A5 release remain separate decisions.
