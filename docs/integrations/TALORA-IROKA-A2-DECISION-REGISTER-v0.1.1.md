# TALORA–IROKA A2 Decision Register

- **Register ID:** TALORA-IROKA-A2-DR-001
- **Version:** 0.1.1
- **Date:** 19 November 2026
- **Authority:** Owner-governed
- **Status:** D01–D09 OWNER DISPOSITIONS RECORDED; D01 reconciliation performed but no compatible immutable graph selected; A2 integration remains PARTIAL / NOT CLOSED
- **Companion contract:** TALORA–IROKA Integration Contract v0.1.2
- **Scope:** TALORA integration decisions only; this does not close the wider IROKA OS/INL/VYRAQON A2 programme.

## Decision protocol

For each decision, record one disposition: APPROVE, AMEND, DEFER or REJECT. A recommendation is not approval. A blank disposition is pending. Any DEFER must state the dependent capability/work package that remains blocked and its reopening conditions. Record decision date, scope and immutable approval evidence. This register does not authorize implementation, merge, provider activation or deployment.

## Summary

| ID | Decision | Recommended default | Current disposition |
|---|---|---|---|
| D01 | IROKA integration baseline | Do not approve current main automatically; select one immutable compatible commit graph after component reconciliation | APPROVED — RECONCILE |
| D02 | Integration method | Private authenticated service API; no distributable SDK until separately reviewed and authorized | APPROVED — API |
| D03 | Cross-project rights | API consumption only under explicit written Owner authorization; no source copying or redistribution absent express grant | APPROVED — API_ONLY |
| D04 | Deployment and residency | Hosted development/test profile first; no production topology or residency claim until reviewed | APPROVED — DEV_FIRST |
| D05 | Model provider | Fake/local deterministic adapter; live provider disabled by default | APPROVED — FAKE_LOCAL |
| D06 | Cost controls | Hard preflight quotas and ETB ceilings; no silent overrun, auto-top-up or paid provider activation without numeric approval | APPROVED — HARD_CAPS |
| D07 | Memory governance | Ephemeral task context by default; persistent project memory opt-in, project-scoped and deletable | APPROVED — OPTIN |
| D08 | Amharic/English assurance | Amharic-first remains binding; no full-workflow claim until corpus, reviewers and acceptance tests are approved and passed | APPROVED — REVIEWED |
| D09 | SLO and support | No production SLO or support commitment until topology and operational owner are selected | APPROVED — MEASURE_FIRST |

## Detailed decisions

### D01 — Immutable integration baseline

**Question:** Which exact IROKA commit and compatible component graph may TALORA integrate?

**Evidence:** IROKA main reference SHA at reconciliation: `1aea1447eadf1d827d702fd6c4034fa058aac21e`. Current main workspace contains `iroka-kernel`; candidate G03/CIW/G05/G08/G11 implementations are on divergent branches. Some candidate workflow runs succeeded, but this does not prove a unified release.

**Recommendation:** Keep the reference SHA for documentation only. Select an integration baseline after exact component commits, dependency compatibility, build/test results and security boundaries are reconciled.

**Owner disposition:** APPROVED — RECONCILE  
**Owner value / rationale:** Reconcile candidate components, dependencies, compatibility and verification evidence before freezing one immutable compatible commit graph; no current-main or candidate branch is automatically approved.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D01: RECONCILE”.  
**Dependent work blocked:** A3 service integration and capability activation.

### D02 — API versus SDK

**Question:** May TALORA consume IROKA only as a private service, or also distribute an SDK?

**Recommendation:** Private authenticated service API only for initial integration. Consider an SDK separately after the interface stabilizes and source/license, versioning and supply-chain risks are approved.

**Owner disposition:** APPROVED — API  
**Owner value / rationale:** Private authenticated service API is the approved initial integration method; no SDK distribution or SDK-first client integration is authorized.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D02: API”.  
**Dependent work blocked:** SDK packaging and client integration beyond a mock contract.

### D03 — Proprietary cross-project rights

**Question:** What rights does TALORA have to consume or reuse IROKA?

**Evidence:** IROKA main README states no explicit open-source license is granted; public visibility does not grant permission to copy, modify, redistribute or sublicense project material.

**Recommendation:** Authorize only the minimum required service integration in writing. Source copying, vendoring, modification, SDK distribution and sublicensing remain prohibited unless expressly granted.

**Owner disposition:** APPROVED — API_ONLY  
**Owner value / rationale:** API/service integration only is authorized within this project scope. No source copying, vendoring, modification, redistribution, sublicensing or broader source reuse is granted; repository proprietary status remains unchanged.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D03: API_ONLY”.  
**Dependent work blocked:** Source-level reuse, vendoring, packaging, SDK distribution or redistribution. API/service use is limited to the explicit TALORA project scope and does not grant source rights.

### D04 — Deployment and data residency

**Question:** Where and how will IROKA run for TALORA?

**Recommendation:** Hosted development/test only until data classification, jurisdiction, operator access, encryption/key custody, backup, recovery and regional residency are decided. Do not send private creative content to an unapproved environment.

**Owner disposition:** APPROVED — DEV_FIRST  
**Owner value / rationale:** Development/test deployment only. No production creative data, production topology or residency claim until separately reviewed and approved.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D04: DEV_FIRST”.  
**Dependent work blocked:** Production deployment design and production data processing.

### D05 — Model-provider strategy

**Question:** Which provider may receive user-approved TALORA content?

**Recommendation:** No live provider by default. Use deterministic fake/local adapters for development and tests. Provider approval must cover region, retention, training, subprocessors, security, price, consent and deletion.

**Owner disposition:** APPROVED — FAKE_LOCAL  
**Owner value / rationale:** Use deterministic fake/local adapters; live external providers remain disabled and private content must not be transmitted to them.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D05: FAKE_LOCAL”.  
**Dependent work blocked:** Live hosted inference and external private-content transmission.

### D06 — Numeric cost controls

**Question:** What are the Free, Premium and organization quotas and hard ETB spend limits?

**Recommendation:** No paid-provider activation until numeric per-task, per-user, per-organization and global limits are approved, including rate version, ETB FX source/timestamp, preflight estimation, circuit breakers and no-top-up behavior.

**Owner disposition:** APPROVED — HARD_CAPS  
**Owner value / rationale:** Require hard preflight per-task, per-user, per-organization and global caps, ETB ceilings and circuit breakers; no silent overrun, auto-top-up or paid provider activation absent numeric approval.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D06: HARD_CAPS”.  
**Dependent work blocked:** Paid inference and commercial quota enforcement.

### D07 — Memory governance

**Question:** What is retained as TALORA project memory, for how long, and how is it deleted?

**Recommendation:** Ephemeral task context by default. Persistent project memory must be explicit opt-in, tenant/project-scoped, provenance-bearing, correctable and deletable, with cache/index/backup treatment and deletion SLAs defined.

**Owner disposition:** APPROVED — OPTIN  
**Owner value / rationale:** Ephemeral task context by default; persistent project memory only by explicit opt-in, project-scoped and deletable, with retention/deletion controls defined before production use.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D07: OPTIN”.  
**Dependent work blocked:** Persistent memory writes and cross-session retrieval.

### D08 — Amharic/English evaluation

**Question:** Who approves the corpus and what evidence permits a capability to be described as supported?

**Recommendation:** Preserve Amharic-first requirements. Approve corpus rights/provenance and competent reviewer authority. Publish support level per workflow (not_supported, input_only, basic_ui, reviewed_ui, full_workflow_verified). No full-workflow claim from script pass-through or generic model assertions.

**Owner disposition:** APPROVED — REVIEWED  
**Owner value / rationale:** Amharic-first; full-workflow support claims require rights-cleared/reviewed corpora, competent reviewers and measurable acceptance tests.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D08: REVIEWED”.  
**Dependent work blocked:** Full Amharic/English capability claims and production language acceptance.

### D09 — SLO and support

**Question:** What availability, latency, recovery, incident response and support commitments apply?

**Recommendation:** Do not publish production SLOs or support commitments until topology, operating team, monitoring, on-call coverage, backup/recovery and incident procedures are defined and measured.

**Owner disposition:** APPROVED — MEASURE_FIRST  
**Owner value / rationale:** No production SLO or support commitments until infrastructure and operational performance are measured and operating ownership is defined.  
**Decision date:** 19 November 2026  
**Approval evidence:** Explicit Owner submission in ChatGPT on 19 November 2026, stating: “D09: MEASURE_FIRST”.  
**Dependent work blocked:** Production service-level commitments and A5 operational approval.

## Binding gate interpretation

1. Owner dispositions here do not authorize A3; A3 requires separate explicit Owner authorization.
2. Automated verification, secure engineering, scoped work packages and exact-SHA evidence remain required during A3.
3. Under Owner direction `OD-2026-11-17-IR-01`, one integrated independent security and architecture assessment occurs after implementation and A4 reconciliation, before A5. It is not a per-PR blocker.
4. A4 must reconcile implementation, tests, dependencies, SBOM, risks, exact commits and remediation.
5. A5 deployment, production keys, live provider activation and production data use remain subject to applicable separate Owner approval.
6. This register does not close IROKA's wider native OS, INL or VYRAQON architecture/conformance programme.

## Closure record

**Register status:** OWNER DISPOSITIONS RECORDED — all nine decisions approved on 19 November 2026.  
**A2 outcome:** PARTIAL / NOT CLOSED. D01 reconciliation has been performed, but the inspected candidate branches do not form one compatible immutable graph. D01 is therefore not satisfied by choosing current main or a collection of divergent branches. Contract v0.1.2 now records all nine Owner dispositions and the graph evidence.  
**A3:** NOT AUTHORIZED — separate explicit Owner approval required.  
**Merge:** NOT AUTHORIZED.  
**A5:** NOT AUTHORIZED — separate explicit Owner approval required.


## Live implementation branch reconciliation — 19 November 2026

This section supersedes the earlier design-branch comparison as the
current implementation-graph evidence. The detailed assessment is in
`TALORA-IROKA-A2-COMPONENT-RECONCILIATION-ASSESSMENT-v0.1.0.md`.

Reference IROKA `main`: `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
The main Cargo workspace contains only `iroka-kernel` and uses Rust
1.75.

| Workstream | Branch / exact head | Comparison / dependency evidence | Result |
|---|---|---|---|
| G03/G08 kernel | `implementation/a3-g08-workflow-graph` — `0680337b7dd0966374acd2649cd9197e56b8d92a` | 378 ahead / 3 behind main; Rust 1.75; G03 inference/premise/uncertainty and G08 workflow modules | Candidate subset; no exact-head PR run returned |
| G08 character workflow | `implementation/a3-g08-character-workflow-graph` — `0dbe0d58f312ef5ddf2be5d3f6b7dde6569d566b` | Rust 1.89.0; toolchain 1.100.0 | Separate MSRV-incompatible candidate |
| G05/G02/G11 | `feat/g11-provider-adapters-a3-rebased` — `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810` | 391 ahead / 3 behind main; Rust 1.75; PostgreSQL 0.19.12, postgres-native-tls 0.5.0, native-tls 0.2.12, rusqlite 0.32.1; 154 lockfile packages | Best G05/G02/G11 subset; no exact-head PR run returned |
| CIW | `feat/ciw-amharic-answer-only-chat` — `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | 172 ahead / 25 behind main; conversation crate and browser routes | Exact-head run 42562324737 succeeded; not the TALORA task API |
| BRAIN/G04/G05 | `feat/brain-a3-b04-g05-memory-core` — `b27816c1c3b172c0a7503d6602cddeaa6008c6cb` | 163 ahead / 3 behind main; kernel + G04 contract + SQLite G05 | Separate older implementation line |
| BRAIN cognitive core | `feat/inga-neurogenetic-a3-foundation` — `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d` | 27 ahead / 3 behind main; `iroka-brain` depends on serde/serde_json | Separate candidate |
| Localization | `feat/a3-4-localization-completion` — `d51a971d295e7b75e3d17fc51202d99c1db1abab` | 59 ahead / 3 behind main; adds localization module/tests | Separate divergent kernel line |

The G05/G11 branch descends from `feat/g05-http-host-a3`
(`c8991fc61170bc04d7aeaea390a76a85900c2232`, 13 commits) and
`feat/g05-postgres-g11-multiworker-a3`
(`2bfac619b9601330b3343f86277bb5ba29ae22b2`, 57 commits). Their
successful workflow runs apply to those older exact heads, not the
current G11 provider head.

Pairwise comparison shows G03/G08 versus G05/G02/G11 are diverged
(378 / 391 commits); CIW versus G05/G11 are diverged (400 / 172);
BRAIN/G05/G01/G02/G11 integration versus G05/G11 provider is diverged
(231 / 391); localization versus G03/G08 is diverged (378 / 59).
These are not fast-forward-compatible components.

The G05 host binds only to loopback behind a trusted TLS-terminating
proxy and exposes `/v1/g05/execute`. CIW exposes conversation and
generation/event routes. Neither provides the full TALORA
`/api/v1/capabilities` and `/api/v1/tasks` contract.

No deterministic model adapter was verified on the inspected refs.
G11 checkpoint HTTPS is not a model provider. No combined workspace
build, dependency resolution, migration test, SBOM or end-to-end API
test was run.

**D01 result:** RECONCILIATION PERFORMED; NO COMPATIBLE IMMUTABLE GRAPH
SELECTED.
