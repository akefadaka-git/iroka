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


## Evidence reconciliation — 19 November 2026

The reference IROKA main SHA remains `1aea1447eadf1d827d702fd6c4034fa058aac21e`. Its root Cargo workspace contains only `crates/iroka-kernel`; it does not contain the proposed TALORA service API. The workspace license field is `LicenseRef-Proprietary`, and README.md states that no open-source license is granted. It is a reference only, not an approved TALORA integration baseline.

| Candidate workstream | Branch | Comparison to main | Result |
|---|---|---|---|
| G05 owner-approved memory contract | `architecture/g05-owner-approved-contract-v1` | Diverged, 1 ahead / 3 behind; merge base `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472` | Logical contract approved; implementation not started |
| G05 + G01/G02/G11 integration amendment | `architecture/g05-g01-g02-g11-integration-contracts` | Diverged, 4 ahead / 3 behind; same merge base `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472` | Owner-approved design decisions; canonical organization authority and owning-domain prerequisites remain open |
| G08 A2 contract | `architecture/g08-orchestration-a2-contract` | Diverged, 3 ahead / 302 behind; merge base `143311a655be68acea2700650b7f88c9fb085526` | Stale lineage and tenant-context blocker |
| CIW A2 contract | `docs/ciw-a2-integration-contracts` | Diverged, 14 ahead / 302 behind; merge base `143311a655be68acea2700650b7f88c9fb085526` | Documentation candidate; no accepted runtime integration |
| G03 Brain A2 contracts | `architecture/brain-a1-a2-proposal` | Diverged, 26 ahead / 118 behind; merge base `a709fc473b23494839417449e34bebf4cb8be77a` | Owner-approved design-only contract; not a merged runtime |

CIW PR #23 candidate head `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` was based on `813b24cbf81f049f2675fbb5492bdc9f262a9d87`; its comparison with current main was DIVERGED (172 ahead / 22 behind). It is not adopted.

The inspected contracts also record:
- G01's authenticated principal does not by itself resolve tenant membership or conversation ACLs.
- G02 signed/persisted policy lifecycle and canonical organization reviewer authority are not established as compatible owning-domain interfaces for TALORA.
- G05 logical memory contracts are not equivalent to an implemented memory API; organization reviewer operations fail closed until G01/G02 authority is available.
- G08 A2 design depends on an authoritative tenant resolver and current Kernel lineage.
- G04 executable retrieval and G06 perception interfaces were not verified in the inspected Brain A2 report.


### Exact runtime candidate heads and dependency split

| Candidate | Exact HEAD | Main comparison | Dependency finding |
|---|---|---|---|
| G01/G02/G11 Kernel A3 | `bb8b9f0ee81b59e793c30cc5c9a0357d3ed48e4a` | 0 ahead / 7 behind; ancestor of main | PR #13 merge is in main lineage; tenant/session/service API boundary remains incomplete |
| G05 reviewer/SQLite | `47edea227fdf1dc7b6ac1667b7e7f9cbb5b4cf39` | 155 ahead / 3 behind | G04/G05 workspace; SQLite `rusqlite 0.32.1`; separate lockfile |
| G05 PostgreSQL/G11 | `2bfac619b9601330b3343f86277bb5ba29ae22b2` | 334 ahead / 3 behind | Adds `postgres 0.19.12`, `postgres-native-tls 0.5.0`, `native-tls 0.2.12`, `tokio-postgres 0.7.18`; separate lockfile |
| G08 A3 coordinator | `2cfcf8db9437824cc8181ad8af1e8d819b936e2c` | 81 ahead / 3 behind | Kernel G08 modules on separate branch |
| CIW A3 conversation | `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | 172 ahead / 25 behind | Adds `iroka-conversation`, SQLite and separate workspace/lockfile |
| G03 Brain A3 core | `9d68b580e06bb8335a626524d64b345c3a5a38aa` | 10 ahead / 3 behind | Adds `iroka-brain`; no production model gateway is established |

The G05 SQLite and PostgreSQL branches are mutually DIVERGED (210 ahead / 31 behind; merge base `c57e4298005222ce476f685972062983c78d626f`). G05 PostgreSQL versus G08 is DIVERGED (81 ahead / 334 behind); G05 PostgreSQL versus Brain A3 is DIVERGED (10 ahead / 334 behind); CIW A3 versus G05 PostgreSQL is DIVERGED (356 ahead / 172 behind). The workspace lockfiles differ. Shared dependency versions do not prove API or build compatibility.

**D01 disposition:** RECONCILIATION PERFORMED; NO COMPATIBLE IMMUTABLE GRAPH SELECTED. This is a substantive integration blocker, not a reason to guess a baseline. Further read-only exact-commit, dependency and API verification is required. D01–D09 remain recorded exactly as approved; none authorizes A3, merge or A5.
