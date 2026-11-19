# TALORA–IROKA A2 Decision Register

- **Register ID:** TALORA-IROKA-A2-DR-001
- **Version:** 0.1.0
- **Date:** 19 November 2026
- **Authority:** Owner-governed
- **Status:** OPEN — Owner dispositions required
- **Companion contract:** TALORA–IROKA Integration Contract v0.1.1
- **Scope:** TALORA integration decisions only; this does not close the wider IROKA OS/INL/VYRAQON A2 programme.

## Decision protocol

For each decision, record one disposition: APPROVE, AMEND, DEFER or REJECT. A recommendation is not approval. A blank disposition is pending. Any DEFER must state the dependent capability/work package that remains blocked and its reopening conditions. Record decision date, scope and immutable approval evidence. This register does not authorize implementation, merge, provider activation or deployment.

## Summary

| ID | Decision | Recommended default | Current disposition |
|---|---|---|---|
| D01 | IROKA integration baseline | Do not approve current main automatically; select one immutable compatible commit graph after component reconciliation | PENDING |
| D02 | Integration method | Private authenticated service API; no distributable SDK until separately reviewed and authorized | PENDING |
| D03 | Cross-project rights | API consumption only under explicit written Owner authorization; no source copying or redistribution absent express grant | PENDING |
| D04 | Deployment and residency | Hosted development/test profile first; no production topology or residency claim until reviewed | PENDING |
| D05 | Model provider | Fake/local deterministic adapter; live provider disabled by default | PENDING |
| D06 | Cost controls | Hard preflight quotas and ETB ceilings; no silent overrun, auto-top-up or paid provider activation without numeric approval | PENDING |
| D07 | Memory governance | Ephemeral task context by default; persistent project memory opt-in, project-scoped and deletable | PENDING |
| D08 | Amharic/English assurance | Amharic-first remains binding; no full-workflow claim until corpus, reviewers and acceptance tests are approved and passed | PENDING |
| D09 | SLO and support | No production SLO or support commitment until topology and operational owner are selected | PENDING |

## Detailed decisions

### D01 — Immutable integration baseline

**Question:** Which exact IROKA commit and compatible component graph may TALORA integrate?

**Evidence:** IROKA main reference SHA at reconciliation: `1aea1447eadf1d827d702fd6c4034fa058aac21e`. Current main workspace contains `iroka-kernel`; candidate G03/CIW/G05/G08/G11 implementations are on divergent branches. Some candidate workflow runs succeeded, but this does not prove a unified release.

**Recommendation:** Keep the reference SHA for documentation only. Select an integration baseline after exact component commits, dependency compatibility, build/test results and security boundaries are reconciled.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** A3 service integration and capability activation.

### D02 — API versus SDK

**Question:** May TALORA consume IROKA only as a private service, or also distribute an SDK?

**Recommendation:** Private authenticated service API only for initial integration. Consider an SDK separately after the interface stabilizes and source/license, versioning and supply-chain risks are approved.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** SDK packaging and client integration beyond a mock contract.

### D03 — Proprietary cross-project rights

**Question:** What rights does TALORA have to consume or reuse IROKA?

**Evidence:** IROKA is public but declares `LicenseRef-Proprietary`; public visibility is not a license.

**Recommendation:** Authorize only the minimum required service integration in writing. Source copying, vendoring, modification, SDK distribution and sublicensing remain prohibited unless expressly granted.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Source-level reuse, vendoring, packaging or redistribution. API integration also requires explicit service-use authority.

### D04 — Deployment and data residency

**Question:** Where and how will IROKA run for TALORA?

**Recommendation:** Hosted development/test only until data classification, jurisdiction, operator access, encryption/key custody, backup, recovery and regional residency are decided. Do not send private creative content to an unapproved environment.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Production deployment design and production data processing.

### D05 — Model-provider strategy

**Question:** Which provider may receive user-approved TALORA content?

**Recommendation:** No live provider by default. Use deterministic fake/local adapters for development and tests. Provider approval must cover region, retention, training, subprocessors, security, price, consent and deletion.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Live hosted inference and external private-content transmission.

### D06 — Numeric cost controls

**Question:** What are the Free, Premium and organization quotas and hard ETB spend limits?

**Recommendation:** No paid-provider activation until numeric per-task, per-user, per-organization and global limits are approved, including rate version, ETB FX source/timestamp, preflight estimation, circuit breakers and no-top-up behavior.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Paid inference and commercial quota enforcement.

### D07 — Memory governance

**Question:** What is retained as TALORA project memory, for how long, and how is it deleted?

**Recommendation:** Ephemeral task context by default. Persistent project memory must be explicit opt-in, tenant/project-scoped, provenance-bearing, correctable and deletable, with cache/index/backup treatment and deletion SLAs defined.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Persistent memory writes and cross-session retrieval.

### D08 — Amharic/English evaluation

**Question:** Who approves the corpus and what evidence permits a capability to be described as supported?

**Recommendation:** Preserve Amharic-first requirements. Approve corpus rights/provenance and competent reviewer authority. Publish support level per workflow (not_supported, input_only, basic_ui, reviewed_ui, full_workflow_verified). No full-workflow claim from script pass-through or generic model assertions.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Full Amharic/English capability claims and production language acceptance.

### D09 — SLO and support

**Question:** What availability, latency, recovery, incident response and support commitments apply?

**Recommendation:** Do not publish production SLOs or support commitments until topology, operating team, monitoring, on-call coverage, backup/recovery and incident procedures are defined and measured.

**Owner disposition:** PENDING  
**Owner value / rationale:**  
**Approval evidence:**  
**Dependent work blocked:** Production service-level commitments and A5 operational approval.

## Binding gate interpretation

1. Owner dispositions here do not authorize A3; A3 requires separate explicit Owner authorization.
2. Automated verification, secure engineering, scoped work packages and exact-SHA evidence remain required during A3.
3. Under Owner direction `OD-2026-11-17-IR-01`, one integrated independent security and architecture assessment occurs after implementation and A4 reconciliation, before A5. It is not a per-PR blocker.
4. A4 must reconcile implementation, tests, dependencies, SBOM, risks, exact commits and remediation.
5. A5 deployment, production keys, live provider activation and production data use remain subject to applicable separate Owner approval.
6. This register does not close IROKA's wider native OS, INL or VYRAQON architecture/conformance programme.

## Closure record

**Register status:** OPEN — no Owner dispositions recorded.  
**A2 recommendation:** PARTIAL; do not declare integration A2 closed until necessary design decisions are dispositioned and the contract is reviewed against them.  
**A3:** Not authorized.  
**A5:** Not authorized.
