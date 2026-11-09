# IROKA BRAIN — A2 Read-Only Reconciliation Report

**Document ID:** IROKA-BRAIN-A2-001  
**Version:** 0.1.0-draft  
**Status:** Read-only reconciliation performed; partial Owner decisions recorded; A2 closure pending  
**Assessment date:** 2026-11-09  
**Repository:** `akefadaka-git/iroka`  
**Reconciliation mode:** Read-only inspection of existing repository state and referenced branches/PRs  
**No changes made to:** `main`, existing branches, existing PRs, workflow settings, trust roots or runtime configuration.

## 1. Executive result

The destination repository is confirmed as the canonical target. The existing approved Genome and Kernel work provide a usable governance and identity foundation, but the Brain is not yet an implemented, integrated cognitive runtime.

The repository already contains:
- an Owner-approved IGACMS A2 genetic architecture baseline;
- a substantial Kernel/G01/G02/G11 A3 implementation on a dedicated, unmerged branch;
- an Amharic-first answer-only conversation vertical slice on a separate, unmerged branch;
- a proposed G08 orchestration A2 contract;
- proposed master strategy and frontier-intelligence roadmap documents;
- a separate, frozen E1 external-checkpoint architecture proposal.

The reconciliation supports a **new, bounded G03 cognitive workstream** that consumes existing domain contracts. It does not support creating duplicate identity, policy, audit, memory, knowledge, perception, orchestration or execution authorities.

**A2 outcome: PARTIAL.** Existing interfaces and workstreams were inspected, but final Brain contracts, dependency acceptance, exact cross-branch integration, and Owner disposition of open decisions remain outstanding. This report does not authorize A3.

## 2. Repository baseline

| Item | Read-only finding |
|---|---|
| Canonical repository | `akefadaka-git/iroka` |
| Repository ID | `1445234713` |
| Visibility | Public |
| Default branch | `main` |
| Default branch head at initial snapshot | `143311a655be68acea2700650b7f88c9fb085526` |
| Default branch head at intermediate recheck | `2304a793ce4a49464bc87f972c0e02fa07f75237` (PR #13 merge) |
| Default branch head at latest recheck | `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472` (PR #24 merge) |
| README blob | `a85ee805e35481b20087e8f32e451eb1bd4eb4a7` |
| Main strategy blob | `84f3f9ffddc8340132b76ab3161a6120e1817b58` |
| Root contents on main | `README.md`, `docs/IMPLEMENTATION_STRATEGY.md` |
| Branch inventory | 28 branch names returned in the initial search |
| Open PR inventory | 22 open PRs returned in the repository listing |
| Repository permissions | Admin, maintain and push available to connected destination account |

The current main branch is a documentation foundation, not a merged runtime baseline. Feature branches and PR heads must be treated as separate candidates; their code is not implicitly part of main.

The initial strategy on main defines eight logical cognitive subsystems and A1–A5 gates. It remains the governing baseline unless a later strategy is explicitly adopted through Owner governance.

## 3. Existing architecture ownership — preserve, do not duplicate

| Genome | Existing authoritative responsibility | Brain integration disposition |
|---|---|---|
| G01 Identity | Principal, credential, trust and identity lifecycle | Consume verified principal and tenant context; do not create a second identity system |
| G02 Governance | Policy, Owner authority, approvals and risk decisions | Ask the Kernel/policy boundary for decisions; never infer authorization |
| G03 Cognitive | Reasoning, planning and metacognition | Primary Brain implementation boundary; no complete Brain runtime found in inspected baseline |
| G04 Knowledge | Ingestion, retrieval, evidence and provenance | Consume evidence references; G04 owns source registry and retrieval |
| G05 Memory | Working, episodic and durable memory under policy | Consume/store only through G05 contracts; no parallel Brain memory database |
| G06 Perception | Multimodal input interpretation | Consume normalized observations; do not reimplement modality authority |
| G07 Agent | Agent identity, capability manifests and delegation | Brain may propose agent tasks; G07 owns identity and delegation scope |
| G08 Orchestration | Durable workflow/task state, retry, cancellation and recovery | Delegate durable work; do not build a second workflow engine |
| G09 Execution | Protected tools and external side effects | No direct Brain side effects; execution remains separately authorized |
| G10 Learning | Evaluation, feedback and validated learning proposals | Submit eligible evaluation records and improvement proposals |
| G11 Assurance | Security, audit, observability and independent verification | Consume/emit approved evidence; model critique is not independent assurance |
| G12 Evolution | Versioning, change approval, release and rollback | Propose changes only; cannot approve or deploy its own changes |

## 4. Inspected workstreams and evidence

### 4.1 Owner-approved IGACMS A2 baseline — PR #12

- PR: https://github.com/akefadaka-git/iroka/pull/12
- Head branch: `architecture/igacms-a2-owner-approved`
- Exact head: `a709fc473b23494839417449e34bebf4cb8be77a`
- Base branch: `architecture/a2-reconciliation-contracts`
- Initial snapshot: open, non-draft. Rechecked at 2026-11-09 06:38:47Z: GitHub records PR #12 merged by `akefadaka-git` into `architecture/a2-reconciliation-contracts`, merge commit `1746c0087eb324b4ae25266a6c321dd1614f2def`. The source branch remains at the approved head. This assistant did not perform that merge.
- Scope includes DNA/Genome/chromosome/gene/marker contracts, 12 chromosomes, historical principles/invariants, marker inventory, trust boundaries, threat model, conformance, migration and rollback documentation.
- A2 baseline records D01–D14 Owner decisions as approved.
- This branch is the starting point for the Brain architecture proposal to preserve the approved A2 source without changing it.

### 4.2 IGACMS A3 implementation — PR #13

- PR: https://github.com/akefadaka-git/iroka/pull/13
- Head branch: `feat/igacms-a3-implementation`
- Exact current branch head: `bb8b9f0ee81b59e793c30cc5c9a0357d3ed48e4a`
- Base: `architecture/igacms-a2-ci-base`
- Initial snapshot: open, ready for review. Rechecked at 2026-11-09 06:41:40Z: GitHub records PR #13 merged by `akefadaka-git` into `main`, merge commit `2304a793ce4a49464bc87f972c0e02fa07f75237`. This assistant did not perform that merge.
- Implemented scope includes machine-readable Genome contracts, canonical validator, signed attestation/Genesis verification, trust/anti-rollback controls, Owner approval binding and conformance tests.
- PR body records A3-R1 through A3-R5 remediation and exact-head workflow evidence.
- Push workflow run #42566864113: completed, SUCCESS, exact head `bb8b9f0...`.
- PR workflow run #42566869592: completed, SUCCESS, exact head `bb8b9f0...`.
- The PR body records formatting, locked compilation, no-default-features compilation, tests and Clippy passing.
- The PR #13 merge is recorded above. No production trust-root provisioning, Genesis activation or deployment is recorded as performed. The merge SHA has no Actions workflow run returned by the exact-head query; PR #13's pre-merge exact-head push/PR workflows passed.

**Brain disposition:** reuse the approved Genome and Kernel contracts. Do not copy or independently redefine Genome validation, identity, approval, trust or audit code. A3 branch is a separate unmerged candidate and is not silently adopted by this proposal.

### 4.3 G08 durable orchestration — PR #18

- PR: https://github.com/akefadaka-git/iroka/pull/18
- Branch: `architecture/g08-orchestration-a2-contract`
- Head: `04c3bab0ba4de2e634ce28612c90ed7451ef9ceb`
- Status: open draft; A2 proposal only.
- Contract covers tenant-scoped workflows/tasks, versioned state transitions, dependency DAG validation, idempotent creation, worker leases, retries, cancellation, restart recovery, persistence semantics and acceptance tests.
- It explicitly excludes G09 protected side effects and model/agent execution.
- Its read-only finding states that the inspected G01 VerifiedPrincipal at that time did not itself carry a tenant identifier or provide an authoritative tenant-membership resolver. It therefore marks multi-tenant G08 A3 NOT READY until a trusted tenant-context contract is approved.
- This dependency must be reconciled against current G01/CIW exact heads before any Brain/G08 implementation relies on it. Do not accept caller-supplied tenant IDs.

**Brain disposition:** consume G08 only through a reconciled, approved contract. The old G08 dependency finding is a known readiness condition, not permission for the Brain to invent tenant authority.

### 4.4 Conversational Interaction Workstream — PRs #19–#23

- Workstream definition PR #19: https://github.com/akefadaka-git/iroka/pull/19
- A2 integration contracts PR #20: https://github.com/akefadaka-git/iroka/pull/20
- A3 plan proposals PRs #21 and #22: open drafts.
- Bounded A3 implementation PR #23: https://github.com/akefadaka-git/iroka/pull/23
- CIW implementation branch: `feat/ciw-amharic-answer-only-chat`
- Exact current head: `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1`
- PR #23 is open draft and unmerged; its stated A3 scope is an Amharic-first/English answer-only conversation vertical slice, with owner/tenant-scoped SQLite persistence, session integration, policy/Kernel adapter, streaming, cancellation, bounded budgets and synthetic-only generation.
- PR #23 explicitly excludes production provider activation, tools/G09, agent delegation, durable memory, voice and multimodal interaction.
- Exact current-head push workflow #42562319218: completed, SUCCESS, head `69f3c181...`.
- Exact current-head PR workflow #42562324737: completed, SUCCESS, head `69f3c181...`.
- Earlier body evidence for head `642792d...` is superseded by the newer branch head; the current-head workflow runs were separately checked.
- CIW A2 contracts assign reasoning/response synthesis to G03, retrieval/provenance to G04, conversation context and memory lifecycle to G05, perception to G06, agent identity to G07, durable task lifecycle to G08, protected effects to G09, evaluation to G10, audit to G11 and versioning to G12.
- The current inspected CIW branch tree contains `crates/iroka-conversation` and Kernel/Genome files; no standalone G03 cognitive runtime, general model gateway or governed memory implementation was identified in the inspected path inventory.

**Brain disposition:** reuse CIW's answer-only interface and security constraints as a consumer of G03. Do not move conversation persistence, sessions, policy, audit or tenant ownership into the Brain. The synthetic generation path is not a production model gateway.

### 4.5 Frontier intelligence roadmap — PR #16

- PR: https://github.com/akefadaka-git/iroka/pull/16
- Branch: `docs/frontier-intelligence-roadmap-benchmarks`
- Head: `974fe1c57fea811b57d3cd1d98fb253d29fec6c2`
- Status: open draft; proposed strategy, not implementation authorization.
- P1 specifies provider-neutral model contracts, multiple adapters, capability/privacy/cost/availability metadata, routing, structured reasoning, assumptions, citations, uncertainty, planning, critique, verification, escalation and provider failure handling.
- P2 specifies governed knowledge and memory with provenance, freshness, hybrid retrieval, correction, retention, export/deletion, isolation and poisoning defenses.
- Benchmark suite B01–B14 includes reasoning, engineering, research, long-term memory, planning, agent/tool safety, multimodal perception, Amharic, trust, reliability, privacy, efficiency, accessibility and predictive quality.
- The document explicitly says it supplements the initial strategy and does not replace or reopen approved A1/A2 decisions.

**Brain disposition:** use the proposed benchmark taxonomy as candidate input, reconcile it with the approved conformance architecture and create Brain-specific traceable benchmark cases. Do not declare PR #16 adopted.

### 4.6 Master strategy v2.0 — PR #17

- PR: https://github.com/akefadaka-git/iroka/pull/17
- Branch: `docs/iroka-implementation-strategy-v2`
- Head: `76875d7ae2c08e0d4943acd607f3e3e9d0abd6b0`
- Status: open draft, proposed master roadmap.
- It retains the twelve Genome domains and A1–A5 governance and adds a seven-layer target architecture and P0–P8 product roadmap.
- It is explicitly awaiting Owner review/approval.

**Brain disposition:** reconcile relevant cognitive-plane content only; do not silently adopt or supersede the main strategy.

### 4.7 External checkpoint architecture — PR #24

- PR: https://github.com/akefadaka-git/iroka/pull/24
- Branch: `architecture/a4-03-external-checkpoint`
- Head: `71ca5a2b7dd2099c75719645d5be05c9122df566`
- Status: open draft; E1 architecture frozen in its own workstream.
- E1 defines checkpoint/manifest/receipt formats, independent verification, 2-of-3 witness quorum, immutable-retention controls and offline verification.
- PR states E1 VERIFIED-CLOSED — ARCHITECTURE FROZEN; E2 NOT AUTHORIZED; live external assurance remains unverified and overall A4 remains PARTIAL.

**Brain disposition:** use G11's approved evidence interfaces. Do not duplicate checkpoint, witness, receipt or retention systems in the Brain.

## 5. Reconciliation result: existing versus missing

| Capability | Existing evidence | A2 disposition |
|---|---|---|
| Genome and constitutional contracts | PR #12 Owner-approved A2 | RETAIN |
| Kernel identity/governance foundation | PR #13 A3 implementation branch | REUSE AFTER exact integration review |
| Model-independent cognitive runtime | Strategy/roadmap proposals only; no complete G03 runtime in inspected tree | MISSING |
| General model gateway | Proposed in PR #16; CIW uses synthetic generation | MISSING |
| Typed cognitive task/result contracts | Proposed concepts across strategy and CIW; no accepted Brain-specific contract | ADAPT / SPECIFY |
| Reasoning/planning/critique interfaces | Logical scope in strategy; no complete G03 implementation found | MISSING |
| Knowledge authority | G04 Genome ownership defined; implementation not verified in inspected A2 baseline | CONTRACT DEPENDENCY |
| Governed memory authority | G05 Genome/CIW ownership defined; durable memory excluded from CIW A3 | CONTRACT DEPENDENCY |
| Multimodal perception | G06 ownership defined; CIW multimodal deferred | CONTRACT DEPENDENCY |
| Durable orchestration | G08 A2 draft PR #18 | CONTRACT NOT FROZEN |
| Agent identity/delegation | G07 Genome ownership defined; no Brain agent runtime authorization | DEFERRED |
| Learning/evaluation | G10 ownership and benchmark proposals exist | SPECIFY / RECONCILE |
| Independent assurance | G11 contracts and checkpoint work exist | REUSE; preserve independence |
| Amharic-first requirements | A1 regional architecture in approved A2 baseline | RETAIN |
| Benchmark methodology | PR #16 proposed B01–B14; A2 conformance suite has normative test methodology | ADAPT; Owner acceptance needed |

## 6. Key gaps and risks

1. **G03 implementation gap:** no complete cognitive runtime, reasoning coordinator, planner/critic contract or general model gateway was identified in the inspected current baseline.
2. **Model gateway gap:** CIW's synthetic-only generator is a test/runtime slice, not a provider-neutral production gateway. No provider is selected or authorized.
3. **G04/G05/G06 contracts:** Brain integration depends on versioned source, memory and perception interfaces. Their authority must remain outside G03.
4. **G08 readiness:** tenant-context and Kernel-lineage dependencies in PR #18 require current exact-head reconciliation before implementation.
5. **CIW integration:** PR #23 is unmerged and A4 remains separate. Its conversation service must not become a substitute for G03 or G05.
6. **Independent assurance:** G03 critic output cannot replace G11 independent verification.
7. **Benchmark evidence:** PR #16 is proposed. No Brain benchmark suite has been executed; thresholds require approved workload, hardware, data and evaluation oracles.
8. **Amharic evaluation:** the regional architecture requires competent review and source fidelity. A reviewed Brain-specific corpus and oracle ownership were not found in this inspection.
9. **Data/provider policy:** no approved model/provider, paid service, production dataset or external data flow is selected.
10. **A1 freeze:** the Brain-specific open decisions in the A1 proposal require Owner disposition before architecture freeze.

## 7. Proposed implementation boundary and dependency order

The Brain workstream should be a G03-owned cognitive runtime with adapters to G01/G02/G04/G05/G06/G07/G08/G09/G10/G11/G12. The first implementation should be a non-side-effecting, synthetic-data vertical slice.

Proposed order after A2 approval and separate A3 authorization:

1. Typed task/result/evidence contracts and deterministic validation.
2. Bounded G03 reasoning coordinator with explicit stop/abstain/error states.
3. Planner and critic interfaces; no direct execution.
4. Model gateway abstraction and deterministic fake adapter; provider selection remains separate.
5. G04 evidence retrieval adapter contract.
6. G05 memory-context adapter contract (no new memory store).
7. G06 observation adapter contract.
8. G10 evaluation and benchmark harness.
9. G11 trace/assurance integration.
10. G08 workflow integration only after tenant-context and lineage dependencies are resolved.
11. G07 agents and G09 protected execution only in later separately scoped work packages.
12. G12 governed change/evolution proposal lifecycle.

## 8. A2 decision register

| ID | Decision required | Current status |
|---|---|---|
| B-A2-01 | Accept eight logical cognitive capability groups and their Genome mapping | APPROVED — D2, 2026-11-09; A1 v1.0.0 frozen |
| B-A2-02 | Confirm G03 critic versus G11 independent assurance boundary | APPROVED — D2, 2026-11-09; A1 v1.0.0 frozen |
| B-A2-03 | Approve task/result/evidence envelope schemas | PENDING OWNER |
| B-A2-04 | Approve initial deterministic/synthetic-only A3 vertical slice | PENDING OWNER |
| B-A2-05 | Resolve G04/G05/G06 interface versions and owners | UNRESOLVED |
| B-A2-06 | Resolve G08 tenant-context and Kernel-lineage dependencies | UNRESOLVED |
| B-A2-07 | Approve model gateway data-flow and provider-selection criteria | PENDING OWNER |
| B-A2-08 | Approve Amharic evaluation corpus governance and review process | UNRESOLVED |
| B-A2-09 | Approve benchmark families and workload-specific thresholds | PENDING OWNER |
| B-A2-10 | Confirm no paid provider, production data or production side effects in first increment | PROPOSED; OWNER CONFIRMATION REQUIRED |

## 9. A2 exit checklist

- [x] Canonical destination repository confirmed.
- [x] Main baseline and default branch recorded.
- [x] Approved IGACMS A2 baseline identified.
- [x] Relevant open PRs and exact heads inspected.
- [x] Genome domain ownership mapped to Brain integration.
- [x] Existing CIW slice and current exact-head workflows reconciled.
- [x] Existing G08 draft dependency finding recorded.
- [x] Proposed roadmap documents distinguished from approved architecture.
- [x] No existing branch, PR, main, workflow, trust root or runtime configuration was modified by this assistant. GitHub records PR #12 and PR #13 merges during this assessment window; these external repository state changes are not attributed to this Brain work.
- [x] Owner decisions B-A2-01 and B-A2-02 recorded as approved by D2.
- [ ] Remaining A2 decisions B-A2-03 through B-A2-10 resolved.
- [ ] G04/G05/G06 interface contracts and versions confirmed.
- [ ] G08 tenant-context and lineage dependencies resolved or explicitly deferred with accepted constraints.
- [ ] Dependency/provenance/license/data-flow assessment completed for the selected A3 increment.
- [ ] A2 closure approved by Owner.

**A2 status: PARTIAL — read-only reconciliation complete and cognitive contract proposal drafted; B-A2-01/02 approved, while formal schema acceptance, domain interfaces, G08/CIW lineage, evaluation governance and first-increment scope remain open.**

## 11. Final repository recheck — 2026-11-09

The repository changed after the initial read-only snapshot:

- PR #12 was merged into `architecture/a2-reconciliation-contracts` at `1746c0087eb324b4ae25266a6c321dd1614f2def` at 06:38:47Z, recorded as merged by `akefadaka-git`.
- PR #13 was merged into `main` at `2304a793ce4a49464bc87f972c0e02fa07f75237` at 06:41:40Z, recorded as merged by `akefadaka-git`.
- A subsequent main update merged PR #24 (E1 external-checkpoint architecture) at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472` at 06:47:29Z, with PR #24 recorded as merged by `akefadaka-git`. Its merge commit has parents `2304a793ce4a49464bc87f972c0e02fa07f75237` and `71ca5a2b7dd2099c75719645d5be05c9122df566`. D1 in this conversation explicitly confirms authorization for PR #12 and #13; it is not treated as a separate authorization record for PR #24.
- The new main merge commit has parents `143311a655be68acea2700650b7f88c9fb085526` and `bb8b9f0ee81b59e793c30cc5c9a0357d3ed48e4a`.
- Exact-head PR #13 push and PR workflows #42566864113 and #42566869592 both completed SUCCESS before merge. No Actions run was returned for merge commit #13 or the later main head #24; no post-merge exact-main CI PASS is claimed.
- The merges were not performed by this assistant. Owner subsequently confirmed D1 = YES on 2026-11-09, explicitly confirming separate authorization for both PR #12 and PR #13 merges. D1 authorization is now recorded; the merged commits remain unchanged.
- The latest main tree contains the Kernel foundation and IGACMS schemas plus the E1 checkpoint architecture, but no G03 runtime or verified G04/G05/G06 implementation was identified in the targeted path inventory.
- PR #18 G08 A2 contract remains draft, based on earlier main SHA `143311a655be68acea2700650b7f88c9fb085526`; its own section 323–334 records no G01 tenant resolver in the inspected Kernel and an integration-lineage blocker. Current main has advanced through PR #13 and PR #24, so G08 ancestry must be reconciled before stacking runtime work.
- PR #20 CIW A2 contract is draft and documents server-side tenant membership, G03 gateway boundary, G04 executable API as unreconciled, and separate G05/G06 ownership. PR #23 remains draft on an earlier Kernel base; current-main integration is not proven.
- The Brain A2 cognitive contract proposal is now present at `docs/brain/IROKA-BRAIN-A2-COGNITIVE-CONTRACTS-001.md`; it defines proposed task/result/plan/critic/gateway envelopes and records unresolved G01/G02/G04/G05/G06/G08/CIW dependencies. It is not Owner-approved.
- The Brain proposal branch remains based on the unchanged Owner-approved A2 source branch at `a709fc473b23494839417449e34bebf4cb8be77a`. Owner confirmed D2 = YES on 2026-11-09; A1 architecture v1.0.0 is now frozen on this proposal branch. The Brain PR remains documentation-only and unmerged.

This state change does not authorize any additional merge, deployment, production trust provisioning or Brain A3 implementation.

## 12. Owner decision record — 2026-11-09

- **D1 = YES:** Owner confirmed separate authorization for the PR #12 and PR #13 merges. The historical authorization gap is resolved. No merge was performed by this assistant.
- **D2 = YES:** Owner approved the IROKA BRAIN architecture proposal for A1 freeze. The A1 document is frozen as v1.0.0 on this branch.
- A1 is VERIFIED-CLOSED. This does not close A2 and does not authorize A3.
- B-A2-01 and B-A2-02 are approved by D2. Remaining A2 decisions require exact contract/dependency evidence and explicit disposition; approval of the architecture is not treated as blanket approval of implementation details.

## 10. Governance boundary

This report records findings; it does not:
- merge or close existing PRs;
- change the default branch or adopt PR #16/#17/#18/#20/#23;
- authorize G03/G04/G05/G06/G07/G08/G09/G10/G12 runtime implementation;
- activate an external model/provider or send production data;
- authorize agent delegation or protected side effects;
- change identity, trust roots, Genesis, policy, audit or witness configuration;
- authorize A4 closure, merge, signing, release, pilot or A5 deployment.

A3 requires separate explicit Owner authorization after A1 freeze and A2 contract closure. A4 verifies exact implementation heads. A5 remains a separate release authorization.


---

## 11. Post-assessment Owner decision and current candidate reconciliation — 2026-11-09

### 11.1 Owner disposition

- **D1:** YES — separate authorization for PR #12 and #13 merges was confirmed. This does not authorize other merges.
- **D2:** YES — A1 Brain architecture v1.0.0 approved and frozen.
- **D3:** YES — A2 cognitive contracts proposal approved as v1.0.0. A2 is VERIFIED-CLOSED for design/contracts only.
- **D4:** Broader cross-domain A3 scope direction accepted as the planning basis. This is not the separate explicit authorization to start A3 implementation.
- Merge, deployment, signing, publication, production activation and paid-provider activation remain unauthorized.

### 11.2 Current main and CIW candidate exactness

The latest comparison query confirms current `main` at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`.

PR #23 (CIW answer-only implementation) remains OPEN / DRAFT / UNMERGED:
- PR: https://github.com/akefadaka-git/iroka/pull/23
- Head branch: `feat/ciw-amharic-answer-only-chat`
- Current PR head SHA: `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1`
- Base branch: `feat/igacms-a3-implementation`
- Recorded base SHA: `813b24cbf81f049f2675fbb5492bdc9f262a9d87`
- Comparison of PR head to current main: **DIVERGED**, 172 commits ahead / 22 behind, merge base `813b24cbf81f049f2675fbb5492bdc9f262a9d87`.
- Current exact-head workflow lookup for `69f3c181...`: run `42562324737`, completed SUCCESS.
- PR description's older claimed verification head `642792d55...` does not match the current PR head. The current run evidence above is the relevant exact-head signal; full job logs and A4 security review remain outstanding.
- PR #23 changes 19 files, including Kernel identity/security-store code, new conversation domain, HTTP transport, tenant/session, policy/budget, browser UI and workflow configuration. It must not be transplanted wholesale or treated as a clean Brain baseline without file-level security review and selective ancestry reconciliation.

**Disposition:** PR #23 is a potentially reusable implementation candidate, not an adopted dependency. No PR #23 merge, branch rewrite, rebase, or code cherry-pick is authorized by the Brain A2 decision.

### 11.3 G08 and cross-domain integration gates

PR #18 remains an open draft A2 G08 contract with tenant-context and stale-base lineage blockers. CIW PR #20 provides useful A2 conversation contracts but its ancestry and assumptions must be reconciled against current main and the current Kernel. G04/G05/G06 executable APIs remain unverified in this Brain reconciliation. No G03 implementation may fabricate these APIs or create substitute stores.

### 11.4 A2 closeout interpretation

A2 is **VERIFIED-CLOSED for the Brain architecture and cognitive interface contract** following Owner approval. A2-C01 through A2-C07 remain **OPEN integration dependencies** for their respective future work packages; A2-C08/C09 remain **DEFERRED** to licensed corpus and representative benchmark approval. A3 may not bypass these dependencies. The broader A3 plan is recorded separately in the implementation plan.

No runtime Brain code was changed in this decision update. No merge or deployment occurred.
