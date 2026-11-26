# NCE-03 — A2 Read-Only Reconciliation Record

**Document type:** A2 read-only evidence and reconciliation record  
**Status:** PARTIAL — A1 reconciled; implementation-base disposition remains an Owner-governed repository sequencing gate  
**Repository:** `akefadaka-git/iroka`  
**Branch:** `architecture/nce-03-a1-a2`  
**Scan baseline:** parent commit `d0801273231eccb7316d40af29d07a51c25eedf3`  
**Main observed during scan:** `6b7004c897907f5ca40de58fee7222732fd7cde0`  
**NCE-03 implementation:** NOT PRESENT / NOT STARTED

## 1. A1 approval and reconciliation update (2026-11-26)

The Owner explicitly approved all six A1 recommendations on 2026-11-26. The companion A1 specification is now version 1.0.0 and OWNER-APPROVED / FROZEN at commit `c4e2ee740bd4a420887341755b17274ffe120331`.

Reconciliation against frozen A1:
- Finite-domain signed-64-bit integer variables: compatible with the existing cognition architecture; no conflicting numeric-domain contract found.
- Exact linear arithmetic and checked signed-128-bit intermediates: no existing arithmetic evaluator or competing numeric semantics found.
- Relations `=`, `!=`, `<=`, `>=`: no conflict found in NCE-01 propositional or NCE-02 symbolic-goal contracts.
- At most one linear min/max objective: no existing optimizer contract found.
- Deterministic propagation and bounded depth-first search: consistent with the repository's deterministic/bounded cognition direction; remains a new NCE-03 engine, not reuse of NCE-01/02 search internals.
- Exclusions (floating point, nonlinear arithmetic, unbounded domains, scheduling/temporal logic, remote ingress): no conflicting implementation requirement found in inspected NCE-01/NCE-02 contracts.

The provisional A1 ceilings are retained for A2 as initial maxima. A2 has not produced benchmark or adversarial-test evidence to validate their operational suitability. They must be treated as provisional caps, not measured capacity; lower caps may be proposed from evidence, while increases require explicit Owner approval. Exact accounting semantics for nodes, propagation work, memory and time must be specified before A3.

## 2. Scope and method

Read-only inspection of the repository tree, native cognition crate, current NCE-01/NCE-02 architecture contracts, Kernel adapters, existing resource/ingress contract, PR #130 metadata and Git commit ancestry. No application source, existing feature branch, PR, or main-branch content was changed as part of this reconciliation. The only new commits on this branch are this A2 record and the companion A1 draft specification.

## 3. Evidence inventory

| Area | Observed evidence | Reconciliation |
|---|---|---|
| NCE-01 | `crates/iroka-cognition/src/lib.rs` | Deterministic propositional forward inference; no numeric domain or constraint solver |
| NCE-02 | `crates/iroka-cognition/src/backward.rs` | First-order terms, unification, Horn clauses and bounded backward search; no arithmetic evaluator, finite-domain propagator or optimizer |
| Cognition dependencies | `crates/iroka-cognition/Cargo.toml` | No external dependencies; native implementation direction is consistent with project constraints |
| Kernel NCE-01 integration | `crates/iroka-kernel/src/advisory_cognition.rs` | Existing one-way Kernel-to-cognition advisory pattern |
| Kernel NCE-02 integration | `crates/iroka-kernel/src/advisory_goal.rs` | Existing separate bounded goal-reasoning adapter |
| NCE-01 ingress contract | `docs/architecture/NCE-01-INGRESS-RESOURCE-CONTRACT.md` | Useful resource/admission precedent, but specifically written for NCE-01 transport ingress; not proof that such ingress exists or a direct solver design |
| NCE-03 code/spec | Repository tree scan at baseline | No NCE-03 implementation, solver module, tests, API contract or prior NCE-03 specification found |
| Crate dependencies | Cognition manifest | No solver dependency currently selected or required by existing code |

## 4. Key compatibility findings

### 3.1 NCE-01 and NCE-02 do not already provide NCE-03

NCE-01 reasons over propositional literals and rules. It has no typed numeric values, finite domains, arithmetic expressions or objective semantics.

NCE-02 exposes `Term` (`Symbol`, `Variable`, `Compound`) and first-order unification over Horn clauses. These are symbolic terms, not typed signed integers or arithmetic expressions. Reusing `Term` as the numeric execution model would conflate symbolic unification with checked arithmetic and introduce ambiguous semantics. Recommendation: keep the NCE-03 numeric model typed and separate. A future explicit bridge may serialize numeric results into symbolic facts, but it must not make NCE-01/NCE-02 implicit dependencies of the solver.

### 3.2 Existing Kernel integration pattern is reusable, not yet a solver contract

NCE-01 and NCE-02 are integrated as separate, synchronous, in-process adapters with bounded requests and advisory-only results. This is the appropriate architectural precedent for a later NCE-03 adapter. It does not authorize a Kernel adapter in this A1/A2 work, nor does it settle the final public API.

### 3.3 Resource controls must account for combinatorial search

NCE-01 and NCE-02 have explicit step/depth/time and payload limits. NCE-03 additionally needs independent limits for variables, constraints, terms, individual and aggregate domain cardinality, propagation work, search nodes, arithmetic intermediate overflow and incumbent/result retention. A wall-clock budget alone is insufficient. Any optimization result must distinguish a feasible incumbent from a proven optimum.

### 3.4 No external solver dependency is present

The cognition crate currently has an empty `[dependencies]` section. The project roadmap calls for native, model-independent cognition. Recommendation: first evaluate a small in-crate deterministic finite-domain integer linear solver; do not introduce an external solver dependency without a documented comparison and explicit Owner approval.

## 5. Proposed canonical architecture direction

Subject to A1 Owner freeze:

1. Add an isolated `constraint` module inside `iroka-cognition`.
2. Define typed finite integer domains, linear expressions, normalized relations, optional linear objective, solve configuration, result status and stop reason.
3. Use checked signed 128-bit arithmetic for expression/bounds evaluation; return typed overflow errors.
4. Use deterministic constraint propagation plus deterministic bounded search. Every returned incumbent must be independently re-evaluated against the original model.
5. Keep feasibility, infeasibility, proven optimality and budget-limited outcomes distinct.
6. Add a separate Kernel adapter only after the native engine API and A3 implementation have passed their own tests; maintain the one-way dependency `iroka-kernel` -> `iroka-cognition`.
7. Keep solver output advisory and without authority-bearing capabilities.

The proposed A1 document captures a candidate finite-domain integer linear model, candidate limits and acceptance evidence. It remains a draft, not a frozen contract.

## 6. Branch and source-lineage findings

At scan time:
- PR #130 is OPEN and DRAFT; head branch `feat/native-cognition-a3`, head `d0801273231eccb7316d40af29d07a51c25eedf3`.
- PR #130 targets `main`; its recorded merge-base/base SHA is `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
- The current `main` ref observed in the same scan is `6b7004c897907f5ca40de58fee7222732fd7cde0`.
- GitHub compare reported the NCE feature head as 149 commits ahead and 1 commit behind current `main`; the single main-side commit is `6b7004c897907f5ca40de58fee7222732fd7cde0`.
- The current main tree scan did not contain the cognition crate or NCE-03 files; the feature branch contains the NCE-01/NCE-02 work.
- The A1/A2 documentation branch was created at exact feature-head SHA `d0801273231eccb7316d40af29d07a51c25eedf3` to preserve the current implementation lineage without adding NCE-03 docs to PR #130.

This divergence is a source-lineage/reconciliation item. Do not rebase, merge, cherry-pick, update PR #130, or alter `main` as part of this read-only A2 scan. Before NCE-03 A3 is based on a canonical branch, reconcile the one main-side commit and the disposition of the NCE-01/NCE-02 feature line. This is a repository sequencing issue, not evidence of an NCE-03 code conflict.

## 7. A2 disposition

| Item | Status |
|---|---|
| Confirm NCE-03 does not already exist on inspected main/feature trees | PASS |
| Identify existing NCE-01/NCE-02 capabilities and boundaries | PASS |
| Identify existing Kernel adapter integration pattern | PASS |
| Identify existing resource/ingress precedent | PASS |
| Recommend separate typed numeric model and independent engine | PASS — recommendation |
| Reconcile source branch against current main | PARTIAL — one main-side commit behind/ahead relationship must be resolved before A3 branch selection |
| Reconcile final API and resource envelope against frozen A1 | BLOCKED — A1 is still DRAFT |
| Final A2 closure | NOT READY |

## 8. Required next gates

1. Owner reviews and explicitly freezes or revises `NCE-03-A1-CONSTRAINT-SOLVING-SPECIFICATION.md`.
2. After A1 freeze, update this A2 record to reconcile every frozen decision against repository evidence and record the canonical implementation base.
3. Resolve the single main-side commit and NCE-01/NCE-02 branch disposition without disturbing unrelated work.
4. Only after explicit A2 closure and separate A3 authorization should implementation begin.

**No NCE-03 source code, dependency, test, Kernel adapter, migration, merge or deployment was created by this work.** Independent security review remains a pre-deployment gate, not a per-development-step gate.


## 9. Source-lineage decision and A3 base recommendation

A fresh compare was run after A1 freeze with:
- Base: NCE feature head `d0801273231eccb7316d40af29d07a51c25eedf3`
- Head: current main `6b7004c897907f5ca40de58fee7222732fd7cde0`
- Result: `diverged`; main is 1 commit ahead of the feature head, and the feature head is 149 commits ahead of main.
- Merge base: `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
- The only main-side commit in this comparison is `6b7004c897907f5ca40de58fee7222732fd7cde0`, whose sole changed file is `docs/architecture/IROKA-A1-MASTER-BASELINE-AND-CLOSURE-REGISTER-v1.0.0.md` (428 additions, no deletions). The compare shows no overlapping changed source file in that one-commit delta.

**Technical recommendation:** preserve the NCE-01/NCE-02 implementation lineage at `d0801273231eccb7316d40af29d07a51c25eedf3` as the technical parent for NCE-03. Do not rebase or rewrite the feature history merely to absorb the main-only documentation commit. The NCE-03 architecture branch currently descends from that feature head, so it preserves the needed cognition code and both A1/A2 records without modifying PR #130 or main.

**Governance limitation:** PR #130 remains OPEN and DRAFT, and its eventual disposition/merge target has not been approved here. Therefore this is a recommended technical parent, not a final authorization to merge, retarget PR #130, or establish a merged canonical mainline. A3 branch creation should wait until the Owner confirms the intended PR #130 lineage disposition or explicitly authorizes proceeding on the isolated feature lineage. No branch, PR or main ref was changed during this reconciliation.

## 10. Updated A2 disposition

| Item | Status |
|---|---|
| Confirm NCE-03 absence in inspected baseline trees | PASS |
| Identify NCE-01/NCE-02 capabilities and boundaries | PASS |
| Identify Kernel adapter pattern and one-way dependency direction | PASS |
| Identify resource-control precedent and NCE-03-specific controls | PASS |
| Reconcile all six Owner-approved A1 decisions against inspected contracts | PASS — no conflicting contract found |
| Reconcile proposed resource ceilings | PARTIAL — provisional ceilings retained; operational evidence/accounting semantics remain for A3 planning and verification |
| Compare feature lineage with main | PASS — exact one-commit main-side documentation delta identified |
| Select technical parent for NCE-03 | PASS — recommend feature head `d0801273231eccb7316d40af29d07a51c25eedf3` |
| Resolve PR #130 disposition / authorize canonical merged lineage | UNRESOLVED — no merge or retarget approval |
| Final A2 closure for implementation | NOT READY — Owner must decide whether A3 may proceed on isolated feature lineage while PR #130 remains open |

## 11. Required Owner gate

Confirm one repository-sequencing decision before A3:
- **Recommended:** allow NCE-03 A3 to proceed on an isolated branch descended from the NCE feature lineage at `d0801273231eccb7316d40af29d07a51c25eedf3`, preserving PR #130 unchanged and leaving main untouched; or
- Defer A3 until PR #130's lineage is separately resolved.

This A2 record does not authorize A3. Separate explicit A3 authorization remains required. No NCE-03 source code, dependency, test, Kernel adapter, migration, merge or deployment has been created. Independent security review remains reserved for the pre-deployment gate.
