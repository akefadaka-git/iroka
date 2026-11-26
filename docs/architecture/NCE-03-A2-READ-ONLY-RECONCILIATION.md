# NCE-03 — A2 Read-Only Reconciliation Record

**Document type:** A2 evidence and reconciliation record  
**Version:** 1.0.0  
**Status:** OWNER-GOVERNED A2 VERIFIED-CLOSED  
**A2 closure date:** 2026-11-26  
**Repository:** `akefadaka-git/iroka`  
**Branch:** `architecture/nce-03-a1-a2`  
**A1 baseline:** `c4e2ee740bd4a420887341755b17274ffe120331`  
**NCE-01/NCE-02 technical parent:** `d0801273231eccb7316d40af29d07a51c25eedf3`  
**NCE-03 implementation:** NOT STARTED

## 1. Owner decisions and stage disposition

The Owner explicitly froze NCE-03 A1 v1.0.0 on 2026-11-26. The six approved scope decisions and the full specification are recorded in [NCE-03-A1-CONSTRAINT-SOLVING-SPECIFICATION.md](NCE-03-A1-CONSTRAINT-SOLVING-SPECIFICATION.md).

The Owner subsequently approved the repository-sequencing recommendation on 2026-11-26:
- NCE-03 may be developed later on an isolated branch descended from the NCE-01/NCE-02 feature lineage at `d0801273231eccb7316d40af29d07a51c25eedf3`.
- Preserve PR #130 unchanged while this work proceeds.
- Do not modify `main`, rebase or rewrite the existing feature history, merge PR #130, or retarget it as part of NCE-03 A2/A3.
- This is approval of the technical branch strategy only. It is **not** A3 implementation authorization, PR merge approval or deployment approval.

With this sequencing decision, A2's architecture and repository-lineage reconciliation is VERIFIED-CLOSED. A3 remains gated on separate explicit Owner authorization.

## 2. Scope and method

Read-only inspection covered the repository tree, native cognition crate, NCE-01/NCE-02 contracts, Kernel adapters, resource/ingress precedent, PR #130 metadata and Git commit ancestry. No application source, existing feature branch, PR #130 or main-branch content was changed during the A2 inspection. The A1/A2 records were committed only to the separate documentation branch.

## 3. Evidence inventory

| Area | Observed evidence | Reconciliation |
|---|---|---|
| NCE-01 | `crates/iroka-cognition/src/lib.rs` | Deterministic propositional forward inference; no numeric domain or constraint solver |
| NCE-02 | `crates/iroka-cognition/src/backward.rs` | First-order terms, unification, Horn clauses and bounded backward search; no arithmetic evaluator, finite-domain propagator or optimizer |
| Cognition dependencies | `crates/iroka-cognition/Cargo.toml` | No external dependencies; native implementation direction is consistent |
| Kernel NCE-01 integration | `crates/iroka-kernel/src/advisory_cognition.rs` | One-way Kernel-to-cognition advisory pattern |
| Kernel NCE-02 integration | `crates/iroka-kernel/src/advisory_goal.rs` | Separate bounded goal-reasoning adapter |
| NCE-01 ingress contract | `docs/architecture/NCE-01-INGRESS-RESOURCE-CONTRACT.md` | Resource/admission precedent, not a solver contract or proof of deployed ingress |
| NCE-03 code | Repository tree at inspected baseline | No NCE-03 implementation, solver module, tests or prior NCE-03 code found |

## 4. Compatibility findings against frozen A1

1. **Finite-domain integer model:** no existing cognition numeric-domain contract conflicts with signed-64-bit finite inclusive domains.
2. **Exact linear arithmetic:** no existing arithmetic evaluator or competing numeric semantics found. Checked signed-128-bit intermediates are a new NCE-03 contract.
3. **Relations `=`, `!=`, `<=`, `>=`:** no conflict found in NCE-01 propositional or NCE-02 symbolic-goal contracts.
4. **Single optional linear objective:** no existing optimizer contract found.
5. **Deterministic bounded propagation/search:** consistent with the repository's deterministic/bounded direction, but NCE-03 must be its own engine rather than reuse NCE-01/02 search internals.
6. **Explicit exclusions:** floating point, nonlinear arithmetic, unbounded domains, scheduling/temporal logic and remote ingress are not required by the inspected NCE-01/NCE-02 contracts.
7. **Typed separation:** NCE-02 `Term` (`Symbol`, `Variable`, `Compound`) represents symbolic terms and unification. It must not be repurposed as the numeric execution model.

**Finding:** all six Owner-approved A1 decisions are compatible with the inspected NCE-01/NCE-02 architecture. No blocking contract conflict was identified.

## 5. Canonical architecture recommendation

- Place the native solver in an isolated `constraint` module inside `iroka-cognition`.
- Define typed finite integer domains, linear expressions, normalized relations, optional linear objective, solve configuration, result status and stop reason.
- Use checked signed-128-bit arithmetic for expression and bound evaluation.
- Use deterministic propagation and bounded deterministic search; independently verify every returned incumbent against the original model.
- Distinguish satisfaction, infeasibility, proven optimality and budget-limited outcomes.
- Keep any future Kernel adapter separate, in-process, bounded and advisory-only, preserving the one-way dependency `iroka-kernel` -> `iroka-cognition`.
- Do not add an external solver dependency without a documented comparison and separate Owner approval.
- Solver results must not grant identity, trust, policy, authorization, approval or protected-execution authority.

## 6. Resource-envelope disposition

The A1 ceilings are accepted as **provisional initial hard maxima**, not measured capacity:

| Resource | Provisional ceiling |
|---|---:|
| Variables per model | 128 |
| Constraints per model | 512 |
| Terms per linear expression | 256 |
| Values in one variable domain | 1,000,000 |
| Aggregate domain cardinality | 1,000,000 |
| Search nodes | 100,000 |
| Propagation operations | 1,000,000 |
| Solver wall-clock budget | 3 seconds |
| Retained/returned assignments | 1 incumbent |
| Variable identifier UTF-8 length | 128 bytes |
| Aggregate model input | 1 MiB |

No benchmark or adversarial-test evidence was produced during A2. These caps therefore must not be represented as proven performance or memory guarantees. Before or during A3 design, define exact accounting points for nodes, propagation work, input size, memory/retained state and time-budget enforcement. A3/A4 must validate boundaries and adversarial cases. Lowering ceilings may be proposed with evidence; increasing any ceiling requires separate explicit Owner approval.

## 7. Branch and source-lineage findings

At the inspected point:
- PR #130 is OPEN and DRAFT; head branch `feat/native-cognition-a3`, head `d0801273231eccb7316d40af29d07a51c25eedf3`.
- PR #130 targets `main`; recorded merge-base/base SHA: `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
- Main observed: `6b7004c897907f5ca40de58fee7222732fd7cde0`.
- Compare result: feature head 149 commits ahead of main; main one commit ahead of feature head.
- The single main-side commit is `6b7004c897907f5ca40de58fee7222732fd7cde0`; its only changed file is `docs/architecture/IROKA-A1-MASTER-BASELINE-AND-CLOSURE-REGISTER-v1.0.0.md` (428 additions, no deletions).
- No overlapping source-file change appears in that one-commit main-side delta.
- The A1/A2 documentation branch descends from feature head `d0801273231eccb7316d40af29d07a51c25eedf3`, preserving NCE-01/NCE-02 lineage without modifying PR #130 or main.

## 8. Owner-approved source-lineage disposition

On 2026-11-26, the Owner approved the recommendation to proceed with any later NCE-03 A3 work on an isolated branch descended from `d0801273231eccb7316d40af29d07a51c25eedf3`, leaving PR #130 unchanged and main untouched.

**A3 base recommendation:** use `d0801273231eccb7316d40af29d07a51c25eedf3` as the technical parent for a new isolated NCE-03 implementation branch. Preserve the A1/A2 documentation branch and the existing NCE feature branch. Do not rebase, cherry-pick, merge, retarget or otherwise rewrite PR #130 as part of NCE-03 work. This decision does not determine PR #130's eventual merge disposition.

## 9. A2 closure register

| Reconciliation item | Status |
|---|---|
| Confirm NCE-03 absence from inspected baseline trees | PASS |
| Identify NCE-01/NCE-02 capabilities and boundaries | PASS |
| Identify Kernel adapter pattern and one-way dependency direction | PASS |
| Identify resource-control precedent and NCE-03-specific controls | PASS |
| Reconcile all six frozen A1 decisions against inspected contracts | PASS |
| Record resource-ceiling evidence limitations and required A3/A4 validation | PASS — limitations documented; caps remain provisional |
| Compare feature lineage with main and identify exact main-side delta | PASS |
| Record Owner-approved isolated A3 technical parent | PASS |
| Preserve PR #130 and main without mutation | PASS |
| A2 architecture and repository-lineage reconciliation | VERIFIED-CLOSED |

## 10. Next stage gates

- **A1:** VERIFIED-CLOSED — Owner-frozen v1.0.0.
- **A2:** VERIFIED-CLOSED — read-only reconciliation and repository sequencing decision recorded.
- **A3:** NOT AUTHORIZED — requires separate explicit Owner approval. If authorized, create an isolated branch from the approved technical parent and implement only the frozen NCE-03 scope.
- **A4:** exact-SHA verification, correctness, deterministic behavior, resource-boundary/adversarial tests, regression tests and evidence-based performance/memory qualification.
- **A5:** separate deployment decision. Independent security review remains a pre-deployment gate, not a per-development-step gate.

**No NCE-03 source code, dependency, test, Kernel adapter, migration, merge or deployment has been created. PR #130 remains unchanged. Main remains unchanged.**
