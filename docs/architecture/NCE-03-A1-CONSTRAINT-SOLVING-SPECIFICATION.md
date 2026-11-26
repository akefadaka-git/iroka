# NCE-03 — Constraint Solving, Arithmetic, Relational Reasoning and Optimization

**Document type:** A1 architecture/specification
**Version:** 1.0.0
**Status:** OWNER-APPROVED / FROZEN
**Owner approval:** Explicit approval received 2026-11-26 for the six v1 scope and solver recommendations recorded below.
**Repository:** `akefadaka-git/iroka`
**Branch:** `architecture/nce-03-a1-a2`
**Baseline:** NCE-01/NCE-02 feature lineage at `d0801273231eccb7316d40af29d07a51c25eedf3`
**Implementation status:** NOT STARTED; this approval does not authorize A3.

## 1. Owner-approved A1 decisions

The Owner approved all six recommendations on 2026-11-26:

1. **Finite-domain integer constraint solving** for v1; not a general symbolic-algebra or SMT engine.
2. **Exact integer linear arithmetic only.**
3. **Normalized relations:** equality (`=`), disequality (`!=`), less-than-or-equal (`<=`) and greater-than-or-equal (`>=`).
4. **At most one linear objective** per model, with minimize or maximize direction.
5. **Deterministic bounded solving:** propagation plus deterministic depth-first search and stable tie-breaking.
6. **Explicit v1 exclusions:** floating-point arithmetic, nonlinear arithmetic, unbounded domains, scheduling/temporal logic and remote ingress.

These decisions freeze the NCE-03 v1 scope and semantics. The detailed model, result semantics, authority boundary, acceptance criteria and stage gates below form the A1 specification.

## 2. Purpose

Define a native, deterministic, bounded constraint-solving capability that lets IROKA represent finite-domain integer variables, arithmetic relationships, relational constraints, and optimization objectives. NCE-03 complements rather than replaces NCE-01 propositional inference and NCE-02 first-order goal-directed reasoning.

The first release is an exact finite-domain integer constraint solver. It must either return a verified assignment/objective result or explicitly report that it could not complete within its configured resource budget. It must never turn an incomplete search into a claim of infeasibility or optimality.

## 3. Goals and non-goals

### Goals

1. Model named integer decision variables with finite, inclusive domains.
2. Express exact integer linear arithmetic over those variables.
3. Express equality, inequality and disequality relations.
4. Find satisfying assignments and report a deterministic solution.
5. Minimize or maximize a linear objective over feasible assignments.
6. Distinguish feasibility, infeasibility, optimality and incomplete search.
7. Enforce hard limits on model size, arithmetic, search nodes, time and retained results.
8. Provide independent solution validation and deterministic test fixtures.
9. Keep all results advisory and separate from Kernel authority.

### Explicit non-goals for v1

- Floating-point, decimal, probabilistic or approximate arithmetic.
- Unbounded integer domains or symbolic algebra.
- Nonlinear multiplication of decision variables, division, modulo, bit-vector/SMT semantics or arbitrary user code.
- Scheduling/calendar, temporal, causal or uncertainty reasoning (separate roadmap workstreams).
- Learning constraints from natural language or external models.
- Distributed solving, remote service ingress, persistent solver state or parallel nondeterministic search.
- Autonomous action selection, policy decisions, identity/trust decisions, approvals or protected side effects.

## 4. Mathematical model

### 4.1 Variables and domains

Each variable has a stable non-empty identifier and a finite inclusive integer interval `[lower, upper]`, where both endpoints are signed 64-bit integers and `lower <= upper`.

Unbounded domains are rejected. The number of values in any domain and the aggregate domain cardinality are subject to hard caps. Domain cardinality calculations use checked wider arithmetic; overflow is a validation error, never wraparound.

### 4.2 Linear expressions

A linear expression is a constant plus a bounded list of coefficient-variable terms:

`constant + Σ(coefficient_i × variable_i)`

Constants and coefficients are signed 64-bit integers. Decision variables are integers. Products are coefficient-times-variable only; variable-times-variable products are excluded. All evaluation and bound arithmetic use checked signed 128-bit intermediates. Any overflow produces a typed arithmetic/model error and cannot be treated as a satisfied constraint.

### 4.3 Constraints

A constraint compares one linear expression with zero using `Equal`, `NotEqual`, `LessOrEqual` or `GreaterOrEqual`. Strict comparisons may be normalized to non-strict integer comparisons only with checked arithmetic. Duplicate variable terms may be canonicalized deterministically; invalid identifiers, empty constraints and out-of-limit term lists are rejected.

### 4.4 Objective

A model may have no objective (satisfaction only) or exactly one linear objective with direction `Minimize` or `Maximize`. A solver must never report an objective optimum unless the search proves it. A feasible incumbent found before a budget stop is a valid feasible result, not a proven optimum.

## 5. Solver strategy

Use deterministic finite-domain constraint programming:

1. Model validation and canonicalization.
2. Safe interval/bounds propagation for linear constraints.
3. Deterministic variable selection (smallest remaining domain first, stable identifier tie-break).
4. Deterministic value ordering (ascending domain values).
5. Depth-first branch-and-bound for optimization.
6. Independent final assignment and constraint/objective verification.

Propagation is an optimization, not the source of truth: every reported solution must be checked against the original normalized constraints. Search is complete for models within declared budgets. The solver may return an incomplete result when a limit is reached.

No random seeds, parallel race-dependent decisions or wall-clock-dependent tie-breaking are allowed. If an incumbent objective is tied, use a stable lexicographic variable/value tie-break.

## 6. Result and status semantics

| Status | Meaning | Caller claim |
|---|---|---|
| `Satisfied` | Satisfaction model has a verified assignment and no objective | A valid assignment was found |
| `Infeasible` | Complete search exhausted all candidates with no satisfying assignment | No assignment exists within the declared model |
| `Optimal` | Objective model has a verified incumbent and complete proof no better assignment exists | Proven optimum |
| `FeasibleNotProvenOptimal` | A verified incumbent exists but search stopped at a budget/deadline | Feasible assignment only; not optimal |
| `UnknownBudget` | Search stopped without finding an assignment | Neither feasible nor infeasible is established |
| `InvalidModel` / typed error | Model rejected before solving or arithmetic overflow occurred | No reasoning conclusion |

A deadline, node, propagation or memory budget stop is always incomplete. It must not be translated to `Infeasible` or `Optimal`. Reports include stop reason, visited nodes, propagation count, elapsed time, incumbent (if any), and explicit completeness/optimality booleans derived from status.

## 7. Resource envelope and A2 validation

The following are provisional initial ceilings for A2 evidence-based validation. They are not benchmark claims. A2 may recommend lower limits with supporting rationale; increasing a ceiling or weakening a bound requires a separate explicit Owner decision.

| Resource | Provisional ceiling |
|---|---:|
| Variables per model | 128 |
| Constraints per model | 512 |
| Terms per linear expression | 256 |
| Values in one variable domain | 1,000,000 |
| Aggregate domain cardinality (sum of domain sizes) | 1,000,000 |
| Search nodes | 100,000 |
| Propagation operations | 1,000,000 |
| Solver wall-clock budget | 3 seconds |
| Returned assignments | 1 incumbent (best found) |
| Variable identifier UTF-8 length | 128 bytes |
| Model aggregate serialized/semantic input | 1 MiB |

The aggregate domain cardinality cap does not guarantee tractability; combinatorial growth is controlled independently by node and time budgets. The engine must reject caller configurations above hard ceilings. Checked counters must saturate or return a limit error, never wrap. A2 must resolve accounting semantics, per-solve time-budget enforcement and whether further reductions are needed before implementation.

## 8. API contract direction

Candidate concepts are `ConstraintModel`, `IntDomain`, `LinearExpr`, `Relation`, `Objective`, `ConstraintSolver`, `ConstraintSolverConfig`, `SolveRequest`, `SolveResult`, `SolveStatus`, `SolveStopReason` and typed validation/arithmetic/resource errors. Concrete Rust names and representations remain subject to A2 API reconciliation; do not expose mutable internal search state.

## 9. Integration and authority boundary

- Keep NCE-03 in `iroka-cognition`; Kernel may depend on cognition, never the reverse.
- NCE-03 must not depend on NCE-01 or NCE-02 internals. Shared low-level types require explicit compatibility analysis.
- Any future Kernel adapter must be separate, in-process, bounded and advisory-only, matching the NCE-01/NCE-02 separation.
- Solver output is a proposal/evidence artifact. It is not an identity assertion, policy decision, authorization, approval, execution grant or permission to cause a protected side effect.
- No network, filesystem, durable memory, external model, tool invocation or autonomous learning is included.

## 10. Verification and acceptance criteria

A3 implementation cannot be considered complete until all are demonstrated on an exact commit SHA:

1. **Model validation:** empty/duplicate IDs, inverted/empty domains, unknown variables, duplicate declarations, zero-term expressions, excessive arity/counts and aggregate payload limits.
2. **Arithmetic correctness:** negative values, zero, endpoint values, coefficient signs, checked i128 intermediate arithmetic and all overflow paths.
3. **Constraint correctness:** all four relations; boundary and contradictory combinations.
4. **Search correctness:** satisfying, unsatisfiable and multiple-solution models; deterministic tie-break; backtracking and domain propagation.
5. **Optimization correctness:** min/max objective, negative coefficients, tied optima, infeasible models and incumbent found before budget exhaustion.
6. **Status correctness:** exhaustive no-solution → Infeasible; exhaustive best solution → Optimal; budget stop with incumbent → FeasibleNotProvenOptimal; budget stop without incumbent → UnknownBudget.
7. **Independent oracle:** exhaustive enumeration for small randomly generated bounded models compared with a simple test oracle; seeded generation recorded and reproducible.
8. **Metamorphic tests:** variable renaming, constraint-order permutation, equivalent normalized constraints and objective sign reversal where applicable.
9. **Resource boundaries:** every count/domain/node/propagation/payload/time limit at boundary and one beyond; adversarial models with high branching and weak propagation.
10. **Determinism:** repeated same model/config returns identical status, assignment, objective and deterministic counters (timing excluded).
11. **Integration:** Kernel adapter tests prove cognition results cannot override Kernel policy denial or create authority.
12. **No regressions:** existing NCE-01/NCE-02 and authorization-contract suites pass.

Property tests use fixed recorded seeds. Benchmark evidence reports model shape, variables, constraints, domain cardinality, search nodes, propagation operations, elapsed time and memory/RSS methodology. A unit-test pass alone does not establish performance or process memory bounds.

## 11. Stage gates

- **A1 — VERIFIED-CLOSED:** the Owner-approved v1 scope and architecture are frozen by this document.
- **A2:** read-only repository/branch/contract reconciliation; identify conflicts, reuse boundaries, dependencies, canonical file paths and implementation plan. Close only after evidence reconciliation against this frozen A1.
- **A3:** implementation only after explicit A3 authorization and A2 closure.
- **A4:** exact-SHA automated verification and implementation acceptance.
- **A5:** separate deployment decision. Independent security review belongs at the pre-deployment gate, not at each development increment.

No A3 implementation, PR merge, main-branch modification or deployment is authorized by this A1 approval.
