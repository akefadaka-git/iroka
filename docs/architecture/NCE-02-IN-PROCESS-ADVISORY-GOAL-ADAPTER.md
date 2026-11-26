# NCE-02 In-Process Advisory Goal Adapter

**Status:** IMPLEMENTED / AUTOMATED-VERIFICATION PASS on code SHA `e75d2cac50b96943bf6f562070f0522591a8fafd`  
**Repository:** `akefadaka-git/iroka`  
**Branch:** `feat/native-cognition-a3`  
**Implementation:** `crates/iroka-kernel/src/advisory_goal.rs`

## Purpose

Expose the existing NCE-02 first-order, goal-directed Horn-clause reasoner to Kernel-owned higher-level services through a synchronous, in-process adapter. The adapter accepts clauses and goals and returns proof trees, substitutions, and explicit search-stop outcomes.

NCE-02 remains advisory. A proof is reasoning evidence, not identity, trust, policy, approval, authorization, capability, or permission to execute an action.

## Public API

- `AdvisoryGoalAdapter`: stateless adapter configured with hard-bounded limits.
- `AdvisoryGoalConfig`: NCE-02 search limits plus aggregate input and goal-count limits.
- `AdvisoryGoalRequest`: Horn clauses and requested goal atoms.
- `AdvisoryGoalResponse`: ordered per-goal results.
- `AdvisoryGoalResult`: original goal and NCE-02 `SearchReport`.
- `AdvisoryGoalError`: typed adapter/configuration/search errors.

The adapter reuses the cognition crate's existing `BackwardReasoner`; it does not duplicate unification, standardization-apart, proof construction, or search logic.

## Hard limits

| Boundary | Default / hard ceiling |
|---|---:|
| Aggregate UTF-8 payload across clause IDs, predicates, terms and goals | 1 MiB |
| Goals per request | 256 |
| Clauses per request | 10,000 |
| Aggregate clause-body atoms | 50,000 |
| Search steps per goal | 20,000 |
| Search depth | 256 |
| Aggregate search deadline per request | 3 seconds |
| Term nesting accepted by adapter preflight | 64 |

The adapter rejects configuration values above these ceilings. It divides the request's configured search duration across the requested goals because the underlying `BackwardReasoner::prove` creates a fresh deadline for each call. This keeps the sum of per-goal search budgets within the request budget.

Input-size preflight uses bounded-depth traversal and saturating byte accounting before passing the request into the reasoner. The request's Rust objects are already allocated by the caller before the adapter receives them; this is not a raw transport/body parser limit, a heap/RSS guarantee, or a process-level concurrency control.

## Result semantics

- `Proven`: a proof tree and substitution are returned.
- `Exhausted`: search completed within its budgets without finding a proof.
- `Deadline`, `StepBudget`, or `DepthBudget`: result is partial; it MUST NOT be interpreted as proof that the goal is false or impossible.
- A response is complete only when every requested goal returned `Proven` or `Exhausted`.
- An empty goal list is a complete no-op.

## Authority and isolation

The adapter has no access to identity verification, Kernel policy evaluation, Owner approval, authorization decisions, capabilities, audit persistence, protected execution, network, filesystem, or durable memory. Downstream services must independently validate any proposed action through the governed Kernel authorization pipeline.

## Tests

Six adapter tests cover:
1. multi-step proof construction and proof-tree output;
2. variable substitution;
3. explicit partial result on a search-step budget stop;
4. aggregate payload rejection;
5. rejection of configuration above hard search ceilings; and
6. goal-count enforcement.

## Exact-SHA verification

Code SHA: `e75d2cac50b96943bf6f562070f0522591a8fafd`

- Native Cognition CI #271: PASS — https://github.com/akefadaka-git/iroka/actions/runs/45838990994
- Rust kernel verification #2407: PASS — https://github.com/akefadaka-git/iroka/actions/runs/45838991039
- Workspace tests: 157 passed, 0 failed (72 cognition, 83 Kernel, 2 authorization-contract).
- Formatting, workspace compile, production-feature verification, full tests and Clippy: PASS.

This verification is a development check, not independent security review, merge approval, deployment approval, or production activation.
