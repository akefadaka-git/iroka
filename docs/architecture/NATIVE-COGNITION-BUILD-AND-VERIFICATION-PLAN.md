# Native Cognition Build and Verification Plan

**Status:** Active implementation baseline — Owner-authorized development
**Repository:** `akefadaka-git/iroka`
**Branch:** `feat/native-cognition-a3`
**Target:** Native, model-independent cognitive capabilities with bounded test mode.

## Governing constraints
- Native reasoning executes without an external model/provider.
- External models are optional adapters and never count as native reasoning.
- Kernel authority remains above cognition; reasoning output is a proposal, never authorization.
- No network, production credentials, protected side effects, self-deployment or self-modification in cognition tests.
- Every run has explicit time, step, memory and input budgets; cancellation fails closed.
- Memory, knowledge and learning preserve provenance, classification, tenant boundaries, retention and auditability.
- Learning proposes changes but cannot adopt or deploy them autonomously.
- Main, production activation and deployment are outside this implementation authorization.

## Engine roadmap

| Workstream | Required capability | Acceptance evidence |
|---|---|---|
| NCE-01 | Native symbolic inference, contradiction detection, provenance and bounded stop | Deterministic tests; no provider dependency |
| NCE-02 | Goal-directed search, first-order unification, backward chaining and proof traces | Soundness, recursion, occurs-check and budget tests |
| NCE-03 | Constraint solving, arithmetic/relational reasoning and optimization | Reference problems with exact expected solutions |
| NCE-04 | Temporal, causal and uncertainty-aware reasoning | Explicit assumptions, calibration and contradiction tests |
| NCE-05 | Cognitive workspace, decomposition, metacognition and critique | Adversarial and multi-step task evaluations |
| NCE-06 | Knowledge ingestion and evidence graph (G04) | Provenance, freshness, conflict and retrieval evaluations |
| NCE-07 | Governed working, episodic and durable memory (G05) | Isolation, retention, correction and deletion tests |
| NCE-08 | Perception adapters (G06), initially text and structured inputs | Input fidelity and source attribution tests |
| NCE-09 | Planning and orchestration (G03/G08), task graphs and recovery | Deterministic planning and bounded recovery tests |
| NCE-10 | Learning and self-evaluation (G10/G11) | Offline evaluation, regression gates and no silent adoption |
| NCE-11 | Agent specialization/delegation (G07) and authorized execution (G09) | Kernel-enforced capability and delegation tests |
| NCE-12 | Three-second cognition harness, cancellation and benchmark reporting | Repeated exact-SHA runs, deadline and cancellation evidence |

## Delivery gates
- A1: architecture, threat model, interfaces and measurable acceptance criteria.
- A2: reconcile existing branches and contracts; select canonical implementation path.
- A3: implement native engines in isolated branches.
- A4: exact-SHA unit, integration, property, adversarial, performance and security verification.
- A5: separate Owner decision; not authorized by this plan.

## Implemented increments

### NCE-01 — forward inference

- Deterministic propositional forward chaining with sorted rule IDs and fixed-point
  evaluation; cyclic rules do not create duplicate derivations.
- Positive/negative literals, four-valued query outcomes (`Entailed`, `Refuted`,
  `Unknown`, `Contradicted`), exhaustive contradiction reporting and per-fact
  derivation provenance.
- Defaults: 10,000 inference-step evaluations, 10,000 facts, 2,000 rules, 256
  premises per rule, three-second deadline; atom length capped at 256 UTF-8 bytes.
- Deadline checked inside premise evaluation; stop outcomes distinguish fixed point,
  deadline, step budget and fact budget.
- 24 dedicated tests include all 64 directed three-node graph topologies compared
  against reference reachability, a 32-edge adversarially ordered chain, 256-premise
  deadline interruption, 512 facts/512 rules, contradiction stability and budget
  boundaries.
- Exact-SHA verification: source SHA
  `3146962ca6532eafb5a98d1ea5875520035f7289`; Native Cognition CI #65 PASS;
  Rust kernel verification #2198 PASS. The workflows report 38 cognition tests,
  71 kernel tests and 2 authorization-contract tests, all passing, with formatting,
  compilation and Clippy successful.

- NCE-01 remains isolated from merge and deployment; this verification is not an
  Owner approval to merge or activate production.

- NCE-02: first-order backward chaining, unification, proof trees and bounded search.


### NCE-01 — Kernel advisory adapter integration

- Added a one-call, in-process adapter in `iroka-kernel` that consumes the
  `iroka-cognition` crate through a one-way workspace dependency.
- Adapter accepts bounded asserted facts, rules and query literals; returns the
  NCE-01 report and query observations with explicit complete/partial status.
- Default adapter caps: 1 MiB aggregate UTF-8 payload and 256 queries, in addition to
  the NCE-01 engine's hard fact/rule/premise/step/deadline ceilings.
- Six integration tests cover multi-step inference, provenance metadata, contradictions,
  partial results, input/query limits, and policy-denial isolation.
- Cognition remains advisory: no identity, policy, authorization, approval, audit,
  execution or protected side-effect interface is exposed.
- Exact-SHA CI and independent review remain separate acceptance gates. Remote ingress,
  raw transport parsing, concurrency admission and peak-RSS qualification remain NOT
  IMPLEMENTED.
