# Native Cognition Build and Verification Plan

**Status:** Active implementation baseline — owner-authorized development
**Repository:** `akefadaka-git/iroka`
**Branch:** `feat/native-cognition-a3`
**Target:** Native, model-independent cognitive capabilities with a three-second bounded test mode.

## Governing constraints

- Native reasoning must execute without an external model or provider.
- External models, if later added, are optional adapters and are never counted as native reasoning.
- The Kernel remains the authority boundary. Reasoning output is a proposal, never an authorization.
- No network access, production credentials, protected side effects, self-deployment or self-modification in cognition tests.
- Every run must have explicit time, step, memory and input budgets; cancellation must fail closed.
- Memory, knowledge and learning must preserve provenance, classification, tenant boundaries, retention and auditability.
- Learning may propose changes but cannot adopt or deploy them autonomously.
- Main, production activation and deployment remain outside this implementation authorization.

## Engine roadmap

| Workstream | Required capability | Acceptance evidence |
|---|---|---|
| NCE-01 | Native symbolic inference, contradiction detection, provenance and bounded stop | Deterministic unit/property tests; no provider dependency |
| NCE-02 | Goal-directed search, unification, backward chaining and proof traces | Benchmark suite and soundness tests |
| NCE-03 | Constraint solving, arithmetic/relational reasoning and optimization | Reference problems with exact expected solutions |
| NCE-04 | Temporal, causal and uncertainty-aware reasoning | Explicit assumptions, calibrated uncertainty and contradiction tests |
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

## Initial scope delivered

NCE-01 is the first implementation increment. It deliberately does not claim completion of the remaining workstreams. The three-second setting is a runtime budget, not a claim that every problem can be solved in three seconds.
