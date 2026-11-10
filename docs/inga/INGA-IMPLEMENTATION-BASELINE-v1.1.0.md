# IROKA Neurogenetic Intelligence Architecture (INGA)
 
**Document ID:** IROKA-INGA-IMPLEMENTATION-BASELINE-001  
**Version:** 1.1.0  
**Status:** OWNER-AUTHORIZED IMPLEMENTATION BASELINE — A3 IN PROGRESS  
**Canonical identity:** `iroka.dna`  
**Parent architecture:** IUGIA v1.0.0 proposal; approved IGACMS A2 baseline  
**Implementation base:** IROKA BRAIN B01 verified synthetic G03 core  
**Base branch:** `feat/brain-a3-b01-cognitive-core`  
**Base commit:** `9d68b580e06bb8335a626524d64b345c3a5a38aa`  
**Implementation branch:** `feat/inga-neurogenetic-a3-foundation`  
**Owner direction:** unified hybrid computational organism + digital evolutionary intelligence + artificial-life-inspired architecture; governed evolution  
**Authorization:** Owner instruction, 2026-11-10 — begin implementation and record this architecture as the implementation base  
**Merge/deployment:** not authorized; not performed

## 1. Purpose and baseline authority

This document establishes the implementation baseline for INGA. It extends, and does not replace, the existing IROKA genome and BRAIN architecture.

The approved twelve-chromosome Genome remains the ownership and authority model:

- G01 Identity
- G02 Governance
- G03 Cognitive
- G04 Knowledge
- G05 Memory
- G06 Perception
- G07 Agent
- G08 Orchestration
- G09 Execution
- G10 Learning
- G11 Assurance
- G12 Evolution

No additional chromosome is created by INGA. Brain regions, computational cell classes, neural circuits, networks, memory interfaces, learning proposals and adaptation proposals are subordinate structures mapped to the existing owners.

The existing IGACMS A2 baseline remains VERIFIED-CLOSED and unchanged. The BRAIN A1 and A2 design/contract gates remain preserved. This implementation is isolated from `main` and is based on the verified B01 synthetic cognitive core.

## 2. Unified architecture

INGA combines three architectural dimensions under one canonical identity:

1. **Computational organism:** integrated cognition, perception, memory interfaces, knowledge interfaces, agency boundaries and execution boundaries.
2. **Digital evolutionary intelligence:** versioned genetic structures, capability proposals, compatibility evaluation and verifiable lineage.
3. **Artificial-life-inspired computation:** bounded self-organization, functional differentiation, adaptation proposals, homeostasis monitoring and controlled regeneration.

These are computational design analogies. They do not assert biological life, biological DNA, subjective consciousness or achieved AGI/ASI.

## 3. Neurogenetic implementation model

The first implementation increment adds G03-owned, model-independent data contracts for:

- Computational cell classes: neuron, sensory/interneuron/motor/pyramidal/inhibitory roles and glial-inspired regulatory roles.
- Brain-inspired functional regions: executive control, language/semantic processing, spatial reasoning, visual/auditory processing, memory interface, routing, action selection, prediction/calibration and homeostatic monitoring.
- Neural connections and bounded neural-network topology.
- Memory-class requests and references without implementing G05 storage or consent.
- Learning proposals without implementing G10 training or model updates.
- Adaptation proposals without runtime self-modification or activation.
- Explicit governance boundaries and fail-closed validation.

Initial contracts use deterministic, synthetic fixtures only. Neural weights use bounded fixed-point integers rather than floating-point values in the contract surface. Graph validation rejects duplicate identities, dangling endpoints, duplicate directed edges, invalid weights and resource-limit violations.

## 4. Chromosome ownership and integration boundaries

| Capability | Owner | INGA responsibility | Explicit boundary |
|---|---|---|---|
| Identity and genome | G01 | Carry opaque identity/genome references | No local identity or trust-root registry |
| Governance | G02 | Represent required approval and policy references | No policy decisions or self-approval |
| Brain and cognition | G03 | Neural structures, circuits, cognitive coordination | No authority or protected execution |
| Knowledge | G04 | Consume future typed evidence references | No duplicate knowledge store |
| Memory | G05 | Define memory request/proposal envelopes | No memory content store, consent registry, reviewer registry or retention authority |
| Perception | G06 | Define future observation interfaces | No duplicate modality processing authority |
| Agent | G07 | No implementation in this increment | Agent identity/delegation remains excluded |
| Orchestration | G08 | Define coordination requirements only | No durable workflow/task-state store |
| Execution | G09 | No implementation in this increment | No tool invocation or protected side effects |
| Learning | G10 | Define learning/evaluation proposals | No model training, dataset ingestion or parameter activation |
| Assurance | G11 | Emit evidence references for owning assurance | No self-certification or duplicate audit store |
| Evolution | G12 | Define change proposals and lineage metadata | No autonomous promotion or canonical genome mutation |

Missing or unverified owner-domain APIs remain blocked. The implementation must not invent substitutes to bypass those dependencies. Existing G05 and G01/G02/G11 work on separate branches is not assumed merged or production-ready.

## 5. Constitutional and runtime invariants

1. Intelligence may propose; governance decides; authorization permits; execution acts; assurance verifies.
2. G12 cannot approve its own changes.
3. G03 cannot grant permissions or alter policy.
4. Memory access, durable activation, consent, retention, correction and deletion belong to G05 and its approved authorities.
5. Learning proposals do not imply training or model updates.
6. Adaptation proposals do not imply application, activation or self-modification.
7. A plan, neural output, model response or successful test is not an execution grant.
8. G09 protected effects remain outside this G03 increment.
9. G11 independent assurance cannot be claimed by a G03 critic or self-evaluation module.
10. Canonical genetic changes require explicit Owner approval under G02/G12 governance and applicable G11 assurance.
11. Experimental structures remain isolated from canonical genome state and production credentials.
12. Unknown contracts, missing evidence, failed verification and unavailable authorities fail closed.

## 6. Implementation increments

| Increment | Scope | Acceptance evidence |
|---|---|---|
| INGA-01 | Neurogenetic types, cell/region/synapse/network contracts | Unit tests, schema validation, bounded graph validation |
| INGA-02 | Brain-region and neural-circuit composition | Deterministic synthetic topology tests |
| INGA-03 | Memory interface contracts | G05 contract reconciliation; no duplicate authority |
| INGA-04 | Learning/evaluation proposal contracts | G10 contract reconciliation; no training side effects |
| INGA-05 | Adaptation and homeostasis proposals | Bounded policy and fail-closed adversarial tests |
| INGA-06 | Perception/world-model interfaces | G06/G04 contracts and provenance tests |
| INGA-07 | Metacognition, reasoning and model-federation integration | G03 contract conformance and model attribution |
| INGA-08 | Evolutionary lineage and genetic change proposals | G12/IGACMS compatibility and Owner approval enforcement |
| INGA-09 | Cross-domain composition and adversarial verification | Exact-HEAD CI and domain-owner conformance |
| INGA-10 | Independent assurance and release readiness | Separate A4 evidence; A5 remains separately authorized |

These increments refine the broader N01–N12 research packages. They do not silently close any existing B01–B09 dependency gate.

## 7. Explicitly excluded from this implementation increment

- Production model providers, API credentials or paid services.
- Real-user or production data.
- Model training, fine-tuning, federated updates or live neural-weight mutation.
- Durable memory storage or memory-content ingestion.
- Production identity, tenant, policy or trust-root provisioning.
- Agent delegation, autonomous tool use or G09 protected effects.
- Production Genesis activation, canonical genome mutation or release.
- Claims of consciousness, biological life, achieved AGI or achieved ASI.
- Merge, deployment or publication.

## 8. Verification and acceptance

The initial implementation is accepted only when:

- The module compiles with the existing locked workspace dependencies.
- Unit tests pass on the exact candidate HEAD.
- Formatting and Clippy pass on the exact candidate HEAD.
- Graph limits, identifier uniqueness, endpoint integrity and fixed-point weight bounds are tested.
- Memory, learning and adaptation types cannot create storage, training, activation or execution side effects.
- Governance fields are default-deny and cannot be caller-promoted to authority.
- Existing B01 tests remain passing.
- The branch and PR preserve the A2 baseline and all unrelated branches.

CI success is not independent A4 assurance. A4 and A5 remain separate gates.

## 9. Baseline record

This file is the canonical implementation planning baseline for INGA v1.1.0 on `feat/inga-neurogenetic-a3-foundation`. The branch begins from B01 exact HEAD `9d68b580e06bb8335a626524d64b345c3a5a38aa`. Every subsequent implementation record must identify its exact base, head SHA, changed files, tests, workflow evidence, unresolved dependencies and authorization boundary.

**Baseline status:** RECORDED — implementation in progress; not yet CI-verified; not merged; not deployed.

## 10. A3 implementation progress — deterministic neural evaluation

**Implementation commit:** `71daff4ec9e094d7cbb355761e33465c843b35f0`  
**Changed implementation file:** `crates/iroka-brain/src/neurogenetic.rs`

The first bounded computation path now evaluates feed-forward networks using signed fixed-point values:

- Input values and resulting activations are constrained to `-1_000_000..=1_000_000`.
- Each root cell requires exactly one caller-supplied input; unknown cells, duplicate inputs, non-root inputs and missing root inputs are rejected.
- Cells are evaluated in deterministic lexicographic topological order.
- Each destination activation is the normalized weighted sum of incoming source activations, truncated toward zero and clamped to the fixed-point range.
- Recurrent and general directed-graph topologies are not evaluated by this function.
- Quarantined cells are rejected.
- The result is a value object only; no state is persisted and no weights or genome structures are mutated.

Seven targeted unit tests were added for deterministic evaluation, clamping, missing/unknown/non-root/duplicate/out-of-range inputs, unsupported topology, quarantined cells and signed inputs. These tests are **NOT RUN** at this record: the current execution environment has no Rust toolchain, and no workflow run or status check was returned for implementation commit `71daff4ec9e094d7cbb355761e33465c843b35f0`. Compilation, formatting, Clippy and test status therefore remain **UNRESOLVED / NOT RUN**, not PASS.

This increment does not close INGA-02 or the A3 acceptance gate. Additional circuit composition, cross-domain integration and exact-HEAD verification remain outstanding.
## 11. A3 implementation progress — circuit composition

**Implementation commit:** `368e9a9c61f449fd317389e07de39ab209c7258c`  
**Changed implementation file:** `crates/iroka-brain/src/neurogenetic.rs`

Added `NeuralCircuit` and `CircuitEvaluation` contracts. A circuit binds to one network, declares its functional region, requires an exact match between its declared inputs and all zero-in-degree network cells, and exposes only its declared output activations. Validation rejects unsupported contract versions, mismatched network identity, missing or duplicate input/output identifiers and invalid output references. Evaluation delegates to the deterministic feed-forward evaluator and returns only the circuit interface outputs.

Four additional adversarial unit tests were authored for output projection, incorrect root declarations, duplicate interfaces, network mismatch, unknown outputs and unsupported versions. Together with the seven neural-evaluation tests, eleven new tests have been authored in these two increments. They remain **NOT RUN**; no compilation, formatting, Clippy or exact-HEAD CI result is claimed.

INGA-02 remains **PARTIAL**. Circuit composition currently provides a single-network boundary, not cross-network orchestration, recurrent-state execution, distributed/federated computation or production cognition.

