# IROKA Neural Network Infrastructure Architecture (INNIA)

**Document ID:** INNIA-A1-ARCH-001  
**Version:** 0.1.0  
**Status:** Owner-requested A1 architecture proposal; pending review and freeze  
**Repository:** aефadaka-git/iroka  
**Normative relationship:** Subordinate to IROKA ZERO constitutional principles, the twelve-chromosome Genome, the Governed Kernel and approved IGACMS contracts.

## 1. Purpose and architectural position

INNIA defines the neural-computation infrastructure through which IROKA may execute native and externally hosted models, coordinate specialized neural capabilities, ground inference in governed knowledge, evaluate learning proposals and scale computation across local and cloud resources.

INNIA is an infrastructure architecture, not a claim that IROKA already owns or operates a trained foundation model, a production neural runtime, GPU clusters or autonomous online learning.

IROKA remains model-independent. Models produce candidate representations, predictions, embeddings, classifications, plans or generated content. They do not establish identity, grant authority, determine policy, authorize protected effects or change canonical architecture.

**Constitutional operating rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.

## 2. Scope and non-goals

### In scope
- Neural model lifecycle: registration, provenance, versioning, evaluation, approval, serving, retirement and rollback.
- Inference runtime and model/provider adapters.
- Neural capability routing and composition.
- Context, retrieval and memory interfaces.
- Offline training, fine-tuning and controlled adaptation pipelines.
- Multimodal processing interfaces.
- Hybrid local/cloud placement and distributed execution.
- Resource, cost, latency, privacy and reliability controls.
- Model security, evaluation, observability and reproducibility.
- Integration with INGA, IGACMS and the G01–G12 Genome.

### Explicit non-goals for this A1 proposal
- Training a foundation model from scratch.
- Selecting or activating a paid provider.
- Provisioning production GPUs, cloud accounts, production credentials or trust roots.
- Enabling production data ingestion, online weight updates or autonomous self-modification.
- Merging, replacing or rewriting existing INGA, IGACMS, BRAIN, CIW, Kernel or Android implementation work.
- Authorizing A3 implementation, A4 closure, merge, release or A5 deployment.

## 3. Constitutional invariants

1. **Kernel supremacy:** All protected capabilities, data access and side effects remain subject to the Governed Kernel and G01/G02/G09/G11 controls.
2. **No model authority:** Model output is untrusted input, never an authorization decision or identity assertion.
3. **Provider independence:** Provider-specific SDKs and protocols remain behind replaceable adapters.
4. **Fail-closed boundaries:** Invalid, missing, expired, revoked or ambiguous authorization blocks protected operations.
5. **Tenant isolation:** Tenant, workspace, project, principal, purpose and data-classification scope must be preserved end-to-end.
6. **Provenance:** Every model, dataset, adapter, prompt/template, evaluation and deployed artifact has traceable origin and version.
7. **Reproducibility:** Evaluation and release records bind to immutable source, configuration, model and dataset identifiers.
8. **Controlled learning:** Training and adaptation produce candidate artifacts; promotion requires evaluation and the required human/Owner authorization.
9. **No silent mutation:** Running models cannot mutate their own weights, policy, tools, trust roots or canonical architecture.
10. **Data minimization:** Private content is processed only for an approved purpose, location and retention period.
11. **Bounded resources:** Token, memory, time, concurrency, accelerator and monetary limits are enforced outside the model.
12. **Evidence-based status:** No capability is described as implemented or production-ready without exact-commit and test evidence.

## 4. Logical architecture

INNIA is divided into a trusted control plane and an untrusted/replaceable computation plane.

### 4.1 Trusted control plane
- **Governed Kernel (G01/G02/G09/G11):** principal verification, policy evaluation, capability grants, approval, revocation, execution authorization and audit.
- **Model Registry and Artifact Ledger (G01/G04/G11/G12):** immutable model identity, provenance, version, license, source, artifact digest, evaluation status and lifecycle state.
- **Policy and Placement Controller (G02/G08/G11):** determines whether a task may run, where it may run and which data classes may be exposed.
- **Evaluation and Promotion Authority (G10/G11/G12):** validates candidate artifacts and records approval; it does not allow a model to approve itself.
- **Observability and Evidence Service (G11):** records trace IDs, decision references, model/version, resource use, errors and integrity-protected evidence with sensitive-data redaction.

### 4.2 Computation plane
- **Inference Runtime:** executes approved model artifacts in isolated, resource-bounded workers.
- **Model Adapter Gateway:** normalizes interfaces to local models, remote providers and specialized inference engines.
- **Neural Capability Router:** selects an approved capability/model based on task type, quality, data classification, residency, latency, resource ceiling and availability.
- **Cognitive Orchestrator (G03/G08):** composes reasoning, planning and specialist tasks; it can propose operations but cannot authorize them.
- **Context and Retrieval Adapters (G04/G05):** retrieve only authorized, provenance-bearing knowledge and memory.
- **Perception Adapters (G06):** normalize text, image, audio and other supported modalities into typed observations with source metadata.
- **Training and Evaluation Workers (G10):** isolated, offline-by-default jobs for dataset validation, fine-tuning, evaluation and artifact packaging.
- **Distributed Compute Scheduler:** dispatches bounded jobs to approved local or cloud workers without transferring authority to workers.

### 4.3 Conceptual request path

Client/Agent → Kernel authentication and policy → task classification → placement and capability routing → authorized context retrieval → isolated inference → output validation and evidence capture → policy check for any requested effect → response.

The model may suggest a tool action. A separate Kernel-mediated authorization step must decide whether that action can occur.

## 5. Neural computation portfolio

The following are candidate capability families, not mandatory separate models or an instruction to implement every architecture.

| Family | Potential use | Integration constraint |
|---|---|---|
| Transformer / encoder-decoder | Language, instruction following, translation, summarization | Model provenance, prompt-injection controls, output validation |
| Embedding models | Semantic indexing and retrieval | Embeddings are not authority; access checks apply before and after retrieval |
| Vision encoders / multimodal models | Image and document understanding | Source metadata, privacy classification, confidence and human review |
| Speech models | Speech recognition and synthesis | Consent, language coverage, audio retention and speaker-identity safeguards |
| Graph neural networks | Structured relational inference | Explicit graph provenance and tenant-scoped graph access |
| CNN / vision models | Image classification and spatial features | Dataset rights, robustness and calibrated confidence |
| Recurrent / state-space models | Sequential, temporal or long-context workloads | Workload-specific benchmarks and bounded state |
| Symbolic-neural hybrids | Combine deterministic rules/logic with learned representations | Deterministic policy remains outside learned model authority |

Architecture selection must be empirical. Do not adopt a model family merely because it is fashionable or present it as superior without benchmark evidence.

## 6. INGA and IGACMS relationship

### INGA
INGA is the proposed native neurogenetic/neural computation substrate within IROKA. Its responsibility is to define computational primitives and safe execution semantics for IROKA-native neural structures. INGA must expose versioned interfaces and remain subordinate to Kernel policy and assurance.

Existing INGA work is an isolated A3 candidate, not a production runtime. Its current implementation and verification status must be reconciled from its exact branch/PR head before any integration claim.

### IGACMS
IGACMS governs the genetic/constitutional architecture and controlled evolution of IROKA. It is not an inference engine, model registry or substitute for G01/G02/G11. Its previously Owner-approved A2 baseline must remain immutable unless a separately authorized amendment is approved.

The boundary is:
- INGA computes.
- INNIA coordinates neural infrastructure and lifecycle.
- IGACMS governs permitted genetic architecture/evolution.
- The Kernel authenticates, authorizes and enforces.
- G11 verifies and records evidence.

No duplicate identity, authority, policy, audit or trust-root implementation may be introduced in these subsystems.

## 7. Model and artifact lifecycle

All model artifacts follow an explicit state machine:

DISCOVERED → QUARANTINED → PROVENANCE_REVIEWED → EVALUATED → APPROVED → STAGED → ACTIVE → DEPRECATED → RETIRED.

Failure or revocation may move an artifact to REJECTED or QUARANTINED from any pre-active state, and to DISABLED from an active state.

Minimum model manifest:
- Stable model ID and semantic version.
- Architecture/family and intended capability.
- Publisher, source reference and acquisition date.
- License and usage restrictions.
- Immutable artifact digest and signature/attestation where available.
- Training-data provenance and declared limitations where known.
- Runtime/container requirements and supported hardware.
- Evaluation suite/version, metrics and results.
- Data classification and residency constraints.
- Safety profile, known risks and approved use cases.
- Approval record, approver, scope and validity.
- Rollback target and retirement/revocation reason.

Unknown provenance, incompatible license, missing integrity evidence or failed safety evaluation blocks promotion.

## 8. Learning and adaptation pipeline

Default pipeline:

DATA_PROPOSAL → RIGHTS_AND_PURPOSE_REVIEW → CLASSIFICATION → SANITIZATION → DATASET_VERSION → TRAIN_OR_ADAPT → HELD_OUT_EVALUATION → ADVERSARIAL_EVALUATION → HUMAN_REVIEW → SIGNED_CANDIDATE → APPROVED_PROMOTION → MONITOR → ROLLBACK_OR_RETIRE.

Requirements:
- Training data must have documented source, permission, purpose, classification and retention.
- User/private data is excluded from training unless a separate, explicit, valid authorization permits it.
- No online weight update in the production inference path by default.
- Dataset and artifact versions are immutable and digest-bound.
- Evaluation includes regression, robustness, security, bias/quality, language/script coverage and resource performance as applicable.
- Candidate performance must be compared with a recorded baseline and acceptance thresholds.
- Promotion requires the designated approval; high-impact or constitutional changes require Owner approval.
- Rollback must restore a previously approved artifact without changing governance state.

## 9. Memory and knowledge integration

Neural infrastructure consumes knowledge and memory through G04/G05 interfaces; it does not own their canonical records or retention policy.

- Retrieval authorization occurs before content is supplied to a model.
- Retrieved records retain source, timestamp, digest where appropriate, confidence, classification, tenant and access metadata.
- Untrusted retrieved content is explicitly marked as data, not instruction.
- Context windows are assembled under purpose, scope, minimization and token limits.
- Generated summaries and embeddings retain links to their source evidence and transformation history.
- Memory write proposals are validated and authorized by G05 policy; model output alone cannot write durable memory.
- Correction, deletion, retention expiry and access revocation must propagate to derived indexes/caches under defined consistency rules.
- Sensitive content is excluded from telemetry by default.

## 10. Hybrid and distributed execution

Placement options:
- **On-device/local:** private, offline, low-latency or resource-constrained tasks.
- **Owner-controlled self-hosted:** workloads requiring controlled infrastructure or specialized accelerators.
- **Approved cloud:** elastic workloads where data residency, confidentiality, contractual and cost controls permit.
- **External provider:** optional replaceable capability for explicitly permitted data classes and tasks.

For every dispatch, the placement decision binds task ID, principal, tenant/workspace/project, purpose, data classification, approved region, model ID/version, worker identity, resource limits, deadline and authorization reference.

Workers receive only the task-scoped input and short-lived execution grant. They cannot mint credentials, widen scope, dispatch arbitrary child jobs or persist data beyond the job contract.

Distributed execution must support bounded queues, idempotency, deadlines, cancellation semantics, retry ceilings, backpressure, worker attestation where required, and auditable result correlation. A worker response is untrusted until validated.

## 11. Security and threat controls

Threats include prompt injection, malicious model output, model/adapter substitution, poisoned datasets, model theft, membership/inference leakage, cross-tenant retrieval, tool escalation, worker compromise, supply-chain compromise, denial of service and covert data transfer.

Minimum controls:
- Isolated workers, least privilege and read-only model artifacts.
- Signed/digest-pinned model and runtime artifacts.
- Egress allowlists and explicit provider/data-sharing policy.
- Input/output schema validation and content trust labels.
- Kernel authorization for every protected read or side effect.
- Tenant isolation across retrieval, cache, queue, logs and artifact access.
- Secret isolation; no credentials in prompts or model context.
- Rate, token, memory, accelerator, concurrency and time quotas.
- Prompt-injection and adversarial robustness testing.
- Dataset and model provenance review, vulnerability scanning and SBOM.
- Redacted, integrity-protected audit records and incident containment.
- Revocation and emergency disable for model, provider, worker or capability.

## 12. Performance, cost and reliability objectives

No numeric production SLO is frozen by this proposal. A2 must define workload classes and measurable targets using representative, permissioned test data.

Measure at minimum:
- End-to-end and per-stage latency (p50/p95/p99).
- Throughput, concurrency, queue wait and cancellation latency.
- Task success and task-specific quality.
- Calibration, abstention and uncertainty quality.
- Retrieval relevance and evidence coverage.
- Memory/accelerator utilization and model load time.
- Cost per successful task and cost ceiling enforcement.
- Availability, timeout, retry and provider-failure rates.
- Local/offline capability and degraded-mode behavior.
- Amharic/Ethiopic, English and regional language performance.

A request must be rejected, degraded safely or routed to an approved alternative when it exceeds resource or cost limits. No paid service or top-up is assumed by this architecture.

## 13. Observability and evaluation

Every task trace should bind:
- Trace/task ID and timestamp.
- Authenticated principal and tenant scope (pseudonymized where appropriate).
- Kernel decision and policy version references.
- Model/adapter/runtime versions and artifact digest.
- Prompt/template and configuration version identifiers, not sensitive prompt content by default.
- Context source references and classification.
- Placement, worker identity and region.
- Token/resource use, latency and cost attribution.
- Output validation, refusal/abstention and error status.
- Human review and promotion decision where applicable.

Evaluation suites must include deterministic contract tests, task benchmarks, adversarial tests, regression tests, language/script tests and operational load tests. Scores must not be collapsed into a single opaque “intelligence” metric.

## 14. Amharic-first and African regional requirements

IROKA's binding Amharic-first Ethiopian/African architecture applies to all neural components:
- Preserve Ethiopic script, Unicode normalization and original source text.
- Evaluate Amharic morphology, orthography, dialect variation and code-switching.
- Support multilingual retrieval and cross-language evidence without silently replacing the source language.
- Measure OCR, speech, translation and generation separately; do not infer support from a model's marketing claims.
- Keep language, calendar, time zone, identity, document and jurisdiction profiles configurable and versioned.
- Ethiopia defaults must not be hardcoded into shared African-core logic.
- Human review is required for consequential translation, legal, financial, identity and official-document interpretation until an approved assurance threshold is demonstrated.

## 15. Integration contracts and dependency order

| Dependency | INNIA responsibility | Authoritative owner |
|---|---|---|
| Identity and trust | Consume verified principal and artifact identity | G01 |
| Governance and approvals | Consume decisions and scoped grants | G02 |
| Cognitive runtime | Execute model-backed reasoning under contract | G03 |
| Knowledge | Retrieve provenance-bearing evidence | G04 |
| Memory | Read/write through governed interfaces | G05 |
| Perception | Normalize modality observations | G06 |
| Agents | Consume registered capabilities and delegation | G07 |
| Orchestration | Submit bounded inference and training jobs | G08 |
| Execution | Request protected effects only through Kernel | G09 |
| Learning | Produce candidate datasets/models and evaluation evidence | G10 |
| Assurance | Expose test, security and operational evidence | G11 |
| Evolution | Version and promote approved architecture/artifacts | G12 |

Implementation dependency order:
1. Reconcile current Kernel, identity, authority and assurance contracts.
2. Freeze model manifest, adapter, task, context and inference result contracts.
3. Establish deterministic local inference/test adapter and resource boundaries.
4. Integrate INGA only after exact-head code and test reconciliation.
5. Integrate G04/G05 context and memory through their canonical owners.
6. Add multimodal adapters and evaluation harness.
7. Add offline training/evaluation and artifact promotion.
8. Add distributed workers and optional provider adapters.
9. Complete end-to-end security, reliability, language and performance assurance.

## 16. A1/A2/A3/A4/A5 gates

### A1 — Architecture proposal
- This document and its interfaces reviewed for consistency with IROKA DNA and G01–G12.
- Confirm INGA/IGACMS boundaries and existing work inventory.
- Record unresolved architecture decisions and risk ownership.
- Owner freezes the version before A2.

### A2 — Evidence and contracts
- Inspect exact branch/PR heads and current main.
- Reconcile INGA, BRAIN, CIW, Kernel, G04/G05, G10/G12 and relevant Android/service work without assuming they are integrated.
- Produce interface schemas, threat/control/test traceability, model manifest schema and lifecycle contract.
- Complete dependency, license, provenance and hardware/runtime review.
- Define data classes, placement policy, resource budgets and workload SLOs.
- Obtain explicit Owner approval for A3 scope.

### A3 — Isolated implementation
- Implement only approved vertical slices on isolated branches.
- No merge, deployment, production provider activation, production data, production trust-root changes or autonomous training unless separately authorized.
- Preserve existing branches and PRs; no duplicate domain authorities.

### A4 — Verification
- Run exact-HEAD format, compile, tests, Clippy, security/supply-chain, integration, performance and language acceptance as applicable.
- Verify adversarial and failure cases.
- Obtain independent security/architecture assessment at the approved programme gate.
- Record all evidence and unresolved findings.

### A5 — Release
- Separate Owner authorization required.
- Require signed artifacts, approved model/provider inventory, operational readiness, rollback and incident controls.
- No release is implied by A1–A4 completion.

## 17. Open decisions for A2

1. INGA's exact normative scope, crate/API boundary and relationship to any BRAIN runtime.
2. Canonical model registry and artifact ledger ownership/storage.
3. Initial local inference runtime and supported CPU/accelerator targets.
4. Supported model formats, quantization and sandbox/isolation mechanism.
5. Embedding/vector retrieval ownership and G04/G05 integration contract.
6. Dataset governance, rights review and permitted training corpus.
7. Amharic/Ethiopic benchmark datasets, annotation standards and human-review oracles.
8. Local/cloud placement, residency and external-provider policy.
9. Resource/cost budgets and workload-specific SLOs.
10. Distributed queue, worker trust and cancellation/recovery semantics.
11. Model evaluation thresholds and approval roles.
12. Model artifact signing, provenance attestation and revocation process.

No open decision is silently resolved by this document.

## 18. Current repository evidence and status

At the time this proposal was prepared, the inspected main workspace manifest listed only crates/iroka-kernel. Neural/cognitive implementation candidates and their PRs are separate, unmerged work. A prior INGA candidate was recorded on feat/inga-neurogenetic-a3-foundation at commit e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d, associated with draft PR #44; the historical report described 30 authored tests but did not establish exact-head verification. This is a historical reference, not a claim that the branch remains at that head today.

Recent repository activity also includes separate BRAIN, native cognition, TALORA task-service and Android integration candidates. Their PR descriptions explicitly identify missing combined runtime/integration evidence and preserve their unmerged status. They are not automatically adopted as INNIA components.

The IGACMS A2 baseline remains a separately governed, previously Owner-approved baseline. This proposal does not amend or reopen it.

**Status at proposal time:**
- INNIA A1 document: proposed; Owner review/freeze pending.
- INGA integration: PARTIAL / current head requires reconciliation.
- Unified neural runtime: MISSING / not demonstrated on main.
- Production model registry/serving: MISSING.
- Governed training/promotion pipeline: MISSING.
- Distributed production compute: MISSING.
- Exact-head verification of this architecture proposal: NOT RUN.
- A3 implementation authorization: NOT granted by this document.
- Merge, production activation and A5 deployment: NOT authorized.

## 19. Change control

Changes to this architecture must be versioned and reviewed for effects on the Kernel, G01–G12 ownership, privacy, data residency, authority, model provenance and safety. Any amendment that changes IGACMS's approved baseline or constitutional trust/authority boundaries requires its own explicit Owner authorization.

---
**End of INNIA A1 proposal v0.1.0**
