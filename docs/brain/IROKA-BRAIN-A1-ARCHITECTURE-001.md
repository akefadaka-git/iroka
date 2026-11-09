# IROKA BRAIN — Cognitive Architecture and Functional Specification

**Document ID:** IROKA-BRAIN-A1-001  
**Version:** 1.0.0  
**Status:** OWNER-APPROVED / FROZEN — A1 CLOSED  
**Scope:** Cognitive plane and its contracts with Genome domains G01–G12  
**Baseline:** Owner-approved IGACMS A2 branch `architecture/igacms-a2-owner-approved` at `a709fc473b23494839417449e34bebf4cb8be77a`  
**Governance:** A1 specification frozen by explicit Owner approval on 2026-11-09 (D2). A2 contract reconciliation remains a separate gate. A3 requires separate explicit authorization. A4 and A5 remain separate gates.

## 1. Purpose

Define IROKA's model-independent cognitive architecture as a governed system capability, not as one model, a chatbot, an unrestricted agent, or a collection of autonomous services.

The Brain coordinates cognitive work while the twelve-chromosome Genome remains the authoritative ownership model. It does not absorb identity, policy, memory, knowledge, perception, agent identity, orchestration, execution, assurance or evolution authorities owned by other domains.

**Constitutional operating rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.

## 2. Normative design principles

1. **Model independence:** model providers are replaceable capability sources; no provider defines IROKA identity, policy, memory authority or trust.
2. **Kernel supremacy:** models, agents and cognitive modules cannot grant permissions, alter trust roots or bypass Kernel decisions.
3. **Evidence before assertion:** distinguish source evidence, verified facts, model outputs, assumptions, inferences, hypotheses and unknowns.
4. **Bounded cognition:** every task has an objective, constraints, context classification, resource budget, deadline/stop condition and completion criteria.
5. **Domain ownership:** G03 coordinates reasoning; G04 owns knowledge; G05 owns memory; G06 owns perception; G07 owns agent identity; G08 owns durable orchestration; G10 owns learning/evaluation; G11 owns independent assurance; G12 owns controlled evolution.
6. **Human accountability:** consequential decisions and actions retain the approval required by G02 policy and applicable governance.
7. **Amharic-first and regional correctness:** Amharic (am-ET) is the Ethiopia-profile default; English and additional languages are explicit capabilities with separate evidence.
8. **Privacy and data minimization:** data classification precedes storage, retrieval, model routing, export or retention.
9. **Inspectable operation:** cognitive decisions expose concise rationale, evidence references, uncertainty, model/provider attribution and trace identifiers, not hidden chain-of-thought.
10. **Controlled improvement:** the Brain may identify and propose improvements; it cannot approve or deploy its own changes.

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are normative.

## 3. Cognitive architecture and Genome mapping

The Brain has eight logical cognitive capability groups. They are not eight required deployable services, eight independent models, or new Genome chromosomes.

| Logical capability | Responsibility | Authoritative Genome owner(s) | Boundary |
|---|---|---|---|
| Core reasoning | Decomposition, inference, synthesis, contradiction and hypothesis analysis | G03; evidence from G04/G06 | Produces structured analyses, never authority |
| Knowledge intelligence | Source-grounded retrieval, relationship exploration and evidence comparison | G04 | Brain consumes knowledge contracts; it does not own the knowledge store |
| Strategic planning | Goal interpretation, plans, dependencies, alternatives and risk-aware prioritization | G03 with G08/G02 | Plans are proposals; G08 owns durable task state |
| Engineering intelligence | Code, architecture, data and technical problem-solving | G03 with G04/G11 | Changes require normal G02/G09/G12 controls |
| Perception intelligence | Interpretation of text, documents, images, audio, video and structured signals | G06 | Outputs normalized observations with provenance and confidence |
| Social and communication intelligence | Dialogue, explanation, translation and localization | G03 plus CIW/experience layer and G06 | Conversation service owns conversation records; no duplicate memory authority |
| Critical analysis | Independent challenge of assumptions, plans and outputs | G03 critic interface plus G11 assurance | Cognitive critique is not independent security assurance |
| Metacognition | Monitoring uncertainty, strategy quality, limits and error patterns | G03 with G10/G11/G12 | Proposes learning/change; cannot self-authorize or self-modify |

### 3.1 Separation of cognition and assurance

G03 may run a critic or verifier model to challenge a draft. That is a cognitive quality-control step, not independent assurance. G11 remains the independent assurance authority for security, audit, verification evidence and release readiness. A model must not certify its own safety or correctness merely by producing a second answer.

### 3.2 Separation of planning and execution

A plan is a typed proposal. G08 owns durable workflow/task state. G02 decides authorization. G09 executes protected side effects only with a valid Kernel authorization. The Brain MUST NOT call protected tools directly or treat a model response as an execution grant.

## 4. Logical architecture

### 4.1 Cognitive task envelope

Every cognitive request MUST be represented by a versioned task envelope containing at least:

- `task_id`, `schema_version`, `correlation_id`;
- authenticated principal reference and verified tenant context supplied by G01 (never caller-invented);
- objective and success criteria;
- task class and requested cognitive capabilities;
- input references, source metadata and content classification;
- policy/context reference from G02;
- allowed model/provider capability constraints;
- resource budget, deadline, cancellation token/reference and bounded iteration limit;
- required evidence/provenance and uncertainty reporting;
- requested output schema and output classification;
- current lifecycle state and terminal reason.

Raw credentials, private keys, approval secrets and unrestricted personal data MUST NOT be placed in model prompts or task envelopes.

### 4.2 Cognitive result envelope

A result MUST include:

- task and correlation identifiers;
- result schema/version and status;
- concise answer or structured artifact;
- evidence references with source, timestamp and relevant excerpt/span identifiers where available;
- explicit assumptions, inferences, hypotheses and unresolved questions;
- calibrated uncertainty or an explicit statement that confidence is unavailable;
- model/provider/adapter identifier and version where a model was used;
- tool/agent references, if any, with authorization receipt references;
- resource usage and termination reason;
- verification status and known limitations.

A generated claim MUST NOT be labelled verified solely because a model emitted it. Citation presence is not citation correctness.

### 4.3 Core request lifecycle

The standard cognitive lifecycle is:

`INTAKE → CLASSIFY → AUTHENTICATE → CONTEXTUALIZE → RETRIEVE → PLAN → REASON → CRITIQUE → VERIFY → RESPOND → RECORD`

For any requested side effect, the separate governed action lifecycle applies:

`PROPOSE → POLICY CHECK → APPROVAL (if required) → KERNEL AUTHORIZATION → G09 EXECUTION → INDEPENDENT OUTCOME CHECK → AUDIT`

A cognitive request may terminate safely at any stage. Cancellation, timeout, budget exhaustion, provider failure, policy denial and uncertainty must produce explicit terminal outcomes rather than fabricated success.

## 5. Cognitive runtime components

These are logical components behind typed, versioned interfaces. Initial implementation SHOULD be a cohesive modular runtime; microservices are not required without operational evidence.

1. **Task intake and classifier:** validates task envelope, purpose, risk, data class and requested capability.
2. **Context assembler:** gathers only permitted context from G04/G05/G06/CIW references, enforces budgets and preserves source labels.
3. **Model gateway:** routes to approved local/external model adapters using capability, privacy, quality, availability, latency and cost metadata.
4. **Reasoning coordinator:** selects bounded reasoning strategies and maintains structured intermediate state.
5. **Planner:** produces typed goal/dependency plans, assumptions, risk and completion criteria.
6. **Critic:** checks contradictions, missing evidence, unsafe assumptions and schema/constraint violations.
7. **Evidence verifier:** checks source resolution and claim-to-source support using independent deterministic checks where feasible; escalates unresolved semantic verification.
8. **Response synthesizer:** produces user-facing, localized output with evidence, uncertainty and limitations.
9. **Metacognitive monitor:** evaluates task quality, stop conditions, resource use, uncertainty and error patterns.
10. **Evaluation adapter:** sends eligible, minimized evaluation records to G10; no training or retention is implied.
11. **Trace adapter:** emits attributable events to G11 under approved audit/data policies.
12. **Workflow adapter:** delegates durable multi-step execution state to G08; no private workflow database in G03.

## 6. Model federation contract

The model gateway MUST be provider-neutral. Each adapter declares a versioned capability manifest, including:

- supported modalities and input/output formats;
- structured-output and streaming support;
- context limits and tokenization/version metadata where known;
- tool-call proposal support (not authorization);
- language capabilities with evidence level, not marketing labels;
- privacy/data handling, retention and residency attributes;
- availability, timeout, rate-limit and cancellation behavior;
- measured latency, quality and resource/cost metadata;
- model identifier, exact version or immutable revision where available.

Routing MUST consider task class, evidence from evaluation, data classification, user/tenant policy, configured resource limits and provider health. Sensitive data MUST NOT be sent to a provider unless the data policy permits that exact flow. Provider fallback MUST NOT silently widen data disclosure or change the task's authority.

The gateway MUST normalize errors, bound retries, support cancellation, prevent unbounded fan-out, record provider attribution and distinguish timeout, refusal, malformed output, rate limit, unavailable provider and policy denial. A provider response is untrusted data.

At least two adapters are a future P1 acceptance target, not a current capability claim. Local/open-weight adapters are preferred where technically and economically feasible, subject to license, security, hardware and data-flow review. No paid provider is assumed or authorized by this specification.

## 7. Reasoning and planning requirements

G03 SHOULD support the following strategies behind replaceable interfaces:

- deductive, inductive and abductive inference;
- multi-step mathematical and computational reasoning;
- causal analysis with explicit distinction between correlation and causation;
- hypothesis generation, evidence comparison and falsification;
- decomposition, dependency analysis and constraint satisfaction;
- scenario comparison and decision support;
- code and engineering analysis;
- multilingual synthesis and translation with source fidelity controls.

Every strategy MUST define supported input classes, expected output schema, resource bounds, known failure modes and evaluation cases. No strategy may claim deterministic correctness where the underlying model or data is nondeterministic.

Plans MUST include objective, preconditions, steps, dependencies, expected outcomes, risk, reversibility, resource bounds, required capabilities, approval points and stop/rollback conditions. Plan validation MUST reject missing prerequisites, cycles where a DAG is required, out-of-scope targets, unsupported capabilities and budget overruns.

## 8. Knowledge, memory and perception integration

### 8.1 G04 Knowledge

G04 owns source registry, ingestion, indexing, retrieval and provenance. G03 consumes typed evidence references and MUST preserve source identity, acquisition time, transformation lineage, freshness, access classification and conflict state. Similarity/relevance scores MUST NOT be treated as truth scores or authorization.

### 8.2 G05 Memory

G05 owns memory policy, storage, consent, retrieval, correction, retention, export and deletion. The Brain may request permitted context and submit candidate memory observations only through G05 contracts.

The architecture recognizes distinct memory classes: working context, episodic task/conversation records, semantic/durable user- or organization-approved knowledge, procedural/skill records, and operational/audit records. Their retention and access policies differ. Audit retention MUST NOT be used as a pretext to retain content that policy requires deleting.

Memory candidates MUST carry owner/tenant, purpose, source, timestamp, classification, confidence/verification state, expiry/retention rule and correction/supersession link. Retrieval relevance MUST NOT silently upgrade an unverified memory to verified fact.

### 8.3 G06 Perception

G06 owns modality adapters and normalized observations. The Brain consumes observations with modality, source, timestamp, transformation, confidence and safety metadata. OCR, ASR, image/video interpretation and generated descriptions remain derived content unless independently verified. User-supplied or retrieved media is untrusted input, not instructions to the Kernel.

## 9. Metacognition and governed learning

Metacognition MUST be measurable and bounded. It includes:

- detect missing prerequisites and knowledge gaps;
- estimate and report uncertainty and calibration;
- detect contradictions and unsupported claims;
- assess whether the selected strategy is suitable;
- monitor iteration, latency, token/resource use and stop conditions;
- detect recurring failure patterns without overgeneralizing from one event;
- recommend human review or abstention when confidence/evidence is insufficient;
- produce versioned improvement proposals with evidence and expected impact.

G10 owns evaluation datasets, scoring, feedback and validated learning proposals. G12 owns version/change approval and rollback. G11 independently verifies required assurance evidence. The Brain MUST NOT update its own weights, prompts, policies, tools, trust roots or code in production without the applicable isolated experiment, approval, implementation, verification and release gates.

## 10. Security, privacy and trust boundaries

Threat model MUST cover prompt injection, retrieved-content instruction smuggling, model/provider compromise, fabricated citations, memory poisoning, cross-tenant context leakage, confused deputy, unauthorized tool proposals, provider data leakage, resource exhaustion, unsafe retries, model/version substitution and self-modification.

Mandatory controls:

1. Authenticate via G01; derive tenant context from trusted membership, never caller payload.
2. Apply G02 policy and data classification before retrieval, model routing or action proposal.
3. Treat user, retrieved, model, perception and tool outputs as untrusted data.
4. Keep secrets, trust roots, hidden prompts and private reasoning traces out of model-editable content.
5. Enforce schema validation, input/output size, iteration, concurrency, rate, time and cost/resource limits.
6. Fail closed for protected effects on authorization denial, expiry, revocation, ambiguity or control-plane outage.
7. Bind every proposal to principal, task, capability, target, scope, policy version, expiry and correlation ID before authorization.
8. Record required security/audit events through G11 interfaces; cognitive logs must minimize sensitive content.
9. Enforce tenant isolation and purpose-bound access on every context retrieval.
10. Support cancellation and safe termination; no blind retry of non-idempotent effects.
11. Require independent review for critical security/cryptographic changes.
12. Do not claim independent assurance from a model-generated critique.

## 11. Amharic-first and regional cognitive requirements

For the Ethiopia profile:

- Amharic (am-ET) is the default language for cognitive interaction and user-facing explanations.
- English remains a selectable secondary language.
- Preserve Ethiopic script, Unicode, combining marks, numerals, punctuation and mixed Amharic/English text end-to-end.
- Preserve original-script names and source text; transliteration is an alias, not canonical replacement.
- Keep language, calendar, time zone, currency and regional profile as separate typed dimensions.
- Distinguish Ethiopian and Gregorian calendar values and label conversions.
- Translate authorization, consent, risk, error and uncertainty explanations with reviewed terminology.
- Evaluate Maale and other languages as separate capabilities with explicit corpora, reviewer competence, source permissions and acceptance evidence; do not claim support without tests.
- Machine-generated translation MUST NOT be the sole oracle for consequential language-quality evaluation.

## 12. Evaluation and benchmark requirements

Every benchmark MUST record benchmark ID/version, task-set provenance/license/classification, exact IROKA SHA, configuration, model/provider exact version, prompts and tool definitions, policy version, hardware/runtime, resource budget, evaluator/scoring version, raw outcomes, confidence intervals and failure analysis. Keep held-out data separate from tuning data. Use synthetic or properly licensed data.

Required benchmark families:

| ID | Capability | Measures and adversarial cases |
|---|---|---|
| BRAIN-01 | Reasoning | accuracy, consistency, calibration; ambiguity, contradictory premises, multi-step traps |
| BRAIN-02 | Evidence/research | claim-support precision, citation correctness, freshness; fabricated/stale/conflicting sources |
| BRAIN-03 | Planning | goal completion, constraint adherence, dependency validity; interruptions and changed constraints |
| BRAIN-04 | Engineering | test pass rate, patch correctness, regression/security findings; hidden tests and vulnerable changes |
| BRAIN-05 | Memory integration | provenance, recall, correction/deletion; poisoning, supersession and cross-tenant leakage |
| BRAIN-06 | Perception integration | task accuracy, OCR/ASR/grounding; noise, poor quality, adversarial media |
| BRAIN-07 | Amharic/localization | native-speaker task success, fidelity and correction burden; dialects, code-switching, names and dates |
| BRAIN-08 | Model gateway | adapter conformance, timeout/cancel/fallback, privacy and cost; malformed output/provider outage |
| BRAIN-09 | Metacognition | calibration, abstention quality, error detection; overconfidence and false certainty |
| BRAIN-10 | Safety/authority | unauthorized side effects (target zero), policy bypass, isolation; injection and confused deputy |
| BRAIN-11 | Reliability | p50/p95/p99 latency, recovery and resource bounds; crash, network partition and exhaustion |
| BRAIN-12 | Efficiency | cost/resource per successful task, local/cloud comparison; rate limits and budget exhaustion |

No aggregate score can compensate for a failed critical security, privacy, localization or authorization gate. Thresholds must be approved against named workload/device profiles; do not invent performance targets before baseline measurement.

## 13. Acceptance criteria

A1 architecture acceptance requires Owner review of the domain map, threat boundaries, task/result contracts, model gateway, memory/knowledge/perception ownership, Amharic-first requirements, benchmark design and exclusions.

A2 contract acceptance requires:
- exact read-only reconciliation of relevant branches, PRs, commits, files and workflows;
- reuse/adapt/missing/blocked disposition with evidence;
- exact Kernel, G01/G02, G04/G05/G06/G08/G11/G12 integration references;
- no duplicate authority or persistence ownership;
- versioned task/result/model/plan/evidence interfaces;
- threat-to-control-to-test traceability;
- dependency, license, provenance, data-flow and cost review;
- resolved or explicitly deferred decisions;
- separate Owner approval before A3.

A3 implementation acceptance (not authorized by this document) will require scoped work packages, tests before implementation where practical, synthetic fixtures, exact-HEAD CI, no production secrets/data, and no merge.

A4 acceptance will require exact-SHA unit, contract, integration, adversarial, fault-injection, privacy, localization, performance and independent security evidence.

A5 deployment remains separately authorized after A4 and operational readiness.

## 14. Explicit exclusions

This specification does not authorize:
- a foundation-model training program or claims of frontier-model parity;
- unrestricted autonomous goals, self-replication or self-modification;
- G09 protected side effects, financial/legal/medical decisions or external actions;
- production model/provider activation, paid service use or data transfer;
- production keys, trust-root changes, Genesis activation or policy changes;
- merging any existing PR, rebasing unrelated branches, deleting branches or changing `main`;
- memory, knowledge or audit stores outside their authoritative Genome owners;
- deployment, pilot, publication or production-data migration.

## 15. A1 freeze record and deferred decisions

**Owner decision:** D2 = YES, explicitly approving the IROKA BRAIN architecture proposal in PR #26 for A1 freeze.  
**Freeze date:** 2026-11-09.  
**Disposition:** VERIFIED-CLOSED — A1 architecture baseline v1.0.0.

The following A1 architectural decisions are frozen:
1. Eight logical cognitive capability groups and their mapping to the existing twelve-chromosome Genome; these are logical capabilities, not new chromosomes or mandated microservices.
2. G03 reasoning/critic is distinct from G11 independent assurance; a cognitive critic cannot self-certify security or release readiness.
3. The Brain is model-independent, bounded, evidence-aware, Amharic-first for the Ethiopia profile, and subject to Kernel/G02 authority and existing Genome domain ownership.
4. Planning is not execution; protected effects remain governed by G02/G09.
5. G04 owns knowledge, G05 memory, G06 perception, G07 agent identity, G08 durable orchestration, G10 learning/evaluation, G11 independent assurance and G12 controlled evolution.
6. No paid provider, production data transfer, production credentials, autonomous self-modification, merge or deployment is authorized by this A1 freeze.

The following matters are deliberately deferred to A2 contracts or later separately approved increments; they do not reopen the frozen architecture:
- formal task/result/model-capability schema definitions and compatibility rules;
- exact first A3 increment and implementation acceptance criteria;
- local execution hardware/resource envelope;
- Amharic evaluation corpus provenance, license, owner and native-review process;
- first G05 memory-class integration scope;
- provider count and local/cloud mix for future P1 acceptance.

**Current disposition:** A1 = VERIFIED-CLOSED / FROZEN. A2 remains PARTIAL. No runtime implementation, merge, deployment or A3 authorization is implied.
