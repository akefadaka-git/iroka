# IROKA ZERO — Master Implementation Strategy and Phased Roadmap v2.0

**Document status:** Proposed master roadmap — saved for Owner review and approval  
**Version:** 2.0  
**Project:** IROKA — Intelligent Reasoning, Orchestration, Knowledge & Assurance  
**Motto:** Intelligence Guided by Wisdom. Governed by Integrity.  
**Repository:** \`akefadaka-git/iroka\`  
**Supersedes for future planning:** The initial strategy remains preserved as historical baseline at \`docs/IMPLEMENTATION_STRATEGY.md\`. This v2.0 document is the proposed forward roadmap; it does not silently close, invalidate or rewrite prior stage decisions.

---

## 0. Executive direction

IROKA is to be built as a **governed, model-independent cognitive operating system**, not as a wrapper around one foundation model and not as an unrestricted autonomous agent.

The platform must combine:

1. A deterministic trust and governance kernel.
2. A model-independent cognitive runtime.
3. Provenance-aware knowledge and governed memory.
4. Secure agent identities, delegation and orchestration.
5. Permissioned execution and replaceable tool adapters.
6. Multimodal perception and human interaction.
7. Evaluation, assurance and controlled evolution.
8. A future native IROKA runtime, programming language and application environment.

The implementation sequence is dependency-led. Security, identity, policy, data governance, observability and evaluation are cross-cutting requirements from the first implementation increment. They are not optional finishing work.

### 0.1 Strategic outcomes

IROKA should ultimately be able to:

- Solve complex reasoning, research, engineering and operational tasks with evidence and uncertainty disclosure.
- Route work across multiple replaceable external and local models.
- Maintain user- and organization-governed working, episodic and durable memory.
- Build and retrieve a source-attributed knowledge base.
- Interpret text, documents, images, audio and video where approved.
- Create plans, delegate bounded work and recover interrupted workflows.
- Use tools and interact with approved applications only under explicit, revocable authority.
- Provide Amharic-first interaction while supporting English and additional languages.
- Operate in hybrid local/cloud environments according to data classification and policy.
- Evaluate its own output and proposed changes without silently changing its governing rules.
- Expose a stable developer platform and, in a later phase, a native runtime and language.

### 0.2 What success is not

Success is not measured by the number of agents, integrations, models, features or lines of code. It is not a claim that IROKA is already equal to frontier foundation models or fictional systems.

Success means reproducible capability, dependable operation, measurable task quality, strong localization, controlled authority, recoverability and independent assurance.

---

## 1. Scope, terminology and planning model

### 1.1 The twelve-chromosome Genome remains authoritative

| ID | Chromosome | Responsibility |
|---|---|---|
| G01 | Identity | System identity, principals, ownership, credentials and trust roots |
| G02 | Governance | Policy, authority, approvals, risk decisions and constraints |
| G03 | Cognitive | Reasoning, planning, synthesis, critique and metacognition |
| G04 | Knowledge | Ingestion, retrieval, evidence, provenance and knowledge quality |
| G05 | Memory | Working, episodic and durable memory under policy |
| G06 | Perception | Text, image, audio, video and document interpretation |
| G07 | Agent | Agent identity, capability manifests, lifecycle and delegation |
| G08 | Orchestration | Durable workflows, task state, scheduling, coordination and recovery |
| G09 | Execution | Tool adapters, external actions, transactions and side effects |
| G10 | Learning | Evaluation, feedback, adaptation and validated learning proposals |
| G11 | Assurance | Security, testing, observability, audit and independent verification |
| G12 | Evolution | Versioning, change control, experimentation, release and rollback |

The Genome describes logical ownership boundaries. It does not require one microservice, model or repository directory per chromosome. Start with cohesive modules and extract services only when operational evidence justifies it.

### 1.2 Delivery stages

The existing governance lifecycle remains:

- **A1 — Assessment and architecture freeze:** define and approve the architecture, requirements, threats and acceptance criteria.
- **A2 — Read-only reconciliation and contract approval:** inspect existing implementation and historical evidence; approve interfaces, dependencies and migration contracts without implementation changes.
- **A3 — Implementation:** build only the approved scope in dependency order.
- **A4 — Verification and assurance:** verify the exact resulting commit under positive, negative, adversarial and failure conditions.
- **A5 — Controlled release:** separately authorized deployment, pilot and production operation.

The new P0–P8 roadmap below is the product capability roadmap. It does not replace A1–A5 governance. Each P-phase still uses A1/A2/A3/A4 gates as applicable; A5 remains separately authorized.

### 1.3 Status vocabulary

Use only evidence-backed statuses:

- \`PASS\` — a named test or check passed against the stated input and commit.
- \`VERIFIED-CLOSED\` — all defined exit evidence is complete and the authorized closure decision is recorded.
- \`PARTIAL\` — some requirements are implemented or verified, but one or more exit conditions remain.
- \`MISSING\` — a required artifact, control or implementation is absent.
- \`UNRESOLVED\` — a known issue or decision remains open.
- \`UNKNOWN\` — evidence is insufficient to determine status.
- \`NOT RUN\` — the required verification has not been performed.
- \`NOT AUTHORIZED\` — the action is outside current approval.

A green CI run is evidence for the checks it actually ran. It is not proof of production readiness, independent organizational trust, privacy compliance, security assurance or operational recovery.

---

## 2. Constitutional and system-wide invariants

These invariants apply to every chromosome, service, model, agent, tool, data store and deployment.

### 2.1 Identity and authority

1. IROKA's identity and constitutional rules are independent of any model, vendor or hosting provider.
2. No model output, agent plan, retrieved document, plugin, tool response or external party can grant authority.
3. Every protected side effect requires a verifiable authorization decision bound to actor, capability, target, scope, context, policy version, expiry and relevant risk attributes.
4. Delegated authority cannot exceed the delegator's authority and must have bounded depth, scope and lifetime.
5. Revocation must invalidate affected grants and sessions within defined propagation objectives.
6. Critical Kernel, identity-root, policy and governance changes require explicit Owner authorization.

### 2.2 Security and data protection

1. Least privilege, secure defaults, tenant isolation and data minimization are mandatory.
2. Untrusted content remains data, never instructions to the Kernel or authorization plane.
3. Secrets must not be committed to the repository, chat, logs or test fixtures.
4. Credentials and keys require lifecycle controls: generation, custody, use, rotation, revocation, recovery and destruction.
5. Sensitive data must be classified before storage, retrieval, model routing or export.
6. Protected operations fail closed on invalid, expired, revoked, ambiguous or unavailable authorization.
7. Security boundaries must be tested under adversarial and degraded conditions.

### 2.3 Evidence and knowledge

1. Material claims should carry source, acquisition time, provenance and confidence/uncertainty.
2. Conflicting sources must remain distinguishable; the system must not silently collapse disagreement.
3. Model-generated content must be distinguishable from verified source evidence.
4. Memory must have purpose, classification, owner, access policy, retention and correction/deletion semantics.
5. Retrieval relevance is not proof of truth or authorization.

### 2.4 Autonomy and evolution

1. Autonomy is bounded by capability, policy, risk, budget, time, target and scope.
2. Human approval is mandatory for high-impact, irreversible, financial, legal, identity, trust-root and production actions unless an explicitly approved policy says otherwise.
3. The system may propose changes to itself; it may not approve or deploy its own changes.
4. Experiments run in isolated environments with synthetic or specifically authorized data.
5. Every adopted change has test evidence, provenance, approval, versioning and a rollback path.

### 2.5 Operational integrity

1. Durable workflows must survive restart, duplicate delivery and partial failure.
2. External side effects need idempotency, bounded retries and reconciliation.
3. Audit records must be attributable and integrity-protected.
4. Recovery and restore must be demonstrated, not inferred from backup creation.
5. Resource, cost, rate and concurrency limits must be enforceable.

---

## 3. Target architecture

### 3.1 Seven platform layers

| Layer | Name | Main responsibilities | Governing rule |
|---|---|---|---|
| L1 | Kernel and infrastructure | Trusted identity, policy enforcement, cryptography, persistence, networking, runtime primitives | Deterministic protected control |
| L2 | Identity, security and governance | Principals, credentials, approval, policy, grants, audit and assurance | Authority is explicit and revocable |
| L3 | Knowledge and memory | Ingestion, source registry, retrieval, graph, memory lifecycle and provenance | Evidence and memory remain governed |
| L4 | Cognitive intelligence | Model gateway, reasoning, planning, critique, evaluation and multimodal cognition | Models provide capability, not authority |
| L5 | Agent and orchestration | Agent runtime, workflow engine, delegation, scheduling and recovery | Bounded, observable task execution |
| L6 | Human interaction | Amharic-first UI, voice, accessibility, workspace and device/application interfaces | Human intent and approval remain clear |
| L7 | IROKA OS and ecosystem | Native runtime, developer SDK, language, package model and applications | Stable, secure extension boundary |

Security, privacy, localization, observability, cost control and evaluation are cross-cutting concerns across all layers.

### 3.2 Control plane and cognitive plane

**Control plane:** identity, policy, approvals, capability grants, execution authorization, audit, revocation and emergency containment. It must be deterministic and must not depend on a generative model to decide whether protected operations are allowed.

**Cognitive plane:** model calls, reasoning, planning, retrieval, perception, synthesis and agent proposals. It can recommend actions but cannot bypass the control plane.

### 3.3 Core request lifecycle

A typical protected task follows this logical path:

1. Receive user or system request and establish authenticated principal.
2. Classify data, task risk, target and required authority.
3. Build a task context with provenance and policy constraints.
4. Plan using approved model and cognitive capabilities.
5. Validate plan structure, scope, resource limits and tool requirements.
6. Obtain approval where required.
7. Ask the Kernel for a short-lived, scoped authorization decision.
8. Execute through a controlled adapter with idempotency and bounded retries.
9. Verify outcome independently where possible.
10. Record audit evidence, sources, model/tool versions and result.
11. Update memory only under the applicable memory policy.
12. Report outcome, uncertainty, side effects and unresolved items.

A plan, model response or successful tool call is not itself proof that the overall task is correct or authorized.

### 3.4 Logical component map

- **Kernel API:** authenticated policy and authorization boundary.
- **Identity service:** principals, credentials, sessions, recovery and trust roots.
- **Governance service:** policy versions, approval workflows, risk classes and Owner decisions.
- **Audit/evidence service:** append-only event model, signatures or integrity proofs, evidence references.
- **Model gateway:** provider-neutral model discovery, routing, budgets and normalized request/response contracts.
- **Cognitive runtime:** task decomposition, reasoning loops, planning, critique and synthesis.
- **Knowledge service:** source registry, ingestion pipeline, indexing, retrieval and provenance.
- **Memory service:** memory classes, consent, access, retention, correction, deletion and retrieval.
- **Perception service:** text, document, image, audio and video adapters.
- **Agent runtime:** isolated agent process, identity, capability manifest and lifecycle.
- **Orchestrator:** durable state machine, dependency graph, retries, cancellation and compensation.
- **Tool gateway:** typed tool registry, authorization check, sandbox and output normalization.
- **Evaluation service:** task suites, scoring, regressions, model comparison and release gates.
- **Human interface:** multilingual conversation, voice, workspace, approvals and notifications.
- **Developer platform:** SDK, APIs, extension manifests, native language/runtime in later phases.

These are logical contracts. Avoid premature microservice proliferation.

---

## 4. Phased roadmap and detailed work packages

## P0 — Trust foundation and current-baseline completion

**Objective:** finish the current trust, identity, governance and independent assurance foundation before granting broader agent authority.

**Prerequisites:** preserve approved A1/A2 decisions and existing A3 work. Reconcile the exact current repository state before changing implementation.

### Work packages

**P0.1 — Baseline reconciliation**
- Record repository default branch, branch heads, open PRs, exact SHAs and workflow evidence.
- Inventory current Kernel modules, identity lifecycle, governance contracts and audit path.
- Map every implemented control to its requirement and test.
- Separate current default-branch state from work on feature branches and open PRs.
- Preserve unrelated changes and historical branches.

**P0.2 — Identity and credential lifecycle**
- Verify principal creation and identity binding.
- Verify credential enrollment, secure storage and rotation.
- Verify authentication, session issuance, expiry and revocation.
- Verify recovery and account/credential compromise handling.
- Test replay, duplicate enrollment, credential substitution and concurrent revocation.
- Define service identities and workload identity boundaries.
- Never use production secrets in tests.

**P0.3 — Owner authority and approvals**
- Bind Owner identity to trusted roots and approval records.
- Define signed approval payload, scope, expiry, nonce and replay protection.
- Enforce separation between proposer, approver and executor where required.
- Record approval withdrawal, expiry and revocation.
- Ensure approvals are bound to exact artifact/change/request digests.

**P0.4 — External witness and checkpoint protocol**
- Retain provider-neutral witness contracts.
- Complete adapter contract tests and deterministic quorum behavior.
- Identify at least two genuinely separately administered witness operators before claiming independent operational trust.
- Provision endpoint identities, mTLS enrollment and public-key fingerprints only through approved secure channels.
- Perform live publish, readback, replay/conflict, outage, restore and retention verification.
- Verify durable server-side append-only persistence and receipt behavior.
- Record organizational independence evidence separately from cryptographic protocol correctness.
- Keep live validation NOT RUN until operators are actually connected.

**P0.5 — Audit and evidence lifecycle**
- Verify event schema, actor/subject/target binding and trace correlation.
- Test tampering, truncation, replay, sequence gaps and key rotation.
- Verify export, retention, access control and backup/restore.
- Define evidence retention without retaining prohibited personal data.
- Verify audit continuity through service restart and partial failure.

**P0.6 — Independent security assessment**
- Complete threat model review.
- Conduct independent code and architecture review of authorization, identity, cryptography, witness and audit boundaries.
- Resolve critical/high findings or document explicit Owner risk acceptance.
- Add regression tests for each resolved finding.

### P0 deliverables
- Current implementation baseline and exact SHA register.
- Identity and authority lifecycle traceability matrix.
- Witness operator enrollment and verification report.
- Audit/evidence threat-control-test matrix.
- Independent security review and remediation register.
- Updated trust architecture and operational runbooks.

### P0 exit criteria
- All protected operations are bound to authenticated identity and current authorization.
- Revocation and expiry are tested under concurrency and failure.
- Owner approvals are cryptographically bound to exact scope and artifacts.
- Independent witness claims are limited to what actual operator evidence proves.
- No unresolved critical/high trust-boundary issue unless explicitly risk-accepted.
- Recovery and audit-integrity tests pass against exact commit.
- Owner accepts P0 closure.

**Status at v2.0 planning baseline:** PARTIAL. Existing kernel and adapter code have CI evidence; independent live witness operations and full operational/security evidence remain open.

---

## P1 — Cognitive core and model-independent intelligence

**Objective:** create a reliable cognitive runtime that can use multiple model providers without surrendering identity, policy or authority.

### Work packages

**P1.1 — Model gateway**
- Define provider-neutral model capability manifest: modalities, context limits, structured output, tool support and operational constraints.
- Define normalized request/response, streaming, cancellation and error contracts.
- Support external APIs and locally hosted models through separate adapters.
- Add provider health, timeout, retry, circuit-breaker and fallback policies.
- Add model/version attribution to every task trace.
- Add per-user, per-task and global budget controls.
- Prevent sensitive data from routing to a provider unless classification and policy allow it.
- Do not hard-code one vendor as the system's identity or authority source.

**P1.2 — Task and reasoning runtime**
- Define task envelope, objective, constraints, context, risk and completion criteria.
- Implement task decomposition and dependency representation.
- Implement bounded reasoning cycles with explicit stop conditions.
- Separate planning, execution proposal, evidence collection, critique and final synthesis.
- Require uncertainty and assumptions to be represented.
- Support deterministic task replay where feasible using captured non-secret inputs and adapter stubs.
- Prevent hidden chain-of-thought exposure; provide concise rationale, evidence and decision summaries instead.

**P1.3 — Planning and critique**
- Build planner and independent critic interfaces.
- Validate plans against schema, scope, policy and resource limits.
- Detect missing prerequisites, contradictory steps, unsupported assumptions and unsafe actions.
- Require evidence for claims of completion.
- Route high-impact uncertainty to human review.

**P1.4 — Model selection and routing**
- Route by task type, quality, latency, privacy classification, availability and cost.
- Keep routing policies inspectable and versioned.
- Support model comparison and controlled fallback.
- Do not silently downgrade quality or privacy guarantees.
- Preserve reproducibility metadata.

**P1.5 — Evaluation harness**
- Build a versioned task corpus with expected outputs or scoring rubrics.
- Measure task success, factuality, citation/provenance quality, calibration, latency, cost, tool correctness and safety.
- Compare models on identical prompts, tools, data, budgets and scoring rules.
- Include Amharic, English and mixed-language tests.
- Track regressions by model, prompt, adapter and code version.
- Use synthetic and licensed evaluation data; record dataset provenance.

### P1 deliverables
- Model gateway specification and adapters.
- Cognitive task schema and runtime.
- Planner/critic contracts.
- Model routing policy and cost controls.
- Reproducible evaluation harness and baseline report.

### P1 exit criteria
- At least two replaceable model backends can execute the same contract.
- Provider outage and timeout do not bypass Kernel policy.
- Every output is attributable to model/version, task context and evidence.
- Planner cannot directly execute protected effects.
- Evaluation is repeatable and reports uncertainty, failure and cost.
- Owner accepts P1 capability and quality thresholds.

---

## P2 — Knowledge, retrieval and governed memory

**Objective:** give IROKA durable, source-attributed knowledge and controlled memory without creating an opaque or unbounded data store.

### Work packages

**P2.1 — Data classification and source registry**
- Define public, internal, confidential, restricted and user-designated classes (final taxonomy requires A1/A2 approval).
- Register source owner, license/permission, acquisition method, timestamp, region and permitted purpose.
- Track content hashes and transformation lineage where appropriate.
- Reject or quarantine unknown-provenance or prohibited sources.

**P2.2 — Ingestion pipeline**
- Support text, structured data, documents and approved media.
- Add malware scanning, file-type validation, size limits and parser isolation.
- Preserve original source reference and normalized derivative separately.
- Detect duplicates and version changes.
- Treat all ingested content as untrusted data.
- Make ingestion idempotent and resumable.

**P2.3 — Retrieval and evidence**
- Implement lexical and semantic retrieval behind replaceable adapters.
- Add metadata filters for tenant, permissions, classification, source and freshness.
- Return source references and relevant excerpts with retrieval results.
- Support conflicting-source representation and stale-data warnings.
- Test prompt injection in retrieved content.
- Never treat vector similarity as authorization or factual verification.

**P2.4 — Knowledge graph**
- Define entity, relation, source, claim, time and confidence schemas.
- Track provenance for each material edge and claim.
- Support temporal facts, corrections and contradictory claims.
- Define merge/disambiguation rules.
- Keep graph writes permissioned and auditable.

**P2.5 — Memory classes and lifecycle**
- Working memory: temporary task context with bounded lifetime.
- Episodic memory: interaction and task history under user/organization policy.
- Durable memory: explicitly approved reusable facts and preferences.
- Operational memory: workflow state and system events, separated from personal memory.
- Audit evidence: protected records under separate retention rules.
- Define creation, access, correction, export, retention, deletion and backup semantics per class.
- Provide user-visible controls and provenance for remembered facts.
- Prevent silent promotion from temporary context to durable memory.
- Prevent one tenant or user from retrieving another's memory.

**P2.6 — Memory safety and quality**
- Test memory poisoning, stale facts, contradictions and retrieval leakage.
- Measure recall, precision, freshness and provenance coverage.
- Verify deletion/correction across indexes, caches, replicas and backups according to documented policy.
- Distinguish logical deletion from physical expiry in backups.
- Do not promise deletion beyond what the storage and backup lifecycle can prove.

### P2 deliverables
- Data classification and source governance contract.
- Ingestion and retrieval services.
- Knowledge graph schema and provenance model.
- Memory lifecycle and user-control interfaces.
- Data retention, export, correction and deletion verification report.

### P2 exit criteria
- Every retrieved material fact has a traceable source or is labeled as model-generated/unsupported.
- Access controls are enforced before retrieval results are exposed.
- Memory lifecycle operations pass tenant-isolation, correction, deletion and recovery tests.
- Prompt injection and poisoned-memory tests pass at the agreed threshold.
- Owner accepts P2 data and memory governance.

---

## P3 — Agent runtime, orchestration and controlled execution

**Objective:** enable specialized agents to perform useful multi-step work while remaining subordinate to Kernel authority.

### Work packages

**P3.1 — Agent identity and manifest**
- Define immutable agent ID, owner, version, purpose and lifecycle state.
- Declare tools, data classes, model needs, resource budget and allowed operations.
- Bind every agent to an identity and capability set.
- Require explicit approval for new high-risk capabilities.
- Prohibit agent self-grant and unbounded delegation.

**P3.2 — Sandboxed runtime**
- Isolate filesystem, network, process and secret access.
- Use allowlisted capabilities and short-lived credentials.
- Apply CPU, memory, time, output and concurrency limits.
- Separate development, test and production environments.
- Ensure sandbox escape attempts fail closed and are observable.

**P3.3 — Durable orchestration**
- Define workflow state machine and task dependency graph.
- Persist state transitions and execution receipts.
- Support cancellation, pause/resume, deadlines and bounded retries.
- Implement idempotency keys and duplicate-delivery protection.
- Define compensation or reconciliation for partially completed side effects.
- Handle worker restart, queue outage and partial network failure.

**P3.4 — Delegation and multi-agent coordination**
- Define parent-child task relationships and authority attenuation.
- Bound delegation depth, fan-out, duration and total resource budget.
- Ensure each agent receives only required context.
- Prevent circular delegation and runaway agent loops.
- Require conflict resolution and independent verification for consequential results.
- Record agent/model/tool lineage in the audit trace.

**P3.5 — Tool gateway**
- Create typed tool manifests with input/output schemas, risk classes and side-effect descriptions.
- Validate inputs and outputs.
- Check authorization immediately before each protected effect.
- Use per-tool credentials, not broad ambient credentials.
- Add idempotency, rate limits, timeout, circuit breaker and output sanitization.
- Keep external tool content untrusted.

**P3.6 — Human approval and emergency controls**
- Provide review screens for proposed actions and their consequences.
- Bind approval to exact action digest, target, parameters and expiry.
- Support denial, modification, cancellation and revocation.
- Add global and scoped emergency stop.
- Test that emergency stop blocks new actions and safely handles in-flight work.

### P3 deliverables
- Agent manifest and identity contract.
- Sandbox runtime.
- Durable orchestrator.
- Tool registry and execution gateway.
- Delegation and approval model.
- Emergency stop and recovery runbooks.

### P3 exit criteria
- No agent can exceed or self-expand its authority.
- Every tool effect has a current authorization decision and trace.
- Duplicate, retry, cancellation and partial failure are safe.
- Sandboxing and resource limits are independently tested.
- Multi-agent workflows terminate within defined budgets.
- Owner accepts P3 execution safety.

---

## P4 — Multimodal perception and localization

**Objective:** enable reliable interpretation and generation across modalities, with Amharic-first interaction and Ethiopian/African context designed into the platform.

### Work packages

**P4.1 — Language and localization foundation**
- Define locale, script, language detection and mixed-language handling.
- Support Amharic and Ethiopic script correctly in UI, search, storage, rendering and export.
- Define Gregorian and Ethiopian calendar representation and conversion rules with explicit timezone handling.
- Support local names, transliteration and spelling variants without losing canonical source text.
- Design for low-bandwidth and intermittent connectivity.
- Make translation and transliteration outputs distinguishable from original source content.

**P4.2 — Text and document perception**
- Add secure parsers for common document and text formats.
- Preserve page, section, table and source location references.
- Support OCR with confidence and human correction.
- Test Ethiopic fonts, layout, mixed scripts and scan quality.
- Detect malformed and adversarial documents.

**P4.3 — Image perception**
- Add approved image understanding adapters.
- Preserve image source and transformation metadata.
- Support visual question answering, classification and extraction only within policy.
- Add safety, privacy and provenance checks.

**P4.4 — Audio and voice**
- Evaluate speech recognition and speech synthesis for Amharic and prioritized regional languages.
- Measure word error rate, character error rate, latency and speaker/noise robustness.
- Preserve uncertainty and timestamps.
- Require explicit consent for recording and retention.
- Separate speaker diarization from identity authentication; voice alone must not establish authority.

**P4.5 — Video and real-time streams**
- Add bounded frame sampling and audio/video synchronization.
- Apply retention and privacy controls before processing.
- Do not implement continuous surveillance by default.
- Require explicit purpose, consent/legal basis and human oversight for monitoring use cases.

**P4.6 — Localization evaluation**
- Create representative, consented or properly licensed datasets.
- Include dialect, accent, code-switching, spelling variation and low-resource conditions.
- Use independent human evaluation for culturally sensitive outputs.
- Track quality gaps by language and task.

### P4 deliverables
- Localization specification and language test corpus.
- Document/OCR, image, audio and video adapter contracts.
- Amharic-first interface primitives.
- Consent and media-retention controls.
- Multimodal benchmark report.

### P4 exit criteria
- No modality bypasses classification, consent or authorization controls.
- Amharic and prioritized language performance meets approved, published thresholds.
- Source and uncertainty are preserved in extracted results.
- Recording and media retention behavior is tested and inspectable.
- Owner accepts P4 localization and perception quality.

---

## P5 — Human-facing IROKA assistant and workspace

**Objective:** provide a dependable, accessible and useful personal/organizational assistant interface, including JARVIS-like interaction patterns without unrestricted device control.

### Work packages

**P5.1 — Conversation and workspace**
- Build conversation, task workspace and project context interfaces.
- Show task state, source evidence, tool actions, approvals and unresolved issues.
- Provide clear distinction between proposal, authorized action and completed action.
- Support user correction and feedback.

**P5.2 — Voice interaction**
- Add push-to-talk and, only where approved, wake interaction.
- Provide visible recording state and consent controls.
- Support interruption, confirmation and disambiguation.
- Require explicit confirmation for consequential commands.
- Never use voice similarity alone to authorize critical actions.

**P5.3 — Personal and organizational workflows**
- Calendar, reminders, document assistance, research and communication integrations.
- Per-integration scopes and revocable tokens.
- Draft-before-send defaults for external communication.
- Explicit confirmation for sending, purchasing, deleting, publishing or modifying records.
- Audit all protected actions.

**P5.4 — Computer and device interaction**
- Begin with read-only observation and guided assistance.
- Use allowlisted applications and per-action authorization.
- Provide preview of target, operation and expected effect.
- Require confirmation for irreversible or high-impact actions.
- Maintain screenshots/interaction logs only where lawful, consented and policy-approved.
- Provide emergency interruption.

**P5.5 — Accessibility and offline operation**
- WCAG-aligned interaction, keyboard access, screen reader labels and adjustable presentation.
- Offline cache only for data permitted by classification and user policy.
- Queue offline actions as proposals; reauthorize before execution after reconnect.
- Avoid replaying stale approvals.

### P5 deliverables
- Amharic-first assistant UI and workspace.
- Voice interaction with consent.
- Integration catalog and permission controls.
- Computer/device interaction safety model.
- Accessibility and offline test report.

### P5 exit criteria
- Users can inspect what IROKA knows, proposes and does.
- Protected actions require explicit current authority.
- Voice, offline and computer-use failure cases are safe.
- Accessibility and localization thresholds pass.
- Owner accepts P5 user experience and controls.

---

## P6 — Predictive, analytical and domain intelligence

**Objective:** deliver measurable analytical capabilities inspired by advanced fictional systems, while rejecting mass surveillance, opaque scoring and unaccountable decision-making.

### Work packages

**P6.1 — Analytical foundation**
- Define domain-specific data contracts and lawful data sources.
- Establish data quality, freshness, missingness and bias checks.
- Build time-series, anomaly detection and forecasting adapters.
- Preserve uncertainty intervals and model limitations.

**P6.2 — Decision support**
- Generate recommendations with evidence, alternatives and assumptions.
- Distinguish correlation from causation.
- Provide human-readable explanations and source lineage.
- Require human review for consequential decisions.

**P6.3 — Monitoring and alerting**
- Define approved signals, thresholds and notification policy.
- Support rate limits, deduplication and alert fatigue controls.
- Provide clear reason and evidence for each alert.
- Do not infer sensitive personal characteristics or create covert individual surveillance.

**P6.4 — Simulation and scenario planning**
- Provide scenario models with explicit assumptions.
- Distinguish simulated outcomes from observed facts.
- Run sensitivity and stress tests.
- Keep simulation environments isolated from production effects.

**P6.5 — Domain packs**
- Add domain-specific knowledge, workflows and evaluation suites only after source, safety and governance review.
- Keep domain policy and data access scoped.
- Require expert validation for high-stakes domains.

### P6 deliverables
- Analytical and forecasting framework.
- Explainable decision-support interface.
- Domain-specific benchmark suites.
- Monitoring and alert governance.
- Model-risk and bias assessment.

### P6 exit criteria
- Predictive performance is measured on held-out, representative data.
- Calibration and false-positive/false-negative costs are documented.
- High-impact decisions remain human-accountable.
- Data provenance, privacy and fairness reviews pass.
- Owner accepts the specific domain deployment scope.

---

## P7 — Native IROKA OS, programming language and developer ecosystem

**Objective:** establish a native platform and language only after stable Kernel, runtime, security, API and developer requirements are proven.

### Work packages

**P7.1 — OS/runtime requirements**
- Define target environments, process model, isolation, resource model and update strategy.
- Decide whether IROKA OS is a dedicated operating system, a secure runtime/distribution, or a layered platform on existing operating systems.
- Prefer incremental runtime delivery before attempting a new general-purpose kernel.
- Define portability and hardware support targets.

**P7.2 — Native language research and design**
- Define language purpose, semantics, type system and memory/concurrency model.
- Define capability-safe APIs and effect system for protected operations.
- Design compiler/interpreter, package format, module system and tooling.
- Specify deterministic and reproducible build requirements.
- Evaluate interoperability with Rust, Python and TypeScript.
- Require a formal language specification before production compiler commitments.

**P7.3 — Futuristic writing-system and interface interoperability**
- Treat the writing system as a language/script research and design program, not as a replacement for accessible standard text.
- Define Unicode, normalization, font, input, rendering, search and accessibility strategy.
- Preserve interoperable text representation and transliteration where appropriate.
- Ensure users can always access content through standard, documented formats.

**P7.4 — Developer platform**
- Provide SDKs, APIs, extension manifests and local test harness.
- Define package signing, provenance, sandbox permissions and review process.
- Publish compatibility/versioning policy.
- Create example applications and developer documentation.

**P7.5 — OS security and update**
- Secure boot or equivalent verified startup where supported.
- Signed updates, rollback protection and recovery.
- Process and storage isolation.
- Device identity and key custody.
- Vulnerability disclosure and patch lifecycle.

### P7 deliverables
- Native runtime architecture decision record.
- Language specification and prototype.
- Compiler/interpreter proof of concept.
- SDK and package model.
- OS/runtime threat model and update design.

### P7 exit criteria
- A demonstrated use case justifies the native runtime/language investment.
- Language semantics, safety model and interoperability are documented.
- Reproducible builds and package provenance are demonstrated.
- Security review and recovery tests pass.
- Owner separately approves productionization.

---

## P8 — Controlled deployment, operations and ecosystem expansion

**Objective:** release only verified capabilities into explicitly approved environments and operate them with measurable service quality.

### Work packages

**P8.1 — Release engineering**
- Reproducible builds and signed artifacts.
- SBOM, dependency/license inventory and vulnerability scan.
- Environment-specific configuration and secrets management.
- Database migration, rollback and compatibility plan.
- Release candidate tied to exact commit and artifact digest.

**P8.2 — Operational readiness**
- SLOs for availability, latency, error rate, task completion and recovery.
- Capacity, cost and rate budgets.
- Monitoring, alerting and incident response.
- Backup/restore and disaster recovery drills.
- Security incident and key-compromise playbooks.
- Support and user communication procedures.

**P8.3 — Staged rollout**
- Development environment.
- Synthetic-data integration environment.
- Controlled internal pilot.
- Limited external pilot after applicable approvals.
- Production only after explicit release decision.

**P8.4 — Governance and compliance**
- Data protection and privacy review for target jurisdiction and data classes.
- Legal, regulatory and sector-specific review where applicable.
- Vendor and processor risk review.
- Retention, deletion, export and incident processes.
- Independent security and operational assessment.

**P8.5 — Continuous assurance**
- Regression and adversarial test suite.
- Model and provider change evaluation.
- Drift and data quality monitoring.
- Periodic access and key reviews.
- Recovery exercises and audit sampling.
- Release rollback triggers.

### P8 exit criteria
- Exact release candidate passes A4.
- Critical/high findings are resolved or explicitly risk-accepted.
- Operational and recovery objectives are demonstrated.
- Data, legal and vendor reviews are complete for the target scope.
- Owner issues separate A5 release authorization.

---

## 5. Cross-cutting engineering programs

These programs run across phases and must have named owners and traceable acceptance criteria.

### 5.1 Security engineering
- Threat modeling at design and material-change points.
- Secure coding and code review.
- SAST, dependency and secret scanning.
- Fuzzing and property-based tests for parsers, protocols and authorization.
- Penetration testing by independent reviewers at defined gates.
- Vulnerability severity, remediation SLA and exception process.

### 5.2 Privacy and data governance
- Data inventory, classification and lawful-purpose record.
- Data minimization and retention limits.
- Tenant isolation and least-privilege access.
- Consent and user control where applicable.
- Data subject request and deletion/correction workflows where legally required.
- Cross-border and third-party model transfer review.

### 5.3 Reliability engineering
- Timeouts, retries, idempotency and circuit breakers.
- Durable queues and workflow recovery.
- Backpressure and resource limits.
- Failure injection and chaos tests in isolated environments.
- Backup, restore and disaster recovery exercises.

### 5.4 Observability and audit
- Structured logs, metrics and traces.
- Correlation IDs across user, task, model, agent, tool and workflow.
- Sensitive-data redaction.
- Audit event integrity and access controls.
- Operator dashboards and incident runbooks.

### 5.5 Evaluation and model risk
- Versioned task suites and representative datasets.
- Quality, factuality, calibration, safety, latency and cost.
- Provider/model regression tests.
- Amharic and regional language evaluation.
- Independent human review for culturally or contextually sensitive results.
- No unsupported claim of frontier-level performance.

### 5.6 Cost and resource discipline
- Per-task and per-user budgets.
- Model routing by approved quality/privacy/cost policy.
- Local inference where justified by privacy, latency or availability.
- Resource quotas and runaway-loop prevention.
- Prefer free/public CI and local/synthetic testing where practical.
- No implementation step may assume Owner can pay, top up, deposit or subscribe to a paid service. Any paid dependency requires a separate feasibility and approval decision; provide a no-cost alternative where possible.

### 5.7 Localization and inclusion
- Amharic-first information architecture and UX.
- Ethiopic script and Unicode correctness.
- Ethiopian calendar and local time support with tested conversions.
- Low-bandwidth and offline-aware design.
- Local data provenance and community review.
- Accessible design and language-quality measurement.

---

## 6. Benchmark and acceptance framework

IROKA must be evaluated against current frontier models and relevant specialist systems using reproducible tests. Public vendor claims are not a substitute for independent measurement.

### 6.1 Benchmark dimensions

| Dimension | What to measure | Evidence |
|---|---|---|
| Reasoning | Accuracy, consistency, uncertainty and multi-step success | Fixed task sets and independent scoring |
| Coding | Correctness, tests passed, regression rate and maintainability | Reproducible repositories and test harness |
| Research | Source quality, citation accuracy, coverage and contradiction handling | Audited source-grounded tasks |
| Memory | Recall precision, freshness, correction and deletion correctness | Controlled longitudinal test corpus |
| Planning | Goal completion, plan validity, cost and recovery | Simulated workflows |
| Tool use | Schema correctness, authorization compliance and side-effect safety | Sandboxed tool benchmarks |
| Agent safety | Privilege escalation, prompt injection and runaway prevention | Adversarial test suite |
| Multimodal | OCR, speech, image and document task quality | Licensed/consented datasets |
| Amharic/localization | Task accuracy, fluency, script handling and dialect robustness | Human-reviewed language corpus |
| Reliability | Availability, latency, recovery and idempotency | Load and failure-injection tests |
| Trust | Identity, approval, audit, revocation and witness evidence | Cryptographic and operational verification |
| Cost efficiency | Cost per successful task and resource use | Metered, comparable runs |

### 6.2 Comparison protocol

- Freeze task set, prompt, data, tools, model versions and scoring before each run.
- Use identical budgets and comparable access for all candidates.
- Separate model-only results from full IROKA system results.
- Report sample size, confidence intervals and known dataset limitations.
- Keep failures and abstentions in the score.
- Avoid cherry-picking or comparing different task difficulty.
- Publish dated benchmark reports with exact code and dataset version.

### 6.3 Suggested acceptance principles

Numerical targets must be set from a measured baseline and use case risk, not invented before data exists. Each benchmark must define:
- Metric and scoring rubric.
- Baseline and target.
- Minimum sample size.
- Confidence or error bounds.
- Dataset/source provenance.
- Release-blocking regression threshold.
- Owner and independent reviewer.

---

## 7. Technical strategy and provisional technology choices

No technology is approved solely because it is named here. Final selection requires A2 review for licensing, security, maintainability, cost, portability and fit.

| Concern | Provisional direction | Decision rule |
|---|---|---|
| Trusted Kernel | Rust | Use for security-sensitive deterministic enforcement |
| Cognitive runtime | Python and/or Rust | Select based on ecosystem, isolation and performance |
| UI and workspace | TypeScript | Typed accessible web interfaces |
| System of record | PostgreSQL or equivalent | Transactional integrity and migration discipline |
| Search/retrieval | Replaceable lexical/vector adapters | Never make retrieval store an authority source |
| Workflow | Durable state machine/queue | Demonstrate replay, retry and recovery |
| Model integration | Provider-neutral gateway | Replaceability, privacy and observability |
| Telemetry | OpenTelemetry-compatible design | Redaction and tenant separation |
| Packaging | Reproducible containers/packages | Signed provenance and least privilege |
| Local inference | Optional model-serving adapters | Only where hardware, quality and security justify it |

Third-party frameworks remain candidates until exact version, license, provenance, transitive dependencies, security history and replacement cost are reviewed. Do not copy source or adopt a service without the required review.

---

## 8. Repository and documentation organization

The target organization is incremental. Do not create empty service scaffolding simply to match this tree.

\`\`\`text
.
├── README.md
├── docs/
│   ├── IMPLEMENTATION_STRATEGY.md              # historical initial baseline
│   ├── IMPLEMENTATION_STRATEGY_V2.md           # proposed master roadmap
│   ├── roadmap/
│   │   ├── PHASE_STATUS.md
│   │   ├── DEPENDENCY_GRAPH.md
│   │   ├── ACCEPTANCE_REGISTER.md
│   │   └── BENCHMARK_STRATEGY.md
│   ├── constitution/
│   ├── architecture/
│   ├── governance/
│   ├── security/
│   ├── domains/
│   ├── decisions/
│   ├── assurance/
│   ├── localization/
│   └── operations/
├── contracts/
│   ├── identity/
│   ├── authorization/
│   ├── audit/
│   ├── model-gateway/
│   ├── knowledge/
│   ├── memory/
│   ├── perception/
│   ├── agents/
│   ├── orchestration/
│   └── execution/
├── crates/                                     # Rust modules already established
├── services/                                   # introduced after contract approval
├── adapters/
├── evals/
├── tests/
└── tooling/
\`\`\`

Existing directories and code take precedence over this conceptual target tree. Do not duplicate a domain or create a second source of truth.

### Required planning registers

1. **Requirement traceability:** requirement → chromosome → component → threat/control → test → evidence.
2. **Decision register:** decision, alternatives, rationale, owner, date, status and supersession.
3. **Dependency register:** exact package/version, license, SBOM, vulnerability state and approval.
4. **Risk register:** severity, likelihood, mitigation, owner, residual risk and acceptance.
5. **Phase status register:** scope, exact SHA, PR, CI, tests, unresolved work and closure approval.
6. **Benchmark register:** dataset, tasks, model/version, metrics, sample size and results.
7. **Data register:** source, classification, purpose, retention and access policy.

---

## 9. Phase dependencies and critical path

The following is the recommended dependency sequence, not a claim that every phase must be strictly serial:

\`\`\`mermaid
flowchart TD
  P0["P0 Trust foundation"] --> P1["P1 Cognitive core"]
  P0 --> P2["P2 Knowledge and memory"]
  P1 --> P2
  P0 --> P3["P3 Agents and orchestration"]
  P1 --> P3
  P2 --> P3
  P1 --> P4["P4 Multimodal and localization"]
  P2 --> P4
  P3 --> P5["P5 Assistant and workspace"]
  P4 --> P5
  P2 --> P6["P6 Predictive intelligence"]
  P3 --> P6
  P5 --> P7["P7 Native OS and language"]
  P0 --> P7
  P6 --> P8["P8 Controlled operations"]
  P7 --> P8
\`\`\`

Parallel work is allowed only when interfaces and security boundaries are stable. For example, localization research can proceed alongside P1, and multimodal adapter prototypes can run in isolated tests before broad production integration.

---

## 10. Verification gates for every work package

Every work package must complete the following sequence:

1. **Specification:** problem, scope, non-goals, owner and acceptance criteria.
2. **Contract:** interfaces, schemas, errors, data handling and compatibility.
3. **Threat analysis:** assets, trust boundaries, abuse cases and mitigations.
4. **Implementation:** smallest useful vertical slice with bounded changes.
5. **Automated verification:** unit, integration, contract, regression and negative tests.
6. **Security verification:** applicable static, dependency, secret, fuzz and adversarial checks.
7. **Operational verification:** logging, metrics, recovery, resource limits and runbook.
8. **Evidence capture:** exact SHA, workflow/run, commands, artifacts and result.
9. **Review:** independent review proportionate to risk.
10. **Closure decision:** Owner-approved closure where governance requires it.

A phase may be marked VERIFIED-CLOSED only when all required work packages and exit evidence are complete. Partial success must remain PARTIAL.

---

## 11. Governance, approvals and change control

### 11.1 Approval boundaries

- Documentation may be prepared as a proposal without authorizing implementation.
- A1 architecture freeze requires explicit Owner approval.
- A2 reconciliation is read-only unless separately authorized.
- A3 implementation requires explicit scope approval.
- A4 verification does not authorize merge or deployment.
- A5 release requires separate explicit authorization.
- Trust-root, identity, policy, production data and external operator changes require their specific approval.

### 11.2 Change classes

| Class | Examples | Required control |
|---|---|---|
| C0 Documentation | Clarifications, diagrams, non-normative roadmap | Review and version history |
| C1 Low-risk code | Isolated tests, non-sensitive utilities | Standard review and CI |
| C2 Security-relevant | Identity, policy, audit, memory access, tool gateway | Threat review, focused tests and explicit approval |
| C3 Critical governance | Trust roots, Owner authority, production permissions | Explicit Owner authorization and independent review |
| C4 Operational release | Deployment, production migration, external service activation | Separate A5 authorization and readiness evidence |

### 11.3 PR and branch policy

- Work on dedicated branches.
- Keep changes scoped and reviewable.
- Do not overwrite historical strategies; mark supersession clearly.
- Keep plan approval distinct from code approval.
- Do not merge a draft PR or change default branch without explicit authorization.
- Protect default branch and require review/status checks when repository settings and available controls permit; report if not configured.
- Never force-push or rewrite history to make status appear cleaner.

---

## 12. Risk register — initial strategic risks

| Risk | Impact | Required mitigation |
|---|---|---|
| Frontier-model dependency | Provider outage, lock-in, cost and policy exposure | Provider-neutral gateway and local fallback strategy |
| Unbounded autonomy | Unauthorized or harmful side effects | Kernel authorization, bounded grants and human gates |
| Memory poisoning/leakage | Persistent false facts or cross-user exposure | Provenance, classification, access checks and adversarial tests |
| Prompt injection | Tool misuse and instruction confusion | Untrusted-content boundary and tool authorization |
| Weak independent witness claims | False assurance | Separate cryptographic correctness from operator independence and retention proof |
| Supply-chain compromise | Code execution or data exposure | SBOM, license/security review, pinned dependencies and signed artifacts |
| Poor Amharic quality | Low trust and harmful misunderstanding | Human-reviewed language benchmarks and iterative evaluation |
| Premature OS/language scope | Excessive complexity and delayed usable product | Prove native runtime value after stable platform APIs |
| Cost or paid-service dependency | Work blocked by unavailable billing | Free/public CI, local tests, synthetic data and no-cost alternatives |
| Weak recovery | Data loss and duplicate side effects | Durable state, idempotency, backup/restore and drills |
| Surveillance misuse | Privacy and civil-rights harm | Purpose limitation, consent, minimization and prohibition of covert mass surveillance |
| Unsupported capability claims | Misleading readiness or competitiveness | Reproducible benchmarks and evidence-backed reporting |

---

## 13. Explicit non-goals and prohibited shortcuts

This roadmap does not authorize:

- Training a large foundation model as the first implementation step.
- Claiming frontier-model parity without reproducible benchmark evidence.
- Unrestricted A4 autonomy or self-authorization.
- Covert mass surveillance, generalized citizen scoring or unaccountable predictive policing.
- Production use of synthetic test credentials or test keys.
- Importing historical code without provenance, license and security review.
- Duplicating existing Kernel, identity, audit or memory ownership.
- Deleting or rewriting historical project work.
- Deploying, merging, activating external services or changing trust roots.
- Introducing paid services or payment requirements without separate approval.
- Treating a roadmap entry as an implementation authorization.

---

## 14. Immediate execution sequence after Owner review

1. Review this v2.0 roadmap and record approval, requested changes or rejection.
2. Reconcile the document against the current repository, open PRs and exact branch heads.
3. Create a phase status register and requirement traceability register from existing code and tests.
4. Keep A4-03 independent witness operations explicitly PARTIAL until live operator evidence exists.
5. Complete P0 work-package specifications and identify the minimum closure blockers.
6. Obtain explicit authorization for any P0 implementation changes not already covered by prior approval.
7. After P0 closure, approve P1/P2 contracts and implementation scope.
8. Proceed phase by phase, preserving exact commit-level evidence and separate A5 release governance.

### Current baseline note

This document is a strategic target, not a new status report. Existing A1/A2/A3/A4 labels must be reconciled against current GitHub evidence before any phase status is changed. In particular, an adapter passing CI does not establish live independent witness operation, and a feature-branch commit does not imply that the same code is present on \`main\`.

---

## 15. Owner decision record

**Requested decision:** approve, amend or reject the proposed IROKA Master Implementation Strategy v2.0.

| Decision item | Proposed state |
|---|---|
| Strategy document | Proposed v2.0 |
| Historical strategy | Preserve as reference |
| Current implementation | Preserve; no reset |
| Existing A4-03 | Remains PARTIAL pending live operational verification |
| New phases P0–P8 | Proposed roadmap |
| Implementation authority | Not granted by this document |
| Merge authority | Not granted |
| Deployment authority | Not granted |
| Paid service/payment | Not assumed or requested |

**Constitutional operating rule:**  
**Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.**
