# IROKA ZERO — Implementation Strategy

**Document status:** Initial strategic baseline  
**Project:** IROKA — Intelligent Reasoning, Orchestration, Knowledge & Assurance  
**Motto:** Intelligence Guided by Wisdom. Governed by Integrity.  
**Repository:** `akefadaka-git/iroka`

## 1. Purpose

This strategy turns the IROKA ZERO constitutional DNA and twelve-chromosome Genome into a sequenced, evidence-driven implementation program. It defines what must be built first, which boundaries must remain independently governed, how external technology may be evaluated, and what evidence is required before each stage can close.

The objective is not to assemble a collection of agents around a model. The objective is to build a governed cognitive operating system in which identity, authority, knowledge, memory, orchestration, execution and evolution are controlled by explicit contracts.

## 2. Strategic outcomes

IROKA must ultimately provide:

1. A stable identity and trusted root independent of model providers.
2. A deterministic, auditable authority and policy boundary.
3. A modular cognitive runtime for reasoning, planning and metacognition.
4. Evidence-grounded knowledge and governed memory.
5. Perception and multimodal input adapters.
6. Agent identities and capability-scoped delegation.
7. Durable orchestration, workflow recovery and bounded execution.
8. A replaceable model and tool integration layer.
9. Independent assurance, evaluation and security controls.
10. Controlled learning and evolution with rollback and human authorization.

## 3. Non-negotiable architecture invariants

- No model, agent, plugin, tool or user-supplied document may self-authorize or modify the trust root.
- No agent may escalate privileges or delegate beyond its own authority.
- No consequential side effect may occur without a current, verifiable authorization decision.
- Denials, expired grants, revoked grants and indeterminate authorization outcomes must fail closed for protected operations.
- Policy, approval and execution decisions must be attributable and auditable.
- Tenant and data-classification boundaries must be enforced at every relevant service boundary.
- Memory must preserve provenance, purpose, access controls and retention/deletion semantics.
- Learning and self-modification must be evaluated in isolation before adoption.
- Critical governance, Kernel and identity changes require explicit Owner approval.
- Completion claims must cite reproducible evidence tied to an exact commit or release.
- External models are replaceable capability providers, never the source of IROKA's authority.

## 4. Target architecture

### 4.1 Governed Kernel (trusted control plane)

The Kernel is the root control plane and the first implementation priority. It owns:

- System and service identity validation.
- Owner authority and approval records.
- Policy evaluation and risk classification.
- Capability registration and scope enforcement.
- Agent delegation and revocation.
- Execution authorization and transaction boundaries.
- Audit events, evidence integrity and trace correlation.
- Emergency stop, containment and recovery controls.

Every protected operation receives an explicit decision: `ALLOW`, `DENY`, `REQUIRE_APPROVAL` or `ESCALATE`. The decision must bind the subject, action/capability, resource, scope, context, policy version, expiry and relevant risk attributes.

The Kernel must not depend on a generative model to make the final authorization decision. Models may supply analysis or structured proposals; deterministic policy and approval controls decide whether an operation is permitted.

### 4.2 Cognitive plane

The cognitive plane coordinates eight logical subsystems:

1. Core Reasoning
2. Knowledge
3. Strategic Planning
4. Engineering
5. Perception
6. Social and Communication
7. Critical Analysis and Assurance
8. Metacognition

These are logical responsibilities. They may use shared runtimes or multiple models, but they must expose typed, versioned interfaces and remain subordinate to Kernel authority.

### 4.3 Genome service domains

| Chromosome | Domain boundary | Primary outputs |
|---|---|---|
| G01 Identity | Identity, ownership, trust roots | Verified principals and identity assertions |
| G02 Governance | Policy, approvals, risk and authority | Decisions, approvals and policy versions |
| G03 Cognitive | Reasoning and planning | Structured analyses and plans |
| G04 Knowledge | Ingestion, retrieval and evidence | Provenanced knowledge and evidence references |
| G05 Memory | Memory lifecycle and controls | Classified memory records and retrieval results |
| G06 Perception | Text, image, audio and other inputs | Normalized observations with source metadata |
| G07 Agent | Agent identity and capabilities | Scoped agent definitions and lifecycle state |
| G08 Orchestration | Durable workflows and delegation | Traceable workflow state and task outcomes |
| G09 Execution | Tool adapters and side effects | Authorized execution results |
| G10 Learning | Evaluation and feedback | Evaluation reports and validated learning proposals |
| G11 Assurance | Security, testing and observability | Independent assurance evidence and findings |
| G12 Evolution | Version and change governance | Approved change records, releases and rollback points |

## 5. Delivery stages and gates

### A1 — Constitutional architecture and requirements

**Objective:** freeze a coherent architecture and implementation contract before code changes.

Work:
- Reconcile the DNA and twelve Genome chromosomes.
- Define trust boundaries, threat model and security assumptions.
- Define principal, capability, policy, approval, grant, audit and evidence concepts.
- Define data classification, tenant isolation and hybrid placement rules.
- Establish the binding Amharic-first Ethiopia baseline and African regional-profile architecture across language/script, localization, calendar/time, identity, documents, knowledge and jurisdiction.
- Define Ethiopia defaults (am-ET, en, Ethiopian calendar, Gregorian interoperability, Africa/Addis_Ababa and ETB) without hardcoding them into shared African core logic.
- Define original-script identity preservation, Amharic-first document/OCR/knowledge acceptance, provenance and human-review requirements.
- Define autonomy levels A0–A4 and permitted operation classes.
- Define service boundaries, interface ownership and dependency graph.
- Establish acceptance criteria, risk register, decision register and unresolved decisions.

A1 regional architecture artifacts:
- [A1 Amharic-First Ethiopian and African Architecture Contract](architecture/A1-AMHARIC-FIRST-REGIONAL-ARCHITECTURE-CONTRACT.md)
- [Regional Deployment Profile Contract](architecture/REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md)
- [A1 Requirements Traceability and Decision Register](architecture/A1-REQUIREMENTS-TRACEABILITY-AND-DECISIONS.md)
- [A1 Implementation Inventory](architecture/A1-IMPLEMENTATION-INVENTORY.md)

Exit evidence:
- Approved architecture baseline and version.
- Domain ownership and interface register.
- Threat model and data classification policy.
- Authorization decision and audit contracts.
- Acceptance matrix with positive, negative and failure-mode cases, including Amharic/Ethiopic and cross-profile conformance.
- Regional profile schema, precedence, versioning and migration contract.
- Implementation inventory tied to an exact code SHA, with MISSING/PARTIAL/NOT RUN statuses.
- Explicit Owner approval of architecture and material risk decisions.

### A2 — Historical evidence and implementation contracts

**Objective:** determine what can safely be reused and make implementation contracts executable and testable.

Work:
- Inventory historical branches and commits without altering the historical repository.
- Create a per-file disposition register for candidate historical material.
- For every candidate file, record imports, consumers, tests, workflows, script/config references, license/provenance status and review outcome.
- Classify each file as `RETAIN`, `ADAPT`, `REVIEW`, `RETIRE_CANDIDATE` or `EXCLUDE`, with evidence and reviewer rationale.
- Reconcile independent histories separately; do not force unrelated histories together.
- Review dependency licenses, transitive dependencies, security posture and maintenance.
- Specify API schemas, event contracts, storage semantics, failure behavior and migration/rollback contracts.
- Produce a traceability matrix from DNA invariant to domain, control, test and evidence.

Exit evidence:
- Complete, reviewed file-disposition register.
- Historical commit and branch provenance record.
- Dependency/license/SBOM assessment for every proposed dependency.
- Versioned interface and data contracts.
- Threat-to-control-to-test traceability.
- Explicit Owner approval to implement.

### A3 — Foundational implementation

Implementation must follow dependency order. Each increment is scoped, reviewed and committed independently.

**Wave 1 — Trust foundation**
- G01 identity and trust roots.
- G02 policy, Owner authority and approval lifecycle.
- G11 audit, evidence integrity and security primitives.

**Wave 2 — Controlled runtime**
- G08 durable orchestration and task state.
- G03 cognitive interfaces and model gateway.
- G04 evidence and knowledge ingestion/retrieval.

**Wave 3 — Context and actors**
- G05 governed memory.
- G06 perception adapters.
- G07 agent identity, capability manifests and delegation contracts.

**Wave 4 — Effects and evolution**
- G09 execution adapters and transaction controls.
- G10 evaluation and learning lifecycle.
- G12 versioning, change approval, release and rollback governance.

Implementation rules:
- Start with contracts and threat cases, then implement the smallest vertical slice.
- Keep the Kernel and policy authority independent of model/framework adapters.
- Use typed schemas, explicit errors, idempotency and bounded retries.
- Make protected side effects observable and attributable.
- Prefer append-only audit evidence with integrity protection.
- Keep model providers, vector stores, queues and agent frameworks behind replaceable adapters.
- Do not merge, deploy, migrate production data or change trust roots without the relevant explicit approval.

### A4 — Verification and assurance

**Objective:** prove that implementation meets the approved contracts under normal, adversarial and failure conditions.

Required verification:
- Unit and contract tests for every domain boundary.
- Authorization positive and negative tests.
- Expired, revoked, replayed, malformed and indeterminate grant tests.
- Privilege escalation and unauthorized delegation tests.
- Tenant-isolation and data-classification tests.
- Prompt injection and untrusted-content boundary tests.
- Audit completeness, integrity and traceability tests.
- Idempotency, concurrency, retry and transaction rollback tests.
- Memory provenance, correction, retention and deletion tests.
- Model/provider outage and adapter substitution tests.
- Backup, restore, recovery and emergency containment tests.
- Performance, capacity and resource-bound tests appropriate to deployment targets.
- Dependency, secret, static and dynamic security analysis.

Evidence must identify the exact repository, commit SHA, environment, command/workflow, result, logs/artifacts and unresolved limitations. A green test suite is not a substitute for security review or Owner acceptance.

### A5 — Controlled release and operations

**Objective:** release only a verified, authorized and recoverable build.

Release prerequisites:
- A4 verification accepted against the exact release candidate SHA.
- No unresolved critical/high security or authorization findings unless explicitly risk-accepted by the Owner.
- Signed/versioned artifacts and dependency inventory.
- Environment-specific configuration and secret management.
- Database migration and rollback/recovery plan.
- Observability, alerting, incident response and emergency stop.
- Backup/restore evidence and operational runbooks.
- Explicit release authorization.

Deployment must be staged (development, controlled test, pilot, production) with health gates and rollback triggers. A deployment attempt is not proof of successful production operation.

## 6. Autonomy and self-improvement governance

### Autonomy levels

| Level | Allowed behavior | Required control |
|---|---|---|
| A0 | Observe and report | Read-only scope |
| A1 | Analyze and advise | Evidence and uncertainty disclosure |
| A2 | Prepare proposed actions | Human review before execution |
| A3 | Execute specifically approved actions | Bound grant, target, scope and expiry |
| A4 | Operate within pre-authorized bounded policy | Continuous monitoring, limits, revocation and audit |

No level grants authority to change the Kernel, identity roots, constitutional policy or its own approval requirements.

### Evolution lifecycle

`MONITOR → DETECT → DIAGNOSE → PROPOSE → ISOLATE → TEST → EVALUATE → AUTHORIZE → IMPLEMENT → VERIFY → RECORD`

Change classes:
- **L1 — Report:** identify issues and provide evidence.
- **L2 — Propose:** prepare a change proposal and impact assessment.
- **L3 — Isolated experiment:** test in a sandbox with no production authority.
- **L4 — Approved implementation:** implement only after the required approval and change gate.

Critical Kernel, governance, identity, privacy and security-boundary changes require explicit Owner approval. Every accepted change needs provenance, test evidence, versioning and rollback.

## 7. Technology strategy

Technology choices are provisional until A2 review. Prefer mature, actively maintained components with permissive licenses, strong security practices and replaceable integration boundaries.

Potential implementation language roles:
- **Rust:** trusted Kernel components and security-sensitive enforcement where appropriate.
- **Python:** cognitive runtime, evaluation, model integration and research workflows.
- **TypeScript:** user-facing platform, control surfaces and developer interfaces.
- **PostgreSQL:** transactional system-of-record data and durable governance state.
- **Vector retrieval:** replaceable adapter for embedding and similarity search; never the authority source.
- **Messaging/workflows:** durable, observable orchestration with explicit recovery semantics.
- **OpenTelemetry-compatible instrumentation:** traces, metrics and logs with sensitive-data controls.
- **Containers:** reproducible isolated services and test environments.

Candidate libraries and frameworks are subjects for A2 evaluation, not approved dependencies. Evaluate policy engines, agent orchestration frameworks, retrieval systems, model serving and observability tools against: license, security history, maintainership, dependency footprint, determinism, portability, data handling, operational cost and ease of replacement.

Do not copy third-party source into IROKA until the exact version, license, provenance, notices and security implications have been reviewed and recorded.

## 8. Security and trust model

Threat model must include:
- Prompt injection and malicious retrieved content.
- Tool misuse, confused-deputy behavior and capability escalation.
- Credential theft, replay, session compromise and forged identity.
- Malicious or compromised model/provider responses.
- Data exfiltration, cross-tenant leakage and memory poisoning.
- Supply-chain compromise and dependency substitution.
- Audit tampering, log injection and evidence deletion.
- Unsafe self-modification and policy drift.
- Resource exhaustion, denial of service and workflow deadlocks.
- Insider misuse and compromised administrative credentials.

Security controls include least privilege, short-lived scoped grants, secure secret storage, signed or integrity-protected evidence, isolation, rate/resource limits, strict input/output schemas, explicit trust labels, revocation, key rotation, secure defaults and independent review.

## 9. Data, knowledge and memory governance

Every data class must define permitted sources, purpose, storage location, encryption, access roles, retention, export, deletion, backup and incident handling.

Knowledge records should preserve source, acquisition time, content hash where appropriate, transformations, confidence, freshness, access classification and conflicting evidence.

Memory must distinguish at least:
- Working context.
- Episodic interaction/task records.
- Durable knowledge or user-approved facts.
- Operational state and audit records.

These classes must not be conflated. Retention and deletion requirements differ; audit obligations must not become a pretext for retaining prohibited content.

## 10. Quality and evidence standard

Each deliverable must carry:
- Requirement and invariant references.
- Domain owner and interface version.
- Threat/control references.
- Test cases and results.
- Exact commit SHA.
- Build and dependency provenance.
- Review and approval record.
- Known limitations and risk status.

Use explicit statuses: `PASS`, `VERIFIED-CLOSED`, `PARTIAL`, `MISSING`, `UNRESOLVED`, `UNKNOWN`, `NOT RUN`.

Do not label a phase closed when its exit evidence is incomplete. Do not repeat scans or tests without a defined reason, changed input or new acceptance requirement.

## 11. Repository organization (initial proposal)

```text
.
├── README.md
├── docs/
│   ├── IMPLEMENTATION_STRATEGY.md
│   ├── constitution/
│   ├── architecture/
│   ├── governance/
│   ├── security/
│   ├── domains/
│   ├── decisions/
│   ├── assurance/
│   └── operations/
├── contracts/
│   ├── identity/
│   ├── authorization/
│   ├── audit/
│   ├── knowledge/
│   ├── memory/
│   ├── agents/
│   └── execution/
├── services/       # introduced only after A2 contract approval
├── adapters/       # replaceable external integrations
├── tests/
└── tooling/
```

This is a target organization, not authorization to create all directories or services immediately. Domain code must remain cohesive and must not duplicate ownership of identity, policy or audit state.

## 12. Immediate execution sequence

1. Verify repository metadata, default branch, README baseline and branch protections.
2. Finalize the README and this implementation strategy as the initial documentation commit(s).
3. Reconcile the historical IROKA branches and complete the per-file disposition register without modifying the historical repository.
4. Close A1 only after the constitutional and architecture documents, threat model, domain boundaries and acceptance criteria are internally consistent and Owner-approved.
5. Complete A2 implementation contracts and dependency/provenance decisions.
6. Request and record explicit A3 authorization before code implementation.
7. Implement in the dependency waves above, preserving exact commit-level evidence.
8. Complete A4 assurance and prepare A5 release evidence for separate authorization.

## 13. Explicit exclusions at this stage

This strategy does not authorize:
- Importing or merging historical repository branches.
- Deleting, rewriting or force-pushing historical work.
- Training a foundation model.
- Enabling unrestricted autonomous execution.
- Deploying production infrastructure or modifying production data.
- Adopting a dependency without A2 review.
- Changing Kernel trust roots or governance policy without explicit Owner approval.
- Claiming A1–A5 completion before each gate's evidence exists.

---

**Constitutional operating rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.


## 14. Amharic-first Ethiopian and African architecture contract

The normative regional and language requirements are defined in [A1 — Amharic-First Ethiopian and African Architecture Contract](architecture/A1-AMHARIC-FIRST-REGIONAL-ARCHITECTURE-CONTRACT.md).

That contract governs language and script, localization, calendar and time, identity, documents, knowledge, regional deployment profiles, and cross-cutting Kernel controls. It is mandatory for new design and implementation. Its existence establishes requirements only; runtime support remains subject to the contract's acceptance evidence and the A1/A2 gate process.
