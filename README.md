# IROKA ZERO

**Intelligent Reasoning, Orchestration, Knowledge & Assurance**

**Motto:** *Intelligence Guided by Wisdom. Governed by Integrity.*

IROKA ZERO is the foundation of a governed cognitive AI operating system designed to coordinate reasoning, knowledge, memory, perception, agents, orchestration and execution under explicit authority, evidence and assurance controls.

IROKA is intended to be model-independent: external and locally hosted AI models may provide capabilities, but they do not define IROKA's identity, policy, authority or trust boundaries.

## Project vision

Build a dependable cognitive operating system that can:

- Reason across complex technical, operational and organizational problems.
- Coordinate specialized cognitive capabilities and task-specific agents.
- Maintain traceable, permission-aware knowledge and memory.
- Perceive and interpret information from approved sources.
- Plan and orchestrate work across replaceable tools and models.
- Execute only within explicit, revocable and auditable authority.
- Evaluate its own outputs and proposed improvements before adoption.
- Operate across hybrid cloud and local environments while respecting data classification and privacy.

IROKA is not intended to be an unrestricted autonomous agent. Autonomy is bounded by policy, risk, scope, resource limits, human accountability and verifiable authorization.

## Constitutional principles

1. **Identity integrity** — IROKA's identity and governing principles are independent of any model or provider.
2. **Governed authority** — no model, agent, tool or external document can grant itself authority.
3. **Evidence before assertion** — material claims and completion states must be supported by traceable evidence.
4. **Bounded autonomy** — actions remain within explicit scope, capability, risk and time limits.
5. **Human accountability** — consequential and critical decisions retain the required human approval.
6. **Least privilege** — identities, agents and services receive only the minimum necessary permissions.
7. **Knowledge integrity** — provenance, confidence, freshness, conflicts and uncertainty are represented.
8. **Responsible memory** — memory is purpose-bound, classified, access-controlled, correctable and governed by retention rules.
9. **Security and privacy by design** — tenant isolation, data minimization and secure defaults are foundational.
10. **Controlled evolution** — self-improvement is proposed, isolated, evaluated, authorized and verified; never silently self-deployed.
11. **Modularity and replaceability** — models, providers and infrastructure components remain replaceable behind controlled interfaces.
12. **Lasting integrity** — operational convenience must not override constitutional safeguards.

## The IROKA Genome

The architecture is organized into twelve logical chromosomes:

| ID | Chromosome | Responsibility |
|---|---|---|
| G01 | Identity | System identity, ownership and trust roots |
| G02 | Governance | Policy, authority, approvals and risk decisions |
| G03 | Cognitive | Reasoning, planning and metacognition |
| G04 | Knowledge | Ingestion, retrieval, provenance and evidence |
| G05 | Memory | Working, episodic and durable memory under policy |
| G06 | Perception | Input interpretation and multimodal understanding |
| G07 | Agent | Specialized agent identities, capabilities and lifecycle |
| G08 | Orchestration | Workflow, delegation, coordination and recovery |
| G09 | Execution | Authorized tools, actions, transactions and effects |
| G10 | Learning | Evaluation, feedback and validated learning |
| G11 | Assurance | Security, testing, observability and independent verification |
| G12 | Evolution | Versioning, change control and governed self-improvement |

The twelve chromosomes are architectural boundaries, not a requirement for twelve separate deployable services or AI models.

## Governed Kernel

The Kernel is the trusted authority boundary. It owns identity validation, policy evaluation, approval state, risk classification, delegation limits, execution authorization, audit evidence, revocation and emergency containment.

Every protected operation must resolve to one of four explicit decisions:

- `ALLOW`
- `DENY`
- `REQUIRE_APPROVAL`
- `ESCALATE`

A model response or agent plan is not an authorization token. Protected side effects require a verifiable authorization decision bound to the actor, capability, target, scope, context and validity period.

## Bounded autonomy

IROKA uses explicit autonomy levels:

| Level | Meaning |
|---|---|
| A0 | Observe and report |
| A1 | Analyze and advise |
| A2 | Prepare proposed actions for review |
| A3 | Execute specifically approved actions within limits |
| A4 | Bounded autonomy within pre-authorized policy, scope and limits |

A4 is not unrestricted autonomy. Critical Kernel, identity, governance and trust-root changes require explicit Owner authorization.

## Deployment model

IROKA is designed for hybrid cloud and local operation. Placement decisions must follow data classification, security requirements, availability, latency, cost and operational constraints. Critical governance and authorization controls must not become dependent on an untrusted model provider.

## Language and regional architecture

IROKA is Amharic-first, Ethiopian-grounded and African-focused. This is a foundational architecture requirement, not a translation-only feature. The Ethiopia profile defaults to Amharic (am-ET), supports English (en), uses the Ethiopian calendar as its default civil display calendar, sets Africa/Addis_Ababa as its default time zone and ETB as its default currency. Other African deployments use independently configurable country and regional profiles; there is no universal African locale.

See [A1 — Amharic-First Ethiopian and African Architecture Contract](docs/architecture/A1-AMHARIC-FIRST-ETHIOPIAN-AFRICAN-CONTRACT.md) for binding requirements covering language, localization, calendar and time, identity, documents, knowledge, regional profiles, acceptance evidence and change control.

## Project status

**Current stage: foundational documentation and architecture reconciliation.**

The initial implementation strategy defines staged gates:

- **A1 — Architecture and requirements:** establish the constitutional baseline, domain contracts, threat model, data classification and acceptance criteria.
- **A2 — Evidence and implementation contracts:** reconcile historical work, verify interfaces and dependencies, and approve detailed contracts.
- **A3 — Implementation:** build the trusted Kernel and foundational services in dependency order.
- **A4 — Verification:** run security, authorization, isolation, reliability and acceptance evidence against exact commits.
- **A5 — Controlled release:** deploy only after explicit release authorization and verified operational readiness.

No stage is considered complete solely because code exists or a workflow passes.

See [Implementation Strategy](docs/IMPLEMENTATION_STRATEGY.md) for the phased plan, dependency order, controls and exit criteria.

## Repository and contribution status

This repository is the new IROKA ZERO destination. Historical IROKA repositories and branches are retained as separate reference material and are not implicitly merged or overwritten.

The repository is publicly visible. Public visibility does not itself grant permission to copy, modify, redistribute or sublicense proprietary project material. No third-party implementation is adopted merely by being listed as a candidate; dependencies require license, security, provenance and compatibility review before use.

Until an explicit license is added, no open-source license is granted by this repository. Do not submit secrets, private data, credentials or unreviewed third-party code.

## Guiding rule

**Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.**
