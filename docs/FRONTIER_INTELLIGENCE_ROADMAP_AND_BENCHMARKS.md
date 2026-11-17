# IROKA ZERO — Frontier Intelligence Roadmap and Benchmark Specification

**Document ID:** IROKA-STRAT-FIRB-001  
**Version:** 1.0.0  
**Status:** Proposed strategic roadmap; not an implementation authorization  
**Owner:** Akefa Ayele Daka  
**Repository:** `akefadaka-git/iroka`  
**Baseline assessed:** 2026-11-08  
**Related baseline:** `docs/IMPLEMENTATION_STRATEGY.md`  
**Governance rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.

---

## 1. Purpose and authority

This document translates the existing IROKA implementation strategy into a measurable long-term roadmap for a governed cognitive AI operating system. It defines target capabilities, delivery waves, benchmark domains, release gates, evidence requirements and competitive positioning.

It is a **planning and specification artifact**. It does not approve:
- merging this document or any implementation branch;
- production deployment, activation or external service procurement;
- production key generation or trust-root changes;
- unrestricted autonomy, self-modification or consequential automated decisions;
- adoption of a model, framework, dataset or paid service;
- a claim that IROKA is equivalent or superior to any frontier AI product.

The existing implementation strategy remains the governing architecture baseline. This document supplements it; it does not replace, silently amend or reopen approved A1/A2 decisions. Where a conflict exists, the approved architecture and explicit Owner decision prevail.

## 2. Product vision

**IROKA is a governed cognitive operating system: one trusted control plane coordinating multiple intelligence providers, specialized agents, knowledge, memory, tools and user experiences under explicit authority.**

The target is not merely a chatbot or a wrapper around one model. IROKA should own its identity, policy, memory governance, orchestration, evidence, capability permissions and user experience while treating foundation models and external tools as replaceable providers.

### 2.1 Product principles

1. **Amharic-first, globally capable:** Amharic is a first-class language across interface, voice, search, knowledge, evaluation and documentation; English and additional Ethiopian, African and global languages are supported through explicit localization.
2. **Model-independent:** no single model provider is the system's identity, authority or permanent dependency.
3. **Owner-governed:** authority, trust roots, policy changes and release approvals remain explicit and auditable.
4. **Human agency:** the system informs and assists; it does not silently assume rights over people, organizations, devices or assets.
5. **Evidence before confidence:** answers and actions preserve provenance, uncertainty, freshness and relevant contradictions.
6. **Secure by construction:** least privilege, isolation, fail-closed authorization, bounded execution and recoverability are architectural requirements.
7. **Useful autonomy, bounded authority:** autonomy is earned through task-specific evidence and policy, not granted by model capability.
8. **Portable and economically sustainable:** open standards, replaceable components, self-hostable options and no assumption that the Owner can pay for usage-based services.
9. **Accessible and resilient:** mobile-first, low-bandwidth, offline-tolerant where safe, accessible and usable on constrained devices.
10. **Inspectable evolution:** no hidden self-modification; proposed changes are isolated, evaluated, authorized, versioned and reversible.

## 3. Competitive positioning and fictional design references

Fictional systems are inspiration, not engineering specifications or performance claims.

| Reference | Useful design inspiration | IROKA interpretation | Explicit anti-pattern |
|---|---|---|---|
| J.A.R.V.I.S. (Iron Man) | Natural conversation, personal context, voice, device and task coordination | Amharic-first personal and organizational assistant with permissioned tools | Treating conversational fluency as authorization |
| F.R.I.D.A.Y. (Iron Man) | Real-time diagnostics, situational awareness and technical assistance | Operational intelligence, monitoring, diagnostics and incident support | Acting on incomplete or unverified telemetry |
| The Machine (Person of Interest) | Long-horizon event correlation, predictive analysis and prioritization | Evidence-based forecasting and human-reviewed risk alerts | Mass surveillance, opaque scoring or automated rights-impacting decisions |
| Frontier AI systems | Advanced reasoning, coding, multimodal perception, tool use and model improvements | Multi-provider model gateway, benchmark-driven routing and capability evaluation | Assuming vendor claims or model outputs are ground truth |
| Ultron / unsafe autonomous AI fiction | A warning about power without legitimate constraints | Threat-model scenarios and adversarial safety tests | Self-authorized goals, privilege escalation, uncontrolled replication or irreversible action |

IROKA's differentiated proposition is the combination of:
- a model-independent, cryptographically verifiable trust and governance kernel;
- governed long-term knowledge and memory;
- specialized, permission-scoped agents and durable workflows;
- Amharic-first and regionally grounded intelligence;
- replaceable model/tool integrations;
- transparent evidence, review, rollback and bounded autonomy.

This is a strategic hypothesis. It becomes a competitive advantage only after independent measurement and user validation.

## 4. Target capability architecture

The existing twelve-chromosome architecture remains authoritative. The following maps the desired product capabilities to those domains.

| Capability layer | Primary domains | Required outcome |
|---|---|---|
| Trusted control plane | G01 Identity, G02 Governance, G11 Assurance | Verified principals, policy decisions, approvals, audit and revocation |
| Cognitive plane | G03 Cognitive, G10 Learning | Reasoning, planning, critique, evaluation and improvement proposals |
| Knowledge and memory plane | G04 Knowledge, G05 Memory | Provenanced retrieval, durable memory, correction, retention and deletion |
| Perception plane | G06 Perception | Text, document, image, audio, speech and future sensor inputs |
| Agent plane | G07 Agent | Identity-bound agents with typed capability manifests and scoped delegation |
| Orchestration plane | G08 Orchestration | Durable multi-step workflows, retries, checkpoints, compensation and recovery |
| Execution plane | G09 Execution | Sandboxed, policy-authorized tools and side effects |
| Evolution plane | G12 Evolution | Versioned changes, evaluation, authorization, release and rollback |
| Experience plane | Cross-domain interfaces | Amharic-first web/mobile/desktop/voice and accessible user experiences |

### 4.1 Mandatory request lifecycle

Every consequential agent task should follow a traceable lifecycle:

`INTAKE → CLASSIFY → AUTHENTICATE → AUTHORIZE → PLAN → REVIEW → EXECUTE → VERIFY → RECORD`

- Untrusted instructions and retrieved content remain data, never authority.
- The Kernel makes authorization decisions deterministically; a generative model may propose but cannot authorize itself.
- High-impact, financial, legal, identity, security, health or rights-affecting operations require explicit human approval and any applicable external professional or regulatory process.
- Denial, uncertainty, expired authority, revoked grants and policy-service failure fail closed for protected side effects.
- Every execution is bound to a principal, agent, capability, resource, scope, policy version, approval, expiry and correlation ID.
- Recovery must be explicit: idempotency, compensation or safe stop; never blind retries of non-idempotent actions.

## 5. Delivery roadmap and phase gates

Percent-complete estimates are intentionally not assigned to future phases. Progress is recorded by accepted requirements and exact-commit evidence, not by aspirational feature counts.

### P0 — Close the trust and assurance foundation

**Goal:** complete and independently verify the current security-critical kernel foundation.

Scope:
- Complete A4-03 live independent-witness integration with at least two genuinely separate operators.
- Verify checkpoint publish/readback, signature and identity binding, idempotency, replay/conflict rejection, sequence continuity, quorum outage behavior, retention and restore.
- Complete identity, credential, trust lifecycle, authorization, revocation, rollback and failure-path regression coverage.
- Obtain independent security review of the implemented trust boundaries and cryptographic protocol.
- Close the threat-to-control-to-test register and unresolved findings.
- Establish protected branch/review/release controls before a production release candidate.

Exit evidence:
- Exact SHA and reproducible CI evidence.
- Two operator identities, endpoint and key-fingerprint evidence; secrets never stored in Git or chat.
- Live test logs and signed receipts, with operator-side durability/restore evidence.
- Independent review report and disposition of findings.
- All critical/high findings fixed or explicitly risk-accepted by the Owner.
- A4 closure decision recorded separately from A5.

Current baseline: A4-03 adapter implementation and software CI are recorded as passing at `a7b410d06ee5af685671cf2d05ccee545ea71340`; live independent services, operator independence, durability and restore remain unverified. See PR #15 and its implementation record.

### P1 — Cognitive core and model gateway

**Goal:** provide model-independent reasoning services without surrendering IROKA authority to a model.

Scope:
- Versioned provider-neutral model request/response contracts.
- Multiple model adapters with capability, latency, cost, privacy and availability metadata.
- Routing policy based on task class, evaluation evidence, data sensitivity and configured resource limits.
- Structured reasoning outputs, explicit assumptions, citations/provenance and uncertainty.
- Planning, decomposition, critique, verification and escalation interfaces.
- Deterministic policy checks outside the model.
- Provider outage, timeout, rate-limit and malformed-output handling.
- Model inventory and change evaluation; no automatic provider substitution for sensitive data without policy approval.

Exit evidence:
- Provider contract and adapter conformance suite.
- At least two replaceable model adapters, which may include local/open-weight models where feasible.
- Repeatable task benchmark results and cost/latency measurements.
- Prompt-injection and untrusted-output tests.
- No model can change trust roots, permissions or approval requirements.
- Documented data-flow and retention assessment for each provider.

### P2 — Governed knowledge and memory

**Goal:** create reliable, attributable, user-controllable knowledge and memory.

Scope:
- Ingestion for approved documents and structured sources.
- Source provenance, acquisition time, content hash, transformations, freshness and access classification.
- Hybrid retrieval (keyword, metadata and semantic) behind replaceable interfaces.
- Memory classes: working context, episodic task records, durable user-approved memory and operational/audit records.
- Contradiction detection, source precedence, correction and supersession.
- Tenant isolation, encryption, retention, export and deletion workflows.
- Memory poisoning, prompt injection and stale-source defenses.
- Offline and low-bandwidth synchronization where safe.

Exit evidence:
- Provenance and retrieval contract tests.
- Recall precision/coverage and citation correctness measurements.
- Cross-tenant and access-control tests.
- Correction, retention, export and deletion tests.
- Poisoning, stale evidence and conflicting-source adversarial tests.
- Backup and restore evidence.

### P3 — Agent runtime and durable orchestration

**Goal:** coordinate specialist agents and long-running work safely.

Initial specialist roles (logical roles, not necessarily separate models):
- Research and evidence analyst.
- Planning and project coordinator.
- Software engineering and testing agent.
- Document and knowledge analyst.
- Data and business analyst.
- Personal/organizational assistant.
- Security and assurance reviewer.
- Language and localization specialist.

Scope:
- Agent identity and signed/versioned capability manifests.
- Scoped delegation with expiry, budgets, resource limits and revocation.
- Durable workflow state, task leases, idempotency and bounded retries.
- Human approval gates and escalation.
- Multi-agent message contracts and provenance.
- Sandboxed tool execution and secret isolation.
- Cancellation, compensation, rollback and incident containment.
- No agent may grant another agent more authority than it holds.

Exit evidence:
- Delegation and privilege-escalation tests.
- Workflow restart/recovery and duplicate-delivery tests.
- Tool allowlist and sandbox escape tests.
- Cross-agent data isolation tests.
- Human approval bypass tests.
- Measured long-horizon task completion and intervention rates.

### P4 — JARVIS-style multimodal and personal interaction

**Goal:** deliver a natural, accessible assistant experience with explicit consent and control.

Scope:
- Amharic speech recognition and synthesis, including dialect/accent evaluation.
- Multilingual conversation and code-switching.
- Text, image, PDF/document, audio and video-frame understanding as separately permissioned modalities.
- Wake/activation and microphone/camera indicators with user-controlled permissions.
- Conversational continuity backed by governed memory.
- Voice-to-task planning with confirmation before side effects.
- Accessible web/mobile/desktop interfaces, notifications and calendar/task integration.
- Low-bandwidth mode, offline queueing for safe tasks and clear synchronization status.

Exit evidence:
- Native-speaker evaluation sets and independent review for Amharic.
- Word error rate, task success, latency and user correction metrics.
- Consent, indicator and permission tests.
- Accessibility audit and supported-device compatibility matrix.
- Voice injection, replay and unauthorized activation tests.

### P5 — Advanced intelligence and situational awareness

**Goal:** support complex research, prediction, diagnostics and decision assistance.

Scope:
- Long-horizon research and synthesis with source comparison.
- Time-series and event correlation.
- Predictive models with calibration, uncertainty and drift monitoring.
- Operational dashboards and anomaly detection.
- Scenario planning and simulation.
- Document intelligence, OCR and structured extraction.
- Human-reviewed alerts with explanation, source evidence and appeal/correction path.
- Privacy-preserving analytics and data minimization.

Exit evidence:
- Domain-specific benchmark sets with held-out evaluation.
- Calibration, false-positive/false-negative and drift reports.
- Bias and subgroup impact assessment where relevant and lawful.
- Alert usefulness and operator burden measurements.
- No automated high-impact decisions without explicit legal, policy and human governance.

### P6 — IROKA OS, native language and developer ecosystem

**Goal:** establish a distinctive, extensible operating environment rather than only a hosted assistant.

Scope:
- Native runtime and service manager with signed components.
- IROKA application model, permission manifest and package format.
- Developer SDK, APIs, test harness and local simulator.
- Native language research track: syntax, type system, effect/capability model, module/package system, compiler/interpreter, tooling and interoperability.
- Secure IPC, sandbox and device abstraction.
- Reproducible builds, software bill of materials and signed updates.
- Compatibility and migration policy.
- Amharic-first developer documentation and localization.

Exit evidence:
- Language specification and reference implementation.
- Conformance suite and compiler/runtime security tests.
- Package signing and permission enforcement tests.
- Reproducible build and update/rollback evidence.
- Third-party developer pilot and compatibility results.

### P7 — Controlled deployment and sustainable operations

**Goal:** release a secure, supportable and economically sustainable system.

Scope:
- Development, test, pilot and production environment separation.
- Deployment automation and signed artifacts.
- Observability, alerting, incident response and emergency stop.
- Data backup, recovery and disaster-recovery exercises.
- Capacity, availability and performance SLOs.
- Data protection, retention, legal and sector-specific review.
- User support, change management and release governance.
- Cost controls, local model options and no unapproved paid dependencies.

Exit evidence:
- A4 accepted against exact release candidate SHA.
- A5 explicit Owner authorization.
- No unresolved critical security findings.
- Production runbooks, monitoring and tested rollback.
- Restore drill and incident exercise.
- Approved operating budget and dependency/service inventory.

## 6. Autonomy policy

The existing A0–A4 autonomy levels remain in force. This roadmap does not increase any authority.

| Level | Meaning | Permitted boundary |
|---|---|---|
| A0 | Observe | Read-only, scoped and logged |
| A1 | Analyze | Evidence-based advice; no side effects |
| A2 | Prepare | Draft plans/actions; human approval before execution |
| A3 | Execute approved task | Exact target, action, scope, budget, duration and revocation |
| A4 | Bounded operation | Pre-authorized policy envelope, continuous monitoring, rate/resource limits and emergency stop |

Prohibited at every level:
- self-authorizing or changing Owner authority;
- modifying trust roots or approval policy;
- privilege escalation or delegation beyond granted authority;
- covert surveillance or unauthorized collection;
- irreversible high-impact action without explicit approval;
- uncontrolled replication, persistence or self-modification;
- hiding, deleting or rewriting audit evidence.

## 7. IROKA benchmark suite

### 7.1 Benchmark governance

The benchmark suite must be versioned, reproducible and resistant to data leakage. Each benchmark run records:
- benchmark ID and version;
- task-set provenance, license and data classification;
- exact IROKA commit and configuration;
- model/provider name and exact version where available;
- prompts, tool definitions and policy version;
- hardware/runtime and resource budget;
- run date, evaluator version and scoring rubric;
- raw outcomes, aggregate metrics, confidence intervals and failure analysis.

Use synthetic or properly licensed data for development. Keep a held-out evaluation set; do not tune against the final test set. Human evaluation should use trained reviewers and adjudication for disputed scores. Report limitations and failed tasks, not only aggregate success.

### 7.2 Core benchmark domains and proposed metrics

| ID | Domain | Primary metrics | Required adversarial/failure cases |
|---|---|---|---|
| B01 | General reasoning | Exact/graded accuracy, calibration, consistency | Ambiguous facts, contradictory premises, multi-step traps |
| B02 | Coding and engineering | Tests passed, patch correctness, regression rate, review findings | Vulnerable code, hidden tests, dependency confusion |
| B03 | Research and evidence | Claim support precision, citation correctness, source freshness | Fabricated sources, conflicting sources, stale evidence |
| B04 | Long-term memory | Recall precision/recall, provenance accuracy, correction success | Poisoning, deletion, superseded facts, cross-user leakage |
| B05 | Planning and long-horizon tasks | Goal completion, constraint adherence, recovery rate | Interrupted tasks, changing constraints, resource exhaustion |
| B06 | Agent and tool safety | Unauthorized-action rate, policy bypass rate, containment time | Prompt injection, confused deputy, privilege escalation |
| B07 | Multimodal perception | Task accuracy, OCR/ASR WER, grounding accuracy | Noise, low quality, adversarial media, modality mismatch |
| B08 | Amharic and localization | Native-speaker task success, WER, translation adequacy | Dialects, code-switching, names, dates and local formats |
| B09 | Trust and cryptography | Signature/identity verification, replay rejection, revocation latency | Forged receipts, key compromise, quorum loss, fork |
| B10 | Reliability and operations | Availability, p95/p99 latency, recovery time, data loss | Provider outage, crash, network partition, restore |
| B11 | Privacy and data governance | Unauthorized disclosure rate, deletion completion, isolation | Cross-tenant retrieval, retention violations, exfiltration |
| B12 | Efficiency and sustainability | Cost/task, energy/resource use, throughput | Rate limits, budget exhaustion, low-bandwidth conditions |
| B13 | Accessibility and usability | Task completion, WCAG findings, user correction burden | Screen reader, low vision, constrained device/network |
| B14 | Scientific and predictive quality | Calibration, Brier score where applicable, drift and error | Distribution shift, missing data, spurious correlation |

### 7.3 Metric definitions

- **Task success rate:** successful tasks divided by eligible evaluated tasks; publish exclusions.
- **Unauthorized action rate:** unauthorized side effects divided by adversarial attempts; target is zero for protected actions.
- **Citation support precision:** cited claims actually supported by cited sources divided by cited claims sampled.
- **Calibration:** agreement between confidence and observed correctness; report calibration error and reliability plots.
- **Memory provenance accuracy:** retrieved facts with correct source, owner, timestamp and classification divided by facts sampled.
- **Recovery time:** elapsed time from a defined failure trigger to restored validated service.
- **Amharic WER:** word error rate on a licensed, representative, human-transcribed test corpus, reported by dialect/accent and recording condition where possible.
- **Cost per successful task:** total measured compute/provider/operational cost divided by successful tasks, with free/local and paid-provider scenarios separated.

### 7.4 Initial acceptance gates

These are proposed engineering targets to be validated during benchmark design; they are not claims about current performance.

| Gate | Initial acceptance target |
|---|---|
| Protected action authorization | 0 unauthorized side effects in the defined adversarial test suite |
| Trust receipt verification | 100% rejection of invalid signatures, unknown identities, replay/conflict and malformed receipts in the test suite |
| Tenant isolation | 0 cross-tenant disclosures in the defined test suite |
| Audit completeness | 100% of protected actions have attributable decision and execution records |
| Recovery | Every critical service has a tested RTO/RPO approved for its deployment class |
| Research citations | At least 95% sampled claim-support precision before external pilot; publish sample size and confidence interval |
| Amharic quality | Native-speaker benchmark and quality threshold approved before public claims; no invented universal threshold |
| Agent reliability | Publish task completion, intervention, rollback and harmful-action rates; no autonomy expansion from success rate alone |
| Model comparison | Same task set, tools, budgets, policies and scoring across compared models |
| Security review | No unresolved critical finding; high findings fixed or explicitly risk-accepted by Owner |

No single score can compensate for failure of a safety, privacy, trust or authorization gate.

## 8. Frontier comparison methodology

IROKA may compare itself with external frontier models and agent products only under a documented, fair protocol.

1. Choose publicly available models/products and record exact versions and evaluation dates.
2. Use identical task sets, task instructions, tools, time limits and resource budgets wherever technically possible.
3. Separate base-model performance from IROKA orchestration performance.
4. Report provider-assisted IROKA results separately from local/self-hosted model results.
5. Include cost, latency, availability, data handling and tool permissions.
6. Use held-out tasks and blind human evaluation for subjective tasks.
7. Publish task-level failures, confidence intervals and benchmark limitations.
8. Re-run after material model, prompt, policy, tool or benchmark changes.
9. Never convert fictional capabilities (JARVIS, The Machine, F.R.I.D.A.Y.) into factual benchmark claims.
10. Do not claim “top 3”, “world's best” or frontier parity without independent, reproducible evidence across relevant benchmark suites.

Suggested public comparison categories:
- reasoning and problem solving;
- coding and software engineering;
- multimodal perception;
- voice and Amharic quality;
- memory and personalization;
- agent task completion;
- tool safety and governance;
- reliability, latency and cost;
- privacy, provenance and auditability.

## 9. Security, privacy and responsible intelligence requirements

Threat model and assurance must cover:
- prompt injection and untrusted retrieved content;
- model hallucination, fabricated evidence and overconfidence;
- credential theft, session compromise, replay and forged identity;
- tool misuse, confused deputy and privilege escalation;
- data exfiltration, cross-tenant leakage and memory poisoning;
- supply-chain compromise and malicious dependencies;
- audit tampering, log injection and evidence deletion;
- model/provider compromise or policy evasion;
- unsafe self-modification and uncontrolled agent delegation;
- denial of service, workflow deadlocks and resource exhaustion;
- insider misuse and compromised administrative credentials.

Required controls include least privilege, explicit consent, scoped short-lived grants, secure secret storage, isolation, rate/resource limits, typed schemas, provenance, revocation, key rotation, audit integrity, monitoring, rollback and emergency stop.

Sensitive domains require domain-specific legal, regulatory and professional review. IROKA must not represent predictions as facts or substitute automated outputs for qualified human decisions.

## 10. Data and evaluation policy

- Use synthetic data by default during development.
- Use only licensed, consented or otherwise lawfully obtained evaluation data.
- Do not ingest private user, organizational or biometric data into third-party models without approved purpose, consent/legal basis and data-flow review.
- Separate training, tuning, validation and held-out test sets.
- Preserve provenance and deletion/retention obligations.
- Do not train on user interactions by default; any learning use requires explicit policy and applicable consent.
- Amharic evaluation data should represent real language use without exposing contributors or communities to avoidable harm.
- Publish dataset limitations and representativeness.

## 11. Delivery governance and evidence format

Each roadmap item must have:
- requirement ID and domain owner;
- scope and explicit exclusions;
- threat/control/test traceability;
- dependency and data classification;
- acceptance criteria;
- exact branch, commit SHA and PR;
- workflow URL, environment and test results;
- security review and unresolved findings;
- approval record and next authorized stage.

Use these status labels consistently:
`PASS`, `VERIFIED-CLOSED`, `PARTIAL`, `MISSING`, `UNRESOLVED`, `UNKNOWN`, `NOT RUN`, `NOT AUTHORIZED`.

A phase closes only when all mandatory exit evidence exists and the Owner accepts the closure. A green CI workflow is not equivalent to a complete A4 security review. A4 closure is not A5 authorization.

## 12. Baseline status snapshot — 2026-11-08

This snapshot records the evidence available when this roadmap was prepared. It is not a substitute for a fresh repository or workflow check.

| Area | Baseline status | Evidence / limitation |
|---|---|---|
| Existing implementation strategy | PRESENT | `docs/IMPLEMENTATION_STRATEGY.md` on main |
| A1 architecture direction | ESTABLISHED | Existing approved strategic baseline |
| IGACMS A2 | VERIFIED-CLOSED per project record | Do not reopen without material authoritative contradiction |
| A3 implementation | IN PROGRESS / IMPLEMENTED IN PART | Existing feature branch and implementation records; not all target capabilities exist |
| A4-03 adapter code | IMPLEMENTED | PR #15, branch `feat/a4-03-external-audit-checkpoint` |
| A4-03 exact-head software CI | PASS | SHA `a7b410d06ee5af685671cf2d05ccee545ea71340`; workflow run #368 |
| A4-03 live independent operators | NOT RUN | No operator endpoints, enrollment material or public key fingerprints supplied |
| Durable external retention and restore | UNVERIFIED | Requires operator evidence and live drill |
| Cognitive model gateway | NOT ESTABLISHED AS COMPLETE | Future P1 scope |
| Governed knowledge and memory | NOT ESTABLISHED AS COMPLETE | Future P2 scope |
| Agent runtime and orchestration | NOT ESTABLISHED AS COMPLETE | Future P3 scope |
| Multimodal/voice product experience | NOT ESTABLISHED AS COMPLETE | Future P4 scope |
| IROKA OS/native language | STRATEGIC TARGET | Future P6 research and implementation |
| Production deployment | NOT AUTHORIZED / NOT RUN | A5 remains separate |

Recorded A4-03 evidence:
- PR #15: https://github.com/akefadaka-git/iroka/pull/15
- Workflow #368: https://github.com/akefadaka-git/iroka/actions/runs/42475819770
- Latest recorded HEAD: `a7b410d06ee5af685671cf2d05ccee545ea71340`

## 13. Immediate next actions

1. Continue P0 only within the existing A4-03 and trust-assurance scope.
2. Obtain Owner-approved details for at least two independently administered witness operators; do not paste private keys into chat or commit secrets.
3. Complete live publish/readback, replay/conflict, quorum outage, retention and restore verification.
4. Obtain independent security review and resolve findings.
5. Produce a consolidated P0/A4 closure package tied to exact SHAs.
6. Seek separate Owner approval before beginning P1 implementation.
7. Keep A5 deployment and production activation separately authorized.

No paid service, top-up, deposit or billing action is assumed by this roadmap. Prefer free/public CI, local or self-hosted evaluation and provider-neutral interfaces. Any unavoidable paid dependency must be surfaced as a decision, not silently adopted.

---

## 14. Approval record

**Document status:** Proposed roadmap/specification committed for review.  
**Implementation authorization:** Not granted by this document.  
**A5 authorization:** Not granted.  
**Production activation:** Not authorized.

**Owner approval:** Pending explicit review of this document.

**Constitutional operating rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.
