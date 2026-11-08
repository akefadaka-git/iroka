# IROKA ZERO — First-Class Conversational Interaction Workstream

**Document status:** Proposed workstream contract for Owner review  
**Workstream ID:** CIW (Conversational Interaction Workstream)  
**Roadmap placement:** Cross-phase, first-class capability spanning P2–P5; initial delivery begins with P2/P3 foundations  
**Architecture domains:** G03 Cognitive, G04 Knowledge, G05 Memory, G06 Perception, G08 Orchestration, G11 Assurance, with G01/G02 governing identity and authority  
**Language priority:** Amharic-first; English supported from the first usable text interface  
**Implementation status:** NOT IMPLEMENTED as an end-to-end conversational product  
**Authorization boundary:** This document establishes scope and sequencing for A1/A2 planning. It does not authorize production deployment, external service activation, paid services, trust-root changes, merge, or protected side effects.

---

## 1. Mandate and outcome

Conversational interaction is a first-class IROKA product workstream, not a late UI feature and not merely a chat window attached to a model. IROKA must provide one coherent, persistent, multilingual interaction surface through which a person can ask, reason, research, create, inspect, and request governed actions.

The interface is the human-facing entry point to IROKA's cognitive capabilities. It must preserve the separation between the **cognitive plane** (interpretation, reasoning, planning and proposals) and the **control plane** (identity, policy, approvals, grants, execution authorization and audit).

The first useful release is a secure text conversation experience. Voice and other modalities follow as separate, testable increments without delaying the text foundation.

## 2. Explicit assurance boundary: witness independence is not a prerequisite

Independent witness enrollment and live A4-03 operational verification remain a separate assurance workstream. They are **not prerequisites** for:
- A1/A2 design and contract work for conversational interaction.
- Local, synthetic-data development and automated testing of the conversation subsystem.
- A controlled, non-production text-chat prototype using test identities, test data and non-production model credentials, once its own A3/A4 gates are approved and met.

They **remain relevant** to any release claim or operation whose assurance case depends on independently witnessed audit checkpoints. The conversational subsystem must not claim A4-03 closure, independent audit durability, or production trust assurance merely because it can chat.

No weakening or bypass of existing identity, Owner authority, approval, audit, revocation, tenant isolation, or fail-closed controls is permitted. Where an assurance dependency is genuinely required for a specific protected action, that action remains unavailable until its required control is verified; ordinary conversation must not be blocked by unrelated witness enrollment.

## 3. Product scope and release sequence

### CIW-0 — A1 architecture and requirements
- Define conversation, thread, turn, message, attachment, tool proposal, citation, memory reference and approval-prompt entities.
- Define user journeys: new conversation, resume, search history, rename/archive, delete subject to retention policy, export, stop generation, retry and report an answer.
- Specify streaming response behavior, cancellation, timeout, partial output and provider failure semantics.
- Define Amharic-first UI, Ethiopic script rendering, mixed Amharic/English input, Unicode normalization and accessible keyboard/mobile behavior.
- Define data classification, retention, consent, export/deletion and tenant boundaries.
- Threat-model prompt injection, malicious attachments, cross-thread leakage, memory poisoning, session theft, tool-output injection and model-provider compromise.
- Define acceptance criteria and a traceability matrix before implementation.

### CIW-1 — A2 read-only reconciliation and contracts
- Inventory existing G01/G02 identity and authorization, G03 cognitive interfaces, G04 knowledge, G05 memory, G06 perception, G08 orchestration and G11 audit implementations.
- Reuse existing contracts where verified; do not duplicate identity, policy, audit, workflow or memory ownership.
- Specify versioned APIs/events and persistence contracts for conversations, threads, turns, messages, attachments, citations and generation runs.
- Specify model-gateway adapter contract, provider-neutral streaming events, cancellation, retries, idempotency and budget limits.
- Specify authorization and audit hooks for every tool proposal and protected action.
- Review proposed dependencies, licenses, data handling and security posture before adoption.
- Produce exact reuse/adapt/missing dispositions and Owner decisions for unresolved architecture choices.

### CIW-2 — A3 text-chat vertical slice (after separate A3 approval)
- Authenticated conversation creation and thread isolation.
- User and assistant message persistence with ordered turn state.
- Streaming text responses through a provider-neutral model gateway.
- Amharic and English text input/output; safe Unicode and mixed-script handling.
- Conversation list, resume, pagination and search.
- Stop/cancel, retry and bounded timeout behavior.
- Source/citation rendering and explicit uncertainty disclosure.
- Usage, latency, token/cost and failure telemetry with sensitive-content minimization.
- No tool execution in the initial slice; the assistant may explain or draft proposed actions only.

### CIW-3 — Context, knowledge and governed memory
- Explicit per-thread context assembly and context-window budgeting.
- User-controlled memory consent and visibility.
- Separate working context, episodic conversation history and durable memory.
- Provenance-linked retrieval and citations.
- Memory correction, deletion, retention expiry and tenant/user access enforcement.
- Defenses against prompt injection and memory poisoning; retrieved content remains untrusted data, never system authority.

### CIW-4 — Governed tool and workflow interaction
- Typed tool registry and capability manifests.
- Read-only tools before write-capable tools.
- Plan preview showing target, scope, side effects, risk and expected result.
- Deterministic Kernel authorization for each protected action.
- Owner/human approval for actions requiring it, bound to exact action digest, target, scope and expiry.
- Short-lived, revocable grants; idempotency and bounded retries.
- Execution only through G09 adapters and durable G08 workflows.
- Outcome verification and auditable user-visible receipts.
- Denied, expired, revoked or indeterminate authorization fails closed.

### CIW-5 — Multimodal interaction
- Voice input/output with explicit recording and retention controls.
- Document/image input through G06 perception adapters, with provenance and malware/content safety checks.
- Audio transcription and speech synthesis as replaceable adapters.
- Later video and real-time multimodal interaction only after separate privacy, safety, performance and cost review.
- Preserve text transcript and user-visible modality indicators; never silently treat extracted content as trusted instructions.

### CIW-6 — Specialized agents and proactive assistance
- Multiple specialized agents behind one conversation surface.
- Agent identity and capability manifests under G07.
- Delegation bounded by parent authority, task scope, depth, time and budget.
- Durable orchestration and recovery through G08.
- Clear indication of which agent/model/tool produced each material result.
- Proactive actions only under explicit user configuration and revocable policy.

## 4. Reference architecture and ownership

| Concern | Primary owner | Conversation integration |
|---|---|---|
| Authentication, session, principal | G01 | Bind every thread and request to verified principal and tenant |
| Policy, risk, approvals | G02 | Authorize protected operations; never delegate authority to a model |
| Reasoning and response synthesis | G03 | Generate responses and structured proposals |
| Retrieval and source provenance | G04 | Ground responses and render citations |
| Conversation context and memory lifecycle | G05 | Govern persistence, retrieval, consent and deletion |
| Text/document/audio/image perception | G06 | Normalize inputs as untrusted observations |
| Agent identities and delegation | G07 | Later multi-agent interaction |
| Durable task lifecycle | G08 | Track generation and approved workflows; recover safely |
| Protected tools and side effects | G09 | Execute only with valid Kernel authorization |
| Evaluation and feedback | G10 | Measure quality, regressions and user feedback |
| Security, audit and observability | G11 | Enforce logging, evidence, monitoring and assurance |
| Versioning and controlled evolution | G12 | Govern model, prompt, policy and interface changes |

The conversation service owns conversation-domain records only. It must not become a second identity provider, policy engine, audit ledger, memory authority, or execution engine.

## 5. Non-negotiable security and privacy controls

1. Authenticate every request and enforce tenant/thread ownership on every read and write.
2. Treat user content, attachments, retrieved documents, model output and tool output as untrusted data.
3. Keep system/developer policy and secrets outside model-editable conversation content.
4. Do not expose credentials, hidden prompts, private chain-of-thought, or other users' context.
5. Enforce input/output size limits, rate limits, abuse controls and resource budgets.
6. Encrypt sensitive data in transit and at rest using approved platform controls.
7. Define retention and deletion separately for messages, attachments, telemetry, backups and legally required audit evidence.
8. Minimize sensitive content in logs; use opaque IDs, redaction and access controls.
9. Prevent cross-thread and cross-tenant retrieval, caching and memory leakage.
10. Make provider routing and data egress visible and policy-controlled.
11. Never allow a model response to authorize a tool call or alter Kernel policy.
12. Fail closed for protected actions when authorization, approval, revocation or audit prerequisites are indeterminate.
13. Provide stop-generation and session-revocation controls.
14. Record model/provider/version, prompt-template version, retrieval references and tool/action receipts without logging secrets.
15. Make limitations, uncertainty and source provenance visible to users.

## 6. Evaluation and acceptance gates

### Text-chat minimum acceptance
- Authentication and tenant isolation tests, including adversarial cross-user/thread access.
- Amharic and English functional test corpus, including mixed script, Ethiopic punctuation, Unicode normalization and long text.
- Conversation ordering, persistence, pagination, search, retry and cancellation tests.
- Provider timeout, disconnect, malformed stream, duplicate event and partial-response tests.
- Prompt-injection and untrusted-attachment tests.
- Data retention, export, deletion and memory-consent tests.
- Secret-leakage and sensitive-logging tests.
- Accessibility and mobile responsive checks.
- Latency, throughput, rate-limit and cost-budget measurements.
- Exact-HEAD verification evidence with environment, commands, results and known limitations.

### Tool-enabled acceptance (later gate)
- Unauthorized tool proposal is denied.
- Expired, revoked, replayed, wrong-target and wrong-scope grants are denied.
- Approval is bound to exact action digest and cannot be replayed.
- Tool output cannot inject instructions into the control plane.
- Idempotency, retry, cancellation and compensation behavior are verified.
- Audit records bind actor, conversation, task, tool, target, decision and outcome.
- No protected side effect occurs when audit or authorization requirements fail.

A successful text-chat test does not establish production readiness or independent witness assurance.

## 7. Delivery gates and governance

- **A1:** approve product scope, architecture, threat model, domain boundaries and measurable acceptance criteria.
- **A2:** complete read-only implementation reconciliation, contract design, dependency review and reuse/missing register.
- **A3:** separately authorize and implement one bounded vertical slice at a time.
- **A4:** verify the exact final SHA, including negative and failure-mode tests.
- **A5:** separately authorize any pilot or production release.

This workstream does not alter the status of existing PRs, A4-03, trust roots, or production controls. It does not authorize merging, deployment, paid provider activation, production credentials or unrestricted agent autonomy.

## 8. Immediate next steps

1. Record CIW as a first-class roadmap workstream and dependency map.
2. Perform CIW-1 A2 read-only reconciliation against the current destination repository HEAD.
3. Produce a conversation-domain contract and gap register, identifying exact existing modules to reuse.
4. Return A1/A2 findings and unresolved Owner decisions before requesting A3 implementation authority.

**Success definition:** a user can hold a secure, persistent, Amharic-first or English conversation with IROKA; IROKA can ground answers in governed knowledge; and any consequential action remains subject to the existing deterministic authority, approval, execution and assurance boundaries.

**Constitutional rule:** Conversation expresses intent. Cognition proposes. Governance decides. Authorization permits. Execution acts. Assurance verifies.


## 9. CIW-1 A2 technical contract

The detailed A2 integration contract is maintained in [CIW-1 A2 — Conversational Integration and Domain Contracts](CIW-1-A2-INTEGRATION-CONTRACTS.md). It records the Kernel reuse/adapt/missing register, proposed conversation/session and persistence model, API/event schemas, capability/resource matrix, G03 model-gateway boundary, data lineage, G08 boundary, threat model, exact A4 verification plan and unresolved Owner decisions.

The A2 contract is a proposal only. Its closure checklist explicitly distinguishes verified candidate Kernel behavior from unmerged feature-branch dependencies and unresolved tenant/session/policy decisions. It does not authorize A3 implementation, merge or deployment.
