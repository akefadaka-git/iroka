# CIW-2 A3 — Bounded Amharic-First Answer-Only Text-Chat Implementation Plan

**Document status:** Proposed for separate Owner A3 authorization  
**Workstream:** Conversational Interaction Workstream (CIW)  
**Plan date:** 2026-11-08  
**Planning baseline:** CIW A2 contract PR #20, head `843e5f1799a54335fa283e71f2d99c806b60a11d`  
**Implementation target:** One non-production, synthetic-data, authenticated answer-only text-chat vertical slice  
**Authorization status:** PLAN ONLY — A3 IMPLEMENTATION NOT AUTHORIZED  
**Release status:** No merge, deployment, pilot, production provider activation or production-data processing is authorized.

---

## 1. Executive proposal

Implement one deliberately narrow, non-production conversational vertical slice that allows an authenticated IROKA user to create and resume a private conversation, submit Amharic or English text, receive a streamed answer from a replaceable model-gateway adapter, stop generation, and review persisted turns.

The first slice is **answer-only**. It has no tool registry, G09 execution, external side effects, agent delegation, autonomous planning, durable memory, attachments, voice, image processing, or production knowledge ingestion. The model may answer, explain, summarize supplied synthetic text, and draft suggestions; it cannot authorize or perform actions.

The implementation must preserve the existing IROKA control-plane boundary. G01 remains the identity authority; G02/Kernel remains the authorization authority; the trusted policy lifecycle, tenant membership and session controls are mandatory application dependencies; conversation-domain audit is distinct from Kernel security-decision audit. Model output is untrusted data and never an authority signal.

A3 is proposed as a branch-only implementation with synthetic fixtures and non-production configuration. A4 exact-HEAD verification, merge and A5 deployment remain separate gates.

## 2. Six mandatory A3 entry dependencies

No user-facing end-to-end slice may be declared complete unless all six dependencies are implemented or, where explicitly stated, separately approved and verified.

### D1 — Select and pin the Kernel baseline

**Current condition:** PR #13 contains candidate Kernel interfaces at `813b24cbf81f049f2675fbb5492bdc9f262a9d87`; it is unmerged and is not automatically adopted.

**A3 task:**
- Reconcile the candidate against the repository target branch and any intervening Kernel changes.
- Submit an explicit baseline-selection record identifying the exact repository, branch/commit SHA, public APIs, feature flags and known limitations.
- Use only the production authenticated authorization path, including credential verification, revocation, constitutional baseline validation and audit append.
- Do not use test-only identity or authorization helpers, `NoRevocations`, or `Policy::evaluate()` as a complete authorization path.
- Keep the Kernel dependency behind a narrow adapter so the conversation domain cannot construct principals, decisions, trust roots or authorization grants.

**Gate:** baseline adoption is a prerequisite to implementation and requires Owner authorization if it entails adopting or changing the unmerged candidate. No merge of PR #13 is implied.

### D2 — Trusted, signed and versioned policy lifecycle

**A3 task:**
- Implement a trusted composition-root policy loader for a versioned policy bundle from an Owner-authorized source.
- Verify signature and integrity against an explicitly provisioned policy-signing trust root; validate schema, epoch, effective interval, digest, capabilities, approval requirements, risk ceilings and tenant applicability.
- Reject invalid signatures, rollback, expired or future-inapplicable policy, unknown schema, ambiguous rules, missing fields and stale/unavailable policy sources.
- Convert only verified bundles into immutable policy snapshots; request handlers and model/provider code must not construct or replace policy.
- Support atomic refresh; pin the exact policy version and digest to each authorization decision and audit record.
- Fail closed when no valid policy snapshot is available.
- Do not reuse credential trust roots for policy signing unless separately and explicitly authorized.

**Acceptance:** valid signed fixture loads; tampered, expired, rolled-back, malformed, stale and unavailable policy cases deny or escalate without generation.

### D3 — Authoritative tenant membership and isolation

**A3 task:**
- Resolve tenant membership from a trusted server-side source using the G01-verified subject.
- Resolve tenant ID, membership state/version, role and freshness; reject absent, suspended, revoked, ambiguous or stale membership.
- Treat a client tenant selector as a requested context only; never as proof of membership.
- Bind each conversation immutably to one tenant and one owner subject for this first slice.
- Enforce tenant and owner predicates on every create, list, read, append, pagination, search, cache operation and background task.
- Return non-disclosing not-found behavior for conversations outside the caller's authorized scope.
- Fail closed on resolver outage or indeterminate membership.

**Acceptance:** cross-tenant and cross-owner negative tests prove zero data leakage for every endpoint and storage access path. Shared threads and member grants remain out of scope.

### D4 — Bounded application sessions, revocation and stream cancellation

**A3 task:**
- Keep G01 credentials as the identity authority; application sessions are bounded transport conveniences only.
- Bind each session to verified subject, tenant, credential/session identifier, issue time, expiry, revocation version and status.
- Revalidate credential, membership and session status on each request and before stream start.
- Recheck during long-running streams and before committing terminal output.
- Propagate credential, key, membership or session revocation/expiry to active-stream cancellation; cancel upstream generation and prevent a revoked stream from committing a final answer.
- Fail closed if revocation or session state cannot be checked.
- Keep session lifecycle state separate from Kernel credential/approval state; do not create a competing identity authority.

**Acceptance:** expiry, credential revocation, membership suspension, session revocation and state-store outage block new requests and terminate active streams without persisting a completed assistant response.

### D5 — Concrete capability/resource mapping and measured limits

**A3 task:**
- Define server-owned capability names and canonical resource formats for conversation create, list, read, message submit, generation start, cancellation and permitted conversation metadata changes.
- Construct each Kernel authorization request server-side from the verified principal subject, constant server-defined capability, canonical tenant/conversation resource and risk classification.
- Enforce conjunctive checks: Kernel decision **and** tenant membership **and** owner ACL **and** valid session.
- Map DENY to stop; REQUIRE_APPROVAL to unavailable/pending without generation; ESCALATE or audit failure to fail closed. The answer-only slice must not implement approval-driven actions.
- Establish configurable hard ceilings for input bytes/tokens, output tokens, concurrent generations per subject and tenant, request rate, wall-clock duration, retries and spend.
- Measure provider/load behavior in a synthetic non-production environment and propose numeric ceilings with a transparent cost envelope for Owner approval. Do not invent production-safe values in this plan.
- Missing, invalid, zero-meaningless or inconsistent budget configuration denies generation; never interpret an absent budget as unlimited.
- Record usage and latency with sensitive-content minimization.

**Acceptance:** capability/resource matrix tests, policy denial tests, per-subject/per-tenant budget tests, concurrency/rate tests and missing-configuration fail-closed tests all pass.

### D6 — Synthetic-only model data and provider boundary

**A3 task:**
- Use synthetic prompts, synthetic conversation fixtures and non-sensitive test identities only.
- Implement a provider-neutral G03 gateway interface with a deterministic local fake/synthetic provider as the default A3 test adapter.
- Keep provider selection and credentials in trusted non-production configuration; never let a user or model select a provider or supply credentials.
- Do not send real shareholder, employee, customer, financial, identity, confidential or other production data to any model.
- Do not activate a paid/external provider or introduce provider credentials unless provider identity, retention, training use, regional processing, subprocessors, security terms and data-handling terms receive separate Owner approval.
- Record provider/model/version and request correlation metadata without logging secrets or unnecessary message content.

**Acceptance:** integration tests run entirely against synthetic fixtures/fake provider; test instrumentation confirms no production dataset or secret enters prompts, logs or provider calls.

---

## 3. Bounded user-visible scope

### Included

1. Authenticated sign-in/session handoff using the adopted G01 trust path.
2. Server-side tenant resolution and owner-only conversation access.
3. Create a conversation and list/resume the caller's own conversations.
4. Submit one text message and persist ordered user/assistant turn state.
5. Stream text answer events through the provider-neutral G03 gateway.
6. Amharic-first interface and response locale; English selectable from the first usable interface.
7. Mixed Amharic/English input, Ethiopic script, Ethiopic punctuation and Unicode-safe storage/rendering.
8. Explicit per-turn locale override or safe locale detection; locale is presentation/generation context only, never identity or policy input.
9. Stop/cancel generation, bounded timeout, controlled retry and idempotent submission.
10. Basic citation/source-reference rendering only where the synthetic fixture supplies provenance; do not imply unimplemented G04 retrieval.
11. Minimal operational telemetry: correlation ID, provider/model version, timing, token/usage counts, status and error class.
12. Configurable retention behavior and immediate access revocation/deletion workflow consistent with approved D03/D04 contracts.

### Explicitly excluded

- Tool registry, G09 execution, write operations or external side effects.
- Agent delegation, autonomous plans, proactive actions or G07.
- Owner approval workflow for actions; no protected action is exposed.
- Durable memory, cross-conversation personalization or automatic profile learning.
- Production knowledge ingestion, live enterprise connectors or unverified citations.
- Attachments, OCR, images, audio, voice, video or multimodal input/output.
- Shared conversations, team collaboration, tenant switching without membership revalidation.
- Production credentials, production data, public release, pilot or deployment.
- Independent witness enrollment as a prerequisite for this non-production text-chat slice; no independent assurance claim is made.

---

## 4. Proposed implementation work packages

| Work package | Deliverables | Dependency / exit condition |
|---|---|---|
| A3.0 Baseline pin and architecture guard | Exact Kernel baseline record; dependency pin; adapter boundary; threat/control traceability | D1 approved; no duplicate identity/policy/audit authority |
| A3.1 Trusted composition and policy | Signed policy loader, immutable snapshots, atomic refresh, fail-closed tests | D2 complete |
| A3.2 Tenant and conversation domain | Membership resolver port/adapter, owner-only ACL, tenant-scoped persistence and indexes | D3 complete |
| A3.3 Session lifecycle | Bounded sessions, revocation checks, active-stream cancellation hooks | D4 complete |
| A3.4 Authorization and budget guard | Capability/resource matrix, Kernel adapter, budget/rate/concurrency controls | D5 mappings approved; measured limits submitted |
| A3.5 Conversation API and persistence | Create/list/read/submit/cancel endpoints; ordered turns; idempotency; retention/deletion states | D1–D5 integrated |
| A3.6 G03 synthetic gateway | Provider-neutral request/stream interface; deterministic fake provider; typed events and cancellation | D6 synthetic boundary verified |
| A3.7 Amharic-first client | Responsive text UI; Amharic default; English switch; stream, stop, retry, history | API contracts stable |
| A3.8 Integration hardening | Failure handling, observability, privacy/log review, security and localization regression suite | All work packages complete; candidate for A4 |

Work packages may be sequenced or developed in isolated branches, but no package may bypass its dependency's gate. The implementation branch must remain separate from the A2 documentation PR.

## 5. Proposed API and event boundary

The A2 contract remains authoritative for detailed schemas. The implementation should expose only the minimum required operations:

- `POST /api/v1/conversations` — create owner-only conversation under server-resolved tenant.
- `GET /api/v1/conversations` — list only the authenticated owner's conversations in the resolved tenant.
- `GET /api/v1/conversations/{conversation_id}` — read authorized conversation and paginated turns.
- `POST /api/v1/conversations/{conversation_id}/turns` — idempotently submit a user message and begin answer generation.
- `POST /api/v1/conversations/{conversation_id}/turns/{turn_id}/cancel` — cancel an active generation.

Request payloads must not contain trusted `subject_id`, authoritative `tenant_id`, capability, resource, risk, policy version, approval result, provider credentials or execution grant. Server-side middleware and domain services derive those values.

Streaming events are typed and versioned: `turn.accepted`, `assistant.delta`, `assistant.completed`, `turn.cancelled`, `turn.failed`, and `usage.summary`. Every event carries conversation/turn/correlation identifiers and sequence information, but no credential or secret. Duplicate/out-of-order events must be safely handled. Revocation or authorization failure terminates the stream and prevents successful completion.

## 6. Persistence and data handling

- Conversation and message records are tenant-scoped and owner-bound; tenant binding is immutable.
- Store ordered turns with idempotency keys and explicit states: accepted, generating, completed, cancelled, failed.
- Keep security decision audit in the Kernel; maintain a separate conversation lifecycle event log.
- Do not copy raw message bodies, credentials, tokens or secrets into Kernel security audit.
- Use approved encryption in transit and at rest; do not label platform encryption as end-to-end encryption.
- Retention is configurable; no indefinite-retention default.
- Deletion immediately revokes access and marks content for purge under the approved legal, security-audit and backup-retention rules. Do not erase required security evidence.
- Export, cache, pagination and background processing must enforce the same tenant and owner constraints.
- Telemetry should prefer opaque IDs, event classes and bounded counters over raw content.

## 7. Threat controls required in the slice

| Threat | Required control |
|---|---|
| Forged identity / replayed credential | G01 verification, audience/expiry/revocation checks, bounded session |
| Tenant or conversation IDOR | Server-side membership resolution, immutable tenant binding, owner ACL, negative tests |
| Policy substitution / rollback | Signed policy bundle, trust-root validation, epoch/version/digest checks, atomic snapshots |
| Authorization bypass | Server-defined capability/resource; production Kernel path; conjunctive ACL checks |
| Revocation race during stream | Periodic and pre-commit checks; cancellation propagation; no completion after revocation |
| Prompt injection / model output authority | Treat all user/model content as untrusted; no tools or control-plane inputs from model |
| Provider data leakage | Synthetic-only data; fake provider by default; explicit provider approval gate |
| Resource exhaustion / cost abuse | Hard input/output/time/rate/concurrency/retry/spend ceilings; fail closed if config missing |
| Sensitive logging | Content minimization, redaction, secret scanning and audit separation |
| Cross-thread cache leakage | Tenant/owner keyed cache and isolation tests; no shared context |

## 8. A4 verification and acceptance plan

A3 is complete only when the implementation is ready for an independently gated A4 exact-HEAD verification. Required evidence:

### Security and authorization
- Valid, invalid, expired, revoked, wrong-audience and malformed credential cases.
- Policy signature tampering, rollback, expiry, unknown schema, stale source and unavailable source.
- Kernel ALLOW/DENY/REQUIRE_APPROVAL/ESCALATE and audit-sink failure behavior.
- Subject mismatch and client-supplied subject/tenant/capability/resource spoofing.
- Tenant membership absent, suspended, revoked, stale, ambiguous and resolver outage.
- Cross-tenant and cross-owner attempts across all API and storage operations.
- Session expiry/revocation and active-stream termination at every relevant checkpoint.
- No successful completion or persisted final answer after revocation/cancellation.

### Conversation correctness
- Ordered persistence, pagination, idempotent submit, duplicate events, retry, timeout, disconnect and partial response.
- Create/list/read/submit/cancel authorization and not-found non-disclosure.
- Retention configuration, immediate access revocation and deletion lifecycle.
- No duplicate conversation or identity authority.

### Language and UX
- Amharic default and English selection.
- Ethiopic script and punctuation, mixed Amharic/English, Unicode normalization, long input and output.
- Mobile responsive behavior, keyboard navigation and accessible labels.
- Correct display of partial streams, cancellation, failure and retry states.

### Provider, privacy and operations
- Fake provider used in all default automated tests.
- Synthetic-only fixture inspection and test proving no production data or credentials are sent.
- Input/output token, rate, concurrency, wall-clock, retry and spend limits.
- Missing/invalid budget config denies generation.
- Logs contain no secrets and avoid raw message content.
- Dependency/license/security review for any added package.
- Exact commands, environment, test outputs, commit SHA and known limitations recorded.

A4 must run against the exact final implementation SHA. Passing unit tests alone is insufficient; negative, failure-mode, integration and localization tests are mandatory. Production readiness is not established by A4 for this non-production slice.

## 9. Branching, change control and evidence

If A3 is separately authorized:
- Create a dedicated implementation branch from the exact approved base SHA.
- Keep changes limited to CIW-2 and required integration seams; do not refactor unrelated IROKA domains.
- No direct main-branch modifications.
- Record each work package, affected files, migration identifiers, dependency changes and exact commits.
- Preserve unrelated existing work and do not rewrite other PR branches.
- Use synthetic fixtures and local/fake-provider tests; avoid paid CI/provider requirements.
- Report workflow evidence when available; distinguish NOT RUN from PASS.
- Do not merge the A3 implementation PR. Merge requires a separate Owner decision after A4.
- Do not deploy, publish, pilot or activate a paid/external provider. A5 and provider activation require separate approval.

## 10. A3 completion definition

A3 may be submitted for A4 only when all of the following are true:

1. The exact Kernel baseline is selected and pinned under its own authorization.
2. Trusted signed/versioned policy lifecycle is implemented and fail-closed tests pass.
3. Authoritative tenant membership and owner-only isolation are implemented and negative tests pass.
4. Bounded sessions, revocation checks and active-stream cancellation are implemented and verified.
5. Capability/resource mapping is explicit; measured hard limits are configured and approved; missing configuration denies generation.
6. Synthetic-only provider boundary is demonstrated; no external provider or production data is activated.
7. Amharic-first/English text-chat UI and API support the included scope.
8. All required automated and integration tests pass; limitations are documented.
9. A3 implementation report records exact HEAD SHA, changed files, migrations, tests, evidence links and residual risks.

Any unresolved fail-open path, tenant leak, unverified policy source, missing budget, provider data egress uncertainty or revocation race blocks A3 completion.

## 11. Decisions reserved for the separate A3 authorization

This plan does not assume the following approvals:
- Adoption of PR #13's unmerged Kernel candidate or any other exact Kernel baseline.
- Selection/provisioning of the policy signing root and Owner-authorized policy source.
- Concrete numeric rate, token, concurrency, duration and spend ceilings after measurement.
- Any external/paid model provider, credentials, data-processing terms or non-synthetic data.
- Any schema migration or persistence backend choice not already approved by the repository's governing architecture.
- Any merge, release, deployment, pilot or production activation.

The Owner may approve the plan as written, approve it with amendments, or decline it. A3 implementation begins only after explicit authorization that identifies the approved scope and baseline. A4, merge and A5 remain separate decisions.

---

**Proposed disposition:** READY FOR OWNER A3 SCOPE REVIEW — NOT AUTHORIZED TO IMPLEMENT.

**Constitutional rule:** Conversation expresses intent. Cognition proposes. Governance decides. Authorization permits. Execution acts. Assurance verifies.
