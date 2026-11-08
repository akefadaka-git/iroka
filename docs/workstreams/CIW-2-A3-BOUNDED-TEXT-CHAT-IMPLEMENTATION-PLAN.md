# CIW-2 A3 — Bounded Amharic-First Answer-Only Text-Chat Implementation Plan

**Status:** PROPOSED FOR SEPARATE OWNER A3 AUTHORIZATION  
**Prepared:** 2026-11-08  
**Parent A2 baseline:** PR #20, head `843e5f1799a54335fa283e71f2d99c806b60a11d`  
**Workstream:** Conversational Interaction Workstream (CIW)  
**Target:** One authenticated, tenant-isolated, persistent, streaming text-chat vertical slice  
**Implementation status:** NOT STARTED — this document is a plan only

---

## 1. Executive scope

Implement one narrow, non-production text-chat vertical slice that lets an authenticated IROKA user create and resume a private conversation, submit a text turn, receive a streamed Amharic-first or English answer, stop generation, and review persisted messages and citations.

The assistant is answer-only. It may explain, summarize, and draft text, but it cannot call tools, execute workflows, delegate to agents, change records, send communications, make purchases, or perform any protected side effect. Model output is untrusted content and never an authorization decision.

The slice uses synthetic fixtures and a synthetic model gateway only. No production provider, production user content, production credentials, live trust-root provisioning, paid service, public pilot, merge, or deployment is in scope.

**A3 is not authorized by this plan.** This plan is submitted for explicit Owner approval before runtime implementation begins.

## 2. A3 objectives and measurable deliverables

1. **Authenticated access:** Every API request is authenticated through the selected Kernel baseline and its production revocation path.
2. **Tenant and owner isolation:** Every conversation is immutably bound to one server-resolved tenant and one owner subject. The first slice has no sharing or member grants.
3. **Persistent chat:** Conversations, turns, messages, generation state, and citations are stored with tenant-scoped constraints and deterministic ordering.
4. **Amharic-first interaction:** Amharic (`am`) is the default UI and response locale; English (`en`) is selectable. Mixed Amharic/English is supported. A per-turn locale override takes precedence over auto-detection, without influencing identity or authorization.
5. **Streaming and cancellation:** Responses stream through a provider-neutral gateway; stop, timeout, disconnect, retry, and idempotency behavior are deterministic.
6. **Governed generation:** Each generation request is subject to the approved trusted policy snapshot, server-defined capability/resource mapping, hard resource budgets, audit append, and revocation checks.
7. **Synthetic-only evidence:** All test conversations and model inputs/outputs are synthetic; the provider adapter is a deterministic local/test double until separately approved.

## 3. Explicit six-dependency entry gate

All six dependencies below are mandatory. A3 implementation may start only after each has a documented resolution and the Owner has separately authorized A3. A plan approval must not be interpreted as approval to merge or deploy.

### D1 — Select and pin the Kernel baseline

**Current evidence:** PR #13 is open, draft and unmerged. Its candidate HEAD at the last A2 reconciliation was `813b24cbf81f049f2675fbb5492bdc9f262a9d87`. It is not automatically adopted.

**Required before implementation:**
- Re-read PR #13 metadata and relevant source files at the then-current exact HEAD.
- Compare its public exports and security behavior against the A2 contract, including credential verification, trust bundle construction, revocation, `VerifiedPrincipal`, production authenticated authorization, Owner-approval handling, audit append, and constitutional baseline checks.
- Decide whether to consume a pinned commit/revision, wait for an approved integration point, or implement against another explicitly selected stable baseline.
- Record the selected repository, branch/ref, full commit SHA, crate/API version, feature flags, and compatibility notes in the A3 implementation record.
- Confirm production configuration cannot enable `NoRevocations`, test-only helpers, or development bypasses.
- Do not merge PR #13 as an incidental part of CIW. Any merge or adoption requiring a repository merge remains separately approved.

**Gate evidence:** exact source reconciliation, dependency pin, successful compile-time API compatibility proof, and Owner-recorded baseline selection.

### D2 — Trusted policy source and lifecycle

**A2 finding:** The candidate `Policy::new(...)` creates an in-memory policy; signing, approval, persistence, and lifecycle are not implemented there. `evaluate()` alone is not the production authorization path.

**Required implementation:**
- Establish a trusted composition-root policy loader using an Owner-authorized policy source.
- Verify policy signature and integrity against a separately provisioned policy-signing trust root. Do not reuse credential trust roots unless that reuse is explicitly authorized.
- Validate schema/version, epoch, effective interval, expiry/freshness, digest, capabilities, approval requirements, risk ceilings, and tenant applicability.
- Reject unsigned, invalid, expired, rolled-back, unknown-schema, ambiguous, incomplete, or unavailable policy state.
- Convert only verified policy material into an immutable runtime snapshot; request handlers and providers cannot construct or mutate policy.
- Support atomic snapshot refresh. Pin policy version/digest to each authorization decision and record it in the security audit.
- Fail closed if no valid policy is loaded or refresh/verification is indeterminate.
- Use the selected Kernel's production authenticated authorization API and durable audit sink. Never use test-only helpers or call policy evaluation as a substitute.

**A3 limitation:** If no authorized policy-signing root/source is available, the implementation must stop at a non-production test harness with an explicitly synthetic policy fixture; it must not silently invent a production trust root or claim production authorization readiness.

**Gate evidence:** positive and negative signature/expiry/rollback tests, atomic-refresh tests, outage tests, and proof that invalid policy cannot produce an ALLOW.

### D3 — Authoritative tenant membership and isolation

**A2 decision D01:** Tenant membership is server-resolved and authoritative. Each conversation is immutably bound to one tenant. Caller-supplied tenant IDs are not authority.

**Required implementation:**
- Integrate an authoritative membership resolver keyed by the Kernel-verified subject.
- Resolver result includes tenant ID, membership state, role, membership version, and freshness/checked-at metadata.
- Reject absent, suspended, revoked, ambiguous, stale or unauthorized membership. Resolver outage fails closed.
- The first slice is owner-only: persist `owner_subject_id`; require verified subject equality on every operation. No shared threads, member grants, collaboration, or cross-tenant conversation transfer.
- Treat any tenant selector from a client as an untrusted requested context only; verify it against authoritative membership.
- Apply tenant and owner predicates to every database read/write, list, pagination, search, cache, export, background task, and stream continuation.
- Use opaque IDs as identifiers only, never as access control.
- Return a non-enumerating not-found response when the caller cannot access a conversation.

**Gate evidence:** resolver contract and outage behavior; adversarial cross-tenant and cross-owner tests for every endpoint, persistence query, cache path and stream.

### D4 — Bounded session lifecycle, revocation and active-stream cancellation

**A2 decision D08:** G01 credential remains the identity authority; app sessions are bounded and revocable, bound to subject and tenant. Credential/session state is revalidated on requests and active streams; revocation/state-store outage stops operation.

**Required implementation:**
- Authenticate each new request with the selected Kernel verifier, expected audience, trusted trust snapshot, and production revocation checker.
- Create bounded application sessions bound to subject, tenant, credential/session ID, issued-at, expiry, revocation version, and status. Session is not a replacement identity provider.
- Enforce absolute expiry and configurable idle expiry; do not invent production duration values in this plan.
- Revalidate credential, membership, and session status on every request.
- Recheck on stream start, during long streams, and immediately before committing terminal output.
- Propagate cancellation to the provider adapter and persistence layer on user stop, client disconnect, timeout, credential/session revocation, membership change, policy invalidation, or security-state outage.
- If cancellation or revocation state cannot be confirmed, stop generation and do not commit further output.
- Prevent replay of turn submission through idempotency keys and state transitions.

**Gate evidence:** expiry/revocation tests, mid-stream revocation tests, state-store outage tests, disconnect/stop tests, and assertions that no terminal completion is committed after revocation.

### D5 — Concrete capability/resource mappings and measured limits

**A2 decision D10:** Configurable hard ceilings at subject and tenant scope for input size, output tokens, concurrency, request rate, wall-clock time, retries, and spend. Missing or invalid budget configuration denies generation. Numeric values must be measured and within an Owner-approved cost envelope.

**Required implementation:**
- Define server-owned capabilities for the initial slice only, such as conversation read, conversation create, message submit, generation start, stream read, and generation cancel.
- Define canonical resource identifiers including tenant and conversation, e.g. `tenant/{tenant_id}/conversation/{conversation_id}`.
- Bind each operation to a risk level and policy version. The client and model cannot supply capability, resource, subject, risk, or policy version.
- Define a mapping table from endpoint/operation to capability, canonical resource pattern, risk, and required checks.
- Establish configuration schema for subject- and tenant-level hard ceilings: input bytes/tokens, output tokens, concurrent generations, requests per interval, wall-clock duration, retries, and spend.
- Measure synthetic workload/provider-test-double behavior to propose safe numeric limits; record methodology and uncertainty.
- Require an explicit Owner-approved cost envelope before setting any spend ceiling or enabling a real provider.
- Reject missing, malformed, zero/negative where invalid, inconsistent, or exceeded budgets before provider invocation. Never interpret an absent limit as unlimited.
- Apply bounded retries only to retryable failures; use idempotency and prevent duplicate billable generations.

**Gate evidence:** capability/resource matrix; config validation tests; boundary tests at, below and above each ceiling; concurrency/rate tests; cost-accounting tests using synthetic prices only.

### D6 — Synthetic-only model and data boundary

**A2 decision D06:** Synthetic data only until a provider and its data-handling terms are separately approved.

**Required implementation:**
- Implement a provider-neutral G03 gateway interface and a deterministic synthetic provider/test double.
- No production provider SDK activation, API key, paid endpoint, real user transcript, real document, or production dataset.
- Use synthetic prompts, fixtures, generated answers, and synthetic citations only.
- Keep provider selection and endpoint configuration in trusted server-side configuration; clients and model output cannot choose providers.
- Record synthetic provider/model identity and version in generation metadata.
- Treat model input, output, citations, and any future retrieval result as untrusted data.
- Redact secrets and minimize content in telemetry. Never place raw credentials, tokens, hidden prompts, or unnecessary message bodies in security audit events.
- A real provider requires a separate decision covering provider identity, data processing terms, data residency/egress, retention, training use, security controls, cost envelope, and credentials. That decision is outside this A3 plan.

**Gate evidence:** configuration and dependency scan proving no production provider is enabled; synthetic fixture provenance; tests that reject unapproved provider configuration.

---

## 4. Target architecture and request flow

```text
Amharic-first Web/PWA Chat UI
        |
        v
Conversation API / Stream Controller
        |
        +--> G01 credential + revocation verification
        |
        +--> authoritative tenant membership + owner ACL
        |
        +--> bounded app-session validation
        |
        +--> trusted policy snapshot + capability/resource mapping
        |          |
        |          v
        |   Kernel authenticated authorization + security audit
        |
        +--> conversation/turn persistence (tenant scoped)
        |
        +--> G03 provider-neutral gateway
                   |
                   v
            synthetic provider only
                   |
                   v
          typed stream events / cancellation
                   |
                   v
         persist terminal state + citations
```

The conversation service owns conversation-domain data only. It does not own identity, trust roots, policy authority, Owner approval, revocation, Kernel security audit, durable tool execution, or agent delegation.

### Request sequence

1. Validate request shape, size, locale and idempotency key.
2. Authenticate with G01; obtain opaque `VerifiedPrincipal`.
3. Resolve current tenant membership from trusted server-side state.
4. Validate bounded session and immutable conversation tenant/owner binding.
5. Load the current verified policy snapshot and hard-budget configuration.
6. Construct `AuthorizationRequest` server-side using the verified subject, fixed capability, canonical resource and configured risk.
7. Call the selected Kernel's production authenticated authorization path; require successful durable security audit append.
8. Atomically create/advance the turn state and record a conversation-domain event.
9. Invoke only the synthetic G03 gateway within enforced budgets.
10. Stream typed events while checking cancellation and revocation.
11. Persist the terminal response and synthetic citation metadata only if all checks remain valid.
12. Return correlation and turn identifiers; expose no internal security details.

## 5. Bounded product and API surface

### Included user capabilities
- Sign in through existing IROKA credential infrastructure.
- Create a private conversation.
- List and resume only the authenticated owner's conversations in the active tenant.
- Submit one text message per turn.
- Stream an answer in Amharic by default or English when selected.
- Support mixed Amharic/English input and per-turn locale override.
- Stop a generation.
- Retry a failed turn safely with idempotency protection.
- Render synthetic citations and source labels where supplied by the test provider.
- Archive a conversation; request deletion under the retention/deletion policy.

### Proposed endpoints

| Method and route | Capability | Behavior |
|---|---|---|
| `POST /v1/conversations` | `conversation.create` | Create owner-only conversation in server-resolved tenant |
| `GET /v1/conversations` | `conversation.read` | List caller's conversations with cursor pagination |
| `GET /v1/conversations/{id}` | `conversation.read` | Read authorized conversation metadata and messages |
| `POST /v1/conversations/{id}/turns` | `conversation.message.submit` | Idempotently create turn and begin synthetic generation |
| `GET /v1/conversations/{id}/turns/{turn_id}/events` | `conversation.stream.read` | Stream typed generation events |
| `POST /v1/conversations/{id}/turns/{turn_id}/cancel` | `conversation.generation.cancel` | Cancel generation and persist cancellation state |
| `POST /v1/conversations/{id}/archive` | `conversation.archive` | Archive owner conversation |
| `DELETE /v1/conversations/{id}` | `conversation.delete.request` | Revoke access immediately and schedule governed purge |

These routes are proposed contracts, not existing endpoints. Exact route shape may be refined during A3 without changing approved security/product boundaries. Any material change to scope or decisions returns to the Owner.

### Typed stream event envelope

Every event includes `event_id`, `conversation_id`, `turn_id`, `sequence`, `correlation_id`, and `occurred_at`.

Allowed event types:
- `turn.accepted`
- `message.delta`
- `citation.added`
- `turn.completed`
- `turn.cancelled`
- `turn.failed`

No stream event may convey tool instructions, execution grants, authorization decisions, secret material, or a client-controlled policy field. Duplicate/out-of-order events are detected and handled deterministically.

## 6. Data model and lifecycle

Minimum logical records:
- **Conversation:** ID, tenant ID, owner subject ID, title, status, timestamps, version.
- **Turn:** ID, tenant ID, conversation ID, sequence, idempotency key, status, locale, start/end timestamps, correlation ID.
- **Message:** ID, tenant ID, conversation ID, turn ID, sequence, role, content, content classification, timestamps.
- **Citation:** ID, tenant ID, conversation ID, turn/message ID, synthetic source identifier, locator/label, provenance metadata.
- **Generation:** ID, turn ID, synthetic provider/model/version, policy version/digest, budget snapshot reference, status, token counters, start/end times.
- **AppSession:** opaque session ID, subject, tenant, credential reference, issued/expiry times, revocation version, status.
- **ConversationEvent:** append-oriented domain lifecycle event with actor, tenant, conversation, turn, correlation, event type and timestamp.

Enforce database-level uniqueness and foreign-key relationships where supported, including unique turn sequence per conversation and idempotency key scoped to owner/conversation. Every query and index path must preserve tenant isolation.

Do not create a second Kernel security audit ledger. Conversation lifecycle events are separate from Kernel authorization audit events.

### Retention and deletion

- **D03:** Retention is configurable. Do not set an indefinite-retention default or invent a final retention period in the implementation plan.
- Retention configuration must distinguish message content, citations, operational telemetry, backups, and legally/security-required audit evidence.
- **D04:** Deletion first revokes access immediately, marks the record deletion-pending, and schedules purge subject to legal, security-audit and backup-retention obligations.
- Deletion must not erase required immutable security audit evidence or bypass legal holds.
- Export, purge, backup expiry and deletion status must be auditable without exposing transcript contents in security logs.

## 7. Amharic-first and Unicode requirements

- Default locale: `am`; selectable alternative: `en`.
- Support Ethiopic Unicode, punctuation, numerals, combining marks, mixed-script messages, and bidirectional text rendering.
- Normalize and validate Unicode consistently without destructive transliteration or loss of original user text.
- Store canonical text as Unicode; preserve user-entered content and display it safely.
- Locale override is a presentation/generation preference only; it must never change subject, tenant, capability, risk, policy, or access checks.
- UI strings, validation errors, loading/cancel states, empty states and accessibility labels must be available in Amharic and English.
- Test mobile layouts, keyboard entry, screen-reader labels and long Ethiopic text.

## 8. Security, privacy and failure behavior

- All user messages, generated answers, citations and synthetic retrieval material are untrusted data.
- No prompt or model output can modify policy, principal, tenant, session, risk, capability, resource, approval or audit state.
- No tools, G07 agent delegation, G08 workflow execution, G09 side effects, or external actions.
- Kernel authorization and conversation tenant/owner ACL checks are conjunctive.
- Fail closed on authentication, revocation, membership, session, policy, audit or budget uncertainty.
- Do not stream further content after cancellation, revocation, expiry, or security-state outage.
- Do not commit a successful terminal response if final authorization/session/revocation checks fail.
- Avoid leaking whether another user's conversation exists.
- Security audit contains decision metadata and opaque references, not raw message bodies, credentials, or secrets.
- Conversation lifecycle audit and operational telemetry are access-controlled and minimized.
- Encrypt data in transit and at rest using approved platform controls; do not claim E2EE.
- No independent witness enrollment is required for this bounded prototype. This does not establish independent assurance, tamper-proof external witnessing, or production readiness.

## 9. Implementation work packages (A3 only after authorization)

| Work package | Deliverables | Depends on |
|---|---|---|
| A3.0 Baseline and composition root | Exact Kernel baseline pin; trusted configuration/composition root; production feature audit | D1, D2 |
| A3.1 Policy and authorization adapter | Signed policy loading/validation/refresh; capability/resource map; production Kernel auth and audit integration | D1, D2, D5 |
| A3.2 Tenant and session boundary | Membership resolver; owner-only ACL; bounded app sessions; revocation and stream cancellation hooks | D1, D3, D4 |
| A3.3 Conversation persistence | Tenant-scoped schema/repository; ordered messages/turns; idempotency; lifecycle/deletion states | D3, D4 |
| A3.4 Synthetic G03 gateway | Provider-neutral interface; deterministic synthetic adapter; streaming event contract; budgets/timeouts | D5, D6 |
| A3.5 Amharic-first client | Responsive chat UI; locale controls; conversation list/resume; streaming, stop, retry, citations | A3.2–A3.4 |
| A3.6 Integration and hardening | End-to-end synthetic flow; negative/failure tests; telemetry minimization; documentation and runbook | A3.0–A3.5 |

Work packages are a proposed sequence. A3 may be paused if any mandatory dependency cannot be satisfied without broadening scope or weakening controls. Do not substitute mocks for required production security boundaries and then claim the full slice has passed; label any harness-only evidence explicitly.

## 10. A4 exact-HEAD verification plan

A4 is a separate gate and must test the final implementation SHA, not merely an earlier commit.

### Required test groups
1. **Kernel integration:** valid credential; malformed/expired/revoked credential; wrong audience; invalid trust snapshot; revocation outage; test-only feature exclusion.
2. **Policy lifecycle:** valid signed policy; invalid signature; expired policy; rollback; unknown schema; stale/unavailable source; atomic refresh; no-policy startup; audit append failure.
3. **Tenant/owner isolation:** absent/suspended/revoked/ambiguous membership; resolver outage; forged tenant selector; cross-tenant and cross-owner read/write/list/search/cache/export/background/stream attempts.
4. **Session lifecycle:** session expiry/revocation; credential revocation; membership change; active stream interrupted; disconnect; explicit cancel; security-state outage.
5. **Authorization mapping:** every route maps to the intended server-defined capability, canonical resource and risk; client/model cannot override these values; deny and escalation paths do not invoke generation.
6. **Budget enforcement:** missing/invalid configuration; input/output ceilings; concurrency; rate; wall-clock; retries; spend; duplicate submission; boundary conditions.
7. **Conversation correctness:** ordering, pagination, idempotency, retry, archive, deletion-pending, purge scheduling, retention configuration and race conditions.
8. **Streaming:** valid event sequence; duplicate/out-of-order events; partial output; provider error; timeout; disconnect; cancel; revoked session mid-stream; no terminal commit after stop/revocation.
9. **Amharic/English:** Ethiopic Unicode, punctuation, combining marks, mixed script, locale override, default Amharic, English selection, accessibility and mobile layout.
10. **Synthetic-only controls:** no live provider configuration or secret; fixtures only; dependency/config scan; synthetic citations; no production data path.
11. **Privacy and audit:** no secrets/raw transcript in Kernel security audit; lifecycle audit access controls; deletion revokes access before purge; no E2EE claim.
12. **Scope guard:** prove no tool registry, G07 delegation, G08 execution, G09 invocation, external side effects, or provider activation.

### Evidence required for each exact-HEAD gate
- Full repository and commit SHA.
- Workflow run URLs and job results where available.
- Exact commands, environment/runtime versions, and exit codes.
- Test counts and failure output.
- Changed-file list and migration status.
- Security negative-test evidence.
- Known limitations, unresolved findings, and explicit NOT RUN labels.
- No PASS claim based only on documentation or mocked tests for an unimplemented security dependency.

## 11. Explicit non-goals and prohibited scope expansion

The following are excluded from this A3 slice:
- Tool calling, tool registry, external APIs or side effects.
- G07 specialized agents or delegation.
- G08 durable workflow execution or G09 protected tool execution.
- Voice, audio, image, document, video or other multimodal input/output.
- Long-term personalized memory, cross-conversation memory, or autonomous retrieval beyond synthetic citations.
- Shared conversations, group chat, member grants, cross-tenant transfer.
- Production model/provider, production credentials, production data or paid services.
- Production trust-root creation/provisioning or policy-signing key creation.
- Public pilot, production activation, merge, release or deployment.
- Independent witness enrollment or a claim of independent assurance.

## 12. Risks and stop conditions

Stop and return to the Owner rather than weakening the design if:
- No Kernel baseline can be selected without relying on unstable or test-only APIs.
- No authorized policy-signing trust source is available.
- Tenant membership cannot be authoritatively resolved.
- Revocation cannot be checked on active streams.
- Any route, cache, query or background path cannot enforce tenant and owner isolation.
- Budget configuration is missing, unmeasured, or outside the approved cost envelope.
- A production provider or non-synthetic data path is required to continue.
- Audit failure can be bypassed or treated as success.
- A proposed change introduces tools, agents, external side effects, shared threads, or materially changes the approved D01–D10 decisions.
- The only way to run verification requires a paid CI/billing top-up; do not ask the Owner to deposit funds. Use available no-cost local/repository verification where feasible and clearly label unavailable workflow evidence.

## 13. A3 authorization request — Owner decision required

The Owner is asked to authorize only the following bounded scope:

> **Authorize CIW-2 A3 implementation of the Amharic-first, answer-only text-chat vertical slice described in this plan, on a dedicated feature branch, with synthetic data and a deterministic synthetic model gateway only, after the six mandatory dependencies are resolved and recorded. Permit implementation commits and non-production migrations/tests within this scope. Do not merge, deploy, activate a production provider, use production data/credentials, or expand into tools, agents, workflows, multimodal interaction, or shared conversations.**

If approved, implementation must remain on a dedicated branch and report each dependency's resolution, exact baseline SHA, changed files, migrations, test evidence, and blockers. If a mandatory dependency is not resolved, implementation pauses at that boundary.

**Separate gates remain:**
- A3 implementation: requires explicit Owner approval of the scope above.
- A4 verification: separate explicit authorization after implementation is ready.
- PR merge: separate explicit approval.
- A5 deployment/pilot: separate explicit approval.
- Production provider/data activation: separate explicit approval and provider/data-handling review.

**Current disposition:** PLAN PREPARED — A3 NOT AUTHORIZED — IMPLEMENTATION NOT STARTED — A4 NOT RUN — MERGE NOT AUTHORIZED — DEPLOYMENT NOT AUTHORIZED.
