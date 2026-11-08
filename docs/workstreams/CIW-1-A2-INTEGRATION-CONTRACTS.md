# CIW-1 A2 — Conversational Integration and Domain Contracts

**Status:** A2 technical contract proposal; pending Owner review  
**Workstream:** Conversational Interaction Workstream (CIW)  
**Scope:** Read-only reconciliation, interface contracts, security boundaries, data lineage and acceptance criteria  
**Baseline references:** IROKA main `143311a655be68acea2700650b7f88c9fb085526`; IGACMS A3 candidate `813b24cbf81f049f2675fbb5492bdc9f262a9d87`; G08 A2 proposal `04c3bab0ba4de2e634ce28612c90ed7451ef9ceb`; CIW workstream `b53c36bb7e8446fbfc44b816fd55ecd4b9853271`  
**Authorization:** Documentation and contract proposal only. No runtime implementation, schema migration, provider activation, merge, deployment, trust-root change or protected side effect is authorized.

---

## 1. Executive disposition

The IGACMS A3 feature branch contains reusable Kernel primitives for credential verification, principal construction, policy evaluation, deterministic decisions, scoped Owner approvals, revocation, security persistence and fail-closed authorization auditing. These are candidate interfaces, not an adopted stable API: the branch is unmerged and its exact source must be reconciled again before implementation pins a dependency.

The conversation subsystem shall be an application/domain client of the Kernel. It shall not create a parallel identity provider, principal type, policy engine, Owner authority, revocation registry, authorization decision engine or security audit ledger.

The first release is a text-only, authenticated conversational vertical slice. It may answer and cite; it shall not execute tools or protected actions. Tool execution remains a later, separately gated capability through G09 and the durable workflow boundary.

### 1.1 Reuse / adapt / missing register

| Capability | Existing candidate interface/evidence | Disposition | A2 qualification |
|---|---|---|---|
| Credential authentication | `Ed25519CredentialVerifier::authenticate()` returns opaque `VerifiedPrincipal` | REUSE | Constructor/trust configuration and production revocation implementation must be wired by trusted composition root |
| Trust and key lifecycle | `SignedTrustBundle`, `TrustRootSet`, trust snapshot verification/rotation | REUSE | Do not create chat-specific trust roots or credential format |
| Revocation | `RevocationChecker`; credential and key revocation checks | REUSE | Authoritative freshness and outage behavior remain fail-closed |
| Policy evaluation | `Policy`, `evaluate()`, `RiskLevel` | REUSE | Map conversation operations to explicit capabilities/resources; policy lifecycle/configuration not fully established by inspected files |
| Decisions | `Decision`, `DecisionCode`, `DecisionReason` | REUSE | Preserve ALLOW/DENY/REQUIRE_APPROVAL/ESCALATE semantics; never interpret model output as a decision |
| Owner approval | `OwnerApprovalVerifier::verify_and_consume()`; signed, scoped, expiring and replay-protected approvals | REUSE | No Owner approval in the initial chat-only slice; later action approvals bind exact action and target |
| Security persistence | `SqliteSecurityStore` | REUSE | Treat as Kernel-owned security state; do not add duplicate chat revocation/approval tables |
| Authorization audit | `AuditEvent`, `AuditSink`, `record_decision()`, `SqliteAuditSink` | REUSE | Security audit records decisions, not message bodies or transcripts |
| Conversation/session domain | No identified Kernel conversation/thread/session interface | ADD IN CONVERSATION DOMAIN | Domain records bind to Kernel subject and independently validated tenant membership |
| Message/turn persistence | No identified implementation in inspected baseline | ADD IN CONVERSATION DOMAIN | Ordered, idempotent, tenant-isolated persistence |
| Streaming/cancellation | No identified Kernel streaming contract | ADD AT API/GATEWAY LAYER | Typed stream events; cancellation propagates to provider and persistence state |
| Model gateway | No provider-neutral inference contract identified in inspected Kernel modules | ADD G03 ADAPTER | Provider abstraction; no model/provider has authority |
| Knowledge retrieval | G04 ownership is defined in CIW workstream; executable API not reconciled in this pass | UNRESOLVED | Do not invent a second retrieval/memory authority |
| Durable generation/task lifecycle | PR #18 proposes G08 durable orchestration A2 contract | ADAPT LATER | G08 contract excludes user-facing UI, model calls and tool execution; use only for durable task lifecycle after compatibility review |
| Tool execution | G09 boundary in CIW strategy; no execution authorized here | DEFER | No tools in initial text-chat slice |
| Independent witness | PR #15/A4-03 separate branch | NOT A CHAT PREREQUISITE | No independent-witness or production assurance claim |

## 2. Kernel integration contract

### 2.1 Trust boundary and composition

Only the trusted application composition root may construct/configure credential verifiers, revocation adapters, policy snapshots, Owner approval verifiers and audit sinks. HTTP handlers, model providers, retrieved documents and conversation payloads must not construct or replace those dependencies.

The request path is:

1. Receive request over authenticated transport.
2. Verify credential using the configured Kernel verifier and expected audience.
3. Resolve tenant membership through an authoritative tenant-membership source; never accept tenant identity solely from a client-supplied field.
4. Resolve the requested conversation and confirm its immutable tenant and owner/ACL binding.
5. Construct an authorization request using the verified principal subject, a server-defined capability, a canonical resource identifier and the active policy version.
6. Obtain the Kernel decision and ensure the decision audit append succeeds.
7. Continue only on the appropriate positive decision. DENY stops; REQUIRE_APPROVAL enters a separately authorized approval flow; ESCALATE stops and raises the configured control-plane signal.
8. Invoke only the domain operation permitted by that decision.
9. Persist the domain event and return a response with correlation identifiers.

The model is downstream of authentication and authorization. It receives only the minimum context needed for answer generation. It cannot set principal, tenant, capability, resource, policy version, risk level, approval state or execution grant.

### 2.2 Verified interfaces versus proposed adapter

Verified in IGACMS A3 candidate source:

- `Ed25519CredentialVerifier::authenticate(compact_token, expected_audience, now) -> Result<VerifiedPrincipal, CredentialError>`
- `VerifiedPrincipal` is produced by successful credential verification and is not freely constructible by downstream callers.
- `RevocationChecker` checks credential and key revocation; unavailable revocation state is an error, not an allow.
- `AuthorizationRequest` supplies subject, capability and resource to policy evaluation.
- `authorize_authenticated_with_owner_approval(...)` validates constitutional baseline, principal/request subject match, policy decision and optional signed Owner approval; audit failure escalates.
- `AuditSink::append(&AuditEvent)` is the fail-closed audit boundary.
- `OwnerApprovalVerifier::verify_and_consume()` binds approval to request subject, capability, resource and policy version, checks expiry/revocation/signature and atomically consumes the approval ID.

The following is an architectural pseudocode contract, **not a claim that this exact Rust API exists**:

```rust
struct ConversationAuthorizationContext {
    principal: VerifiedPrincipal, // Kernel-produced opaque principal
    tenant_id: TenantId,          // resolved server-side
    conversation_id: ConversationId,
    policy_version: PolicyVersion,
    correlation_id: CorrelationId,
}

trait ConversationKernelPort {
    fn authenticate(&self, credential: &Credential, audience: &str, now: Timestamp)
        -> Result<VerifiedPrincipal, AuthenticationFailure>;

    fn authorize(
        &self,
        principal: &VerifiedPrincipal,
        capability: ConversationCapability,
        canonical_resource: &ResourceId,
        risk: RiskLevel,
        correlation_id: &CorrelationId,
        now: Timestamp,
    ) -> Result<KernelDecision, AuthorizationFailure>;
}
```

The concrete adapter must call the real public Kernel API from the adopted Kernel revision. It must not wrap a test-only authorization helper as production behavior. The currently inspected legacy assertion-based helper is marked `cfg(test)`; production integration must use the authenticated, Owner-approval-aware path or a subsequently approved public equivalent.

### 2.3 Error mapping

| Kernel/authentication outcome | Conversation/API behavior | Side-effect rule |
|---|---|---|
| Invalid/malformed/expired credential | 401; generic external error | No session/message operation |
| Revoked credential or key | 401/403 according to external policy; security event | No operation |
| Revocation unavailable | 503 or controlled fail-closed response | No operation |
| Subject mismatch | 403; security event | No operation |
| Policy DENY | 403 | No protected operation |
| REQUIRE_APPROVAL | 202/pending approval only where supported later | No execution until exact approval verified |
| ESCALATE / constitutional validation failure | 503 or controlled escalation response | No operation |
| Audit sink unavailable/integrity failure | 503; preserve correlation | No protected operation |
| Conversation not found or not visible to principal | 404 (avoid existence disclosure) | No read/write |
| Tenant membership unresolved | 503/403 by policy; do not trust request tenant | No operation |

Do not expose cryptographic parsing details, key identifiers, internal policy diagnostics or other sensitive security metadata to clients.

## 3. Tenant, principal, session and conversation contract

### 3.1 Identity and ownership

- `subject_id` is the stable subject returned by the Kernel-verified principal; never accept it from a request body.
- `tenant_id` is resolved from an authoritative membership/tenant service after authentication. A client-supplied tenant selector may be treated only as a requested context and must be checked against membership.
- A conversation is permanently bound to one tenant at creation. Moving a conversation across tenants is not supported.
- Conversation access requires both tenant membership and conversation-level owner/ACL permission.
- Every database read, update, delete, search, cache lookup and background job must carry the tenant predicate and relevant ACL constraint.
- Conversation IDs are opaque, non-sequential identifiers; opacity is not an authorization control.
- Session tokens are transport/session credentials, not a replacement for Kernel identity. Revocation and expiry must take effect on subsequent requests and active stream checks.

### 3.2 Proposed domain records

| Record | Required fields | Notes |
|---|---|---|
| Conversation | `id, tenant_id, owner_subject_id, title, status, created_at, updated_at, version` | Immutable tenant/owner origin; status active/archived/deletion-pending/deleted |
| ConversationMember | `conversation_id, tenant_id, subject_id, role, granted_by, created_at, revoked_at` | Optional collaboration; default owner-only; membership changes authorized |
| Turn | `id, tenant_id, conversation_id, sequence, status, idempotency_key, started_at, completed_at` | One user request and its assistant generation lifecycle |
| Message | `id, tenant_id, conversation_id, turn_id, sequence, role, content_ref, content_type, created_at` | Roles user/assistant/system-service; system policy never stored as user-editable content |
| GenerationRun | `id, tenant_id, conversation_id, turn_id, provider_id, model_id, prompt_template_version, status, started_at, ended_at, usage` | Minimize provider metadata; no secrets or hidden reasoning |
| Attachment | `id, tenant_id, conversation_id, message_id, object_ref, media_type, size, digest, scan_status, retention_state` | Quarantined until validation; extracted text remains untrusted |
| Citation | `id, tenant_id, message_id, source_ref, locator, excerpt_digest, provenance` | Preserve source identity and exact supporting locator |
| ConversationEvent | `id, tenant_id, conversation_id, actor_subject_id, event_type, correlation_id, occurred_at, metadata` | Domain lifecycle audit; no secret/raw token fields |

Content may be stored inline or in encrypted object storage according to size and classification. If object storage is used, metadata and object ACLs must be tenant-bound; signed URLs must be short-lived and scoped. Message body encryption, key management, backup retention and deletion semantics require platform-specific approval before implementation.

### 3.3 Ordering, idempotency and concurrency

- Client submits a unique idempotency key for each turn-creation attempt; uniqueness scope is tenant + conversation + actor + key.
- Replaying the same key returns the original turn/result state and does not create a second model charge or duplicate message.
- Server assigns monotonically increasing conversation sequence numbers inside a transaction/atomic compare-and-swap.
- A conversation allows one active generation per turn by default. Concurrent submissions either serialize or receive a deterministic conflict response; no silent interleaving.
- Stream event IDs are monotonic within a generation and replayable from a bounded cursor where supported.
- A retry creates a new generation attempt linked to the same user turn only under explicit retry semantics; it must not silently overwrite previously delivered assistant content.
- Partial generation is retained with an explicit interrupted/failed status and partial-output marker; never mark it complete on disconnect.

### 3.4 Retention, deletion and export

Retention is a policy decision, not an implicit database default. Define separate schedules and deletion semantics for conversation messages, attachments, provider-side retention, operational telemetry, backups and legally required security evidence. User deletion cannot erase required security evidence or alter the immutable authorization audit chain. Exports must be authenticated, tenant-scoped, rate-limited and include provenance/metadata without exposing secrets or other tenant content. Deletion must revoke attachment access, remove searchable indexes and schedule backup expiry according to the approved retention policy.

**Owner decision required before A3:** retention periods, deletion grace period, export format, shared-conversation policy, and whether end-to-end encryption is in scope for the first release.

## 4. Conversation API contract (proposed, versioned)

Base path: `/api/v1`. All endpoints require authenticated transport and Kernel-backed identity. Tenant context is resolved server-side. JSON examples are normative shapes for A2 review, not implemented endpoints.

### 4.1 Endpoints

| Method and path | Purpose | Authorization capability | Idempotency |
|---|---|---|---|
| POST `/conversations` | Create conversation | `conversation.create` | Required |
| GET `/conversations` | List visible conversations | `conversation.list` | N/A |
| GET `/conversations/{conversation_id}` | Read metadata | `conversation.read` | N/A |
| PATCH `/conversations/{conversation_id}` | Rename/archive | `conversation.update` | Required |
| DELETE `/conversations/{conversation_id}` | Request deletion | `conversation.delete` | Required |
| GET `/conversations/{conversation_id}/messages` | Paginated history | `message.list` | N/A |
| POST `/conversations/{conversation_id}/turns` | Submit user turn and start generation | `turn.create` | Required |
| GET `/conversations/{conversation_id}/turns/{turn_id}` | Read turn/generation state | `turn.read` | N/A |
| POST `/conversations/{conversation_id}/turns/{turn_id}/cancel` | Stop generation | `generation.cancel` | Required |
| POST `/conversations/{conversation_id}/turns/{turn_id}/retry` | Retry failed/interrupted generation | `generation.retry` | Required |
| GET `/generations/{generation_id}/events` | Stream generation events (SSE or equivalent) | `generation.stream` | Cursor-based |
| GET `/conversations/{conversation_id}/export` | Export visible content | `conversation.export` | N/A |

History search, attachments, shared membership, memory controls and tool actions are excluded from the initial vertical slice unless separately specified and approved.

### 4.2 Request and response schemas

Create conversation:

```json
{
  "title": "string (optional, max 160 Unicode scalar values)",
  "client_request_id": "opaque idempotency key"
}
```

Response:

```json
{
  "conversation": {
    "id": "opaque-id",
    "title": "string",
    "status": "active",
    "created_at": "RFC3339 timestamp",
    "updated_at": "RFC3339 timestamp",
    "version": 1
  },
  "correlation_id": "opaque-id"
}
```

Create turn:

```json
{
  "client_request_id": "opaque idempotency key",
  "input": {
    "type": "text",
    "text": "user-authored text"
  },
  "locale": "am | en | auto"
}
```

Response:

```json
{
  "turn": {
    "id": "opaque-id",
    "sequence": 1,
    "status": "accepted"
  },
  "generation": {
    "id": "opaque-id",
    "status": "queued"
  },
  "correlation_id": "opaque-id",
  "events_url": "/api/v1/generations/{generation_id}/events"
}
```

Generation event envelope:

```json
{
  "event_id": 1,
  "generation_id": "opaque-id",
  "turn_id": "opaque-id",
  "type": "generation.started | message.delta | citation.added | generation.completed | generation.interrupted | generation.failed",
  "occurred_at": "RFC3339 timestamp",
  "payload": {}
}
```

Event requirements:
- Each event has a stable generation-scoped sequence and schema version.
- `message.delta` contains only user-visible response text; never hidden chain-of-thought, secrets, system prompts or internal policy deliberation.
- `citation.added` contains a provenance-safe reference, not an unrestricted private source payload.
- Completion, interruption and failure are terminal states; duplicate delivery is idempotently ignored.
- Client disconnect is not proof of user cancellation. Explicit cancel is an authenticated, authorized command; server-side disconnect cleanup is bounded and safe.
- Provider cancellation is best-effort but the server must stop accepting/committing late deltas after terminal state.

### 4.3 Standard error envelope

```json
{
  "error": {
    "code": "stable_machine_code",
    "message": "safe user-facing message",
    "retryable": false,
    "correlation_id": "opaque-id"
  }
}
```

No raw exception, provider response, token, credential, policy secret or internal prompt is returned.

## 5. Capability and resource matrix

Capabilities below are proposed names; the concrete Kernel policy schema and naming conventions must be reconciled against the adopted Kernel source before code.

| Operation | Proposed capability | Canonical resource | Risk | Default initial-slice policy |
|---|---|---|---|---|
| Create conversation | `conversation.create` | `tenant/{t}/subject/{s}/conversation/new` | LOW | Allow authenticated eligible tenant member |
| List conversations | `conversation.list` | `tenant/{t}/subject/{s}/conversations` | LOW | Owner/member only |
| Read metadata/history | `conversation.read`, `message.list` | `tenant/{t}/conversation/{c}` | LOW/MODERATE | Owner/member only; tenant predicate mandatory |
| Rename/archive | `conversation.update` | `tenant/{t}/conversation/{c}` | LOW | Owner or explicitly granted role |
| Delete/request deletion | `conversation.delete` | `tenant/{t}/conversation/{c}` | MODERATE | Owner; retention workflow and audit preserved |
| Submit text turn | `turn.create` | `tenant/{t}/conversation/{c}/turn/new` | MODERATE | Authenticated owner/member; rate/cost limits |
| Stream response | `generation.stream` | `tenant/{t}/generation/{g}` | LOW/MODERATE | Same conversation ACL; recheck session/revocation |
| Cancel generation | `generation.cancel` | `tenant/{t}/generation/{g}` | LOW | Initiating actor or conversation owner |
| Retry generation | `generation.retry` | `tenant/{t}/generation/{g}` | MODERATE | Owner/member; bounded retries and budget |
| Export conversation | `conversation.export` | `tenant/{t}/conversation/{c}/export` | MODERATE | Owner; explicit rate/size limits |
| Search history (later) | `conversation.search` | tenant-scoped search resource | MODERATE | Search only visible conversations |
| Read memory (later) | `memory.read` | user/tenant memory namespace | MODERATE | Explicit consent and G05 policy |
| Write/delete memory (later) | `memory.write` / `memory.delete` | user/tenant memory item | HIGH | Explicit user control; provenance and audit |
| Propose tool action (later) | `tool.propose` | exact action proposal digest | HIGH | Proposal only; never execution authority |
| Execute tool action (later) | G09-specific capability | exact tool + target + action digest | HIGH/CRITICAL | Separate Kernel decision, approval/grant and G09 enforcement |

The initial text-chat vertical slice shall not expose tool-execution capabilities. A model's function-call or tool-call syntax is untrusted proposal data and must not be connected to an executor.

## 6. G03 model gateway and generation contract

### 6.1 Provider-neutral adapter

Proposed interfaces:

```rust
struct GenerationRequest {
    generation_id: GenerationId,
    correlation_id: CorrelationId,
    locale: LocalePreference,
    messages: Vec<PromptMessage>,
    output_limit: u32,
    deadline: Timestamp,
}

trait ModelGateway {
    async fn generate_stream(
        &self,
        request: GenerationRequest,
        cancellation: CancellationToken,
    ) -> Result<GenerationStream, GatewayError>;
}
```

This is a design sketch, not an existing IROKA type. The gateway receives only context authorized for the conversation and necessary for the task. Provider selection, credentials, endpoint allowlists, data residency and retention settings are controlled by trusted server configuration, not model output or user-supplied provider URLs.

### 6.2 Required controls

- Provider credentials reside only in server-side secret management and never enter prompts, client bundles, logs or audit payloads.
- Provider/model allowlisting and outbound network policy are enforced outside the model.
- User content and retrieved content are explicitly delimited as untrusted input.
- No private chain-of-thought is requested, persisted or returned. Store only user-visible answer, safe structured metadata and source references.
- Request limits: maximum input bytes/tokens, output tokens, wall-clock deadline, concurrency, per-subject/tenant rate, daily budget and retry budget. Exact numeric limits require Owner/product decision and load testing.
- Provider timeout, disconnect, malformed stream, refusal, quota exhaustion and outage map to typed gateway errors.
- Retry only on classified transient failures, bounded by idempotency and budget; never duplicate a completed generation.
- Cancellation token propagates from API to gateway; ignore late events after cancellation/terminal state.
- Record provider/model identifiers, model version if available, prompt-template version, token usage, latency and outcome. Minimize or redact content.
- Provider data handling and retention must be verified contractually before any non-synthetic data is sent.

### 6.3 Amharic-first behavior

- Support Ethiopic script and Amharic from first usable release; English is also supported.
- Preserve original user text; normalize only for comparison/search where appropriate and retain original Unicode content.
- Do not strip Ethiopic punctuation, combining marks or script-specific characters.
- Locale is a preference/hint, not an identity or authorization attribute.
- Mixed Amharic/English messages must not be split into separate security contexts.
- Evaluation corpus must include native Amharic prompts, mixed-script prompts, numbers/dates, long messages and adversarial prompt-injection examples.
- UI must provide correct font fallback, cursor movement, selection, copy/paste and mobile keyboard behavior.

## 7. Data lineage and trust classification

| Data/input | Origin | Trust classification | Permitted flow | Prohibited interpretation |
|---|---|---|---|---|
| Credential | Client transport | Untrusted until Kernel verification | Kernel verifier only | Never trust decoded claims without signature/trust/revocation checks |
| VerifiedPrincipal | Kernel verifier | Authenticated identity assertion | Server-side authorization/session context | Not a model-editable field |
| Tenant membership | Authoritative tenant service | Trusted after validated lookup | Server-side context and query predicates | Never infer from prompt or body |
| User message | User | Untrusted content | Conversation store; bounded model context | Not policy, system instruction or authority |
| Attachment/extracted text | User file/perception | Untrusted observation | Quarantine, scanning, then bounded retrieval | Never execute embedded instructions |
| Retrieved knowledge | G04 source | External/untrusted evidence with provenance | Context with source metadata/citations | Cannot override system policy or authorize actions |
| Memory | G05 governed store | Untrusted contextual data with provenance | Consent- and ACL-controlled context assembly | Cannot create authority or silently change user preferences |
| Model output | External model | Untrusted generated content | Output validation and user-visible response | Never a Kernel decision, grant or approval |
| Tool proposal | Model-generated structured data | Untrusted proposal | Display/validate; later policy evaluation | Never execute directly |
| Kernel Decision | Kernel policy path | Authoritative control-plane result | Gate operation; correlate to audit | Must not be fabricated, cached beyond policy semantics or inferred |
| Owner approval | Owner-signed evidence | Authoritative, scoped and time-bound after verification | Kernel approval verifier | Never model-generated or replayed |
| Tool result | External execution adapter | Untrusted result | Validate, sanitize, cite and audit outcome | Never feed as trusted instructions |
| ConversationEvent | Conversation service | Domain event | Product history/operations audit | Not a replacement for Kernel security audit |
| AuditEvent | Kernel | Security decision evidence | Append-only audit sink | Do not insert raw transcript or secrets |

## 8. Audit, privacy and correlation

Two linked but distinct event systems are required:

1. **Kernel security audit:** records authorization decisions using the existing `AuditEvent` and `AuditSink` contract. Preserve its fail-closed behavior.
2. **Conversation domain event log:** records lifecycle events such as conversation created, message accepted, generation started/completed/interrupted, cancellation requested, export requested and deletion scheduled.

Both carry opaque correlation identifiers. The conversation event may reference the Kernel audit event/correlation ID; it must not copy or rewrite the Kernel decision record. The Kernel audit must not contain raw message text, full prompts, attachments, provider secrets or hidden reasoning.

Minimum conversation event metadata: event ID, tenant ID, conversation ID, actor subject ID where applicable, event type, timestamp, correlation ID, schema version and safe metadata. Access to event logs is separately permissioned and retention-defined.

## 9. G08 boundary and workflow integration

PR #18's G08 A2 proposal is a durable orchestration contract, not a model gateway or chat API. It explicitly does not provide user-facing UI, model calls/planning/provider selection, G07 agent delegation or G09 tool execution.

Therefore:
- The initial text generation path may use a bounded request lifecycle without introducing durable workflow execution.
- If generation must survive process restarts or become a durable user-visible task, integrate through the adopted G08 task contract after its own A2/A3 lifecycle is verified.
- A G08 task ID is correlation/lifecycle metadata, not permission to act.
- G08 cannot mint Kernel principals, decisions, Owner approvals, grants or tool authority.
- Every protected G09 action must independently pass current Kernel authorization and the required approval/grant checks at execution time.
- Independent witness enrollment is not a prerequisite for the design or controlled non-production text-chat slice; no A4-03 or independent anchoring claim is implied.

## 10. Threat model and mandatory mitigations

| Threat | Required mitigation | Verification evidence |
|---|---|---|
| Cross-tenant IDOR | Server-resolved tenant + tenant predicate + ACL on every query | Adversarial cross-tenant read/write tests |
| Cross-conversation context leakage | Context builder filters by conversation and ACL; cache keys include tenant and conversation | Canary-data leakage tests |
| Session theft/revocation lag | Secure session controls, credential revalidation/revocation policy, stream checks | Revocation during active stream |
| Prompt injection | Treat all user/retrieved/attachment/tool content as data; no policy in model context | Injection corpus and no-side-effect assertion |
| Memory poisoning | G05 provenance, user control, review/deletion and trust labels | Poisoned-memory retrieval tests |
| Model/provider compromise | No authority in model; minimal context; output validation; provider allowlist | Malicious output and provider failure tests |
| Provider data leakage | Approved egress, secrets management, contractual retention review, data minimization | Configuration inspection and synthetic-data egress test |
| Duplicate turns/charges | Idempotency key and atomic turn creation | Concurrent duplicate submission tests |
| Stream replay/reordering | Stable sequence IDs, terminal state, deduplication | Duplicate/out-of-order event tests |
| Cancellation race | Cancellation token + terminal-state CAS + reject late deltas | Cancel/provider race tests |
| Audit outage/tamper | Kernel fail-closed audit; integrity verification | Sink unavailable/integrity-failure tests |
| Sensitive logs | Redaction, opaque identifiers, no raw token/prompt/secrets | Log inspection with seeded secrets |
| Malicious attachment | Quarantine, scanning, parser isolation, extracted text remains untrusted | Malformed/polyglot/oversized file tests (later attachment phase) |
| Resource exhaustion | Rate/concurrency/input/output/time/cost limits | Load, abuse and budget-bound tests |

## 11. A4 acceptance and exact verification plan

Verification shall run against one recorded exact final commit SHA and record environment, dependency lock state, commands, exit codes, artifacts and known limitations. No CI execution is implied by this documentation contract.

### 11.1 Contract and unit tests
- Schema validation rejects unknown/invalid fields, overlong text, invalid locale and malformed IDs.
- Kernel adapter maps every authentication, revocation, policy and audit outcome exactly as specified.
- No production path invokes test-only credential/approval helpers or `NoRevocations`.
- Capability/resource strings are server-generated and canonicalized.
- Idempotency returns the original turn for duplicate keys and rejects conflicting payload reuse.
- Conversation sequence assignment is atomic under concurrent writers.
- Generation terminal states are monotonic; no late delta after terminal state.

### 11.2 Integration and security tests
- Missing, malformed, expired, wrong-audience, revoked credential and revocation-store outage.
- Tenant A attempts to list/read/update/delete Tenant B conversation by guessed ID.
- Same tenant, unauthorized subject attempts private conversation access.
- Conversation ID from one tenant submitted with another tenant context.
- Cross-conversation retrieval/cache/context injection with unique canary strings.
- Credential revocation while SSE stream is active.
- Kernel audit sink unavailable, rejects append or reports integrity failure; verify no protected operation proceeds.
- Provider timeout, disconnect, malformed event, quota exhaustion and late response after cancellation.
- Duplicate request, concurrent request, retry and cancellation race.
- Prompt injection in user text and retrieved text; verify no tools are invoked and no policy changes.
- Amharic Unicode preservation, Ethiopic punctuation, mixed Amharic/English, long text, RTL/LTR interaction if applicable to mixed scripts.
- Export/deletion/retention tests after retention policy values are approved.
- Secret scan of logs, API errors, client payloads and persisted generation metadata.

### 11.3 Release evidence

A4 report must include:
- exact repository, branch, commit SHA and dirty-state statement;
- exact Kernel dependency revision and public interfaces used;
- commands, environment and toolchain versions;
- PASS/FAIL/NOT RUN for each test group;
- test reports and relevant redacted logs;
- security negative-test evidence;
- Amharic/English corpus results;
- provider/model configuration and data-handling approval status;
- unresolved risks and explicit exclusions;
- no claim of production readiness or independent witness assurance unless separately evidenced and approved.

## 12. Owner decisions required to close A2

The following are product/policy choices, not safe assumptions for implementation:

| ID | Decision | Proposed default for initial text slice | Owner response required |
|---|---|---|---|
| CIW-D01 | Tenant model | Tenant membership resolved server-side; every conversation single-tenant | Confirm |
| CIW-D02 | Conversation sharing | Owner-only; no shared threads in first slice | Confirm |
| CIW-D03 | Retention | Configurable policy; do not hard-code period in code | Set policy before production data |
| CIW-D04 | User deletion | Soft-delete request, immediate access revocation, scheduled purge subject to legal/audit retention | Confirm |
| CIW-D05 | End-to-end encryption | Platform encryption at rest/in transit; E2EE out of first slice | Confirm |
| CIW-D06 | Model provider | Provider-neutral interface; synthetic data only until provider and data handling approved | Select/approve provider separately |
| CIW-D07 | Initial tool scope | No tool execution; answer-only text slice | Confirm |
| CIW-D08 | Session behavior | Existing G01 credential remains identity authority; application session is revocable and bounded | Confirm session/refresh policy |
| CIW-D09 | Amharic default | Amharic-first UI and auto locale detection; English selectable | Confirm default behavior |
| CIW-D10 | Budget/rate limits | Strict configurable limits; numeric ceilings set from product/load test evidence | Set thresholds before pilot |

These defaults are recommendations for Owner review, not approved policy. A2 can document the contract while leaving the above decisions explicitly open; A3 must not silently turn them into irreversible production defaults.

## 13. A2 closure checklist

| A2 item | Status | Evidence / closure condition |
|---|---|---|
| Candidate Kernel source inventory | PASS | Exact PR #13 files inspected at `813b24c...` |
| Reuse/adapt/missing register | PASS (proposal) | Section 1 |
| Kernel adapter contract | PARTIAL | Verified behavior mapped; exact stable public API depends on adopted Kernel baseline |
| Tenant/session contract | PARTIAL | Proposed invariants; tenant membership service and session lifecycle implementation not found in inspected source |
| Conversation persistence contract | PARTIAL | Proposed records/ordering/idempotency; storage technology and retention policy not approved |
| Conversation API schemas | PASS (proposal) | Section 4 |
| Capability/resource matrix | PASS (proposal) | Section 5; concrete policy schema mapping pending |
| G03 gateway contract | PASS (proposal) | Section 6; no provider selected/activated |
| Data lineage/trust boundaries | PASS (proposal) | Section 7 |
| Audit/correlation contract | PASS (proposal) | Section 8 |
| G08 dependency boundary | PASS (proposal) | Section 9; PR #18 remains proposed/unmerged |
| Threat model and acceptance | PASS (proposal) | Sections 10–11 |
| Owner decisions | UNRESOLVED | Section 12 |
| A2 closure | NOT CLOSED | Requires adoption/reconciliation of Kernel baseline, tenant/session owner, policy mapping and Owner decisions |

## 14. Explicit exclusions and next gate

This document does not:
- implement chat endpoints, storage, streaming, model providers or UI;
- add dependencies, migrations, secrets, provider credentials or production configuration;
- merge PR #13, #15, #17, #18 or #19;
- alter trust roots, identity, policy, revocation, Owner authority or audit behavior;
- enable tools, agents, voice, multimodal processing or autonomous actions;
- require independent witness enrollment for design or controlled non-production chat;
- claim A4-03 closure, independent audit durability or production readiness.

**Next gate:** Owner review of CIW-D01–D10 and the A2 closure conditions. After the Kernel baseline and tenant/session/policy interfaces are confirmed, prepare a bounded A3 implementation plan for the answer-only Amharic-first text-chat vertical slice. A3 code, merge and deployment remain separately authorized gates.

**Constitutional rule:** Conversation expresses intent. Cognition proposes. Governance decides. Authorization permits. Execution acts. Assurance verifies.
