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


### 2.3 Exact public-API reconciliation — PR #13 candidate HEAD

A second targeted source pass inspected `request.rs`, `policy.rs`, `decision.rs`, `identity.rs`, `service.rs`, `lib.rs`, and the credential verifier implementation at `813b24cbf81f049f2675fbb5492bdc9f262a9d87`. The following qualifications are material to the A3 design:

| Source finding | Exact behavior | CIW consequence |
|---|---|---|
| Request identity | `AuthorizationRequest::new(subject, capability, resource, risk)` is public; all fields are caller-supplied strings; there is no tenant field or tenant accessor | The chat adapter must set subject from `VerifiedPrincipal::subject()`, never from request JSON. Tenant membership and conversation ACL are separate server-side checks before constructing the request. Tenant isolation is not supplied by this Kernel request type. |
| Policy lifecycle | `Policy::new(...)` is public and constructs an in-memory policy from version, allowed capabilities, approval-required capabilities and maximum risk. Source comment explicitly says signing, approval and persistence are not implemented | Do not treat arbitrary runtime construction or a client/provider-selected policy as an authoritative production policy lifecycle. A3 must identify a trusted policy composition/refresh source and fail-closed behavior; this remains unresolved in the candidate Kernel. |
| Decision surface | `Decision` fields are private; public accessors expose code, reason and policy version. `Decision::new` is crate-private | Downstream code cannot mint a Kernel decision through the public constructor; preserve this boundary. |
| Low-level evaluation | `evaluate()` is public and performs deterministic policy checks only; it does not authenticate, verify approval or append audit | Conversation services must not use `evaluate()` as their complete authorization path. |
| Production authorization | `authorize_authenticated_with_owner_approval()` is the only publicly exported production authorization pipeline in the inspected `lib.rs`; it validates the embedded baseline, principal/request subject match, policy, optional signed Owner approval and audit append | Candidate production integration point. Its exact dependency constructors and policy lifecycle still need a trusted application composition root. ALLOW is a decision, not an execution grant. |
| Legacy authorization | Assertion-based `authorize()` and `authorize_authenticated()` are `cfg(test)` and crate-private; test-only identity assertions/verifiers are not production interfaces | Do not call or emulate these test helpers in a production chat adapter. |
| Credential verifier | `authenticate()` is public; verifier construction is restricted to `from_signed_bundle`, `from_signed_bundle_with_roots` or `from_verified_trust_snapshot`; raw `TrustStore::new` and verifier `new` are crate-private | Use signed/verified trust snapshots and the real revocation checker. `NoRevocations` is compiled only for tests or the explicit `dev-no-revocations` feature and is prohibited in production. |
| Principal | `VerifiedPrincipal` is publicly readable through subject/issuer/credential ID accessors, but its fields and constructor are not publicly writable | Treat it as opaque authenticated identity; never deserialize a client principal. |
| Exports | `lib.rs` publicly exports the request, policy, decision, verifier, trust, audit, approval and authenticated Owner-approval authorization types/functions | Public export does not make an interface a stable adopted API while PR #13 remains unmerged. Pin/reconcile the exact adopted revision before A3. |

**Critical A2 gaps confirmed:** the inspected Kernel does not provide tenant membership, tenant-scoped authorization fields, conversation ACLs, session lifecycle, signed/persisted policy lifecycle, conversation persistence, or streaming. These belong in explicit application/domain contracts and trusted adapters; they must not be claimed as existing Kernel features.

The `authorize_authenticated_with_owner_approval` function takes a verified principal, a `VerifiedGenesis`, optional signed Owner approval, an `OwnerApprovalVerifier`, an `AuditSink`, a `Policy`, time, emergency-stop state and audit identifiers. For normal low-risk read/chat capabilities that do not require Owner approval, the approval argument may be absent; this does not waive authentication, policy evaluation, constitutional validation or audit append. The application must not interpret ALLOW as permission for G09 execution.

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

| ID | Decision | Owner disposition | Status |
|---|---|---|---|
| CIW-D01 | Tenant model | Server-resolved authoritative membership; each conversation bound immutably to one tenant | PROPOSED — OWNER RATIFICATION REQUIRED |
| CIW-D02 | Conversation sharing | Owner-only; no shared threads in the first slice | PROPOSED — OWNER RATIFICATION REQUIRED |
| CIW-D03 | Retention | Configurable; no indefinite-retention default; do not hard-code a period | APPROVED BY OWNER |
| CIW-D04 | User deletion | Revoke access immediately; schedule purge subject to legal, security-audit and backup-retention obligations | APPROVED BY OWNER |
| CIW-D05 | End-to-end encryption | Approved platform encryption in transit and at rest; E2EE excluded from first slice | PROPOSED — OWNER RATIFICATION REQUIRED |
| CIW-D06 | Model provider | Synthetic data only until provider and data-handling terms are separately approved | APPROVED BY OWNER |
| CIW-D07 | Initial tool scope | No tool execution; answer-only text slice | PROPOSED — OWNER RATIFICATION REQUIRED |
| CIW-D08 | Session behavior | G01 credential remains identity authority; bounded, revocable application sessions; recheck on requests and active streams | PROPOSED — OWNER RATIFICATION REQUIRED |
| CIW-D09 | Amharic default | Amharic-first default; English selectable; mixed-language input and automatic detection supported | PROPOSED — OWNER RATIFICATION REQUIRED |
| CIW-D10 | Budget/rate limits | Configurable hard limits per subject and tenant for input/output, concurrency, rate, time, retries and spend; safe defaults fail closed | PROPOSED — OWNER RATIFICATION REQUIRED |

**Owner decision record (2026-11-08):** The Owner explicitly approved CIW-D03 = configurable retention, CIW-D04 = immediate access revocation followed by scheduled purge subject to retention obligations, and CIW-D06 = synthetic data only until separate provider approval. These three decisions are resolved for the A2 proposal. The other seven decisions remain open; recommendations above are not approvals.

The approved decisions constrain A3 design but do not activate a provider, define a numeric retention period, or authorize production data processing.

## 13. A2 closure checklist

| A2 item | Status | Evidence / closure condition |
|---|---|---|
| Candidate Kernel source inventory | PASS | Exact PR #13 files inspected at `813b24c...` |
| Reuse/adapt/missing register | PASS (proposal) | Section 1 |
| Kernel adapter contract | PARTIAL | Verified behavior mapped; exact stable public API depends on adopted Kernel baseline |
| Tenant/session contract | PARTIAL | Proposed invariants; tenant membership service and session lifecycle implementation not found in inspected source |
| Conversation persistence contract | PARTIAL | Proposed records/ordering/idempotency; configurable retention approved but storage technology, exact retention schedules and deletion mechanics remain to be designed |
| Conversation API schemas | PASS (proposal) | Section 4 |
| Capability/resource matrix | PASS (proposal) | Section 5; concrete policy schema mapping pending |
| G03 gateway contract | PASS (proposal) | Section 6; no provider selected/activated |
| Data lineage/trust boundaries | PASS (proposal) | Section 7 |
| Audit/correlation contract | PASS (proposal) | Section 8 |
| G08 dependency boundary | PASS (proposal) | Section 9; PR #18 remains proposed/unmerged |
| Threat model and acceptance | PASS (proposal) | Sections 10–11 |
| Owner decisions | PARTIAL — 3/10 RESOLVED | D03, D04 and D06 approved by Owner on 2026-11-08; D01, D02, D05, D07–D10 remain pending |
| A2 closure | NOT CLOSED | Requires adopted Kernel baseline, trusted policy lifecycle, tenant/session authority and resolution of the seven pending Owner decisions |


## 13.1 Proposed dispositions for the seven remaining Owner decisions

The following are the recommended A2 dispositions, based on least privilege, the existing CIW mandate and the inspected Kernel boundaries. They are **proposals for Owner ratification**, not approvals. They do not authorize implementation.

| Decision | Recommended disposition | Rationale / binding consequence |
|---|---|---|
| D01 — Tenant model | Resolve tenant from an authoritative server-side membership service after G01 authentication. Bind each conversation permanently to exactly one tenant. Reject caller-supplied tenant IDs as authority. | G01 `VerifiedPrincipal` has no tenant claim/resolver; PR #18 independently confirms that caller-supplied tenant IDs are unacceptable. Every read/write/cache/search/job must enforce tenant + conversation ACL. |
| D02 — Sharing | Owner-only conversations for the first slice; no shared threads or member grants. | Avoids an unimplemented ACL/membership mutation surface. Sharing requires a later explicit membership contract and adversarial tests. |
| D05 — E2EE | Exclude end-to-end encryption from the first slice. Require approved TLS in transit and platform-managed encryption at rest, with controlled key access and backup/deletion policy. | E2EE materially changes search, recovery, moderation, export and deletion. Platform encryption is not equivalent to E2EE and must not be described as such. |
| D07 — Tools | Answer-only text interaction; no tool registry invocation, external side effects, agent delegation or G09 execution. | Keeps the first vertical slice read-only with respect to external systems. Model tool-call syntax remains untrusted proposal data. |
| D08 — Sessions | G01 credential verification remains the identity authority. Application sessions are bounded, revocable and tenant/subject-bound; revalidate credential/session state on every request and periodically/on each event for active streams. Revocation or state-store outage stops the operation/stream. | No session lifecycle exists in the inspected Kernel. Do not mint an independent identity or treat an app cookie as a replacement for G01. |
| D09 — Language | Amharic is the default UI/assistant language; English is selectable; accept mixed Amharic/English and allow explicit per-turn locale override or automatic detection. | Aligns with the workstream mandate. Locale is a presentation/generation preference, never an identity or policy input. |
| D10 — Limits | Enforce configurable hard ceilings at both subject and tenant scope for input size, output tokens, concurrency, request rate, wall-clock time, retries and spend. Missing/invalid budget configuration denies generation. Numeric defaults must be set before A3 from measured provider/load constraints and Owner-approved cost envelope. | Prevents unbounded cost/denial-of-service exposure. No numeric ceiling should be invented without evidence. |

## 13.2 Trusted policy integration contract

The inspected candidate Kernel does **not** provide a signed/persisted policy lifecycle. `Policy::new(...)` constructs an in-memory policy; its source comment states signing, approval and persistence are not implemented. Public `evaluate()` is only a deterministic evaluator and is not a complete authorization path.

The required A3 integration contract is therefore:

1. A trusted composition root loads a versioned policy bundle from an Owner-authorized policy source. The bundle must be integrity/authenticity verified against an explicitly provisioned policy-signing trust root; a model, HTTP request, tenant administrator without delegated authority, or provider cannot supply or replace it.
2. The bundle declares schema/version, monotonically increasing policy epoch, effective interval, capability allowlist, approval-required set, risk ceilings, tenant applicability and a digest. Reject rollback, unknown schema, invalid signature, expired policy, duplicate/ambiguous capability rules and incomplete required fields.
3. Convert only a verified bundle into an immutable in-memory Kernel `Policy` snapshot inside the trusted composition root. Do not expose `Policy::new` to request handlers or accept policy values from client/provider input.
4. Pin one policy version/digest for each authorization decision and record it in the Kernel audit event. Policy refresh is atomic: requests use either the previous valid snapshot or the new valid snapshot, never a partially loaded state.
5. If no valid policy snapshot exists, signature/epoch validation fails, refresh state is indeterminate beyond the approved freshness bound, or the policy source is unavailable at startup, protected conversation operations fail closed. Do not silently fall back to permissive defaults or stale policy outside its approved validity.
6. Every operation constructs `AuthorizationRequest` server-side using `VerifiedPrincipal::subject()`, a constant server-defined capability, a canonical resource and risk classification. Call the production `authorize_authenticated_with_owner_approval(...)` path (or a later approved public equivalent), not `evaluate()` alone or test-only helpers. An ALLOW is a decision, not an execution grant.
7. Keep policy administration and policy-signing-key rotation outside the chat runtime. Owner approvals remain scoped to exact capability/resource/policy version and are verified/consumed by the Kernel.

**A2 disposition:** contract specified; implementation and trusted signing/persistence adapter are missing. The policy trust root, policy source, freshness bound and policy-administration delegation must be approved before A3. Do not reuse the credential trust bundle as a policy-signing authority unless its purpose and key usage are explicitly authorized.

## 13.3 Trusted tenant and session integration contract

1. Authenticate the request using the configured G01 credential verifier and production revocation checker. Never deserialize a `VerifiedPrincipal` or accept a subject from request JSON.
2. Resolve tenant membership from a trusted server-side source keyed by the verified subject. The resolver returns tenant ID, membership state, role, membership version and checked-at time. A client tenant selector is only a requested context and must match an active membership.
3. Reject absent, suspended, revoked, ambiguous or stale membership. Resolver outage or inability to establish freshness is a fail-closed error; never infer tenant from email, hostname, untrusted JWT metadata or model context.
4. For D02's proposed owner-only first slice, authorize only the immutable `owner_subject_id`; no share/member table or implicit tenant-wide visibility is enabled. Conversation creation records the resolved tenant and owner atomically.
5. For each read, write, list, export, cache, search and background task, enforce the same tenant predicate and owner ACL in the data-access layer. Do not rely on opaque IDs or a prior request's check.
6. Build the Kernel resource canonically, including tenant and conversation scope (for example `tenant/{tenant_id}/conversation/{conversation_id}`). Kernel capability authorization and tenant/owner authorization are conjunctive: both must pass; either denial or indeterminate result blocks the operation.
7. Bind app-session records to subject, tenant, credential/session identifier, issued-at, expiry, revocation version and session status. App session is a bounded transport/session convenience, not an alternate identity authority. Credential revocation, membership revocation, session revocation or expiry must invalidate subsequent requests and active streams.
8. Recheck authorization/session/membership before stream start and during long-lived streams at a bounded interval and before committing terminal output. Stop accepting provider deltas immediately after revocation or authorization loss.
9. Include tenant-scoped canonical resource and correlation identifiers in Kernel audit. Keep conversation lifecycle/message audit separate from the Kernel security-decision audit; never copy raw message bodies, tokens or secrets into the security audit.
10. Until a concrete trusted membership/session source and its availability/freshness semantics are selected and verified, multi-tenant operation is NOT READY. A single-tenant test fixture may be used only in synthetic non-production testing and must not be represented as a production tenant authority.

**A2 disposition:** the application contract is now explicit; no tenant-membership resolver, tenant-aware Kernel request field, conversation ACL service or session lifecycle was found in the inspected candidate Kernel. The resolver/session adapter is a required A3 dependency and must be independently tested for cross-tenant and revoked-membership denial.

## 13.4 Final A2 closure assessment — prepared for Owner approval

| Closure criterion | Assessment | Evidence / remaining condition |
|---|---|---|
| CIW workstream definition | PASS (proposal) | PR #19 and workstream contract |
| Kernel reuse/adapt/missing inventory | PASS (candidate inventory) | PR #13 source at exact candidate HEAD; not adopted |
| Authentication, revocation, Owner approval and audit boundary | PASS (candidate behavior reconciled) | Production authenticated Owner-approval path identified; stable dependency adoption remains gated |
| Trusted policy lifecycle | CONTRACT DEFINED / IMPLEMENTATION MISSING | This document §13.2; no signed/persisted policy lifecycle in candidate Kernel |
| Tenant membership and session authority | CONTRACT DEFINED / IMPLEMENTATION MISSING | This document §13.3; no trusted resolver or session lifecycle found |
| Conversation ownership and isolation | PASS (contract) / IMPLEMENTATION MISSING | Owner-only and immutable tenant binding proposed; no runtime persistence |
| API, streaming, G03 and G08 boundaries | PASS (proposal) | Schemas and boundaries specified; G08 PR #18 is unmerged and not a chat runtime |
| Seven pending Owner decisions | PROPOSED — 7/7 READY FOR RATIFICATION | Values recommended above; not Owner-approved |
| Previously approved D03/D04/D06 | PASS — 3/10 OWNER-APPROVED | Exact 2026-11-08 Owner record |
| A4 acceptance/verification plan | PASS (plan only) | No runtime tests run because implementation is not authorized/not present |
| A2 closure | **NOT YET CLOSED — OWNER RATIFICATION AND BASELINE DEPENDENCIES REMAIN** | Requires Owner disposition of D01/D02/D05/D07–D10 and explicit selection of the Kernel/policy/tenant baseline before A3 |

**Recommendation:** approve the seven proposed dispositions as written, subject to the stated conditions; record the policy and tenant contracts as the mandatory A3 integration boundary; then close A2 as a design/contract gate with the unmerged Kernel adoption, policy trust source and tenant/session adapter recorded as explicit A3 entry blockers. Do not claim the runtime is implemented, verified or production-ready.

## 14. Explicit exclusions and next gate

This document does not:
- implement chat endpoints, storage, streaming, model providers or UI;
- add dependencies, migrations, secrets, provider credentials or production configuration;
- merge PR #13, #15, #17, #18 or #19;
- alter trust roots, identity, policy, revocation, Owner authority or audit behavior;
- enable tools, agents, voice, multimodal processing or autonomous actions;
- require independent witness enrollment for design or controlled non-production chat;
- claim A4-03 closure, independent audit durability or production readiness.

**Next gate:** resolve the seven pending Owner decisions and close technical dependencies: adopted Kernel baseline, trusted policy lifecycle, tenant-membership/session authority, and concrete policy-to-capability mapping. D03, D04 and D06 are already recorded as approved. A2 remains open. After the Kernel baseline and tenant/session/policy interfaces are confirmed, prepare a bounded A3 implementation plan for the answer-only Amharic-first text-chat vertical slice. A3 code, merge and deployment remain separately authorized gates.

**Constitutional rule:** Conversation expresses intent. Cognition proposes. Governance decides. Authorization permits. Execution acts. Assurance verifies.
