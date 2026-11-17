# IROKA G05 — Memory Architecture and Implementation Contract

- **Contract ID:** IROKA-G05-MEM-001
- **Version:** 1.0.0
- **Status:** OWNER-APPROVED
- **Approval:** Explicit Owner approval recorded in the project conversation on 2026-11-09
- **Implementation status:** NOT STARTED — separate A3 authorization required
- **Baseline:** IROKA A1/A2 pinned baseline `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`

## 1. Purpose and normative language

G05 is the IROKA memory domain. It governs the proposal, capture, approval, storage, retrieval, correction, restriction, retention, expiry, and deletion of memory records. Memory must be purpose-bound, tenant- and principal-scoped, provenance-preserving, reviewable, and subject to explicit lifecycle controls.

The terms MUST, MUST NOT, REQUIRED, SHOULD, and MAY are normative.

This contract defines logical responsibilities and acceptance requirements. It does not itself create an API, runtime, database, migration, provider, or production authority.

## 2. Domain ownership and boundaries

| Domain | Authoritative responsibility | G05 boundary |
|---|---|---|
| G01 Identity | Credential verification and principal identity | G05 consumes verified opaque identity references; it does not authenticate users. |
| IROKA tenant authority | Membership resolution and immutable tenant binding | G05 consumes server-resolved tenant context; caller-supplied tenant IDs are selectors only. |
| G02 Governance | Authorization, policy, approvals and revocation | G05 MUST obtain authorization from G02 before memory access or lifecycle mutation. |
| G03 Cognition | Reasoning, planning, synthesis | G03 may propose memory candidates but MUST NOT own or directly persist authoritative memory. |
| G04 Knowledge | External source registry, retrieval, evidence and provenance | G05 may retain references to G04 evidence; it MUST NOT duplicate G04's source registry or retrieval authority. |
| G05 Memory | Memory records and lifecycle | Sole owner of memory record lifecycle and memory retrieval semantics. |
| G06 Perception | Perceptual inputs and interpretation | G05 consumes only authorized, appropriately classified outputs. |
| G08 Orchestration | Workflow coordination | Orchestrates G05 operations without becoming a memory authority. |
| G09 Execution | Protected effects | A G05 result or G02 ALLOW decision is not an execution grant. G09 MUST independently revalidate authorization before effects. |
| G10 Evaluation | Quality and evaluation | May evaluate memory quality through an approved contract; it does not activate memory. |
| G11 Assurance/Audit | Audit records and assurance | Owns audit event persistence and integrity; G05 emits versioned events. |
| G12 Evolution | Governed system evolution | No authority to bypass G05 lifecycle, G02 policy, or Owner approval. |

No parallel identity, authorization, external knowledge, audit, or protected-execution authority may be introduced in G05.

## 3. Memory classes

### 3.1 Working memory

Temporary task/session-scoped context with an explicit expiry. Working memory MUST NOT be promoted automatically to episodic or durable memory. Restricted-classification content is excluded from all initial G05 working-memory operations, including temporary storage, caches, derived representations, and retrieval candidates.

### 3.2 Episodic memory

A traceable record of a significant event, interaction, or decision, retaining source, actor, time, purpose, and provenance. Episodic capture is **opt-in**. No episodic record may be created unless the relevant user or authorized organization has explicitly opted in for the applicable purpose and scope. Opt-in MUST be revocable prospectively.

### 3.3 Durable memory

An approved, persistent preference, decision, or context record with an explicit purpose, provenance, classification, retention rule, and accountable subject or organization.

**Every durable memory record requires explicit approval for that individual record.** No model confidence, automated evaluation, repeated use, inferred preference, or ordinary access authorization can substitute for that approval. A model-generated candidate remains a proposal until the required human approval is recorded.

For organizational durable memory, approval MUST be provided by a designated, authorized human reviewer whose authority is scoped to the relevant tenant and organization. No automatic organizational durable-memory activation is permitted.

## 4. Owner decisions — binding v1.0.0 rules

| ID | Owner decision | Normative rule |
|---|---|---|
| D1 | Durable activation: explicit approval for every record | Every durable record requires an explicit, attributable approval for that record before activation. |
| D2 | Episodic default: opt-in | Episodic capture is disabled by default and requires explicit opt-in for the relevant scope and purpose. |
| D3 | Personal rights: inspect and request deletion of eligible records | An authenticated principal can inspect eligible records within authorized scope and submit deletion requests. |
| D4 | Organizational durable memory: designated human reviewer | A designated authorized human reviewer must approve each organizational durable record. |
| D5 | Semantic/vector retrieval: defer | Vector databases, embeddings, semantic indexes, and semantic retrieval are excluded from initial implementation until a separate security and dependency review is completed and approved. |
| D6 | Cross-principal sharing: prohibit unless explicitly authorized by policy | Sharing is default-deny. G02 must explicitly authorize the recipient(s), purpose, tenant, classification, and scope before access. |
| D7 | Restricted data in working memory: exclude | Restricted-classification content MUST NOT enter initial G05 working memory, its caches, derived forms, or retrieval candidates. |

These decisions supersede any conflicting defaults in earlier proposal text.

## 5. Logical memory record

The following is a logical contract shape, not a finalized wire schema:

- `memory_id`: stable unique record identifier
- `tenant_id`: server-resolved tenant identifier
- `subject_ref`: opaque G01 principal or authorized organizational subject reference
- `actor_ref`: opaque identity reference for the creator or acting reviewer
- `memory_class`: WORKING, EPISODIC, or DURABLE
- `content_ref`: protected content reference; raw content is not exposed in audit events
- `content_hash`: integrity digest for the canonical content representation
- `purpose`: enumerated, approved purpose
- `classification`: PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED
- `source_refs[]`: references to originating interactions, G04 evidence, or authorized workflow records
- `provenance`: source and derivation lineage
- `confidence`: optional calibrated metadata; never an activation authority
- `created_at`, `updated_at`: timestamps
- `expires_at`: required where the memory class or retention policy requires expiry
- `retention_policy_ref`: applicable retention rule
- `consent_ref`: applicable opt-in/consent reference where required
- `approval_ref`: attributable approval evidence for durable activation
- `record_version`: monotonic version for concurrency and correction
- `lifecycle_state`: governed lifecycle state
- `audit_ref`: G11 correlation/reference

The implementation MUST define canonical serialization, validation, field constraints, and version compatibility before exposing a wire API.

## 6. Provenance and evidence integrity

Provenance categories:

- `USER_EXPLICIT`
- `OWNER_APPROVED`
- `SYSTEM_OBSERVED`
- `G04_EVIDENCE_REFERENCE`
- `AUTHORIZED_WORKFLOW`
- `HUMAN_REVIEWED`
- `MODEL_PROPOSED`

A `MODEL_PROPOSED` record is an unverified candidate, not an established fact. Derived summaries or representations MUST preserve lineage to their source records. Conflicting evidence MUST be represented without silently overwriting the prior record. G04 evidence references MUST preserve source revision and integrity information supplied by G04.

G05 MUST NOT claim that a source is verified merely because a model generated or summarized it.

## 7. Authorization and tenant isolation

All memory operations MUST follow the authoritative chain:

1. G01 verifies the credential and resolves an opaque principal reference.
2. IROKA's tenant authority resolves membership and immutable tenant context server-side.
3. G02 evaluates the operation, purpose, tenant, subject, classification, lifecycle state, and applicable policy.
4. G05 performs the operation only after successful authorization and required approval/consent checks.
5. G11 receives the required audit event.

Callers MUST NOT supply authoritative principal, membership, tenant context, policy, reviewer authority, or consent state. A client-supplied tenant identifier is a selector only and MUST be checked against server-resolved membership.

Authorization MUST be checked before content access, candidate ranking, retrieval exposure, correction, export, sharing, or deletion. Failure to resolve identity, tenant, policy, consent, reviewer authority, or audit prerequisites MUST fail closed.

G02 access authorization does not replace D1/D4 record-level human approval. A G02 ALLOW decision does not authorize G09 protected effects.

## 8. Purpose limitation, consent, and classification

Proposed initial purpose vocabulary, subject to schema validation during A3:

- `TASK_CONTINUITY`
- `USER_PREFERENCE`
- `PROJECT_CONTEXT`
- `ORGANIZATIONAL_CONTEXT`
- `OPERATIONAL_HISTORY`
- `AUTHORIZED_SYSTEM_ASSURANCE`

Every record MUST have a declared purpose and an applicable authorization basis. Episodic records require explicit opt-in. Durable records require record-specific approval. Consent/opt-in and approval evidence MUST be revocable or supersedable according to policy.

Initial classification vocabulary:

- `PUBLIC`
- `INTERNAL`
- `CONFIDENTIAL`
- `RESTRICTED`

Classification is a handling constraint, not an access grant. Restricted content is excluded from initial G05 working memory. Secrets, credentials, private keys, access tokens, and recovery codes MUST NOT be stored as ordinary memory content.

## 9. Retention and lifecycle

Working memory MUST be short-lived and expire according to a bounded policy. Episodic memory MUST have a declared retention rule and remain subject to opt-in. Durable memory MUST have an explicit retention rule and review path. No record may be retained indefinitely merely because no expiry was supplied.

Proposed lifecycle states:

- `PROPOSED`
- `PENDING_REVIEW`
- `ACTIVE`
- `REJECTED`
- `RESTRICTED`
- `CORRECTION_PENDING`
- `DELETION_PENDING`
- `EXPIRED`
- `DELETED`

Only authorized transitions are permitted. Durable records cannot transition to ACTIVE without the record-specific approval required by D1 and, for organizational records, D4. Expired, restricted, pending-deletion, or deleted records MUST NOT be returned as ordinary active memory.

Retention enforcement MUST address primary storage, indexes, caches, derived representations, replicas, and backups as applicable. Legal holds or other mandatory retention constraints must be explicit, scoped, auditable, and communicated in deletion-request status. Deleted content MUST NOT be resurrected through backup restoration or stale indexes.

## 10. Personal inspection, correction, and deletion

An authenticated principal MUST be able to inspect eligible memory records within their authorized scope and request deletion of eligible records. The interface MUST distinguish at least:

- request received;
- authorization/eligibility review pending;
- deletion blocked by an identified retention or legal constraint;
- deletion in progress;
- deletion completed;
- deletion independently verified.

Correction MUST preserve record version history and provenance. A correction MUST NOT silently rewrite source evidence. Where deletion is not immediately permissible, G05 MUST record the reason, scope, responsible authority, and review condition without exposing protected content.

Deletion verification MUST account for primary content, indexes, caches, derived representations, replicas, and backups according to the approved retention/deletion design. G11 audit records may retain minimal non-content proof and correlation metadata where policy requires, but MUST NOT retain deleted memory content as a shadow copy.

## 11. Retrieval contract

Initial v1 retrieval MUST use only an explicitly approved, non-vector retrieval mechanism. Semantic/vector retrieval, embedding generation, vector databases, and semantic indexes are DEFERRED until a separate security, privacy, dependency, licensing, and operational review is approved.

Retrieval sequence:

1. Resolve G01 principal and server-side tenant membership.
2. Obtain G02 authorization for the requested operation, purpose, scope, and classification.
3. Validate consent, record-specific approval, lifecycle state, retention, and sharing policy.
4. Restrict candidates to the authorized tenant and subject scope.
5. Retrieve and rank only after authorization checks; do not leak candidate existence, counts, scores, or metadata across unauthorized scopes.
6. Return content with provenance, record version, classification, and applicable freshness/retention metadata.
7. Emit the required G11 audit event.

Cross-principal sharing is prohibited by default. Any exception requires explicit G02 policy authorization specifying recipients, purpose, tenant, classification, and scope. A tenant-wide membership relationship alone does not authorize sharing.

## 12. Persistence and storage constraints

The storage implementation MUST be replaceable and MUST NOT presume a particular relational database, vector store, or embedding provider in this contract. A3 must define:

- tenant-aware isolation and uniqueness constraints;
- transactional lifecycle transitions and approval consumption;
- monotonic record versions and concurrency control;
- idempotent create, update, and deletion operations;
- integrity verification and corruption handling;
- retention, expiry, deletion, and backup-resurrection controls;
- encryption and key-management boundaries;
- recovery and migration procedures;
- provider data-retention and no-training terms where external components are considered.

No external memory provider or vector dependency is authorized by this contract.

## 13. G11 audit integration

G11 remains the authoritative audit and assurance domain. G05 MUST emit versioned events sufficient to establish actor, tenant, operation, purpose, record reference, decision/approval reference, outcome, and correlation without copying memory content into audit logs.

Proposed event vocabulary:

- `memory.proposed`
- `memory.created`
- `memory.activated`
- `memory.retrieved`
- `memory.promoted`
- `memory.corrected`
- `memory.restricted`
- `memory.expired`
- `memory.deletion_requested`
- `memory.deletion_completed`
- `memory.retention_blocked`
- `memory.authorization_denied`

The current G11 event schema must be inspected and extended through a separately versioned, backward-compatible contract before implementation. G05 MUST fail closed where the required audit guarantee cannot be met. G05 does not create a parallel audit store or claim external checkpoint anchoring unless G11 provides it.

## 14. G03, G04, and G10 integration

- G03 may submit a `MODEL_PROPOSED` candidate. It cannot activate durable memory, bypass opt-in, or write directly to G05 persistence.
- G04 remains authoritative for external evidence retrieval and provenance. G05 stores references and approved memory-derived records, not a duplicate G04 source registry.
- G10 may evaluate quality, utility, consistency, and retrieval outcomes only through a separately approved contract. Evaluation scores do not activate, authorize, or delete records.
- Integration contracts MUST use opaque references and explicit versioning. No guessed APIs or undeclared runtime capabilities may be assumed.

## 15. Threat model and required controls

A3/A4 must address at minimum:

- cross-tenant and cross-principal disclosure;
- authorization time-of-check/time-of-use and stale membership/policy;
- prompt injection and malicious memory poisoning;
- model-generated false facts and fabricated provenance;
- unauthorized durable activation or reviewer impersonation;
- consent withdrawal and opt-in replay;
- candidate-count, ranking-score, and metadata side channels;
- embedding, cache, index, replica, and backup leakage;
- incomplete deletion and backup resurrection;
- retention-policy bypass and indefinite storage;
- replay, idempotency, and concurrent lifecycle races;
- delegated-agent overreach and confused-deputy behavior;
- external provider retention, training, licensing, and dependency risk;
- audit omission, tampering, or content leakage.

## 16. Logical operations

The following are logical operation names only. They are not authorized endpoint names or implemented APIs:

- `propose_memory`
- `create_working_memory`
- `create_episodic_memory`
- `activate_durable_memory`
- `retrieve_memory`
- `get_memory_metadata`
- `correct_memory`
- `restrict_memory`
- `expire_memory`
- `request_memory_deletion`
- `verify_memory_deletion`
- `review_memory_candidate`
- `evaluate_memory_quality`

## 17. Acceptance criteria

A3 implementation and A4 verification must provide evidence for at least these tests:

- **G05-AT-01:** Working memory expires within its bounded policy.
- **G05-AT-02:** No durable record activates without explicit record-specific approval.
- **G05-AT-03:** Organizational durable activation requires a designated, authorized human reviewer.
- **G05-AT-04:** Episodic capture is impossible without explicit opt-in and stops prospectively after opt-out.
- **G05-AT-05:** Cross-tenant access is denied, including metadata and candidate-existence leakage.
- **G05-AT-06:** Authorization occurs before content access and ranking.
- **G05-AT-07:** G03 cannot persist authoritative memory directly.
- **G05-AT-08:** G04 source references retain verifiable provenance and revision lineage.
- **G05-AT-09:** Model-proposed candidates are not treated as verified facts or activated automatically.
- **G05-AT-10:** Correction increments record version and preserves provenance/history.
- **G05-AT-11:** Restricted, expired, deletion-pending, and deleted records are not returned as active memory.
- **G05-AT-12:** Deletion covers indexes, caches, derived representations, replicas, and backup restoration controls.
- **G05-AT-13:** Required audit failure prevents protected lifecycle completion.
- **G05-AT-14:** Operations are idempotent and safe under concurrency/replay.
- **G05-AT-15:** Purpose, classification, retention, and consent constraints are enforced.
- **G05-AT-16:** Prompt-injected or poisoned memory candidates cannot bypass review, provenance, or authorization.
- **G05-AT-17:** Cross-principal sharing is denied absent explicit G02 policy authorization.
- **G05-AT-18:** Restricted-classification data cannot enter initial working memory or its derived/cache paths.
- **G05-AT-19:** Semantic/vector retrieval components are absent from the initial implementation unless separately approved after review.

## 18. Implementation package and stage gates

Before A3 begins, the implementation plan must identify exact contracts and dependencies for:

1. machine-readable record and event schemas;
2. G01 and tenant-authority integration;
3. G02 operation-level authorization matrix;
4. record-specific durable approval and designated organizational reviewer authority;
5. episodic opt-in and withdrawal;
6. purpose, classification, retention, expiry, correction, and deletion;
7. storage adapter, transaction, versioning, and recovery design;
8. G11 event extension and failure semantics;
9. G03/G04/G10 integration boundaries;
10. threat model, abuse cases, synthetic test fixtures, dependency and license review.

Stage gates:

- **A1:** Architecture baseline frozen.
- **A2:** Contract design and Owner decisions approved.
- **A3:** Implementation only after separate explicit Owner authorization; isolated branch/PR; preserve unrelated changes.
- **A4:** Exact-HEAD verification, security review, data-lifecycle tests, recovery/deletion evidence, and independent assurance where available.
- **A5:** Separate deployment/release authorization.

This contract approval closes the G05 design gate only. It does NOT authorize A3 implementation, real-user ingestion, production key provisioning, merge, signing, release, deployment, or production activation.

## 19. Approval record

The Owner explicitly approved **IROKA G05 Memory Architecture and Implementation Contract v1.0.0** after reviewing and deciding D1–D7. This repository artifact records that approval and the resulting normative requirements.

**Approval scope:** Contract v1.0.0 and its governance decisions.
**Not included:** A3 implementation authorization, A4 closure, or A5 release/deployment authorization.
