# IROKA G05 — G01/G02/G11 Authority Integration Contract Amendment

- **Document ID:** IROKA-G05-INT-001
- **Version:** 0.1.0
- **Status:** DRAFT — FOR OWNER REVIEW
- **Related approved contract:** IROKA-G05-MEM-001 v1.0.0
- **Related implementation:** A3 B04 G05 core, PR #34
- **Design baseline:** IROKA A1/A2 pinned baseline `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`
- **Prepared against:** G05 implementation HEAD `2b5cbbd2e74308286547890d993820a5beeca329`
- **Scope:** Contract design only. No runtime/API implementation, migration, production authority, merge, or deployment is authorized by this document.

## 1. Purpose and status

This amendment proposes the missing integration contracts needed to complete G05 organizational durable-memory approval and G11 lifecycle assurance without creating duplicate authority domains.

It is subordinate to, and does not amend or weaken, the Owner-approved G05 contract v1.0.0. Its D1–D7 decisions remain binding. If this proposal conflicts with v1.0.0, v1.0.0 prevails until the Owner explicitly approves a revised contract.

The proposal is based on repository inspection:

- G01 has Ed25519 compact-JWS credential verification, immutable trusted-key snapshots, and revocation-checker interfaces for credential and key revocation.
- G02 has Owner-signed approvals, Owner-signed security commands, and global capability policy lifecycle. The inspected implementation does not expose an organization-scoped reviewer-delegation registry or authorization contract.
- G11 has a decision-oriented `AuditEvent` and append-only hash-chained SQLite sink with idempotent append support. The inspected event type is not a versioned memory-lifecycle event envelope.
- G05 currently depends on trusted provider interfaces for reviewer proof and organization scope. Its concrete Kernel adapter deliberately denies organization-scope authorization until an authoritative provider exists.

These observations are the basis for the proposed interfaces; they do not imply that the proposed interfaces already exist.

## 2. Design principles

1. **Single authority per domain.** G01 verifies identity and signatures; G02 decides authority and policy; G05 owns memory records and transitions; G11 owns assurance-event acceptance and durable audit.
2. **No local trust roots in G05.** G05 MUST NOT create, enroll, or independently trust reviewer signing keys.
3. **No implicit organizational authority.** Tenant membership, employment, group membership, or a global G02 capability MUST NOT by itself confer authority to designate a memory reviewer.
4. **Record-specific approval.** Every organizational durable-memory activation requires a fresh, attributable approval bound to the exact record version and content digest.
5. **Revocation wins.** Current key, credential, delegation, membership, and policy state MUST be revalidated at the point of use. Stale or unavailable authority state fails closed.
6. **No content in audit.** G11 lifecycle events carry references, digests, classifications, and outcome metadata only; never memory content, excerpts, prompts, embeddings, or secrets.
7. **No false exactly-once claim.** Delivery is at-least-once with stable idempotency keys and receiver-side deduplication. A pending outbox item is not proof that G11 accepted an event.
8. **No new production authority.** All interfaces remain disabled/default-deny until their owning domain provides an approved implementation and the relevant stage gates pass.

## 3. G01 reviewer-approval proof contract

### 3.1 Ownership

G01 owns reviewer principal authentication, signing-key identity binding, signature verification, credential validity, and current key/credential revocation checks. G01 MUST expose a narrow verifier to G05; G05 MUST consume only its opaque verified result.

The existing Owner approval verifier MUST NOT be repurposed as a reviewer verifier. Owner authority and delegated organizational reviewer authority are distinct principals and trust purposes.

### 3.2 Proposed proof claims

A signed reviewer approval proof MUST bind at least:

- proof schema/version and cryptographic algorithm identifier;
- proof identifier (unique, non-empty, replay-detectable);
- issuer and key identifier;
- reviewer subject reference (opaque G01 principal);
- tenant and organization identifiers;
- delegation identifier and delegation version;
- action fixed to `ACTIVATE_DURABLE_MEMORY`;
- memory identifier and exact record version;
- canonical content digest and digest algorithm;
- purpose and classification;
- issued-at and expiry timestamps;
- a nonce or unique approval reference.

The proof MUST NOT carry memory content. Unknown fields MUST be rejected for the selected schema version. Canonical serialization and signature input MUST be explicitly specified before implementation; signing arbitrary JSON serialization is prohibited.

### 3.3 Verification requirements

The G01 verifier MUST:

1. authenticate the signer against an authoritative G01 principal/key binding;
2. validate algorithm, signature, issuer, key identifier, and schema version;
3. validate issued-at, expiry, maximum proof lifetime, and permitted clock skew;
4. check current key and credential revocation state;
5. fail closed if revocation or identity authority is unavailable or exceeds its declared freshness bound;
6. return an opaque verified reviewer-proof reference and verified claims, not a caller-constructible boolean;
7. bind the verified proof to the exact tenant, organization, delegation version, memory ID, record version, content digest, purpose, classification, and activation action;
8. expose enough immutable metadata for G02/G05 to compare the proof with current delegation and candidate state.

G01 proves who signed and whether the proof is cryptographically valid. G01 does NOT decide whether the signer is authorized to review for the organization; that decision belongs to G02.

### 3.4 Revocation and replay

Key and credential revocation MUST be checked at proof use, not only when the proof is first received. A proof whose key or credential is revoked, unknown, stale, or uncheckable MUST be rejected.

The proof identifier/nonce MUST be consumed once for its exact activation scope. Reuse against another record, another record version, another tenant, or a second activation MUST be denied. Consumption must be concurrency-safe and durable.

A signature that remains mathematically valid after key revocation MUST NOT remain operationally acceptable.

## 4. G02 organization-scoped reviewer delegation contract

### 4.1 Ownership and authority source

G02 owns the decision whether a principal may designate, revoke, or act as a reviewer for a specific organization and memory purpose. G02 MUST obtain the underlying organizational authority from a canonical, independently governed organization-delegation source. The source and its proof of authority must be identified and approved before implementation.

The inspected repository does not currently provide that canonical organization-delegation authority. Therefore, this proposal does not invent an organization-admin role, assume that tenant membership grants delegation rights, or designate an Owner key as an organization reviewer key.

Until the canonical authority source and G02 adapter are approved and available, reviewer designation, revocation, and organizational durable activation MUST remain default-deny.

### 4.2 Delegation record

A G02-authoritative delegation record MUST contain at least:

- immutable delegation ID and monotonically increasing version;
- tenant ID and organization ID;
- designated reviewer principal reference from G01;
- permitted memory action(s), initially only `ACTIVATE_DURABLE_MEMORY`;
- permitted purpose and classification scope;
- optional subject/record scope restrictions;
- grantor principal and verified grantor-authority reference;
- issued-at, not-before, expiry, and revocation state;
- policy/delegation schema version;
- G11 audit correlation/reference.

The delegation MUST be least-privilege, tenant-bound, organization-bound, time-bounded, and revocable. Wildcard tenant or organization scope is prohibited for this initial integration.

### 4.3 Designate, change, revoke

G02 MUST authorize designation and revocation using an explicit organization-scoped capability and the canonical organization-authority provider. A global capability alone is insufficient.

A change creates a new monotonically increasing delegation version. The latest version is authoritative. Revoked, expired, superseded, or otherwise invalid latest state MUST NOT cause an earlier version to become active again.

Revocation MUST invalidate subsequent approvals immediately according to the authority store's consistency guarantee. If current state cannot be checked, the action fails closed. A3 must document the linearization point and consistency model; no claim of cross-database atomicity may be made without evidence.

### 4.4 Activation decision

Before G05 activates a durable organizational record, G02 MUST authorize the exact tuple:

`tenant + organization + reviewer + delegation ID/version + action + memory ID + record version + content digest + purpose + classification`.

G02 MUST independently verify that:
- the delegation is current, active, in scope, and not revoked;
- the G01-verified reviewer proof matches the delegation and exact candidate;
- the policy permits the action and classification;
- the approval proof has not expired or been consumed;
- no applicable emergency stop, policy revocation, or organization restriction blocks activation.

G02 returns an opaque, short-lived authorization decision/reference. It does not write or activate the memory record. G05 remains responsible for the memory lifecycle transition.

### 4.5 TOCTOU and atomicity

The current G05 registry and Kernel G02 authority use separate persistence transactions. The implementation MUST NOT claim atomic policy/delegation revocation and memory activation across those stores.

Before activation, G05 MUST revalidate current G02 policy, tenant membership, delegation version, reviewer proof validity/revocation, and one-time proof consumption. The final activation operation MUST be conditional on the exact record version and digest. If a reliable transactional boundary across G02 and G05 cannot be provided, the state machine MUST preserve a non-active pending state until the authoritative checks and required audit acknowledgment are complete.

G09 MUST still independently revalidate all authority immediately before any protected external effect.

## 5. G11 versioned memory-lifecycle event contract

### 5.1 Separate event families

The current G11 `AuditEvent` represents an authorization decision with a `DecisionCode`. It MUST NOT be overloaded by mapping memory lifecycle events to ALLOW/DENY/ESCALATE values.

G11 SHOULD introduce a separately versioned assurance-event envelope or a versioned event union while preserving existing decision-event compatibility. G11 remains the sole owner of event acceptance, durable append, integrity, retention, and checkpoint assurance.

### 5.2 Proposed envelope

The versioned envelope MUST carry:

- `event_schema`: stable schema identifier;
- `event_version`: explicit integer/semver-compatible version;
- `event_id`: stable globally unique idempotency key;
- `event_type`: allowlisted event name;
- `occurred_at`: event time;
- `tenant_ref`: opaque tenant reference;
- `actor_ref`: opaque actor reference;
- `subject_ref`: opaque memory subject reference;
- `memory_ref`: opaque memory identifier;
- `record_version`: monotonic record version where applicable;
- `purpose` and `classification`;
- `authorization_ref`, `consent_ref`, `approval_ref`, or `delegation_ref` as applicable;
- `outcome`: typed lifecycle outcome, not a G02 decision code;
- `correlation_id` and causation reference;
- `payload_digest` or other integrity reference where necessary.

The envelope MUST NOT contain content, excerpts, prompts, embedding vectors, raw credentials, signing material, secrets, or unnecessary personal data. Event validation MUST reject unknown event types, malformed identifiers, oversized fields, invalid versions, and prohibited content fields.

### 5.3 Initial event vocabulary

The initial G05 event extension SHOULD include at least:

- `memory.proposed`
- `memory.working.created`
- `memory.episodic.created`
- `memory.durable.review_requested`
- `memory.durable.approved`
- `memory.durable.activated`
- `memory.retrieved`
- `memory.corrected`
- `memory.restricted`
- `memory.expired`
- `memory.deletion.requested`
- `memory.deletion.blocked`
- `memory.deletion.completed`
- `memory.deletion.verified`
- `memory.authorization.denied`
- `memory.consent.granted`
- `memory.consent.withdrawn`
- `memory.reviewer.designated`
- `memory.reviewer.revoked`
- `memory.reviewer.approval.consumed`

The final event vocabulary and required fields are subject to G11 Owner/domain review. Events MUST describe completed facts accurately; a request, queued outbox record, or attempted deletion MUST NOT be reported as completed or verified.

### 5.4 Transactional outbox and delivery

G05 mutations that require an audit event MUST write a content-free outbox record in the same local transaction as the corresponding G05 state change. The outbox MUST preserve event ID, schema version, payload digest, creation time, delivery attempts, and acknowledgment state.

Delivery is at-least-once. G11 MUST deduplicate by stable event ID and reject an event-ID collision where the same ID is presented with a different canonical payload digest. Replaying an identical event MUST be idempotent.

An outbox item in PENDING/RETRY state is not an accepted G11 audit event. For lifecycle operations whose contract requires completed audit before exposure or activation, G05 MUST keep the record in a non-active/pending state until G11 acknowledges durable acceptance. G05 MUST expose a distinct pending-audit outcome rather than claiming success.

G11 unavailability, integrity failure, schema mismatch, or idempotency conflict MUST fail closed for the affected protected lifecycle transition. Retry must not duplicate the underlying transition or silently discard the event.

### 5.5 Integrity and retention

G11 MUST define whether the new event family is covered by the existing append-only hash chain, its checkpoint process, access controls, retention, and export controls. Local hash chaining alone MUST NOT be described as external anchoring. No new external checkpoint service or key is authorized by this proposal.

Audit retention MUST be reconciled with G05 deletion rights: G11 may retain only the minimum content-free evidence required by policy. It MUST NOT retain memory content as a shadow copy.

## 6. Required G05 integration sequence

For organizational durable activation, the proposed sequence is:

1. G05 freezes a candidate snapshot: tenant, organization, memory ID, record version, content digest, purpose, and classification.
2. G01 authenticates the reviewer and verifies the signed approval proof against current trusted key and credential status.
3. G02 resolves the current organization-scoped delegation and policy, then authorizes the exact candidate/action tuple.
4. G05 atomically consumes the approval reference with the candidate version check within its supported transactional boundary; where cross-domain atomicity is unavailable, it preserves pending state and revalidates before activation.
5. G05 records the lifecycle event in its transactional outbox.
6. G11 validates and durably acknowledges the versioned event using stable idempotency semantics.
7. G05 transitions the record to ACTIVE only when all approval, authorization, concurrency, and required audit conditions are satisfied.
8. G09 independently revalidates membership and policy before any later protected effect.

No step may be skipped because an earlier authorization or proof was once valid.

## 7. Failure semantics

The following conditions MUST deny or leave the record non-active:

- unknown or revoked reviewer key/credential;
- invalid, expired, malformed, replayed, or wrong-scope approval proof;
- missing, stale, revoked, expired, superseded, or mismatched delegation;
- inability to resolve canonical organization authority;
- missing, stale, revoked, or unavailable G02 policy;
- tenant membership or organization scope mismatch;
- record version or content digest changed after approval;
- approval already consumed;
- emergency stop or applicable policy restriction;
- G11 schema rejection, audit unavailability, integrity failure, or event-ID collision;
- concurrency conflict or unavailable authority store.

Error responses MUST avoid disclosing unauthorized record content or cross-tenant existence.

## 8. Required adversarial acceptance tests

The following are additional integration tests; they supplement, not replace, G05-AT-01 through G05-AT-19 in v1.0.0.

- **G05-INT-AT-01:** A reviewer key unknown to G01 cannot approve.
- **G05-INT-AT-02:** A valid signature from a revoked key or credential is rejected.
- **G05-INT-AT-03:** G01 proof verification fails closed when current revocation state is unavailable or stale.
- **G05-INT-AT-04:** A proof for one tenant, organization, record, record version, digest, purpose, or classification cannot authorize another.
- **G05-INT-AT-05:** Owner approval credentials cannot be substituted for reviewer credentials, or vice versa.
- **G05-INT-AT-06:** A reviewer with tenant membership but no organization delegation is denied.
- **G05-INT-AT-07:** A global G02 capability without canonical organization authority is denied.
- **G05-INT-AT-08:** Revocation or supersession of the latest delegation version prevents activation; an older version is not resurrected.
- **G05-INT-AT-09:** Expired, revoked, out-of-scope, or wrong-purpose delegation is denied.
- **G05-INT-AT-10:** A reviewer approval proof is consumed once; concurrent replay cannot activate twice.
- **G05-INT-AT-11:** Changing record version or content digest after approval invalidates the approval.
- **G05-INT-AT-12:** G02, G01, or organization-authority unavailability leaves the record non-active.
- **G05-INT-AT-13:** G11 rejects unknown event versions/types and prohibited content fields.
- **G05-INT-AT-14:** Identical event retries are idempotent; same event ID with a different digest is rejected.
- **G05-INT-AT-15:** G11 outage leaves a required-audit transition pending and not reported as completed.
- **G05-INT-AT-16:** Outbox retries do not duplicate state transitions or lose events after restart.
- **G05-INT-AT-17:** Audit events contain no memory content, excerpts, prompts, embeddings, credentials, or secrets.
- **G05-INT-AT-18:** Event schema upgrades preserve compatibility with existing G11 decision events.
- **G05-INT-AT-19:** A stale tenant membership or policy version is rejected at activation and rechecked by G09 before protected effects.
- **G05-INT-AT-20:** A concurrency race between delegation revocation and activation resolves according to a documented linearization point; absent proof of ordering, activation fails closed.

## 9. Implementation prerequisites and ownership

| Work item | Owner | Required evidence before G05 production integration |
|---|---|---|
| Reviewer principal/key binding and signed-proof verification | G01 | Versioned proof schema, canonical signing bytes, current revocation provider, verifier contract and adversarial tests |
| Organization reviewer delegation and revocation | G02 + canonical organization authority | Identified authority source, grant/revoke authorization matrix, versioned registry contract, consistency/linearization semantics |
| Memory lifecycle event envelope and sink | G11 | Versioned schema, validation rules, durable append, idempotency/collision semantics, retention and integrity evidence |
| G05 composition and state machine | G05 | Exact integration contracts, no cross-store atomicity overclaim, pending-audit behavior, tests and migration/recovery plan |
| Independent security assurance | A4 | Threat-led review of exact proposed implementation HEAD and adversarial evidence |

No team/domain may implement another domain's authority as a shortcut. Where a prerequisite is absent, the dependent G05 operation remains fail-closed.

## 10. Stage gates and explicit exclusions

- **Current status:** Proposal only; not Owner-approved.
- **A3:** Existing G05 A3 authorization does not automatically approve this new integration contract. Implementation of these proposed cross-domain interfaces requires explicit approval of this amendment and confirmation by the owning domain contracts.
- **A4:** Independent security assurance remains NOT RUN.
- **A5:** Deployment/release remains NOT AUTHORIZED.

This document does NOT authorize:
- changing or merging main;
- merging PR #34 or any other PR;
- production key creation, provisioning, rotation, or signing ceremonies;
- live organizational reviewer designation;
- real-user or production memory ingestion;
- production policy activation;
- external audit/checkpoint services;
- vector/semantic memory dependencies;
- deployment, release, or production activation.

## 11. Review decisions requested

Owner and domain review should resolve:

1. Whether the G01 proof claims and binding rules are sufficient, including the authoritative source for reviewer principal-to-key binding.
2. Which canonical organization authority supplies the grantor's right to designate/revoke reviewers, and its version/revocation consistency guarantees.
3. Whether G02's proposed exact-tuple authorization and one-time proof consumption fit its policy lifecycle without introducing a parallel policy engine.
4. Whether G11 will adopt a separate versioned assurance-event envelope or a versioned event union, and the required durable-acknowledgment semantics.
5. The supported transaction/linearization model for delegation revocation versus G05 activation.
6. Whether any additional data-minimization, retention, or privacy constraints are required for the event envelope.

**No implementation should begin against unresolved authority semantics.**

---
Prepared as a reviewable proposal only. The Owner-approved G05 v1.0.0 contract and existing A3 implementation authorization remain unchanged.
