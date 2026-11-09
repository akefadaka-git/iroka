# G05 A3 B04 — Implementation Record

- Contract: `IROKA-G05-MEM-001` v1.0.0 (Owner-approved)
- Stage: A3 implementation
- Status: PARTIAL — domain core and fail-closed primitives implemented; production adapters are not.
- Base: G04 adapter branch `feat/brain-a3-b03-g04-contract-adapter`, commit `4e0c954516b4a471e2f36760b665add0a98efe9f`
- Branch: `feat/brain-a3-b04-g05-memory-core`

## Implemented

The new `iroka-g05-memory` Rust workspace crate provides:

- Versioned G05 record, provenance, approval receipt, access context, lifecycle, operation and content-free audit-event types.
- Canonical SHA-256 content integrity validation.
- Bounded working-memory expiry validation using explicit caller-supplied policy limits; no deployment TTL defaults are invented.
- Episodic expiry validation using explicit policy limits; retention periods remain a deployment-policy decision.
- Episodic opt-in reference requirement.
- Rejection of Restricted-classification working memory.
- Gated candidate preparation: working/episodic records activate only after G02 authorization and episodic opt-in verification; durable records enter PENDING_REVIEW.
- Durable activation preparation increments the record version and requires a record-bound approval receipt, G02 authorization and trusted designated-reviewer verification.
- Approval binding to exact memory ID, tenant, subject and content digest, with issue/expiry checks.
- Explicit default-deny cross-principal sharing validation and tenant-scope checks.
- A lifecycle transition matrix that does not permit direct or implicit durable activation.
- Governance and repository adapter traits documenting G01/tenant/G02/reviewer/G11 boundaries and authorization-before-content-access requirements.
- Durable activation preflight delegates cryptographic approval and designated-reviewer verification to the trusted governance port; reviewer authority is resolved by that adapter rather than a caller-supplied organizational flag.
- Two-phase retrieval authorization: G02 preflight before metadata lookup, then authorization against stored tenant/subject/purpose/classification/state/expiry before content access.
- Metadata-only repository return type excludes content; mutation repository methods require an atomic G11 outbox event.
- Episodic capture preflight verifies opt-in through the trusted governance port; an opt-in reference alone is not treated as consent.
- Synthetic unit tests for the core invariants.

The crate deliberately does not implement identity verification, tenant resolution, policy evaluation, cryptographic reviewer verification, G11 audit storage, or a production persistence provider.

## Contract decisions enforced in code

| Decision | Implementation evidence |
|---|---|
| D1 — explicit approval for every durable record | durable activation binding validator; no direct Proposed/PendingReview → Active transition |
| D2 — episodic opt-in | episodic candidates require an opt-in reference |
| D3 — personal inspect/deletion rights | logical operation types and repository boundary; service workflow remains pending |
| D4 — designated human reviewer | approval-verification port receives durable receipt and organizational scope; concrete reviewer authority adapter pending |
| D5 — defer semantic/vector retrieval | no embedding, vector database, or semantic index dependency added |
| D6 — default-deny sharing | explicit policy authorization required by sharing validator |
| D7 — no Restricted working memory | validator rejects it |

## Explicit A3 gaps

1. No concrete adapter yet binds the G05 governance port to the existing G01 → tenant authority → G02 composition path. This must reuse the canonical Kernel composition and must not introduce a second authorization engine.
2. No concrete designated-reviewer signature/authority verifier. The verifier must consume the approved G02/Owner authority model; G05 must not invent a parallel trust root.
3. No persistent G05 repository or schema migration. Storage encryption, key ownership, transactional versioning, backup handling, retention and deletion semantics need a verified design before content persistence.
4. No atomic G11 outbox/transaction adapter. A G05 mutation cannot be reported complete until its required audit guarantee is met.
5. Personal inspection, correction, deletion, retention holds, expiry workers, idempotency and recovery workflows are not yet implemented.
6. No production source ingestion or real-user data is permitted in this stage.
7. The code has not yet passed exact-HEAD CI; A4 security review is not run. The crate currently contains 15 synthetic unit tests.


## Existing Kernel integration reconciliation

Read-only inspection of the stacked B03 base confirmed these integration constraints:

- `iroka-kernel::authorize_compact_in_tenant` composes compact G01 credential verification, IROKA-owned tenant membership, the active global G02 policy, optional Owner approval and G11 decision audit. It returns a decision, not a reusable G05 authorization capability.
- The Kernel `AuthorizationRequest` is a narrow subject/capability/resource/risk envelope. The G05 adapter must map each memory operation to an explicit capability and must not trust caller-supplied principal or tenant values.
- The Kernel's current G11 `AuditSink` and `AuditEvent` represent authorization decisions. They do not yet define the versioned memory lifecycle event schema required by this contract. G05 memory events must not be misrepresented as authorization decisions.
- The inspected Kernel API does not provide a G05 episodic opt-in registry or a designated organizational human-reviewer registry. These cannot be fabricated inside G05 or replaced with a boolean supplied by the caller.
- The existing tenant membership resolver is backed by the Owner-governed security store and returns immutable tenant context. G05 must consume this authority rather than create a parallel membership table.

Therefore, the new G05 traits remain explicit integration ports. A concrete production adapter is blocked until the G05 consent/reviewer authority and versioned G11 event extension are defined and wired to trusted services. This is an intentional fail-closed boundary, not a claim that production integration is complete.

## Required next work

- Compile and test the exact branch head with the repository's locked workspace CI matrix.
- Fix all compiler, test, formatting and Clippy failures.
- Inspect current G01/G02/G11 public integration surfaces on the stacked base and implement only adapters that can be safely composed without weakening their authority.
- Add transactional persistence only after encryption/key-management and deletion/backup semantics are specified and verified.
- Add tests for authorization-before-content-access, reviewer designation, audit failure, tenant isolation, opt-in revocation, deletion/resurrection, concurrency and idempotency.
- Keep PR draft and unmerged. A4 and A5 remain separate gates.

## Safety statement

This is a non-production domain core. It is not a memory service, secure database, consent authority, authorization engine, or deployment-ready capability. No real-user memory was ingested. No merge, signing, release, deployment, or production activation is authorized by this record.


## Trusted consent and designated-reviewer authority integration

The A3 authority boundary is now represented by `src/authority.rs` and exported by the G05 crate:

- `G02AuthorizationAuthority`: delegates every G05 authorization to the canonical G01 -> tenant -> G02 composition. It may not trust caller-supplied identity or tenant context.
- `EpisodicConsentAuthority`: resolves an opaque consent reference in the authoritative consent store and verifies exact tenant, subject, purpose, opt-in state, effective interval, revocation and integrity at operation time. Consent is purpose-specific. Missing, expired, withdrawn, revoked, mismatched or unavailable consent denies capture.
- `DesignatedReviewerAuthority`: resolves the current reviewer designation for the organizational subject and verifies the approval proof against a separately provisioned trust root. It must bind reviewer, organization, tenant, subject, memory ID, content digest, issue/expiry interval, revocation and replay state. An Owner approval does not by itself establish organizational reviewer designation.
- `G11MemoryAuditAuthority`: delegates versioned, content-free memory lifecycle events to G11. Atomicity with memory mutation remains the repository transaction/outbox responsibility.
- `TrustedGovernanceAdapter<G,C,R,A>`: composes all four required providers into the existing G05 `GovernancePort`; it creates no local trust root, registry, policy or authority.

The current durable receipt's `subject_ref` is treated as the organization scope passed to the reviewer authority. The reviewer provider must independently resolve and validate that scope; it must not accept the receipt's reviewer claim as designation evidence.

### Integration status and blockers

- The adapter and fail-closed unit tests are implemented.
- The canonical Kernel exposes the G01/tenant/G02 composition, but its current composition function is not yet exposed as a reusable G05 authorization provider. A concrete adapter must be added at the Kernel composition boundary rather than duplicating authorization logic inside G05.
- No authoritative episodic consent registry or opt-in/revocation API was found in the inspected base.
- No authoritative organizational reviewer designation registry, signed reviewer-approval format, key lifecycle, or replay/revocation store was found in the inspected base.
- No versioned G11 memory-lifecycle event contract/outbox implementation is yet available.
- Therefore the new interfaces are integration-ready contracts, not live trusted providers. Production construction must remain unavailable until all provider implementations are backed by their canonical authorities and are independently tested. Test doubles are not production authorities.
- No new trust root, production key, real consent record, reviewer identity, or user data was provisioned.

### Acceptance evidence added

- A missing/revoked episodic consent provider response is propagated as a denial.
- An undesignated reviewer provider response is propagated as a denial.
- Full exact-HEAD formatting, compilation, workspace tests, no-default-features checks and Clippy remain NOT RUN for the resulting commit until CI evidence is collected.


## B04 authoritative consent and designated-reviewer registries

The implementation now includes a G05-owned SQLite authority registry in `crates/iroka-g05-memory/src/registry.rs`, integrated through the G01/G02/G11 ports.

### Episodic consent
- Grant requires a G01 `VerifiedPrincipal` and Kernel `TenantContext`; subject and tenant are derived from those opaque verified objects, not caller-provided identity fields.
- The grant operation is an explicit authenticated action and is G02-authorized with a purpose-bound capability/resource request.
- Expiry is bounded by an explicit server-supplied maximum TTL; there is no hidden default.
- Consent references are unique and immutable; withdrawal is self-only, permanent for that record, versioned, and audited through the G05 outbox.
- Retrieval of consent checks exact consent reference, tenant, subject, purpose, granted-at/expiry interval and revocation on every verification.

### Organizational reviewer designation
- Designation/revocation requires G02 capability authorization AND an organization-scoped G02 delegation check. The latter defaults to DENY; a global capability alone cannot make an actor an organization administrator.
- The target reviewer/key binding is checked by a G01-owned provider before designation. The registry stores organization, tenant, reviewer, key reference, designation version and validity interval.
- Durable approval checks current designation, exact organization/tenant/reviewer, approval validity within designation validity, and a G01 proof-verification provider. Approval references are consumed once in a transaction that rechecks designation state, so a designation revocation that commits first blocks consumption.
- Replay, missing designation, expired/revoked designation, wrong tenant/organization/reviewer, invalid proof and out-of-window approval fail closed.

### G02/G11 integration
- `KernelG02AuthorizationAdapter` maps G05 operations to explicit G02 capabilities and invokes the canonical Kernel G01 -> tenant -> G02 -> G11 decision composition using server-side credential/session dependencies. It checks that the request tenant matches the server-resolved tenant selector. Any non-ALLOW decision is denied.
- The adapter intentionally does not grant organization-scoped reviewer-management authority. The Kernel's current G02 policy is global capability-based and has no organization delegation registry; the new organization-scope hook therefore defaults to DENY until that canonical G02 authority is implemented.
- Consent and reviewer changes plus approval consumption enqueue content-free G05 authority events in the same SQLite transaction as the mutation. `drain_g11_outbox` retries delivery and marks an event delivered only after G11 accepts it. G11 must deduplicate event IDs.
- G05 authority events use a new event family (`memory.consent.*`, `memory.reviewer.*`). G11's versioned event-schema extension/production sink acceptance remains a separately verified integration dependency.

### Tests added (synthetic only)
- Consent missing, wrong tenant, wrong subject, wrong purpose, expiry and withdrawal/revocation.
- Reviewer replay, wrong tenant, wrong organization, wrong reviewer, invalid proof, proof retry after failed verification, designation expiry/revocation and approval validity outside designation window.
- End-to-end composition of SQLite consent + reviewer registries through `TrustedGovernanceAdapter`.
- G02 global capability without organization delegation is denied.
- G11 outbox retries after sink failure, then marks successful delivery and does not redeliver.
- No real user identity, consent, reviewer, key or memory content was provisioned.

### Explicit unresolved production dependencies
- A concrete G01 reviewer-proof provider must verify reviewer identity/key binding, proof signature, exact receipt claims and current key/credential revocation. The registry deliberately does not create or trust its own reviewer keys.
- A canonical G02 organization-delegation registry/provider is absent. Reviewer designation and revocation therefore remain fail-closed under the concrete Kernel adapter until this is implemented.
- G11 must approve/implement the versioned G05 authority event extension and idempotent sink adapter before outbox delivery can be considered production-ready.
- SQLite registry is single-node only. Multi-node deployments require a shared transactional store with equivalent isolation, uniqueness and revocation semantics.
- G02 authorization and G05 SQLite mutation are separate database transactions. The adapter authorizes immediately before mutation, but cross-store atomic policy revocation is not yet guaranteed; this remains a security review item.
- Exact-HEAD CI and independent A4 security review have not yet been run.
