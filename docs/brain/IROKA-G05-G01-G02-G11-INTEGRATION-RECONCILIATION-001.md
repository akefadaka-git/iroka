# IROKA G05 G01/G02/G11 Integration Reconciliation and A3 Record

- **Record:** IROKA-G05-INT-RECON-001
- **Status:** G11 adapter implemented; G01 and G02 authority-provider dependencies remain fail-closed
- **Baseline:** G05 A3 candidate `2b5cbbd2e74308286547890d993820a5beeca329`
- **Owner decisions:** D1–D6 approved 2026-11-10 in PR #42
- **Scope:** isolated A3 integration increment; no merge, production activation, key provisioning or deployment

## 1. G01 reviewer identity and proof

### Existing authoritative capability

At the G05 A3 base, `crates/iroka-kernel/src/identity_crypto.rs` provides `Ed25519CredentialVerifier`, `TrustStore`, and `RevocationChecker`. The credential verifier validates compact-JWS Ed25519 credentials against trusted issuer/key snapshots, exact audience, credential validity, and current credential/key revocation. Revocation-provider errors fail closed. `VerifiedPrincipal` is minted only after successful verification.

### Exact gap

G05's `G01ReviewerProofAuthority` port in `crates/iroka-g05-memory/src/registry.rs` is an interface only. No concrete G01-owned implementation was found that:
- validates a reviewer principal-to-signing-key binding for a current designation;
- verifies a signed approval proof with canonical signing bytes and domain separation;
- binds the proof to tenant, organization, reviewer, designation version, memory ID, record version, content digest, purpose and classification; and
- rechecks current signing-key/credential revocation at proof use.

The existing G01 credential proves authenticated identity; it is not itself proof that a human approved a specific memory record. G02 Owner approvals are Owner-level approvals and are not interchangeable with organization reviewer proofs.

### Disposition

Reuse G01's existing credential and revocation primitives. The proof envelope, canonical bytes, signing domain, current key binding and proof verifier must be implemented and owned by G01. G05 retains only the opaque proof reference and exact scope binding. Until the G01-owned verifier exists, durable reviewer approval remains denied. No G05-local trust roots, reviewer keys or proof cryptography are introduced.

## 2. G02 organization authority and exact-tuple authorization

### Existing authoritative capability

G02 has Owner-signed policy snapshots, Owner-signed security commands, replay-protected Owner approval, and IROKA-owned tenant membership in the Kernel security store. The tenant membership resolver creates opaque `TenantContext` from a verified G01 principal and server-side membership state.

### Exact gap

The inspected Kernel security store contains tenant membership and revocation/policy state, but no canonical organization-delegation registry. `OwnerSecurityAction` has no organization-delegation designation/revocation action. `KernelG02AuthorizationAdapter` implements global G05 capability authorization but does not implement organization-scoped delegation. G05's `G02AuthorizationAuthority::authorize_organization_scope` therefore defaults to DENY.

The current G05 operation request binds tenant, organization subject, actor, operation, purpose, classification and recipient selector into a G02 resource. It does not carry a canonical delegation ID/version and cannot independently prove that the actor holds a current organization-scoped delegation. A global capability or tenant membership is not an organization role.

### Disposition

G02 must resolve an independently governed organization-authority source and authorize a versioned delegation tuple. The tuple must bind tenant, organization, actor, delegation ID/version, action, reviewer, and—when approving a memory—memory ID, record version, content digest, purpose and classification. G02 must revalidate current delegation/revocation at use and provide a documented consistency/linearization guarantee. The canonical source/provider and its governance owner are not identified by the current repository evidence; no provider is invented in this increment. Designation, revocation and organizational durable activation remain default-deny.

## 3. G11 memory lifecycle assurance

### Existing authoritative capability

G11's existing `AuditEvent` and `SqliteAuditSink` form an append-only, hash-chained decision audit stream. Its decision schema includes decision codes and is intentionally not repurposed for memory lifecycle events.

### Implemented supported integration

This branch adds:
- `iroka_kernel::MemoryLifecycleEvent`, schema ID `iroka.g11.memory-lifecycle-event`, version 1;
- a distinct `g11_memory_lifecycle_events` append-only table and independent SHA-256 event chain;
- stable event-ID idempotency; identical retries succeed, conflicting payload reuse is rejected;
- strict schema/version, event namespace, field-size and required-field validation;
- a G05 `KernelG11MemoryAuditAdapter` that converts committed G05 outbox events to the G11-owned versioned schema;
- deliberate omission of the G05 content digest from the G11 payload to reduce dictionary/fingerprinting leakage; and
- adversarial tests for idempotent retry, event-ID collision, unknown schema, invalid event namespace, missing/oversized opaque references and content-free serialization.

The new stream does not change or overload G11 decision-event compatibility. The G05 outbox remains the transaction boundary for G05-local authority mutation; G11 delivery is retried idempotently. This does **not** create cross-database atomicity.

## 4. Transaction and deployment limits

- G05 authority mutation and G11 append are coordinated by a durable G05 outbox, not a distributed transaction.
- A crash after G11 append and before G05 delivery marking is recovered by idempotent event replay.
- G02 policy/delegation revocation and G05 mutation are not one cross-domain transaction. G05 must remain pending/non-active when authority freshness or ordering cannot be established.
- SQLite adapters are single-node; no multi-node consistency claim is made.
- Production key custody, live organization-authority provisioning, real-user memory, production retention/legal-hold operations, independent A4 review and A5 deployment remain outside this increment.

## 5. A3 acceptance disposition

| Area | Result |
|---|---|
| G01 existing credential/revocation primitives | **RECONCILED** |
| G01 reviewer-proof verifier | **MISSING — fail-closed** |
| G02 Owner policy and tenant authority | **RECONCILED** |
| G02 canonical organization-delegation provider | **MISSING — fail-closed** |
| G02 exact delegation tuple enforcement | **MISSING — fail-closed** |
| G11 separate versioned memory event stream | **IMPLEMENTED IN THIS BRANCH — CI pending** |
| G11 content-free adapter and idempotent delivery contract | **IMPLEMENTED IN THIS BRANCH — CI pending** |
| Cross-domain atomicity / multi-node | **NOT IMPLEMENTED** |
| Independent A4 security assurance | **NOT RUN** |
| A5 deployment | **NOT AUTHORIZED** |

No missing authority is replaced with a G05-local registry, test stub, caller-supplied assertion or Owner approval. The two missing provider integrations are explicit dependency blockers, not reasons to hold up the independent G11 implementation.
