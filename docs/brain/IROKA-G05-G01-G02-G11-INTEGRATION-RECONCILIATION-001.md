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

### Implemented G01/G05 integration candidate

The integration branch now carries the G01 proof verifier in `crates/iroka-kernel/src/reviewer_proof.rs` and exports the typed `SignedReviewerProof` / `VerifiedReviewerProof` boundary. The proof is Ed25519-signed over deterministic JCS bytes under the dedicated NUL-terminated G01 domain. It binds issuer, subject, credential, reviewer, key, approval, tenant, organization, designation ID/version, memory ID, record version, content digest, purpose, classification, capability, resource and policy version. G01 rechecks current key and credential revocation, binding freshness, validity, exact scope and proof replay.

G05's `G01ReviewerProofAuthority` now accepts the typed signed proof, G01-minted `VerifiedPrincipal`, current designation, receipt and candidate record, and returns `VerifiedReviewerProof`. The concrete `KernelG01ReviewerProofAdapter` delegates cryptographic verification to the Kernel verifier. G05 then independently compares the verified result to its own approval and record fields.

G05 no longer treats `proof_ref` as proof: `DurableApprovalReceipt` carries the typed signed envelope and requires `proof_ref == payload.proof_id`; receipt issue/expiry times must equal the signed values. Durable activation requires the verified reviewer principal, and the principal subject must equal the designated reviewer.

Before cryptographic verification, G05 re-resolves the current active designation from its canonical designation registry. It also re-resolves current memory metadata through `CanonicalMemoryMetadataResolver` (blanket-adapted from the `MemoryRepository::get_metadata` port) and compares memory ID, tenant, subject, class, digest, purpose, classification, lifecycle state, record version, expiry and retention policy with the record being activated. The supplied record content is re-hashed against its digest.

After proof verification, G05 rechecks designation currency inside an immediate SQLite transaction and inserts the approval ID into a primary-key-protected consumed-approval table. The consumption record and G05 authority outbox event commit in the same transaction. Duplicate approval use returns `ApprovalReplay`. G01 proof-ID replay is separately rejected by the Kernel security store.

### Remaining trust boundary

The code defines the production adapter contracts but does not provision the issuer-side authoritative reviewer-key binding service or the designation-time reviewer identity/key resolver. A production G05 repository must implement `MemoryRepository` against the canonical store; no in-memory or caller-authored metadata is accepted as canonical by the reviewer authority. The SQLite adapters remain single-node only. Cross-store G01-proof and G05-approval consumption is fail-closed but is not a distributed transaction: if G01 consumes a proof and a later G05 transaction fails, the proof cannot be retried with the same proof ID. No G05-local trust roots or reviewer keys are introduced.

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
- strict schema/version, event namespace, field-size and required-field validation, including rejection of whitespace/control characters in opaque-reference fields;
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
| G01 cryptographic reviewer-proof verifier | **IMPLEMENTED — CI PASS #42957771604; production issuer adapter pending** |
| G05 typed proof adapter and verified-principal binding | **IMPLEMENTED — CI PASS #42957771604** |
| G05 current designation + canonical memory metadata re-resolution | **IMPLEMENTED — CI PASS #42957771604; production repository provisioning pending** |
| G05 exactly-once approval consumption + outbox transaction | **IMPLEMENTED — exact-head CI pending** |
| G02 Owner policy and tenant authority | **RECONCILED** |
| G02 canonical organization-delegation provider | **MISSING — fail-closed** |
| G02 exact delegation tuple enforcement | **MISSING — fail-closed** |
| G11 separate versioned memory event stream | **IMPLEMENTED IN THIS BRANCH — CI pending** |
| G11 content-free adapter and idempotent delivery contract | **IMPLEMENTED IN THIS BRANCH — CI pending** |
| Cross-domain atomicity / multi-node | **NOT IMPLEMENTED** |
| Independent A4 security assurance | **NOT RUN** |
| A5 deployment | **NOT AUTHORIZED** |

No missing authority is replaced with a G05-local registry, test stub, caller-supplied assertion or Owner approval. The two missing provider integrations are explicit dependency blockers, not reasons to hold up the independent G11 implementation.


### Exact-head verification evidence — 2026-11-11

The combined G01/G05/G11 integration candidate at `444901f36f03a4444174a0e3e4a09bf2be3d2a6a` passed GitHub Actions [run #42957771604](https://github.com/akefadaka-git/iroka/actions/runs/42957771604): formatting PASS, workspace/all-target compilation PASS, production feature-set safeguard PASS, **140 tests passed / 0 failed**, and Clippy PASS. The run covers the exact current implementation head; subsequent documentation-only updates do not change the tested code.

This is kernel/G05 integration verification, not production trust-adapter provisioning or independent A4 assurance. PR #43 remains draft and unmerged.
