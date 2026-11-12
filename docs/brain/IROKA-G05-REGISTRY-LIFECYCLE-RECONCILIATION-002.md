# G05 Registry and Lifecycle Reconciliation — A3

- **Record:** IROKA-G05-REG-LIFE-RECON-002
- **Status:** CONTRACT RECONCILIATION RECORDED; SOURCE IMPLEMENTATION STILL PARTIAL
- **Target branch:** `feat/brain-a3-g05-g01-g02-g11-integration`
- **Reviewed integration head:** `60a8bc027f64b17aa35b4c6ce6e3af5cbe8f4a5d`
- **Controlling contracts:** Owner-approved `IROKA-G05-MEM-001 v1.0.0`; Owner-approved G05 integration decisions D1–D6 in `IROKA-G05-INT-001 v0.1.0`; G02 Owner-Governed Organization Authority Contract v0.1.0; G01 Reviewer-Proof Contract v0.1.0.
- **Scope:** Resolve competing A3 implementation variants and define a single contract-conformant integration direction. This record does not approve a new authority model, change the approved contracts, merge branches, or authorize production activation.

## 1. Controlling rules

The original G05 v1.0.0 contract prevails over the integration amendment. The amendment's D1–D6 decisions are binding where they add cross-domain constraints:

1. G01 alone authenticates reviewer principals, binds keys, verifies signatures and checks current credential/key revocation. G05 accepts only an opaque G01-verified proof result.
2. G02 is the sole canonical source for organization authority, designations, delegations and revocation. G05 MUST NOT create a competing organization-role or reviewer-designation authority.
3. G02 authorization must bind tenant, organization, reviewer, delegation ID/version, action, memory ID, record version, content digest, purpose and classification. Approval/proof consumption is one-time and replay-resistant.
4. G11 owns a separate, versioned, content-free memory-lifecycle event stream. Existing decision-audit compatibility must be preserved.
5. Every authority is revalidated at use. No cross-store atomicity may be claimed without evidence. Where ordering or required audit acknowledgment is unproven, G05 keeps the record non-active/pending.
6. Audit payloads exclude memory content, excerpts, prompts, embeddings, credentials and secrets; retention/deletion compatibility remains explicit.

## 2. Competing implementation findings

| Candidate | Useful implementation | Conflict or limitation | Disposition |
|---|---|---|---|
| PR #34 / `feat/brain-a3-b04-g05-memory-core` | G05 domain model, validation, lifecycle matrix, repository ports and original G05 v1.0.0 acceptance framing | Does not provide the complete G01/G02/G11 adapters; repository/persistence and service lifecycle remain partial | Retain as the domain-contract baseline |
| PR #43 / `feat/brain-a3-g05-g01-g02-g11-integration` | Typed signed-proof boundary, G01 verifier adapter, G05 metadata re-resolution, G11 memory event stream/outbox candidate | `g05_reviewer_designations` is a G05-owned authority table; the G02 adapter only maps global capabilities and organization-scope authorization defaults to DENY; the proof does not bind a G02 delegation ID/version | Retain compatible G01/G11 work only; do not treat its local designation table as canonical |
| PR #51 / `feat/a3-8-g05-verified-reviewer-integration` | Repository-backed immutable pending-approval envelope, canonical metadata/content checks, conditional one-time consumption and optimistic record-version preparation | Still requires authoritative G01 binding provider and canonical G02 organization authority; does not by itself resolve D2/D3 | Reuse the pending-approval lifecycle pattern after API reconciliation |
| PR #52 / `feat/g05-g01-reviewer-proof-integration` | G05 consumes opaque `VerifiedReviewerProof`; exact proof/record/designation comparison and one-time approval consumption | Its G05 designation persistence still needs to be replaced by G02 canonical resolution; test-only proof construction must remain test-only | Prefer opaque proof consumption semantics; do not copy its registry authority model |
| PR #50 / `feat/a3-8-g01-tenant-reconciliation` | G02 Owner-signed organization/designation/delegation commands and canonical Kernel security-store resolver | Resolver returns designation/delegation capability context but does not yet authorize the full G05 record tuple including record version, digest, purpose and classification; delegated administrator mutation signing is not implemented | Use as the G02 canonical-provider candidate; extend its G02-owned decision contract before G05 activation can rely on it |

## 3. Canonical ownership and data disposition

### G05 may own

- Memory records, content and metadata.
- Memory lifecycle state and optimistic record versions.
- User episodic-consent records and their purpose-bound grant/withdrawal history.
- Pending approval envelopes as immutable, record-bound G05 workflow data.
- A G05 outbox for G05 mutations, with stable event IDs and retry metadata.
- References to G02 organization/designation/delegation IDs and versions, and G01 proof IDs.

### G05 must not own

- Organization creation or tenant binding.
- Organization administrator roles, reviewer-role authority, delegation grants or revocation truth.
- Reviewer signing keys, issuer trust roots, identity bindings or key revocation state.
- G02 policy decisions or G11 audit acceptance.

The current `g05_reviewer_designations` table MUST NOT be treated as the authority source. It must be removed from the authoritative read/write path in the follow-on implementation. If a compatibility projection is temporarily retained for migration, it must be explicitly non-authoritative, rebuildable from G02, version-checked at every use, and incapable of granting access when G02 is unavailable. No migration may promote its rows into G02 authority.

The `g05_episodic_consents` table is different: purpose-specific user opt-in is a G05 memory-domain consent record, not an organization role. It may remain G05-owned, subject to the G05 v1.0.0 consent requirements, explicit user action, revocation and audit.

## 4. Selected integration sequence

The following is the single accepted reconciliation direction for A3 implementation:

1. **G05 candidate snapshot:** freeze tenant, subject, organization, memory ID, record version, content digest, purpose, classification and retention-policy reference from canonical G05 metadata.
2. **G01 identity/proof:** authenticate the reviewer and verify the signed approval proof; return an opaque `VerifiedReviewerProof`. The G01 result must bind the proof to current reviewer key/credential state and exact approval scope.
3. **G02 organization authority:** resolve the current Owner-governed organization designation/delegation. The G02 decision must bind the G01 reviewer principal, tenant, organization, designation/delegation ID and version, action, memory ID, record version, digest, purpose and classification. Global capability or tenant membership alone is insufficient.
4. **G05 approval workflow:** register the signed approval as an immutable pending envelope only after the appropriate G02 preflight; compare it to canonical G05 metadata before any content read; re-resolve G01/G02 authority at activation.
5. **G05 local atomicity:** conditionally consume the G05 approval against the exact record version and digest. G05's own approval consumption and its local outbox enqueue must be one transaction. G01 proof consumption remains a separate store unless a supported shared transaction is demonstrated; on partial failure the record remains non-active and a new proof may be required.
6. **G11 acknowledgment:** deliver the content-free, versioned lifecycle event at least once with stable event ID and canonical payload digest. G11 must deduplicate identical retries and reject same-ID/different-payload collisions.
7. **Activation:** do not expose `ACTIVE` merely because a G01 proof and G02 decision passed. Keep the record `PENDING_REVIEW` (or a separately represented non-active pending-audit workflow status) until the required G11 durable acknowledgment and final G05 version check are satisfied. Then atomically persist the ACTIVE transition with its G05 outbox/acknowledgment evidence.
8. **G09:** independently revalidate current identity, membership and policy before any later protected external effect.

## 5. Required code reconciliation

| File / surface | Required disposition |
|---|---|
| `crates/iroka-g05-memory/src/registry.rs` | Keep G05 consent and approval workflow persistence. Replace authoritative reviewer-designation CRUD and `active_designation` reads with a G02-owned resolver interface. Preserve latest-version/revocation fail-closed behavior by reading canonical G02 state on every privileged decision. |
| `crates/iroka-g05-memory/src/authority.rs` | Replace the current organization-scope boolean-style port with an exact, typed G02 decision request/result. The G02 adapter must not infer delegation from a global capability. |
| `crates/iroka-g05-memory/src/lib.rs` | Preserve G05 v1.0.0 record/lifecycle invariants and PR #51 repository-backed pending approval pattern. Bind G02 delegation ID/version and opaque G01 proof result into the approval flow. |
| `crates/iroka-kernel/src/organization_authority.rs` (G02-owned) | Extend the G02 resolver/decision contract to authorize the complete G05 activation tuple. The current `OrganizationContext`/`DelegationContext` capability lookup alone does not prove the record-specific D3 tuple. |
| `crates/iroka-kernel/src/reviewer_proof.rs` (G01-owned) | Reconcile the proof schema with the approved requirement for delegation ID/version and exact action. Preserve G01 ownership of signing bytes, issuer binding, revocation, proof validity and proof replay. |
| `crates/iroka-kernel/src/memory_audit.rs` and G05 outbox adapter | Preserve a distinct G11 memory event schema; add/verify canonical payload digest, durable acknowledgment, retry state and event-ID collision rejection. Never map memory lifecycle events into decision codes. |
| `MemoryRepository::replace_with_audit` | Require conditional expected-version update and atomic G05 outbox insertion. Add a separate pending-audit/acknowledgment step so a pending event cannot be mistaken for G11 acceptance or ACTIVE completion. |

## 6. Unresolved contract gaps — remain fail-closed

1. **G02 exact-tuple API:** PR #50's current resolver checks organization/delegation capability and freshness but its public decision does not accept memory ID, record version, content digest, purpose and classification. D3 is therefore not fully implemented.
2. **Delegation in G01 proof:** the current G01 proof schema binds designation ID/version but does not include the required G02 delegation ID/version. G01/G02 must agree on the authoritative tuple before the schema is changed.
3. **Reviewer designation semantics:** G02's Owner-signed organization designation is the canonical authority. G05 must not independently create a reviewer appointment. The exact capability vocabulary and mapping for reviewer approval/designation must be defined in G02.
4. **G11 completion gate:** the G05 pure activation-preparation function can produce an ACTIVE value before any G11 acknowledgment is represented. It must remain a preflight-only object or be redesigned so durable activation cannot be committed/exposed until acknowledgment is confirmed.
5. **Cross-store ordering:** G01 proof consumption, G02 authority resolution, G05 approval consumption and G11 acknowledgment are not one distributed transaction. The implementation must document linearization points and preserve non-active pending state whenever final ordering cannot be proven.
6. **Production adapters:** PR #50 and PR #43 are draft/unmerged branches; SQLite adapters are single-node. No production issuer, shared authority database, production key ceremony or independent A4 assurance is established by these code candidates.

No G05-local table, test fixture, global G02 capability, Owner approval substitution, caller assertion or stale cache may be used to close these gaps.

## 7. Acceptance and verification gates

The reconciliation is accepted as the implementation direction, not as code completion.

Before A3 integration can be marked complete:
- G05 v1.0.0 G05-AT-01..19 remain mandatory.
- G05-INT-AT-01..20 from the approved amendment remain mandatory.
- Add regressions proving that G05-local designation rows cannot grant authority; G02 missing/stale/revoked/unavailable denies; exact delegation/record tuple mismatch denies; pending G11 acknowledgment cannot activate; event retries are idempotent; and stale record versions cannot activate.
- Verify all changed Rust workspace targets with rustfmt, locked compile, no-default-features/production feature safeguard, complete tests and Clippy against the exact final commit.
- Conduct independent A4 security assurance separately.

## 8. Current disposition

- G05 v1.0.0 domain model and lifecycle invariants: **RETAIN**.
- G05-local reviewer designation table as authority: **REJECT — CONTRARY TO D2**.
- PR #50 G02 organization authority: **CANONICAL PROVIDER CANDIDATE; D3 EXTENSION REQUIRED**.
- PR #43 G01 proof verifier and G11 lifecycle stream: **RETAIN AS CANDIDATES; INTEGRATION GAPS OPEN**.
- PR #51 repository-backed pending approval pattern: **PREFERRED WORKFLOW PATTERN; RECONCILE WITH CURRENT TYPES**.
- PR #52 opaque verified-proof boundary: **PREFERRED G01/G05 TRUST BOUNDARY**.
- Full G05 registry/lifecycle integration: **PARTIAL / NOT VERIFIED**.
- A4 independent security assurance: **NOT RUN**.
- Merge, production keys, activation and A5 deployment: **NOT AUTHORIZED**.

This record preserves the Owner-approved G05 and G01/G02/G11 decisions. It records no new authority grant and does not reopen the closed A1/A2 baselines.
