# G01–G02 Kernel Authority Boundary

**Status:** A3 implementation boundary; production activation remains separately gated.

## Canonical ownership

- **G01 — Identity and trust:** authenticates principals, verifies credentials and trust state, and owns the verified principal plus current tenant/membership context. A caller-supplied subject, tenant ID, role, or membership version is a selector or claim, never proof.
- **G02 — Governance and policy:** owns Owner authority, organization/tenant governance policy, approval records, capability policy, signed policy snapshots, policy activation/revocation, and emergency stop. G02 may authorize a membership mutation through a signed, scoped Owner command, but it does not authenticate a principal or mint G01 identity/tenant-context evidence.
- **G11 — Assurance:** owns durable audit/evidence recording. A decision is not complete if its required audit append fails.
- **G09 — Execution:** independently revalidates current authority and policy before a protected effect. A Kernel ALLOW decision is not an execution grant.

## Required decision flow

1. G01 verifies the credential and resolves the requested tenant against the current membership ledger. The tenant selector alone cannot establish membership.
2. G02 validates Owner authority, one-time approval scope, signed policy snapshot, monotonic policy epoch, revocation, and emergency-stop state.
3. The Kernel composes those verified inputs into a bounded authorization decision.
4. G11 records the decision with tenant, membership-version, policy-version, and correlation context.
5. G09 revalidates current membership and active policy immediately before any protected effect.

## Prohibited ownership crossings

- G02 must not issue or fabricate principal identity, reviewer identity, credential proof, or G01 tenant-context evidence.
- G01 must not create Owner authority, policy approvals, capability policy, or policy activation decisions.
- Brain/model/agent output, request fields, and retrieved documents cannot create or elevate authority.
- No domain may treat a successful decision as a durable execution grant.

## Implementation and deployment limits

The current Kernel composition uses a local SQLite security store and a global active policy snapshot. SQLite is single-node only; multi-node production requires a shared transactional adapter with equivalent uniqueness, ordering, revocation, and fail-closed semantics. Tenant-specific policy partitioning, production key custody, G09 execution integration, and external/durable G11 anchoring remain separate gates. This A3 slice does not authorize production activation or deployment.
