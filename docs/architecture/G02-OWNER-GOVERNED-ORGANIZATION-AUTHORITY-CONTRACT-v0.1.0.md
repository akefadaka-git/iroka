# G02 Owner-Governed Organization Authority Contract

**Document ID:** IROKA-G02-ORG-AUTHORITY-001  
**Version:** 0.1.0  
**Status:** A3 implementation contract — Owner model selected; implementation and verification pending  
**Programme:** IROKA Ethical Intelligence and Human-Flourishing Programme  
**Canonical authority owner:** G02 Governance  
**Selected model:** A — Owner-governed authority  
**Decision date:** 2026-11-10

## 1. Owner decision and scope

The Owner selected model A: IROKA's organization authority is governed directly through G02. The Owner is the sole root authority for organization creation and for initial appointment, delegation and revocation of organization-scoped administrators. This contract implements that decision within A3.8; it does not reopen A1 or A2.

G02 is the sole canonical source of organization authority. A request field, tenant selector, self-asserted role, G01 credential, G05 memory record, or G11 audit event cannot create or prove an organization role.

## 2. Chromosome ownership

- **G01 Identity:** authenticates the principal and verifies credential/key trust and revocation. G01 does not decide organization roles.
- **G02 Governance:** validates Owner-signed organization commands, owns the canonical organization/delegation state and resolves current scoped authority.
- **G05 Memory:** consumes a G02 decision for memory consent/reviewer gates; it must not maintain a second organization-role registry.
- **G11 Assurance:** records governance/lifecycle evidence through its own contracts. Audit evidence is not itself an authorization grant.

## 3. Governed records

The G02 authority provider must support the following versioned, Owner-signed actions:

1. Create an organization with a stable organization ID and immutable tenant binding.
2. Set or replace a principal's organization-scoped designation with explicit role/capability scope.
3. Revoke a designation (revocation is explicit; no implicit expiry extension).
4. Suspend or reactivate an organization under a new Owner-signed versioned command.

Every command binds: command ID, Owner subject, Owner key ID, issued-at, expires-at, organization ID, tenant ID, target principal where applicable, action, designation ID, monotonically increasing version, explicit capabilities/scope, and non-empty reason. Canonical signing bytes use a dedicated G02 domain separator and deterministic serialization. Unknown fields/actions are rejected.

No organization or designation is created by a user request, tenant selector, membership record, model inference, or an administrator appointing another administrator unless a separately verified Owner-signed delegation explicitly grants that exact subdelegation capability. Default is no subdelegation.

## 4. Resolution contract

Authorization resolution requires a G01-verified principal and an exact request tuple: tenant, organization, principal, action/capability, designation version and current time. The resolver must read the canonical G02 store on each privileged decision (or use a cache with an explicitly bounded freshness contract and revocation invalidation). It returns an immutable verified organization context only when:

- the organization exists and is active;
- its tenant binding matches the verified tenant context;
- the principal has an active designation for that organization;
- the requested capability is explicitly included in the designation;
- the record is current, not stale or future-dated, and its version has not rolled back;
- the Owner signing key and command have valid signature, validity and non-revoked status;
- the store is available and consistency requirements are met.

Missing, malformed, stale, revoked, conflicting, unavailable, or scope-mismatched state denies authorization. Caller-supplied role labels are never trusted.

## 5. Persistence and consistency

The initial SQLite adapter is a single-node implementation/test adapter only. It must use transactions, unique command IDs, version monotonicity, immutable command digests, and atomic command-consumption plus state mutation. Replaying an identical command is idempotent only if explicitly specified; conflicting reuse is rejected. A lower version is rejected; same-version different content is a conflict.

No multi-node, distributed transaction, cross-store atomicity or production durability claim is made. A shared transactional adapter with equivalent linearization and revocation guarantees is required before multi-node production use. No production key ceremony or key material is included in A3.

## 6. Security and adversarial test requirements

Tests must prove:
- no authority exists before an Owner-signed organization command;
- invalid signature, unknown/revoked Owner key, expired/future command and malformed fields fail closed;
- wrong tenant, organization, principal, capability or designation version is denied;
- caller-forged roles and tenant selectors cannot grant authority;
- organization suspension and designation revocation take effect;
- version rollback and same-version conflicting content are rejected;
- command replay and command-ID collision are rejected safely;
- a revoked Owner key cannot issue a subsequent organization command;
- store failure, stale state and inconsistent state deny;
- organization authority cannot be inferred from G01 authentication or G01 tenant membership alone;
- G05 cannot grant or retain organization authority when G02 is absent/unavailable;
- G11 evidence failure does not produce a positive authorization result where audit is mandatory.

## 7. Explicit exclusions and stop conditions

This contract does not authorize production Owner-key provisioning, live organization onboarding, real user/community data, autonomous delegation, G05 memory activation, protected execution, training, genome mutation, merge, deployment or A5 activation. No default Owner key or private key is embedded in code. Production authority remains unavailable until a separately governed key ceremony, protected key allowlist, operational storage adapter and independent A4 security review are complete.

G01 reviewer-proof verification remains a separate A3.8 blocker. G05/G11 PR #43 remains an unmerged candidate and is not treated as an integrated dependency by this contract.

## 8. Exit status

This is the selected-model implementation contract. It is not evidence that the provider is implemented or verified. A3.8 remains PARTIAL until the G01 reviewer-proof provider, G02 organization-authority provider, reconciled G05/G11 adapter and cross-domain adversarial verification meet the A3.8 exit criteria. A4 and A5 remain separate gates.
