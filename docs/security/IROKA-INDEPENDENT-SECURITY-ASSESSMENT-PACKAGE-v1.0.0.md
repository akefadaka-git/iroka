# IROKA Independent Security Assessment Package v1.0.0

**Status:** REVIEW PACKAGE PREPARED — INDEPENDENT ASSESSMENT NOT STARTED  
**Target:** IROKA ZERO security implementation, G01/G02/G09/G11 and A3.10.3/A3.10.5  
**Review authority:** Independent third-party assessor; appointment and acceptance remain Owner-controlled

## 1. Purpose

This package defines the evidence, scope, independence conditions, methods and acceptance criteria for an external security assessment. It is not an assessment report, certification, penetration-test result or substitute for an independent reviewer.

The implementation author and repository owner must not self-approve this workstream as independently assessed.

## 2. Independence and reviewer eligibility

The assessor must:
- Be a named individual or organization with demonstrable application-security, cryptographic-protocol and secure-build expertise.
- Have no authorship or implementation responsibility for the reviewed changes.
- Disclose employment, financial, family, advisory and other conflicts relevant to the Owner, repository and implementation contributors.
- Have no authority to modify production trust roots, production credentials or runtime systems as a condition of review.
- Receive a frozen commit SHA and read-only access to source, CI evidence and relevant contracts.
- Sign or otherwise authenticate the final report and identify the exact commit and evidence reviewed.

The Owner appoints the reviewer and accepts the scope. No reviewer has been appointed through this package.

## 3. Review scope

### A. Identity, Owner authority and trust roots
- Trust-root enrollment, purpose separation, validity, rotation overlap, revocation and anti-rollback.
- Owner approval and security-command signature domains, canonicalization, replay protection and transaction atomicity.
- Persistent trust-state writes, concurrency, failure handling and snapshot publication.

### B. Audit integrity and external checkpoints
- Audit-chain construction, verified head and prefix snapshot consistency.
- Checkpoint signer separation, domain-separated signatures and canonical serialization.
- Witness receipt binding, identity/key uniqueness, quorum enforcement, monotonic acceptance and idempotent retry.
- SQLite witness ledger transactionality, append-only triggers, crash/restart behavior and storage failure modes.
- HTTPS/mTLS client endpoint validation, certificate and private-key handling, curl invocation, proxy/config isolation, timeouts and response bounds.
- Recovery, rollback, fork detection and external reconciliation.

### C. Protected execution (G09)
- Exact-operation authorization binding, approval requirements, nonce lifetime, replay/revocation race handling and audit-before-effect ordering.
- Executor identity, result verification, idempotency and ambiguous outcome handling.
- Failure injection and fail-closed behavior.

### D. Supply chain and CI
- Cargo lock integrity, advisory and license/source policies, duplicate dependency disposition and MSRV.
- Gitleaks full-history scanning and workflow permissions.
- SPDX 2.3 generator correctness and dependency completeness.
- Action pinning, release trigger conditions, OIDC/Sigstore permissions, artifact provenance and SBOM attestation.
- Release artifact identity, reproducibility limitations and verification procedure.

### E. Deployment boundary
- Whether the current repository produces a deployable runtime artifact.
- Configuration, secrets, key custody, witness operator independence, recovery and operational monitoring gaps.
- A5 readiness controls and any unsafe assumptions in the proposed deployment path.

## 4. Minimum adversarial test plan

The assessor should independently reproduce and/or add tests for:
1. Trust bundle tampering, wrong root, duplicate key IDs/public keys, expired/not-yet-valid roots, invalid overlap, rollback and concurrent installation.
2. Owner signer revocation racing command consumption; duplicate command IDs; crash/failure rollback.
3. Checkpoint tampering, wrong stream, invalid signer, receipt substitution, duplicate witness identity/key, insufficient quorum and stale receipt.
4. Witness replay, conflicting same-sequence content, sequence gap/regression, predecessor mismatch, exact retry and restart persistence.
5. SQLite update/delete trigger bypass attempts, disk-full, busy-lock exhaustion, interrupted commit and database corruption.
6. Audit prefix fork, local-behind-anchor, local-ahead-unanchored and recovery from independently retained evidence.
7. HTTPS endpoint downgrade, malformed endpoint, TLS trust failure, mTLS failure, path/symlink/permission attacks, oversized response, timeout, proxy injection and command argument injection.
8. G09 operation substitution, grant replay, expiry, revocation race, audit failure, executor key revocation and ambiguous execution outcome.
9. Dependency advisory regression, lockfile drift, license/source violation, secret introduced in current tree or Git history, SBOM package/relationship omission and attestation subject mismatch.
10. Release workflow execution only from a published release tag and absence of deployment side effects.

## 5. Required report format

The report must include:
- Assessor identity, qualifications, independence statement and conflict disclosures.
- Exact commit SHA, branch, file/blob scope and exclusions.
- Date, environment, tools and versions, commands, test cases and raw evidence references.
- Findings with severity, affected component/blob, preconditions, exploitability, impact, reproduction, evidence, remediation and retest status.
- Explicit assessment of residual risk and whether any issue prevents A5 readiness.
- A signed/authenticated final report and a cryptographic digest of the report artifact.

Severity guidance:
- **Critical:** practical compromise of Owner authority, trust roots, protected execution or broad confidentiality/integrity.
- **High:** realistic bypass of authorization, trust validation, checkpoint integrity or build/release provenance.
- **Medium:** meaningful exploit requiring constrained preconditions or limited impact.
- **Low/Informational:** hardening, observability or documentation defects without direct security impact.

## 6. Acceptance criteria

A3.10.7 may be closed only when:
- A qualified independent assessor has completed the agreed scope on a frozen exact commit.
- The authenticated report and evidence references are committed or securely linked.
- No unresolved Critical or High findings remain.
- Medium findings are fixed and independently retested, or explicitly risk-accepted by the Owner with owner, rationale, compensating controls and expiry/review date.
- All remediation commits have exact-head CI evidence.
- The assessor confirms retest results or explicitly documents limitations.

A comment from the implementation author, automated CI, internal review or this package is not independent assessment evidence.

## 7. Evidence handoff checklist

- [ ] Owner appoints assessor and approves scope.
- [ ] Conflict-of-interest and independence statement received.
- [ ] Frozen commit SHA recorded.
- [ ] PR #88 and its parent baseline PR #85 made available read-only.
- [ ] Exact-head Rust, GENESIS and supply-chain workflow runs linked.
- [ ] Trust-root, witness API, operations, supply-chain and A5 documents provided.
- [ ] Assessor report and finding register received.
- [ ] Remediation and independent retest complete.
- [ ] Owner accepts residual risk and authorizes A3.10.7 closure.

## 8. Current disposition

**A3.10.7: NOT CLOSED — AWAITING OWNER-APPOINTED INDEPENDENT ASSESSOR.**

This package prepares the engagement. It does not claim that a reviewer has been selected, testing has occurred, findings are absent or the system is certified.
