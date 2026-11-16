# IROKA A3.10 — Security Implementation and Verification Plan v1.0.0

**Status:** A3.10.1 specification freeze — Owner-authorized  
**Repository:** `akefadaka-git/iroka`  
**Implementation branch:** `feat/a3-security-workstreams`  
**Baseline:** PR #85 head `8e4a8b5582d47d430539ae7b56aac75f0991c8a4`  
**Governance:** Owner approval authorizes A3.10.1 through A3.10.7 and A4 verification. A5 deployment is expressly not authorized.  
**Architecture constraint:** Preserve the approved 12 chromosomes and 36 genes. No new genes, no changes to PR #85, no rewriting verified security foundations, and no unrelated modifications.

## 1. Purpose and closure rule

This plan governs completion of the eight security workstreams identified by A2 Item 10. The objective is an evidence-backed security implementation, not a status-label change.

A2 Item 10 remains PARTIAL/OPEN until implementation, exact-head verification, and independent review criteria in this plan are satisfied. A4 may mark the item VERIFIED-CLOSED only when every mandatory acceptance criterion is evidenced and no unresolved critical or high-severity security finding remains. A passing test suite alone is insufficient.

This document freezes the scope and acceptance model. It does not claim that the controls below are implemented merely because they are specified.

## 2. Frozen baseline and preservation rules

The approved source baseline is commit `8e4a8b5582d47d430539ae7b56aac75f0991c8a4`, previously used for the read-only A2 Item 10 audit. The security branch is created from that exact commit.

Preserve:
- PR #85 and its head/base, review history, workflows, and files.
- Existing A3 branch `feat/a3-shared-evidence-contracts` and its A3.1 specification.
- Existing Ed25519 credential verification, Owner approval verification and atomic single-use consumption, trust-bundle lifecycle, SQLite security persistence, audit hash-chain implementation, and IGACMS controls unless a narrowly scoped, evidence-backed correction is required.
- All unrelated branches, commits, and files.

All changes for this authorization must be isolated to `feat/a3-security-workstreams` and its associated review PR. No merge, release, deployment, production activation, production-key generation, or production-secret handling is authorized.

## 3. Security objectives and threat model

The implementation must protect these assets:
1. Owner authority and signing-key integrity.
2. Trusted issuer keys, credentials, trust roots, and revocation state.
3. Authorization decisions, approval identifiers, capabilities, and protected effects.
4. Security and audit databases, checkpoints, backups, and recovery state.
5. Build inputs, dependency graph, CI credentials, and release artifacts.
6. Evidence lineage, policy/Genome/schema versions, and execution receipts.

Threat actors and failure sources include:
- External unauthenticated callers and malicious authenticated principals.
- Compromised, expired, revoked, substituted, or unknown signing keys.
- Replay, race, concurrency, time-of-check/time-of-use, and scope-substitution attacks.
- Malformed, oversized, ambiguous, contradictory, stale, or untrusted input.
- Database lock, storage, corruption, crash, rollback, backup-restore, and partial-commit failures.
- Malicious or compromised dependencies, build actions, workflows, and release artifacts.
- Insider error, lost keys, compromised roots, and audit-history replacement.
- Clock skew, process interruption, resource exhaustion, and unavailable dependencies.

Security properties:
- Fail closed for protected authorization and security-state mutations when required verification, storage, audit, or trust services are unavailable.
- Separate identity authentication, Owner authority, policy authorization, admission, execution, and evidence verification.
- Bind approvals and execution grants to the exact subject, executor, capability, resource, effect, operation digest, policy/Genome/schema version, expiry, and unique nonce as applicable.
- Preserve distinctions between received, parsed, verified, attested, revoked, unknown, false, inconclusive, failed, and not-run states.
- Never treat a valid signature as proof that signed content is substantively true.
- Make security state transitions atomic, replay-resistant, auditable, and recoverable.
- Do not permit evidence, metadata, model output, or descriptive configuration to create authority.

Out of scope for this plan: claiming resistance to every possible hardware, physical, endpoint, or supply-chain compromise; production deployment; multi-region disaster-recovery certification; and external regulatory certification. These limitations must be stated in the final assessment.

## 4. Workstream definitions and acceptance criteria

### SEC-01 — Identity and credential security

Preserve the existing Ed25519 credential-verification implementation. Verify and complete:
- Algorithm/type allowlisting and strict parsing; reject algorithm substitution and unknown critical fields.
- Issuer, subject, audience, key ID, credential ID, issued-at, not-before, expiry, and maximum-lifetime validation.
- Credential and key revocation, including fail-closed behavior when revocation state is unavailable.
- Explicit key rotation overlap, retirement, and revocation semantics.
- An explicit credential replay policy. If bearer credentials are reusable by design, document that policy and bound exposure through expiry/revocation; if one-time credentials are required, implement atomic identifier consumption.
- Clock-skew, boundary, malformed, oversized, duplicate-claim, and unknown-key tests.

Acceptance: no invalid, expired, revoked, incorrectly scoped, malformed, or unverifiable credential yields an authenticated principal. Tests demonstrate each applicable boundary and failure mode.

### SEC-02 — Owner authority, approvals, and revocation race

Preserve existing Owner signature verification and atomic single-use approval consumption. Correct the A2-confirmed security-command race:
- Recheck the command-signing Owner key's revocation state inside the same immediate transaction that inserts the command identity and applies its revocation effect.
- Preserve a deterministic serialization order between signer-key revocation and command application.
- Ensure duplicate command IDs/digests cannot apply twice and conflicting command reuse is rejected.
- Keep signature, owner-subject, validity-window, expiry, command-digest, and action validation fail-closed.
- Do not persist Owner private keys in the kernel, repository, CI, or ordinary application configuration.

Required concurrency tests:
1. Key revocation commits before command transaction: command rejected.
2. Command transaction serializes before revocation: command may commit only according to the explicitly documented ordering and valid-at-commit policy.
3. Concurrent command and key revocation under controlled scheduling.
4. Duplicate and conflicting command IDs.
5. Storage/write/commit failure and process interruption.
6. Approval replay, approval revocation, and signing-key revocation races.

Acceptance: no command commits if its signer key is revoked at the transaction's authoritative serialization point; command identity and effect are atomic; all race outcomes are deterministic and tested.

### SEC-03 — Trust-root provisioning, custody, rotation, and recovery

Specify and implement an operational lifecycle for root trust:
- Root-key generation and custody requirements; private keys remain outside the repository and ordinary runtime configuration.
- Explicit trust-root enrollment and authenticated authorization of changes.
- Separation of root keys from routine issuer/signing keys.
- Rotation, overlap, retirement, revocation, emergency replacement, and compromise response.
- Recovery and quorum/dual-control requirements where operationally supported.
- Signed, versioned, append-only records of lifecycle events.
- Test-only keys and synthetic fixtures must be unmistakably non-production.

Acceptance: documented ceremony and recovery runbooks; deterministic tests for enrollment, rotation, overlap, expiry, revocation, compromised-root recovery, unknown roots, rollback, and failed persistence. Production key ceremonies are not performed as part of this repository implementation.

### SEC-04 — Security persistence and recovery

Preserve the existing SQLite single-node adapter and its transactional guarantees. Specify adapter invariants before any multi-node implementation:
- Atomic transactions for approvals, revocations, trust versions, command IDs, and related audit records.
- Explicit concurrency/serialization behavior and uniqueness constraints.
- Fail-closed handling for lock, read, write, commit, corruption, and unavailable-storage conditions.
- Database integrity checks, secure file permissions, backup/restore validation, and crash recovery.
- Document that SQLite local persistence is a single-node deployment model unless a shared adapter is separately implemented and verified.
- Do not claim multi-node safety without a shared transactional store and distributed concurrency tests.

Acceptance: fault-injection, concurrent-operation, crash/reopen, corruption, backup/restore, rollback, and lock-contention tests; no storage failure produces a positive authorization or silently loses a committed security transition.

### SEC-05 — Tamper-evident audit and external checkpoints

Preserve and harden the existing append-only hash-chain audit:
- Canonical event encoding, event identity, sequence, timestamp, actor, action, relevant object references, and previous/current digest.
- Detect modification, deletion, insertion, reordering, truncation, duplicate identity, and broken chain.
- Create signed, monotonic checkpoints over a defined audit range and chain head.
- Anchor checkpoints in an independently controlled append-only or immutable destination; local database state must not be its own sole trust anchor.
- Verify checkpoint signatures, sequence continuity, range coverage, and consistency during startup/recovery.
- Define unavailable-anchor behavior, checkpoint retry, and recovery without rewriting history.
- Avoid putting secrets or unnecessary personal data into audit events.

Acceptance: adversarial tests for tampering, truncation, deletion, reordering, checkpoint substitution, rollback, invalid signatures, unavailable anchor, and recovery. Demonstrate independent verification from exported checkpoint material. A mock/test anchor is not evidence of a production external anchor; clearly label the implementation assurance level.

### SEC-06 — G09 operation-specific authorization and protected execution

Complete the authorization-to-effect boundary without treating an authorization decision as arbitrary execution permission:
- Define canonical effect types, target/resource scope, executor identity, risk classification, and policy.
- Bind a short-lived grant to exact subject, executor, capability, resource, effect, operation digest, policy/Genome/schema versions, authorization reference, expiry, and unique nonce.
- Revalidate required revocation and policy conditions at admission.
- Atomically admit and consume the nonce before the protected effect, with a clearly defined idempotency/compensation protocol for partial outcomes.
- Separate denied, admitted, running, succeeded, failed, partial, cancelled, timed-out, and unknown outcomes.
- Produce a verifiable execution receipt bound to the grant, operation digest, result digest, executor, and audit event.
- Ensure retries cannot duplicate non-idempotent effects; define reconciliation for interrupted operations.
- Keep protected effect adapters deny-by-default until their contracts and enforcement are implemented.

Acceptance: end-to-end integration tests for scope substitution, subject/executor substitution, altered operation digest, expired/revoked grant, nonce replay, concurrent admission, policy/version drift, denial, timeout, cancellation, partial effect, crash recovery, receipt tampering, and audit failure. No claim of production side-effect safety without an actual protected adapter and its tests.

### SEC-07 — Dependency and software supply-chain security

Implement free/public CI controls where available:
- Enforce and review Cargo.lock for application/workspace builds.
- Run Rust formatting, tests, Clippy, and production feature guards.
- Add dependency vulnerability/advisory checks with documented data freshness and fail/waiver policy.
- Add license-policy checks and an explicit exception process.
- Add secret scanning and ensure CI logs/artifacts do not expose secrets.
- Minimize workflow token permissions; pin third-party actions to immutable commit SHAs where applicable.
- Review workflow triggers and untrusted pull-request inputs for privilege escalation.
- Generate build provenance/SBOM or equivalent dependency inventory where practical; bind release artifacts to source commit and workflow identity.
- Document reproducibility limits and avoid claiming a reproducible build unless independently demonstrated.

Acceptance: exact-head workflow results for every required job; tests of policy failure on a deliberately vulnerable/forbidden fixture where safe; documented exception handling; no paid service dependency. If an external advisory source is unavailable, report NOT RUN rather than PASS.

### SEC-08 — Independent security assessment and remediation

Obtain review by a reviewer independent of the implementation author for:
- Threat model and trust boundaries.
- Identity/credential and Owner authority paths.
- Cryptographic use and key lifecycle.
- Persistence, transaction ordering, concurrency, backup and recovery.
- Audit chain and external checkpoint verification.
- G09 admission/execution and effect adapters.
- CI, dependencies, workflow permissions, build provenance, and secret handling.

Track every finding with severity, affected commit/path, reproducible evidence, remediation commit, regression test, and independent retest. The reviewer must disclose scope, limitations, and independence. Internal code review or automated scanners are not a substitute for this independent assessment.

Acceptance: signed or otherwise attributable assessment report; no unresolved critical/high findings; all accepted medium/low risks have explicit Owner disposition; remediation independently retested. If no qualified independent reviewer is available, SEC-08 remains OPEN and A4 cannot mark Item 10 VERIFIED-CLOSED.

## 5. A3 execution sequence and gates

A3.10.1 — Specification freeze (this document): freeze threat model, workstream boundaries, acceptance criteria, and branch/base preservation rules.

A3.10.2 — Critical corrections: SEC-02 Owner revocation race and associated concurrency tests; address any directly blocking persistence defects.

A3.10.3 — Trust and audit: SEC-03 root lifecycle and SEC-05 signed external checkpoints, with SEC-04 persistence support.

A3.10.4 — Protected execution: SEC-06 G09 operation-specific grant, admission, nonce, receipt, and recovery.

A3.10.5 — Supply chain: SEC-07 dependency, workflow, secret, provenance, and artifact controls.

A3.10.6 — Integrated verification: run all relevant unit, contract, integration, adversarial, concurrency, failure-injection, recovery, and exact-head CI checks.

A3.10.7 — Independent review: SEC-08 assessment, remediation, and retest.

A4 — Compile the evidence ledger, independently verify exact source SHAs and workflow conclusions, reconcile every acceptance criterion, record residual risks, and request Owner closure decision.

A5 — Deployment remains separately gated and unauthorized by this approval.

Each stage must preserve unrelated changes. Do not start a later stage by silently weakening or bypassing a failed earlier-stage gate. A failed CI run must be investigated and fixed on this branch; do not claim success from a different commit.

## 6. Evidence ledger requirements

For every control, record:
- Control ID and acceptance criterion.
- Source path(s), exact commit SHA, and blob SHA(s).
- Test names and exact test command/workflow job.
- Positive, negative, boundary, concurrency, and failure-injection coverage as applicable.
- Exact workflow run URL, triggering head SHA, conclusion, and job results.
- Independent reviewer finding and retest reference where applicable.
- Status: PASS, PARTIAL, MISSING, UNRESOLVED, NOT RUN, or VERIFIED-CLOSED.
- Residual risk, owner, and explicit disposition.

A test existing in source is not evidence that it ran. A passing CI result is valid only for its exact triggering commit and relevant job. Do not transfer results between commits.

## 7. Non-negotiable security and governance constraints

- Preserve the 12-chromosome/36-gene architecture; this plan does not authorize adding genes.
- No default Owner, model-created authority, self-registration, or authority inherited from evidence.
- No production private keys or secrets in Git, tests, fixtures, logs, or CI.
- No fail-open behavior on missing, unknown, invalid, expired, revoked, or unverifiable security state.
- No production external anchor or root ceremony represented by a mock.
- No merge of PR #85, no merge of this work, no deployment, no release, and no production activation under this authorization.
- No paid CI or service requirement where a public/free alternative is practical.
- No unrelated changes.
- A4 verification and Owner closure are distinct from A5 deployment approval.

## 8. Current baseline observations to carry forward

The A2 Item 10 inspection reported the following baseline observations, which must be revalidated against the actual implementation branch before remediation:
- Ed25519 credential verification, key/credential revocation checks, trust-bundle lifecycle checks, and anti-rollback behavior exist in the audited baseline.
- Owner approvals are signature-verified and consumed atomically; an A2-confirmed gap exists because Owner-signed security-command signer revocation is checked before, but not repeated inside, the transaction applying the command.
- SQLite security persistence includes transactional state handling and is a single-node adapter.
- Audit records use a local hash chain; independently anchored signed checkpoints are not yet established by the A2 evidence.
- G09 schemas describe effect/admission/receipt concepts, but a complete end-to-end protected-effect path was not established by A2.
- Exact-head baseline CI previously passed runs 43751617651 (GENESIS schema closure) and 43751617646 (Rust kernel verification). These are baseline evidence only, not proof of the new security workstreams.

## 9. Freeze record

This plan is the normative A3.10.1 implementation and verification scope for the Owner authorization dated 2026-11-16. Changes to scope, architecture, acceptance criteria, or deployment authority require an explicit Owner decision. Corrections that clarify wording without weakening requirements may be documented with version history.

**A3.10.1 exit condition:** this specification is committed to the dedicated security branch, re-fetched and hash-verified, and its branch base is confirmed to be the approved PR #85 head. This exit condition does not imply that SEC-01 through SEC-08 are implemented or that A2 Item 10 is closed.
