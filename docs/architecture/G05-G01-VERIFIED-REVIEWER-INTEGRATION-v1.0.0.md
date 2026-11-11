# G05–G01 Verified Reviewer Approval Integration v1.0.0

**Status:** A3 integration candidate; exact-head CI PASS; independent A4 assurance pending.

## Trust and data flow

1. G01 authenticates the reviewer and produces an opaque `VerifiedPrincipal`. The application constructs a request-scoped `KernelG01ReviewerProofAuthority` with that principal and a `ReviewerProofVerifier` backed by the authoritative `ReviewerKeyBindingResolver` and Kernel security store. The adapter must not be reused across reviewer sessions.
2. G05 registers an immutable pending approval envelope against a canonical durable `MemoryRecord`. The envelope stores the approval ID, memory ID, tenant, organization/subject, record version, content digest, purpose, classification, contract version, reviewer, validity window and signed proof JSON. Duplicate approval IDs cannot overwrite an existing pending envelope.
3. At activation, the canonical repository path authorizes the G02 request before content access, resolves metadata, loads the record from `MemoryRepository`, and requires metadata/record/receipt agreement. Caller-authored record data is not accepted by this path.
4. G05 re-resolves the latest active reviewer designation for the exact tenant, organization and reviewer. It checks designation validity and current version, then compares the pending canonical approval envelope to the receipt and current memory record.
5. G01 verifies the signed envelope against the request-scoped `VerifiedPrincipal`, current issuer/subject/credential/key binding, revocation state, Ed25519 signature, 300-second proof lifetime, 30-second binding freshness, and exact reviewer/key/designation/version, approval, tenant, organization, memory ID/version/digest, purpose, classification, capability, resource and policy version. Only G01 can construct `VerifiedReviewerProof`.
6. G05 checks the typed `VerifiedReviewerProof` fields against its canonical approval, memory record and freshly resolved designation. It then rechecks designation state and atomically inserts the unique consumed-approval row, marks the pending approval consumed, and writes the G11 outbox event in one G05 SQLite transaction.

## Canonical resource and capability

- Capability: `g05.memory.durable.activate`.
- Resource: `g05:durable.activate:{tenant}:{organization}:{memory}:{record_version}:{content_sha256}`.
- Policy version: the stored memory record's contract version.
- Purpose and classification use the canonical G05 enum keys.

## Exactly-once and failure semantics

- G01 proof ID is unique in the Kernel security store under `(issuer, credential_id, proof_id)`.
- G05 approval ID is unique in `g05_consumed_reviewer_approvals`; pending approval state transitions from unconsumed to consumed with a conditional update in the same transaction as the G05 outbox event.
- Replays, stale designations, stale record versions, mismatched digests, invalid signatures, missing key bindings and store failures fail closed.
- G01 proof consumption and G05 approval consumption are separate SQLite transactions. A failure after G01 consumption but before G05 commit can require a new proof; this is intentionally fail-closed, not cross-database atomic.
- The caller must persist the returned activated record using the repository's optimistic-version `replace_with_audit` operation. If that write fails after approval consumption, the approval remains consumed and must not be reused.
- SQLite authority stores are single-node only. Multi-node deployments require shared transactional adapters with equivalent uniqueness and durability.

## Non-goals and outstanding assurance

This integration does not appoint reviewers, provision issuer trust roots, establish community authority, approve Maale language content, or activate memory automatically. Production use requires a real issuer-side `ReviewerKeyBindingResolver`, a request-scoped G01 principal, canonical `MemoryRepository` wiring, G05/G11 integration tests, and independent A4 security review.

## Verification evidence

Exact integration head `5dd6ca77afab958b01b0d9009dbb71ff32f05342` passed GitHub Actions run [42957553177](https://github.com/akefadaka-git/iroka/actions/runs/42957553177): formatting PASS, workspace/all-target compilation PASS, production no-default-feature safeguard PASS, **141 tests passed / 0 failed**, and Clippy PASS. This verifies the implementation and its deterministic test adapters; it does not provision a production issuer registry or constitute independent security review.
