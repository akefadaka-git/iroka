# K-04 A2/A3 Remediation and Evidence Disposition

**Record:** IROKA-G11-K04-A2-A3-REMEDIATION-002  
**Date:** 2026-11-07  
**Repository:** `akefadaka-git/iroka`  
**Remediation branch:** `fix/k04-a2-a3-remediation`  
**Parent:** PR #8, `fix/k04-witness-roster-fail-closed`  
**Status:** Source remediation committed; exact-head CI and independent operational evidence pending.

## 1. Scope and governance

This record closes the source-level A2 assessment findings and implements the bounded A3 K-04 security corrections authorized by the Owner. It does not close A2 across the whole IROKA system, authorize a merge, provision production trust material, deploy witness services, or close K-04.

PR #5 → PR #7 → PR #8 remain the existing dependency chain. This remediation is stacked on PR #8 and must not be merged independently into `main`.

## 2. A2 finding dispositions

| Finding | Source-level correction | Current disposition |
|---|---|---|
| K04-RV-01 — witness identity/key binding and fixed quorum | Three-entry roster binds witness ID, key ID and public key; exactly 2-of-3; Owner-signed manifest activation; unprovisioned state fails closed | IMPLEMENTED IN STACK; production Owner root and independent witness identities not provisioned |
| K04-RV-02 — receipt-chain progression and truncation | Contiguous receipt/checkpoint indexes, predecessor receipt/checkpoint digests, increasing event sequence, nondecreasing witness time, independent expected terminal head; historical roster resolver | IMPLEMENTED IN SOURCE; exact-head CI pending |
| K04-RV-03 — checkpoint arithmetic | Checked sequence-count arithmetic, checked checkpoint-number increment, non-genesis predecessor digest required; regression tests | IMPLEMENTED IN SOURCE |
| K04-RV-04 — missing event-count threshold | Both freshness and event-count limits are mandatory; missing/zero values report UNCONFIGURED and force checkpoint due; manual request trigger contract added | IMPLEMENTED IN KERNEL POLICY; production numeric values and caller authorization integration remain open |
| K04-RV-05 — receipt digest domain | Correct NUL-terminated receipt-digest domain and fixed regression vector | IMPLEMENTED IN SOURCE |
| K04-RV-06 — consistent snapshot and append integrity | Checkpoint head verification and extraction run in one SQLite read transaction; every append revalidates the chain inside its immediate transaction | IMPLEMENTED IN SOURCE |
| K04-RV-07 — recovery continuity | Two distinct signed recovery approvals bind one recovery ID, stream, external checkpoint and verified local head; approvals are consumed atomically; local rollback below external high-water is rejected | IMPLEMENTED IN KERNEL; external high-water adapter and production approver keys remain open |
| K04-RV-08 — test signer exposure | Local Ed25519 checkpoint/witness test signers and in-memory witness ledger are compiled/exported only under `cfg(test)` | IMPLEMENTED IN SOURCE; production-feature build verification pending |
| K04-RV-09 — Owner decision reconciliation | Section 3 maps all OD01–OD12 to source and operational evidence | DOCUMENTED; OD02/03/06/07/10/11 production evidence remains open |

## 3. Owner Decision Record reconciliation

| Owner decision | Source / control mapping | Remaining evidence |
|---|---|---|
| OD01 — 3 witnesses, 2-of-3 | `audit_verifier.rs`, `witness_roster.rs` | Three production witnesses and independent operators |
| OD02 — independent administration | `audit_witness.rs` durable adapter; operational runbook | Separate control planes, administrators, credentials, key custody and backup operators |
| OD03 — time, event-count and manual triggers | `audit_operations.rs` | Risk-tier numeric configuration; authenticated request endpoint and production scheduler |
| OD04 — fresh quorum for high-risk actions | `audit_operations.rs`, quorum verifier | Authorization-service enforcement integration and approved freshness values |
| OD05 — synchronous fail-closed audit | Existing authorization/audit sink path; `audit_store.rs` | End-to-end protected-operation evidence and alert delivery |
| OD06 — provider-neutral signer | `audit_signer.rs`, `audit_witness.rs` signer traits | Production HSM/KMS/offline adapter and custody ceremony |
| OD07 — independent append-only witness history | `audit_witness.rs` SQLite adapter and receipt verification | Independently administered transparency/retention-locked storage |
| OD08 — one opaque stream | Roster and durable witness ledger bind one configured stream | Production stream ID provisioning; multi-tenant use remains disabled |
| OD09 — preserve V1 | Checkpoint builder anchors V1 head without rewriting event hashes | V2 remains a separate future design |
| OD10 — two-person recovery and anti-rollback | `audit_recovery.rs`, `security_store.rs` | Independent high-water provider, production approver identities, tested operational recovery |
| OD11 — retention, residency and lawful export | Operational runbook records controls | Legal review, retention schedule and jurisdiction/residency decisions |
| OD12 — no blockchain | Existing design baseline | No additional action |

## 4. Implemented A3 hardening

### Checkpoint and local audit chain
- Checked arithmetic rejects checkpoint counter overflow and invalid progression.
- A non-genesis checkpoint must commit to a non-zero predecessor digest.
- Append validates the complete existing V1 chain inside the write transaction before extending it.
- Checkpoint verification and head/count extraction share one SQLite read snapshot.

### Witness receipt ledger and roster lifecycle
- Receipt digest uses the canonical NUL-terminated domain and a fixed test vector.
- Durable witness ledgers are bound to one provisioned witness ID and one opaque stream ID.
- The ledger verifies the complete stored receipt history on open, before append, and before returning its head.
- Historical receipt signatures are verified against the configured historical public-key set, including key rotation.
- Signed roster manifests are retained in the security store for historical resolution.
- `HistoricalWitnessRosterResolver` resolves the Owner-signed roster valid at each receipt's witness-assigned time.
- `WitnessRosterManager` publishes a higher roster version under a write lock so concurrent readers see one complete roster snapshot.

### Recovery
- Recovery requires exactly two distinct approver subjects with valid Ed25519 signatures.
- Both approvals bind the same recovery, stream, external checkpoint and locally verified audit head.
- The local head is obtained from `SqliteAuditSink::checkpoint_head()`, not trusted as a caller-supplied arbitrary value.
- The external high-water value must match the signed approvals; local history below that high-water or a conflicting hash is rejected.
- Recovery IDs and approval IDs are consumed atomically and cannot be replayed.

### Operational policy
- Missing/zero freshness or event-count thresholds are UNCONFIGURED and block high-risk operations.
- Time and event-count checkpoint triggers are explicit.
- A structurally valid manual checkpoint request forces a checkpoint attempt. The caller remains responsible for authenticating and authorizing the requester before accepting the request.

## 5. Remaining A2 and production boundaries

The following are not code-only closures and remain explicitly open:

1. Three independent production witness services, separate administrators/control planes, credentials, signing keys and backup custody.
2. Production Owner root and witness-key provisioning through a protected out-of-band boundary.
3. Production checkpoint signer and non-exportable key custody.
4. External high-water/checkpoint anchor resistant to database snapshot rollback.
5. Numeric cadence/freshness limits by risk tier and production scheduler/alert delivery.
6. Authenticated manual checkpoint request integration with the authorization and audit pipeline.
7. Production recovery approver identities, external high-water provider and witnessed restore exercise.
8. Retention, evidence access, residency and lawful export approvals.
9. Full event-coverage inventory for protected side effects.
10. A2 platform-wide gaps recorded by the existing A2/A4 verification report: native microkernel/platform targets, IR/VM, INL, bilateral VYRAQON interoperability, canonical interchange, regional runtime profile conformance, hardware/bare-metal qualification and the full system assurance suite.

These items prevent an A2-wide or K-04 production-closure claim. A local SQLite ledger, test key, CI pass or process-local manager is not evidence of an independent production trust domain.

## 6. Verification status

The remediation branch has a push-triggered Rust kernel workflow. The final PR head must be verified for:
- `cargo fmt --all -- --check`;
- locked workspace/all-target compilation;
- production feature configuration and rejection of development bypasses;
- complete unit/contract tests, including new recovery, key-rotation, stream-binding, arithmetic, digest and tamper-continuation cases;
- Clippy with warnings denied under the configured policy.

The exact checked-out SHA, run URL, job logs and exit codes are to be appended only after a successful run against the final PR head. No earlier SHA's successful run is transferable to a later head.

## 7. Final disposition

- K-04 A2 source-level review findings RV-01 through RV-09: **SOURCE REMEDIATION IMPLEMENTED; EXACT-SHA VERIFICATION PENDING**.
- A2 platform-wide gate: **PARTIAL**.
- A3 security remediation: **IMPLEMENTATION IN PROGRESS; VERIFICATION PENDING**.
- K-04 production readiness: **NOT ESTABLISHED**.
- PR #5, #7 and #8: remain open and draft.
- This remediation PR: draft only.
- Merge, deployment, production trust activation, branch deletion and K-04/A2 closure: **NOT AUTHORIZED**.
