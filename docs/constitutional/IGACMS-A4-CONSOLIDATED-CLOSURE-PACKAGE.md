# IGACMS A4 Consolidated Closure Package

**Assessment date:** 2026-11-08  
**Repository:** `akefadaka-git/iroka`  
**Implementation branch:** `feat/igacms-a3-implementation`  
**A2 baseline:** `a709fc473b23494839417449e34bebf4cb8be77a`  
**Latest PR:** [#13 — IGACMS v1.0 A3 implementation](https://github.com/akefadaka-git/iroka/pull/13)  
**Latest observed PR head before this package:** `d4a7a9e4e74dc9521300b4dfdbc32ef6592540f0`  
**Overall A4 disposition:** **PARTIAL — NOT CLOSED**  
**Merge / deployment:** NOT AUTHORIZED; NOT PERFORMED

## 1. Executive disposition

This package consolidates the A4 implementation and verification evidence currently available. It distinguishes verified local implementation controls from controls that are absent or require a separate Owner decision.

The following work is verified:
- A4-01 approval/revocation atomicity.
- A4-02 trust snapshot publication ordering and fail-closed behavior.
- A4-03 local SQLite audit-chain integrity.
- A4-04 the enumerated SQLite busy-lock, page-limit disk-full, injected write failure, deferred commit failure and abrupt-process/WAL-recovery scenarios.

The following are **not** represented as completed:
- A4-03 external signed checkpointing, independent witness publication and remote retention.
- A4-05 production custody, production trust-root provisioning, Genesis activation, runtime promotion and deployment.
- Physical storage-device failure, host power loss, filesystem corruption and every possible I/O failure mode.

Therefore this is an evidence-backed **A4 consolidated assessment and closure-readiness package**, not an A4 closure certificate. A4 remains **PARTIAL — NOT CLOSED** until the Owner separately resolves the external-checkpoint and operational-governance boundaries and the corresponding approved work is completed and verified.

## 2. Scope and governance

### In scope for this package
- Consolidation of A4-01 through A4-05 findings, remediation, test evidence and residual risks.
- Exact commit and GitHub Actions evidence references.
- Explicit separation of implemented local controls from absent external/operational controls.
- A closure-readiness decision register for the Owner.

### Explicitly outside the completed implementation
- External checkpoint signer, witness/notary service, remote retention or independent checkpoint verifier.
- Production signing-key creation, custody ceremony, key provisioning or rotation.
- Production Genesis activation, runtime promotion, release, merge or deployment.
- Multi-node production security-store architecture or certification.

### Governance constraints
- The Owner's 2026-11-08 waiver of independent security review as an A3/A4 prerequisite remains in force. No independent audit is claimed.
- The waiver does not waive automated tests, evidence integrity, production custody, external audit anchoring or deployment controls.
- No merge or deployment authorization is inferred from this package.
- No production key or trust root is created or provisioned by these A4 remediations.

## 3. Consolidated work-package register

| ID | Control / finding | Evidence and disposition | Status |
|---|---|---|---|
| A4-01 | Owner approval and revocation atomicity | SQLite `IMMEDIATE` transaction rechecks signing-key and approval revocation in the same transaction as one-time consumption and receipt. Regression tests cover pre-revoked key, pre-revoked approval and a two-connection revocation/consumption race. | **VERIFIED-CLOSED** |
| A4-02 | Trust snapshot publication ordering | Manager-wide installation mutex serializes verification, durable anti-rollback persistence and active snapshot publication. Deterministic concurrent-install, poisoned-lock and rollback tests added. | **VERIFIED-CLOSED** |
| A4-03-L | Local audit-chain integrity | Append-only SQLite audit events, domain-separated SHA-256 hash chaining, duplicate-ID rejection, chain verification and tamper/reopen tests. | **VERIFIED** |
| A4-03-E | External signed checkpoint / witness / independent retention | No checkpoint envelope/signer, independent witness publication, remote retention or external verifier implemented. Local hash chaining alone cannot prove that a database tail was not truncated and reconstructed by an actor able to replace the local database. | **NOT IMPLEMENTED — OWNER DECISION REQUIRED** |
| A4-04-R | Rollback and replay controls | Trust-bundle monotonic-version and rollback rejection; approval single-use/replay rejection; revocation command replay protections; audit verification. | **VERIFIED** |
| A4-04-F | Database/process fault injection | Five targeted tests cover SQLite busy timeout, SQLite `SQLITE_FULL` via page limit, injected trigger/write abort, deferred foreign-key commit failure, and abrupt child-process exit with WAL recovery. | **VERIFIED FOR ENUMERATED TEST SCENARIOS** |
| A4-04-X | Physical infrastructure failure envelope | No physical disk failure, host power-loss, filesystem corruption or exhaustive I/O fault certification. | **NOT TESTED / OUTSIDE CURRENT HARNESS** |
| A4-05 | Production operational custody and activation | No production Owner private key/trust root, custody ceremony, production rotation, Genesis activation, runtime promotion or deployment. | **NOT RUN — SEPARATELY OWNER-GATED** |

## 4. Detailed verified implementation evidence

### 4.1 A4-01 — Approval/revocation atomicity

**Disposition: VERIFIED-CLOSED.**

The security store now uses a SQLite `IMMEDIATE` transaction for the critical authorization-consumption sequence. Signing-key revocation and approval revocation are checked in that transaction, together with the one-time consumption marker and approval receipt. This prevents the previously identified gap between an out-of-transaction revocation check and approval consumption.

Regression coverage:
1. `approval_consumption_rechecks_signing_key_revocation_atomically`
2. `approval_consumption_rechecks_approval_revocation_atomically`
3. `concurrent_key_revocation_and_approval_consumption_are_serializable`

Implementation evidence:
- Relevant implementation commits include `c4710a58cd5846bdedd46583ee8095970e1cfdc3`, `5c12ad868d4a9c50419a1cc67c452403b4c59299`, and `36d900b76a77242479300c843872ef65e51656df`.
- Verified code/test SHA: `bb8ce3dec81dcbd2601658321bea6af9fbe4ffa9`.
- Exact-head workflow [#42459388552](https://github.com/akefadaka-git/iroka/actions/runs/42459388552): SUCCESS; all five gates passed.
- Documentation-inclusive exact-head workflow [#42459440729](https://github.com/akefadaka-git/iroka/actions/runs/42459440729): SUCCESS; all five gates passed at `a1b92959011c88a7b732f81a40187f2e0667a868`.

### 4.2 A4-02 — Trust snapshot publication ordering

**Disposition: VERIFIED-CLOSED.**

Root cause: verification and durable anti-rollback persistence could complete before the in-memory snapshot write lock was acquired. Concurrent installations could persist versions in one order and publish snapshots in the reverse order, leaving the active snapshot behind the durable high-water mark.

Correction:
- Added a manager-wide installation mutex.
- Held it across signed-bundle verification, durable monotonic-version persistence, snapshot write-lock acquisition and snapshot publication.
- Routed both `install` and `install_with_roots` through the same serialized installation path.
- Poisoned installation lock fails closed with `TrustBundleError::StoreUnavailable`.

Regression coverage:
1. `concurrent_snapshot_installation_serializes_persistence_and_publication`
2. `poisoned_installation_lock_fails_closed_without_persisting_or_publishing`
3. `rollback_rejection_leaves_active_snapshot_unchanged`

Implementation commits:
- `39f671036c70f7ac1d43344b188264b6a76ecc48`
- `755b35d0c2506a269314fc2d790d3a60a40de4e2`
- `7caaf18211107b383728653b4699eb0352983f5f`

Exact-source workflow [#42460964752](https://github.com/akefadaka-git/iroka/actions/runs/42460964752): SUCCESS; all five gates passed, 61 unit tests plus 2 contract tests.

### 4.3 A4-03 — Local audit-chain integrity

**Disposition: VERIFIED for the local chain implementation and tested integrity cases. External anchoring remains unimplemented.**

The local audit sink provides:
- Append-only SQLite event storage under ordinary application paths.
- Domain-separated SHA-256 hash chaining with length-prefixed fields.
- Duplicate event-ID rejection.
- Previous-hash and event-hash continuity verification.
- Update/delete triggers intended to prevent ordinary application-level mutation.
- Tests for append/verify, duplicate IDs, modified-row detection, deleted-row detection and persistence/reopen.

These local controls provide tamper evidence within the local database model. They do **not** independently establish that a privileged actor could not replace the database, truncate its tail and reconstruct a self-consistent local chain. A trusted checkpoint retained outside that database is required to detect that class of history replacement.

No external checkpoint format, production checkpoint signer, witness/notary publication, independent remote retention or external checkpoint verifier was introduced by this work.

### 4.4 A4-04 — Rollback, failure and recovery

**Disposition: VERIFIED for the enumerated source-level and deterministic SQLite test scenarios.**

Previously verified controls include monotonic trust-bundle versions, rollback rejection, same-version idempotence/conflict handling, epoch rollback/overflow rejection, approval replay rejection, revocation command replay protection, and audit-chain verification.

Five additional tests were added in `crates/iroka-kernel/src/security_store.rs`:

| Test | Fault injected | Verified outcome |
|---|---|---|
| `busy_lock_exhaustion_fails_closed_without_partial_trust_write` | Competing SQLite `BEGIN IMMEDIATE` lock held through busy timeout | Installation returns unavailable; trust state/history do not partially advance |
| `sqlite_page_limit_disk_full_fails_closed_without_advancing_trust_state` | SQLite `PRAGMA max_page_count` induces `SQLITE_FULL` | Installation fails closed; pre-existing trust history remains unchanged |
| `injected_storage_write_failure_rolls_back_all_trust_state` | Trigger aborts history insert after state-row write | Transaction rolls back all trust state |
| `deferred_constraint_commit_failure_rolls_back_trust_state` | Deferred foreign-key violation surfaces at commit | Commit failure is fail-closed; no partial trust state remains |
| `abrupt_process_exit_recovers_wal_without_uncommitted_trust_state` | Child process exits during an uncommitted transaction | Reopen/WAL recovery does not expose uncommitted trust state |

Implementation/test commits:
- `88b2133a550ef85d6ae427ebf300b91086452201`
- `d24d00283a93c464954bfdf3252e3a2324510f62`
- `845724cd26818f1001fa96265e03ada340f4e5bd`
- `7bb57b13ee4b0927ce9124cd7553ac09c113c682`
- `c4b5408618122fc868cd43b3bc127c8034e42d24`

Exact code/test SHA: `c4b5408618122fc868cd43b3bc127c8034e42d24`. Workflow [#42462303853](https://github.com/akefadaka-git/iroka/actions/runs/42462303853): SUCCESS; all five gates passed; 66 unit tests and 2 contract tests passed, zero failures.

**Limit:** these are deterministic SQLite-level tests. They are not physical storage-device failure, host power-loss, filesystem corruption or exhaustive I/O failure certification.

## 5. Exact-head consolidated verification

The final documentation-inclusive package commit is expected to receive the same repository workflow because the workflow path filter includes the implementation record and documentation paths. The exact final SHA and its workflow result must be recorded after the package and its index entry are committed.

Already verified code/test baseline:
- Code/test SHA: `c4b5408618122fc868cd43b3bc127c8034e42d24`.
- Workflow: [#42462303853](https://github.com/akefadaka-git/iroka/actions/runs/42462303853).
- Result: SUCCESS.
- Test totals: 66 unit tests + 2 contract tests; zero failures.

The final package/index documentation commit is not represented as verified until its own exact-head workflow finishes successfully.

Required five gates for the final exact HEAD:
1. `cargo fmt --all -- --check`
2. `cargo check --workspace --all-targets --locked`
3. `cargo check --workspace --all-targets --no-default-features`
4. `cargo test --workspace --all-targets --locked`
5. `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic`

## 6. Owner-governed decisions — explicitly not assumed

### Decision O-A4-03-E: external audit checkpoint

**Current state:** NOT IMPLEMENTED. Local audit-chain verification is not a substitute for external anchoring.

The Owner must decide whether to:
- **Defer** external checkpointing and accept that A4 remains open/partial with the stated audit-history limitation; or
- **Authorize a separately scoped design and implementation stage** for checkpoint envelope, signer custody model, independent witness/notary, remote immutable retention, verifier, failure modes, key rotation/revocation, recovery and exact-head conformance evidence.

No signer, witness, remote storage provider or checkpoint protocol is selected by this package. No implementation or third-party service is activated.

### Decision O-A4-05: production custody and activation

**Current state:** NOT RUN. These are operational and production-security decisions, not consequences of passing CI.

Separate explicit Owner authorization and evidence are required before:
- Creating or provisioning production Owner signing keys or trust roots.
- Defining and executing custody, backup, recovery, dual-control and rotation ceremonies.
- Activating production Genesis or promoting a runtime.
- Authorizing release, merge or deployment.

This package does not request or perform those actions.

## 7. Closure criteria and next-stage sequence

A4 can be reconsidered for closure only after the Owner has dispositioned the external checkpoint boundary and the operational activation boundary. The minimum evidence sequence is:

1. **Owner decision recorded:** explicit defer/acceptance or separately scoped authorization for external checkpointing; explicit decision on whether production custody/activation is in scope for the A4 closure target.
2. **If checkpointing is authorized:** complete its separate architecture and threat model, implementation, independent witness/retention path, key lifecycle, failure/recovery tests and exact-head CI. If deferred, record the residual limitation and do not claim externally anchored audit integrity.
3. **Operational boundary:** either keep production custody/activation explicitly out of the A4 closure target with a documented non-production status, or authorize and complete the separate custody/activation gates. Do not infer production readiness from test success.
4. **Final assurance review:** reconcile all A4 findings, confirm all approved requirements have evidence, record residual risks and verify the final exact HEAD through all five CI gates.
5. **Separate release governance:** merge and deployment remain separate decisions and require explicit authorization.

## 8. Current repository and release state

At package preparation:
- PR [#13](https://github.com/akefadaka-git/iroka/pull/13) is **OPEN, DRAFT, UNMERGED**.
- PR head before this package: `d4a7a9e4e74dc9521300b4dfdbc32ef6592540f0`.
- Base: `architecture/igacms-a2-ci-base`.
- No merge commit exists for PR #13.
- No deployment, production key provisioning, Genesis activation or runtime promotion has occurred.
- No external checkpoint implementation has been added.
- No paid CI service, top-up, deposit or payment was used or requested.

## 9. Final status statement

**A4-01: VERIFIED-CLOSED.**  
**A4-02: VERIFIED-CLOSED.**  
**A4-03 local audit chain: VERIFIED.**  
**A4-03 external checkpoint/witness/retention: NOT IMPLEMENTED — OWNER DECISION REQUIRED.**  
**A4-04 enumerated rollback, SQLite fault-injection and process/WAL recovery cases: VERIFIED.**  
**A4-04 physical infrastructure failure envelope: NOT TESTED.**  
**A4-05 operational custody and production activation: NOT RUN — SEPARATELY OWNER-GATED.**

**OVERALL A4: PARTIAL — NOT CLOSED.**

This is the consolidated evidence package and accurate closure-readiness disposition. It deliberately does not convert unimplemented external controls or unperformed production operations into PASS claims, and it does not authorize merge or deployment.
