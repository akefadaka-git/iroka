# K-04 PR #7 / PR #8 Review — RV-01 and RV-02

**Review date:** 2026-11-05  
**Repository:** `akefadaka-git/iroka`  
**Review scope:** PR #7 and PR #8 source, their dependency relationship to PR #5, the controlling Owner Decision Record, and the code paths for K04-RV-01 / K04-RV-02.

## Exact reviewed revisions

| Item | Revision / state |
|---|---|
| PR #5 base package head | `87fed43cfc0c235ca38d61a23354ee5d5ad93477` — open, draft |
| PR #7 head | `ecd93b61ef19a60dbee66ea3492c3e306ee85cff` — open, draft |
| PR #8 reviewed head after corrections | `db9d9d0d9d9dd2cf4ba55e9b3da54028b17a6f76` — open, draft |
| PR #7 base | PR #5 head branch `feature/k04-checkpoint-packages-clean` |
| PR #8 base | PR #7 head branch `fix/k04-authorized-witness-roster` |

PR #8 is stacked on PR #7, and PR #7 is stacked on PR #5. Do not merge PR #7 or PR #8 directly to `main` or out of dependency order.

## Controlling policy

The Owner Decision Record `docs/architecture/G11-K04-OWNER-DECISIONS-001.md` records OD01 as three independently administered witnesses with a two-of-three signed receipt quorum. OD02 requires separate security administration, control-plane/account boundary, credentials, signing keys and backup operators. The record authorizes bounded pilot implementation, not production key provisioning, deployment, merge or K-04 closure.

## PR #7 review — authorized witness identity binding

**Reviewed changes:** `crates/iroka-kernel/src/audit_verifier.rs`, `crates/iroka-kernel/src/lib.rs`.

Implemented in PR #7:
- exactly three roster entries;
- rejection of blank and duplicate witness IDs and key IDs;
- rejection of public-key reuse;
- binding of receipt witness ID and signing-key ID to the same roster entry before signature verification;
- fixed two-of-three quorum, not caller-supplied quorum;
- tests for quorum sufficiency, identity relabelling and duplicate key reuse.

**Review disposition:** The identity-to-key and fixed-quorum logic is sound as a bounded verifier primitive. PR #7 alone is not acceptable for merge: its public roster constructor allows an external caller to instantiate an arbitrary three-entry roster without Owner authorization. PR #8 closes that construction path by making the constructor crate-private and requiring signed-manifest activation. PR #7 must therefore remain stacked and must not be merged independently.

## PR #8 review — Owner-authorized activation and fail-closed boundary

**Reviewed changes:** `audit_verifier.rs`, new `witness_roster.rs`, `security_store.rs`, `lib.rs`, and `G11-K04-OWNER-SIGNED-WITNESS-ROSTER-001.md`.

Implemented:
- explicit unprovisioned roster state; verification fails closed without provisioned authority;
- crate-private arbitrary roster construction;
- domain-separated Ed25519-signed roster manifest bound to Owner subject, root key ID, stream, version and validity window;
- exactly three unique witness IDs, key IDs and public keys;
- fixed two-of-three quorum;
- witness keys must be valid for the complete roster validity window;
- stream scope and manifest expiry checks;
- atomic SQLite roster version/digest persistence, rejecting lower versions and conflicting same-version payloads;
- explicit higher-version rotation and retired-key identifiers.

Important deployment boundary:
- `OwnerWitnessRosterRoot` is supplied as a trust-anchor parameter. The library cannot prove that the caller loaded it from protected bootstrap configuration. The host adapter must keep this value out of user/API request control and load it only from a protected out-of-band source or hardware-backed trust.
- The Owner root is not provisioned. No production root or witness credentials exist.
- A higher-version activation must atomically replace and invalidate prior in-memory roster state in the deployment adapter. The kernel state object does not itself coordinate process-wide invalidation.
- Separate witness administration and custody must be evidenced operationally; three different public keys do not prove three independent trust domains.
- SQLite high-water state can be rolled back by restoring an older database snapshot; production needs an external anti-rollback anchor.
- Historical receipt verification across key rotations still needs a historical-roster resolver.

**Review disposition:** The code-level arbitrary-roster construction weakness is corrected in the PR #7 + PR #8 stack. Production Owner authorization and independent-witness assurance remain blocked. K04-RV-01 is therefore **PARTIAL**, not VERIFIED-CLOSED.

## K04-RV-02 — receipt progression and checkpoint linkage

The reviewed pre-correction verifier checked signatures, witness/stream identity, receipt-log index and previous-receipt digest, but did not enforce checkpoint-number progression, previous-checkpoint digest linkage, monotonic event sequence or monotonic witness time.

PR #8 now enforces:
1. genesis receipt log index and checkpoint number start at one;
2. previous receipt digest starts at zero and links to the preceding signed receipt;
3. previous checkpoint digest starts at zero and links to the preceding checkpoint digest;
4. checkpoint numbers and receipt log indices are contiguous;
5. accepted event sequence strictly increases;
6. witness acceptance time never moves backwards;
7. overflow while advancing expected indices is rejected;
8. the last exported receipt must equal an expected terminal head obtained independently from the witness head endpoint, so a truncated export is rejected when that independently obtained head is available.

Regression tests were added for a skipped checkpoint number, broken checkpoint digest link, non-increasing event sequence, regressed witness time and truncated receipt history.

**Review disposition:** The identified verifier gap is addressed in source and regression cases. K04-RV-02 is **IMPLEMENTED — VERIFICATION PENDING** until formatting, compilation and tests run successfully at the exact reviewed head SHA. A production end-to-end claim also requires independently retrieving the expected witness head.

## Verification evidence

For exact head `db9d9d0d9d9dd2cf4ba55e9b3da54028b17a6f76`:
- PR-triggered workflow runs: **0**
- GitHub commit statuses: **0**
- GitHub check runs: **0**
- formatting: **NOT RUN**
- compilation: **NOT RUN**
- unit/regression tests: **NOT RUN**
- Clippy: **NOT RUN**
- independent operational witness review: **NOT RUN**

The implementation and test cases are source-reviewed only. No claim is made that the code compiles or tests pass.

## Final review decisions

| Item | Status |
|---|---|
| PR #7 identity/key binding | **IMPLEMENTED** |
| PR #7 standalone merge readiness | **NOT READY** — arbitrary roster constructor before PR #8 |
| PR #8 signed activation and fail-closed boundary | **IMPLEMENTED; production provisioning blocked** |
| K04-RV-01 | **PARTIAL** — code path corrected; Owner root and operational independence not provisioned/evidenced |
| K04-RV-02 | **IMPLEMENTED — VERIFICATION PENDING** |
| PR #5 / #7 / #8 merge | **NOT AUTHORIZED** |
| Production activation / deployment | **BLOCKED** |
| K-04 closure | **NOT AUTHORIZED** |

## Required next acceptance steps

1. Run `cargo fmt --check`, `cargo check`, the relevant crate tests and `cargo clippy` at the exact PR #8 head; retain logs and exit codes.
2. Have an independent reviewer inspect the trust-anchor provisioning boundary, state replacement on roster rotation, receipt-history completeness and SQLite/external anti-rollback design.
3. Provision the Owner root only through the separately approved protected bootstrap process; do not put private keys in GitHub or source files.
4. Evidence three independent witness operators, infrastructure/control planes, credentials, key custody and backup/recovery separation.
5. Implement the historical-roster resolver and external anti-rollback anchor before claiming full production key-lifecycle assurance.
6. Reconcile any remaining K-04 findings individually. Do not infer closure of RV-03 through RV-09 from this review.

No merge, deployment, production trust activation, branch deletion or K-04 closure is authorized by this report.
