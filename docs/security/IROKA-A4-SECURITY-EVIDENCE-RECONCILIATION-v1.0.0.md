# IROKA A4 Security Evidence Reconciliation v1.0.0

**Status:** OPEN — EVIDENCE REGISTER PREPARED; FINAL A4 CLOSURE NOT MET  
**Scope:** A3.10.3, A3.10.5, A3.10.7 and integrated security baseline  
**Deployment:** Not authorized

## 1. Reconciliation rule

A stage is closed only when implementation, exact-head verification, required operational evidence and independent review (where applicable) are all present. A successful CI run on an earlier SHA is historical evidence, not proof for a later commit. A written procedure is not proof that a ceremony, restore or external operation occurred.

## 2. Evidence baseline

Current source of truth is PR #88 on `feat/a3-security-workstreams`. At the time this evidence register was authored, the last fully reconciled automated evidence baseline was `d51cc78323bfa87ad726d726eb6dc1e1bf872be5`. Later changes to the durable SQLite witness adapter, SBOM generation, release attestation workflow and evidence documents require new exact-head CI.

| Evidence | Historical exact-head result | Current disposition |
|---|---|---|
| Rust kernel run #1721 | PASS on `d51cc78323bfa87ad726d726eb6dc1e1bf872be5` | Re-run required after later code changes |
| GENESIS run #100 | PASS on same SHA | Re-run required after later code changes |
| Supply-chain run #23 | PASS on same SHA, including Gitleaks | Re-run required after SBOM/workflow changes |
| Durable SQLite witness tests | Added after that SHA | CI pending |
| SPDX SBOM generator | Added after that SHA | CI pending |
| Release provenance/SBOM workflow | Added after that SHA; release-triggered | Workflow syntax and release execution pending |
| Independent assessment | No assessor/report | NOT STARTED |
| Live independent witness operators | No endpoints or operator evidence | NOT PERFORMED |
| Production trust-root ceremony | No production keys/custody evidence | NOT PERFORMED |
| External backup/restore drill | No external drill evidence | NOT PERFORMED |
| Production G09 adapter | Not integrated/activated | NOT IMPLEMENTED |
| Runtime deployment artifact | Repository currently builds a kernel library, not a runtime service | NOT AVAILABLE |

## 3. A3.10.3 — Trust roots and audit checkpoints

**Software status:** IMPLEMENTED, exact-head verification pending for the durable SQLite witness backend.

Evidence includes:
- Root-signed canonical trust bundles and monotonic persistent versioning.
- Atomic trust snapshot publication and rotation/revocation behavior.
- Signed checkpoint and witness receipt protocol.
- Verified audit head/prefix reconciliation and append-only local checkpoint evidence.
- HTTPS/mTLS witness client adapter.
- Durable SQLite witness reference backend with immediate transactions, exact idempotency, per-stream sequence/predecessor enforcement, persisted signed receipts, append-only triggers and restart readback tests.

**Operational status:** OPEN. Independent operator endpoints, mTLS enrollment, operator identity/independence evidence, production key custody, external backups, durable readback and restore rehearsal have not been performed.

A3.10.3 cannot be marked fully closed until exact-head software tests pass and the external operational evidence is supplied.

## 4. A3.10.5 — Supply-chain security

**Existing controls:** VERIFIED on historical exact head `d51cc78323bfa87ad726d726eb6dc1e1bf872be5`:
- RustSec advisory scan and cargo-deny policy checks.
- Locked optimized build.
- Full Git-history and working-tree Gitleaks scan.
- SQLite advisory remediation without an ignore/waiver.
- Pinned scanner/action versions and read-only security workflow.

**New controls:** IMPLEMENTED, exact-head verification pending:
- SPDX 2.3 SBOM generation from Cargo metadata and Cargo.lock.
- SBOM validation and 90-day workflow artifact retention.
- Published-release workflow to build the kernel library, generate SBOM, create GitHub/Sigstore build-provenance and SBOM attestations, and attach release assets.

A3.10.5 closure requires current-head CI, review of the generated SPDX package and dependency graph, and a real release attestation verification before claiming an attested release artifact exists.

## 5. A3.10.7 — Independent assessment

**Status:** NOT CLOSED. The independent assessment handoff package is prepared. No independent assessor has been appointed, no independent testing has been performed, and no report/findings/retest evidence exists.

This workstream cannot be closed by the implementation author or automated CI.

## 6. A4 closure checklist

- [ ] Current PR #88 head and parent baseline re-fetched and frozen.
- [ ] Rust kernel workflow passes on exact current head.
- [ ] GENESIS schema workflow passes on exact current head.
- [ ] Supply-chain workflow passes on exact current head, including SPDX generation and Gitleaks.
- [ ] Generated SBOM is parsed and package/relationship counts reconciled against Cargo metadata and Cargo.lock.
- [ ] Release workflow syntax is validated; a real release artifact and provenance/SBOM attestations are generated and independently verified when a release is authorized.
- [ ] Trust-root and witness software tests pass on exact current head.
- [ ] Two independent witness operators are identified and their organizational independence verified.
- [ ] Live publish/readback, replay/conflict, outage/quorum, key rotation and restore tests pass.
- [ ] Owner/custodian root ceremony and protected signing boundary evidence are recorded.
- [ ] External backup/restore/reconciliation drill passes.
- [ ] Independent security assessment completed and Critical/High findings remediated and retested.
- [ ] All medium residual risks explicitly accepted by the Owner or remediated.
- [ ] Runtime packaging/deployment target and operational controls are verified.
- [ ] A5 readiness review is signed and Owner decision recorded.

## 7. Closure decision

**A4: NOT CLOSED.** The evidence register is established, but several required gates are absent. Do not convert pending, not performed or not independently verified states into PASS.

A4 may be closed only after every applicable checklist item is evidenced, the independent report is accepted and the Owner signs the closure record. No merge or deployment follows automatically from A4 closure.
