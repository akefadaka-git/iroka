# IROKA A5 Deployment Readiness Gate v1.0.0

**Status:** READINESS PLAN PREPARED — NOT READY FOR DEPLOYMENT  
**Authority:** Owner approval required for every production provisioning and deployment action  
**Current repository artifact:** Rust kernel library (.rlib); no production runtime executable/container is defined

## 1. Purpose

This document defines the evidence required before IROKA can enter A5 deployment. It prepares the deployment gate; it does not authorize production key generation, provisioning, release, activation, traffic migration or deployment.

## 2. Runtime architecture baseline

The reference architecture is documented in `docs/architecture/IROKA-HYBRID-RUNTIME-REFERENCE-ARCHITECTURE-v1.0.0.md`. It separates:
- Amharic-first clients and edge/API services.
- G01 identity and G02 Owner governance.
- Deterministic Rust kernel service and G09 admission/receipt path.
- Isolated untrusted workload/agent workers.
- Separate least-privilege business executors.
- Append-only audit, external witnesses, backup/recovery and operations.

The proposed logical processes (API, governance, kernel service, worker, audit bridge and node agent) are architecture components, not existing executable binaries. The first target hosting provider, jurisdiction, hardware/OS, database, identity provider, HSM/KMS and operational objectives still require Owner approval.

## 3. Current blockers

1. **No deployable runtime target:** repository builds a kernel library, not a runnable IROKA service, application, container image or deployment bundle.
2. **No production G09 executor:** the kernel trait and verification path exist, but no real business system, effect domain, API, staging endpoint, idempotency ledger, executor key or mTLS enrollment is selected or integrated.
3. **A3.10.3 operational trust remains open:** no independently administered witness operators/endpoints, production mTLS enrollment, Owner root ceremony, protected signing boundary or external restore evidence.
4. **A3.10.7 independent assessment is outstanding:** no Owner-appointed independent assessor or authenticated report; no independent retest evidence.
5. **A4 is not closed:** the evidence reconciliation identifies missing independent, external operational and runtime evidence.
6. **Release attestation has not been executed:** workflow code exists and is being hardened, but no stable release, verified SBOM attestation or provenance attestation exists from this programme.
7. **Environment/operations decisions remain open:** hosting target, data jurisdiction, RPO/RTO, monitoring, incident response, operations ownership and rollback evidence are not approved.

## 4. Mandatory A5 gates

### A. Architecture and artifact
- [ ] Owner-approved runtime architecture, hosting target, jurisdiction and component inventory.
- [ ] Deployable application/service executable or container image, not only a library.
- [ ] Reproducible build instructions and pinned toolchain.
- [ ] Stable release tag reachable from main and immutable release assets.
- [ ] SPDX SBOM reconciled to exact release dependency graph and artifact.
- [ ] Signed provenance and SBOM attestations independently verified against repository, workflow, tag and artifact digest.
- [ ] Vulnerability, license, source and secret scans pass on release commit.

### B. Identity, trust and cryptographic custody
- [ ] Owner-approved root manifest and fingerprint verification through an independent channel.
- [ ] Two-person root enrollment/rotation/revocation ceremony.
- [ ] Production signing boundary (HSM/KMS or Owner-approved equivalent) selected, enrolled and attested.
- [ ] No production private keys in Git, ordinary application configuration or CI secrets.
- [ ] mTLS client credentials provisioned and rotation/revocation tested.
- [ ] Trust snapshot, anti-rollback state and revocation persistence verified after restart/restore.

### C. External audit and witness operations
- [ ] At least two separately administered witness operators selected by the Owner.
- [ ] Independence evidenced across legal/control, accounts, infrastructure, signing keys, backup administration and retention.
- [ ] Live durable publish/readback and exact idempotent retry verified.
- [ ] Replay, conflict, sequence gap/regression, predecessor mismatch, outage/quorum and key-rotation tests pass.
- [ ] External backup/restore and independent evidence reconciliation pass.
- [ ] Audit fork/rollback handling and incident escalation rehearsed.

### D. Authorization and protected execution
- [ ] Production executor adapters reviewed and least-privilege scoped.
- [ ] Exact-operation approval, replay, expiry, revocation and audit-before-effect behavior tested end-to-end.
- [ ] Idempotency and ambiguous-outcome recovery proven against the real adapter.
- [ ] Emergency stop tested and independently observed.
- [ ] No protected side effect can execute from a plain policy ALLOW without required approval.
- [ ] Executor key rotation/revocation and incident reconciliation tested.

### E. Independent assurance and governance
- [ ] A3.10.7 independent assessment completed on the release candidate.
- [ ] No unresolved Critical or High findings.
- [ ] Medium findings fixed or risk-accepted by the Owner with compensating controls and expiry.
- [ ] A4 evidence reconciliation closed and signed.
- [ ] Data classification, privacy, regulatory and retention obligations assessed for actual deployment jurisdiction and use case.
- [ ] Owner approves residual risk, operations owner, support model and change-control procedure.

### F. Operations and recovery
- [ ] Monitoring, alerting, audit export and incident response runbooks tested.
- [ ] Backup frequency, retention, RPO/RTO and restore drills approved and passed.
- [ ] Key compromise, witness outage, data corruption and service rollback scenarios rehearsed.
- [ ] Environment hardening, network ingress/egress, secrets handling, patching and access review complete.
- [ ] Deployment, health-check, rollback and post-deployment verification plans reviewed.
- [ ] Production data migration and rollback tested using approved non-production data.

## 5. Release attestation boundary

`.github/workflows/release-attest.yml` is designed to run only after a stable, non-draft, non-prerelease GitHub release whose tag commit is reachable from main. It checks out the exact tag, runs the Rust checks, builds the kernel library, generates SPDX SBOM, creates provenance and SBOM attestations, verifies both with GitHub CLI and uploads the library and SBOM.

The GitHub attestation action's documented requirements include OIDC token, attestation write and artifact metadata write permissions; the configured action uses the documented subject-path and sbom-path inputs. This workflow is not a deployment workflow. It has not been executed because no release has been authorized. The resulting .rlib remains a library, not a deployable service.

## 6. Go/no-go rule

A5 may be declared READY only when every mandatory gate in Sections 4A–4F is supported by exact, inspectable evidence and the Owner signs a readiness decision.

A5 deployment may proceed only after a separate explicit Owner authorization naming:
- The exact release/tag and artifact digests.
- The target environment and deployment window.
- The approved operational and security owners.
- The approved migration/rollback plan.
- The permitted production activation scope.

**Current decision: NO-GO / NOT READY.** Preparation is underway; no production deployment or activation is authorized.
