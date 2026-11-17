# IROKA A5 Deployment Readiness Gate v1.0.0

**Status:** READINESS PLAN PREPARED — NOT READY FOR DEPLOYMENT  
**Authority:** Owner approval required for every production provisioning and deployment action  
**Current repository artifact:** Rust kernel library (`.rlib`); no production runtime executable/container is defined

## 1. Purpose

This document defines the evidence required before IROKA can enter A5 deployment. It prepares the deployment gate; it does not authorize production key generation, provisioning, release, activation, traffic migration or deployment.

## 2. Current blockers

1. **No deployable runtime target:** the repository builds a kernel library, not a runnable IROKA service, application, container image or deployment bundle. The runtime composition, interfaces, operating model and deployment topology must be specified and verified before A5.
2. **A3.10.3 operational trust remains open:** no independently administered witness operators/endpoints, production mTLS enrollment, Owner root ceremony, protected signing boundary or external restore evidence.
3. **A3.10.7 independent assessment is outstanding:** no independent assessor or authenticated report; no independent retest evidence.
4. **A4 is not closed:** current evidence register identifies exact-head CI and operational/independent gates still required.
5. **Production G09 integration is absent:** no production executor/adapter, end-to-end protected side-effect test or operational kill-switch evidence.
6. **Release attestation is implemented as a workflow but not yet executed:** no published release, SBOM attestation or provenance attestation exists from this implementation.
7. **Environment and operational decisions remain unselected:** no Owner-approved hosting/runtime target, environment configuration, recovery objectives, monitoring, incident response or deployment rollback evidence.

## 3. Mandatory A5 gates

### A. Architecture and artifact
- [ ] Owner-approved runtime architecture and component inventory.
- [ ] Deployable application/service executable or container image, not only a library.
- [ ] Reproducible build instructions and pinned toolchain.
- [ ] Versioned release tag and immutable release assets.
- [ ] SPDX SBOM reconciled to the exact release artifact.
- [ ] Signed provenance and SBOM attestations independently verified against repository, workflow, tag and artifact digest.
- [ ] Vulnerability, license, source and secret scans pass on the release commit.

### B. Identity, trust and cryptographic custody
- [ ] Owner-approved root manifest and fingerprint verification through an independent channel.
- [ ] Two-person root enrollment/rotation/revocation ceremony.
- [ ] Production signing boundary (HSM/KMS or Owner-approved equivalent) selected, enrolled and attested.
- [ ] No production private keys in Git, ordinary application configuration or unprotected CI secrets.
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

### E. Independent assurance and governance
- [ ] A3.10.7 independent assessment completed on the release candidate.
- [ ] No unresolved Critical or High findings.
- [ ] Medium findings fixed or risk-accepted by the Owner with compensating controls and expiry.
- [ ] A4 evidence reconciliation closed and signed.
- [ ] Data classification, privacy, regulatory and retention obligations assessed for the actual deployment jurisdiction and use case.
- [ ] Owner approves residual risk, operations owner, support model and change-control procedure.

### F. Operations and recovery
- [ ] Monitoring, alerting, audit export and incident response runbooks tested.
- [ ] Backup frequency, retention, RPO/RTO and restore drills approved.
- [ ] Key compromise, witness outage, data corruption and service rollback scenarios rehearsed.
- [ ] Environment hardening, network ingress/egress, secrets handling, patching and access review complete.
- [ ] Deployment, health-check, rollback and post-deployment verification plans reviewed.
- [ ] Production data migration and rollback tested using approved non-production data.

## 4. Release workflow boundary

`.github/workflows/release-attest.yml` runs only after a GitHub release is published. It builds and tests the current kernel library, generates an SPDX SBOM, creates GitHub/Sigstore provenance and SBOM attestations, and attaches the library and SBOM to that release.

This workflow is not a deployment workflow. It does not provision production keys, contact witness operators, configure a production environment, activate runtime services or route traffic. The current `.rlib` is a library artifact and is not a deployable application on its own.

## 5. Go/no-go rule

A5 may be declared READY only when every mandatory gate in Sections 3A–3F is supported by exact, inspectable evidence and the Owner signs a readiness decision.

A5 deployment may proceed only after a separate explicit Owner authorization naming:
- The exact release/tag and artifact digests.
- The target environment and deployment window.
- The approved operational and security owners.
- The approved migration/rollback plan.
- The permitted production activation scope.

**Current decision: NO-GO / NOT READY.** Preparation is underway; no production deployment or activation is authorized.
