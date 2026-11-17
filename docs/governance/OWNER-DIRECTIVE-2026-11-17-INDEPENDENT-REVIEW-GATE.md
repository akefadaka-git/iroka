# Owner Directive — Independent Review Timing

**Directive ID:** OD-2026-11-17-IR-01  
**Project:** IROKA ZERO  
**Repository:** `akefadaka-git/iroka`  
**Authority:** Repository Owner  
**Effective date:** 2026-11-17  
**Status:** APPROVED — GOVERNING

## 1. Owner decision

The independent security and architecture assessment is a single, system-level gate to be completed **once, immediately before deployment readiness is submitted**. It is not a mandatory approval step for every implementation increment, code change, pull request, chromosome, gene, or intermediate development stage.

IROKA development is to proceed toward full implementation and A4 verification without waiting for the final independent assessment.

## 2. Controls that remain in force during development

This directive does not remove or weaken:

- Normal engineering review, change control, automated CI, unit tests, contract tests, integration tests, static analysis, dependency and supply-chain checks, or security testing appropriate to each change.
- Exact-commit evidence, traceability, reproducible verification, and explicit reporting of unresolved risks.
- Owner authorization for material scope, architecture, trust-root, governance, protected execution, merge, and deployment decisions where separately required.
- The A1–A4 stage objectives and acceptance evidence.
- The separate A5 deployment/release authorization gate.

Routine engineering review and automated assurance are not the same as the final independent assessment. The latter must be performed by a suitably qualified person who did not author or implement the work being assessed.

## 3. Final independent assessment scope

Before deployment readiness can be approved, the independent assessor must review the integrated IROKA release candidate, not conduct repeated reviews of each development step. The assessment must include, at minimum:

1. Architecture and trust-boundary integrity across the twelve chromosomes and Kernel.
2. Identity, trust roots, Owner authority, authorization, delegation, and revocation.
3. Security threat model, attack surfaces, privacy, tenant isolation, and data governance.
4. Supply-chain provenance, dependency inventory/SBOM, build and release integrity.
5. Runtime behavior, protected side effects, failure handling, recovery, and rollback.
6. Test coverage and exact-SHA A4 evidence, including adversarial and negative cases.
7. Operational controls, monitoring, incident response, key custody, backup and restore.
8. All unresolved findings, severity, remediation evidence, and any proposed Owner risk acceptance.

The assessor must produce a dated report identifying the exact release-candidate SHA, scope, evidence examined, findings, severity, limitations, and recommendation. Findings must be remediated or explicitly risk-accepted by the Owner before deployment authorization.

## 4. Stage interpretation

- **A1 — Architecture:** proceed under the approved architecture and Owner decision controls.
- **A2 — Contracts and evidence:** complete contract reconciliation and automated validation; do not block routine development solely because the final independent assessment has not yet occurred.
- **A3 — Implementation:** proceed in dependency order with normal engineering review and continuous automated verification. Do not require a separate independent assessment for each increment.
- **A4 — Verification:** complete the system-level verification and assemble exact-SHA evidence. The final independent assessment is scheduled after the integrated release candidate and A4 evidence are available, before A5.
- **A5 — Deployment:** remains a separate, explicit Owner authorization. No deployment is authorized by this directive.

## 5. Supersession and precedence

For the timing and frequency of the independent security/architecture assessment, this Owner Directive governs over any earlier project note, checklist, PR description, or workflow text that implies an independent assessment is required at every implementation step or before development may proceed.

This directive does not retroactively mark any incomplete A1–A4 work as complete, approve a merge, close a pull request, accept a security finding, or authorize deployment.

## 6. Binding rule

**Build and verify IROKA first. Conduct one independent, integrated assessment against the completed release candidate immediately before deployment readiness. Obtain separate Owner authorization before deployment.**
