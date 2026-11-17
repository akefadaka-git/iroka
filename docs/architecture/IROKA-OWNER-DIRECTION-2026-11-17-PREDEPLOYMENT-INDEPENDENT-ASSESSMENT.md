# Owner Direction — One Integrated Independent Assessment Before Deployment

- Decision ID: `OD-2026-11-17-IR-01`
- Decision date: 2026-11-17
- Authority: IROKA Owner direction
- Status: APPROVED
- Applies to: IROKA development, A4 evidence reconciliation and A5 deployment gate

## Binding decision

Independent security and architecture review is **deferred until immediately before deployment**. IROKA should first be fully developed through its approved implementation scope. An independent assessment is not a per-gene, per-PR, or routine code-change gate.

The project will conduct **one integrated independent security and architecture assessment** after implementation and A4 evidence reconciliation are complete, and before any A5 deployment authorization or production release.

## Development rules

1. Continue implementation in scoped, traceable work packages with automated tests, static analysis, schema/conformance checks and exact-commit CI evidence.
2. Do not require an independent external reviewer for every implementation increment.
3. Record material implementation decisions, test evidence, defects, remediation and unresolved risks in the repository.
4. Preserve the approved 12-chromosome / 36-gene genome and all previously approved governance boundaries unless the Owner explicitly authorizes a change.
5. The final independent assessment must evaluate the integrated system, not merely a collection of isolated PRs.

## Pre-deployment assessment scope

The single integrated assessment must include, at minimum:

- identity, credential verification, trust roots, key rotation and revocation;
- Owner authority, signed approvals, governance and authorization boundaries;
- memory, knowledge provenance, privacy, retention and deletion controls;
- agent autonomy, orchestration, execution isolation and least privilege;
- supply-chain security, dependency and build provenance, SBOM and release attestations;
- audit integrity, incident response, backup/restore and rollback;
- adversarial testing, threat model, deployment configuration and operational readiness;
- Amharic-first and Ethiopian/African localization, Unicode and calendar requirements;
- evidence traceability, test coverage, known limitations and residual risk acceptance.

## Gate separation

- A3 implementation: authorized within the approved scope; independent review is deferred.
- A4 evidence reconciliation: required after implementation; reconcile exact SHAs, CI, tests, artifacts, risks and closure evidence.
- Integrated independent assessment: one review after A4 and before A5.
- A5 deployment: separate Owner decision. This record does not authorize deployment, release, production key provisioning or production activation.

## Change control

This decision supersedes any earlier project workflow wording that would make independent review a mandatory blocker on each code increment. It does not waive automated verification, secure engineering practice, Owner approvals, A4 reconciliation, or the final pre-deployment independent assessment.

No implementation branch may treat this record as permission to merge or deploy. The final assessment report and Owner's A5 decision must be recorded on the repository's `main` branch.
