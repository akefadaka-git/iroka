# K-04 Owner Decision Record — Audit Integrity and Independent Checkpoints

**Record:** IROKA-G11-K04-OWNER-DECISIONS-001  
**Decision date:** 2026-11-05  
**Authority:** Owner instruction in the current project conversation to review and approve the twelve K-04 decisions and then open implementation.  
**Design baseline:** `1b32938b6cf657cc50406f05217b468179293109`  
**Status:** APPROVED FOR BOUNDED IMPLEMENTATION; PRODUCTION PARAMETERS PARTIALLY OPEN

## Decision dispositions

| ID | Approved disposition | Boundaries / unresolved items |
|---|---|---|
| OD01 | Three independently administered witnesses; two-of-three signed receipt quorum. | No production witness endpoints are selected by this record. |
| OD02 | Independence requires separate security administration, cloud/account or equivalent control-plane boundary, credentials, signing keys, and backup operators. | Evidence of actual independence is required before production acceptance. |
| OD03 | Support both elapsed-time and event-count checkpoint triggers, plus explicit manual checkpoint requests. | Numeric limits must be configured by risk tier. No implicit production default is approved; missing configuration is reported as unconfigured. |
| OD04 | High-risk operations require a current two-of-three checkpoint quorum within the configured maximum staleness window. | If the maximum is absent or stale, affected high-risk operations are blocked. |
| OD05 | Local audit append remains synchronous and fail-closed. Remote anchoring is asynchronous. Staleness raises a high-severity alert and degraded state; high-risk operations block after the configured limit. | No emergency override is approved. No events may be discarded to recover from outage. |
| OD06 | Signing is delegated through a separate signer boundary, intended for non-exportable HSM/KMS or an offline signing service. | Implement only a provider-neutral signer contract and test signer. No private key, vendor selection, production credential or CI secret is authorized. |
| OD07 | Witness receipts and accepted checkpoint history use an independently administered append-only transparency ledger or retention-locked store, with exportable signed receipts. | A local test adapter is not evidence of independent custody. |
| OD08 | Initial pilot uses one provisioned opaque stream ID. | Multi-tenant streams remain disabled until authenticated tenant identity, stream provisioning and cross-tenant verification rules are separately specified. |
| OD09 | Preserve the existing V1 event chain and anchor its current head without rewriting historical hashes. Define V2 as a separate version with stream and sequence binding before any migration. | V2 migration is not part of this pilot. |
| OD10 | Recovery requires two-person approval and reconciliation against independently witnessed high-water marks. | No reset, rollback or lowering of witness state is permitted. Recovery authority identities and production procedure remain to be provisioned. |
| OD11 | Retention, evidence access, residency and lawful export must be governed per operating jurisdiction. | Exact retention periods, jurisdictional legal review and residency decisions remain unresolved; production rollout is blocked until recorded. |
| OD12 | No blockchain is introduced for K-04. | Reconsider only through a separate documented threat/benefit analysis demonstrating a requirement not met by independent witnesses. |

## Authorization and limits

These dispositions approve the architecture and open a bounded A3 implementation pilot in separately reviewable packages:

1. Checkpoint builder and V1 anchor compatibility.
2. Provider-neutral signing boundary.
3. Independent witness protocol and append-only acceptance ledger.
4. Offline verifier and recovery reconciliation.
5. Operational assurance, monitoring contracts, runbooks and test evidence.

Implementation must preserve the current verified correction branch and `main`. Work must be isolated on a new branch. Each package must have its own reviewable commit or clearly isolated commit group, tests, and acceptance evidence.

This record does **not** authorize:
- production signing keys, HSM/KMS provisioning, vendor procurement or secret creation;
- live witness deployment or claiming that a local test ledger is independently administered;
- production freshness/cadence values, retention schedules or jurisdictional legal conclusions;
- multi-tenant activation or V2 event-chain migration;
- merge, deployment, branch deletion, or K-04/A2 closure.

Any unresolved production parameter must fail visibly as UNCONFIGURED and must not be silently assigned a permissive default. The pilot must not change existing authorization semantics except to preserve the already established fail-closed audit behavior.

## Acceptance status

- Twelve architecture/policy dispositions: **APPROVED**.
- OD03 numeric cadence limits: **UNRESOLVED — production configuration required**.
- OD06 signer provider and custody ceremony: **UNRESOLVED — provider-neutral interface only**.
- OD08 multi-tenant contract: **UNRESOLVED — single-stream pilot only**.
- OD11 retention periods and jurisdictional approvals: **UNRESOLVED — production blocked**.
- A3 bounded implementation: **AUTHORIZED**.
- Production deployment / merge / K-04 closure: **NOT AUTHORIZED**.
