# K-04 Operational Assurance — Pilot Runbook

**Status:** A3 implementation guidance; not production operating authority  
**Applies to:** single provisioned V1 audit stream, three-witness target topology  
**Production readiness:** NOT ESTABLISHED

## 1. Operational invariants

1. Local audit append remains synchronous. An append failure must not permit a positive protected authorization decision.
2. Checkpoint construction operates on a locally verified, committed audit prefix.
3. A checkpoint is externally anchored only after two distinct, independently administered witnesses return valid signed receipts for the same checkpoint digest.
4. The primary application host never stores checkpoint-signing private keys or witness receipt private keys.
5. The witness high-water mark is monotonic. Restore procedures never reset or lower it.
6. Witness outage does not discard local audit events. Stale/unconfigured state is visible and high-risk operations are blocked according to the approved policy.
7. Witnesses receive checkpoint commitments and bounded metadata only, not raw audit event payloads or personal data.
8. The in-memory witness ledger and local test signers are test adapters, not production security controls.

## 2. Required telemetry

Expose at minimum, per stream:
- local verified event sequence and event hash;
- last local checkpoint number/digest;
- last accepted checkpoint number/digest and sequence per witness;
- distinct witness count and current quorum status;
- age of last quorum-accepted checkpoint;
- unanchored event count;
- time and result of last witness contact;
- signer key ID and key validity state (never key material);
- invalid signature, sequence gap, duplicate retry, equivocation and witness disagreement counters;
- recovery/quarantine state.

Human-facing operator diagnostics are Amharic-first with English available. Preserve original UTF-8 and Ethiopic code points. Machine timestamps must be explicit UTC instants.

## 3. Alert and response matrix

| Condition | Severity | Required response |
|---|---|---|
| Checkpoint due | INFO | Build and submit checkpoint; do not report anchored until quorum receipts verify. |
| One witness unavailable, last quorum checkpoint still fresh | WARNING | Continue bounded degraded operation; retry and alert. |
| Quorum unavailable beyond configured freshness | CRITICAL | Block designated high-risk operations; continue local append; preserve pending checkpoint. |
| Missing cadence/freshness configuration | CRITICAL / UNCONFIGURED | Do not assume defaults; block high-risk operations until approved configuration is loaded. |
| Invalid signer or receipt signature | CRITICAL | Reject checkpoint/receipt; preserve evidence; suspend affected key or witness pending review. |
| Conflicting digest at same stream/checkpoint number | CRITICAL / EQUIVOCATION | Freeze automatic acceptance; preserve both signed artifacts; require independent incident review. |
| Local head below witnessed high-water mark | CRITICAL / ROLLBACK | Quarantine stream; do not truncate/reinitialize or lower witness state. |
| Witnesses disagree | CRITICAL / NO QUORUM | Stop automatic checkpoint acceptance; retain local audit; reconcile witness histories. |
| Signing key expiry/revocation | HIGH | Stop signing with affected key; follow separately approved rotation/revocation process. |

## 4. Restore and recovery procedure

1. Freeze protected high-risk operations for the affected stream.
2. Preserve the restored database, WAL/SHM files, backups, local logs, checkpoints and every witness receipt as incident evidence.
3. Verify the local event chain from genesis or the last independently accepted checkpoint.
4. Obtain checkpoint and receipt histories independently from each configured witness.
5. Verify checkpoint signatures, witness receipt signatures, receipt-chain continuity, stream identity and the two-of-three quorum.
6. Compare local sequence/hash with the highest quorum-accepted checkpoint.
7. If local sequence is lower or the hash at the accepted sequence differs, keep the stream quarantined as ROLLBACK_OR_TAMPERED.
8. Restore missing event payloads only from separately protected backups; replay and verify them against the accepted checkpoint. A checkpoint is not a backup.
9. Require two-person recovery authorization before resuming protected operations.
10. Record exact source SHA, backup identity, witness receipt digests, operator identities, decision and verification output.

Never reset the witness high-water mark to make a restored local database appear current.

## 5. Key rotation and compromise

- Keep checkpoint signer and each witness receipt key in separate custody domains.
- Publish key IDs, public keys, validity periods and revocation state through a separately governed signed trust policy.
- Rotation requires an approved overlap window and dual verification; old-key cutoff is explicit.
- On suspected compromise, stop the affected signing authority, preserve all signed checkpoints/receipts, notify independent witness operators and reconcile the last accepted head.
- Do not replace historical receipts or rewrite the witness ledger.

No vendor, HSM/KMS account, production key, recovery custodian or key ceremony is selected by this runbook.

## 6. Backup and restore exercises

Before production acceptance, run and retain exact-SHA evidence for:
- primary audit database backup and restore;
- witness ledger backup and restore under separate administration;
- terminal event truncation and local rollback;
- conflicting checkpoint / split-view simulation;
- witness quorum loss and recovery;
- signer rotation, revocation and compromise simulation;
- operator separation and two-person recovery;
- export and offline verification of receipts.

## 7. Production blockers

The following remain mandatory before production:
- independent durable witness implementations and evidence of separate administration;
- production signer provider, non-exportable key custody and ceremony;
- approved numeric checkpoint cadence and maximum freshness by risk tier;
- approved retention periods, jurisdiction, residency and lawful evidence-access review;
- authenticated tenant/stream provisioning before multi-tenant use;
- operational alert delivery, incident ownership, tested backup/recovery and service-level objectives;
- event coverage inventory for every protected side effect.

**Current pilot implementation does not satisfy these production requirements.**
