# Security review record — G02/G05/G11 A3 increments

**Review type:** Internal implementation review  
**Status:** PARTIAL — not an independent third-party security assessment  
**Scope:** PostgreSQL G02 Owner authority, G09 resolver, G05 ingress HTTP host, G02 outbox delivery, G11 checkpoint quorum and HTTPS provider clients.

## Controls reviewed

| Area | Implementation evidence | Assessment |
|---|---|---|
| Owner command signatures | Ed25519 verification over canonical signed command payloads; issuer/key identity, validity and current revocation checks | Implemented; production trust-root ceremony/HSM custody not verified |
| Policy snapshot signatures | JCS canonical payload, SHA-256 digest comparison, Ed25519 signature, Owner/key identity and expiry validation | Implemented; pinned production trust bundle not provisioned |
| Key revocation | Current G02 signing-key and credential revocation projections; command writes serialized with advisory lock | Implemented in test environment; production role/replica behavior not rehearsed |
| Replay and monotonicity | Unique command IDs, transactional replay check, policy epoch and membership/emergency-stop version monotonicity | PostgreSQL integration tests pass |
| Atomic authority event | Signed command, projections and outbox insert commit in one transaction | PostgreSQL integration tests pass |
| Outbox delivery | Database-clock leases, `SKIP LOCKED`, idempotency contract, acknowledgement digest, retry and append-only payload trigger | PostgreSQL integration tests pass; production sink not configured |
| G09 enforcement | Active policy, revocation, emergency stop and tenant membership; ingress revalidation immediately before effect | Implemented; resource-level policy semantics and real executor integration still require final system review |
| HTTP boundary | Loopback bind, proxy HTTPS assertion, host allowlist, bounded Content-Length, duplicate-header/transfer-encoding rejection and bounded worker queue | Unit tests pass; actual proxy and service deployment not exercised |
| Checkpoint evidence | Ed25519/JCS witness and retention receipts, 2-of-3 witnesses, two distinct WORM retention domains, offline verifier | Protocol and tests implemented; no real provider receipts |
| HTTPS providers | System-root TLS validation, hostname verification, no redirects, bearer token and bounded JSON response | Client implementation present; no external endpoint tested |

## Threat cases exercised

- Altered policy payload or signature.
- Expired, revoked or unknown Owner signing key.
- Replayed command ID and stale policy/membership/emergency-stop versions.
- Concurrent duplicate command submission and transaction rollback.
- Missing, stale or revoked policy and tenant membership.
- One failed witness with a valid 2-of-3 quorum.
- Tampered witness receipt and reused cross-role public key.
- Missing retention receipt, insufficient retention interval and non-WORM mode (protocol validation).
- Outbox duplicate claims, stale leases, acknowledgement and retry.
- Outbox payload mutation/deletion.
- HTTP duplicate headers, transfer encoding, malformed framing, invalid Host/proxy protocol and oversized input.
- HTTPS plaintext downgrade, credential forwarding tricks and redirect refusal.

## Findings and unresolved risks

1. **Production Owner trust root:** the code accepts injected/pinned trust material, but no production offline root ceremony, HSM-backed signing, rotation, backup or revocation runbook has been independently verified.
2. **Administrative independence:** the quorum policy rejects duplicate operator IDs and public keys. Those identifiers do not prove legal or operational independence. External evidence and third-party validation are required.
3. **Provider reality:** HTTPS adapters are protocol clients. No real witness or immutable-retention endpoints, WORM object-lock configuration, receipts, or long-term restore tests are available in this repository evidence.
4. **Service host integration:** the host is a reusable adapter, not a production executable. No concrete production executor, reverse-proxy config, process supervision, graceful shutdown, secrets manager or monitoring deployment has been verified.
5. **Database privileges:** production roles separating Owner command writes, resolver reads, outbox leases and schema migration privileges are not provisioned or tested.
6. **Independent review:** no independent reviewer has performed or signed a review of this implementation. This record is not a substitute.
7. **Operational verification:** PostgreSQL 16 CI is not production rehearsal. Failover, backup/restore, clock discipline, TLS rotation, alerting, incident response and provider outage drills remain NOT RUN.

## Closure decision

**A4 security/operational closure: NOT AUTHORIZED / NOT VERIFIED.**

The implementation is suitable for continued review and integration in draft PRs. Do not merge, deploy, sign, publish, or activate production services until the unresolved items above have evidence and the Owner separately authorizes the applicable stage.
