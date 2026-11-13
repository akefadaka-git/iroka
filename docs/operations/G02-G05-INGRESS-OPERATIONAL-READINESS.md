# G02/G05 Ingress and External Checkpoint Readiness

**Branch:** `feat/g02-postgres-command-processor-a3`  
**PR:** #80  
**Disposition:** IMPLEMENTATION IN PROGRESS — NOT PRODUCTION READY

## Implemented on this branch

- `PostgresOwnerSignatureVerifier` now implements the G02 ingress authorization port. Every ingress authorization reads the subject/tenant membership projection from PostgreSQL primary state and rejects missing, inactive, or non-positive-version membership.
- The same adapter reads the singleton emergency-stop projection and rejects an active stop or malformed stop state. Database/query failures map to `AuthorityUnavailable`.
- The G01 credential verifier uses the same PostgreSQL authority instance as its `RevocationChecker`, so credential and signing-key revocation failures deny access.
- The G09 resolver independently re-reads the current signed policy head, policy/key revocations, emergency-stop state and tenant membership. The ingress path therefore performs G01, G02 and G09 checks; external effects re-run those checks through `execute_external`.
- `authorize_http` accepts only a single non-empty `Authorization: Bearer <credential>` value and rejects absent, malformed, whitespace-containing, or alternate-scheme values.
- Added synthetic ingress denial tests for missing/invalid credentials, revoked credentials, inactive tenant membership, emergency stop, stale/denied policy and G01/G09 database unavailability.
- Added live PostgreSQL coverage for G02 membership denial and emergency-stop denial.

## Security and correctness boundaries

- The HTTP helper is an authentication-header boundary, **not a production HTTP server**. No HTTP runtime, router, listener, TLS termination or request/response serialization has been integrated. These tests are ingress-service integration tests, not end-to-end socket-level HTTP tests.
- Durable activation remains fail-closed in the ingress adapter. It requires the separate canonical G01 reviewer-proof and G02 organization-authority composition; this adapter does not invent that decision.
- Owner public keys are still supplied through the current verifier constructor. Production root ceremony, root-registry reconciliation, HSM custody, key rotation and runtime secret provisioning are not evidenced.
- The G09 policy verifier's revocation lookup and resolver's policy transaction use separate PostgreSQL client operations. The resolver's SQL filters key revocation in its read transaction; external effects must continue to revalidate immediately before execution. A future unified transaction-bound verifier would strengthen snapshot consistency.
- PostgreSQL integration tests run against disposable GitHub Actions PostgreSQL 16 service containers only. They are not production database or operational evidence.

## Requested HTTP denial matrix

| Case | Expected result | Evidence status |
|---|---|---|
| Missing Authorization header | Deny | Synthetic test added |
| Invalid/malformed credential | Deny | Synthetic test added |
| Revoked credential | Deny | Synthetic revocation test added; live PostgreSQL credential-revocation HTTP path not yet wired end-to-end |
| Inactive tenant membership | Deny | Synthetic test + live PostgreSQL adapter test added |
| Emergency stop active | Deny | Synthetic test + live PostgreSQL adapter test added |
| Stale/expired policy | Deny | Synthetic stale-policy denial test; live expired-snapshot HTTP path pending |
| Database unavailable | Deny/defer | Synthetic G01/G09 unavailable tests; live outage/fault-injection test pending |

## Witness and immutable-retention adapters

The frozen E1 architecture deliberately selected no provider, witness operator, cloud account, region, retention service, or production key. The quorum verifier validates signed receipt formats and the 2-of-3 / two-domain rule, but it is not a network adapter and does not prove real-world administrative independence.

No real witness endpoint, independent operator, immutable-retention provider, KMS/HSM key, or credentials are present in the repository or current CI environment. Consequently, actual provider adapters and live end-to-end receipts cannot be honestly marked implemented or verified until the provider/operator topology and credentials are provisioned under the Owner's reserved selection/custody decisions. No paid account, deposit, secret, or production key was created by this work.

## Independent security review

- PR #80 currently has no submitted independent review.
- The branch commits inspected so far are authored by the repository owner account. Self-review is not an independent review.
- No external reviewer is assumed or fabricated. Independent security review remains **NOT PERFORMED**.

## Operational readiness evidence

| Control | Status |
|---|---|
| PostgreSQL 16 migration/replay/concurrency tests | Prior exact-head run passed; latest branch verification pending |
| G02 membership and emergency-stop adapter tests | Added; exact-head CI pending |
| HTTP denial-path tests | Added at ingress boundary; exact-head CI pending |
| Real HTTP listener/router/TLS | MISSING |
| Production database roles and least-privilege grants | NOT RUN |
| Production verify-full TLS connectivity | NOT RUN |
| Root ceremony/HSM and key rotation | NOT RUN |
| Three independent witness operators | NOT SELECTED / NOT PROVISIONED |
| Two independent immutable-retention domains | NOT SELECTED / NOT PROVISIONED |
| Read-back/retention-lock verification | NOT RUN |
| Backup restoration and disaster-recovery drill | NOT RUN |
| Monitoring, alert routing and operational SLOs | NOT RUN |
| Independent security review | NOT PERFORMED |
| Production deployment/activation | NOT AUTHORIZED |

## Release gate

Do not merge, deploy, or activate production based on this document. A4 closure requires a green exact-head CI run, real HTTP server integration and socket-level negative tests, independently provisioned witness/retention services with signed receipts and read-back evidence, independent security review, and production operational verification. A5 remains a separate approval.
