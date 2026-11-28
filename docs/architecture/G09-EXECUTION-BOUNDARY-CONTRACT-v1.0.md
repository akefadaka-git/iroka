# G09 Execution-Boundary Contract v1.0

## Authority ownership
- G01 is the only source of `VerifiedPrincipal` and opaque `TenantContext`.
- G02 is the only source of current tenant membership, signed policy, Owner-key registry/revocation, and emergency-stop state.
- G09 evaluates current authority at the protected-effect boundary and holds a serialization guard through the effect.
- G11 durably records execution intent and outcome. Failure to append intent prevents the effect.

## Mandatory protocol
1. Accept only a G01-verified principal and G01-issued tenant context.
2. Bind subject and tenant to the request and compare membership version with current G02 state.
3. Reject stale/future context, inactive membership, expired/revoked policy, invalid/revoked Owner key, emergency stop, or unavailable authority.
4. Reload and cryptographically verify the current G02 policy through the canonical G02 verifier.
5. Evaluate the exact capability/resource at execution time. A previous Kernel `ALLOW` is never a grant.
6. Hold G02 SHARE locks through the protected effect. G02 mutation transactions requiring ROW EXCLUSIVE locks serialize before or after it.
7. Append G11 intent receipt before the effect and outcome receipt afterward, binding actor, tenant, capability, resource, membership version, correlation and event identity.
8. Consume each authenticated execution context once; replay is denied.

## Failure semantics
- Intent receipt failure: no protected effect.
- Outcome receipt failure: return `AuditUnavailable`; do not report the effect as successfully audited.
- The G09 PostgreSQL adapter fails readiness if any required G02 Owner-key registry/revocation table is missing.

## Production gates
The injected G02 verifier must validate canonical payload, digest, domain-separated signature, Owner subject, current root-verified Owner-key registry, key validity and revocation. Deployment additionally requires exact-SHA CI, live PostgreSQL concurrency verification, G11 integrity verification, key-custody evidence, and recovery tests.
