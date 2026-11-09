# Governed Kernel — Foundation Contract v0.1

**Status:** Initial implementation slice; not production authorization.

## Scope

The first Rust crate provides a deterministic policy evaluator with four outcomes: ALLOW, DENY, REQUIRE_APPROVAL and ESCALATE.

It validates request shape, checks capability membership, enforces a maximum risk level, and gives the emergency-stop condition precedence over normal policy evaluation.

## Deliberate limitations

This slice does not authenticate principals, verify signed approvals, load or sign policies, persist audit events, issue execution grants, revoke grants, isolate tenants, or execute tools. It is not safe to expose as a production authorization endpoint.

A request's subject string is descriptive input, not proof of identity. A policy instance is an in-memory value, not an approved or signed policy artifact. Approval-required outcomes remain non-executable until a separately governed approval and grant-verification path exists.

## Required next contracts

1. G01 identity: authenticated principal and service identity assertions.
2. G02 governance: versioned policy lifecycle, Owner authority and approval records.
3. G11 assurance: append-only audit/evidence interface and correlation identifiers.
4. G08 orchestration: typed decision request/response boundary.
5. G09 execution: short-lived, scope-bound, single-use execution authorization.

## Security invariant

No model, agent, plugin, tool or external document may create authority. Missing, invalid, expired, revoked or indeterminate authorization evidence must prevent protected side effects.

## Verification status

Unit and integration tests are authored in the repository. They have not yet been executed in a Rust toolchain. No production-readiness claim is made.
