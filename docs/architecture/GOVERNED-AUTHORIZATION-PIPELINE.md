# Governed Authorization Pipeline v0.1

## Processing order

1. Validate the subject credential through the trusted identity adapter.
2. Bind the credential subject to the requested subject exactly.
3. Evaluate emergency stop, request shape, capability and risk policy.
4. If policy requires approval, validate approval scope and expiry.
5. Authenticate the approver independently.
6. Ask the governance adapter to verify authority, authenticity, revocation and separation-of-duties rules.
7. Append an audit event.
8. If audit persistence fails, return ESCALATE regardless of the prior result.

## Decision semantics

- Invalid subject identity: DENY.
- Subject mismatch: DENY.
- Policy denial: DENY.
- Excessive risk or active emergency stop: ESCALATE.
- Missing approval: REQUIRE_APPROVAL.
- Invalid, expired, revoked or unverifiable approval: ESCALATE.
- Verified approval: ALLOW, subject to successful audit append.
- Audit append failure: ESCALATE.

## Critical limitation

An ALLOW is not permission to execute by itself. It is a decision result from this library. G09 must implement a separate, short-lived, scope-bound, revocable and single-use execution grant. No tool or agent may treat an ordinary model output or caller-supplied ALLOW value as an execution credential.

## Trusted adapters

IdentityVerifier, ApprovalVerifier and AuditSink implementations are trusted computing base components. They require concrete implementations, key-management design, durable stores, independent review, negative-path tests and operational recovery before production use.
