# G11 — Assurance Contract v0.1

## Purpose
Make decisions traceable and prevent protected execution when decision evidence cannot be durably recorded.

## Audit event minimum
Each event binds event ID, correlation ID, subject, capability, resource, policy version, decision and occurrence time.

## Sink requirements
A production sink must provide durable append-only semantics, integrity protection, access controls, tamper evidence, retention policy, export and recovery. A successful in-memory write is not durable assurance.

## Fail-closed rule
If an audit append fails, a positive authorization result is converted to ESCALATE. Protected execution must not proceed.

## Deliberate limitations
This is an interface contract, not a production audit store. Hash chaining, signatures, durable database transactions, outbox/recovery, clock trust and external anchoring remain to be implemented and verified.
