# G02 — Governance Contract v0.1

## Purpose
Define how authority and approval evidence is checked without allowing a model, agent or tool to create authority.

## Approval binding
An approval must bind:
- approval identifier;
- authenticated approver;
- requesting subject;
- exact capability and resource;
- exact policy version;
- expiry and revocation status;
- separation-of-duties and delegated-authority rules.

Any mismatch is a rejection. Expired, unknown, revoked or unverifiable approval evidence cannot authorize an operation.

## Owner authority
The Owner trust root and emergency authority must be established through a separate, protected provisioning ceremony. No default Owner credential, embedded secret or model-generated authority is permitted.

## Deliberate limitations
This contract defines types and verifier obligations. It does not yet implement signed approvals, durable governance storage, Owner key provisioning, quorum, delegation or revocation.
