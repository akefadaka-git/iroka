# G01 — Identity Contract v0.1

## Purpose
Establish the identity boundary between untrusted request data and a principal that has passed a trusted credential verifier.

## Contract
- Every assertion identifies issuer, subject, audience, expiry and credential ID.
- Expired, malformed, wrong-audience or failed credentials are rejected.
- The verifier adapter must check signature/integrity, issuer trust, revocation, assurance level and credential lifecycle.
- Authorization requests must bind exactly to the verified subject.
- Subject strings supplied by agents or callers are never identity proof.

## Trust boundary
The IdentityVerifier implementation is trusted computing base code. It must be independently reviewed and tested. This initial contract does not implement JWT, OIDC, mTLS or hardware-backed identity verification.

## Required follow-up
Implement a concrete verifier with pinned algorithms, key rotation, issuer allowlists, revocation behavior, clock-skew policy, audience separation and negative-path tests. Never silently accept unsigned or algorithm-downgraded credentials.
