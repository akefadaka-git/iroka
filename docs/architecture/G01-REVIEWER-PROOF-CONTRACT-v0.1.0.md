# G01 Reviewer-Proof Contract v0.1.0

**Status:** A3 implementation candidate; production trust-adapter provisioning and G05 integration remain pending.

## Purpose

A verified login is not evidence that a person is the reviewer named in a governance record. Reviewer approval requires a separate Ed25519 proof whose signing key is authoritatively bound to the exact verified G01 principal and whose proof is scoped to one approval decision.

## Trust boundary

`ReviewerKeyBindingResolver` is a required trusted adapter. It must resolve the current key binding from the authoritative identity issuer/reviewer-key registry for the exact tuple `(issuer, subject, credential_id, key_id)`. It must return the public key, key validity interval, current credential/key revocation flags, and the time it checked that state. Missing bindings, stale checks, adapter errors and malformed keys fail closed. No local caller-supplied key or self-registration is accepted.

The resolver adapter is part of the trusted computing base. This repository change defines and tests its contract; it does not provision an issuer registry or establish that any real reviewer key is bound.

## Signed proof

The canonical JCS payload is signed under the domain-separated bytes:

`IROKA:G01:REVIEWER_PROOF:V1\0`

Required fields bind:
- unique proof ID;
- verified issuer, subject and credential ID;
- reviewer designation ID and reviewer signing-key ID;
- approval ID;
- tenant and organization;
- capability, resource and policy version;
- issue and expiry times.

Maximum proof lifetime is 300 seconds. The verifier checks exact principal tuple, exact expected approval scope, issue/expiry and key validity windows, current binding freshness (30 seconds), credential/key revocation, Ed25519 signature, and one-time proof consumption.

## Replay

The canonical security store atomically inserts `(issuer, credential_id, proof_id)` under a unique key. Duplicate consumption returns `Replay`; persistence failure fails closed. The current SQLite adapter is single-node only.

## G05 consumption contract

G05 must accept only `VerifiedReviewerProof`, not a boolean, reviewer ID string, ordinary `VerifiedPrincipal`, or caller-authored JSON claim. G05 must compare all returned fields to its own pending approval/designation record and consume the proof exactly once with its approval lifecycle. This G01 change does not yet wire G05 designation lookup, approval-state transition, or memory/consent activation.

## Explicit non-goals

This contract does not appoint reviewers, establish community authority, grant organization capabilities, approve Maale translations, or activate memory. Reviewer designation remains a separate G02/G05 governance decision. A3.4 community content review remains pending until authoritative human evidence is recorded.

## Verification status

The unit tests exercise identity binding, exact scope, signature integrity, time bounds, revocation and replay with a deterministic test adapter. Production assurance requires an independently reviewed authoritative `ReviewerKeyBindingResolver` implementation, live revocation guarantees, G05 integration tests, and A4 security review.
