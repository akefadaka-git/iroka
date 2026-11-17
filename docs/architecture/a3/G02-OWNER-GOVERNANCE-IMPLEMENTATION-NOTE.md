# A3 G02 Owner-Governance Implementation Note

- Gene: `g02.owner-governance`
- Additive schema version: v1.1.0
- Execution: read-only approval/register evidence evaluation

## Implemented controls

1. Adds a read-only detached Owner-signature verification method to the existing Owner key verifier. It checks canonical Owner subject, configured key identity, key validity at issuance and evaluation, signature integrity and live key revocation without consuming an approval or mutating the store.
2. Approval payload uses canonical JSON with an explicit domain-separation prefix and binds Owner ID, decision ID, decision, decision-content digest, exact scope, nonce, contract version and UTC validity interval.
3. Approval digest is recomputed and compared with the supplied digest.
4. A signed decision-register snapshot binds sequence and entries; duplicate decision IDs/nonces, missing or ambiguous entries, stale sequence, revoked/superseded entries and supersession links are rejected.
5. Scope must be canonical, unique and identical across request, approval and register entry.
6. UTC timestamps, interval ordering, maximum TTL, snapshot validity and trusted Owner key validity are checked.
7. Non-overridable safeguard conflicts are reported explicitly. `execution_authorized` is always false, including for a valid Owner approval.
8. The evaluator is read-only and does not create authority, consume approvals, grant capabilities or execute actions.

## Test boundary

Only synthetic Owner keys, approval records and register snapshots are used. Production Owner-key custody, live decision-register integration and A5 deployment are not performed by this increment.
