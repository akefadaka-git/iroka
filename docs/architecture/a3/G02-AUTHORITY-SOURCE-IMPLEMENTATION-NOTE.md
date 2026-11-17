# A3 G02 Authority-Source Implementation Note

- Gene: `g02.authority-source`
- Contract baseline: A2 v1.0.0, unchanged
- Additive A3 schema version: v1.1.0
- Execution: validation-only; no authority is created, granted or executed

## Controls implemented

1. Principal registration is signed by a key in the configured trusted snapshot and checked against live key revocation.
2. Registration binds the canonical authority identifier, source class, issuer/key and active/suspended/revoked status.
3. Mandate is separately signed and binds mandate reference, authority principal, source class, exact scope, delegation chain, validity interval, unbounded-expiry policy and evidence digests.
4. Source class must be permitted by explicit policy; claimed class alone is never proof.
5. Timestamps accept only canonical UTC `YYYY-MM-DDTHH:MM:SSZ`; calendar fields, interval ordering and current validity are checked.
6. Null expiry is accepted only when both policy and the signed mandate explicitly allow it.
7. Delegation chain must be unique and, for delegated authority, terminate at the exact delegate principal.
8. Scope must be non-empty, unique and exactly the scope authenticated by the mandate. Invalid/expired results expose no scope.
9. Provenance and version-bound evidence are digest-bound by the signed mandate.
10. The evaluator returns evidence only. It does not authorize actions or grant capabilities.

## Verification boundary

Synthetic test keys and records only. Production trust-root provisioning, live authority registry integration, real Owner credentials, merge, release and deployment are not performed by this increment.

Automated exact-head verification is required before this increment can be marked complete.
