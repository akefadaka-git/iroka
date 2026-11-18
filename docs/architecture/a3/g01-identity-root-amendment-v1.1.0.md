# G01 identity-root A3 bounded amendment v1.1.0

## Status and scope

This additive amendment closes the four semantic gaps recorded in A2 review `A2-G01-IDENTITY-ROOT-SEMANTIC-REVIEW-001` (G01-SEM-01 through G01-SEM-04). It changes only `g01.identity-root` schema and conformance artifacts. The frozen A2 v1.0.0 schemas remain intact. Genome scope remains 12 chromosomes and 36 genes.

## Input changes

- `key_material_ref` identifies the canonical public-key material in the trusted registry. The registry adapter must load the actual key bytes and recompute SHA-256; a caller-provided fingerprint is never proof.
- `key_fingerprint` is constrained to `sha256:` plus 64 lowercase hexadecimal characters and must equal the independently computed fingerprint.
- `algorithm_policy_id` and `algorithm_policy_version` bind the algorithm decision to an authenticated, versioned allowlist. A non-empty algorithm string alone is insufficient.
- Root status, activation epoch, provenance and version-bound evidence are reconciled against the authoritative registry record.

## Output changes

The v1.1.0 output evidence requires issuer-chain evidence, canonical key status, the algorithm-policy decision and a human-readable decision rationale. JSON Schema conditionals enforce that `verified=true` only accompanies `trust_decision=trusted`; `untrusted` and `revoked` require `verified=false`.

## Runtime rules

- Unknown root/issuer, unavailable key material, fingerprint mismatch, policy-version mismatch, unverifiable provenance or invalid version evidence fail closed.
- Revoked root or issuer-chain status yields `revoked/false`.
- Suspended roots, not-yet-active roots, untrusted issuer chains and disallowed algorithms yield `untrusted/false`.
- Only a canonical active root with trusted issuer chain, matching key fingerprint, allowed versioned algorithm policy and verified evidence yields `trusted/true`.
- The gene never grants authority, capability or permission to execute protected effects.

## Conformance

The v1.1.0 vector set covers one positive case and eight negative cases, including fingerprint mismatch, disallowed algorithm, unknown issuer, revoked issuer/root, suspended root, future activation and contradictory output. The static A3 audit checks schema identity, required fields, closed objects, evidence structure, output conditionals, vector uniqueness and fixed genome counts.

## Remaining production boundary

The registry adapter must be backed by Owner-provisioned canonical root records and authenticated issuer/key material. The evaluator's resolver trait is an integration boundary; tests using a deterministic fake registry are not production trust-root provisioning or live revocation evidence.
