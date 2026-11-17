# A3 G03 Premise-Model Implementation Note

- Gene: `g03.premise-model`
- Additive schema version: v1.1.0
- Operation: deterministic normalization and explicit epistemic disposition only

## Implemented controls

1. Controlled epistemic status vocabulary: fact, assumption, hypothesis and unknown. The evaluator never promotes an assumption or hypothesis to fact.
2. Source-backed premises require structured source ID/type, SHA-256 content digest, provenance reference and observation-time evidence.
3. Source-unavailable and unknown-time states require explicit reasons and remain unresolved.
4. Source observation timestamps use strict UTC RFC3339-second form; future observations, invalid intervals and expired source references remain unresolved.
5. Confidence values must be finite and within [0,1].
6. Premise IDs and source IDs are unique; context mismatches are unresolved.
7. Normalization is deterministic whitespace normalization; source references and premise records are ordered deterministically.
8. Every input premise is represented exactly once in the disjoint normalized/unresolved output partition.
9. Canonical digest binds context, model version, normalization policy, normalized and unresolved partitions, provenance and version-bound evidence.
10. Model and normalization-policy versions must match explicit policy configuration.

## Verification boundary

No external source is fetched or independently authenticated by this pure evaluator. Source digests and provenance references are structurally checked and bound into the premise-set digest; authoritative source retrieval/verification remains an integration responsibility. No inference or execution is performed.


## Runtime integration status

The Rust evaluator is registered in the kernel public API and is exercised by the branch's dedicated test suite. It remains a pure deterministic normalization component; it does not fetch or authenticate external sources and does not execute inference rules.
