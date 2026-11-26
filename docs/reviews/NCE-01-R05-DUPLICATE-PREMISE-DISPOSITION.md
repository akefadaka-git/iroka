# NCE-01 R-05 Duplicate-Premise Disposition

**Status:** INTERNAL ENGINEERING DISPOSITION — pending exact-SHA CI verification  
**Scope:** NCE-01 propositional forward inference only  
**Related review item:** R-05 in `NCE-01-INDEPENDENT-REVIEW-PACKAGE.md`

## Decision

Duplicate premises are **accepted and retained**, not normalized or deduplicated.

For inference semantics, a rule body is a conjunction over the current fact set. Repeating a literal does not require multiple copies of that fact: if literal `p` is present, both `p` and `p, p` are satisfied; if `p` is absent, neither body is satisfied. Duplicate occurrences therefore have no additional logical force.

For resource accounting and provenance fidelity, every submitted occurrence remains in the rule's premise vector:
- each occurrence counts toward `max_rule_premises`;
- each occurrence counts toward the aggregate 50,000-premise ceiling;
- each occurrence is retained in the derivation witness in the accepted order;
- duplicates do not cause duplicate fact insertion or multiple witnesses for the same (conclusion, rule ID).

This choice preserves the caller's submitted rule representation and prevents duplicate-heavy input from bypassing cardinality budgets through implicit normalization. It does not assert that duplicate literals represent independent evidence.

## Verification added

`crates/iroka-cognition/tests/nce01_duplicate_premises.rs` adds integration tests for:
1. duplicate premises satisfying a rule from one matching fact while remaining visible in the derivation witness;
2. an absent duplicated premise not deriving a conclusion;
3. duplicate occurrences counting toward the exact 50,000 aggregate premise ceiling, with one-over rejection.

## Status boundaries

- R-05 semantic disposition: DEFINED.
- Regression tests: ADDED; CI verification pending.
- R-03 upstream ingress: remains PARTIAL / SPECIFIED ONLY until a concrete adapter is implemented and passes its integration gates.
- Independent review: NOT PERFORMED. This internal disposition does not close the independent review gate or authorize merge/deployment.
