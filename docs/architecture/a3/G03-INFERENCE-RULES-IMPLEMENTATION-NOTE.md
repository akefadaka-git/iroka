# A3 G03 Inference-Rules Implementation Note

- Gene: `g03.inference-rules`
- Additive schema version: v1.1.0
- Evaluation: constrained declarative rule evaluation only

## Implemented controls

1. Only the literal `AXIOM` or `AND(premise_id,...)` grammar is accepted. No code, scripts, expression evaluation, interpolation or action dispatch is supported.
2. Rule definitions are canonicalized and domain-separated; each rule content digest is checked against an explicit immutable registry allowlist.
3. The rule-set digest is recomputed from sorted rule IDs and definition digests and must match policy and version-bound evidence.
4. Query digest, premise-set digest, premise-model version, evaluator version and confidence-policy version are explicitly bound.
5. Antecedents must exist, be unique and have epistemic statuses permitted by the rule. Unknown premises cannot support derivations.
6. Confidence is finite and in [0,1]; derivation confidence uses the conservative minimum of rule and premise support.
7. Conflicting templates for the same conclusion ID are rejected rather than selecting an arbitrary winner.
8. Every rule produces either an applied derivation trace or an explicit unsupported-step reason. Applied rule IDs are the exact union of successful traces.
9. Results include deterministic conclusion ordering, reproducibility digest and provenance/version evidence.
10. The evaluator does not execute rules or dispatch actions.

## Integration boundary

The premise-set digest is supplied from the preceding premise-model output and cross-checked against version-bound evidence; end-to-end runtime wiring remains a later integration task. This evaluator does not independently authenticate source documents or provide a general-purpose logic programming runtime.
