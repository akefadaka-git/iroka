# IROKA Native Cognition

Native, model-independent symbolic reasoning primitives with bounded execution.

## NCE-01: Forward reasoning
- Deterministic propositional forward chaining.
- Explicit positive/negative facts and contradiction reporting.
- Provenance derivations and step/fact/rule/time budgets.

## NCE-02: Goal-directed reasoning
- First-order terms, variables and compound terms.
- Unification with an occurs check.
- Backward chaining over Horn clauses, including recursive rules.
- Standardized-apart rule variables for each search branch.
- Proof trees, answer substitutions and explicit deadline/step/depth outcomes.
- No external model, network, filesystem, tool or protected effect.

## Limitations
This remains a symbolic reasoning substrate, not general intelligence. Natural-language
understanding, probabilistic inference, constraint solving, causal/temporal reasoning,
knowledge ingestion, governed memory, planning, learning, perception and orchestration
remain separate workstreams. Three seconds is a budget, not a guarantee every problem
can be solved within that time.
