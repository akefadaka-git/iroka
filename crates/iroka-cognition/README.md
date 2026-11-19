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

## NCE-01 resource bounds and verification

Default limits are 10,000 inference-step evaluations, 10,000 facts, 2,000 rules,
256 premises per rule, and a three-second reasoning deadline. Atoms are limited to
256 UTF-8 bytes. The deadline is checked at reasoning-loop/rule boundaries and
during premise evaluation. A run reports one of `FixedPoint`, `Deadline`,
`StepBudget` or `FactBudget`. Only `FixedPoint` is a complete closure:
`ReasoningReport::is_complete()` returns true only for that stop reason, while
`is_partial()` identifies every deadline or budget stop. Consumers must not treat
facts in a partial report as an exhaustive knowledge state. The configured deadline
is cooperative and currently governs inference evaluation; contradiction collection
and report materialization follow the inference loop and are not hard-preempted by it.
Unknown evidence remains distinct from refutation, and contradictory positive/negative
evidence is reported explicitly.

The dedicated NCE-01 suite contains 24 tests covering multi-step closure, deterministic
rule ordering, cyclic and adversarial rule order, all 64 directed three-node graph
topologies against a reference reachability calculation, exhaustive contradiction
reporting, premise/fact/rule/step/time boundaries, failed-insertion atomicity, and a
512-fact/512-rule workload. The deadline test exercises a rule at the full 256-premise
limit and verifies that the engine stops during the premise scan without deriving its
conclusion.

Exact-SHA verification on 2026-11-19:
- Source SHA: `3146962ca6532eafb5a98d1ea5875520035f7289`
- Native Cognition CI #65: PASS (38 cognition tests; Clippy and formatting pass).
- Rust kernel verification #2198: PASS (38 cognition, 71 kernel and 2 authorization
  contract tests; workspace formatting, compilation and Clippy pass).
