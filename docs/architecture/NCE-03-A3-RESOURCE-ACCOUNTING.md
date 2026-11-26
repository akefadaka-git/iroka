# NCE-03 A3 — Resource accounting contract

**Status:** A3 implementation record  
**Baseline:** A1 v1.0.0 and A2 VERIFIED-CLOSED  
**Implementation branch:** `feat/nce-03-constraint-solver-a3`

## Deterministic accounting

- **Variables:** one unit per declared variable; hard ceiling 128.
- **Constraints:** one unit per declared constraint; hard ceiling 512.
- **Expression terms:** one unit per term in each expression; hard ceiling 256 per constraint/objective expression. Duplicate variable references within one expression are rejected rather than silently combined.
- **Domain cardinality:** inclusive `upper - lower + 1`, computed in checked wider arithmetic; each domain and the sum across variables are capped at 1,000,000.
- **Semantic model bytes:** UTF-8 variable declaration identifier bytes + 16 bytes per variable (two i64 endpoints) + 8 bytes per expression constant + UTF-8 variable-reference bytes plus 8 coefficient bytes per term + one byte per relation and one byte for an objective direction. Objective expression is included. Checked additions enforce 1 MiB while normalizing. This is a deterministic semantic-size measure, not Rust heap/RSS measurement; caller-owned allocations made before `solve` are outside this accounting boundary.
- **Search nodes:** one unit each time the DFS enters a search state, before propagation; hard ceiling 100,000. Variable selection uses the smallest remaining domain, identifier-lexical tie-breaking, and ascending value order. Each recursive branch restores its full parent-domain snapshot before trying a sibling.
- **Propagation operations:** one unit for each global constraint interval-feasibility check and one unit for each constraint/variable bound-tightening attempt. Deterministic passes repeat until no bound changes; hard ceiling 1,000,000. Equality, less-or-equal and greater-or-equal constraints tighten inclusive integer bounds using exact floor/ceiling division; disequality prunes only when the expression interval is exactly `[0, 0]`. If the interval includes zero and at least one nonzero value, interval bounds alone cannot prune it. A constraint is pruned only when its interval proves it impossible.
- **Time:** monotonic elapsed time from entry into search; checked at each search-state entry, each constraint evaluation, and each value branch. Hard ceiling three seconds. This is cooperative deadline enforcement, not OS-level preemption.
- **Retained incumbents:** at most one assignment (the best verified incumbent); no solution list is retained.

## Arithmetic and stop semantics

All expression bounds and complete-assignment evaluations use checked signed i128 intermediates. Full-domain expression bounds are validated before search; overflow returns `ArithmeticOverflow` as a model error. Counters and byte accounting use checked additions. A resource stop is incomplete and cannot establish infeasibility or optimality. A verified objective incumbent at a stop is `FeasibleNotProvenOptimal`; without an incumbent it is `UnknownBudget`. A satisfaction assignment remains valid evidence even if later search work is stopped.

## Memory qualification

The engine stores interval pairs, normalized expressions, bounded recursion state, and at most one assignment. Input counts, term counts, identifier sizes, semantic bytes and search depth (at most 128 variables) are bounded. The semantic-byte limit is not a measured peak-RSS ceiling. Peak process memory and adversarial performance still require A4 measurement; no memory/RSS performance claim is made by this A3 record.

## A4 validation still required

Test every ceiling at and one beyond its boundary; independently enumerate small models; test arithmetic overflow, all relations, optimization ties, deterministic order permutations, deadline/node/propagation stops, and adversarial weak-propagation/high-branching models. Benchmark records must include model shape, counters, elapsed time and a reproducible RSS methodology.
