# NCE-01 Independent Review Package

**Review status:** PREPARED — independent review NOT YET PERFORMED  
**Review target (immutable source revision):** `a8cb72825eb12beefc40fcd63e3c7eae5f49d8f2`  
**Repository:** `akefadaka-git/iroka`  
**Working branch / PR:** `feat/native-cognition-a3` / [PR #130](https://github.com/akefadaka-git/iroka/pull/130)  
**Review scope:** NCE-01 only — propositional forward inference, contradiction semantics, provenance, resource limits and deadline behavior.  
**Governance:** PR #130 must remain OPEN and DRAFT. No merge, deployment, production activation, NCE-02 expansion or acceptance of review findings is implied by this package.

## 1. Purpose and reviewer independence

This package enables an independent Rust, logic-programming and security reviewer to assess NCE-01 without relying on the implementation author's conclusions. It records the exact source target, reproducible CI evidence, review questions, preliminary risks and required verdict format.

The CI runs are implementation verification, not independent security review. The preliminary observations in §7 are review leads, not final findings. The reviewer should independently inspect the pinned source and reproduce tests before reaching conclusions.

**Do not silently substitute the current PR head for the pinned source.** If the source changes, record the new SHA, compare the diff, and decide whether the review must be repeated.

## 2. Pinned source and evidence

### Source identity

- Commit: `a8cb72825eb12beefc40fcd63e3c7eae5f49d8f2`
- Source file: `crates/iroka-cognition/src/lib.rs`
- Source blob at the pinned revision: `1c6e8df3e02962ab63ab778d445a5822bf4817cf`
- NCE-01 implementation: `NativeReasoner`, `EngineConfig`, `Literal`, `Rule`, `QueryResult`, `Derivation`, `Contradiction`, `ReasoningReport`.
- NCE-01 source areas: validation and insertion at approximately lines 153–195; query semantics at 198–209; forward reasoning and report construction at 211–290; atom validation at 292 onward; NCE-01 tests begin in the test module.

### Exact-SHA CI evidence

Both workflows completed successfully for the pinned source SHA:

| Workflow | Run | Result | Evidence |
|---|---:|---|---|
| Native Cognition CI | #68 | PASS | [Run 44589981910](https://github.com/akefadaka-git/iroka/actions/runs/44589981910) |
| Rust kernel verification | #2199 | PASS | [Run 44589980137](https://github.com/akefadaka-git/iroka/actions/runs/44589980137) |

Recorded log totals: 38 cognition tests, 71 kernel tests and 2 authorization-contract tests passed. Formatting, compilation, production-feature check and Clippy passed in the kernel workflow; formatting, workspace tests and Clippy passed in Native Cognition CI.

These results establish CI status only. They do not establish logical soundness, completeness, resistance to every adversarial input, production suitability or independent approval.

### Reproduction

From a clean checkout of the pinned revision:

```sh
git checkout --detach a8cb72825eb12beefc40fcd63e3c7eae5f49d8f2
cargo fmt --all -- --check
cargo test -p iroka-cognition
cargo clippy -p iroka-cognition --all-targets -- -D warnings
cargo test --workspace
```

Also inspect the repository workflow definitions and reproduce the production-feature check used by Rust kernel verification. Record Rust toolchain version, host/target, command output and any environment deviations. Do not treat a local run on a different toolchain as a replacement for the pinned CI evidence.

## 3. System model and intended semantics

NCE-01 is a deterministic propositional forward-chaining engine. It stores positive and explicitly negative literals, applies rules whose complete premise lists are present, and repeats passes until no new fact is derived or a configured stop condition occurs.

It does **not** implement negation-as-failure, closed-world inference, probabilistic confidence, default logic or classical explosion. A negative literal is explicit evidence, not the absence of a positive literal.

For a queried literal (p), the intended four outcomes are:

| Evidence in fact set | Query result |
|---|---|
| (p) only | `Entailed` |
| complement of (p) only | `Refuted` |
| neither | `Unknown` |
| both | `Contradicted` |

The reviewer must verify that this table holds for both directly inserted and rule-derived evidence, including when the query itself is negative.

## 4. Review scope and required checks

### A. Inference soundness and fixed-point behavior

1. Confirm every inserted conclusion has a rule whose complete premise set was present at the time of derivation.
2. Confirm rules are applied deterministically, including when inserted in different orders.
3. Verify that cycles terminate at a fixed point and cannot produce duplicate facts or unbounded duplicate derivations.
4. Verify multi-step chains, multiple rules with the same conclusion, rules whose conclusion is already a fact, and rules whose premises include explicit negative literals.
5. Independently compare small generated rule/fact systems against a simple reference evaluator. Include reordered rules, cycles, disconnected components and mutually dependent rules.
6. Clarify the contract for a rule whose premises contain duplicates. The current representation permits duplicate premises; confirm that this is semantically harmless and does not distort accounting.
7. Determine whether the implementation promises only sound derivation or also completeness when a budget is reached. A budget stop must never be presented as a fixed point.

**Required verdict:** PASS / PASS WITH CONDITIONS / FAIL, with counterexamples and reproducible tests.

### B. Contradiction semantics

1. Verify all positive/negative pairs are reported exactly once, in stable order.
2. Verify contradictions can be introduced directly or derived through rules.
3. Verify a contradiction in one atom does not cause unrelated conclusions to be inferred (no explosion).
4. Verify querying a negative literal applies the same four-valued semantics with the polarity reversed correctly.
5. Verify budget/deadline termination still reports contradictions among the facts accumulated so far, while not implying the knowledge base is complete.
6. Confirm API documentation distinguishes explicit negative evidence from negation-as-failure and from absence of evidence.

**Required verdict:** PASS / PASS WITH CONDITIONS / FAIL.

### C. Provenance integrity

1. For every derived fact, verify that its recorded rule ID and premise list exactly match an accepted rule.
2. Verify the recorded premises were present when the conclusion was derived and that deterministic rule ordering makes the selected derivation reproducible.
3. Test chains where a premise is itself derived, multiple derivations exist for the same conclusion, and a contradiction is derived through separate paths.
4. Verify one deterministic witness is retained for each satisfied (conclusion, rule ID) pair, including alternative rule IDs supporting an already-known conclusion.
5. Verify asserted facts are represented separately from derived witnesses, including legacy assertions without a source ID and source-aware assertions.
6. Verify source identifiers are bounded, deduplicated and treated as opaque metadata, not authenticated identity, trust, chronology or evidence quality.
7. Verify a witness is not recorded when fact-budget exhaustion prevents a new conclusion from being inserted.
8. Verify no witness refers to a nonexistent rule or a premise that was not present when the rule fired.

**Required verdict:** PASS / PASS WITH CONDITIONS / FAIL, including whether provenance is a minimal witness or audit-grade lineage.

### D. Resource exhaustion and input validation

Review every configured and implicit bound:

- `max_inference_steps` (default 10,000)
- `max_facts` (default 10,000)
- `max_rules` (default 2,000)
- `max_rule_premises` (default 256)
- `max_sources_per_fact` (default 32)
- source identifier byte length (256 bytes)
- `max_duration` (default three seconds)
- atom byte length (256 bytes)
- non-empty atom/rule ID and non-empty rule premise list

Required checks:

1. Zero values are rejected for all configured resource limits.
2. Exact-limit values are accepted and one-over values rejected without mutating engine state.
3. Duplicate fact insertion at capacity remains idempotent; a new fact at capacity fails.
4. Rule insertion failures do not consume rule IDs, append partial rules or alter ordering.
5. Step-budget and fact-budget exhaustion are distinguishable from fixed-point completion.
6. Test large but permitted fact/rule/premise counts, repeated invocations, and adversarially ordered rules.
7. Inspect allocation behavior and complexity. The engine bounds retained facts, rules and premises, but callers construct owned strings/vectors before passing them to the API; state clearly what memory is and is not bounded by this component.
8. Check integer and duration edge cases, including `Duration::MAX`, very large counters and report-size growth.

**Required verdict:** PASS / PASS WITH CONDITIONS / FAIL, with a table of tested boundary values and observed outcomes.

### E. Deadline and bounded-stop behavior

1. Verify deadline checks occur before reasoning, between rule evaluations and inside premise evaluation.
2. Verify a long rule cannot monopolize execution without deadline checks.
3. Verify the deadline stop does not derive the conclusion of a rule whose premise scan was interrupted.
4. Measure worst-case runtime near configured maxima on a constrained target, not only a developer workstation.
5. Verify deadline checks during report materialization. If report generation is interrupted, ensure the stop reason is `Deadline` and the returned facts/contradictions are explicitly partial.
6. Verify `elapsed_micros` includes the intended work and that deadline reporting is not confused with hard real-time cancellation. The implementation uses cooperative elapsed-time checks; it does not provide preemptive cancellation.
7. Verify repeated calls after a budget/deadline stop have documented semantics and cannot be mistaken for one continuous bounded session.

**Required verdict:** PASS / PASS WITH CONDITIONS / FAIL. Include maximum observed duration, test host/target and whether report finalization is inside the deadline contract.

## 5. Required adversarial test matrix

At minimum, independently run or add tests for:

| Test family | Minimum cases |
|---|---|
| Rule soundness | Missing one premise; all premises present; negative premise; conclusion already present |
| Rule ordering | Reverse insertion order; lexical ID order; same conclusion from multiple rules |
| Cycles | Self-loop; two-rule cycle; longer cycle; cycle with an unreachable component |
| Contradictions | Direct; derived; both sides derived; multiple contradictory atoms; query negative literal |
| Provenance | Chain; alternative derivations; already-asserted conclusion; source metadata; source bounds; premise not present |
| Budgets | Exact and one-over facts/rules/premises/steps; zero config; no partial mutation |
| Deadline | Before first rule; between rules; during maximum-premise scan; during final report construction |
| Scale | Configured maximums; near-maximum combinations; repeated reasoning calls |
| Determinism | Same input built in multiple insertion orders; byte-for-byte equivalent semantic report |

The existing test suite includes a 64-topology three-node reachability comparison, a generated adversarial chain, a 256-premise deadline test and a 512-fact/512-rule workload. The reviewer should independently validate their assertions and supplement any missing cases above.

## 6. Threat and misuse boundaries

The review must explicitly consider:

- Untrusted or malformed rule/fact input.
- Excessive input construction before engine validation.
- Contradictory or misleading evidence being misinterpreted as certainty.
- Partial knowledge after budget/deadline stops being treated as complete.
- Provenance being overstated as source-authenticated or audit-grade.
- Deterministic ordering being mistaken for truth or evidence quality.
- Resource exhaustion caused by many rules, large premise lists, repeated invocations or report generation.
- Downstream components treating a reasoning result as authorization.

NCE-01 output is a reasoning result, never an authorization decision. Kernel authority and policy enforcement remain outside and above this engine.

## 7. Preliminary review leads — NOT independent findings

These points were identified during package preparation and must be confirmed, rejected or refined by the independent reviewer:

| ID | Area | Preliminary observation | Reviewer disposition required |
|---|---|---|---|
| R-01 | Provenance | Initial-fact source metadata and alternative rule witnesses were missing. | INTERNAL REMEDIATION IMPLEMENTED on the working branch; verify the contract and regression tests below. Independent review remains pending. |
| R-02 | Deadline | The report finalization path originally lacked deadline checks. | INTERNAL REMEDIATION IMPLEMENTED on the working branch; exact-SHA CI verification pending. |
| R-03 | Resource accounting | Configured limits bound retained engine state and inference work, but do not bound memory already allocated by callers to construct input strings/vectors. | Document API boundary and any required upstream input-size controls. |
| R-04 | Partial result semantics | A report can contain facts and derivations accumulated before `Deadline`, `StepBudget` or `FactBudget`. | Confirm all consumers must treat such reports as incomplete, not as a completed closure. |
| R-05 | Duplicate premises | Rule premises are stored as a vector and are not deduplicated. | Confirm intended logical and accounting semantics; test repeated literals. |

These are review questions, not declarations of defects. No severity or remediation is assigned until independently assessed.

### 7.1 R-01 internal remediation and binding provenance contract

The working-branch implementation defines the following bounded NCE-01 contract. This is an internal engineering disposition, not an independent reviewer verdict:

1. **Asserted-input record:** every asserted fact is exposed through `ReasoningReport::asserted_facts`. The compatibility `add_fact` method records `source_id: None`; `add_fact_with_source` records an opaque caller-supplied source identifier.
2. **Source identifier semantics:** source IDs are caller-provided labels only. The engine does not authenticate the source, assess trust, timestamp the evidence, or validate the truth of a claim. Empty IDs and IDs over 256 UTF-8 bytes are rejected.
3. **Bounded source multiplicity:** identical `(fact, source_id)` assertions are idempotent. Distinct source IDs per fact are capped by `EngineConfig::max_sources_per_fact` (default 32). The fact counts once against `max_facts`.
4. **Alternative derivation witnesses:** the report retains one deterministic witness per distinct `(conclusion, rule_id)` pair whose complete premises are satisfied. Different rules supporting the same conclusion are retained, even when the conclusion was already asserted or derived. A rule is recorded at most once per `reason()` call.
5. **Witness integrity:** the witness is recorded only after the conclusion is already present or successfully inserted. If fact-budget exhaustion prevents insertion of a new conclusion, no witness is emitted for that failed derivation.
6. **Scope limitation:** the report is a bounded set of direct rule witnesses, not a recursively expanded proof DAG or complete proof-history database. Witnesses refer to the accepted rule's full premise vector; premise derivations can be followed through other witnesses. Cycles can occur across witness records.
7. **Trust boundary:** source IDs and rule witnesses are provenance metadata, not authenticated evidence, source reputation, trust scores, chronology, audit-grade chain of custody, or authorization.

Regression tests added on the working branch cover multiple independent rules for one conclusion, support for an already-asserted conclusion, asserted facts with and without source IDs, source ID validation, per-fact source bounds, and cycle witness behavior. These tests still require fresh exact-SHA CI execution.

## 8. Out-of-scope components

- NCE-02 backward chaining, unification and proof search.
- Constraint, arithmetic, temporal, causal, probabilistic or natural-language reasoning.
- Knowledge ingestion, evidence trust, durable memory, planning, learning, perception, orchestration and agent execution.
- Kernel authorization, deployment, production data and operational readiness.

The cognition crate currently contains a separate backward-reasoning module. Its presence does not expand this NCE-01 review. Reviewers should avoid treating NCE-02 tests as NCE-01 evidence.

## 9. Reviewer report template

The independent reviewer should return a signed or attributable report containing:

1. Reviewer name/organization, relevant expertise, date and independence/conflict statement.
2. Exact repository, source SHA and source blob SHA reviewed.
3. Toolchain, environment, commands and reproducibility results.
4. Per-area verdicts for inference soundness, contradiction semantics, provenance, resource exhaustion and deadline behavior.
5. Findings with unique ID, severity (Critical/High/Medium/Low/Informational), affected file/line, exploit or failure preconditions, impact, reproducible evidence and remediation.
6. Explicit treatment of R-01 through R-05.
7. Tests added or run, including failures and deviations from this package.
8. Residual risks and conditions for acceptance.
9. Overall recommendation: ACCEPT, ACCEPT WITH CONDITIONS, or REJECT.
10. Reviewer identity/signature or verifiable review record.

A finding is not closed by a code change alone. It requires a linked fix, regression test, fresh exact-SHA CI evidence and reviewer confirmation where the finding affects the review verdict.

## 10. Governance and closure gates

- PR #130 remains OPEN and DRAFT while independent review is pending.
- Do not merge, deploy, activate in production or mark NCE-01 independently reviewed based on this package.
- Any reviewer finding that requires code changes must be handled on the authorized feature branch, followed by fresh exact-SHA verification and a review delta.
- The pinned source review is complete only when the reviewer report is received and all blocking findings have a documented disposition.
- Any Owner decision to accept conditions, close the review gate, merge or proceed to another workstream is a separate explicit decision.

**Current status:** PACKAGE PREPARED / INDEPENDENT REVIEW PENDING / OWNER DECISION PENDING.
