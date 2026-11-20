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
256 premises per rule, 32 distinct source identifiers per asserted fact, and a
three-second reasoning deadline. Atoms, rule identifiers and source identifiers are
limited to 256 UTF-8 bytes. The deadline is checked at reasoning-loop/rule boundaries and
during premise evaluation. A run reports one of `FixedPoint`, `Deadline`,
`StepBudget` or `FactBudget`. Only `FixedPoint` is a complete closure:
`ReasoningReport::is_complete()` returns true only for that stop reason, while
`is_partial()` identifies every deadline or budget stop. Consumers must not treat
facts in a partial report as an exhaustive knowledge state. The configured deadline is cooperative: checks occur during inference and while
materializing the facts/contradiction report. If it expires during report construction,
the returned report may contain only a partial facts/contradictions snapshot and is
marked `Deadline`; consumers must use `is_partial()` and must not treat that snapshot
as exhaustive. This is not a hard real-time or preemptive cancellation guarantee.
Unknown evidence remains distinct from refutation, and contradictory positive/negative
evidence is reported explicitly.

### Caller-side resource boundary (R-03)

Engine limits apply to data retained by the reasoner and work performed during inference.
They cannot retroactively bound memory a caller has already allocated before invoking
the API. In particular, Literal::positive/negative own a String immediately, and the
public Rule type contains a caller-allocated Vec<Literal>. add_fact validates an
already-created Literal; add_rule rejects an oversized premise vector but receives that
vector only after it has been allocated.

Safer incremental entry points are provided:
- Literal::try_positive and Literal::try_negative validate a borrowed atom's UTF-8 byte
  length and blankness before cloning it into an owned String.
- add_fact_with_source accepts a borrowed source ID, checks its 256-byte limit before
  cloning it into engine-owned provenance metadata.
- add_rule_from_iter consumes premises incrementally and stops after observing the first
  item beyond max_rule_premises. Use a lazy iterator rather than first collecting an
  untrusted input into Vec<Literal>.
- add_rule also caps retained rule IDs at 256 UTF-8 bytes. The length check precedes
  whitespace scanning, duplicate comparisons and retention.

These APIs bound engine-side copies and collections; they do not make an untrusted
transport/parser safe by themselves. Any upstream ingestion boundary must enforce a raw
request/body byte limit before parsing, cap fact/rule/premise counts before collection,
validate atom and identifier lengths before cloning, and apply aggregate/concurrency
quotas plus request deadlines. max_duration covers reasoning and report materialization,
not caller parsing, object construction, add_fact, or add_rule validation. NCE-01 has no
external ingestion service, so those upstream controls remain an integration requirement.

The dedicated NCE-01 suite contains 36 tests covering multi-step closure, deterministic
rule ordering, cyclic and adversarial rule order, all 64 directed three-node graph
topologies against a reference reachability calculation, exhaustive contradiction
reporting, premise/fact/rule/step/time boundaries, failed-insertion atomicity, and a
512-fact/512-rule workload, source-ID validation and limits, multiple assertion sources,
alternative rule witnesses, and witness behavior for already-asserted conclusions. Deadline
tests exercise both a full 256-premise scan and report materialization interruption.

## NCE-01 provenance contract

- Every asserted fact is represented in `ReasoningReport::asserted_facts`, including
  assertions made through the compatibility `add_fact` method, whose `source_id` is
  `None`.
- `add_fact_with_source` accepts an opaque caller-supplied source identifier. It is
  metadata only: NCE-01 does not authenticate the source, validate its trustworthiness,
  timestamp the evidence, or prove the source's claims.
- Repeated identical assertions are idempotent. Distinct source identifiers for one fact
  are retained up to `max_sources_per_fact`; the default is 32. The fact itself is still
  counted once against `max_facts`.
- `ReasoningReport::derivations` retains one deterministic witness for each distinct
  (conclusion, rule ID) pair whose premises are satisfied. Alternative rules supporting
  the same conclusion are retained, including rules supporting a fact that was already
  asserted or derived. Each rule contributes at most one witness per reasoning call.
- A derivation witness records the rule ID and the rule's complete premise vector. This is
  a bounded witness set, not a recursively expanded proof DAG: premises may themselves
  have derivations, and cycles can appear across witness records.
- A rule witness is recorded only after its conclusion is already present or has been
  successfully inserted. A failed fact-budget insertion does not create a false witness.
- Source identifiers and derivation records are provenance metadata, not authenticated
  evidence, trust scores, chronology, or authorization.
Exact-SHA verification on 2026-11-19:
- Verified working-branch source SHA: `b027860e5714463ce1ad51cdec1ef347b803cd81`.
- Native Cognition CI #132: PASS — [Run 44597222447](https://github.com/akefadaka-git/iroka/actions/runs/44597222447); formatting, complete workspace tests and cognition Clippy passed.
- Rust kernel verification #2230: PASS — [Run 44597222456](https://github.com/akefadaka-git/iroka/actions/runs/44597222456); formatting, workspace compilation, no-default-features check, complete workspace tests and full-workspace Clippy passed.
- Recorded totals: 50 cognition-crate tests (36 NCE-01 forward-reasoning and 14 backward-reasoning), 71 kernel tests and 2 authorization-contract tests.


## R-03 aggregate resource ceilings (2026-11-20)

Caller-supplied `EngineConfig` values are now validated against hard ceilings; defaults are not merely recommendations. The accepted maxima are 10,000 inference steps, 10,000 facts, 2,000 rules, 256 premises per rule, 32 distinct source IDs per asserted fact, and 3 seconds for reasoning/report materialization. A zero value returns `ZeroBudget`; any value above these ceilings returns `ConfigLimitExceeded`.

Multiplicative limits are additionally constrained by aggregate retained-state budgets: at most 50,000 rule-premise entries across all rules and at most 50,000 distinct asserted-fact/source records across the reasoner. Both checks occur before mutation; rejected additions leave retained state unchanged. The per-rule and per-fact limits remain independently enforced. The aggregate rule-premise ceiling also bounds copied premise literals in derivation witnesses; the aggregate assertion ceiling bounds provenance records copied into reports.

These are cardinality bounds, not a byte-exact heap/RSS guarantee. B-tree/vector/string allocator overhead, capacity growth, sorting temporaries, caller-owned input allocations, iterator internals, and returned reports held by callers are outside a strict process-memory guarantee. Atom, rule ID, and source ID payloads remain capped at 256 UTF-8 bytes. A conservative payload-only retained-state envelope is therefore calculable, but must not be presented as a precise resident-memory ceiling. The crate has no network/file ingress layer; upstream request-size, parse-time, concurrency, and aggregate process-memory controls remain integration requirements.

Regression coverage: caller configuration above each representative hard ceiling is rejected; aggregate premise overflow is rejected atomically; aggregate assertion overflow is rejected atomically. Exact-commit CI evidence is recorded only after the corresponding workflow runs complete.


### Aggregate payload calculation and exact-SHA verification

At the hard maxima, the engine-owned retained UTF-8 string payload has a cardinality-derived upper bound of approximately **42.0 MB (decimal)**: facts 2.56 MB (10,000 × 256 bytes), asserted-fact/source records 25.60 MB (50,000 × [256-byte atom + 256-byte source ID]), rule IDs and conclusions 1.024 MB (2,000 × [256 + 256 bytes]), and rule premises 12.80 MB (50,000 × 256 bytes). These categories are counted independently even where logical values overlap because the engine stores copies.

A fully materialized report can add up to approximately **44.544 MB** of string payload: 2.56 MB facts, 25.60 MB asserted records, 2.56 MB contradiction pairs (at most 5,000 pairs), and 13.824 MB derivation witnesses (2,000 × 512-byte conclusion/rule-ID payload plus 50,000 × 256-byte premise payload). The temporary derivation-deduplication key set can add approximately 1.024 MB. Thus a conservative combined engine + report + derivation-key string-payload envelope is about **87.6 MB**, before allocator/container metadata, node pointers, vector capacity slack, alignment, transient sorting/allocation costs, and caller-held copies. This is a defensible payload bound, **not** a process RSS or total heap guarantee.

The reasoning deadline applies to reasoning and report materialization, not input parsing or construction. `Rule` and `Literal` compatibility APIs receive already-allocated caller values; validate borrowed atoms with `Literal::try_positive`/`try_negative` before ownership, use the lazy premise iterator, and enforce raw input size and concurrency limits at any future ingress boundary. No network/file ingress service exists in this crate, so those upstream limits remain integration work.

Exact-SHA verification for implementation commit `bcee3f5d5557361ec8349919171406094b69854d`:
- Native Cognition CI push Run #148: PASS — https://github.com/akefadaka-git/iroka/actions/runs/44649515635
- Native Cognition CI PR Run #149: PASS — https://github.com/akefadaka-git/iroka/actions/runs/44649522569
- Rust kernel verification Run #2238: PASS — https://github.com/akefadaka-git/iroka/actions/runs/44649522520
- Test totals: cognition 53 passed; kernel 71 passed; authorization-contract 2 passed; zero failures.
- Formatting, workspace compile/check, complete workspace tests, production-feature bypass check, and Clippy: PASS.
