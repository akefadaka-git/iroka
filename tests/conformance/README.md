# IROKA A2 conformance harness

The machine-readable 40-case inventory is `catalog.json`. The Rust CLI validates the catalog, executes only registered synthetic adapters, and emits a machine-readable exact-SHA disposition report plus a GitHub Actions step summary.

## Run in GitHub Actions

```sh
cargo run --locked -p iroka-kernel --bin iroka-conformance -- tests/conformance/catalog.json --output "$RUNNER_TEMP/iroka-a2-conformance-report.json"
```

The report captures repository, ref, exact commit SHA, workflow/run metadata, runner OS/architecture, harness version, timestamps, case results and status counts. The JSON is printed into retained workflow logs; the workflow step summary gives the gate disposition.

## Current adapter coverage

The harness currently registers nine synthetic kernel adapters, with eight expected PASS outcomes and one intentionally BLOCKED end-to-end case:

- `OS-BOOT-003`: durable trust-bundle rollback rejection.
- `OS-AUD-001`: the kernel audit sink failure escalation is exercised, but the full protected-effect adapter remains BLOCKED until the caller's side-effect suppression is proven end to end.
- `OS-TIME-001`: a future checkpoint timestamp is treated as a clock anomaly and high-risk actions are denied.
- `A1-TIME-001`: date-only temporal value remains distinct from an absolute instant.
- `A1-LOC-001`: Ethiopia technical profile resolves Amharic as its declared primary locale.
- `A1-LOC-002`: Ethiopia technical profile resolves Africa/Addis_Ababa.
- `A1-CUR-001`: Ethiopia technical profile resolves ETB.
- `A1-REG-001`: synthetic Kenya profile does not inherit Ethiopia calendar, time-zone, currency or script defaults.
- `A1-REG-002`: strict regional profile schema rejects an unrecognized kernel-authority field.

The other 31 catalog cases remain BLOCKED when their fixture is absent, or NOT RUN when a fixture exists but no executor is registered. Including the protected-effect integration gap, the expected disposition is 8 PASS and 32 BLOCKED. They are never silently marked PASS.

The nine synthetic fixtures are code-defined and non-sensitive. They are not replacements for independent boot hardware, IPC, isolation, INL compiler/runtime, VYRAQON authoritative grammar and semantic vectors, reviewed Amharic/English corpus, Ethiopian calendar reference oracle, legal/data-governance references, hardware profiles or end-to-end assurance fixtures.

## Gate semantics

- `PASS`: a registered adapter executed and matched its expected result.
- `FAIL`: a registered adapter executed and did not match its expected result; the harness exits non-zero.
- `BLOCKED`: required fixture or oracle is missing.
- `NOT RUN`: a fixture exists but no executor is registered.
- `NOT APPLICABLE`: explicit catalog disposition only.

A green CI workflow means the harness executed correctly and the Rust checks passed. It does **not** mean the A2 conformance gate passed. If any required case is BLOCKED or NOT RUN, the reported A2 gate remains BLOCKED.

The initial three adapter results cover only the narrow kernel contracts named above. Independent Amharic/Ethiopic corpus review, Ethiopian calendar oracle, VYRAQON authoritative release/ratification, named hardware profiles/budgets and native OS/INL runtime adapters remain prerequisites for A2 closure.
