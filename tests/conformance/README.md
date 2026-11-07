# IROKA A2 conformance harness

The machine-readable 40-case inventory is `catalog.json`. The Rust CLI validates the catalog, executes only registered synthetic adapters, and emits a machine-readable exact-SHA disposition report plus a GitHub Actions step summary.

## Run in GitHub Actions

```sh
cargo run --locked -p iroka-kernel --bin iroka-conformance -- tests/conformance/catalog.json --output "$RUNNER_TEMP/iroka-a2-conformance-report.json"
```

The report captures repository, ref, exact commit SHA, workflow/run metadata, runner OS/architecture, harness version, timestamps, case results and status counts. The JSON is printed into retained workflow logs; the workflow step summary gives the gate disposition.

## Current adapter coverage

The initial harness registers three synthetic kernel adapters:

- `OS-BOOT-003`: durable trust-bundle rollback rejection.
- `OS-AUD-001`: audit sink failure escalates a proposed Allow decision.
- `OS-TIME-001`: a future checkpoint timestamp is treated as a clock anomaly and high-risk actions are denied.

All other catalog cases remain BLOCKED when their fixture is absent, or NOT RUN when a fixture exists but no executor is registered. They are never silently marked PASS.

The three synthetic fixtures are code-defined and non-sensitive. They are not replacements for independent boot hardware, IPC, isolation, INL, VYRAQON, language, calendar, regional, hardware or end-to-end assurance fixtures.

## Gate semantics

- `PASS`: a registered adapter executed and matched its expected result.
- `FAIL`: a registered adapter executed and did not match its expected result; the harness exits non-zero.
- `BLOCKED`: required fixture or oracle is missing.
- `NOT RUN`: a fixture exists but no executor is registered.
- `NOT APPLICABLE`: explicit catalog disposition only.

A green CI workflow means the harness executed correctly and the Rust checks passed. It does **not** mean the A2 conformance gate passed. If any required case is BLOCKED or NOT RUN, the reported A2 gate remains BLOCKED.

The initial three adapter results cover only the narrow kernel contracts named above. Independent Amharic/Ethiopic corpus review, Ethiopian calendar oracle, VYRAQON authoritative release/ratification, named hardware profiles/budgets and native OS/INL runtime adapters remain prerequisites for A2 closure.
