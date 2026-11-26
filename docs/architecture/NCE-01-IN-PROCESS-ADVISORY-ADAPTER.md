# NCE-01 In-Process Advisory Cognition Adapter

**Status:** IMPLEMENTED / VERIFIED on exact code SHA `12bbc2682e0efea796b23a1c5c7b2a45c69b26ae`  
**Owner:** IROKA ZERO  
**Implementation:** `crates/iroka-kernel/src/advisory_cognition.rs`  
**Engine:** `iroka-cognition` / NCE-01

## Purpose

Provide an in-process entry point for higher-level IROKA services to request native,
deterministic propositional forward reasoning. The adapter returns reasoning evidence
and query observations. It is not an authorization, identity, approval, execution,
audit, or policy interface.

The Kernel depends on the cognition crate, but the cognition crate does not depend on
the Kernel. This dependency direction allows Kernel-owned services to call cognition
without granting cognition authority over Kernel decisions.

## Public interface

- `AdvisoryCognitionAdapter`: immutable, copyable adapter configured at construction.
- `AdvisoryCognitionConfig`: NCE-01 engine limits plus adapter input/query limits.
- `AdvisoryCognitionRequest`: asserted facts, propositional rules, and query literals.
- `AdvisoryFact`: a literal with an optional opaque source identifier.
- `AdvisoryCognitionResult`: the NCE-01 reasoning report and query observations.
- `AdvisoryCognitionError`: explicit input/configuration/engine rejection.

A request is processed synchronously in memory. The adapter validates collection counts
and aggregate UTF-8 payload bytes before copying data into engine-owned state. It then
adds facts and rules, executes NCE-01, and evaluates the requested literals against the
resulting fact state.

## Limits

Default adapter limits:

| Boundary | Default | Hard adapter ceiling |
|---|---:|---:|
| Aggregate fact/rule/query UTF-8 payload | 1 MiB | 1 MiB |
| Query count | 256 | 256 |
| Facts | NCE-01 default 10,000 | NCE-01 engine ceiling |
| Rules | NCE-01 default 2,000 | NCE-01 engine ceiling |
| Rule premises | NCE-01 default 256 each | NCE-01 engine ceiling |
| Inference work | NCE-01 default 10,000 rule evaluations | NCE-01 engine ceiling |
| Reasoning/report deadline | NCE-01 default 3 seconds | NCE-01 engine ceiling |

The adapter byte count covers UTF-8 payload strings (atom names, source IDs and rule IDs).
It is not a heap/RSS bound and does not include allocator metadata or the caller's
already-allocated request objects. The engine independently enforces its retained-state
and inference budgets.

## Partial-result contract

- `AdvisoryCognitionResult::is_complete()` is true only when NCE-01 reaches a fixed point.
- `is_partial()` is true for deadline or engine-budget stops.
- Query results from a partial report are observations of the facts discovered so far.
- Absence from a partial result MUST NOT be interpreted as refutation or proof of absence.
- Callers must propagate the completeness status when presenting or storing a result.

## Authority and security boundary

The adapter:

- does not receive or authenticate a principal;
- does not call Kernel policy evaluation or authorization;
- cannot create a Kernel `Decision`, execution grant, owner approval, or capability;
- does not write audit records or perform protected side effects;
- does not load external models, access network/filesystem, or persist memory;
- treats source identifiers as caller-supplied provenance metadata, not authenticated evidence.

A reasoning result MUST NOT be used as permission, approval, identity proof, or execution
authorization. Protected actions remain subject to the independent Kernel authorization
and G09 execution contracts. A downstream service may use an advisory result to inform a
proposal, but must separately validate that proposal through the governed pipeline.

## Verification included

Six adapter tests cover:
1. multi-step inference and retention of input provenance metadata;
2. explicit positive/negative contradiction reporting;
3. partial-result signalling after an inference-step budget stop;
4. aggregate input-byte rejection;
5. query-count rejection; and
6. proof that advisory facts do not override Kernel policy denial.

## Remaining integration gates

This adapter is an in-process library interface, not an HTTP/IPC ingress service. It does
not yet provide transport parsing, raw-body limits, end-to-end request deadlines before
Rust request allocation, concurrency admission, process memory isolation, cancellation
of caller-side work, or peak-RSS qualification. Those controls remain required before
exposing cognition to untrusted remote inputs or enabling production service traffic.

Independent security review and exact-SHA CI are separate gates. This implementation
does not authorize merge, deployment, or production activation.


## Exact-SHA verification record

Code SHA: `12bbc2682e0efea796b23a1c5c7b2a45c69b26ae`

- Native Cognition CI: PASS — https://github.com/akefadaka-git/iroka/actions/runs/45835698806
- Rust kernel verification: PASS — https://github.com/akefadaka-git/iroka/actions/runs/45835698696
- Adapter integration tests: 6 passed, 0 failed.
- Complete workspace test binaries: 72 cognition tests, 77 Kernel tests, and 2 authorization-contract tests; 151 passed, 0 failed.
- `cargo check --workspace --all-targets --locked`: PASS.
- `cargo check --workspace --all-targets --no-default-features`: PASS.
- `cargo fmt --all -- --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::pedantic`: PASS.

These checks verify the code on the cited SHA. Independent security review and remote-ingress qualification remain open.
