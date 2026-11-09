# IROKA Coding Intelligence Program

Status: implementation program initiated; milestone acceptance remains gated.

## Objective

Build a governed software-engineering capability that can understand, create,
modify, test, debug and explain software across established and future
programming languages. Language coverage is extensible, not a promise that
every language is already supported.

The coding system remains subordinate to IROKA's canonical G01 identity,
G02 authorization and Owner approval, G11 audit and applicable workspace
policy. An authorization decision is not itself permission to execute code.
No model, planner or adapter may bypass those controls.

## Milestone C1 — Functional AI software engineering agent

Deliver a working agent for existing languages through a provider-neutral,
extensible adapter architecture.

Required workstreams:
1. Language/toolchain registry and capability discovery. Unknown languages
   remain unknown until an adapter is installed and verified.
2. Repository/workspace indexing, project and dependency understanding.
3. Task decomposition and evidence-linked change planning.
4. Read/write patch operations with diff preview and protected-path controls.
5. Toolchain broker for compilation, tests, formatters, linters and debuggers.
6. Isolated, resource-bounded execution with network disabled by default.
7. Test-failure diagnosis, repair proposals and regression verification.
8. Human approval for privileged operations, dependency changes, destructive
   actions, secret access, network access, commits, merges and deployment.
9. Audit records for requests, plans, tool invocations, outputs and approvals.
10. Evaluation suite measuring correctness, regression rate, security and
    reproducibility.

C1 does not claim autonomous production changes. Initial execution is
sandboxed and repository-local. Model backends and credentials must be supplied
through reviewed provider/secret-management adapters, never hard-coded.

## Milestone C2 — Native IROKA language, compiler and runtime

Deliver a language specification and independently testable implementation:
- language goals, syntax, semantics, type system and module model;
- parser, AST, diagnostics and source maps;
- typed intermediate representation and deterministic compiler pipeline;
- runtime/VM with explicit memory, concurrency and capability boundaries;
- package/module manager and reproducible build format;
- FFI and stable interoperability ABI for existing languages;
- formatter, language-server protocol and debugger interface;
- conformance, fuzz, differential and supply-chain tests.

The language must be useful independently and interoperable with C1 adapters.
The compiler/runtime must not grant ambient OS, filesystem or network authority.

## Milestone C3 — Advanced autonomous software engineering

Deliver bounded multi-step engineering workflows:
- plan, implement, build, test, debug and iterate;
- independent verification agents and adversarial review;
- regression, property-based, fuzz and security testing;
- provenance-aware memory of prior fixes and repository conventions;
- governed self-improvement of tools, prompts, adapters and code;
- rollback, canary and approval-gated release workflows.

Self-improvement may propose and validate changes, but cannot rewrite or
disable its own governance, trust roots, audit controls or Owner authority.
Changes to the agent's own control plane require independent review and
explicit approval.

## Language coverage model

The core uses open identifiers and registered adapters, not a closed enum.
A language becomes supported at a specific level only after its adapter passes
the relevant conformance suite. Levels are:

- Recognized: file/project detection only.
- Analyzed: syntax and/or semantic diagnostics are available.
- Edited: safe, validated source transformations are supported.
- Built: compiler/build integration is verified.
- Tested: test discovery and execution are verified.
- Debugged: debugger/trace integration is verified.
- Engineered: end-to-end C1 workflows pass the language-specific benchmark.

Future languages can be added by implementing the stable adapter contract and
passing conformance tests. No finite static list can guarantee support for
languages that do not yet exist.

## Safety and governance invariants

- Deny by default; least privilege and per-operation authorization.
- Sandboxed execution; no production credentials in build/test environments.
- No network access by default; explicit allowlists when required.
- Resource, time, process and output limits.
- Secret redaction and prompt-injection-resistant treatment of repository data.
- Human approval for external side effects and high-impact changes.
- Immutable, content-addressed audit evidence.
- Reproducible toolchain versions and exact-HEAD CI.
- No merge, signing, release, deployment or production activation without
  separate Owner authorization.

## C1.2 — Repository indexing and project understanding

**Status: VERIFIED-CLOSED — supported baseline**

The C1.2 implementation is recorded in
`docs/coding-intelligence/C1.2-REPOSITORY-INDEXING-ACCEPTANCE.md`.
It delivers deterministic repository indexing, bounded read-only workspace
snapshot collection, manifest/project recognition, declared dependency
extraction, and selected lockfile package/dependency-reference analysis.

The collector in `crates/iroka-coding/src/snapshot.rs` enforces canonical-root
confinement checks, symlink/non-regular-file rejection, deterministic ordering,
common generated/vendor exclusions, literal root `.gitignore` rules, and
file-count/per-file/aggregate-byte/depth limits. It does not execute repository
content.

Manifest recognition covers Cargo, npm, Python, Go, Maven, Gradle, Composer,
CMake and Ruby. Dependency extraction is implemented for supported Cargo,
npm, Python, Go and Ruby patterns. Lockfile package records are parsed for
Cargo.lock, package-lock.json/npm-shrinkwrap.json and composer.lock. Unsupported
syntax and formats are marked PARTIAL, not represented as complete.

Exact implementation HEAD:
`7398a7afd4dc07bc8c70e8bd972c9133911e552d`.
Exact-HEAD workflow #743 passed formatting, compilation, production-feature
checks, all tests and Clippy: 25 coding tests + 71 kernel tests + 2 integration
tests = 98 passed, 0 failed.

Known extensions remain: pnpm/Yarn/Poetry/Pipenv/Go/Ruby lockfile parsers;
Maven/Gradle/CMake dependency parsing; vulnerability/advisory and license-policy
analysis; and a normalized cross-ecosystem transitive graph. These limitations
are documented in the acceptance record. No registry access, dependency
installation, script execution or network access is performed.

## C1.3 — AI task planner and structured code generation

**Status: VERIFIED-CLOSED — planner/code-generation core and local-provider adapter**

The C1.3 implementation and evidence are recorded in
`docs/coding-intelligence/C1.3-PLANNER-CODEGEN-ACCEPTANCE.md`. It provides
evidence-bound task plans, dependency-DAG validation, mandatory Owner-approval
boundaries, strict structured code-generation responses, registered-language
binding and single-target unified-diff validation.

The optional Ollama-compatible adapter uses a loopback-only endpoint with
bounded HTTP requests/responses and timeouts. It does not contact remote hosts,
run local commands, or apply generated patches. A real local Ollama runtime/model
was not provisioned; the adapter was tested against a mock loopback server.
Remote provider adapters and model-quality/red-team evaluation remain future
work.

Exact implementation HEAD:
`f705ca9d916b12f6f83effbdf470569f6b14ffed`.
Exact-HEAD workflow #758 passed formatting, compilation, production-feature
checks, all tests and Clippy: 40 coding tests + 71 kernel tests + 2 integration
tests = 113 passed, 0 failed.

## Acceptance gates

Each milestone requires an A1 frozen contract, A2 read-only reconciliation,
A3 implementation, A4 independent verification and A5 separately authorized
deployment. C1 must pass before C2 is declared complete; C2 before C3 is
declared complete. Parallel work is allowed only where interfaces are stable
and no milestone dependency is bypassed.

## Initial implementation slice

The first C1 slice adds the iroka-coding crate with:
- validated, extensible language identifiers;
- an adapter trait and runtime registry;
- truthful per-language capability declarations;
- deterministic file-extension recognition;
- tests for unknown/future languages, duplicate registration, malformed IDs
  and the distinction between recognition and executable capabilities.

This is an adapter foundation, not yet a complete AI coding agent.
