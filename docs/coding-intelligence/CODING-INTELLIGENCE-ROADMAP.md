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

The first static analysis implementation is in `crates/iroka-coding/src/index.rs`.
It consumes a caller-provided repository snapshot and produces a deterministic
file index, language classifications through registered adapters, project
manifest records, dependency declarations and explicit analysis issues.

Current manifest recognition covers Cargo, npm/package.json, Python
pyproject/requirements, Go modules, Maven, Gradle, Composer, CMake and Ruby
Gemfile. Initial dependency extraction is implemented for Cargo dependency
tables, common package.json dependency blocks, basic Python dependency
declarations, Go require statements and simple Gemfile gem declarations.
Unsupported or ambiguous manifest syntax is marked partial rather than being
reported as a complete dependency inventory.

The index enforces configurable file-count, per-file and aggregate byte limits;
rejects absolute, traversal, malformed and duplicate paths; and skips symlinks.
It sorts output deterministically. It does not execute project scripts, resolve
versions, install dependencies, invoke package managers or access the network.
Lockfiles are identified as evidence but are not yet parsed into a resolved
transitive dependency graph.

A bounded workspace collector now lives in `crates/iroka-coding/src/snapshot.rs`.
It traverses a canonicalized root deterministically, skips symlinks and non-regular
files, applies file-count/per-file/aggregate-size/depth limits, excludes common
build/vendor directories, and honors literal root `.gitignore` entries. It exposes
`collect_snapshot` and `analyze_workspace` so callers can collect and index a local
workspace without executing repository content or invoking package managers.
Glob, negation and nested `.gitignore` rules are reported as unsupported; they are
not silently approximated. Non-UTF-8 files are skipped and reported. This is a
read-only collector, not an OS sandbox or a race-free hostile-filesystem boundary.

Dependency analysis remains static and declaration-oriented. Lockfiles are
identified but not yet parsed into a complete resolved transitive graph, and
Maven/Gradle/Composer/CMake parsing remains partial. No versions are resolved,
packages installed, scripts executed or network requests made.

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
