# IROKA Native Language (INL) — Language and Toolchain Design

**Contract ID:** IROKA-A2-INL-001  
**Version:** 1.0.0-draft  
**Status:** A2 language design baseline; name and final syntax provisional  
**Parent:** IROKA-A2-NATIVE-001; IROKA-A1-REGIONAL-001  
**Implementation authorization:** None

## 1. Language identity and separation of concerns

IROKA Native Language (INL) is the working designation for IROKA's native systems and cognitive programming language. The public name is not decided.

INL and VYRAQON are complementary, not competing:
- **VYRAQON** is the independently governed universal writing and computational representation system.
- **INL** is IROKA's executable language: types, memory/resource semantics, effects, concurrency, modules, ABI and runtime behavior.
- VYRAQON program representations may lower to a typed INL program or verified intermediate representation (IR).
- INL programs may be documented, rendered or exchanged using VYRAQON without changing executable semantics.

INL MUST NOT define a second universal writing system, script or orthography to replace VYRAQON. Its syntax may support familiar and VYRAQON-mediated authoring, but one canonical semantic model must govern all front ends.

## 2. Design goals

1. Memory and resource safety by default.
2. Strong static typing and explicit effect/capability boundaries.
3. No ambient authority for protected operations.
4. Predictable concurrency, cancellation and failure behavior.
5. Reproducible builds and verifiable artifacts.
6. Explicit interoperability with VYRAQON and human-language tooling.
7. Safe foreign-function interfaces and versioned ABI.
8. Excellent diagnostics, source maps and debugging across source representations.
9. Small trusted compiler/runtime core with independently testable stages.
10. Amharic-first developer experience for Ethiopia, with African regional extensibility.

Non-goals include maximizing syntax novelty, requiring all developers to use one human language, embedding model inference into compiler trust, or promising formal verification for arbitrary programs.

## 3. Normative terminology

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY have normative meaning. The language specification is divided into:
- lexical and syntactic grammar;
- name and module resolution;
- type system;
- ownership and memory model;
- effects and capabilities;
- concurrency and async model;
- error and resource lifecycle;
- IR and compiler pipeline;
- runtime and ABI;
- package/build/provenance model;
- tooling/localization contract.

No implementation may claim language conformance by accepting syntax alone; semantic and runtime rules are also normative.

## 4. Source model and front ends

### 4.1 Canonical semantic model

All supported source front ends MUST lower to a versioned canonical AST/IR with stable node identity, type information, source spans, effect declarations and provenance. Formatting and comments may differ; semantic identity must not depend on display language, glyph font or editor.

The parser MUST preserve original source bytes/code points and source encoding metadata where lossless preservation is specified. Normalized tokens MUST retain a mapping to original spans. Unicode normalization may be used for defined identifier comparison only; it MUST NOT rewrite string literals, names, legal identity values or embedded documents.

### 4.2 Authoring modes

The design MAY support:
- canonical INL source syntax;
- VYRAQON-native computational authoring;
- structured visual/pseudocode authoring;
- localized explanatory annotations and diagnostics.

Only a front end with a published grammar and conformance suite may be called supported. A natural-language prompt is not source code and must pass through a reviewed translation/intent pipeline before any compilation or execution proposal.

### 4.3 Amharic-first developer experience

For the Ethiopia profile:
- primary developer documentation, onboarding, compiler diagnostics, error explanations and critical tool workflows MUST be available in reviewed Amharic;
- English is available as a secondary technical language;
- Ethiopic text MUST be accepted in comments, string literals, documentation, identifiers only if the identifier profile explicitly permits it, and test fixtures;
- source code and comments MUST retain original script and code points;
- editors, terminals, debuggers and package tools MUST be tested for Ethiopic shaping, cursor movement, selection, copy/paste and mixed-script layout;
- no English-only benchmark or successful Latin-only demo establishes Amharic support.

The initial identifier policy SHOULD favor a stable, unambiguous identifier subset while allowing Amharic/Ethiopic text in comments, literals and documentation. Any future Ethiopic identifier support requires normalization, confusable, bidi and tooling security tests before activation.

## 5. Lexical and syntax design constraints

Final concrete grammar is a separate decision after VYRAQON grammar mapping and comparative prototypes. This contract fixes semantic requirements without prematurely inventing a syntax.

The grammar MUST define:
- source encoding and line-ending behavior;
- token boundaries and whitespace;
- comments and documentation comments;
- identifiers and Unicode policy;
- numeric, string, byte and character literals;
- module/import declarations;
- declarations, expressions and pattern matching;
- type and effect annotations;
- async/concurrency constructs;
- error propagation and resource scopes;
- attributes/annotations and versioned extensions.

The grammar MUST be unambiguous, machine-readable, versioned and testable. Reserved words, escaping and compatibility rules MUST be explicit. Locale-specific number/date formatting MUST NOT alter lexical numeric values.

## 6. Type system

### 6.1 Core requirements

INL MUST use a strong static type system with:
- explicit primitive and compound types;
- algebraic data types and exhaustive pattern matching;
- parametric generics with defined constraints;
- explicit optional/nullable values;
- checked numeric conversions;
- immutable-by-default bindings where practical;
- explicit mutability and aliasing rules;
- typed errors/results;
- interface/trait or equivalent abstraction contracts;
- module visibility and encapsulation.

Implicit coercions that can lose precision, change units, cross trust boundaries or erase error states are prohibited.

### 6.2 Security and domain types

Security-sensitive values MUST use distinct nominal types, not plain strings:
- PrincipalId;
- TenantId;
- Capability;
- ResourceId;
- PolicyDecision;
- ApprovalRef;
- ArtifactDigest;
- SignatureEvidence;
- LocaleId;
- CalendarId;
- CurrencyCode;
- ZonedInstant;
- CivilDate;
- SourceLanguage;
- ProvenanceRef.

A localized display string MUST NOT be accepted where a typed canonical value is required.

### 6.3 Refinement and invariants

The type system SHOULD support refinements/contracts for ranges, invariants and validated states. Runtime checks remain required where static proof is unavailable. A type annotation is not evidence that untrusted data has been validated; parsing and validation constructors MUST establish trusted values.

## 7. Ownership, memory and resource model

The language MUST prevent use-after-free, double-free and data races in safe code by construction or verified runtime mechanisms.

A2 must select and specify one primary memory model, comparing:
- ownership/borrowing with explicit lifetimes;
- region/arena management;
- tracing or reference-counted managed memory;
- a carefully bounded hybrid.

The choice MUST be justified against kernel use, low-memory devices, predictable latency, FFI, cognitive workloads and implementation complexity. This document does not pretend that a specific model has already been selected.

Rules:
- safe code cannot dereference invalid memory;
- mutable aliasing must be controlled;
- resource acquisition and release must be explicit and exception-safe;
- secrets have zeroization semantics where technically supported;
- unsafe operations are isolated, documented and audited;
- FFI pointers and handles are validated at boundaries;
- allocation failure is explicit and cannot silently corrupt state.

## 8. Effects and capabilities

Every operation with an externally observable or privileged effect MUST declare its effect set. Proposed effect categories:
- pure computation;
- local state read/write;
- filesystem/object access;
- network access;
- process/service control;
- identity/policy/approval access;
- cryptographic/key operations;
- device access;
- external model/tool invocation;
- time/randomness;
- audit emission.

Effects are statically represented and dynamically enforced. A program's declared effects are an upper bound; actual authority is supplied at runtime through scoped capabilities. Static declarations never grant authority.

A capability MUST bind subject, operation, resource, tenant, purpose, scope, expiry and revocation context. Effect escalation is prohibited. Dynamic dispatch, reflection, FFI and plugin calls MUST preserve or conservatively widen effect information; they may not erase it.

Pure code MUST be deterministic for fixed inputs and specified runtime version. Nondeterministic operations MUST be explicit and injectable for testing.

## 9. Concurrency and async execution

The language/runtime MUST define:
- task creation and ownership;
- structured concurrency and parent-child cancellation;
- task supervision and failure propagation;
- synchronization and atomic memory semantics;
- channel/message ordering guarantees;
- deadlines, timeouts and cancellation;
- resource quotas and backpressure;
- deterministic testing hooks.

Unstructured background tasks with no lifecycle owner are prohibited in safe application code. Shared mutable state requires explicit synchronization or ownership transfer. A task cannot outlive its authority lease for protected operations.

## 10. Errors, exceptions and resource lifecycle

Expected failures MUST be represented in typed result/error values. Panics or fatal traps are reserved for violated runtime invariants and unrecoverable faults. Error values MUST have stable machine codes, structured context and localized human-readable presentation.

Resource scopes MUST define deterministic cleanup for files, locks, transactions, capabilities and temporary secrets. Cancellation and failure MUST release resources and revoke temporary authority. Error localization MUST not change the machine code or canonical evidence.

## 11. Compiler and toolchain pipeline

The compiler MUST expose independently testable stages:

1. Source ingestion and lossless source mapping.
2. Lexing/parsing under an explicit grammar version.
3. Name/module resolution.
4. Type checking and constraint validation.
5. Effect/capability analysis.
6. Ownership/resource analysis.
7. Canonical typed IR generation.
8. IR validation and optimization under declared semantics.
9. Target lowering and code generation.
10. Link/package generation.
11. Artifact manifest, digest and provenance emission.

Every stage MUST reject malformed or unsupported inputs with stable diagnostics. Optimizations MUST preserve defined observable semantics and effect boundaries. Compiler plugins are untrusted extensions and MUST run sandboxed.

## 12. Intermediate representation

The canonical IR MUST be versioned and machine-readable. It MUST encode:
- schema and language version;
- node kind and stable identity;
- typed operands and result types;
- control/data flow;
- effect declarations;
- capability requirements (not grants);
- source spans and source representation identifiers;
- provenance and transformation lineage;
- deterministic constants and explicit nondeterminism;
- target/runtime constraints.

IR serialization MUST be canonical for the same semantic program and IR version. Unknown mandatory fields or incompatible major versions fail closed. IR is not executable merely because it parses.

## 13. Runtime and ABI

The runtime ABI MUST define calling convention, type layout, error propagation, memory ownership, async/task model, panic/trap behavior, capability handles, FFI and version negotiation.

Runtime modules MUST declare ABI compatibility and required system services. Dynamic loading MUST validate signature/provenance, digest, ABI, dependency constraints and policy before activation.

The initial target may be a hosted runtime. A native IROKA OS target is a separate backend and cannot be claimed until boot, kernel, runtime and hardware conformance pass.

## 14. Modules, packages and reproducible builds

A package manifest MUST identify:
- package name and stable ID;
- semantic version;
- source and artifact digests;
- compiler and toolchain versions;
- target triples/runtime ABI;
- dependency lock with exact versions and digests;
- license and provenance metadata;
- declared effects/capability requirements;
- build inputs and reproducibility settings;
- signatures and publisher identity.

Builds MUST be hermetic or document all non-hermetic inputs. Reproducible-build tests compare artifact digests under defined independent environments. Dependency substitution, floating unpinned versions and implicit network fetches during privileged build steps are prohibited.

## 15. Foreign-function and plugin boundaries

FFI MUST define memory ownership, calling convention, error mapping, thread safety, cancellation, capability propagation and data encoding. Unsafe FFI MUST be isolated behind small audited wrappers.

Plugins MUST:
- declare interfaces and effects;
- execute with least privilege;
- have bounded resources;
- be signed/provenanced according to policy;
- be revocable;
- not load into the TCB by default;
- produce audit evidence for protected calls.

## 16. Diagnostics, debugging and developer tools

Diagnostics MUST have stable IDs, severity, source span, machine-readable parameters and localized messages. Amharic is the default diagnostics language in the Ethiopia profile; English is selectable. Compiler output MUST preserve source snippets and exact source mapping without lossy transliteration.

Debugger and profiler interfaces MUST distinguish source representation, canonical IR and generated machine/runtime artifact. Sensitive values MUST be redacted by policy. Crash reports MUST not expose secrets.

## 17. VYRAQON interoperability

INL MUST consume VYRAQON through the versioned interface contract defined in IROKA-VYRAQON-INTEROP-001. It MUST NOT embed an unofficial grammar fork. The adapter records the exact VYRAQON standard, grammar, schema and artifact digests.

The VYRAQON front end lowers into the same typed canonical IR as native INL. It cannot bypass type/effect checks, capability validation, package provenance or Kernel policy. Any semantic ambiguity, unsupported construct, lossy mapping or version mismatch blocks executable lowering.

## 18. Language conformance levels

| Level | Meaning | Required evidence |
|---|---|---|
| L0 Parse | Grammar accepts/rejects normative syntax | Positive/negative parser corpus |
| L1 Semantic | Name/type/effect rules conform | Type/effect fixtures |
| L2 IR | Canonical lowering and source maps conform | Golden IR and round-trip vectors |
| L3 Runtime | ABI, memory, errors and concurrency conform | Runtime behavioral suite |
| L4 Secure execution | Capability and effect boundaries enforced | Adversarial authorization suite |
| L5 Regional developer experience | Amharic-first tools and Ethiopic source fidelity | Reviewed localization/accessibility suite |

A release MUST declare the highest level fully passed. It MUST NOT average away a failed mandatory level.

## 19. Measurable acceptance gates

| ID | Measure | Threshold |
|---|---|---|
| INL-PARSE-01 | Normative parser positive/negative vectors | 100% expected outcomes |
| INL-TYPE-01 | Type-system positive/negative vectors | 100% expected outcomes |
| INL-EFFECT-01 | Undeclared effect acceptance | 0 |
| INL-CAP-01 | Static declaration treated as runtime authority | 0 |
| INL-MEM-01 | Safe-code memory safety violations in defined suite | 0 |
| INL-CONC-01 | Data races/deadlocks in defined deterministic stress suite | 0 |
| INL-IR-01 | Canonical IR digest for golden semantic fixtures | 100% exact |
| INL-SOURCE-01 | Source-span mapping for required fixtures | 100% mapped |
| INL-BUILD-01 | Reproducible artifact digest across independent builders | 100% exact for declared reproducible set |
| INL-ABI-01 | Declared ABI compatibility matrix | 100% expected outcomes |
| INL-FFI-01 | Invalid boundary input accepted | 0 |
| INL-LOCALE-01 | Amharic-first critical developer workflows | 100% reviewed journeys |
| INL-UNICODE-01 | Ethiopic source/comment/literal corruption in lossless paths | 0 |
| INL-VYRAQON-01 | VYRAQON input bypasses INL type/effect validation | 0 |
| INL-AUDIT-01 | Protected execution transitions with traceable audit | 100% |

## 20. Unresolved language decisions before A3

The following require comparative prototypes and Owner-approved decision records:
1. Final public language name.
2. Canonical source syntax and grammar.
3. Whether multiple source syntaxes are supported in v1.
4. Identifier Unicode policy and confusable/bidi defenses.
5. Memory model.
6. Type-system feature ceiling and refinement strategy.
7. Effect-system syntax and static/dynamic division.
8. Canonical IR schema and encoding.
9. Initial target backends and ABI.
10. Runtime implementation language and isolation strategy.
11. Package registry, signing and dependency trust policy.
12. FFI support and unsafe-code governance.
13. Amharic technical terminology and reviewed diagnostic corpus.

Until resolved, these are design blockers, not permission to improvise during implementation.

## 21. Status

This is a complete requirements-level language design contract, not a finalized grammar, compiler, runtime or language release. The unresolved decisions above require evidence and approval before A3. A language implementation must not be represented as conformant until the measurable suite passes on an exact commit and declared target.
