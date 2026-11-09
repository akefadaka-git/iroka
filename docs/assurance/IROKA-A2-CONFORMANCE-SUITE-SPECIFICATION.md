# IROKA A2 — Native Platform and VYRAQON Conformance Suite

**Contract ID:** IROKA-A2-CONFORMANCE-001  
**Version:** 1.0.0-draft  
**Status:** Test architecture and measurable acceptance baseline  
**Applies to:** IROKA OS, Kernel, INL, VYRAQON adapter and A1 regional requirements  
**Implementation authorization:** None; this document does not authorize A3

## 1. Purpose

This document defines a measurable, traceable conformance program for the native computing architecture. It establishes test IDs, expected outcomes, fixture classes, evidence requirements, coverage rules, security invariants and release gates.

It is a test specification, not a test result. No PASS status is claimed until a runnable harness, reviewed fixtures, pinned dependencies and exact-SHA execution evidence exist.

## 2. Conformance principles

- Tests are deterministic where the property under test permits.
- Every test maps to one or more normative requirements.
- Positive, negative, boundary, fault-injection and adversarial cases are mandatory.
- A security invariant uses zero-tolerance acceptance for prohibited behavior.
- Regional and language tests are first-class gates, not optional localization checks.
- Test data must be lawful, consented or synthetic; no personal data is required for baseline fixtures.
- Tests must preserve original source bytes and record derived transformations.
- A test suite cannot prove absence of all vulnerabilities; residual risks remain explicit.
- No aggregate score can compensate for a failed critical security, authorization or A1 requirement.

## 3. Suite structure

| Suite | Scope | Minimum categories |
|---|---|---|
| C00 Governance | authority and evidence | identity, approval, risk, provenance, audit |
| C10 Boot | startup trust | signature, digest, rollback, recovery |
| C20 Kernel | isolation and resources | memory, process, capability, scheduling, IPC |
| C30 OS services | storage/network/time/update | tenant access, egress, key lifecycle, revocation |
| C40 INL frontend | source and grammar | parser, Unicode, diagnostics, source maps |
| C41 INL semantics | types/effects/resources | type errors, undeclared effects, ownership |
| C42 INL runtime | ABI/concurrency | deterministic behavior, cancellation, quotas |
| C50 VYRAQON interop | artifact and semantic mapping | integrity, versioning, parse, round-trip, mapping |
| C60 Amharic/Ethiopic | regional language quality | UI, text fidelity, search, documents, accessibility |
| C70 African profiles | regional isolation | profile schema, precedence, leakage and migration |
| C80 Supply chain | build/package | SBOM, provenance, reproducibility, signatures |
| C90 End-to-end | complete journeys | author→parse→review→compile→authorize→execute→audit |

## 4. Requirement-to-test traceability

| Requirement family | Test prefix | Required result |
|---|---|---|
| OS boot/trust | OS-BOOT | invalid artifacts rejected; approved chain verified |
| Capability/authorization | OS-CAP, C00-AUTH | zero unauthorized effects |
| Isolation | OS-ISO, OS-IPC | zero cross-boundary violations |
| Resource bounds | OS-RES | all defined quota boundaries enforced |
| Audit/provenance | OS-AUD, C00-AUD | 100% protected transitions correlatable |
| INL grammar/types | INL-PARSE, INL-TYPE | 100% normative vector outcomes |
| INL effects | INL-EFFECT, INL-CAP | zero undeclared/unauthorized effects |
| INL memory/concurrency | INL-MEM, INL-CONC | zero violations in defined suite |
| INL IR/build/ABI | INL-IR, INL-BUILD, INL-ABI | exact golden outputs and expected matrix |
| VYRAQON integrity/grammar | VY-ART, VY-GRAM | 100% pinned release/vector outcomes |
| VYRAQON semantics | VY-SEM, VY-MAP | 100% expected semantic mappings |
| Amharic/Ethiopic | A1-LANG, A1-DOC, VY-UNI | all reviewed mandatory workflows pass |
| Regional profiles | A1-REG, OS-REG | zero unintended cross-profile leakage |
| End-to-end | E2E | every protected effect has valid approval and audit |

The authoritative requirement source is the referenced contract version, not this summary table.

## 5. Test case record schema

Each case MUST be represented in the harness with at least:

| Field | Required meaning |
|---|---|
| test_id | Stable unique ID |
| requirement_ids | Normative contract references |
| suite | Suite identifier |
| title | Concise test purpose |
| class | positive, negative, boundary, fault, adversarial, regression |
| preconditions | Environment and state |
| input_fixture | Immutable fixture ID and digest |
| procedure | Deterministic steps |
| expected_result | Exact machine-verifiable outcome |
| severity | Critical, high, medium or low |
| locale_profile | Locale and regional context, if applicable |
| source_language/script | Source metadata, if applicable |
| oracle | Expected output or independent reference |
| timeout/resource_budget | Explicit bounds |
| evidence | Logs, artifacts, traces and report references |
| status | PASS, FAIL, BLOCKED, NOT RUN, NOT APPLICABLE |
| tested_sha | Exact code commit |
| environment | Hardware/OS/runtime and dependency versions |

Test fixtures and oracles MUST be versioned. A changed oracle requires review and a recorded reason.

## 6. Mandatory test classes

### 6.1 Positive
Valid supported inputs produce the specified output, preserve provenance and remain within resource limits.

### 6.2 Negative
Invalid signatures, unsupported versions, malformed types, undeclared effects, missing capabilities and malformed Unicode are rejected with stable error codes.

### 6.3 Boundary
Test exact minimum/maximum payload, integer boundaries, time expiry edges, calendar year boundaries, memory quota limits, recursion/depth limits and version compatibility boundaries.

### 6.4 Fault injection
Simulate audit sink outage, key broker outage, clock uncertainty, interrupted update, storage failure, network loss, compiler crash, partial artifact write and recovery interruption.

### 6.5 Adversarial
Test forged capability, replay, confused deputy, privilege escalation, tenant escape, malicious parser payload, Unicode spoofing, prompt injection, dependency substitution and resource exhaustion.

### 6.6 Regression
Every fixed defect receives a stable regression case linked to its original issue and exact introducing/fixing commits.

## 7. Amharic-first Ethiopia conformance corpus

The suite MUST include reviewed synthetic fixtures across all of the following dimensions:

1. Amharic-only text.
2. English-only secondary-language text.
3. Mixed Amharic/English sentences.
4. Ethiopic numerals and Western digits.
5. Ethiopic punctuation, combining marks and mixed punctuation.
6. Names in original Ethiopic script, Latin transliteration and explicitly supplied aliases.
7. Similar-looking names that MUST remain distinct.
8. Long text, line wrapping, cursor movement, selection and copy/paste.
9. Search queries with representative Amharic morphology and spelling variation.
10. Amharic document samples for supported PDF/DOCX/spreadsheet workflows.
11. Ethiopian calendar dates around year and leap-year boundaries.
12. Gregorian interoperability and explicit calendar labels.
13. Date-only values versus instants and Africa/Addis_Ababa display.
14. ETB display and typed currency behavior.
15. Amharic diagnostics, approval prompts, errors and recovery messages.
16. Amharic speech/handwriting only if separately declared as supported; otherwise those tests remain NOT APPLICABLE with no capability claim.

All text fixtures MUST be reviewed by competent Amharic language reviewers. Machine-generated translations cannot serve as the sole oracle for Amharic correctness.

## 8. African regional profile conformance

At least one synthetic non-Ethiopian African profile fixture MUST be used to prove separation of dimensions. It must not invent legal rules or assert compliance. It should deliberately use a distinct language set, time zone, calendar preference and currency configuration supplied by a reviewed profile fixture.

Required tests:
- profile schema validity and version compatibility;
- default and user preference precedence;
- explicit language/calendar/currency/time-zone dimensions;
- no Ethiopia-specific default leakage unless configured;
- regional profile cannot change Kernel security or Owner authority;
- profile migration and rollback preserve data;
- user source language and identity values remain unchanged after profile switch.

Additional country profiles require jurisdictional review before being described as supported.

## 9. Security invariants and zero-tolerance cases

The following acceptance thresholds are zero:
- forged, expired, revoked or out-of-scope capability accepted;
- cross-tenant data or memory access;
- privilege amplification by delegation;
- VYRAQON/INL source or compiler output bypasses authorization;
- model output directly triggers a protected effect;
- invalid boot/update signature or digest accepted;
- unsupported major version executed;
- undeclared effect reaches a protected runtime operation;
- untrusted package gains ambient authority;
- locale, script or regional profile alters authority;
- audit evidence omitted for a protected effect.

Any observed violation is a critical failure and blocks A3 approval for the affected boundary until root cause, fix and regression evidence are accepted.

## 10. Quantitative acceptance thresholds

| Metric | Threshold |
|---|---|
| Normative positive/negative test vectors | 100% expected outcomes |
| Critical security invariant violations | 0 |
| Protected effect audit coverage | 100% |
| Required source-span coverage | 100% for fixtures requiring source maps |
| Lossless source preservation | 100% for declared lossless fixtures |
| Canonical IR golden digest match | 100% for pinned compiler/IR version |
| Reproducible build digest match | 100% for declared reproducible fixture set |
| Required Amharic critical journeys | 100% reviewed pass |
| Ethiopic code-point corruption in lossless paths | 0 |
| Unauthorized regional profile leakage | 0 |
| Unsupported/ambiguous executable constructs accepted | 0 |
| Unresolved critical/high security findings | 0 unless explicit Owner risk acceptance, documented separately |

Performance/capacity gates MUST specify named hardware, compiler/runtime version, workload, warm/cold state, sample size, percentile, resource budget and measurement tool. No latency, throughput or memory target is invented in this generic suite.

## 11. Benchmark methodology

For each performance benchmark:
- identify target device/CPU/RAM/storage/network/firmware;
- pin build and dependency digests;
- define workload and input corpus digest;
- define warm-up, sample count and run isolation;
- report p50, p95, p99 where relevant, throughput and peak memory;
- record power/thermal data where available;
- repeat under representative constrained-connectivity conditions;
- retain raw results and scripts;
- compare against a pre-approved budget.

Benchmark thresholds require an Owner-approved target matrix before A3 implementation. Performance results cannot override failed security or language conformance.

## 12. Test environment and execution policy

Test tiers:
- **T0 static contract checks:** schemas, version manifests, traceability and documentation consistency.
- **T1 deterministic unit/contract:** parsers, types, IR, policy and service contracts.
- **T2 integration:** kernel/services, VYRAQON adapter, INL runtime and regional profile interactions.
- **T3 adversarial/security:** isolation, fuzzing, fault injection, supply chain and authorization bypass.
- **T4 target hardware:** boot, drivers, performance, recovery and hardware-specific assurance.

Each run MUST capture exact repository, commit SHA, branch/ref, dirty state if applicable, runner/environment, command/workflow, dependency lock, test suite version, start/end time, exit code and artifact URLs/digests.

A test not run is NOT RUN. A missing fixture is BLOCKED or MISSING, never PASS. A workflow queued without execution is NOT RUN. A green documentation check does not prove OS, language or security conformance.

## 13. Fuzzing and differential testing

Fuzz targets SHOULD include:
- VYRAQON parser and serializer;
- INL lexer/parser/type checker;
- canonical IR decoder/validator;
- package manifest and signature parser;
- IPC message decoder;
- Unicode and bidi processing;
- calendar conversion boundaries;
- policy/capability token decoder.

Fuzz runs MUST pin corpus, seed, engine and time/resource budget. Crashes and semantic mismatches become regression fixtures. Differential testing across independent parser/compiler implementations is required where available; identical outputs from two wrappers around the same implementation do not count as independent evidence.

## 14. Release gate rules

A conformance release report MUST:
1. list exact tested SHAs for every component/repository;
2. identify pinned VYRAQON release and INL/IR versions;
3. list all test IDs and status;
4. show pass/fail/blocked/not-run counts by suite;
5. attach raw evidence and fixture digests;
6. identify failed and flaky tests;
7. list unresolved risks and deviations;
8. state supported language, hardware, regional and deployment profiles precisely;
9. record independent review and Owner acceptance where required.

No A3 gate may be declared complete when a required test family is MISSING, BLOCKED or NOT RUN. A3 authorization remains a separate Owner decision even after A2 design closure.

## 15. Initial conformance inventory

At this specification baseline:
- test architecture and measurable thresholds: SPECIFIED;
- executable harness: NOT IMPLEMENTED;
- reviewed Amharic/Ethiopic oracle corpus: MISSING;
- non-Ethiopian regional fixture: MISSING;
- named hardware target and performance budgets: MISSING;
- VYRAQON authoritative release/grammar: MISSING;
- cross-repository VYRAQON vectors: BLOCKED;
- OS/INL runtime tests: NOT RUN;
- exact-SHA conformance execution: NOT RUN.

These statuses are deliberate and must not be upgraded without evidence.

## 16. A2 exit evidence

A2 design exit requires complete contract-to-test traceability, reviewed fixtures/oracles, resolved platform and language decisions, VYRAQON bilateral ratification, target hardware and budgets, threat-model review, dependency/provenance assessment and Owner approval.

This suite is the acceptance contract for future implementation and verification. It is not proof of implementation or test success.
