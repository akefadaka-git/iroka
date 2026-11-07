# IROKA A2 Implementation and Conformance Status

**Record:** IROKA-A2-IMPLEMENTATION-STATUS-002  
**Date:** 2026-11-07  
**Repository:** `akefadaka-git/iroka`  
**Branch:** `feat/a2-conformance-regional-runtime`  
**Status:** A2 runtime foundations and executable disposition harness implemented; platform-wide A2 gate remains PARTIAL.

## 1. Implemented in this work package

### Executable conformance disposition harness
- Validates the versioned 40-case A2 catalog and rejects duplicate/malformed test IDs.
- Executes only registered synthetic adapters.
- Records exact commit SHA, repository/ref, workflow/run metadata, runner OS/architecture, timestamps, case result, reason code and evidence reference.
- Emits JSON into the workflow log and a GitHub Actions step summary.
- Uses distinct PASS, FAIL, BLOCKED, NOT RUN and NOT APPLICABLE states.
- A blocked case never becomes a pass merely because the catalog entry exists.
- The first nine adapters cover the existing kernel audit-failure decision, trust-store rollback, clock-anomaly denial, typed date-only semantics, Ethiopia technical locale/time-zone/currency defaults and cross-region isolation/authority-field rejection.

### Regional profile runtime foundation
- Adds a typed regional profile schema with jurisdiction, effective dates, language/script, calendar, time zone, currency, numeral systems, legal references, data-governance references and provenance.
- Implements deterministic preference precedence: deployment defaults → organization → user → request.
- Prevents user/request preferences from overriding jurisdiction, time zone or currency.
- Rejects unsupported preferences and inactive profiles.
- Fails closed for legal operations when legal references are absent/unreviewed and for cross-border transfer when data-governance references are absent/unreviewed.
- Adds Ethiopia and synthetic Kenya technical fixtures. These are test fixtures, not legal approvals or production profiles.

### Typed temporal semantics
- Adds distinct DateOnly, LocalDateTime and Instant variants.
- Prevents silent conversion of date-only or local civil values into absolute Unix instants.
- Performs structural validation only; calendar-specific conversion remains dependent on an independently reviewed Ethiopian calendar implementation/oracle.

## 2. Current conformance disposition

The exact-SHA workflow report is the authoritative count. The harness is expected to report:
- 40 catalog cases total;
- 9 registered synthetic adapters;
- 9 PASS if all registered adapter contracts succeed;
- 31 BLOCKED because required reviewed fixtures, runtime components or independent oracles are not yet available;
- 0 catalog-only or implicit passes.

A green Rust workflow means formatting, compilation, tests, lint and the harness execution succeeded. The A2 conformance gate remains BLOCKED while any required case is BLOCKED or NOT RUN.

## 3. Remaining A2 blockers

| Area | Missing evidence or implementation | Closure condition |
|---|---|---|
| Native OS boot/target | Signed boot artifact verification, immutable root of trust, target-specific boot chain and native target qualification | Implemented boot-chain adapters plus exact-SHA tests on each approved target |
| Capability/runtime isolation | Complete runtime capability token lifecycle, tenant/object isolation and delegation enforcement | Executable adapters for OS-CAP and OS-ISO cases; adversarial tests |
| IPC and resource controls | Replay-protected IPC, bounded payload handling, per-workload memory/resource quotas | Implemented IPC/quota services and OS-IPC/OS-RES fixtures |
| INL | Pinned normative grammar, parser, type/effect checker, capability model, canonical IR, VM/runtime and reproducible build pipeline | Owner-approved grammar/IR contracts, implementation and all INL positive/negative vectors |
| VYRAQON | Independent authoritative repository/release, grammar and semantic vectors, versioned artifact/digest, bilateral adapter | Pinned approved VYRAQON release and verified round-trip/negative interoperability suite |
| Amharic/Ethiopic text | Reviewed Amharic/English corpus, Unicode normalization policy, identity/name fixtures and rendering oracles | Independent corpus review and exact-SHA text/identity/rendering evidence |
| Ethiopian calendar | Independent calendar conversion oracle and boundary/leap-year fixtures | Reviewed oracle plus boundary and leap-year conformance evidence |
| Regional governance | Signed/versioned profile registry, legal references, data residency and cross-border policy approvals | Owner-approved profile lifecycle/signature model and jurisdictional legal review |
| Hardware/bare metal | Named hardware profiles, memory budgets, device drivers, boot qualification and physical test evidence | Approved hardware inventory/budgets and target-specific execution evidence |
| End-to-end assurance | Complete authorized Amharic request flow, privileged-instruction denial, protected side-effect adapter and reviewed fixtures | All required E2E cases executed on exact SHA with independent evidence |

## 4. Deliberate non-claims

- Ethiopia and Kenya regional records are technical fixtures only. They do not establish current law, residency permission or production compliance.
- The regional resolver is an in-process library contract, not yet a signed, persistent, multi-tenant profile registry.
- Temporal types preserve semantic distinctions but do not implement calendar conversion.
- The conformance runner executes nine adapters; it does not implement the other 31 platform components.
- A CI pass is not a hardware qualification, VYRAQON interoperability certification, corpus review or legal approval.

## 5. Gate disposition

- A2 conformance harness: **IMPLEMENTED; EXACT-SHA EXECUTION REQUIRED**.
- Regional profile resolver: **IMPLEMENTED AS TECHNICAL FOUNDATION; PRODUCTION GOVERNANCE OPEN**.
- Typed temporal semantics: **IMPLEMENTED; CALENDAR ORACLE OPEN**.
- K-04 A2 source findings: **REMEDIATED IN PR #10; EXACT-SHA CI PASS**.
- A2 platform-wide gate: **PARTIAL / NOT CLOSED**.
- A3 K-04 security remediation: **IMPLEMENTED IN PR #10; EXACT-SHA CI PASS; OPERATIONAL PRODUCTION EVIDENCE OPEN**.
- A5 deployment: **NOT STARTED**.

No merge, deployment, production trust activation, hardware qualification claim, VYRAQON release claim or A2 closure is made by this record.
