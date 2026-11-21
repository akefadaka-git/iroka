# NCE-01 Upstream Ingress Resource Contract (R-03)

**Status:** SPECIFIED — NOT IMPLEMENTED  
**Applies to:** Any future HTTP, IPC, file-import, queue-consumer, or other untrusted-input adapter that constructs `iroka-cognition::NativeReasoner`.  
**Authority:** This document constrains adapters; it does not create an ingress service or authorize network exposure.

## 1. Purpose and non-goals

The cognition crate has bounded retained state and reasoning work, but it does not own transport parsing, caller allocations, request admission, or process scheduling. This contract defines the minimum controls an adapter must enforce **before** creating owned `Literal`, `Rule`, or provenance values.

The adapter MUST NOT interpret source IDs as authenticated identities, treat partial reasoning as complete closure, or expose reasoning output as authorization to perform protected effects. Authentication, authorization, provenance trust, and execution grants remain separate controls.

## 2. Hard per-request input limits

| Input dimension | Maximum | Enforcement point |
|---|---:|---|
| Raw request body | 32 MiB (33,554,432 bytes) | Streaming transport reader, before full buffering/decompression |
| Decompressed body, if compression is enabled | 32 MiB | Decompressor output counter; compressed-size limit alone is insufficient |
| Facts | 10,000 | Streaming schema validator, before constructing owned facts |
| Rules | 2,000 | Streaming schema validator, before constructing owned rules |
| Premises per rule | 256 | Per-rule streaming counter |
| Total premises across rules | 50,000 | Request-wide streaming counter |
| Asserted fact/source records | 50,000 | Request-wide counter; duplicates follow engine idempotency rules |
| Atom, rule ID, source ID | 256 UTF-8 bytes each | Validate borrowed byte slices before allocating owned strings |
| Empty/blank atom, rule ID, source ID | Rejected | Schema validation before object construction |

The transport reader MUST stop after byte 33,554,432 and reject the request; it MUST NOT read an unbounded body into memory and check its size afterward. If compressed request bodies are supported, the decompressed-byte counter is mandatory. The safest initial deployment profile is to disable request compression.

The counts above are independent maxima, not a promise that every maximum can be represented in one 32 MiB body. The raw-body cap applies in addition to all semantic count limits.

## 3. Parsing and object-construction rules

1. Use a streaming parser or bounded token/event parser. Do not deserialize an untrusted body into an unconstrained generic JSON tree or unbounded intermediate `Vec`/map.
2. Maintain request-local counters for facts, rules, premises-per-rule, total premises, and asserted source records. Reject immediately when a counter would exceed its limit.
3. Validate UTF-8 byte lengths and blankness on borrowed input before cloning into owned strings. Do not use character count as a substitute for UTF-8 byte count.
4. Construct facts with `Literal::try_positive` / `Literal::try_negative`; never use compatibility constructors for untrusted raw strings.
5. Feed rule premises through a lazy iterator to `add_rule_from_iter`; do not first collect the complete untrusted premise list into a vector.
6. Validate rule/source IDs before retaining them. Source IDs are opaque metadata only and MUST NOT be represented as verified identities.
7. Do not silently truncate, drop, deduplicate, or reinterpret over-limit inputs. Return a stable validation error and leave request processing without a partially accepted request.
8. Bound diagnostic output: no full request echo, no unbounded list of invalid fields, and no raw sensitive payload in logs.

The adapter MUST keep all state request-scoped until validation succeeds. If an error occurs after engine construction has begun, discard the entire reasoner and report the request as rejected; do not reuse a partially populated reasoner for another request.

## 4. Time and cancellation budget

Use a monotonic clock. The proposed end-to-end request deadline is **5 seconds from admission**, including queue wait, body read, parsing, engine construction, reasoning, and response serialization. The existing engine's maximum 3-second cooperative reasoning/report-materialization budget remains a separate inner limit.

Suggested phase ceilings are: body read 1 second; parse and object construction 1 second; reasoning/report materialization up to 3 seconds; response serialization 1 second. These are sub-budgets within the 5-second overall deadline, not additive extensions. The adapter MUST propagate cancellation/deadline expiration, stop reading/parsing, discard partial input state, and avoid starting new work after cancellation.

A deadline is not a hard real-time guarantee. Runtime scheduling, allocator stalls, kernel I/O, and serialization may overrun; enforce a transport-level deadline and worker/process limits as well.

## 5. Admission control and memory isolation

The engine's previously calculated approximately 87.6 MB combined string-payload envelope excludes allocator/container overhead, parser buffers, input/output buffers, and caller-held copies. It MUST NOT be treated as a process-memory ceiling.

Before admitting a request, the adapter MUST acquire a weighted memory/concurrency permit. The permit weight MUST be established from peak-RSS measurements of the actual parser + engine + report + serializer path under adversarial maximum-size fixtures, with an explicit safety margin. A simple request-count semaphore is insufficient unless every request has the same conservative reservation.

Until those measurements exist, the safe deployment default is **one maximum-profile cognition request in flight per worker**, with an operator-configured worker memory limit and fail-closed admission when the reservation is unavailable. Do not infer a safe concurrency count from the 87.6 MB string-payload calculation.

The service MUST:
- enforce a process/container memory limit independent of request-level counters;
- reject or shed work before allocation when the weighted permit is unavailable;
- cap queued requests and queue wait time;
- release permits on success, validation failure, timeout, cancellation, and panic/unwind paths;
- avoid retaining completed reports beyond the request lifecycle unless a separately bounded storage policy applies;
- apply per-principal rate limits only after the principal has been authenticated by an independent identity layer.

If the process approaches its memory limit, stop admitting work and fail closed; do not rely on the allocator or operating system to recover gracefully.

## 6. Response and partial-result contract

The adapter MUST expose the engine's `stop_reason` and `ReasoningReport::is_complete()` / `is_partial()` semantics. A report stopped by `Deadline`, `StepBudget`, or `FactBudget` is partial and MUST NOT be described as a complete closure. A partial result must be visibly marked in the response schema and must not be cached as a complete answer.

Validation/resource rejection must be distinguishable from a valid reasoning result. Recommended stable categories:

- `BODY_TOO_LARGE`
- `DECOMPRESSED_BODY_TOO_LARGE`
- `INPUT_COUNT_LIMIT_EXCEEDED`
- `FIELD_TOO_LONG`
- `INVALID_INPUT`
- `ADMISSION_CAPACITY_EXCEEDED`
- `REQUEST_DEADLINE_EXCEEDED`
- `REASONING_PARTIAL`

Do not expose stack traces, internal memory figures, or raw untrusted values in client-facing errors.

## 7. Verification gates before an ingress implementation can be called complete

An implementation must provide automated tests for:

- body limit at exactly 32 MiB and one byte above;
- decompression expansion beyond 32 MiB, if compression is enabled;
- each semantic count at limit and one above;
- multibyte UTF-8 strings at exactly 256 bytes and 257 bytes;
- blank values and malformed UTF-8/JSON handling;
- a lazy premise stream that exceeds the cap, proving the parser stops without materializing the tail;
- aggregate premise/source overflow and request-wide atomic rejection;
- slow body delivery, parse deadline, reasoning deadline, serialization deadline, and cancellation;
- permit acquisition/release across success, every error path, timeout, cancellation, and panic;
- concurrent maximum-profile requests under the configured worker memory cap;
- peak RSS under adversarial fixtures with parser, engine, report, and serialization active together;
- partial reasoning response semantics and cache exclusion.

The acceptance report must record exact commit SHA, runtime/toolchain, fixture sizes, peak RSS, concurrency, memory limit, workflow runs, and test outcomes. A passing unit suite alone does not establish the process-memory bound.

## 8. Current implementation disposition

| Control | Status |
|---|---|
| Engine hard ceilings for configurable budgets | IMPLEMENTED / CI VERIFIED |
| Aggregate engine rule-premise ceiling (50,000) | IMPLEMENTED / CI VERIFIED |
| Aggregate asserted provenance ceiling (50,000) | IMPLEMENTED / CI VERIFIED |
| Borrowed atom/source validation and lazy premise API | IMPLEMENTED / CI VERIFIED |
| Transport raw/decompressed body cap | NOT IMPLEMENTED — no ingress adapter |
| Streaming schema parser and request-wide counters | NOT IMPLEMENTED — no ingress adapter |
| End-to-end deadline and cancellation propagation | NOT IMPLEMENTED — no ingress adapter |
| Weighted memory admission and queue cap | NOT IMPLEMENTED — no ingress adapter |
| Process/container memory cap and peak-RSS qualification | NOT IMPLEMENTED — deployment integration |
| Ingress adversarial integration test suite | NOT RUN — implementation does not exist |

**R-03 remains PARTIAL.** This contract is a design artifact, not evidence that ingress protection exists. Implementation requires a separately identified adapter/service and its own scoped implementation and verification work. No HTTP endpoint, network listener, deployment, or production activation is introduced by this specification.
