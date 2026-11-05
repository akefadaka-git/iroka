# IROKA A2 Owner Decision Register

- Register ID: IROKA-A2-OWNER-DECISIONS-001
- Version: 0.1.0
- Status: PROPOSED — OWNER DECISION REQUIRED
- Applies to: IROKA ZERO native OS, IROKA Native Language (INL), VYRAQON interoperability and conformance
- Governing baseline: IROKA A1 Amharic-first Ethiopian and African requirements
- Authority: Owner
- Implementation state: No decision in this register is approved merely by publication.

## 1. Purpose and decision protocol

This register converts unresolved A2 architecture questions into explicit, reviewable decisions. Each entry gives a recommended default, alternatives, consequences and evidence needed. Recommendations are not approvals.

Decision values:
- **APPROVE** — Owner accepts the recommendation as written.
- **AMEND** — Owner provides a replacement value or constraints.
- **DEFER** — Keep the decision unresolved and block dependent A3 work.
- **REJECT** — Do not use the recommendation; record the selected alternative and rationale.

No implementation, trust-root change, repository creation, cross-repository publication, merge or deployment is authorized by this register. Approved decisions must be recorded with Owner identity, timestamp, scope, version and an integrity-protected approval record before implementation planning treats them as binding.

## 2. Decision summary

| ID | Decision | Recommended default | Current status |
|---|---|---|---|
| OD-01 | Kernel architecture | Small capability-based microkernel; Rust implementation foundation | OWNER DECISION REQUIRED |
| OD-02 | Execution and portability | Deterministic typed IROKA IR plus sandboxed VM; native backends later | OWNER DECISION REQUIRED |
| OD-03 | Initial hardware targets | x86_64 and AArch64; hosted development mode first | OWNER DECISION REQUIRED |
| OD-04 | INL memory and safety model | Statically checked ownership/borrowing, safe by default | OWNER DECISION REQUIRED |
| OD-05 | INL compiler and runtime strategy | Rust-hosted compiler first; self-hosting only after conformance | OWNER DECISION REQUIRED |
| OD-06 | VYRAQON authority and repository boundary | Independent VYRAQON specification/release; IROKA adapter consumes signed releases | OWNER DECISION REQUIRED |
| OD-07 | Interchange representation | Versioned canonical semantic model; deterministic CBOR signed envelope; JSON debug view | OWNER DECISION REQUIRED |
| OD-08 | Regional and language profile policy | Amharic-first Ethiopia profile plus independently versioned African regional profiles | OWNER DECISION REQUIRED |
| OD-09 | Assurance and release thresholds | Zero tolerance for critical security failures; measurable performance budgets ratified per target | OWNER DECISION REQUIRED |

## 3. Detailed decisions

### OD-01 — Kernel architecture and privilege boundary

**Question:** What architecture governs the native IROKA OS kernel?

**Recommended default:** A small, capability-based microkernel. Keep scheduling, address-space isolation, interrupt and minimal IPC mechanisms in the privileged core. Move device drivers, filesystems, networking, language services and cognitive services into isolated user-space services wherever feasible. Retain the existing Rust kernel work as an implementation foundation subject to A2 security and architecture review; do not assume it already constitutes a complete native OS.

**Alternatives:** (A) monolithic kernel; (B) hybrid kernel; (C) microkernel with selected performance-critical services admitted to privileged space through separately reviewed interfaces.

**Rationale:** A small trusted computing base, explicit authority boundaries, fault containment and auditable service interfaces align with IROKA's assurance-first design.

**Consequences:** More IPC and service-boundary engineering; additional performance work; clearer least-privilege and independent service restart boundaries.

**A2 evidence required:** privilege map; threat model; trusted computing base inventory; boot and recovery design; IPC and capability model; driver isolation plan; failure-containment tests.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-02 — Execution model and portability

**Question:** What is the canonical execution target for INL and IROKA services?

**Recommended default:** Define a typed, versioned, deterministic IROKA Intermediate Representation (IIR). Execute portable workloads first in a capability-restricted virtual machine with explicit resource limits. Add architecture-specific native code generation only after semantic equivalence, reproducible builds and security conformance are demonstrated.

**Alternatives:** (A) native machine code as the only target; (B) WebAssembly as the canonical IR; (C) IIR plus VM and multiple backends (recommended).

**Rationale:** A platform-owned IR avoids coupling the language's semantics to one external runtime while allowing hosted development, offline operation and future hardware targets.

**Consequences:** IROKA must own IR versioning, verifier, VM semantics, debug metadata and backend conformance. WebAssembly may be evaluated as an optional interchange or hosted target, not silently made the normative language definition.

**A2 evidence required:** IR grammar/schema; verifier rules; deterministic execution contract; capability ABI; VM threat model; golden vectors; backend equivalence criteria.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-03 — Initial hardware and boot targets

**Question:** Which hardware families are first-class for the initial native OS engineering target?

**Recommended default:** x86_64 and AArch64 as initial architecture families, with a hosted developer/test profile preceding bare-metal release claims. Treat specific boards, firmware, secure boot facilities, TPM/TEE availability and device drivers as separately qualified platform profiles.

**Alternatives:** (A) x86_64 only; (B) AArch64 only; (C) both families; (D) hosted-only until a reference board is selected.

**Rationale:** Two major architecture families provide a useful portability test without pretending every device is supported. Hosted mode lowers early development risk.

**Consequences:** The project must maintain separate boot, interrupt, memory-map, device and hardware qualification matrices. A supported architecture family does not mean every machine in that family is supported.

**A2 evidence required:** reference hardware shortlist; firmware/boot assumptions; secure boot and recovery capabilities; minimum RAM/storage/CPU budgets; device support matrix; hardware lab and emulator strategy.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-04 — INL memory, type and safety model

**Question:** What safety model governs the native language?

**Recommended default:** A statically typed language with ownership and borrowing or an equivalently enforceable affine resource model; memory safety by default; explicit, narrowly scoped unsafe/foreign-function boundaries; algebraic data types; exhaustive pattern checking; deterministic error/result handling; and explicit effects.

**Alternatives:** (A) garbage-collected managed runtime; (B) ownership/borrowing model; (C) region/arena-based memory with static lifetime rules; (D) mixed model with a formally specified safe core.

**Rationale:** A safe systems language can support kernel and service development while making resource ownership, concurrency and authority visible in code review.

**Consequences:** Language ergonomics and compiler complexity require deliberate design. Unsafe code, FFI and runtime internals require separate audit rules. Static effect declarations do not grant runtime authority.

**A2 evidence required:** type-system specification; lifetime/resource rules; aliasing and concurrency model; unsafe-code policy; FFI boundary; diagnostics; reference examples; adversarial compiler tests.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-05 — INL compiler bootstrap and self-hosting

**Question:** How should the compiler and runtime be brought into existence?

**Recommended default:** Implement the first compiler and verifier in a mature, memory-safe host language (Rust is the proposed host, subject to review). Specify INL independently of its implementation language. Permit self-hosting only after the compiler, standard library, IR and runtime pass the same pinned conformance suite and reproducible-build checks.

**Alternatives:** (A) immediate self-hosting; (B) Rust-hosted bootstrap then staged self-hosting; (C) compiler implemented in another approved host language.

**Rationale:** A staged bootstrap reduces circular dependencies and makes compiler correctness measurable.

**Consequences:** A host compiler is a bootstrap dependency, not the identity of INL. Compiler provenance, toolchain pinning, artifact signing and independent rebuilds are mandatory.

**A2 evidence required:** compiler pipeline; grammar and semantic versioning; bootstrap trust chain; reproducible build process; compiler test corpus; self-hosting exit criteria.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-06 — VYRAQON authority, independence and repository boundary

**Question:** How is VYRAQON governed and consumed by IROKA?

**Recommended default:** VYRAQON remains an independently governed, separately versioned writing-system project and repository. IROKA consumes only explicit, versioned and integrity-verified VYRAQON releases through a narrow adapter. IROKA does not fork, silently redefine or claim ownership of VYRAQON's normative grammar. VYRAQON does not gain execution authority inside IROKA.

**Alternatives:** (A) VYRAQON maintained only inside IROKA; (B) separate project with IROKA-owned fork; (C) independent project with pinned, signed releases (recommended).

**Rationale:** This preserves the independent identity of VYRAQON and permits other systems to use it while protecting IROKA's execution and governance boundary.

**Consequences:** A bilateral compatibility contract, release provenance, version policy, conformance vectors and a repository access/visibility decision are required. The IROKA adapter must fail closed on unknown major versions or unsupported semantics.

**A2 evidence required:** confirmed VYRAQON repository; approved VYRAQON charter and normative release; canonical data model; signed release metadata; compatibility matrix; round-trip and downgrade tests.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-07 — VYRAQON interchange and canonical representation

**Question:** What representation is used at the IROKA/VYRAQON boundary?

**Recommended default:** A versioned semantic model with stable node identifiers, explicit script/language/orthography/semantic metadata, source spans, provenance and extension rules. Use deterministic CBOR for signed machine interchange, with a documented JSON diagnostic/debug representation. Preserve original source bytes/code points and distinguish source text from normalized semantic interpretation.

**Alternatives:** (A) JSON-only; (B) CBOR-only; (C) canonical semantic model with signed CBOR envelope and JSON diagnostic view (recommended).

**Rationale:** A canonical semantic model separates meaning from display and parser implementation; deterministic serialization supports signatures and reproducibility.

**Consequences:** The schema, canonicalization, unknown-field behavior, extension namespace, digest algorithm, signature envelope and compatibility policy must be normative. Do not assume this recommendation selects cryptographic algorithms or key custody without a separate security review.

**A2 evidence required:** schema and canonicalization spec; signed artifact example; parser/serializer vectors; unknown extension behavior; version compatibility matrix; source-preservation tests.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-08 — Amharic-first and African regional profile policy

**Question:** How do native OS, INL and VYRAQON preserve the binding regional requirements?

**Recommended default:** Maintain an Amharic-first Ethiopia profile as the default IROKA human-facing profile, with English as an available secondary language. Support Ethiopic Unicode text and mixed-script content without destructive transliteration. Use explicit Ethiopian-calendar and Gregorian-calendar types/conversions; do not collapse a civil date into a timestamp. Use Africa/Addis_Ababa and ETB as Ethiopia-profile defaults where applicable. Add independent, versioned African regional profiles rather than treating Africa as one locale or exporting Ethiopian defaults to all countries.

**Alternatives:** (A) Amharic-first Ethiopia baseline plus independently governed regional profiles (recommended); (B) language-neutral defaults with user-selected profiles; (C) separate country-specific distributions.

**Rationale:** It preserves the already-binding A1 contract while supporting Africa-wide expansion without cultural or legal overgeneralization.

**Consequences:** Unicode preservation, font/rendering/input, keyboard and speech support, calendar conversion, locale data, identity handling, legal terminology and human review require explicit acceptance criteria. Transliteration must never merge distinct identities or replace the original name.

**A2 evidence required:** reviewed Amharic/Ethiopic corpus; input/rendering/accessibility matrix; approved Ethiopian calendar reference oracle; date/time semantics; regional profile schema; competent language review and country-specific profile governance.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

### OD-09 — Assurance, release thresholds and performance budgets

**Question:** What conditions are required before a platform profile can be declared conformant or production-ready?

**Recommended default:**
1. Zero tolerance for known critical authorization bypass, cross-tenant access, signature-verification bypass, unsafe privileged execution or unrecoverable protected-state corruption.
2. Every normative conformance case must be executed against an exact commit and target profile; evidence must include test harness version, fixture/oracle version, environment, result and artifact references.
3. No aggregate pass percentage may conceal a critical failure or a blocked mandatory suite.
4. Performance budgets must be separately approved per reference hardware profile, with cold boot, service startup, IPC latency, scheduler latency, memory footprint, storage and recovery measurements.
5. Reproducible build verification and signed artifact provenance are release gates.

**Alternatives:** thresholds may be stricter; any relaxation requires an explicit Owner-approved risk exception with scope, expiry, compensating controls and audit record.

**Rationale:** Platform readiness is evidence-based and target-specific; passing a hosted test suite cannot certify bare-metal operation.

**Consequences:** The project needs test infrastructure, reference devices/emulators, reviewed language oracles, stable fixtures and release evidence retention.

**A2 evidence required:** finalized test catalog; harness; test oracles; target-specific budgets; security acceptance; recovery exercises; signed build attestations.

**Owner decision:** [ ] APPROVE  [ ] AMEND  [ ] DEFER  [ ] REJECT  
**Owner value / rationale:** Pending.

## 4. Mandatory A2 exit criteria

A2 may be proposed for closure only when all the following are true:

1. OD-01 through OD-09 have explicit Owner dispositions; any deferred item has an approved scope boundary and dependent A3 work remains blocked.
2. The OS threat model, privilege boundary, boot chain, hardware profiles, recovery model and trusted computing base are internally consistent.
3. INL grammar, type system, memory/resource model, effect system, concurrency model, IR, ABI, compiler bootstrap and package provenance are normative and versioned.
4. The VYRAQON repository and governance boundary are confirmed; the authoritative VYRAQON release and bilateral compatibility contract are available.
5. The Amharic/Ethiopic corpus and Ethiopian calendar oracle have independent competent review and provenance.
6. The conformance harness can execute the catalog, retain exact-SHA evidence and distinguish PASS, FAIL, BLOCKED and NOT RUN.
7. Critical security, authorization and regional-preservation cases have zero tolerance and are demonstrably enforced.
8. Performance budgets and supported target profiles are explicit; hosted and bare-metal evidence are not conflated.
9. All A2 documents are cross-linked, versioned and reviewed for contradictions.
10. A separate Owner authorization explicitly opens A3.

## 5. A3 implementation boundary

Once approved, A3 should be decomposed into separately reviewable work packages:

- A3-OS-01: boot/trust chain, kernel privilege boundary and platform abstraction.
- A3-OS-02: capability, IPC, isolation and resource enforcement.
- A3-INL-01: grammar, parser, type/effect checker and canonical IR.
- A3-INL-02: verifier, sandbox runtime and reproducible compiler pipeline.
- A3-VY-01: signed VYRAQON release ingestion, parser/serializer adapter and semantic conformance.
- A3-REG-01: Amharic/Ethiopic input, rendering, Unicode preservation, Ethiopian calendar and regional profiles.
- A3-ASSURE-01: conformance harness, evidence store, adversarial tests and release attestation.

Each work package requires an approved scope, acceptance criteria, threat review, exact target SHA and independent verification. No package authorizes production deployment.

## 6. Current dependency and evidence register

| Dependency | State at register creation | Closure evidence |
|---|---|---|
| IROKA destination repository | Present | Repository and branch read-back |
| IROKA A2 architecture contracts | Drafted on A2 branch | Owner review and consistency review |
| VYRAQON destination repository | Not verified/present in connected account search | Repository URL, access and governing charter |
| Normative VYRAQON grammar/release | Missing | Versioned source, release signature and conformance vectors |
| INL normative grammar | Pending Owner decision | Approved language specification |
| Amharic/Ethiopic reviewed corpus | Missing | Review record, corpus version and provenance |
| Ethiopian calendar oracle | Missing | Independent oracle and boundary vectors |
| Executable conformance harness | Not verified | Exact-SHA run with retained machine-readable evidence |
| Hardware performance budgets | Missing | Approved target profiles and measured baselines |

## 7. Owner response record

The Owner may respond using decision IDs and values, for example:

- `OD-01 APPROVE`
- `OD-02 AMEND: ...`
- `OD-03 DEFER`
- `OD-04 APPROVE`

No blank checkbox or proposed default is interpreted as approval. Record the final decision in a separate immutable approval artifact and link it to this register; do not rewrite historical decision records.
