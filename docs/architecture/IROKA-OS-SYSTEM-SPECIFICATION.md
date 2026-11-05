# IROKA OS — System Architecture Specification

**Contract ID:** IROKA-A2-OS-001  
**Version:** 1.0.0-draft  
**Status:** A2 design baseline; architecture decision gates explicitly identified  
**Normative parent:** IROKA-A1-REGIONAL-001 v1.0.0  
**Related:** IROKA-A2-NATIVE-001  
**Implementation authorization:** None; A3 remains gated

## 1. Purpose and scope

This specification defines the target architecture and externally observable contracts for IROKA OS. It covers boot and trust establishment, kernel/user-space separation, hardware abstraction, isolation, capabilities, IPC, scheduling, storage, networking, localization services, deployment modes, updates, recovery, observability and assurance.

IROKA OS is a long-term native computing platform. A hosted IROKA runtime is an interim deployment profile and is not a native OS. Existing Rust components are candidate implementation assets, not evidence that the complete OS described here exists.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are normative.

## 2. Design objectives and non-goals

### 2.1 Objectives

1. Establish a small, auditable privileged computing base.
2. Make identity, authority, capability and policy enforcement independent of probabilistic model output.
3. Isolate tenants, services, agents, workloads and external model adapters.
4. Support local, offline, hybrid and cloud deployments under the same security invariants.
5. Preserve source data, provenance and audit integrity across system boundaries.
6. Make resource use, effects, failures and recovery observable and bounded.
7. Provide Amharic-first Ethiopian user experience and extensible African regional profiles as platform requirements.
8. Permit independent replacement of hardware, model, storage, networking and presentation adapters without weakening the trusted control plane.

### 2.2 Non-goals

- A claim of a new hardware ISA, fabricated silicon, sentience or extraterrestrial technology.
- Unrestricted autonomous operation or self-modification of the trusted computing base.
- A requirement to replace every host OS immediately.
- A requirement for a single monolithic kernel, process or deployment unit.
- A claim of legal or regulatory compliance without jurisdiction-specific assessment.

## 3. System context and trust domains

The platform is divided into explicit trust domains:

| Domain | Responsibility | Trust rule |
|---|---|---|
| Hardware/firmware | CPU, memory, devices, boot firmware | Untrusted until measured/validated to the supported platform policy |
| Boot and platform trust | Verify boot chain and load policy | Minimal immutable/controlled root; rollback protected |
| IROKA Kernel | Isolation primitives, scheduling boundary, IPC mediation, capability enforcement hooks | Small privileged computing base |
| Trusted system services | Identity, policy, audit, storage/key broker, network broker, locale services | Least privilege; signed/versioned |
| Cognitive runtime | Reasoning, planning, memory and agents | No ambient authority; model output is untrusted input |
| VYRAQON/INL toolchain | Parse, validate, compile, link and package | Compiler output is data until verified and authorized |
| User applications | Workspace and user-facing applications | Sandboxed; explicit grants |
| External providers | Models, tools, cloud services, plugins | Replaceable and untrusted by default |
| Operator/Owner | Governance and risk acceptance | Explicit authenticated approvals; separation of duties where required |

A component MUST NOT acquire trust merely because it is inside the same process, repository, tenant, network or deployment.

## 4. Platform architecture

### 4.1 Logical layers

1. **Platform layer:** hardware abstraction, firmware interface, boot measurement and device discovery.
2. **Kernel layer:** address-space isolation, task scheduling primitives, interrupt and device mediation, capability handles, IPC transport and resource accounting.
3. **Trusted services:** identity/trust, policy, approval, audit, secure storage, key management, update/recovery, network mediation, time and localization.
4. **Runtime layer:** INL runtime, VYRAQON parser/serializer, verified IR execution, cognitive runtime and agent isolation.
5. **Experience layer:** Amharic-first shell, accessibility, workspace, applications, multimodal interfaces and developer tools.

### 4.2 Kernel architecture decision

The kernel design is not silently preselected. A2 records a preference for a minimal capability-oriented design and requires a comparative decision among:
- capability-based microkernel;
- capability-oriented modular kernel;
- other demonstrably suitable designs.

The decision record MUST score attack surface, memory isolation, formal/verifiable properties, driver isolation, IPC cost, portability, boot complexity, maintainability, hardware support and migration cost. A microkernel is not automatically safer without evidence; a monolithic design is not accepted solely for performance convenience.

### 4.3 Trusted computing base

The trusted computing base (TCB) MUST be enumerated by component, version, source, build provenance, privileges and assurance evidence. Components not needed for authorization, isolation or boot trust SHOULD remain outside the privileged TCB.

The TCB MUST include a defined mechanism for:
- authenticated principal and service identity;
- capability validation and revocation;
- policy decision enforcement for protected effects;
- audit event integrity and protected time/context;
- emergency containment and recovery;
- trusted update and rollback prevention.

No generative model, language parser, compiler, plugin or VYRAQON expression may become a trust root.

## 5. Boot, measured startup and trust lifecycle

### 5.1 Boot sequence

The implementation MUST define and verify the following conceptual chain:

1. Platform firmware establishes the initial execution environment.
2. Boot verifier validates the next-stage image against configured trust policy.
3. Each stage measures the next stage and relevant configuration into a protected measurement log.
4. Kernel image and mandatory boot policy are verified before privileged execution.
5. Trusted services start in dependency order with authenticated identities.
6. Policy and revocation state are loaded; stale or unverifiable critical state causes protected operations to fail closed.
7. Audit integrity and system health are established before workloads receive capabilities.
8. The system exposes a signed/attested boot state to authorized assurance consumers.

Hardware roots of trust are platform-dependent. Where unavailable, the system MUST declare a weaker assurance profile; software-only measurement MUST NOT be described as hardware-backed attestation.

### 5.2 Key lifecycle

Key generation, enrollment, storage, rotation, revocation, backup and destruction MUST be specified per key class. Private signing keys MUST NOT be embedded in source, ordinary images, logs or model context. Key access MUST be mediated by a dedicated broker or platform security facility.

Compromise response MUST support revocation, trust-chain replacement, artifact invalidation, forensic preservation and recovery. Recovery MUST NOT silently re-enroll an unverified identity.

### 5.3 Secure boot and rollback

- Boot artifacts and policy bundles MUST be authenticated.
- Version counters or equivalent anti-rollback controls MUST protect security-critical components.
- An update with an invalid signature, digest, provenance or policy compatibility MUST be rejected.
- Recovery images MUST be authenticated and separately controlled.
- Rollback MUST be blocked when it would reintroduce revoked keys, known critical vulnerabilities or incompatible state.

## 6. Kernel and user-space boundary

The kernel provides mechanisms, not business policy. Policy semantics remain in a separately testable trusted governance service, with enforcement hooks in the kernel/runtime.

Kernel responsibilities:
- process/task and address-space isolation;
- scheduling and resource accounting;
- capability handle lifecycle and kernel-mediated checks;
- secure IPC primitives;
- device and interrupt mediation;
- memory mapping and protected execution boundaries;
- fault containment and system health hooks.

User-space responsibilities:
- identity lifecycle and policy evaluation;
- Owner approvals and risk classification;
- audit indexing and evidence presentation;
- file and object services;
- network and model-provider adapters;
- locale, calendar, currency and language services;
- cognitive runtime, VYRAQON and INL tooling;
- shell, applications and accessibility.

A user-space service compromise MUST NOT permit direct modification of kernel memory, trusted boot state, signing roots or another tenant's protected address space.

## 7. Identity, capability and authorization model

### 7.1 Principal model

A principal is a typed, stable identity for a user, service, agent, workload or device. Authentication establishes a principal; it does not grant unrestricted authority.

### 7.2 Capability model

A capability MUST be:
- unforgeable or cryptographically verifiable;
- bound to issuer, subject, action, resource and scope;
- limited by tenant, purpose, environment and risk where applicable;
- time-bounded with explicit expiry;
- attenuable but never amplifiable by delegation;
- revocable, with defined revocation freshness;
- auditable and replay-resistant.

Ambient authority is prohibited for protected operations. File descriptors, handles, IPC endpoints and service tokens MUST carry explicit access semantics.

### 7.3 Policy decision

Every protected effect MUST resolve to one of:
- ALLOW;
- DENY;
- REQUIRE_APPROVAL;
- ESCALATE.

The decision MUST bind subject, capability, target, operation, context, policy version, approval reference, validity interval and trace ID. Unknown, malformed, stale, conflicting or unavailable authorization state MUST fail closed for protected operations.

The kernel may enforce a verified decision token, but it MUST NOT accept a model-generated statement as such a token.

### 7.4 Delegation

Delegation MUST preserve the original authority chain, scope ceiling, expiry and revocation. A delegated agent MUST NOT grant a capability it does not possess. Cross-tenant delegation is denied unless an explicit, policy-approved federation contract exists.

## 8. Process, task and resource model

The OS MUST distinguish:
- process: isolated protection and resource domain;
- task/thread: schedulable execution context;
- service: authenticated long-lived system component;
- agent: governed cognitive actor with a capability manifest;
- workload: bounded execution unit;
- transaction: effect group with commit/rollback semantics where supported.

Every workload MUST declare or receive policy-bounded CPU, memory, storage, network, concurrency and wall-clock budgets. Quotas MUST be enforced independently of model intent. Exhaustion MUST produce a typed failure and preserve system stability.

Priority scheduling MUST NOT allow an untrusted tenant to starve the governance, audit, revocation or recovery plane. Critical-service reservations and starvation controls require measurable tests.

## 9. Memory and isolation

The design MUST specify:
- address-space isolation and privilege transitions;
- safe allocation and lifetime rules;
- zeroization of designated secrets;
- shared-memory ownership and synchronization;
- DMA/IOMMU requirements where supported;
- speculative-execution and side-channel assumptions;
- crash/fault containment;
- memory quotas and exhaustion behavior.

A security claim MUST identify its hardware assumptions and residual risks. Shared memory MUST be treated as an explicit capability and validated at both endpoints.

## 10. IPC and service discovery

IPC MUST authenticate both endpoints, validate message schemas, enforce capability scope and preserve trace context. Service discovery MUST return authenticated identities and versioned interfaces, not trust based on service names or network location.

Messages crossing trust boundaries MUST include:
- schema and version;
- sender and recipient identities;
- tenant and classification context;
- correlation/trace ID;
- expiry or freshness data where relevant;
- integrity protection where threat model requires it.

Malformed, oversized, replayed, expired or unauthorized messages MUST be rejected with stable error codes. IPC MUST support bounded queues, backpressure, cancellation and deadline propagation.

## 11. Storage, filesystem and data lifecycle

Storage interfaces MUST separate:
- immutable source artifacts;
- derived artifacts and indexes;
- operational mutable state;
- secrets and key material;
- append-only or tamper-evident audit evidence.

Access is capability-controlled and tenant-scoped. Encryption at rest and in transit is required according to data classification and deployment profile. Integrity digests MUST bind source artifacts to derived processing lineage.

Deletion, retention, backup and legal hold semantics MUST be explicit per data class. A backup restore MUST preserve authorization boundaries and audit continuity. A derived summary, embedding or translation MUST NOT replace the source artifact.

## 12. Networking and external model isolation

Network access MUST be mediated by a policy-controlled broker or equivalent boundary. Workloads receive destination-, protocol-, byte- and time-bounded permissions. DNS resolution, proxying, certificate validation, egress logging and secret redaction MUST be specified.

External models and tools:
- receive only the minimum authorized data;
- have no direct kernel or governance authority;
- return untrusted outputs with provider/model/version provenance;
- cannot directly invoke privileged effects;
- are replaceable without changing the authorization model.

Offline mode MUST define local policy freshness, queued operations, conflict handling and revocation behavior. When revocation freshness cannot be established, protected operations requiring current authorization MUST be blocked or restricted to a formally approved offline policy.

## 13. Runtime, compiler and executable artifact loading

INL runtime and VYRAQON-generated artifacts MUST execute in isolated workloads with explicit memory, CPU, I/O and effect budgets. Loading requires:
1. canonical artifact identity and digest;
2. signature/provenance validation where required;
3. compatible language, IR, ABI and runtime versions;
4. static validation and declared effects;
5. policy evaluation and capability grant;
6. bounded execution;
7. correlated audit evidence.

Compilation MUST NOT execute output. Package installation MUST NOT run arbitrary lifecycle scripts with ambient authority. JIT execution, if ever supported, requires a separate threat model and code-integrity controls.

## 14. Amharic-first system and regional services

The A1 contract is normative and applies to every layer, including boot recovery UX, shell, diagnostics, logs exposed to users, system settings, consent, approval, notifications, developer tooling and documentation.

For the Ethiopia profile:
- Amharic (am-ET) is the default user-facing language; English is selectable as secondary.
- Ethiopic Unicode code points, combining marks, punctuation and mixed-script content MUST be preserved end-to-end.
- Ethiopian calendar is the default human-facing calendar; Gregorian interoperability remains available and explicit.
- Africa/Addis_Ababa is the default time zone.
- ETB is the default financial display/entry currency where relevant.
- Original-script identity names and source documents MUST remain authoritative.
- Numeric/date/currency machine values MUST remain typed and independent of localized presentation.

African expansion MUST use independently versioned regional profiles. Country, language, calendar, currency, time zone and legal jurisdiction MUST remain separate dimensions. Ethiopia-specific defaults MUST NOT leak into another profile unless that profile explicitly selects them.

A system failure or recovery screen MUST provide reviewed Amharic content for the Ethiopia profile. If a language pack is missing or corrupt, the system MUST preserve data and provide a clearly declared fallback; it MUST NOT claim full Amharic support.

## 15. Time, chronology and deterministic services

System instants use canonical UTC representation with explicit time source and monotonic-clock use for elapsed-time measurements. Civil dates and local times retain calendar and zone identifiers. Ethiopian calendar conversion MUST use a vetted deterministic library and boundary corpus; this spec does not select a library.

Time uncertainty, clock rollback and synchronization failure MUST be observable. Expiring capabilities MUST use a trusted time basis and fail closed when expiry cannot be safely evaluated.

## 16. Update, rollback and recovery

Updates MUST be signed, versioned, reproducible where feasible, staged and policy-approved. The update manifest binds:
- component identity and version;
- artifact digest;
- dependency and SBOM references;
- build provenance;
- compatible OS/kernel/runtime/ABI versions;
- required migrations;
- security advisories and rollback constraints.

A/B or equivalent atomic update strategy SHOULD be used where target hardware permits. Recovery MUST preserve audit evidence, restore trusted configuration and re-establish identity/revocation state before enabling protected effects.

## 17. Observability and assurance

System telemetry MUST distinguish inference, deterministic computation, policy decision, approval, execution and external effect. Logs MUST be structured, access-controlled and redacted. Audit records MUST be correlatable across kernel, services, compiler, VYRAQON and INL boundaries.

Minimum event fields:
- event ID and schema version;
- UTC timestamp and time quality;
- actor/service principal;
- tenant and classification;
- operation and target;
- capability/policy/approval identifiers;
- artifact and dependency digests where relevant;
- decision and result;
- trace/correlation ID;
- source language and locale/profile context when user-facing meaning depends on it.

Telemetry MUST NOT leak secrets or sensitive source text by default. Audit integrity failure MUST trigger a defined degraded/containment state.

## 18. Deployment profiles

| Profile | Description | Mandatory controls |
|---|---|---|
| Hosted development | IROKA services run on a supported host OS | Host isolation, signed components, explicit capabilities, no native OS claim |
| Single-device local | Local execution on approved hardware | Secure storage, local identity, update/recovery, offline policy |
| Private infrastructure | Organization-controlled deployment | Tenant isolation, key custody, audit and update governance |
| Hybrid | Local and remote components | Data placement policy, authenticated links, revocation freshness, synchronization |
| Native IROKA OS | Bootable OS on a supported hardware matrix | Full boot chain, kernel/user-space controls, recovery, hardware-specific assurance |

No profile inherits a stronger assurance claim than its tested controls support.

## 19. Threat model and required adversarial scenarios

Threat actors include malicious users, compromised agents, malicious documents, hostile model outputs, compromised providers, malicious packages, insiders, network attackers and compromised devices.

Mandatory scenarios:
1. Forged or replayed capability.
2. Expired/revoked grant during a long-running task.
3. Agent attempts privilege amplification through delegation.
4. Cross-tenant IPC or shared-memory access.
5. Malformed/oversized IPC message and queue exhaustion.
6. Compromised model proposes privileged command.
7. VYRAQON/INL artifact declares missing or misleading effects.
8. Malicious package or dependency substitution.
9. Boot image downgrade or invalid signature.
10. Audit sink unavailable or tampered.
11. Clock rollback during capability expiry check.
12. Offline operation with stale revocation state.
13. Resource exhaustion targeting governance/recovery services.
14. Ethiopic text corruption in recovery, logs or system UI.
15. Regional profile switch attempts to alter authority or legal configuration without approval.

## 20. Measurable OS acceptance gates

| ID | Measure | Threshold |
|---|---|---|
| OS-BOOT-01 | Invalid/unsigned boot artifact acceptance | 0 accepted |
| OS-BOOT-02 | Unauthorized rollback acceptance | 0 accepted |
| OS-CAP-01 | Forged, expired, revoked or out-of-scope capability accepted | 0 |
| OS-CAP-02 | Privilege amplification through delegation | 0 |
| OS-ISO-01 | Cross-tenant/process isolation violations in defined adversarial suite | 0 |
| OS-IPC-01 | Unauthorized/malformed/replayed IPC messages accepted | 0 |
| OS-RES-01 | Workload quota enforcement | 100% of specified boundary cases |
| OS-AUD-01 | Protected effect transitions with correlatable audit event | 100% |
| OS-UPD-01 | Invalid signature/digest/provenance update accepted | 0 |
| OS-REC-01 | Recovery restores approved trust policy without audit discontinuity | 100% of recovery fixtures |
| OS-LOC-01 | Ethiopia profile defaults and Amharic-first critical screens | 100% of A1 required journeys |
| OS-UNICODE-01 | Ethiopic source round-trip corruption | 0 code-point/byte changes in lossless paths |
| OS-REG-01 | Unconfigured Ethiopia defaults leaking to other profile | 0 |
| OS-MODEL-01 | Model-originated request bypasses policy/approval | 0 |

Performance thresholds MUST be established per named hardware target before implementation benchmarking. No universal latency or memory figure is asserted without a target device, workload and measurement method.

## 21. A2 decision register

The following are deliberately unresolved until evidence is supplied:
- kernel family and implementation boundary;
- initial CPU/board/firmware support matrix;
- hardware root-of-trust availability and assurance profiles;
- device driver isolation strategy;
- storage/filesystem choice and encryption/key custody model;
- scheduler policy and real-time requirements;
- IPC transport and wire encoding;
- offline revocation staleness bound;
- memory and performance budgets per target;
- approved Ethiopian calendar implementation and reference oracle;
- boot/update signing ceremony and key custody;
- exact TCB component inventory and formal assurance target.

These are blockers to an implementation-ready OS design decision. They MUST be resolved through versioned decision records before A3 work on the affected subsystem.

## 22. Exit evidence

This specification is complete as a system-level contract when the architecture decision register is resolved, each requirement maps to an implementation component and conformance test, the threat model is reviewed, target hardware is named, and Owner approval is recorded.

It does not prove an OS implementation exists or passes these gates. A3 authorization remains separate.
