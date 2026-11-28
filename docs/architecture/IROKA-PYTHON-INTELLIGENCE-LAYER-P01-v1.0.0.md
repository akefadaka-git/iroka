# IROKA Python Intelligence Layer — P01 Architecture and Constitutional Contract

**Document ID:** IROKA-PYINT-P01-001  
**Version:** 1.0.0  
**Status:** P01 architecture proposal — ready for Owner disposition; no Python production implementation authorized  
**Repository:** `akefadaka-git/iroka`  
**Baseline:** `main` at `6b7004c897907f5ca40de58fee7222732fd7cde0`  
**Parent architecture:** IROKA ZERO constitutional baseline; G01–G12 Genome; INNIA; BRAIN; INGA; integrated A2 implementation-contract reconciliation  
**Scope:** Python intelligence runtime, its module boundaries, Kernel interface, data/knowledge/memory integration, model execution, learning/evaluation and assurance  
**Change class:** Documentation-only architecture specification

---

## 1. Purpose and decision

This document defines the Python Intelligence Layer as a bounded computation subsystem within IROKA. It does not establish a second Kernel, a second authority plane, or a Python-owned copy of canonical identity, policy, memory, knowledge, audit or execution state.

**Architecture decision:** Python is an untrusted, replaceable intelligence-computation runtime. The Rust Governed Kernel remains the sole trusted authority boundary. Python may interpret, reason, retrieve through authorized domain interfaces, prepare proposals, execute approved model computations and produce evaluation evidence. It may not authenticate principals by itself, grant capabilities, decide policy, approve its own output, mutate canonical memory without G05 authorization, or execute protected effects directly.

The Python layer is a runtime implementation option within INNIA's computation plane and the G03/G10 capability surface. It is not a replacement for:
- the Rust Kernel and G01/G02/G09/G11 authority path;
- the existing Rust BRAIN contracts and bounded G03 cognitive primitives;
- INGA's separately governed native neurogenetic computation substrate;
- G04 knowledge ownership or G05 memory ownership;
- G08 durable workflow ownership;
- G10 evaluation/learning governance or G12 promotion/evolution governance.

The P01 objective is architectural separation and contract definition. Runtime code, dependency installation, model download, provider activation, training, production data use, merge and deployment are excluded.

## 2. Repository evidence and baseline

Read-only inspection of `main` at the baseline above established:
- the Cargo workspace contains only `crates/iroka-kernel`;
- the repository's canonical `main` has no Python package manifest, Python source tree, Python runtime, PyTorch integration or Python model-serving adapter;
- the Rust Kernel exposes identity, governance, policy, audit, security-store and authorization-service components;
- the existing BRAIN, INGA and INNIA candidates are separate branches/PRs and are not thereby integrated into `main`.

Relevant existing evidence:
- INNIA A1 architecture proposal: PR #134, draft, unmerged; proposes trusted control plane versus replaceable neural computation plane.
- INNIA A2 read-only reconciliation: PR #135, draft, unmerged; records no production model registry/serving runtime or governed training/promotion pipeline and lists unresolved dependencies.
- BRAIN bounded G03 synthetic core: PR #27, draft, unmerged; its stated scope uses a deterministic fake adapter and explicitly excludes provider access, persistence, delegation and protected effects.
- INGA neurogenetic candidate: PR #44, draft, unmerged; its PR description reports authored tests but no exact-head verification in the recorded evidence.
- Integrated A2 implementation-contract reconciliation: PR #146, draft, unmerged; records overall A2 as PARTIAL / NOT CLOSED.

These records are evidence of proposals and isolated candidate work, not evidence of a unified production Python runtime. P01 preserves their branch/PR lineage and does not adopt, merge, rewrite or supersede them.

## 3. Constitutional invariants

The following are mandatory for every Python package, process, adapter, model worker and training job:

1. **Kernel supremacy:** G01/G02/G09/G11 remain the only authority path for identity, policy, protected execution and assurance.
2. **No self-authority:** model output, Python code, tool output, retrieved content and agent plans cannot create or elevate authority.
3. **Deny by default:** missing, stale, invalid, revoked, ambiguous or unavailable authorization blocks protected reads and all protected effects.
4. **No raw bypass:** no Python module may call privileged tools, production APIs, domain databases, credential stores or execution adapters outside their governed service contracts.
5. **Domain ownership:** G04 owns knowledge; G05 owns canonical memory and consent; G08 owns durable workflow state; G10 owns evaluation/learning decisions; G12 owns evolution/promotion; G11 owns audit evidence.
6. **Provider independence:** provider SDKs are isolated behind replaceable adapters; provider-specific objects do not cross canonical contracts.
7. **Data minimization:** only the minimum authorized data required for a declared purpose may enter a model context.
8. **Tenant isolation:** tenant, actor, project, purpose and classification scope are preserved across queues, caches, retrieval, inference, logs and artifacts.
9. **Reproducibility:** every material output and evaluation binds to versioned code, configuration, model, adapter, prompt/template, dataset and evidence identifiers.
10. **Controlled learning:** training/adaptation creates quarantined candidates; no automatic online weight updates or self-promotion.
11. **Bounded resources:** time, input/output bytes, tokens, memory, CPU/GPU, concurrency, retries, queue depth and cost are enforced outside model control.
12. **Truthful status:** a passing synthetic adapter or unit test does not prove model quality, provider safety, Amharic quality, production readiness or independent assurance.

## 4. Target architecture

### 4.1 Trusted control plane — Rust Kernel and domain owners

The trusted control plane owns:
- principal authentication and tenant context (G01);
- Owner authority, policy, risk and approval (G02);
- current protected-effect authorization and execution (G09);
- authoritative audit and assurance evidence (G11);
- canonical knowledge/source permission and provenance (G04);
- canonical memory, consent, retention, correction and deletion (G05);
- durable task/workflow lifecycle, cancellation and recovery (G08);
- evaluation governance and accepted learning evidence (G10);
- model/architecture promotion and rollback governance (G12).

Python must not duplicate these services or access their underlying stores directly.

### 4.2 Python computation plane

Python provides replaceable implementation modules for:
- model adapter execution and inference composition;
- structured reasoning support and bounded task decomposition;
- language/NLP and multimodal model adapters;
- embedding computation (not canonical retrieval permission or source ownership);
- authorized context assembly using G04/G05 responses;
- offline dataset preparation and model evaluation workers;
- experiment orchestration within G08-issued bounded jobs;
- output validation, confidence/abstention reporting and candidate recommendations.

Python components are workers, not authorities. They receive narrow task-scoped input and return typed results.

### 4.3 Conceptual flow

`Client / Agent → Rust Kernel authentication and policy → G08 task admission → Python task worker → authorized G04/G05 context → isolated model adapter → output validation → G11 evidence → response`

Any proposed protected effect follows a separate path:

`Python proposal → Rust Kernel authorization → G09 execution service → verified effect receipt → G11 audit`

The Python process never converts an `ALLOW` decision into an unrestricted capability. Only the authoritative G09 service may admit and perform a protected effect under its own current checks.

## 5. Python package boundaries

The following are logical package boundaries, not a requirement for one microservice per package. A2 may combine packages where isolation, ownership and testability remain intact.

| Package | Responsibility | Must not own |
|---|---|---|
| `iroka_py.contracts` | Versioned request/result/error DTOs and schema validation | Identity, policy or grants |
| `iroka_py.kernel_client` | Authenticated client for approved Kernel/domain contracts | Direct SQL, local policy decisions or token minting |
| `iroka_py.runtime` | Worker lifecycle, task admission, deadlines, cancellation and resource accounting | Durable workflow truth or protected execution |
| `iroka_py.models` | Model manifest parsing, adapter registry and capability declarations | Canonical model approval/promotion state |
| `iroka_py.inference` | Bounded inference calls and normalized outputs | Provider authority or arbitrary network access |
| `iroka_py.reasoning` | Reasoning strategies, decomposition, synthesis and abstention | G03 canonical policy, identity or memory |
| `iroka_py.language` | Language detection/classification and language-model adapters | Claims of reviewed language quality without evaluation |
| `iroka_py.perception` | Optional OCR/vision/audio adapters returning candidate observations | Source-document truth or acceptance of consequential fields |
| `iroka_py.context` | Purpose-bound context assembly from authorized G04/G05 results | Retrieval authorization or canonical storage |
| `iroka_py.embeddings` | Embedding generation and version metadata | Source permissions, canonical index or memory lifecycle |
| `iroka_py.evaluation` | Reproducible benchmark execution and metric calculation | Approval of its own candidate or release |
| `iroka_py.learning` | Offline experiment orchestration and candidate packaging | Online production weight mutation or self-promotion |
| `iroka_py.observability` | Redacted traces, metrics and correlation metadata | Independent audit ledger or sensitive prompt retention |
| `iroka_py.security` | Local input validation, artifact digest checks and sandbox configuration | A second authorization engine or trust-root registry |

Import direction must be acyclic. Domain-facing interfaces depend on `contracts`; provider adapters depend on adapter protocols; application composition wires implementations. No provider-specific package may become a dependency of the contract layer.

## 6. Rust/Python integration contract

### 6.1 Process boundary

P01 selects a separate Python worker process as the default deployment boundary. In-process embedding of Python into the Rust Kernel is not the baseline because it expands the trusted computing base, couples interpreter lifecycle to authority code and complicates failure isolation.

The exact transport (local Unix-domain socket, named pipe, loopback mutually authenticated HTTP, or another reviewed IPC mechanism) is an A2 decision. It must provide:
- peer/process authentication and integrity;
- explicit protocol and schema versions;
- bounded frame/message sizes;
- request/response correlation and replay-safe task IDs;
- deadlines and cancellation;
- authenticated tenant/task scope supplied by the trusted composition root;
- no caller-controlled authority fields;
- fail-closed behavior on malformed, expired or uncorrelated messages.

No network listener or cross-host Python service is implied by P01.

### 6.2 Request envelope

The normative logical request contains:
- `schema_id`, `schema_version`, `request_id`, `trace_id`;
- task type and declared objective;
- opaque Kernel-issued actor/tenant/task context references;
- requested capability identifiers;
- purpose and data-classification ceiling;
- explicit locale/language metadata where relevant;
- authorized evidence/context references, not unverified content claims;
- bounded input/output, time, concurrency and resource budgets;
- deadline/cancellation reference;
- idempotency key for retryable task submission.

The envelope MUST NOT accept caller-authored `is_owner`, role lists, policy objects, raw bearer credentials, trusted tenant membership, approval decisions or execution grants as proof.

### 6.3 Result envelope

The result contains:
- matching schema/version and request/trace IDs;
- task status: `SUCCEEDED`, `PARTIAL`, `ABSTAINED`, `REJECTED`, `CANCELLED`, `TIMED_OUT` or `FAILED`;
- typed output payload and declared output schema;
- evidence references/citation spans returned by authorized owners;
- model, adapter, runtime and configuration identifiers;
- confidence/calibration metadata only where supported by the method;
- limitations, unresolved questions and validation failures;
- resource usage and timing;
- output digest and provenance references.

A result cannot carry an authorization decision that the Kernel has not issued. Any action plan is a proposal only.

### 6.4 Error semantics

Errors are stable machine codes, not provider-native exception text. They distinguish invalid schema, unsupported version, unauthorized context, unavailable domain authority, budget exceeded, provider unavailable, model timeout, output validation failure, cancellation, audit failure and indeterminate task outcome. Sensitive data and credentials must not appear in error strings or logs.

## 7. Model adapter and provider isolation

Every adapter implements a narrow capability protocol: describe capabilities, validate its configuration, execute one bounded request, report normalized result/usage and close/cancel safely.

Adapters MUST:
- declare provider/model/version, supported tasks/modalities, language claims, context/output limits, resource needs and data handling;
- use immutable configuration snapshots and explicit timeouts;
- receive only the authorized input subset;
- have network egress disabled unless a separately approved provider policy enables a specific destination;
- avoid ambient credentials and implicit environment discovery;
- normalize errors and redact provider payloads;
- support deterministic fake adapters for contract tests;
- expose no tool execution, filesystem escape, subprocess shell or credential-management capability by default.

No production provider is selected by P01. Local inference is the preferred first evaluation target because it can be tested without paid services or external data transfer, but the model and runtime are A2 choices based on hardware, license, quality, security and reproducibility evidence. No model download, GPU provisioning or paid inference is authorized.

## 8. Knowledge, memory and perception integration

### G04 knowledge
Python requests retrieval through the G04-owned interface. G04 must enforce source permissions before ranking or returning content. Each returned evidence item carries source identity/version, exact locator/span, source hash or integrity reference, freshness, rights/license, tenant and classification metadata. Python may rank or summarize only the authorized result set. It may not create a parallel canonical knowledge store.

### G05 memory
Python requests memory through G05. G05 controls consent, purpose, classification, retention, correction, deletion and authorization. Memory writes are proposals submitted to G05; the model cannot directly persist a durable memory. Derived summaries/embeddings must remain linked to source memory/version and participate in correction/deletion propagation.

### G06 perception
Python perception adapters return candidate observations with source hash, page/region/time locator, engine/model version, language/script, confidence and review state. OCR or model extraction is not source truth. Consequential identity, legal, financial or governance fields require the applicable human verification process.

### Context assembly
Context assembly is purpose-bound and least-privilege. Untrusted retrieved text is marked as data, never elevated to instructions. Prompt injection cannot alter the worker's allowed capabilities, adapter policy, tenant scope or tool inventory.

## 9. Learning and model lifecycle

The Python layer may run offline experiments, but lifecycle authority remains with G10/G12 and G02 where approvals are required.

Candidate lifecycle:

`PROPOSED → RIGHTS_REVIEW → QUARANTINED → DATASET_VALIDATED → EXPERIMENTED → EVALUATED → SECURITY_REVIEWED → CANDIDATE_PACKAGED → APPROVAL_PENDING → APPROVED → STAGED → ACTIVE`

Any failure may result in `REJECTED`, `QUARANTINED` or `DISABLED`. Python workers cannot transition an artifact into `APPROVED` or `ACTIVE`.

Mandatory controls:
- dataset source, rights/consent, purpose, classification, retention and immutable version;
- train/validation/test split provenance and held-out evaluation;
- contamination/leakage checks and duplicate detection;
- baseline comparison and predeclared acceptance thresholds;
- robustness, prompt-injection, privacy-leakage and regression tests;
- Amharic/Ethiopic and multilingual evaluation where claimed;
- model artifact digest, dependency/SBOM record and reproducible build metadata;
- human review and required Owner authorization for promotion;
- rollback to a previously approved artifact.

Online learning and automatic production weight updates are disabled by default and excluded from the initial Python layer.

## 10. Security, privacy and execution isolation

Python workers run with:
- a dedicated non-privileged OS identity;
- read-only code/model mounts and a bounded temporary workspace;
- no access to Kernel signing keys, trust roots, production database credentials or host secrets;
- default-deny filesystem and network access;
- CPU, memory, process, file-size, wall-time, output-size and concurrency limits;
- pinned runtime/dependency artifacts and vulnerability/secret scanning;
- explicit task-scoped input/output channels;
- process termination and cleanup on timeout, cancellation or policy revocation;
- redacted telemetry and no raw prompt/content logging by default.

Python must not invoke arbitrary shell commands or spawn unconstrained child processes. If subprocess execution is later required for a specific model runtime, it is a separately reviewed adapter capability with a pinned executable, argument allowlist and OS sandbox contract. A Python-level timeout alone is not a security sandbox.

## 11. Amharic-first and regional intelligence requirements

The Python layer inherits the binding IROKA Amharic-first regional architecture:
- preserve original Unicode/Ethiopic source text;
- treat normalization as a derived representation with algorithm/version metadata;
- support mixed Ethiopic/Latin content and explicit language tags;
- evaluate Amharic morphology, spelling, dialect/code-switching and named-entity behavior separately;
- preserve original evidence alongside translation, transliteration, summary and embedding derivatives;
- distinguish Ethiopian-calendar date values from Gregorian values and UTC instants;
- do not infer identity, language, ethnicity, jurisdiction or consent from a person's name or network location;
- require human review for consequential translation, OCR, identity, legal, financial and official-document interpretation until independently reviewed acceptance evidence exists.

A model's advertised language coverage is not acceptance evidence. P01 sets no numerical quality claim or benchmark threshold.

## 12. Reliability, observability and operational behavior

Every task must have a bounded deadline, cancellation path, maximum attempts, resource ceiling and explicit outcome semantics. Retries are idempotent and must not duplicate protected effects. If a worker loses connection after execution begins, the task outcome is resolved through G08 task state; the caller must not assume failure or retry blindly.

Telemetry records task/trace IDs, model/adapter/runtime versions, policy reference, authorized source references, placement, resource use, latency, status and output digest. It excludes raw prompts, private retrieved content, secrets and personal data unless a separately approved diagnostic purpose and retention policy permit them.

Worker crash, provider timeout, invalid output, stale authorization, G04/G05 unavailability, audit failure, queue saturation and cancellation races must produce explicit bounded outcomes. Protected operations fail closed when their required authority or audit path is unavailable.

## 13. Testing and acceptance design

P01 requires the following test families to be defined before A3:

1. **Contract conformance:** schema versioning, unknown fields, bounds, malformed payloads, correlation mismatch and compatibility.
2. **Authority boundary:** forged actor/tenant/role/approval fields, stale/revoked context, wrong tenant, cross-project access and attempted direct execution.
3. **Bypass resistance:** raw adapter access, direct database/network access, tool injection, shell/subprocess attempts and environment-secret discovery.
4. **Data governance:** G04 permission-before-retrieval, G05 consent/retention/deletion propagation, classification and minimization.
5. **Prompt injection:** malicious retrieved content, indirect instructions, output-schema attacks and tool-call proposals.
6. **Runtime isolation:** filesystem, network, process, CPU, memory, output and wall-time limits.
7. **Reliability:** timeout, cancellation, crash, retry, duplicate delivery, queue saturation and indeterminate outcomes.
8. **Model provenance:** digest mismatch, unapproved artifact, license failure, model substitution and rollback.
9. **Learning integrity:** dataset leakage, duplicate/poisoned examples, unauthorized data, evaluation contamination and self-promotion attempts.
10. **Language quality:** frozen, licensed, reviewed Amharic/Ethiopic and multilingual corpora with held-out sets and independent human evaluation.
11. **Reproducibility:** same pinned inputs/configuration/artifacts yield reproducible deterministic contract/evaluation outputs within declared numerical tolerances.
12. **Performance:** per-workload latency, throughput, memory/accelerator use, cost ceilings and degraded-mode behavior on declared reference hardware.

No single aggregate intelligence score can mask a critical authorization, privacy, data-integrity or safety failure.

## 14. Technology selection policy

P01 freezes responsibilities and boundaries, not specific Python package versions or a framework choice.

A2 must compare candidate Python versions, environment/packaging tools, schema/serialization libraries, Rust IPC bindings, ML frameworks, local inference runtimes, tokenizer libraries, vector/embedding libraries and sandbox mechanisms against:
- active maintenance and supported Python/Rust compatibility;
- license and transitive dependency obligations;
- known vulnerabilities and supply-chain posture;
- deterministic/reproducible installation and offline availability;
- CPU-first viability and optional accelerator portability;
- memory/latency/resource characteristics on available hardware;
- Amharic/Ethiopic tokenizer and Unicode behavior;
- isolation, data handling and telemetry defaults;
- provider replaceability and API stability;
- free/no-cost operation for the initial baseline.

PyTorch is a candidate for training/research workloads, not a mandatory runtime dependency. A lightweight inference runtime may be more suitable for deployment. No dependency is approved until the A2 dependency register contains exact version, license, provenance, security review, purpose and owner disposition. Do not introduce multiple overlapping ML frameworks without a measured need.

## 15. A2 decisions required before Python implementation

| ID | Decision / evidence | Current status |
|---|---|---|
| PY-A2-01 | Reconcile exact current heads and contracts for BRAIN, INGA, INNIA, G04, G05, G08, G09, G10, G11 and G12 | PARTIAL; candidate work is split across unmerged branches |
| PY-A2-02 | Select Python runtime version and deterministic offline packaging strategy | OPEN |
| PY-A2-03 | Select Rust/Python IPC protocol and authentication mechanism | OPEN |
| PY-A2-04 | Define machine-readable request/result/error schemas and compatibility policy | OPEN |
| PY-A2-05 | Select initial CPU-only inference target and hardware baseline | OPEN |
| PY-A2-06 | Select model format, tokenizer and adapter capability contract | OPEN |
| PY-A2-07 | Complete dependency/license/SBOM/security review | NOT DONE |
| PY-A2-08 | Define G04/G05 authorized context and memory-write proposal adapters | BLOCKED on authoritative interface integration |
| PY-A2-09 | Define G08 job admission, trusted time, cancellation and recovery composition | BLOCKED on G08 temporal contract disposition |
| PY-A2-10 | Define G10 dataset/evaluation evidence and G12 promotion/rollback interfaces | OPEN |
| PY-A2-11 | Freeze Amharic/Ethiopic benchmark corpus, rights and independent human-review oracle | MISSING |
| PY-A2-12 | Define worker OS sandbox, egress and resource enforcement evidence | OPEN |
| PY-A2-13 | Define test harness, exact-SHA CI and acceptance thresholds | OPEN |
| PY-A2-14 | Record explicit Owner approval of the A3 Python implementation scope | NOT GRANTED BY THIS DOCUMENT |

## 16. A3 implementation order after A2 closure and separate authorization

The proposed dependency order is:

1. **P02 — Contract package:** versioned DTOs, schema validation, error taxonomy and compatibility tests; no provider access.
2. **P03 — Kernel client and worker boundary:** authenticated IPC, opaque context references, cancellation and fail-closed admission.
3. **P04 — Deterministic fake adapter:** bounded execution, result normalization and adversarial contract tests.
4. **P05 — Local CPU inference adapter:** only after runtime/dependency/model license and sandbox review.
5. **P06 — G03/BRAIN composition:** consume bounded reasoning interfaces; preserve Rust BRAIN authority boundaries and abstention semantics.
6. **P07 — G04/G05 integration:** authorized retrieval/context and governed memory proposals only after exact owner contracts are available.
7. **P08 — Language/perception adapters:** only with approved datasets, rights and acceptance oracles.
8. **P09 — G10 evaluation and offline learning:** isolated experiments, immutable artifacts and non-self-promoting candidate records.
9. **P10 — G08/G09/G11/G12 integration:** durable task lifecycle, protected-effect handoff, audit and governed artifact promotion.
10. **P11 — Exact-SHA integrated verification:** contract, security, isolation, reproducibility, language, performance and failure-mode evidence.

Each increment remains on a separately authorized branch/PR. Merge and deployment remain separate approvals.

## 17. P01 exit criteria and disposition

P01 is complete as an architecture specification when:
- the Python runtime is explicitly subordinate to the Rust Kernel;
- G01–G12 ownership and non-ownership are mapped;
- package and process boundaries are defined;
- Rust/Python request/result/error semantics are defined;
- model/provider and training lifecycle boundaries are defined;
- G04/G05/G08/G09/G10/G11/G12 dependencies are explicit;
- security, privacy, regional, testing and reproducibility requirements are stated;
- open A2 decisions and A3 entry conditions are recorded;
- no implementation or production activation is represented as complete.

**P01 disposition in this document:** architecture specification complete and submitted for Owner disposition. It does not close the broader INNIA A2 reconciliation, resolve the A2 decisions in Section 15, or authorize A3.

**Overall Python Intelligence Layer status:** architecture-defined; repository runtime MISSING on canonical main; production readiness NOT ESTABLISHED.

**Immediate next gate:** P02/A2 — resolve the open technology, IPC, schema, model, sandbox, dataset and domain-integration decisions, then obtain explicit A3 scope authorization before creating Python runtime code.

---

## 18. Preservation and non-actions

- This document is documentation-only.
- Canonical `main` is unchanged.
- No Rust or Python runtime source, package manifest, lockfile, workflow, migration, dependency or production configuration is changed.
- No existing candidate branch or PR is rewritten, rebased, merged, closed or deleted.
- No Python dependency is installed; no model is downloaded or activated.
- No external provider, paid service, production data, production credential or trust root is used.
- No training, production activation, release or deployment is performed.

**Constitutional operating rule:** Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.
