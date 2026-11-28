# IROKA Python Intelligence Layer — P02 Technology and Integration Reconciliation

**Document ID:** IROKA-PYINT-P02-001  
**Version:** 1.0.0  
**Status:** A2 reconciliation performed; A2 EXIT GATE PARTIAL / NOT CLOSED  
**Repository:** `akefadaka-git/iroka`  
**Canonical main baseline inspected:** `6b7004c897907f5ca40de58fee7222732fd7cde0`  
**P01 specification:** `IROKA-PYINT-P01-001 v1.0.0`, commit `0842fb353710185bd4239a31e1feaa28c13eae3d`  
**Mode:** Read-only source reconciliation plus documentation-only decision record. No Python production code is authorized or introduced.

---

## 1. Executive determination

P02 has reconciled the Python-layer architecture against the current canonical main branch and the relevant unmerged BRAIN, INGA, INNIA, G04, G05, G08, G09, G10, G11 and G12 candidate work.

**Determination: P02 reconciliation is materially advanced, but NOT CLOSED.** The architectural boundary is sound: Python must remain a replaceable, untrusted computation worker below the Rust Governed Kernel. The repository does not yet contain a Python runtime, Python package manifest, Python dependency lock, Python CI workflow, approved model artifact, or verified Python/Rust worker integration.

The available evidence is sufficient to define the implementation constraints and reject unsafe integration shortcuts. It is not sufficient to freeze a specific Python version, inference engine, model format, accelerator matrix, IPC transport, production sandbox, benchmark corpus or complete cross-domain runtime composition.

The P02 outcome is therefore a **decision-ready A2 register with explicit unresolved items**, not a false claim that all technology choices have been verified.

## 2. Scope and method

Read-only inspection covered:
- canonical `main` tree and Cargo workspace at the baseline above;
- P01 Python architecture branch and draft PR #148;
- INNIA A1/A2 proposals and the integrated A2 implementation-contract reconciliation;
- current PR metadata, exact head/base SHAs, stated workflow evidence and dependency ancestry for BRAIN, INGA, Native Cognition, G04/G05, G08 and G02/G09/G11 candidates;
- the documented G08 temporal contract and the G05/G04 adapter boundaries.

Evidence rules:
- PR body statements are claims until matched to the exact current head SHA and a corresponding run.
- A passing candidate test proves only the tested candidate and scope; it does not prove integration or production readiness.
- Historical branch-local evidence is not promoted to current-main evidence.
- Unmerged PRs and their branches remain separate candidates and are not silently composed into one runtime.
- Missing hardware, corpus, operational or owner evidence is recorded as missing rather than inferred.

## 3. Canonical baseline and Python source inventory

The inspected `main` baseline is `6b7004c897907f5ca40de58fee7222732fd7cde0`. Its Cargo workspace contains `crates/iroka-kernel`. The inspected canonical tree does not establish:
- a Python source package or runtime entry point;
- `pyproject.toml`, Python requirements/lockfile or Python environment policy;
- a Rust/Python IPC implementation or protocol schema;
- a model registry, inference server or approved model artifact;
- Python worker sandbox or Python CI test matrix;
- a governed dataset/training/evaluation/promotion pipeline.

This is a repository finding, not a claim that no Python code exists anywhere in other repositories or personal environments. No such external source is adopted by this P02 record.

## 4. Normative architecture and ownership

P01 is the governing Python-layer proposal on branch `architecture/python-intelligence-p01`. Its constitutional rule is retained:

**Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.**

| Owner | Canonical responsibility | Python integration constraint |
|---|---|---|
| Rust Kernel / G01 | Principal authentication, trust and credential validity | Consume verified opaque principal/task context; never authenticate from Python claims |
| G02 | Owner/organization/tenant authority, policy, approval and revocation | Consume current Kernel decisions; no local roles, grants, tenant authority or policy engine |
| G03 / BRAIN | Cognitive task orchestration, reasoning and candidate plans | Python may provide bounded computation behind G03 contracts; no canonical cognitive authority |
| G04 | Knowledge source registry, rights, access, retrieval, provenance and freshness | Retrieve only through G04; no parallel knowledge store or permission shortcut |
| G05 | Canonical memory, consent, purpose, classification, retention, correction and deletion | No direct database access or model-controlled canonical memory writes |
| G06 | Perception and normalized observations | Python adapters return typed, source-bound candidate observations, not source truth |
| G08 | Durable task/workflow lifecycle, trusted time, leases, retries, cancellation and recovery | Python workers execute bounded admitted jobs; they do not own workflow truth or caller-supplied deadlines |
| G09 | Protected-effect authorization and execution | Python returns proposals only; protected effects return to the Kernel/G09 service |
| G10 | Dataset governance, evaluation and learning decisions | Python may run isolated evaluation/experiments; it cannot approve its own results |
| G11 | Authoritative audit and assurance evidence | Use approved audit/evidence interfaces; model output is never self-attestation |
| G12 / IGACMS | Versioning, evolution, compatibility, activation and rollback | Candidate artifacts remain quarantined until governed approval and promotion |

No Python package may duplicate any of these canonical owners.

## 5. Candidate implementation reconciliation

### 5.1 BRAIN and symbolic cognition

- **BRAIN PR #27:** current PR metadata reports head `5c551a7ab023b05adf98022903cdc0ea8640ae02`; its description cites a previously verified synthetic B01 head `9d68b580e06bb8335a626524d64b345c3a5a38aa`. Those SHAs differ. The cited earlier PASS is not sufficient proof for the current PR head. The implementation remains a bounded Rust synthetic cognitive core with fake adapter only; no production model runtime or provider.
- **Native Cognition PR #130:** head `d0801273231eccb7316d40af29d07a51c25eedf3`; bounded deterministic symbolic reasoning candidate with prior exact-head workflow evidence reported PASS. It is complementary to neural computation, not a model-serving runtime.
- **Native constraint solver PR #147:** head `0ba01ae8e2e3ead7c87a13cfa8723eca0ef12d32`; its PR reports exact-head format, tests and Clippy PASS for the bounded solver increment. It does not supply a Python runtime or model gateway.

Disposition: preserve the separate Rust capabilities. Python may later implement model-backed adapters behind a frozen G03 interface; do not recreate the Rust symbolic engine or G03 authority in Python.

### 5.2 INGA and INNIA

- **INGA PR #44:** current head `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d`, based on BRAIN PR #27's earlier head `9d68b580e06bb8335a626524d64b345c3a5a38aa`. Its description reports 30 authored tests but explicitly says format, compile, tests and Clippy were NOT RUN at that recorded evidence point. Treat exact-head verification as NOT ESTABLISHED until a current-head run is inspected.
- **INNIA A1 PR #134:** draft and unmerged; its base is older than the ratified current main baseline. It is an architecture proposal, not proof of an integrated runtime.
- **INNIA A2 PR #135:** draft and unmerged; its base is also older than current main. Its report says A2 PARTIAL / NOT CLOSED, identifies missing neural/model runtime, missing model registry and training/promotion pipeline, and preserves unresolved G04/G05/G08/G10/G12 integration.
- **Integrated A2 PR #146:** draft and unmerged, based on current main SHA `6b7004c897907f5ca40de58fee7222732fd7cde0`. It records cross-domain ownership and explicitly says overall A2 remains PARTIAL / NOT CLOSED.

Disposition: P02 must not claim that INNIA is already a deployed model-serving system or that INGA is a trained neural model. Refresh the older INNIA evidence against the current main baseline before adopting it as a normative integration artifact.

### 5.3 G04 knowledge

- **G04 contract proposal PR #31:** Owner-approved G04 ownership boundary; G04 remains the authority for source permissions, lifecycle, retrieval, provenance, freshness and revocation.
- **G04 adapter PR #32:** current head `4e0c954516b4a471e2f36760b665add0a98efe9f`; its description reports exact-head workflow #707 SUCCESS. It supplies typed retrieval request/evidence-bundle contracts and a fail-closed validating adapter.
- PR #32 explicitly does not supply a G04 provider/runtime, source registry, persistent store, index, crawler or production retrieval engine. It does not authenticate opaque G01/G02 references itself; the authoritative provider must resolve and enforce them. G11 event extension and G10 evaluation integration remain separately gated.

Disposition: reuse the typed G04 adapter as a candidate contract only after its exact current head and transitive branch ancestry are revalidated. Python must call an authoritative G04 provider; it must not embed a new vector store or knowledge permission engine.

### 5.4 G05 memory and G01/G02/G09/G11 authority

Evidence includes:
- **PR #34:** governed G05 SQLite core candidate stacked on G04 adapter PR #32; it defines consent/reviewer registries, authorization composition and G11 outbox. The current PR head is `b27816c1c3b172c0a7503d6602cddeaa6008c6cb`; earlier verification claims must be checked against that exact head.
- **PR #65:** G01/G02/G05/G11 SQLite activation candidate, exact-head run `43216600529` reported PASS at `b12739de686ac466dde02ad089f14e898eadffe9`; single-node SQLite scope only.
- **PR #77:** PostgreSQL multi-worker G05/G11 candidate, head `2bfac619b9601330b3343f86277bb5ba29ae22b2`; its description and INNIA A2 record report exact-head run `43240382987` SUCCESS, including PostgreSQL integration tests. External witness/retention providers, production roles and operational evidence remain open.
- **PR #80:** G02 PostgreSQL command processor candidate; code verification is recorded for code SHA `90023eac07ba3fba4f475cca6fa149417613cb9d`, while current PR head includes later documentation commit `7290142ba083f77f565d4d1b0922a158b391d1d8`.
- **PR #81:** G05 bounded HTTP host candidate, exact-head run `43280117777` reported PASS at `c8991fc61170bc04d7aeaea390a76a85900c2232`; not a complete production executable with a concrete memory executor.
- **PR #83:** G11 external checkpoint/provider adapter candidate, run `43284483860` reported PASS at `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810`; live witness/retention endpoints, production custody and operational rehearsal are not evidenced.
- **PR #84:** alternative G02 migration reconciliation; its description records a PostgreSQL ingress test failure (45 passed, 1 failed) and missing exact-head CI at that report point. It must not be treated as an accepted migration baseline.

Disposition: G05 and its authority/audit integration are significant but remain a set of stacked candidates, not one verified production-wired service. Python memory access is blocked on one current, compatible, approved G05/G01/G02/G11 interface and exact integration evidence. No direct PostgreSQL/SQLite access from Python.

### 5.5 G08 orchestration and trusted time

- **PR #121:** bounded `g08.workflow-graph` contract candidate, separate from durable orchestration.
- **PR #63:** durable coordinator candidate. Its earlier verification and threat-model evidence identify a trust-boundary defect: caller-supplied timestamps remain in public mutation requests, and not every state-changing transaction obtains one internally sourced trusted-time observation.
- **G08 temporal A2 contract in PR #135:** still PROPOSED / NOT APPROVED in the inspected reconciliation. It requires internal trusted UTC observation, monotonic high-water validation, fail-closed behavior, atomic time/state/event persistence and bounded deadlines/leases/retries. Trusted-source operators, quorum/skew/TTL values and external anti-rollback anchor remain unresolved.
- **PR #18:** earlier durable orchestration contract proposal; it identifies the missing G01 verified tenant-context resolver as an A3 dependency.

Disposition: G08 durable dispatch is a hard integration blocker. Python workers must not accept caller/model timestamps as authoritative, schedule themselves, extend leases, or retry protected work outside G08. No Python task scheduler should be implemented until the authoritative G08 temporal and job contracts are approved and the coordinator gap is corrected and verified.

### 5.6 G10/G12 learning and model lifecycle

The inspected evidence does not establish a unified G10/G12 production model lifecycle:
- no approved model registry or artifact ledger is integrated on main;
- no canonical Python training pipeline exists;
- no frozen dataset rights/consent manifest, held-out benchmark corpus or independent Amharic/Ethiopic quality oracle is evidenced;
- no exact model promotion/rollback contract is integrated end-to-end;
- INGA exposes bounded computation and learning/adaptation proposals, not training or self-modification.

Disposition: learning remains offline, isolated and candidate-producing only. No online learning, production fine-tuning, automatic promotion or self-modification. A Python learning worker cannot transition an artifact to APPROVED or ACTIVE.

## 6. Technology decision matrix

The following decisions are evidence-based dispositions. A named product/framework is not selected merely because it is common.

| Decision | P02 disposition | Reason / entry evidence |
|---|---|---|
| Python runtime version | OPEN — do not pin yet | Must test compatibility with selected inference runtime, Rust IPC binding, supported OS matrix and reproducible build image |
| Packaging/lock strategy | REQUIREMENT FROZEN; tool OPEN | Require pinned transitive graph, hashes, offline wheel/cache path, SBOM and license scan; choose tool only after platform compatibility test |
| IPC transport | OPEN | Separate worker process is P01 baseline; Unix socket vs Windows named pipe vs loopback authenticated transport requires platform and threat-model proof |
| Wire schema | REQUIREMENT FROZEN; encoding OPEN | Closed, versioned request/result/error contracts, strict unknown-field behavior, bounded frames, canonical correlation and compatibility tests |
| Local inference | CPU-first candidate; engine OPEN | No hardware inventory, model/license shortlist or benchmark evidence to compare ONNX Runtime, llama.cpp, PyTorch or alternatives |
| Training framework | NOT SELECTED | PyTorch is optional candidate for isolated research/training, not a mandatory serving dependency |
| Model format/tokenizer | OPEN | Requires model license/provenance, format compatibility, tokenizer coverage and Amharic/Ethiopic benchmark evidence |
| Embedding/vector stack | OPEN / G04-owned | Python may compute embeddings; canonical indexing, permissions and retrieval remain G04-owned |
| Sandbox | REQUIREMENT FROZEN; mechanism OPEN | Need OS-specific worker isolation, default-deny egress/filesystem, resource ceilings and hostile-input tests |
| External provider | DISABLED / NOT SELECTED | No provider, credentials, paid service or data egress authorized |
| Dataset/benchmark | MISSING | Rights, consent, provenance, annotation, held-out split and independent oracle are absent |
| Production model registry | MISSING | G10/G11/G12-owned manifest, immutable artifact store, signature/digest and revocation/promotion lifecycle not integrated |

### 6.1 Transport recommendation for a later bounded proof

Keep the separate-process boundary. Evaluate local IPC first (Unix-domain sockets on supported Unix-like systems and named pipes on Windows) against a common framed, versioned contract. Do not choose this as a frozen implementation until peer authentication, message limits, cancellation, crash recovery, cross-platform behavior and hostile-client tests pass. Do not expose a network listener as a shortcut.

### 6.2 Inference-engine evaluation recommendation

Use a CPU-only, offline proof-of-concept with synthetic/non-sensitive fixtures before considering accelerator or provider paths. Compare candidate runtimes on:
- exact supported OS/CPU architectures and memory footprint;
- model format and quantization support;
- license and redistribution rights for runtime and model;
- artifact integrity and supply-chain evidence;
- startup, p50/p95 latency, throughput and bounded memory;
- tokenizer behavior and Amharic/Ethiopic evaluation;
- reproducible offline installation;
- sandbox compatibility and egress requirements.

No comparison can be completed credibly until a reference hardware profile and candidate model artifacts are declared. No GPU purchase or paid service is assumed.

## 7. Rust/Python contract disposition

P01's logical request/result/error envelope is accepted as the target design. The exact wire representation and transport remain open. Before A3:
- the Kernel composition root must issue opaque, task-scoped references; Python must not mint them;
- every request must bind request/trace/task IDs, schema version, tenant/purpose/classification, authorized context references, deadline and resource budgets;
- Python must reject forged actor, tenant, role, approval, policy, capability and authority claims;
- result status must distinguish success, partial, abstained, rejected, cancelled, timed out and failed;
- result metadata must bind exact model/adapter/runtime/config/artifact versions and output digest;
- retries must be idempotent and resolved by G08 task state, never inferred from a timeout;
- provider-native exceptions and raw sensitive prompts must not cross the boundary;
- the Kernel/G09 must independently revalidate any proposed protected effect.

The P02 artifact does not claim a machine-readable schema, IPC implementation or cross-platform conformance proof exists.

## 8. A2 blocker register

| ID | Required decision/evidence | Status | Closure condition |
|---|---|---|---|
| PY-A2-01 | Refresh INNIA/BRAIN/INGA candidate lineage against current ratified main; resolve PR-head vs cited verification SHA mismatches | PARTIAL | Exact head/base/merge-base/path matrix and exact-head workflow inspection |
| PY-A2-02 | Python runtime version and supported OS/architecture matrix | OPEN | Selected runtime passes locked offline install and compatibility tests |
| PY-A2-03 | Reproducible package/lock/SBOM/license policy | REQUIREMENT DEFINED; TOOL OPEN | Exact dependency shortlist, hashes, licenses, provenance and offline install evidence |
| PY-A2-04 | Authenticated Rust/Python IPC transport | OPEN | Threat-model-backed transport choice and cross-platform proof |
| PY-A2-05 | Closed wire schemas and compatibility rules | LOGICAL CONTRACT DEFINED; MACHINE SCHEMA MISSING | Versioned machine-readable schemas and negative conformance vectors |
| PY-A2-06 | CPU reference hardware and model/runtime shortlist | MISSING | Owner-approved available hardware profile and measured candidate comparison |
| PY-A2-07 | Model format, tokenizer and Amharic/Ethiopic capability evidence | MISSING | Licensed artifacts, tokenizer manifest and reviewed held-out benchmark |
| PY-A2-08 | G04/G05 authorized context and memory interface | PARTIAL / BLOCKED | Current exact compatible provider contract; permission, consent, revocation, deletion and audit integration |
| PY-A2-09 | G08 task admission, trusted time, cancellation and recovery | BLOCKED | Owner-disposed temporal contract and exact-head coordinator remediation/integration |
| PY-A2-10 | G09/G11 protected-effect and audit handoff | PARTIAL | Single current composition path with exact-SHA adversarial/failure evidence |
| PY-A2-11 | G10/G12 dataset, evaluation, promotion and rollback | MISSING END-TO-END | Versioned lifecycle schemas, approval semantics, artifact evidence and rollback tests |
| PY-A2-12 | Worker sandbox, egress and resource enforcement | OPEN | OS-enforced sandbox proof, limits and escape/failure tests |
| PY-A2-13 | Amharic/Ethiopic corpus rights and independent evaluation oracle | MISSING | Frozen licensed corpus manifest, annotation protocol, held-out split and qualified reviewer evidence |
| PY-A2-14 | Python CI and exact-SHA conformance harness | MISSING | Offline locked install, static/security scan, contract/security/reproducibility tests and retained exact-SHA runs |
| PY-A2-15 | Explicit A3 scope and entry authorization | NOT GRANTED | P02 A2 closure disposition and separate explicit Owner authorization |

## 9. P02 exit criteria

P02 can be marked VERIFIED-CLOSED only when all mandatory entries in Section 8 are resolved or explicitly excluded by an Owner-approved scope amendment, and:
1. Candidate branch ancestry and current-head verification are reconciled without relying on stale PR-body claims.
2. Python version, packaging, supported OS/architecture and IPC decisions have reproducible evidence.
3. Machine-readable Rust/Python request/result/error schemas have closed shapes, versioning and adversarial vectors.
4. A CPU reference profile and lawful model/runtime shortlist have measured evidence.
5. G04/G05/G08/G09/G10/G11/G12 dependencies have one compatible, owner-approved interface path and no duplicated authority.
6. Worker sandbox, resource ceilings, provenance and audit behavior are testable and fail closed.
7. Amharic/Ethiopic benchmark rights, annotation, held-out evaluation and review oracles are established.
8. A3 entry scope is separately authorized.

At this stage, criteria 1–8 are not all met. Therefore **P02 remains PARTIAL / NOT CLOSED**.

## 10. Recommended A3 sequence after P02 closure

No A3 Python source work is authorized by this document. After P02 closure and separate authorization, the safest order is:
1. Machine-readable contracts and strict schema validator only.
2. Authenticated local worker protocol and fake adapter; no external model.
3. OS isolation/resource enforcement and adversarial bypass tests.
4. CPU-only local inference proof using an approved, licensed model artifact.
5. G03/BRAIN adapter integration with explicit abstention and evidence semantics.
6. G04/G05 authorized context integration after their canonical provider interfaces are verified.
7. G08 durable task lifecycle integration only after trusted-time remediation.
8. G10 evaluation and offline candidate packaging; no self-promotion.
9. G11 audit and G12 governed promotion/rollback integration.
10. Exact-SHA cross-platform security, quality, language, reproducibility and performance verification.

## 11. Preservation and non-actions

- This is a documentation-only P02 reconciliation.
- Canonical `main` is unchanged.
- No Python source, manifest, lockfile, dependency, CI workflow, Rust source, schema migration or production configuration is changed.
- Existing branches and PRs are not rebased, merged, closed, retargeted or deleted.
- No model or dataset is downloaded; no provider is activated; no external data egress, paid service, production data or production credential is used.
- No training, online learning, model promotion, merge or deployment is performed.
- P01 remains a proposal pending Owner disposition; this P02 record does not silently freeze P01 or authorize A3.

**Final P02 disposition: A2 RECONCILIATION PARTIAL / NOT CLOSED.** The technology and integration blockers are now explicit and traceable. The next meaningful closure work is to obtain the missing hardware/corpus/owner evidence and complete exact-head source reconciliation; do not start Python production code before that gate.

---

**Operating rule:** Python computes within a task boundary. Rust governs the boundary. Domain owners govern their data. G09 alone executes protected effects. G11 verifies evidence.


---

## 12. Exact-current-head integration reconciliation — 2026-11-28

This addendum supersedes any earlier candidate-head or workflow statements where the PR head has since moved. All checks below are read-only observations of the current open PR metadata, exact head references, file lists, and GitHub Actions metadata.

### 12.1 G08 coordinator and orchestration

- PR #63 is OPEN / DRAFT / UNMERGED; base `main` at stale SHA `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`; current head `583640619174cac76067ec68d9bba82d99c3b037`.
- Exact-head runs on that SHA conflict: run #44898113614 reports SUCCESS; later run #44898118078 reports FAILURE in “Run complete unit and contract test suite”; formatting, all-target compilation and production-feature exclusion passed in the failing run. Clippy was skipped. The failure output has not yet been inspected, so its cause is UNKNOWN. No pass may be substituted for the later failing run.
- Current source has a `TrustedClock` dependency and the final commits explicitly remove caller timestamps from cancellation and source coordinator mutation time from the trusted clock. However, legacy public request structs still visibly contain `now: u64` fields (including task claim, lease renewal and completion request shapes). A complete public-surface/reachability audit is still required to prove these types cannot bypass the authenticated APIs. This is an unresolved contract/API issue, not a claim that the final coordinator methods still trust those values.
- G08 A2 contract PR #18 remains OPEN / DRAFT and is based on `143311a655be68acea2700650b7f88c9fb085526`, not current main. Workflow-graph PR #121 is also OPEN / DRAFT and based on `bbd971f35cf6b19be53921cfbb75c1a54912250c`. Neither is an integrated current-main contract baseline.
- G08 PR #63's threat model itself states that SQLite cannot prevent privileged full-database rollback without an external monotonic anchor/witness; production time-source, issuer-side G01 registry, key custody and live revocation services remain unestablished.
- **Disposition:** G08 is NOT accepted as a Python integration dependency. Resolve the exact-head test failure, audit/remove or make unreachable all legacy caller-time APIs, reconcile G08 contract/graph ancestry to current main, and establish the G01/G02/G11 production authority handoffs before any Python worker contract depends on it.

### 12.2 G04 knowledge boundary

- PR #32 current head: `4e0c954516b4a471e2f36760b665add0a98efe9f`; exact-head run #42609492232 is SUCCESS.
- The crate `iroka-g04-contract` supplies bounded versioned retrieval request/evidence bundle types and response validation. It does not authenticate opaque request references or implement source registration, source lifecycle, permissions, persistent storage, indexing, crawling, or a retrieval provider.
- The provider remains the G04 authority and must resolve G01/G02 references and enforce source permission, freshness, classification, provenance and revocation before retrieval/ranking. The adapter validates returned evidence; it cannot prove that a remote provider enforced its obligations.
- G04 PR #32 is stacked on `feat/brain-a3-b02-authorization-composition` at `d5d519ee8b29e9cf8c618b3b357825e7740fe86a`; its base is not the current canonical main baseline. G04 contract PR #31 is a separate proposal based on the older BRAIN A1/A2 proposal branch.
- **Disposition:** exact-head adapter CI is verified, but G04 is only a typed contract/client boundary. It is not a production knowledge dependency and must remain provider-gated.

### 12.3 G05 memory boundary

- PR #34 current head: `b27816c1c3b172c0a7503d6602cddeaa6008c6cb`; base is G04 PR #32 head `4e0c954516b4a471e2f36760b665add0a98efe9f`.
- The current PR body still cites exact-head verification at the older `2b5cbbd2e74308286547890d993820a5beeca329`. Current-head check-runs query returned zero checks. Therefore the earlier 130-test pass and Clippy claim do not verify current head.
- Current source separates G05-owned memory policy/lifecycle from G01 principal and reviewer-proof verification, G02 authorization and organization-scoped delegation, consent authority, and G11 audit delivery. The SQLite implementation and outbox are candidates; production provider integration, G11 event extension/receipt behavior, cross-store atomicity and multi-node persistence remain explicit limitations in the PR description.
- **Disposition:** G05 current head is UNVERIFIED. Do not bind Python context or memory directly to this adapter. Require current-head full CI, dependency ancestry reconciliation, and explicit G01/G02/G11 contract acceptance first.

### 12.4 BRAIN and INGA cognition boundary

- BRAIN PR #27 current head: `5c551a7ab023b05adf98022903cdc0ea8640ae02`; exact-head run #46128473927 reports SUCCESS. Its PR body still cites older head `9d68b580e06bb8335a626524d64b345c3a5a38aa`; update the evidence record before treating the PR description as current.
- BRAIN remains a deterministic synthetic G03 cognitive core with a fake adapter. It does not provide production model serving, a provider/model registry, durable context, or protected-effect authority.
- INGA PR #44 current head: `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d`; no exact-head workflow run/check was found. The PR records 30 authored tests as NOT RUN and formatting, compilation and Clippy as NOT RUN / UNRESOLVED.
- INGA is based on old BRAIN head `9d68b580e06bb8335a626524d64b345c3a5a38aa`, not current BRAIN head `5c551a7ab023b05adf98022903cdc0ea8640ae02`. The dependency chain is therefore stale even though the INGA PR remains open.
- INGA's declared G05/G10/G12 ownership boundaries are appropriate: it proposes deterministic neurogenetic computation and learning/adaptation proposals, but no storage, training, weight mutation, self-modification or activation.
- **Disposition:** BRAIN is a verified synthetic cognition candidate only. INGA is unverified and based on stale BRAIN ancestry. Neither constitutes a production model runtime or an approved Python intelligence implementation.

### 12.5 Cross-domain integration contract determination

The current candidate graph is not a single verified integration baseline:

1. G08 PR #63 is based on an older main SHA and has conflicting exact-head CI results plus a remaining public-API audit.
2. G04 PR #32 has a passing exact-head adapter run but is stacked on an older BRAIN/G02 branch and has no production provider.
3. G05 PR #34 is stacked on G04 #32, but its current head has no attached check runs and its PR body cites an earlier tested SHA.
4. BRAIN #27 has a passing current-head run but stale PR-body evidence and no model runtime.
5. INGA #44 is based on an older BRAIN head and has no exact-head verification.

No candidate in this chain grants Python permission to authenticate, authorize, retrieve unrestricted context, mutate memory, schedule durable work, approve outputs, or execute protected effects. Python remains an untrusted replaceable computation plane behind a versioned Rust-kernel contract.

**P02 remains PARTIAL / NOT CLOSED.** No Python production source, package manifest, runtime dependency, model provider, model artifact, training pipeline or Python/Rust IPC implementation was introduced by this reconciliation. No PR was merged and no deployment or production activation occurred.

### 12.6 Remaining P02 closure work

- Inspect the failing G08 exact-head test output and rerun after a narrowly scoped correction; do not treat the earlier same-SHA success as sufficient.
- Audit every exported G08 public mutation/request type and prove no caller-supplied time can reach a coordinator mutation.
- Reconcile G08 A2 contract and graph ancestry against current main and settle trusted-time/anti-rollback/G01/G02/G11 handoffs.
- Re-run the complete G05 suite and Clippy on exact head `b27816c1c3b172c0a7503d6602cddeaa6008c6cb`; refresh its PR evidence record.
- Reconcile G04/G05 stacked ancestry and provider contracts to a common current baseline without merging.
- Rebase/reconcile INGA's declared BRAIN dependency and run format, compile, complete tests and Clippy on the resulting exact SHA.
- Refresh BRAIN PR #27's evidence record to current head `5c551a7ab023b05adf98022903cdc0ea8640ae02`.
- Keep Python implementation blocked until P02 exit criteria are met and a separate A3 scope is explicitly authorized.


---

## 13. Follow-up execution and dependency alignment — 2026-11-28

### 13.1 G08 exact failure output and diagnosis

The actual job log for run #44898118078, job 136828023829, identifies one failing test:

`g08_trust_adapters::tests::replay_guard_subprocess_race_restart_and_revocation`

The complete library test result was 110 passed, 1 failed. The failure output is:

- First failure: `crates/iroka-kernel/src/g08_trust_adapters.rs:874:69`, where `Command::spawn().unwrap()` panicked on `Err(Unavailable)`.
- Parent failure: line 918, `assert!(child.wait_with_output().unwrap().status.success())`.
- A child invocation of the same test printed a passing result in the same log.

This is direct evidence of failure in subprocess startup/child completion during the race test. It is not a failing trusted-clock assertion, replay sequence assertion, or lease-time assertion. The precise OS resource condition behind `Unavailable` is not identified by the log and must not be guessed.

### 13.2 G08 caller-time API reconciliation

Source inspection of exact head `583640619174cac76067ec68d9bba82d99c3b037` established:

- `TaskClaimRequest`, `TaskLeaseRenewalRequest`, and `TaskLeaseCompletionRequest` contained public `now` fields but were consumed only by `pub(crate)` implementation methods.
- `crates/iroka-kernel/src/lib.rs` exports the authenticated request types, not those legacy internal request types.
- `claim_next_task_authenticated`, `renew_task_lease_authenticated`, and `complete_task_lease_authenticated` verify the signed worker proof and derive the internal timestamp from the authenticated trusted-clock result.
- `create_workflow`, `create_task_graph`, `transition_task`, retry scheduling and cancellation obtain time through `TrustedClock`.

For a clearer enforced boundary, commit `ab067f988c0b69944aa1eac5b289ec10e69bef63` changed the three legacy request structs to `pub(crate)` and documented their trusted-kernel-only timestamp. This narrows the Rust public API without changing trusted-time calculations.

Exact-head verification for `ab067f988c0b69944aa1eac5b289ec10e69bef63` is running as runs #46168287956 and #46168294772. Formatting passed in the observed job snapshots; compilation, production-feature checks, full tests and Clippy were still in progress at the time this addendum was written. The prior failing run remains unresolved until these exact-head runs complete successfully.

### 13.3 G05 exact-current-head verification

- PR #34 remains OPEN / DRAFT / UNMERGED.
- Current head remains `b27816c1c3b172c0a7503d6602cddeaa6008c6cb`, based on G04 PR #32 head `4e0c954516b4a471e2f36760b665add0a98efe9f`.
- The PR description's previous PASS evidence cited older SHA `2b5cbbd2e74308286547890d993820a5beeca329`. GitHub check-runs for current head `b27816c1c3b172c0a7503d6602cddeaa6008c6cb` returned zero entries.
- The PR body was corrected to mark exact-current-head formatting, compilation, complete tests and Clippy as NOT VERIFIED. Static source inspection confirms the G05 module's stated separation of memory policy from G01 identity/reviewer verification, G02 authorization and G11 audit delivery; this is not a substitute for executable exact-head verification.
- The inspected Rust workflow does not target this PR's feature-branch base for pull-request events, and its push branch allow-list excludes the G05 branch. No safe workflow-dispatch action is exposed through the connected GitHub actions. Therefore no current-head test result is claimed.

### 13.4 INGA advanced to current BRAIN baseline

- BRAIN current head: `5c551a7ab023b05adf98022903cdc0ea8640ae02`.
- INGA previous head: `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d`, whose base was the older BRAIN head `9d68b580e06bb8335a626524d64b345c3a5a38aa`.
- A two-parent merge commit was created: `1c7123b414d5ca9ae14ad361bb3e3945d49ff44d`, preserving the INGA history and adding the current BRAIN head as its second parent. The BRAIN crate root was reconciled to include the INGA neurogenetic module export while preserving the current BRAIN execution-control implementation.
- The existing branch `feat/inga-neurogenetic-a3-foundation` was advanced using a non-force, expected-SHA update from the prior head. No new branch was created.
- PR #44 now reports head `1c7123b414d5ca9ae14ad361bb3e3945d49ff44d` and base `feat/brain-a3-b01-cognitive-core` at `5c551a7ab023b05adf98022903cdc0ea8640ae02`.
- Compare result: 18 commits ahead, 0 behind, merge base exactly current BRAIN head; INGA changes remain the three intended files (`crates/iroka-brain/src/lib.rs`, `crates/iroka-brain/src/neurogenetic.rs`, and its baseline document).
- INGA still has 30 authored tests not run and no exact-head workflow run. The current Rust workflow's pull-request target filters do not include INGA's feature-branch base, and its push filters do not include the INGA branch. No test or Clippy PASS is claimed.

### 13.5 Current disposition

G08 caller-time request visibility is now narrowed, but exact-head CI is pending. G08's earlier test failure is identified as subprocess launch/child exit failure; root OS cause remains undetermined. G05 exact-current-head execution remains unavailable and unverified. INGA is now based on the current BRAIN commit lineage but remains unverified.

**P02 remains PARTIAL / NOT CLOSED. Python production implementation remains blocked.** No Python code, Python runtime dependency, model provider, or model artifact has been introduced. No PR has been merged and canonical `main` remains `6b7004c897907f5ca40de58fee7222732fd7cde0`.
