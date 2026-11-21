# INNIA A2 — Neural Infrastructure Read-Only Reconciliation

**Document ID:** INNIA-A2-RECON-001  
**Version:** 1.0.0  
**Status:** READ-ONLY RECONCILIATION COMPLETE FOR THE INSPECTED CANDIDATE SET; INTEGRATION BASELINE NOT FROZEN  
**Repository:** `akefadaka-git/iroka`  
**Canonical base:** `main` — `1aea1447eadf1d827d702fd6c4034fa058aac21e`  
**Related A1 proposal:** PR #134 — INNIA v0.1.0  
**Scope:** INGA, BRAIN, native cognition, CIW, G01/G02/G04/G05/G08/G11 dependencies, TALORA service candidate and Android integration evidence.

## 1. Executive determination

The read-only reconciliation confirms that IROKA has several substantial, independently developed cognitive, neural, memory, governance, conversation and orchestration candidates. They are not one integrated neural platform.

The canonical `main` Cargo workspace currently contains only `crates/iroka-kernel`. The neural and cognitive crates, memory adapters, conversation runtime, workflow coordinator, provider adapters and service hosts reviewed in this report remain on separate unmerged branches and draft pull requests.

**A2 outcome: PARTIAL / NOT CLOSED.**

The candidate inventory, source lineage, available exact-SHA workflow evidence, ownership boundaries and major integration blockers are now recorded. The integrated technical baseline cannot be frozen because the authoritative interfaces and runtime composition are not yet reconciled end-to-end. In particular, INGA's exact-head verification is absent; the current canonical G01/G02 authority and tenant context must be connected to the neural runtime; G04/G05 context and memory integration is not unified; G08 durable orchestration has unresolved trusted-time requirements; and no approved model-serving/provider runtime exists.

This report does not authorize additional neural runtime code, branch integration, cherry-picking, rebase, merge, deployment, provider activation or production data use.

## 2. Method and scope

Read-only repository inspection was performed against:
- `main` and its workspace manifest/README/implementation strategy.
- Branch references for INGA, BRAIN, native cognition, CIW, G04/G05, G08, G01/G02/G11, TALORA service and Android integration.
- Pull-request metadata, branch/base/head SHA declarations, implementation records, architecture contracts and available workflow runs.
- Relevant Rust manifests and source files, including the INGA neurogenetic module, BRAIN cognitive core, G05 persistence adapters, G08 coordinator and native cognition engine.

No source, manifest, lockfile, workflow, migration, branch, existing PR or main-branch content was modified by the reconciliation. No CI was triggered by this A2 work. The separate INNIA A1 proposal PR #134 remains unchanged.

This is a bounded reconciliation of neural-infrastructure dependencies, not a full re-audit of every IROKA branch or all 12 chromosomes.

## 3. Canonical baseline

| Item | Observed value | Status |
|---|---|---|
| Repository | `akefadaka-git/iroka` | CONFIRMED |
| Default branch | `main` | CONFIRMED |
| Main SHA | `1aea1447eadf1d827d702fd6c4034fa058aac21e` | CONFIRMED |
| Main workspace manifest blob | `d64d3143b762589346fb19ee77e6f40d4af8c77c` | INSPECTED |
| Main workspace members | `crates/iroka-kernel` only | CONFIRMED |
| Main README blob | `a85ee805e35481b20087e8f32e451eb1bd4eb4a7` | INSPECTED |
| Main implementation strategy blob | `85d3e69ef160f53acdc4aa2fcf2783581f639d24` | INSPECTED |
| INNIA A1 proposal | PR #134, head `5d6f6b36e0d514e8fd14f144d8cde905e0f49d92` | OPEN / DRAFT / UNMERGED |

The README defines IROKA as a model-independent governed cognitive operating system with twelve logical chromosomes. The strategy makes the Governed Kernel authoritative for identity, policy, approval, delegation, execution authorization, audit and revocation. Neural models and agents remain capability providers, not authority sources.

## 4. Candidate inventory and evidence

### 4.1 INGA — neurogenetic computation

**PR #44:** `feat/inga-neurogenetic-a3-foundation`  
**Head:** `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d`  
**Base:** BRAIN PR #27 at `9d68b580e06bb8335a626524d64b345c3a5a38aa`  
**State:** OPEN / DRAFT / UNMERGED  
**Exact-head workflow:** none returned for the stated head; format, compile, tests and Clippy NOT RUN / UNRESOLVED.

Observed implementation:
- Extends the existing `iroka-brain` crate; it does not establish a separate production neural runtime.
- Defines computational cell roles, functional regions, synapses, bounded network structures, circuit descriptors and memory/learning/adaptation proposal interfaces.
- Uses deterministic fixed-point feed-forward evaluation with bounded weights, explicit excitatory/inhibitory polarity and clipped-linear, ReLU, leaky-ReLU and binary-step activation functions.
- Uses topological evaluation and rejects recurrent/general directed-graph topologies, quarantined cells, structurally unverified cells, invalid roots and invalid graph references.
- The baseline documents 30 authored unit tests, but explicitly states they are NOT RUN.

Boundary:
- G05 retains memory storage/consent/retention authority.
- G10 retains training and learning authority.
- G12 retains evolution and activation authority.
- INGA does not implement weight training, durable memory, self-modification, provider access, agent delegation, G02 policy decisions or G09 protected execution.
- IGACMS A2 remains a separate VERIFIED-CLOSED baseline and is not reopened by INGA.

Determination: **PARTIAL; not ready for runtime integration.** The bounded evaluator is a useful synthetic computational substrate, not a trained neural model, recurrent neural runtime, general model-serving engine or verified production capability.

### 4.2 BRAIN — bounded cognitive runtime

**PR #27:** `feat/brain-a3-b01-cognitive-core`  
**Head:** `9d68b580e06bb8335a626524d64b345c3a5a38aa`  
**Base:** main at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472` (historical main predecessor)  
**Exact-head workflow:** run `42576912231` — SUCCESS.

Observed implementation:
- Isolated `iroka-brain` Rust crate with versioned task/result envelopes.
- Schema/version validation, bounded serialized inputs, iteration/output limits, typed plan proposals, plan validation and critic output.
- Injected model-adapter interface with deterministic fake adapter only.
- Rejects caller-supplied principal/tenant/policy references and unsupported G04/G05/G06/CIW references.
- Rejects external providers, persistence, delegation and protected-effect flags.
- Required evidence causes abstention; no fabricated citations.
- Exact-head verification recorded: formatting, locked workspace compile, no-default-features compile, tests (15 BRAIN + 71 Kernel + 2 conformance), and Clippy all PASS.

Determination: **VERIFIED for the bounded synthetic B01 increment only.** It is not a production model gateway or integrated cognitive runtime. It does not authenticate principals, resolve tenant membership, retrieve knowledge, access memory, persist tasks, invoke tools or execute protected effects. A4 independent assurance remains separate.

### 4.3 Native Cognition — deterministic symbolic reasoning

**PR #130:** `feat/native-cognition-a3`  
**Head:** `e20701b03a087674cbd4d8ab196442d1056ffdc3`  
**Base:** main at `1aea1447eadf1d827d702fd6c4034fa058aac21e`  
**Exact-head workflow:** Rust run `44675531548` and Native Cognition CI run `44675531477` — both SUCCESS.

Observed implementation:
- Separate `iroka-cognition` crate.
- NCE-01 propositional forward reasoning, contradiction reporting and bounded inference.
- NCE-02 first-order terms, unification with occurs check, backward chaining, recursive Horn-clause search and proof trees.
- Provenance and explicit budget/deadline outcomes.
- No external model, network, filesystem, tool or protected effect.
- The README explicitly states that language understanding, probabilistic inference, causal/temporal reasoning, knowledge ingestion, governed memory, planning, learning, perception and orchestration remain separate workstreams.
- The documented engine suite has 36 tests; caller-side parsing/allocation and transport bounds remain integration responsibilities.

Determination: **VERIFIED for the reported NCE-01/NCE-02 bounded symbolic increments.** This is complementary native reasoning, not a neural network and not a replacement for INGA or BRAIN. Its ingress resource boundary and G04/G05/G08 integration remain open.

### 4.4 CIW — conversational interaction

**PR #23:** `feat/ciw-amharic-answer-only-chat`  
**Head:** `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1`  
**Base:** `feat/igacms-a3-implementation` at `813b24cbf81f049f2675fbb5492bdc9f262a9d87`  
**Exact-head workflow:** run `42562324737` — SUCCESS.

Observed implementation and contracts:
- Amharic-first answer-only conversation with English selection.
- G01 Ed25519 credential-cookie authentication and revocation-epoch checks.
- Tenant-scoped sessions, SQLite session registry, signed/versioned policy and budget enforcement.
- Kernel authorization adapter, bounded HTTP transport, streaming and cancellation behavior, conversation persistence, retention and deletion controls.
- Synthetic-only Amharic/English generation; no production model/provider.
- Runtime composition requires a trusted host to verify credentials, resolve authoritative membership, issue sessions, configure shared security storage and place the listener behind a trusted TLS reverse proxy.

Lineage risk:
- CIW is stacked on an unmerged IGACMS A3 implementation branch, not directly on current main.
- The branch comparison against current main reports a diverged history (172 commits ahead, 25 behind) with a different merge base.
- It cannot be treated as a directly mergeable or adopted runtime component without a separate source-lineage and authority reconciliation.

Determination: **VERIFIED for the bounded CIW answer-only slice at its recorded head; integration PARTIAL.** CIW is a conversation surface/runtime component, not a universal Android API, model provider or complete neural orchestration system.

### 4.5 G04/G05 — knowledge and memory

Relevant evidence:
- **PR #34** `feat/brain-a3-b04-g05-memory-core`, head `b27816c1c3b172c0a7503d6602cddeaa6008c6cb`: governed memory primitives, domain model, validation, lifecycle matrix and repository ports. Its exact-head status must be distinguished from the earlier G05 base run; PR #34's head is not the same as the earlier verified base `2b5cbbd2e74308286547890d993820a5beeca329`.
- **PR #42** `architecture/g05-g01-g02-g11-integration-contracts`, head `0e8009bee94b321211636656448837a0636232fd`: Owner-approved D1–D6 integration decisions. D2 still requires G02 as the canonical organization authority source; G05 must not maintain a competing reviewer/organization authority registry.
- **PR #43** closed and superseded; no changes merged.
- **PR #65** `feat/g05-g02-g11-activation-v12`, head `b12739de686ac466dde02ad089f14e898eadffe9`: G01/G02/G05/G11 SQLite activation composition. Exact-head run `43216600529` PASS (176 tests). It remains a single-node SQLite candidate; external checkpoint anchoring, shared multi-node adapters, production ingress and independent review remain open.
- **PR #77** `feat/g05-postgres-g11-multiworker-a3`, head `2bfac619b9601330b3343f86277bb5ba29ae22b2`, based on PR #65. Exact-head run `43240382987` SUCCESS (184 tests, PostgreSQL 16 integration tests, Clippy). Adds PostgreSQL memory persistence, multi-worker outbox, G11 receipt chain and checkpoint persistence. Real external witness/retention providers, production trust-root operations, production DB roles, deployed host and independent review remain unverified.
- **PR #78** `feat/g02-postgres-authority-a3`, head `be1bd77b290a4561d9f67f2752d0bfd70af88a39`: schema/transaction contract only; Rust authority adapter and migration execution were NOT RUN at that recorded gate.
- **PR #79** G09 PostgreSQL resolver head `3e6273e592eb1c5d15cda398d51939cd19f0a7b5`: tests passed, but canonical G02 Owner trust-root verifier and signed command processor were still outstanding at that gate.
- **PR #80** G02 PostgreSQL command processor head `7290142ba083f77f565d4d1b0922a158b391d1d8`; code SHA `90023eac07ba3fba4f475cca6fa149417613cb9d` exact workflow run `43357517022` PASS (198 tests). The PR itself records no production HTTP host, production root/key ceremony, live witness/retention providers, production roles, independent security review or operational rehearsal.
- **PR #81** G05 HTTP host head `c8991fc61170bc04d7aeaea390a76a85900c2232`; run `43280117777` PASS (192 tests). It is a bounded reusable host adapter, not a production executable with a concrete memory operation executor.
- **PR #82** root-verified G02 registry/commands head `a9c05318e25aa75b620a553a509e06387e51ee30`; recorded exact-head tests pass (186 tests). G09 resolver wiring, production trust-root ceremony and independent security review remain separate.
- **PR #83** G11 provider adapters head `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810`; run `43284483860` PASS (203 tests). It implements quorum and HTTPS provider clients, but no real witness or retention endpoints/receipts, production signer/HSM, service host, operational drills or independent review are evidenced.
- **PR #84** G02 migration reconciliation head `6bec405058ee26d4961c1da99dda4f37d431f6be`: latest exact-head workflow returned FAILURE; migration clean-install/upgrade and authority-consolidation gates remain open.
- **PR #133** `feat/a3-android-integration-unification`, head `683da7e3f39fcb27a50f46d440fdddcf4d0dde79`: combines the G02 PostgreSQL command-processor base with the G05 HTTP host source without modifying source branches. A Rust workflow is associated with this exact head and succeeded, but the PR body still requires explicit full integration checks including PostgreSQL-backed tests. The result is a narrow G05 ingress host, not a complete Android `/api/v1` task service or production identity issuer.

Determination:
- G05 domain, persistence and activation work is substantial and has multiple independently verified increments.
- The canonical authority rule is clear: G01 authenticates, G02 owns organization/tenant authority and approvals, G05 owns memory lifecycle, and G11 owns assurance/audit evidence.
- The source variants are stacked across multiple branches and database models. SQLite activation, PostgreSQL multi-worker persistence, G02 command processing, G09 resolver and G11 external checkpoint adapters are not yet one verified, production-wired service.
- No neural component may write or retrieve durable memory by bypassing the canonical G04/G05 authorization and provenance interfaces.

### 4.6 G08 — workflow graph and durable orchestration

**PR #121:** `implementation/a3-g08-character-workflow-graph`  
**Head:** `0dbe0d58f312ef5ddf2be5d3f6b7dde6569d566b`  
**Base:** G07 CI candidate `bbd971f35cf6b19be53921cfbb75c1a54912250c`  
**Exact-head workflows:** Rust `44237721339`, GENESIS `44237721347`, supply-chain `44237721471`, G08-specific `44237722359` — all SUCCESS.

This implements the bounded `g08.workflow-graph` gene: immutable graph revision and digest, operation registry binding, canonical configuration digest, dependency semantics, DAG validation, deterministic topological ordering and checkpoint references. It has no side effects and grants no execution authority. Remaining G08 genes are separate.

**PR #63:** `feat/g08-a3-durable-coordinator`  
**Head:** `2cfcf8db9437824cc8181ad8af1e8d819b936e2c`  
**Base:** historical main `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`  
**Associated workflow:** `43230367894` — SUCCESS.

The coordinator candidate implements tenant-gated workflow/task state, DAG validation, idempotency, worker proofs, replay protection, leases, retries, cancellation and trusted-clock concepts. Its threat model and PR evidence identify a critical unresolved issue: caller-supplied timestamps remain in public mutation requests and not every coordinator operation obtains one internally sourced trusted-time observation per transaction. The candidate also lacks production G01/G02/G05/G11 integration, independently protected anti-rollback anchoring and independent security review.

Determination: **G08 workflow-graph gene verified; durable coordinator PARTIAL / NOT A4-READY.** The graph evaluator and durable coordinator are different deliverables and must not be conflated.

### 4.7 G01/G02/G11 authority and assurance dependencies

**PR #126** G01 production-backed authority registry adapters:
- Head `ad612d9fda8cd2be8c5b5d89d103f2570a1625aa`.
- The exact-head workflow `44254408239` currently reports FAILURE in the repository workflow query.
- Its PR body also lists SEC-01 and SEC-03 as PARTIAL and states that the supply-chain audit/SBOM work is incomplete at that evidence point.
- Therefore it cannot be treated as a fully verified identity/trust foundation.

G02/G11 PostgreSQL and provider candidates:
- G02 command processor and G11 provider code have successful candidate workflow evidence, but their branches are stacked and their production trust roots, live external providers, operational roles, host wiring and independent assurance remain outstanding.
- An internal security review explicitly says it is not an independent third-party assessment and leaves production trust-root ceremony, organizational independence, real provider receipts, production host integration, DB privilege rehearsal and restore/incident drills unresolved.

Determination: **Authority contracts exist and several implementation increments pass CI, but the production authority/evidence plane is not closed.** Neural runtime must consume canonical interfaces and may not create substitute identity, organization, tenant, policy, reviewer, audit or trust registries.

## 5. Consolidated integration graph

The observed candidate topology is:

`G01/G02 Kernel authority → G03 BRAIN/INGA or native cognition → G04 knowledge → G05 memory → G08 orchestration → G06 perception and CIW surfaces → G09 authorized effects → G11 assurance → G12 controlled evolution`

This is a logical dependency graph, not a verified executable composition.

| Integration edge | Evidence | Reconciliation result |
|---|---|---|
| BRAIN → INGA | PR #44 based on PR #27 exact head | SOURCE LINEAGE KNOWN; INGA exact-head verification MISSING |
| BRAIN → TALORA API | PR #129 salvages BRAIN and exposes fake/local task service | VERIFIED bounded service slice; TALORA-specific, not general API |
| BRAIN → CIW | CIW consumes synthetic G03 generation through its own runtime boundary | PARTIAL; separate host and authority lineage |
| Native Cognition → BRAIN | Separate crates and PRs; no common runtime adapter proven | MISSING |
| INGA → G04/G05 | Proposal/reference interfaces only; owners remain external | MISSING end-to-end |
| Neural runtime → G01/G02 | BRAIN rejects caller identity refs; INGA has no identity authority | Correct boundary; canonical composition not integrated |
| G05 → G01/G02/G11 | PR #65/#77/#80/#83 and contracts | PARTIAL; several verified increments, no unified production service |
| G08 → G01 tenant authority | Workflow candidate requires authoritative tenant context | PARTIAL; trusted-time contract gap remains |
| G08 → neural task execution | Graph and coordinator candidates exist separately | MISSING unified dispatch/result contract |
| Android → IROKA service | PR #132 A2 and PR #133 host unification | PARTIAL; no full production mobile API/auth/service composition |
| Model registry → inference serving | INNIA A1 target only | MISSING |
| Training/evaluation → approved model promotion | INGA/G10 proposals and G12 boundaries | MISSING end-to-end governed pipeline |

## 6. Canonical ownership and duplication controls

The following ownership boundaries are binding for subsequent A2 contracts:

| Concern | Canonical owner | Neural infrastructure rule |
|---|---|---|
| Principal identity, credential/key trust and revocation | G01 | Consume verified identity; never mint a substitute principal |
| Owner authority, organization/tenant membership, policy and approval | G02 | Consume scoped, current decisions; no local role or approval authority |
| Reasoning, planning and cognitive composition | G03 | INGA, BRAIN and native cognition remain G03-owned capabilities |
| Knowledge records and provenance | G04 | Consume authorized, provenance-bearing evidence |
| Memory, consent, retention, correction and deletion | G05 | No private memory store or bypass path in INGA/BRAIN |
| Perception and normalized observations | G06 | Adapters must preserve source and classification metadata |
| Agent identity and delegation | G07 | No delegation until G07 and Kernel contracts permit it |
| Workflow/task coordination and recovery | G08 | Submit bounded tasks; do not duplicate durable workflow authority |
| Tool execution and protected side effects | G09 | Neural outputs are proposals; Kernel authorizes each protected effect |
| Learning, dataset and model evaluation | G10 | Training pipeline is offline-by-default and promotion-gated |
| Security, audit, observability and evidence | G11 | Use canonical assurance interfaces; no model-generated self-attestation |
| Versioning, evolution, activation and rollback | G12 / IGACMS | Candidate changes cannot mutate canonical architecture without approval |

## 7. Model/runtime status

The inspected candidates establish:
- Deterministic synthetic BRAIN execution.
- Deterministic fixed-point INGA feed-forward evaluation (tests authored but not run at its recorded head).
- Native symbolic inference in the separate `iroka-cognition` crate.
- Synthetic-only CIW answer generation.
- Fake/local TALORA task execution.
- Separate G08 graph and workflow execution candidates.

They do **not** establish:
- An approved production model registry.
- A verified local neural inference runtime with supported model formats/hardware.
- A production remote-provider adapter selected and activated by Owner approval.
- A unified BRAIN/INGA/native-cognition capability router.
- A canonical G04/G05 context retrieval/write composition for neural tasks.
- A verified multimodal neural runtime.
- A governed offline training/fine-tuning/evaluation and artifact-promotion pipeline.
- A distributed neural compute scheduler connected to G08 and trusted G01/G02 authority.
- A production Android-compatible on-device model artifact.
- End-to-end Amharic neural quality benchmarks and reviewed evaluation oracles.

Therefore no foundation model training, paid service, GPU purchase or provider activation is assumed or authorized.

## 8. Exact verification ledger

| Candidate | Exact SHA | Available evidence | Result |
|---|---|---|---|
| BRAIN PR #27 | `9d68b580e06bb8335a626524d64b345c3a5a38aa` | Run `42576912231` | PASS for B01 |
| INGA PR #44 | `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d` | No workflow returned | NOT RUN |
| CIW PR #23 | `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | Run `42562324737` | PASS for bounded CIW |
| G05 activation PR #65 | `b12739de686ac466dde02ad089f14e898eadffe9` | Run `43216600529` | PASS for candidate |
| G05 PostgreSQL PR #77 | `2bfac619b9601330b3343f86277bb5ba29ae22b2` | Run `43240382987` | PASS for candidate |
| G02 command processor PR #80 | `7290142ba083f77f565d4d1b0922a158b391d1d8` (code SHA `90023eac07ba3fba4f475cca6fa149417613cb9d`) | Run `43357517022` | PASS for stated code SHA |
| G05 HTTP host PR #81 | `c8991fc61170bc04d7aeaea390a76a85900c2232` | Run `43280117777` | PASS for bounded host |
| G11 provider PR #83 | `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810` | Run `43284483860` | PASS for candidate |
| G02 migration reconciliation PR #84 | `6bec405058ee26d4961c1da99dda4f37d431f6be` | Latest associated run | FAILURE |
| G08 coordinator PR #63 | `2cfcf8db9437824cc8181ad8af1e8d819b936e2c` | Run `43230367894` | SUCCESS; documented trust gaps remain |
| G08 workflow graph PR #121 | `0dbe0d58f312ef5ddf2be5d3f6b7dde6569d566b` | Runs `44237721339`, `44237721347`, `44237721471`, `44237722359` | PASS for graph gene |
| G01 authority PR #126 | `ad612d9fda8cd2be8c5b5d89d103f2570a1625aa` | Run `44254408239` | FAILURE |
| Native Cognition PR #130 | `e20701b03a087674cbd4d8ab196442d1056ffdc3` | Runs `44675531548`, `44675531477` | PASS for NCE-01/NCE-02 |
| G02/G05 host unification PR #133 | `683da7e3f39fcb27a50f46d440fdddcf4d0dde79` | Rust run `44678590336` | SUCCESS; full integration acceptance remains required |
| TALORA API PR #129 | Verified code SHA `8056cea136f42436d896078046796eba2129092b` | Run `44457815902` | PASS for fake/local service slice |

A workflow result applies only to the exact commit it checked out and the gates it actually ran. It does not prove production operation, independent security review or integration with other branch candidates.

## 9. A2 decisions and dispositions

### Decisions supported by current evidence

1. **Keep IROKA model-independent.** No external provider defines IROKA identity, authority or trust.
2. **Retain separate cognitive capabilities.** INGA, BRAIN and Native Cognition have different responsibilities; no forced consolidation or duplicated crate is justified yet.
3. **Keep INGA as G03-owned synthetic neurogenetic substrate.** Do not promote it as a production model-serving runtime.
4. **Keep Native Cognition as a separate deterministic reasoning capability.** It is not a neural model and must expose a bounded, versioned adapter contract if later composed.
5. **Preserve G01/G02/G04/G05/G08/G09/G10/G11/G12 ownership.** Neural code must not create local substitutes.
6. **Use synthetic-only model/task fixtures until source rights, data classification, privacy and provider terms are approved.**
7. **No online weight updates or autonomous model promotion.** Training/evaluation produces candidate artifacts only.
8. **No merge or deployment.** Existing PRs remain independent review units.

### Unresolved decisions blocking A2 closure

| ID | Decision / missing evidence | Required owner |
|---|---|---|
| A2-NN-01 | INGA exact-head compile/test/Clippy and source/test reconciliation | G03 / INGA |
| A2-NN-02 | Canonical BRAIN/INGA/native-cognition capability and adapter contracts | G03 |
| A2-NN-03 | Current authoritative G01 principal + tenant-context contract and exact verified source SHA | G01 |
| A2-NN-04 | Current G02 Owner/org/tenant authority resolver contract and verified integration point | G02 |
| A2-NN-05 | Canonical G04 evidence and G05 memory read/write/context contracts, including revocation/deletion propagation | G04/G05 |
| A2-NN-06 | G08 task submission/result/cancellation contract using internally sourced trusted time | G08 |
| A2-NN-07 | G11 audit/evidence and checkpoint contract for inference/model lifecycle | G11 |
| A2-NN-08 | Model manifest, artifact provenance, license, digest/signature and revocation schema | G01/G10/G11/G12 |
| A2-NN-09 | Initial local inference engine, supported formats, CPU/accelerator matrix and sandbox model | G03/G11 |
| A2-NN-10 | Amharic/Ethiopic benchmark dataset rights, annotation quality, evaluation oracles and acceptance thresholds | G04/G06/G10 |
| A2-NN-11 | Data placement, residency, local/cloud policy and non-paid resource budget | G02/G11 |
| A2-NN-12 | Distributed worker trust, queue semantics, cancellation, retries, backpressure and recovery | G08/G11 |
| A2-NN-13 | Governed offline training, evaluation, human review, model promotion and rollback contracts | G10/G12 |
| A2-NN-14 | Android/on-device capability contract and model artifact compatibility; no production artifact currently verified | G03 / Android |

## 10. Required A2 closure evidence

A2 can be proposed for closure only when all of the following are available:
- Exact source and branch disposition for the selected INGA, BRAIN and Native Cognition candidates.
- Exact-head verification for INGA; no inferred pass from BRAIN or TALORA CI.
- One approved G01/G02 principal, tenant, policy and capability authorization contract.
- Versioned G03 cognitive task, adapter, model attribution, resource budget, output and error contracts.
- Versioned G04/G05 context and memory interfaces with provenance, classification, consent, retention, revocation and deletion semantics.
- G08 durable task lifecycle contract with trusted time, cancellation and recovery semantics.
- G11 inference/model lifecycle audit and evidence contract.
- Model artifact manifest and promotion lifecycle, including license/provenance and rollback.
- Hardware/runtime and Amharic/Ethiopic evaluation plan with measurable acceptance criteria.
- Dependency graph, threat-to-control-to-test matrix, risk register and explicit Owner approval of the A2 baseline.

Until those artifacts exist, status remains PARTIAL / NOT CLOSED.

## 11. Recommended dependency order after A2 closure

This is a sequencing recommendation, not an A3 authorization:

1. Reconcile G01/G02/G11 authority and evidence interfaces.
2. Freeze G03 task/model/adapter contracts and decide how BRAIN, INGA and Native Cognition are composed without duplicate authority.
3. Freeze G04/G05 authorized context and memory contracts.
4. Freeze G08 durable task lifecycle and trusted-time semantics.
5. Establish a deterministic local inference adapter/test harness with resource bounds.
6. Integrate INGA only after exact-head verification.
7. Integrate symbolic reasoning and perception through versioned G03/G06 contracts.
8. Implement offline model artifact evaluation and governed promotion.
9. Add distributed workers and optional provider adapters only after trust, placement, resource and audit contracts are verified.
10. Complete A4 security, reliability, language, performance and integration assurance.

## 12. Preservation and authorization record

- Main remains unchanged at `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
- No existing source branch or pull request was changed, merged, rebased, retargeted, closed or deleted.
- No Rust neural runtime code, Cargo manifest, lockfile, workflow, database migration or runtime configuration was written.
- No production data, secrets, credentials, paid provider, GPU service or deployment was activated.
- INGA and IGACMS remain separately governed; the IGACMS A2 VERIFIED-CLOSED baseline is not amended or reopened by this report.
- INNIA A1 PR #134 remains open/draft and is not merged by this A2 report.
- This A2 report does not authorize A3 implementation, merge, A4 closure or A5 release.

## 13. Final status

| Gate | Result |
|---|---|
| Repository baseline inspected | PASS |
| Neural/cognitive candidate inventory | PASS for inspected candidate set |
| Branch lineage and PR dependency review | PASS for listed candidates |
| Available exact-SHA workflow evidence reconciled | PASS for listed candidates |
| INGA exact-head verification | MISSING / NOT RUN |
| Unified authority + neural + memory + orchestration contracts | PARTIAL |
| Unified model runtime/registry/serving | MISSING |
| A2 integration baseline freeze | NOT READY |
| A2 overall | **PARTIAL / NOT CLOSED** |
| A3 neural runtime implementation | NOT AUTHORIZED by this report |
| Merge/deployment/A5 | NOT AUTHORIZED |

**Conclusion:** The reconciliation has identified the existing capabilities, their boundaries, the verified increments and the blockers to a single neural infrastructure. The correct next engineering action is to resolve the named A2 interface and verification gaps—not to add another neural runtime or duplicate an existing authority or memory subsystem.

---
**End of INNIA A2 read-only reconciliation v1.0.0**


## 14. INGA exact-head verification trigger audit (2026-11-21)

The exact INGA candidate was re-inspected at `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d`.

- The root workspace manifest at this candidate includes both `crates/iroka-kernel` and `crates/iroka-brain`; the neurogenetic implementation is in `crates/iroka-brain/src/neurogenetic.rs` (blob `5165ada49403c96dffca6aef69b612c6e1ee2cb3`). The crate manifest is `crates/iroka-brain/Cargo.toml` (blob `e09ffd8379988e0f3de3fd2a670f8e6c2c3be3f4`). This is not a separate `crates/inga` crate; INGA currently extends the BRAIN crate.
- The workflow definition at `.github/workflows/rust-kernel.yml` (blob `f259c08b457f544eae7cafe4755aa1faab1dbe7c`) defines `workflow_dispatch`, but its automatic `pull_request` trigger is restricted to base branches `main` and `architecture/igacms-a2-ci-base`. Its path filter includes `crates/**` and root Cargo manifests/lockfile, so INGA source changes are in scope only when the PR base and path conditions are met.
- The workflow checks out the exact PR head SHA and runs `cargo fmt --all -- --check`, `cargo check --workspace --all-targets --locked`, no-default-features check, `cargo test --workspace --all-targets --locked` and Clippy with warnings denied (pedantic lint allowed).
- The GitHub connector available for this work exposes workflow-run reads but no workflow-dispatch/action trigger. No dispatch was attempted, no source/manifest/workflow file was changed to manufacture a trigger, and no run is claimed.

**Disposition:** workflow definition is technically capable of manual dispatch, but exact-head INGA verification remains **NOT RUN** because this execution path cannot invoke that dispatch. The workflow configuration itself is **PASS / INSPECTED**; INGA formatting, compilation, tests and Clippy remain **NOT RUN / UNVERIFIED**. Do not interpret the presence of `workflow_dispatch` as evidence that a run occurred.


## 15. Mainline authority-contract reconciliation (2026-11-21)

The four authoritative contract documents and corresponding kernel modules were re-read from `main` at baseline `1aea1447eadf1d827d702fd6c4034fa058aac21e`.

| Domain | Mainline evidence | What is established | What remains outside the mainline baseline |
|---|---|---|---|
| G01 | `docs/architecture/G01-IDENTITY-CONTRACT.md` (blob `bb3786ba04b5163b39896d871a1447ec757759b7`); `identity.rs` (blob `36b4230be95e4f72f79e1d4b6b1b29e9062de051`) | Ed25519 compact-JWS contract; exact issuer/kid/audience and signed claims; fail-closed revocation boundary; verified principal is distinct from authorization | Production trust-root ceremony, authoritative revocation storage/operations, issuer/key provisioning and operational distribution. Mainline identity module retains test-only legacy assertion adapter; later G01 candidate branch must be separately reviewed.
| G02 | `docs/architecture/G02-GOVERNANCE-CONTRACT.md` (blob `5bfdaab549b8879e2d3dabe46fa593fe6e412bae`); `governance.rs` (blob `83dc762add000528a48f2f91acbbec200ec0a226`) | Direct Owner authority model; signed, exact-scope approval payload; replay/revocation/audit fail-closed requirements; approval does not execute | No real Owner key provisioned; authority/approval registries and production command path are not established by the mainline contract module. PR #80/#82 are later candidate increments and not assumed merged.
| G11 | `docs/architecture/G11-ASSURANCE-CONTRACT.md` (blob `3373a0ac3ed2a1f6a17d128064150ef0f278d352`) and `G11-AUDIT-INTEGRITY-CONTRACT.md` (blob `69aa4f5dd02255ff05f47a0b60fc8195c72ac060`); `assurance.rs` (blob `52e52dfe8f1bf78b9c84034c92232c15ce79e105`) | Common audit event fields; audit failure converts positive decision to ESCALATE; SQLite reference sink and tamper-evident hash-chain design | External immutable checkpoint anchor/signing, retention/export/recovery drills, operational access controls, multi-node transactional adapter, and G09 side-effect outcome evidence.

**Integration finding:** the documents establish compatible principles but do not constitute one executable end-to-end principal → organization/tenant resolution → Owner/policy approval → durable audit → G09 execution grant contract. G01 verified identity is not tenant authority; G02 approval is not an execution grant; G11 audit is not a replacement for G01/G02 authoritative registries. INGA must consume opaque, versioned results from those owners and must not derive or persist substitute identities, tenants, approvals or audit state.

**Disposition:** architectural ownership boundaries are **PASS / DOCUMENTED**. End-to-end production authority integration is **PARTIAL / NOT VERIFIED**. A2-NN-03, A2-NN-04 and A2-NN-07 remain open.
