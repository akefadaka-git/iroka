# IROKA Android — A2 Read-only Integration Reconciliation

**Document ID:** IROKA-ANDROID-A2-RIR-001  
**Version:** 0.1.0  
**Assessment date:** 19 November 2026  
**Authority:** Owner-governed; read-only reconciliation  
**Product:** IROKA native Android client  
**A1 baseline:** IROKA-ANDROID-A1-001 v0.1.0 — Owner-approved/frozen 19 November 2026  
**Canonical repository:** `akefadaka-git/iroka`  
**Main comparison SHA:** `1aea1447eadf1d827d702fd6c4034fa058aac21e`  
**A2 branch:** `architecture/a2-android-integration-reconciliation`  
**Outcome:** **PARTIAL / NOT CLOSED — no single compatible production integration baseline verified**  
**A3 implementation:** NOT AUTHORIZED by this assessment  
**Merge / A5:** NOT AUTHORIZED

## 1. Executive determination

A1 is frozen with the Owner-selected product identity **IROKA**, **hybrid cloud + on-device architecture**, and **full access to every capability that the authenticated principal is authorized to use and the deployed IROKA runtime actually exposes**.

A2 has reconciled the live IROKA main baseline and the relevant BRAIN, CIW, and private task-service candidate PRs at their exact current branch refs. The candidates provide useful, independently tested building blocks, but they do not form one compatible, production-ready mobile integration graph.

The evidence supports these conclusions:

1. **BRAIN PR #27** is an isolated, deterministic G03 cognitive-core increment. It passes exact-head CI, but its fake adapter is not generative inference and its task validator deliberately rejects trusted principal/tenant/policy context and non-empty domain input references. It cannot be connected directly to a real authenticated Android request without a separately designed composition boundary.
2. **CIW PR #23** is the strongest inspected G01-authenticated conversation slice. It provides G01 Ed25519 credential verification, host-only HttpOnly/Secure cookies, server-side session and tenant checks, Kernel authorization, SQLite persistence and SSE generation. It is browser-oriented and depends on a trusted SSO/session issuer, membership synchronization, TLS reverse proxy and durable host composition. It is not a native Android authentication contract or a full cognitive task API.
3. **Private task API PR #129** is the closest task/capability API prototype. It defines authenticated task admission, a capability catalogue, task status and an event route. However, it is a transport-neutral route handler, not a runnable network service; it uses an injected workload-authenticator, process-local ephemeral task storage and a deterministic fake adapter. Its cancellation route does not cancel an executing task. It is TALORA-specific and is not an approved first-party Android API contract.
4. **On-device cognitive runtime:** no Android-compatible IROKA inference runtime, approved model artifact, device floor, artifact update/provenance mechanism or local/cloud placement policy was verified.
5. **No single immutable commit graph** was verified that combines the required Kernel authority, BRAIN, CIW, task API, governed memory, capability discovery and a local runtime into one supported service.
6. The Android application repository `akefadaka-git/iroka-android` has not been created. This A2 assessment does not create it.

**A2 disposition:** the read-only reconciliation has identified the strongest candidate components and concrete blockers. The technical integration baseline cannot be frozen yet. A2 is therefore **PARTIAL / NOT CLOSED**, not VERIFIED-CLOSED.

## 2. Owner decisions and scope

| Decision | Frozen value | A2 treatment |
|---|---|---|
| Product identity | IROKA | Confirmed; unchanged |
| Client | Native Android application | Confirmed |
| Architecture | Hybrid | Target architecture retained; initial placement must be phased |
| Cognitive access | Full authorized capabilities | Capability discovery and server-side authorization required |
| Canonical intelligence authority | Existing IROKA platform | Android is a client, not an alternate authority |
| Android repository | `akefadaka-git/iroka-android` proposed | Not created; requires separate A3 authorization |
| Independent review | Once after A4 and before A5 | Preserved; not a per-step blocker |

A2 was read-only against implementation branches and `main`. No source code, workflow, dependency manifest, lockfile, credential, branch protection setting or production resource was modified. The A1 specification branch received only a documentation status update recording the Owner's freeze approval.

## 3. Canonical repository baseline

- Repository: `akefadaka-git/iroka` (repository ID `1445234713`).
- Default branch: `main`.
- Main HEAD observed: `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
- Root Cargo workspace at main declares only `crates/iroka-kernel`.
- Workspace Rust MSRV is 1.75.
- Main branch protection endpoint reports `protected: false`; required status checks are disabled. This is a material governance risk, recorded but not changed in A2.
- Repository visibility is public, while the repository declares `LicenseRef-Proprietary`. Public visibility is not a source reuse, redistribution or sublicensing grant.

Main was unchanged by A2.

## 4. Candidate reconciliation

### 4.1 BRAIN — PR #27

- PR: [#27 — bounded G03 cognitive core](https://github.com/akefadaka-git/iroka/pull/27)
- State: OPEN / DRAFT / UNMERGED.
- Branch: `feat/brain-a3-b01-cognitive-core`.
- Exact current branch/PR HEAD: `9d68b580e06bb8335a626524d64b345c3a5a38aa`.
- Base recorded in PR: `main` at `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`, not the current main SHA used for this Android A2 assessment.
- Exact-head workflow: [Run #649](https://github.com/akefadaka-git/iroka/actions/runs/42576912231), run ID `42576912231`, completed SUCCESS. Formatting, all-target compilation, production-feature exclusion check, full unit/contract tests and Clippy all passed.

**Verified implementation boundary:**
- Isolated Rust `iroka-brain` crate; serde/serde_json dependencies.
- Versioned task/result envelopes; bounded input/output/iteration validation; typed plan proposal and critique.
- Injected model-adapter interface and `DeterministicFakeAdapter`.
- Explicitly no authentication, tenant resolution, policy authority, knowledge retrieval, memory, perception, persistence, agent delegation, tools or protected effects.
- The validator rejects populated principal, tenant and policy context references and rejects non-empty domain input references.
- The fake adapter returns synthetic fixture text. It is not a production model and does not demonstrate generative reasoning quality, Amharic quality, provider connectivity or local model inference.

**Android integration decision:** candidate only. Do not connect the Android client directly to this crate. A trusted composition/service layer must validate identity, tenant, consent, policy and capability before passing a minimal, typed task to a cognitive component. Any adapter contract change requires separately authorized implementation and tests.

### 4.2 CIW — PR #23

- PR: [#23 — secure Amharic-first answer-only conversation core](https://github.com/akefadaka-git/iroka/pull/23)
- State: OPEN / DRAFT / UNMERGED.
- Branch: `feat/ciw-amharic-answer-only-chat`.
- Exact current branch/PR HEAD: `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1`.
- PR base branch: `feat/igacms-a3-implementation`, base SHA `813b24cbf81f049f2675fbb5492bdc9f262a9d87`; it is not a direct main-based PR and is stacked on a separate unmerged Kernel candidate.
- Exact current-head workflow: [Run #614](https://github.com/akefadaka-git/iroka/actions/runs/42562324737), run ID `42562324737`, completed SUCCESS. Formatting, browser JavaScript syntax, patch whitespace, all-target compilation, production-feature exclusion check, full unit/contract tests and Clippy all passed.

**Verified implementation boundary:**
- Separate `iroka-conversation` Rust crate with SQLite-backed tenant-scoped conversation and generation state.
- G01 Ed25519 credential verification; signing-key/credential validity and issuer revocation-epoch checks.
- Host-only `__Host-iroka_credential` and `__Host-iroka_session` cookies (HttpOnly, Secure, Path=/, SameSite=Strict).
- Trusted session issuer and server-side tenant membership resolution.
- Kernel authorization through verified policy/genesis, Owner approval verifier and audit sink.
- Same-origin conversation routes, incremental output and SSE event delivery; bounded connections and generation state.
- Synthetic-only answer generation; no production model/provider.

**Required host composition:** the trusted host must supply credential/session issuance, authoritative membership synchronization, TLS reverse proxy and durable shared storage for multi-node deployment. The HTTP server component is a library, not a standalone production service.

**Android incompatibility:** this is a browser-oriented cookie contract. Its session issuance and same-origin behavior cannot be assumed to be a secure native Android flow. A native client needs an explicit G01-compatible authorization contract, such as a reviewed system-browser Authorization Code + PKCE flow if supported by the authoritative identity service. No such mobile issuer/client registration/token lifecycle was verified in this A2 pass.

**Capability limitation:** CIW is answer-only conversation. Its PR explicitly excludes BRAIN integration, memory, voice, multimodal capabilities, tool execution, G09 effects and production provider use. It is not the full cognitive API.

### 4.3 Private task API — PR #129

- PR: [#129 — bounded TALORA private task-service core](https://github.com/akefadaka-git/iroka/pull/129)
- State: OPEN / DRAFT / UNMERGED.
- Branch: `integration/talora-a3-private-api`.
- Exact current branch HEAD: `00b323750fb120f80d56191069d10a825e66dc41`.
- PR body identifies verified code head `8056cea136f42436d896078046796eba2129092b`; the latest two commits are documentation-only.
- Exact code-head workflow: [Run #2166](https://github.com/akefadaka-git/iroka/actions/runs/44457815902), run ID `44457815902`, completed SUCCESS.
- Exact current branch-head workflow: [Run #2168](https://github.com/akefadaka-git/iroka/actions/runs/44458023955), run ID `44458023955`, completed SUCCESS. Formatting, all-target compilation, production-feature exclusion check, full unit/contract tests and Clippy passed.

**Verified implementation boundary:**
- `iroka-talora-api` transport-neutral service core and private route handler.
- `GET /api/v1/capabilities`, `POST /api/v1/tasks`, task status, event and cancellation route shapes.
- Injected `WorkloadAuthenticator` boundary; audience, tenant, workspace, project and scope checks.
- Kernel policy evaluator invoked before capability execution, with a fixed development TALORA policy.
- Process-local bounded task store, idempotency checks, request and output limits, short task TTL.
- One advertised capability: `talora.dev.fake.v1`, version `1.0.0`, development-only, provider class `FAKE_LOCAL`, locales `am-ET` and `en`, no persistent memory.
- The fake adapter explicitly marks `inference_performed: false`; it is not generative inference.
- Inputs must be classified synthetic; evidence references are rejected by the fake adapter; paid-provider calls and cost are zero.
- Task state is process-memory-only and ephemeral.
- The cancellation route returns conflict for an existing task rather than cancelling in-flight work. The event route emits a single completed event, not a durable asynchronous event stream.

**Missing host and authority:**
- No runnable network listener/HTTP host, TLS/proxy binding or production workload-token verifier/issuer/revocation configuration.
- No durable task queue or event replay.
- No effective cancellation of in-flight tasks.
- No G05 governed memory.
- No integrated CIW/Kernel/G01/G02/G11 authority composition.
- No Android client network test.
- No production provider, production data, SBOM or independent security review.

**Android integration decision:** useful reference for task/capability schema concepts only. It is TALORA-specific and must not be treated as the approved IROKA Android API. Its development policy and capability identifiers are not first-party Android entitlements or production capabilities.

### 4.4 TALORA integration contracts — PRs #127 and #128

- [PR #127 — v0.1.0](https://github.com/akefadaka-git/iroka/pull/127): OPEN / DRAFT / UNMERGED.
- [PR #128 — v0.1.1 and A2 decision register](https://github.com/akefadaka-git/iroka/pull/128): OPEN / DRAFT / UNMERGED.

These documents are TALORA-specific and do not define the IROKA first-party Android product. Their API-only reuse boundary, fake-local provider default, hard-cap requirements, opt-in memory, Amharic assurance and post-A4 independent review timing may inform general design principles, but their contracts and Owner decisions are not silently inherited as Android approvals.

PR #128's own A2 reconciliation records divergent G03/G08, G05/G02/G11, CIW, BRAIN and localization candidate histories and a missing unified immutable graph. This is corroborating integration-risk evidence, not a substitute for this Android-specific A2 record.

## 5. Cross-component compatibility determination

| Required capability | Best inspected evidence | Current disposition |
|---|---|---|
| Kernel identity and authority | CIW G01/G02 composition | Partial; host/session issuer and base-branch dependency unresolved |
| Native Android authentication | None verified | MISSING |
| Conversation | CIW | Partial, synthetic answer-only, browser-oriented |
| Cognitive reasoning | BRAIN | Partial, deterministic fake adapter only |
| Authenticated task API | TALORA task service | Partial, development-only, no production host |
| Capability discovery | TALORA task service | One fake TALORA capability only |
| Persistent governed memory | No integrated mobile-facing G05 service | MISSING |
| Knowledge retrieval | No integrated Android-facing service verified | MISSING |
| Voice/perception | No verified mobile cognitive API | MISSING |
| On-device inference | No approved Android runtime/model artifact | MISSING |
| Hybrid placement policy | No verified placement/consent protocol | MISSING |
| Durable asynchronous task lifecycle | No unified service | MISSING |
| Production deployment topology | No verified host | MISSING |

The candidates pass their own isolated CI, but separate passing workflows do not establish that the components compile, link, authorize or behave correctly together. No combined build, cross-component contract suite, migration verification, Android client integration test or production host verification was performed.

## 6. Recommended Android integration architecture

The A1 hybrid target is retained. The safest implementation path is **cloud-authoritative, hybrid-capable by staged admission**:

### Phase 1 — secure connected client
- Native Kotlin/Jetpack Compose application.
- First-party IROKA API, versioned and capability-driven.
- Authentication delegated to G01 through a verified native flow; no embedded secrets.
- Server-side principal, tenant, scope, consent, policy and capability authorization.
- Conversation/task UI must display actual runtime availability and distinguish synthetic test responses from real inference.
- Local encrypted settings and explicitly cacheable content only.
- Offline mode limited to safe local UI/cache operations; queued tasks are proposals requiring server re-authorization.

### Phase 2 — governed cognitive integration
- Compose BRAIN, CIW and approved Kernel services through one trusted IROKA host/service composition.
- Expose capability discovery, task admission, progress, result, cancellation, idempotency, resource accounting and provenance as one versioned contract.
- Integrate G05 memory only through its authoritative API, with explicit opt-in, scope, retention and deletion.
- Do not let Android implement policy, Owner approvals, identity, memory or audit authority.

### Phase 3 — verified on-device capabilities
- Add a local inference adapter only after a specific Android-compatible runtime and model artifact are selected and verified.
- Require artifact provenance/signature, license review, supported ABI/device/RAM floor, update/rollback, model/data classification, offline policy and resource/cost controls.
- Server policy remains authoritative for capability grants and consequential actions.
- Clearly label local results and cloud results; no implicit upload of local data.

This phased plan preserves the user's hybrid architecture decision without falsely claiming that an on-device cognitive runtime already exists.

## 7. Required first-party Android API contract

The following is the recommended contract surface for A3 design; it is not a statement that these routes currently exist:

| Contract area | Required behavior |
|---|---|
| Identity | Native sign-in, token rotation, expiry, revocation and logout |
| Capability catalogue | Versioned capability IDs, scopes, locale support, availability, placement, limits and policy constraints |
| Conversation | Session creation, turns, streaming, cancellation and history under G05/retention policy |
| Cognitive tasks | Submit/status/events/cancel with idempotency and terminal states |
| Provenance | Runtime/model/adapter version, source references, uncertainty, assumptions and verification status |
| Memory | Explicit consent, scope, inspect/correct/delete, retention and audit |
| Hybrid placement | Local/cloud eligibility, data classification, user consent, device requirements and authoritative fallback |
| Operations | Health/readiness, supported contract versions, quota and usage information |

All requests must be authenticated and authorized server-side. Client-provided tenant, role, capability, consent, policy, Owner approval or execution authority references are not trusted merely because they appear in a request payload.

## 8. A2 decision register — unresolved blockers

1. **G01 native authentication:** identify the authoritative issuer and exact mobile-client flow, token audience/scopes, expiry, refresh, revocation and lost-device process. The CIW browser-cookie contract is not accepted as native mobile authentication without a separately verified design.
2. **Canonical composition graph:** select exact immutable Kernel, G01/G02, BRAIN, CIW, G05 and G11 refs and demonstrate a combined build/test. Do not cherry-pick or combine divergent branches by assumption.
3. **First-party service host:** identify the runnable host, trusted proxy/TLS, database, queue, event stream, worker lifecycle, cancellation and recovery semantics.
4. **First-party API ownership:** define IROKA Android API contract independently of TALORA's task API and capability namespace.
5. **Cognitive provider policy:** retain fake/local test mode until a separately authorized provider decision, data handling and cost control exists. No provider calls in A2.
6. **G05 memory:** establish the canonical mobile-facing interface, opt-in consent, tenant isolation, retention, deletion propagation and audit evidence.
7. **On-device runtime:** identify whether a suitable runtime exists, model artifact rights/provenance, supported devices, resource limits and update mechanism. Until then, hybrid Phase 1 is cloud-connected plus safe local functions/cache, not local cognitive inference.
8. **Offline and sync:** define what can be cached or queued, expiration, conflict resolution, re-authorization and user visibility.
9. **Amharic assurance:** define the reviewed corpus, human evaluation, UI/voice workflow scope and measurable acceptance; locale tags alone do not prove language capability.
10. **Release and supply chain:** choose APK/Play distribution, app signing custody, SBOM, reproducible build and update/rollback requirements.
11. **Branch governance:** main currently lacks branch protection. Owner decision required to establish required checks/review protections before implementation/merge, but no setting was changed in A2.
12. **Operational targets:** define device floor, latency, battery/data usage, service SLO, monitoring and support only after measurement and operational ownership.

## 9. A2 closure criteria

A2 may close only when the following evidence is available:

- A single versioned first-party Android API and capability contract is approved.
- A G01-compatible native authentication design is reconciled with the actual authority implementation.
- The exact Kernel/BRAIN/CIW/G05/API composition graph is identified and proven buildable, or explicitly scoped to a smaller verified first release.
- The selected service host has an implementable durable task, event, cancellation and recovery design.
- Hybrid local/cloud data placement, offline behavior and local-runtime admission criteria are frozen.
- G05 memory and Amharic assurance boundaries are explicit.
- Repository ownership, licensing boundary, branch governance and release supply-chain requirements are resolved.

Until these conditions are met, the integration baseline is **NOT FROZEN**.

## 10. Preservation and authorization record

- IROKA main remains at `1aea1447eadf1d827d702fd6c4034fa058aac21e` during this assessment.
- PRs #23, #27, #127, #128 and #129 remain open/draft/unmerged at the refs listed above.
- No candidate branch was rebased, merged, force-pushed, deleted or retargeted.
- No source code was copied or modified.
- No GitHub Actions run was triggered by A2; only existing exact-head workflow evidence was inspected.
- No production credentials, model provider, user data, paid service, memory service, app signing key or deployment was activated.
- No Android repository was created.
- A3 implementation: **NOT AUTHORIZED** by this A2 report.
- Merge and A5 deployment: **NOT AUTHORIZED**.

## 11. A2 disposition

**A1:** OWNER-APPROVED / VERIFIED-FROZEN.  
**A2 repository and component assessment:** COMPLETE for the inspected exact refs.  
**A2 integration baseline:** NOT FROZEN.  
**A2 overall:** **PARTIAL / NOT CLOSED**.  
**Reason:** no verified, compatible native authentication + unified cognitive service + governed memory + hybrid runtime graph currently exists.  
**Immediate next step:** resolve the A2 decision register and establish a single approved first-party IROKA Android API/composition baseline before requesting A3 implementation authorization.

**Governing principle:** one IROKA intelligence authority, multiple governed clients, no duplicated authority and no capability claims beyond verified implementation.


## 8. Extended domain reconciliation — 2026-11-20

This section records additional read-only inspection after the initial A2 report. It does not change any domain contract or authorize implementation.

### 8.1 G05 memory and G01/G02/G11

**Owner-approved design evidence**
- G05 memory contract v1.0.0 is marked OWNER-APPROVED, baseline `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`, and explicitly requires separate A3 authorization.
- G05 D1–D7 remain binding: record-specific durable approval; episodic opt-in; personal inspection/deletion rights; designated human review for organizational durable memory; vector/semantic retrieval deferred; cross-principal sharing default-deny; restricted data excluded from initial working memory.
- G05 G01/G02/G11 integration amendment v0.1.0 records Owner-approved D1–D6, subordinate to the original G05 contract.
- G02 organization authority contract selects Owner-governed authority, but explicitly says production Owner-key provisioning, live organization onboarding, G05 activation, merge and deployment are not authorized.

**Implementation candidates and exact-head evidence**
- G01/G02 candidate branch `feat/a3-8-g01-tenant-reconciliation`: `c46f2b5876c0294481ee22dc0786fded1cdad9a6`; 130 commits ahead / 3 behind current main; exact-head workflow run #43128701870 succeeded.
- G05/Kernel integrated candidate `feat/brain-a3-g05-g01-g02-g11-integration`: `0968221b55563a9aacbec4fa499fdac7679e9915`; 231 ahead / 3 behind current main. Latest head is a documentation reconciliation commit; the branch's G05 implementation lineage is not thereby certified as a single production integration.
- G05 HTTP/PostgreSQL candidate `feat/g05-http-host-a3`: `c8991fc61170bc04d7aeaea390a76a85900c2232`; 378 ahead / 3 behind current main; exact-head Rust verification run #43280580981 succeeded.
- G05 PostgreSQL/G11 multiworker candidate `feat/g05-postgres-g11-multiworker-a3`: `2bfac619b9601330b3343f86277bb5ba29ae22b2`; 334 ahead / 3 behind current main; exact-head Rust verification runs #43240878046 and #43240392654 succeeded.
- G05 registry/lifecycle reconciliation record identifies incompatible variants: PR #43's G05-local reviewer-designation table is not authoritative and must be removed from the authority path; G02 must own organization designations/delegations. The record prefers opaque G01-verified proof consumption and the PR #51 pending-approval pattern, but still identifies G02 exact-tuple authorization, delegation binding, G11 acknowledgment gating and cross-store ordering as unresolved.

**A2 disposition:** G05's product contract and cross-domain direction are approved; G05 A3 implementation and G01/G02/G11 integration remain PARTIAL. Passing CI on individual heads does not resolve authority ownership or cross-store transaction gaps. No candidate is promoted as the Android app's runtime dependency.

### 8.2 G08 durable orchestration

- G08 A2 Owner closure record `IROKA-G08-A2-CLOSE-001`, version 1.0.0, commit `d941e2120f83ef5f864746c65d96bf9d4616110e`, states VERIFIED-CLOSED for architecture, scope and dependency-boundary reconciliation only.
- Its accepted scope is a tenant-scoped durable coordinator: versioned workflow/task state, DAG validation, idempotency, bounded leases/retry/cancellation, restart recovery and append-only transition evidence.
- It explicitly excludes tool execution, external side effects, G09 grants, model calls, production trust provisioning and deployment. G08 A3 implementation was NOT AUTHORIZED by that closure record.
- The separate G08 implementation candidate `feat/g08-a3-durable-coordinator` is at `2cfcf8db9437824cc8181ad8af1e8d819b936e2c`, 81 commits ahead / 3 behind current main; exact-head workflow run #43230367894 succeeded. This does not supersede the A3 authorization boundary or prove integration with an Android-facing service.

**A2 disposition:** G08 architecture is VERIFIED-CLOSED within its own domain. It remains a candidate dependency for the Android integration graph, not an approved or deployed mobile task runtime.

### 8.3 Updated Android integration graph

The repository now contains substantial G05, G01/G02 and G08 candidate work, but it still does not establish a single immutable, compatible, production-authoritative graph for the Android app. The following remain blockers for Android A2 closure:
1. A single canonical, exact-SHA integration baseline reconciling Kernel/G01/G02/G05/G08/G11; candidate branches currently diverge from current main and from one another.
2. A G01 native Android authentication contract and issuer-backed lifecycle (audience, scopes, refresh, revocation, device loss); browser cookie contracts are not adopted for native use.
3. A G02 exact-tuple decision API that is authoritative for tenant, organization, actor/reviewer, delegation version, operation, resource, record version/digest, purpose and classification.
4. G05 authority ownership correction and G11 durable acknowledgment/activation ordering, including explicit handling of cross-store partial failure.
5. A runnable first-party service host and a separate mobile API contract; G05 HTTP host is a domain-specific candidate, not yet an Android-wide cognition/task API.
6. G08 A3 authorization and exact integration contract before it can be used as a mobile task coordinator.
7. No verified Android-compatible on-device model/runtime artifact, signature/provenance chain, license, ABI/device floor or resource budget has been established.

**Updated A2 status: PARTIAL / NOT CLOSED.** G05 and G08 Owner-approved architecture decisions improve the evidence base but do not close the Android integration blockers. No Android repository or application code has been created; no source implementation, merge, main modification, deployment or production activation was performed.
