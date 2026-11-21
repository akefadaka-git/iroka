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


## 9. G01/G02/G05/G11 candidate lineage — exact ancestry reconciliation

Inspection of exact branch refs and pairwise GitHub compare results establishes the following ancestry. This is a source-lineage finding, not a merge or production approval.

### 9.1 Semantic authority baseline

**Canonical semantic integration candidate:** branch `feat/g05-g02-g11-activation-v12`, exact HEAD `b12739de686ac466dde02ad089f14e898eadffe9`.

This branch contains the G01 identity/reviewer-proof, G02 Owner-governed organization authority, G05 memory activation and G11 audit composition:
- G01 tenant-reconciliation candidate `c46f2b5876c0294481ee22dc0786fded1cdad9a6` is an ancestor of the v12 HEAD (94 commits behind it).
- G02 Owner/organization-authority candidate `31dd1cff9ab48c7ecedb941e920281f5e1924051` is an ancestor of the v12 HEAD (175 commits behind it).
- The v12 branch contains `iroka-kernel` and `iroka-g05-memory`; it is not an Android app or a complete hosted service.
- G01 verifies the signed credential into an opaque `VerifiedPrincipal`, then separately verifies a short-lived Ed25519 reviewer proof against the current issuer/subject/credential/key binding and exact approval/resource tuple. Reviewer proof lifetime is at most 300 seconds; binding freshness is at most 30 seconds; proof use is one-time.
- G02 is the sole organization designation/delegation authority. It resolves the current organization, tenant, reviewer, designation/delegation version and capability from Owner-signed authority state. G01 authentication or tenant membership alone does not imply an organization role.
- G05 owns memory records, episodic opt-in and lifecycle. The v12 registry deliberately limits itself to episodic consent and migrates legacy G05-local reviewer tables out of the authority path. G05 consumes typed G01 proof and a fresh G02 decision.
- G11 owns audit acceptance. Durable activation is staged as PendingReview -> PendingAudit -> G11 acknowledgment -> final repository compare-and-swap to Active. An acknowledgment must match the stable event ID and payload digest. This avoids reporting Active before the audit receipt and final version check.
- The v12 concrete composition uses `SqliteSecurityStore` and `SqliteAuditSink`; these are single-node/test adapters, not a multi-instance production persistence claim.

**Exact-head verification:** v12 commit `b12739de686ac466dde02ad089f14e898eadffe9`, workflow run [#43216600529](https://github.com/akefadaka-git/iroka/actions/runs/43216600529), success. Its job passed formatting, all-target compilation, production-feature exclusion, complete unit/contract tests and Clippy.

### 9.2 PostgreSQL persistence ancestry

The following chain is confirmed by pairwise comparisons with zero commits missing from the preceding baseline:

1. **G05/G11 PostgreSQL base:** `feat/g05-postgres-g11-multiworker-a3`, HEAD `2bfac619b9601330b3343f86277bb5ba29ae22b2`. It is 110 commits ahead of v12 with no v12 commits missing. It adds the shared PostgreSQL G05 repository, migrations, G05/G11 outbox, lease-based multiworker delivery and ADR-0007. Exact-head runs [#43240878046](https://github.com/akefadaka-git/iroka/actions/runs/43240878046) and [#43240392654](https://github.com/akefadaka-git/iroka/actions/runs/43240392654) succeeded.
2. **G02 PostgreSQL authority resolver:** `feat/g02-postgres-g09-resolver-a3`, HEAD `3e6273e592eb1c5d15cda398d51939cd19f0a7b5`. It is 10 commits ahead of the G05/G11 PostgreSQL base with no base commits missing. It adds G02 authority migrations and PostgreSQL resolver implementation. Exact-head runs [#43272969758](https://github.com/akefadaka-git/iroka/actions/runs/43272969758) and [#43272528554](https://github.com/akefadaka-git/iroka/actions/runs/43272528554) succeeded.
3. **G05 HTTP host:** `feat/g05-http-host-a3`, HEAD `c8991fc61170bc04d7aeaea390a76a85900c2232`. It is 34 commits ahead of the G02 resolver branch with no resolver commits missing. It adds the G05 HTTP ingress host and includes the G02 PostgreSQL migrations/adapters. Exact-head run [#43280580981](https://github.com/akefadaka-git/iroka/actions/runs/43280580981) succeeded.

The G05 HTTP host is narrow: it exposes `GET /healthz` and `POST /v1/g05/execute`, accepts a G01 credential in its request envelope, and runs G01/G02/G09 checks. It is not the first-party Android cognition/task API specified below.

### 9.3 Divergent G02 command-processor fork

A separate, newer G02 implementation branch exists:
- `feat/g02-postgres-command-processor-a3`, HEAD `7290142ba083f77f565d4d1b0922a158b391d1d8`.
- It is 60 commits ahead of the G05/G11 PostgreSQL base with no base commits missing.
- Exact-head run [#43357789397](https://github.com/akefadaka-git/iroka/actions/runs/43357789397) succeeded; the other listed run #43357761138 was cancelled and is not used as passing evidence.
- It includes the G02 PostgreSQL command processor and authority persistence work, but it does not include the G05 HTTP host branch's final HTTP host changes.

Pairwise compare confirms `feat/g02-postgres-command-processor-a3` and `feat/g05-http-host-a3` are **diverged siblings**: relative to the command-processor branch, the HTTP-host branch has 11 commits not in it, while the command-processor branch has 27 commits not in the HTTP-host branch. They share the G05 PostgreSQL ancestry but neither is a superset of the other. The command-processor branch is 50 commits ahead of the G02 resolver branch; the HTTP-host branch is 34 commits ahead of that resolver branch.

**Canonical lineage decision for A2:** retain v12 as the semantic authority baseline; retain G05 PostgreSQL -> G02 PostgreSQL resolver as the persistence lineage; designate the G02 command processor as the current G02 authority implementation candidate; designate the G05 HTTP host as the current narrow host candidate. Do not call these four refs one integrated build. A3 must reconcile the two sibling forks, preserve the later G02 command-processor changes, carry forward the host, and run one combined exact-head verification. No branch has been rebased, merged, modified or promoted in this A2 step.

### 9.4 Authority graph and transaction boundaries

The canonical authority direction is:

`Android client -> first-party API ingress -> G01 VerifiedPrincipal -> tenant membership resolution -> G02 current organization/delegation decision -> capability/policy decision -> G05 domain operation -> G11 durable audit receipt -> final state CAS`

Rules:
- G01 owns credential verification, key trust/rotation/revocation and signed reviewer-proof verification. A normal authenticated principal is not a reviewer approval.
- G02 owns Owner-signed organization creation, designation, delegation, suspension and revocation. No G05-local organization/reviewer registry is authoritative.
- G05 owns memory content, provenance, consent and lifecycle. It must compare the G01 proof and G02 current decision to the exact record version/digest/purpose/classification/capability tuple.
- G11 owns audit event acceptance and durable receipts; audit rows are evidence, not authority grants.
- G09 revalidates current authority immediately before any protected external effect. A prior ALLOW or cached grant is not a reusable execution authorization.
- G05 record mutation and creation of its content-free G11 outbox event must share one PostgreSQL transaction. G11 delivery is at-least-once with stable event IDs, payload-digest matching, leases and idempotent acknowledgment.
- G02 authority mutation and G05 memory activation are not one distributed transaction. If current G02 authority cannot be re-established, G05 remains pending/denied. No cross-database atomicity claim is made.
- G11 acceptance before final G05 CAS is a staged protocol, not a distributed transaction. Retries must be idempotent; a failed final CAS cannot reactivate or reuse a consumed approval.
- SQLite is limited to development/single-process tests. Shared deployment requires PostgreSQL primary/linearizable authority reads, transactional CAS, multi-process tests, least-privilege roles and independently protected checkpoint-signing keys.

## 10. First-party Android API contract proposal

**Status: A2 design proposal, not yet Owner-frozen and not implemented.** This contract is independent of the TALORA-specific API. It is the proposed Android-facing surface over a single trusted IROKA service; the G05-only HTTP host is not adopted as the complete API.

### 10.1 API conventions

- Base path: `/api/v1`; HTTPS only; JSON UTF-8; explicit request/response schema versions.
- Resource authentication: `Authorization: Bearer <short-lived IROKA access credential>`. No browser session cookies and no tokens in query strings.
- Every request receives a server-generated correlation ID. Mutating requests require an `Idempotency-Key` scoped to the authenticated issuer, subject and resolved tenant.
- Standard error envelope: RFC 9457 Problem Details (`application/problem+json`) with stable IROKA error code, correlation ID and retryability. Do not return stack traces, internal policy details or secret-bearing diagnostics.
- Principal, reviewer, organization role, capability grant and approval status are never accepted as caller-authored authority fields. A tenant selector is only a selector; the server resolves and validates current membership.
- Capability discovery is authorization-filtered. It reports only capabilities actually deployed, enabled and authorized for the current principal and tenant. A requested capability or execution mode is not itself a grant.
- All task, event, memory and provider operations are subject to server-side quotas, bounded input/output, request deadlines, concurrency limits, idempotency and audit requirements.

### 10.2 Core endpoint surface

| Endpoint | Contract |
|---|---|
| `GET /api/v1/session` | Return the authenticated principal's safe display identity, current session expiry and server-resolved tenant choices; never expose trust secrets or raw policy internals. |
| `GET /api/v1/capabilities` | Return the current principal/tenant's allowed capability IDs, versions, input/output schema refs, locales, execution modes actually available, limits and availability state. |
| `POST /api/v1/tasks` | Submit a capability-versioned task with bounded input, locale, optional authorized context references and idempotency key. Return `202 Accepted`, task ID and initial state. |
| `GET /api/v1/tasks/{task_id}` | Return state, timestamps, safe progress, result reference and terminal/error status after tenant/owner authorization. |
| `GET /api/v1/tasks/{task_id}/events` | Stream durable progress events over HTTPS SSE; support replay using `Last-Event-ID`; authorize every stream and bound retention/connection count. |
| `POST /api/v1/tasks/{task_id}/cancel` | Request idempotent cancellation only while the coordinator state permits it; report whether cancellation was accepted, already terminal or too late. Cancellation cannot reverse a committed protected effect. |
| `POST /api/v1/session/logout` | Revoke the current device/session refresh-token family at the issuer and invalidate server session state; then clear local credentials. |

Task submission proposal:
- Required: `capability_id`, `capability_version`, `input`, `locale`, client-generated `request_id`.
- Optional: tenant selector, authorized context references, requested execution preference (`cloud`, `on_device`, `hybrid`, `auto`).
- The server derives principal and authorization from G01/G02. The server may downgrade or reject an execution preference; it never executes a caller-selected provider or model directly.
- Initial task states: `accepted`, `queued`, `running`, `awaiting_authorization`, `succeeded`, `failed`, `cancelled`, `expired`. Only states supported by the deployed coordinator may be advertised.
- Result payloads include capability/version, schema version, provenance/evidence references, locale, execution mode and explicit synthetic/test labeling when applicable. No fake adapter response may be presented as real inference.

### 10.3 G05 memory API boundary

G05 memory is exposed only through capability- and policy-checked service endpoints after its HTTP/service adapter is integrated and verified. Proposed resource operations are metadata-first list/read, propose/create, inspect, correct, restrict, consent grant/withdrawal, deletion request and deletion verification. Content retrieval is a separate authorized operation after metadata checks. Durable activation requires the G01 signed reviewer proof, G02 exact current designation/delegation decision, G11 receipt and final optimistic version CAS. No direct client database access, raw memory-store API, client-authored approval, or offline activation is permitted.

## 11. Native Android authentication contract proposal

**Status: proposed profile; no production issuer, client registration, key ceremony or Android login implementation has been established.**

1. **Public client:** Android is a public OAuth client; no embedded client secret. Use Authorization Code + PKCE (S256) through the system browser/Custom Tabs, not an embedded WebView. Bind the callback to a verified HTTPS Android App Link or a tightly registered redirect URI; validate `state` and, where OIDC is used, `nonce`.
2. **Issuer boundary:** login/credential issuance belongs to a trusted IROKA identity issuer. The issuer exchanges the authorization code and PKCE verifier for a short-lived IROKA G01 access credential. The Android app does not mint identities or sign G01 credentials.
3. **Credential profile:** use the G01 compact JWS profile already implemented: EdDSA, `typ=IROKA-CREDENTIAL`, issuer/key ID, and claims `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`. The proposed resource audience is exactly `iroka-android-api`; the issuer must provision this audience and the verifier must check it exactly. Proposed access-token lifetime is 5–10 minutes, below the existing G01 maximum accepted lifetime of 3,600 seconds. Trust bundles remain root-signed, anti-rollback checked and rotated with controlled overlap.
4. **No authority claims in the token:** do not treat client-supplied role, organization, reviewer, capability, memory consent or tenant claims as grants. G01 authenticates; the server resolves tenant membership and G02 authority for each privileged request. If a tenant selector is supplied, reject it unless the current G01/G02 stores confirm membership and scope.
5. **Refresh lifecycle:** the issuer must issue opaque, high-entropy refresh tokens, store only their hashes server-side, rotate on every use, detect reuse, revoke the token family and expose device/session revocation. These issuer functions are not present in the current G01 credential verifier and must be separately implemented and verified. Refresh tokens never go to resource endpoints.
6. **Revocation and device loss:** credential/key revocation checks must use authoritative state or an explicitly bounded freshness policy; unavailable or stale revocation state fails closed. Logout revokes the current device/session family. A lost device can be revoked without affecting other devices. No production device-attestation or proof-of-possession support is claimed in this proposal.
7. **Android storage:** keep access credentials in memory where practical; protect refresh-token material using Android Keystore-backed encryption and exclude it from backups/logs/analytics. Do not store passwords or private issuer keys on device. Clear local tokens and cached sensitive data on logout/revocation.
8. **No browser-cookie dependency:** the existing `__Host-` browser cookie contract is not the native Android authentication contract. Native requests use HTTPS bearer credentials; CSRF defenses are not substituted for bearer-token validation. TLS certificate validation is mandatory; no permissive trust manager or certificate bypass.
9. **Offline:** offline use is limited to explicitly cacheable, non-sensitive content and local drafts. Offline task submissions may be stored as untrusted drafts but are not authorized, scheduled for protected effects, or executed until online re-authentication and fresh G01/G02/G09 checks. No stale capability snapshot authorizes execution.
10. **Issuer acceptance tests:** PKCE interception/replay, redirect mismatch, state/nonce mismatch, wrong audience, invalid signature, unknown issuer/key, token expiry/not-before, credential/key revocation, stale/unavailable revocation service, refresh rotation/reuse, device revocation, logout, tenant switching, and concurrent session revocation.

## 12. On-device runtime gate — unchanged and explicit

No on-device model/runtime is selected or approved. A future candidate must provide all of:
- immutable source/artifact provenance, signed release and independently verifiable SHA-256;
- license and redistribution/derivative-use rights compatible with the app and target markets;
- SBOM, vulnerability status, reproducible build or verifiable vendor build provenance;
- Android runtime/library version, supported model format, ABI, Android API floor and device/SoC/GPU/NPU compatibility matrix;
- measured peak RAM, storage, CPU/GPU/NPU utilization, cold-start/latency, battery and thermal behavior on representative low/mid/high devices;
- data classification, on-device retention/deletion, telemetry/network behavior, update/rollback and artifact-integrity controls;
- Amharic/English quality evidence, safety evaluation and a clear cloud fallback.
Until all gates pass, cloud-authoritative execution is the only approved execution mode; the app may provide safe offline reading/drafting only. On-device inference must never gain G01/G02/G09 authority or execute protected external effects.

## 13. Updated A2 disposition and required A3 work

**A2 status remains PARTIAL / NOT CLOSED.** The semantic authority graph and API/native-auth design proposal are now specified with exact evidence. The production integration graph is not yet a single branch: the G02 command-processor fork and G05 HTTP-host fork require a controlled A3 reconciliation and combined exact-head verification. The first-party API host, native issuer lifecycle, and Android app do not yet exist.

A3 implementation scope, only after separate Owner authorization:
1. Reconcile `feat/g02-postgres-command-processor-a3` and `feat/g05-http-host-a3` without discarding either the later G02 command-processor work or the HTTP host; produce one exact integration commit/branch.
2. Add cross-domain PostgreSQL integration tests for G01 credential/reviewer proof, G02 command/revocation/delegation, G05 transaction/CAS, G11 outbox/acknowledgment, worker restart/concurrency and failure injection.
3. Establish the first-party `/api/v1` host and implement the approved Android API contract, capability registry and durable task/event/cancellation lifecycle; do not reuse TALORA API semantics without explicit adoption.
4. Implement and test the native issuer/PKCE/refresh/revocation profile; do not enable production login before trust-root/key ceremony and issuer operations are verified.
5. Keep the on-device runtime gated by Section 12 evidence.

No A3 code, merge, rebase, branch deletion, production key provisioning, Android repository creation, deployment or main-branch modification was performed by this A2 reconciliation.
