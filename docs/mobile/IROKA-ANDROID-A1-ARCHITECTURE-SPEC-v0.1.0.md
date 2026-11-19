# IROKA Android — A1 Architecture and Requirements Specification

**Document ID:** IROKA-ANDROID-A1-001  
**Version:** 0.1.0  
**Status:** OWNER-APPROVED / A1 FROZEN — 19 November 2026  
**Date:** 19 November 2026  
**Product:** IROKA (first-party Android client)  
**Selected architecture:** Hybrid (cloud + on-device)  
**Cognitive access:** Full access to capabilities independently authorized and exposed by IROKA  
**Canonical intelligence repository:** `akefadaka-git/iroka`  
**A1 baseline commit:** `1aea1447eadf1d827d702fd6c4034fa058aac21e`  
**Working branch:** `architecture/a1-android-client-hybrid-spec`

## 1. Purpose and decision record

This specification assesses and defines a first-party Android application that provides a secure mobile interface to the IROKA cognitive platform. It is an IROKA client, not a fork, replacement, or independently authoritative cognitive system.

Owner-selected decisions:

| Decision | Selected value |
|---|---|
| Application identity | IROKA |
| Client platform | Native Android |
| Connection architecture | Hybrid |
| Cognitive access | Full authorized IROKA capabilities |
| Canonical authority | Existing IROKA Kernel and governed domain services |
| Android implementation repository | Proposed separate repository: `akefadaka-git/iroka-android` (not yet created) |

The term **full cognitive access** means the client can discover and invoke every capability that the authenticated principal is authorized to use and that the connected IROKA deployment declares available. It does not imply that every planned chromosome, agent, modality, model provider, or execution capability is already implemented or production-ready.

## 2. A1 assessment — verified repository facts

The assessment was performed against the connected GitHub destination repository.

### 2.1 Canonical repository

- Repository: `akefadaka-git/iroka`
- Repository ID: `1445234713`
- Visibility: public; repository license declaration remains proprietary (`LicenseRef-Proprietary`).
- Default branch: `main`
- Exact main HEAD at assessment: `1aea1447eadf1d827d702fd6c4034fa058aac21e`
- Main HEAD commit date: 17 November 2026.
- The main branch was reported as unprotected by the GitHub branch endpoint. This is a governance/security risk to record; this A1 change does not alter repository settings.
- Main Cargo workspace currently declares `crates/iroka-kernel` as its only workspace member.

### 2.2 Existing candidate work — preserve, do not silently adopt

The following relevant work exists on separate, unmerged draft branches/PRs:

| Work | Current evidence | Assessment |
|---|---|---|
| TALORA API service slice | PR #129, branch `integration/talora-a3-private-api`, head `00b323750fb120f80d56191069d10a825e66dc41` | Partial host/service candidate; not a production mobile API |
| BRAIN cognitive core | PR #27, branch `feat/brain-a3-b01-cognitive-core`, head `9d68b580e06bb8335a626524d64b345c3a5a38aa` | Synthetic deterministic cognitive slice; provider/network and persistent-memory access absent |
| Conversational interaction | PR #23, branch `feat/ciw-amharic-answer-only-chat`, head `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | Amharic-first text conversation slice; draft/unmerged and dependent on a separate Kernel branch |
| TALORA contract v0.1.0 | PR #127, head `df6a8035ec0bf9d8f094f3f17599092e830379bf` | Draft contract; TALORA-specific |
| TALORA contract v0.1.1 | PR #128, head `7ae4bd58125666530985a1c232d13696865e0548` | Reconciled TALORA-specific A2 proposal; Owner decisions still open |

PR #129 explicitly records that it has no runnable HTTP host/network listener, no production workload-token verifier or issuer/revocation configuration, no durable worker/event replay, no effective in-flight cancellation, no integrated G05 memory, and no end-to-end TALORA client network test. Its successful exact-head CI is not proof of a deployable service.

PR #23 records that the conversation server component is not a standalone production binary and requires a trusted host for session-cookie issuance, authoritative membership synchronization, TLS reverse proxy and (for multi-node deployment) shared durable storage. Its generator is synthetic-only.

PR #27 implements a bounded synthetic G03 core with a fake adapter. It does not establish a production model gateway or complete cognitive system.

### 2.3 Contract applicability

TALORA contracts #127/#128 describe a separate client product and must not be treated as the approved first-party Android contract. Their API, security, task-envelope and memory concepts may be examined as candidate evidence in A2, but the Android client needs its own authority, identity, lifecycle, capability, device, offline and release requirements.

No existing candidate branch or PR is selected as the Android integration baseline. No branch is merged, rebased, rewritten, deleted or repurposed by this A1 work.

## 3. Product and system boundary

IROKA Android is a first-party presentation and device-capability client. It communicates with an IROKA-owned service interface and, where explicitly supported, a locally installed IROKA runtime component.

The Android app MUST NOT:
- Treat GitHub as the cognitive execution server.
- Download arbitrary source from a branch and execute it as an app update or runtime.
- Contain GitHub personal access tokens, provider API keys, Owner signing keys, database credentials or privileged service credentials.
- Implement a competing identity, policy, Owner approval, audit, memory, trust-root, or execution authority.
- trust client-supplied tenant, role, entitlement, principal, consent or authorization claims without server-side verification.
- bypass G01/G02/G05/G08/G09/G11/G12 controls.
- claim capabilities as operational merely because a screen or API model exists.

IROKA remains the authoritative system. The Android client may cache user-permitted content and maintain local UI state, but local state is not a substitute for authoritative IROKA policy or audit state.

## 4. Target hybrid architecture

### 4.1 Android client layer

Proposed implementation:
- Kotlin and Jetpack Compose.
- MVVM with clean separation between presentation, domain/use-case and data/network layers.
- Retrofit/OkHttp (or a subsequently approved equivalent) for authenticated HTTPS APIs.
- Kotlin Serialization for versioned wire contracts.
- Room for bounded local metadata and offline cache.
- Android Keystore-backed encryption/key protection for local secrets.
- WorkManager for bounded, retryable synchronization of non-consequential work.
- Android audio/speech interfaces only after the corresponding IROKA perception/voice capabilities and privacy controls are verified.

The client exposes a capability-driven interface. Screens and actions are generated from the authenticated capability catalogue and explicit client support declarations, not from hardcoded assumptions that all planned functions exist.

### 4.2 Cloud IROKA service layer

The cloud service is responsible for:
- Authentication and verified-principal establishment.
- Server-side tenant and membership resolution.
- G02 policy and approval evaluation.
- Capability discovery and version negotiation.
- Task admission, idempotency, quotas, cancellation and result delivery.
- Orchestration and routing to authorized cognitive components.
- G05 governed memory operations.
- G11 audit/evidence records and operational security.
- G09 protected effects only through the existing authorization and approval path.
- G12 release and capability-version governance.

The API host is a required A2/A3 dependency. A library route handler is not equivalent to a runnable, secured production service.

### 4.3 On-device runtime layer

On-device processing is a placement option, not an independent authority. Candidate local functions include:
- UI rendering and accessibility.
- Encrypted, policy-bounded cache and user-selected offline content.
- Local input preprocessing and device-native speech capture.
- An approved local model/runtime adapter, only after its artifact provenance, compatibility, resource use, data handling and security are validated.
- Offline tasks explicitly classified as safe, local-only and non-consequential.

The device MUST NOT locally mint Owner approvals, alter trust roots, grant capabilities, activate production policies, or perform protected effects while disconnected. Offline queued requests are proposals and must be re-authorized by the service before execution. The client must clearly distinguish local-only results from cloud-verified results.

No production on-device model, inference artifact, quantization, device floor or local runtime has been verified in this A1 assessment. These are A2 decisions, not assumed capabilities.

### 4.4 Placement and synchronization

A placement decision must consider data classification, user consent, device capability, network availability, latency, resource limits, cost and provider policy.

- Local-only data must not be uploaded implicitly.
- Cloud-only capabilities must fail clearly when unavailable.
- Sync requests must carry stable request/idempotency identifiers, schema versions, expiry and minimal required context.
- Server-side authorization is re-evaluated at execution time; cached permissions do not grant indefinite authority.
- Conflicts must be surfaced and resolved under explicit revision semantics; the client must not silently overwrite canonical state.
- Revocation, logout and account disablement must invalidate applicable client credentials and sensitive cached access.

## 5. Mobile API and protocol requirements

The initial API shape is a proposal to reconcile in A2, not a claim that these endpoints already exist:

| Interface | Purpose |
|---|---|
| `GET /api/v1/health/live` | Non-sensitive service liveness |
| `GET /api/v1/health/ready` | Readiness of required dependencies and authority stores |
| `GET /api/v1/capabilities` | Capability IDs, versions, scopes, locales, limits and availability |
| `POST /api/v1/tasks` | Submit a bounded cognitive task |
| `GET /api/v1/tasks/{id}` | Read authorized task state/result |
| `GET /api/v1/tasks/{id}/events` | Bounded progress/result event stream |
| `POST /api/v1/tasks/{id}/cancel` | Request cancellation |
| Conversation/session routes | Establish and continue authorized conversations through the canonical conversation service |

Every task request must be bound to a verified principal, server-resolved tenant context, capability and version, correlation ID, idempotency key, expiry, locale, data classification, purpose, policy/authorization context, bounded resource constraints and required output schema. The client must not be the source of truth for authority-bearing references.

Responses must distinguish completed, partial, abstained, denied, cancelled, timed out, budget exhausted and failed outcomes; include capability/version and provider/runtime attribution; and identify evidence, uncertainty, limitations and usage where applicable.

Streaming must be bounded, authenticated, ordered and reconnect-safe. Cancellation is best-effort and must return an explicit state. Retry behavior must not duplicate tasks or protected effects.

### 5.1 Mobile authentication

The native app requires a mobile-appropriate authentication contract. The current CIW cookie/session design assumes a trusted host capable of issuing and validating its session cookies; it is not automatically a native Android authentication solution.

A2 must select and verify a G01-compatible mobile flow, including:
- Authorization Code with PKCE or another explicitly approved secure native-client flow.
- Short-lived, audience-restricted credentials and refresh/revocation semantics.
- Secure credential storage using Android Keystore-backed protections.
- Logout, credential rotation, lost-device response and session revocation.
- Server-side tenant membership and authorization resolution.
- No embedded client secret or long-lived privileged token.

Exact issuer, token format, scopes, key binding and revocation semantics remain OPEN pending G01 reconciliation.

## 6. Functional requirements

| ID | Requirement |
|---|---|
| AND-F01 | Secure sign-in, sign-out and session/device revocation |
| AND-F02 | Discover all available, versioned IROKA capabilities and explain unavailable/unauthorized states |
| AND-F03 | Amharic-first text conversation with English and explicit locale handling |
| AND-F04 | Structured cognitive task submission, progress, result, retry and cancellation |
| AND-F05 | Evidence, assumptions, uncertainty, abstention and provenance display |
| AND-F06 | Governed memory access only through G05-approved interfaces and consent |
| AND-F07 | Voice and other perception interfaces only when corresponding capabilities are verified |
| AND-F08 | Hybrid placement with clear local/cloud provenance and user-visible data handling |
| AND-F09 | Offline access to explicitly cacheable information and safe local-only functions |
| AND-F10 | Owner/administrative controls surfaced only when server-authorized; no client-side authority |
| AND-F11 | Runtime, API, capability and app-version health/status visibility |
| AND-F12 | Accessible interaction, localization, notification and privacy controls |

## 7. Security, privacy and governance requirements

- G01 remains the sole identity and trust-root authority.
- G02 remains the policy, Owner authority and approval authority.
- G05 remains the only IROKA memory authority.
- G08 owns durable orchestration and task lifecycle.
- G09 remains the protected execution boundary.
- G11 owns assurance and audit evidence; app telemetry cannot substitute for authoritative audit.
- G12 controls version adoption and evolution.
- G03 output is untrusted analysis, not permission.
- Device compromise, root/debug state, backup extraction, screenshots, clipboard, notification previews, logcat and crash reporting must be considered in the threat model.
- Sensitive local data must be minimized, encrypted, access-controlled and subject to retention/deletion rules.
- TLS is mandatory; certificate/pinning strategy, rotation and failure behavior are A2 decisions.
- Deep links, exported Android components, intents, WebViews, local IPC and backup/restore must be threat-modelled.
- No private user content may be transmitted to a live external model provider unless the provider, data handling, consent and policy are separately approved.
- All model, tool, retrieved, cached and user-provided content is untrusted input.
- Critical governance and trust-root operations remain Owner-controlled and cannot be approved by the app or model itself.

## 8. Localization, accessibility and device support

- Amharic-first interface and Ethiopic script preservation are mandatory.
- English is supported as an additional interface/content language.
- Locale, calendar and time-zone handling must use regional profiles; Ethiopia defaults must not be hardcoded into shared African core logic.
- Ethiopian calendar and Gregorian interoperability must be tested where dates are displayed.
- No transliteration or normalization may silently destroy original-script identity or source text.
- Accessibility target: WCAG 2.2 AA-aligned interaction principles as applicable to native Android, including TalkBack, scalable text, contrast, focus order, touch targets and reduced-motion behavior.
- A2 must establish minimum Android API level, device/RAM/storage requirements, ABI, local-runtime hardware floor and supported offline behavior based on actual test devices.

## 9. Non-functional requirements and acceptance targets

A2 must convert these into measurable thresholds after target devices and service topology are selected:

- Security: authorization-negative tests, tenant isolation, token expiry/revocation, replay, injection, secure storage and no-secret-in-APK checks.
- Reliability: bounded retry, idempotency, reconnect, task recovery and explicit partial/failure states.
- Performance: cold start, UI responsiveness, API latency, streaming time-to-first-event, memory, battery, thermal and data usage.
- Privacy: data-flow inventory, local/cloud classification, consent, retention, deletion and telemetry minimization.
- Compatibility: supported Android versions, ABI and device matrix.
- Accessibility/localization: Amharic/Ethiopic rendering, TalkBack flows, dynamic text and locale/calendar conformance.
- Supply chain: reproducible locked builds, dependency/license review, SBOM, artifact signing, provenance and release verification.

No numerical production SLO is frozen in A1.

## 10. Delivery stages and gates

| Stage | Scope | Exit condition |
|---|---|---|
| A1 | Assessment, architecture, requirements, threat boundaries and decision register | Owner freezes this specification and unresolved decision list |
| A2 | Reconcile exact IROKA component graph, G01/G02 mobile identity, API host, CIW/BRAIN integration, device/runtime, data placement and test contracts | Versioned compatible integration baseline and Owner authorization for implementation |
| A3 | Implement isolated Android app and only the required, separately authorized IROKA host/runtime integration | Exact-commit implementation and CI evidence |
| A4 | Device, API, security, accessibility, offline/recovery and cognitive acceptance verification | Complete exact-SHA verification report; independent assessment scheduled once after A4 and before A5 |
| A5 | Release/deployment | Separate explicit Owner authorization and verified release readiness |

Independent review is not a per-step or per-PR blocker. It is scheduled once after implementation and A4, immediately before A5 deployment. No deployment is authorized by this specification.

## 11. A2 decision register — unresolved

1. **Repository creation and governance:** confirm separate `akefadaka-git/iroka-android` repository, proprietary status, branch protections and release ownership. Repository does not yet exist at A1 assessment.
2. **Integration baseline:** reconcile BRAIN, CIW, Kernel, G01/G02, G05, G08 and service/API candidates by exact commits and dependencies. No candidate branch is automatically approved.
3. **Mobile identity:** select G01-compatible native authentication, token binding, scopes, expiry, refresh, revocation and lost-device flow.
4. **Runnable service host:** select deployment/hosting topology, TLS termination, trusted proxy, durable storage, event delivery, scaling and operations. PR #129 is not a runnable production host.
5. **Capability contract:** freeze capability catalogue schema, versions, discovery, authorization errors, feature availability and client compatibility.
6. **Hybrid execution:** classify which functions are local, cloud or either; select local runtime/artifact, supported hardware and update/provenance mechanism.
7. **Offline policy:** define cache classes, retention, queued request limits, expiry, conflict handling and re-authorization.
8. **Provider policy:** retain fake/local deterministic testing by default; no live provider activation without separate approval.
9. **Memory:** specify G05 mobile access, opt-in, consent, visibility, correction, retention and deletion; no separate Android memory store.
10. **Localization and assurance:** approve Amharic/Ethiopic test corpus, reviewers and measurable acceptance thresholds.
11. **Release channel:** choose Play Store, signed APK distribution or both; define signing-key custody, update/rollback and artifact provenance.
12. **Device floor and SLO:** measure supported devices, performance, battery, network and availability before numeric commitments.

## 12. A1 exclusions

This A1 work does not:
- Create the Android repository or implement Android code.
- Modify IROKA main or any existing branch/PR.
- Merge, close, rebase, retarget or delete existing IROKA work.
- Select a production model provider or send private data to one.
- Provision production credentials, trust roots or Owner keys.
- Activate production memory, G09 effects, autonomous execution or a local model.
- Claim a production-ready cognitive runtime or API.
- Authorize A5 deployment.

## 13. A1 disposition

**Assessment:** COMPLETE for the initial repository and architecture review.  
**Specification:** DRAFTED as v0.1.0 on an isolated documentation branch.  
**A1 freeze:** OWNER-APPROVED on 19 November 2026. The twelve unresolved items remain A2 reconciliation decisions; they do not reopen the approved product identity, hybrid architecture, or full-authorized-capabilities objective.  
**Implementation authorization:** NOT GRANTED by this document.  
**Main branch:** unchanged at `1aea1447eadf1d827d702fd6c4034fa058aac21e`.

Guiding rule: **IROKA Android is a governed client of IROKA, never a second source of IROKA authority.**
