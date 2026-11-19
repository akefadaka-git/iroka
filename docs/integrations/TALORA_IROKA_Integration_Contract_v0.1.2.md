# TALORA--IROKA Integration Contract

**Document ID:** TALORA-IROKA-IC-001\
**Version:** 0.1.2\
**Status:** A2 contract aligned to Owner dispositions D01–D09; integration baseline UNRESOLVED; not implementation authorization\
**Date:** 19 November 2026\
**Parent baseline:** TALORA A1 approved product definition\
**IROKA reference baseline:** `akefadaka-git/iroka` `main` at
`1aea1447eadf1d827d702fd6c4034fa058aac21e` (reference only; not yet approved as the integration implementation baseline)\
**Authority:** Owner-governed; A3 implementation requires separate
approval

## 1. Purpose and scope

This contract defines a safe, versioned integration boundary between
TALORA Creative Studio and IROKA. TALORA remains the system of record
for creative projects, scripts, revisions, production records,
subscriptions and user-facing consent. IROKA supplies governed
intelligence capabilities through replaceable adapters. IROKA is not the
owner of TALORA projects and must not silently mutate TALORA content.

This is a proposed contract, not evidence that the endpoints, provider
adapters, production model access, Android SDK or complete IROKA runtime
already exist.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and
**MAY** have their usual requirements meaning.

## 2. Architectural boundary

1.  TALORA Android communicates with the TALORA backend.
2.  The TALORA backend authenticates the user, resolves
    organization/workspace/project permissions, applies subscription
    entitlements, obtains consent and constructs a scoped IROKA task.
3.  The TALORA backend calls IROKA through a private service-to-service
    interface.
4.  IROKA validates its own workload identity, tenant scope, policy,
    capability, budget and data-classification constraints.
5.  IROKA returns a typed result or a proposed patch. TALORA validates
    and stores the proposal.
6.  A user with the required TALORA permission explicitly accepts or
    rejects any script/document change. Acceptance is a TALORA
    operation, not an IROKA side effect.

The Android application MUST NOT contain IROKA provider keys, database
credentials, signing keys or privileged service credentials. IROKA MUST
NOT trust client-supplied project, tenant, role, entitlement or consent
claims without TALORA backend authentication and authorization.

## 3. Versioning and compatibility

-   API prefix: `/api/v1`.
-   Media type: `application/vnd.iroka.task.v1+json`; responses use the
    corresponding `result.v1` media type.
-   Every request MUST include `contract_version`, `task_schema_id`,
    `client_request_id`, `correlation_id`, `created_at`, `expires_at`,
    and an idempotency key.
-   Additive optional fields are permitted within v1. Removing fields,
    changing semantics, relaxing security, or changing canonical
    serialization requires a new major API version.
-   Every task and result MUST include schema identifiers and version
    numbers. Unknown major versions MUST be rejected.
-   TALORA MUST pin the accepted IROKA API contract and capability
    versions. It MUST NOT infer compatibility from branch names or a
    successful CI run.
-   IROKA MUST expose `GET /api/v1/capabilities` with capability IDs,
    contract versions, supported locales, maximum input/output limits,
    availability state, provider class and declared data-handling
    constraints.

## 4. API surface

### 4.1 Proposed endpoints

  ---------------------------------------------------------------------------------
  Method and path                               Purpose
  --------------------------------------------- -----------------------------------
  `GET /api/v1/health/live`                     Process liveness only; no sensitive
                                                details

  `GET /api/v1/health/ready`                    Dependency readiness; fail closed
                                                for required authority stores

  `GET /api/v1/capabilities`                    Versioned capability and locale
                                                discovery

  `POST /api/v1/tasks`                          Submit a bounded intelligence task

  `GET /api/v1/tasks/{task_id}`                 Retrieve task state and result
                                                metadata

  `GET /api/v1/tasks/{task_id}/events`          Bounded SSE progress stream

  `POST /api/v1/tasks/{task_id}/cancel`         Cancel a running task

  `POST /api/v1/memory/query`                   Authorized project-scoped memory
                                                retrieval

  `POST /api/v1/memory/records`                 Create an authorized memory record

  `GET /api/v1/memory/records/{record_id}`      Read a record within current
                                                authorization

  `DELETE /api/v1/memory/records/{record_id}`   Request governed deletion/retention
                                                action
  ---------------------------------------------------------------------------------

Memory endpoints are internal backend interfaces. They MUST NOT be
exposed directly to the Android client. G05 remains the sole memory
authority; TALORA MUST NOT create a competing IROKA memory store or
bypass G05 consent, classification, retention, correction, deletion and
audit rules.

### 4.2 Task request envelope

Required fields:

-   `task_schema_id`, `contract_version`
-   `task_id`, `client_request_id`, `correlation_id`, `idempotency_key`
-   `principal_ref`, `tenant_ref`, `workspace_ref`, `project_ref`
-   `document_ref`, `document_revision` when the task concerns a script
    or production document
-   `capability_id` and `capability_version`
-   `task_class` and `objective`
-   `locale` and optional `calendar`
-   `input_refs[]`, each with source, classification, purpose and
    revision/digest
-   `consent_ref`, `authorization_ref`, `policy_ref`
-   `constraints`: input bytes, output tokens, deadline, iteration
    limit, provider permission, persistence permission and cancellation
    behavior
-   `required_evidence` and output schema identifier

The caller MUST pass opaque identifiers and only the minimum source text
required for the task. IROKA MUST reject missing, stale, ambiguous or
out-of-scope authority context.

### 4.3 Result envelope

Every result MUST include:

-   task and correlation identifiers; contract and schema versions
-   terminal state: `completed`, `partial`, `abstained`, `denied`,
    `cancelled`, `timed_out`, `budget_exhausted` or `failed`
-   capability and model/provider attribution
-   locale used and any fallback
-   claims, evidence references, assumptions, uncertainty and unresolved
    questions
-   resource usage and cost attribution
-   verification status and limitations
-   either a result payload or a proposed patch, never an implicit
    document mutation

A script patch MUST be bound to `project_ref`, `document_ref`, base
`document_revision`, and a content digest. TALORA MUST reject a patch if
the source revision has changed. Patches MUST be previewable,
reviewable, diffable and reversible. IROKA MUST NOT commit or publish a
TALORA document.

### 4.4 Asynchronous execution

`POST /tasks` returns `202 Accepted` with `task_id`, current state and
polling/event URLs. Repeated requests with the same idempotency key and
equivalent payload MUST return the original task, not create duplicate
work. SSE events MUST be ordered, bounded and replayable where the
persistence contract supports it. Cancellation is best-effort but MUST
produce an explicit terminal state; a completed task cannot be
retroactively cancelled.

## 5. Initial capability identifiers

The following identifiers are proposed TALORA-facing capabilities. They
are TALORA orchestration contracts, not claims that corresponding IROKA
services are implemented:

-   `talora.story.architect.v1`
-   `talora.script.doctor.v1`
-   `talora.character.intelligence.v1`
-   `talora.continuity.guardian.v1`
-   `talora.cinematic.intelligence.v1`
-   `talora.stage.director.v1`
-   `talora.production.intelligence.v1`
-   `talora.language.assistant.v1`

Each capability MUST declare allowed input types, output schema, locale
coverage, classification ceiling, evidence requirements, token/cost
ceiling, persistence behavior, and whether it may return suggestions
only or structured patch proposals. None may directly invoke G09
protected effects or autonomously alter a canonical TALORA script.

## 6. Model-provider contract

### 6.1 Adapter requirements

A model provider MUST be accessed only through an IROKA-owned
`ModelAdapter` interface. The adapter contract MUST support:

-   `generate(request, limits)` and, where supported, bounded streaming
-   provider/model/version attribution
-   deterministic request correlation and idempotency behavior
-   timeout, cancellation and provider-error mapping
-   measured input/output usage, latency and estimated/actual cost
-   provider region, retention/training policy and data-classification
    constraints
-   health/readiness and circuit-breaker state
-   replaceability without changing TALORA task schemas

The inspected G03 candidate refs expose inference, premise and uncertainty kernel modules, but no TALORA-ready model-provider adapter was verified on the exact refs reconciled for v0.1.2. The earlier v0.1.1 assertion that a `ModelAdapter` and `DeterministicFakeAdapter` were present is withdrawn as an implementation claim. The G11 `checkpoint_https` adapter is an external checkpoint-publication adapter, not a generative-model adapter. No live or deterministic fake model adapter is verified on the candidate graph. D05 therefore establishes the binding provider policy (fake/local only; no live provider), not proof that an adapter is implemented.

### 6.2 Provider selection and data handling

-   Initial A3 MUST use a deterministic fake/local adapter for
    integration and acceptance tests.
-   A remote provider MUST remain disabled until provider identity,
    service region, subprocessors, retention, training use, security
    controls, price schedule, availability and contractual terms are
    reviewed and explicitly approved.
-   Private or unpublished scripts MUST NOT be sent to an external
    provider by default. Any exception requires explicit, informed,
    revocable user/organization authorization and a policy decision
    bound to the exact task and data classification.
-   Providers MUST NOT train on TALORA private creative content unless
    the owner of the content gives explicit informed authorization under
    a separate opt-in.
-   Provider prompts and responses MUST be treated as untrusted data.
    Prompt injection MUST NOT alter IROKA authority, TALORA permissions
    or policy.
-   The adapter MUST never receive long-lived Owner signing keys or
    TALORA database credentials.

### 6.3 Provider failure

If a provider is unavailable, over budget, disallowed by classification,
or unable to meet the requested locale, IROKA MUST return an explicit
partial/abstained/failed state. TALORA writing, editing, export and
offline workflows MUST continue without IROKA.

## 7. Memory and creative-content governance

TALORA is the system of record for projects and scripts. G05 is the only
IROKA memory authority.

Memory records MUST be scoped by tenant, workspace, project and, where
applicable, document and revision. Each record MUST carry:

-   owner and scope references
-   purpose and user/organization consent reference
-   classification and sensitivity
-   source reference, source revision/digest and provenance
-   creation and expiry/retention timestamps
-   allowed operations and current authorization version
-   correction, deletion and audit state

Default policy:

1.  No unpublished script content is persisted to long-term IROKA memory
    by default.
2.  Task context is ephemeral unless the user explicitly enables project
    memory.
3.  Project memory is opt-in, project-scoped and visible to authorized
    project members.
4.  Organization memory MUST be separately consented and must not
    silently include personal projects.
5.  Cross-project retrieval is denied unless an explicit policy and
    permission grant authorizes it.
6.  A user may inspect, correct, export and request deletion of memory
    associated with their project, subject to disclosed legal retention
    requirements.
7.  Deletion requests MUST propagate to derived indexes, caches and
    replicas under a documented deletion SLA; immutable audit records
    may retain minimal non-content evidence where legally required.
8.  Memory retrieval MUST return provenance and source references.
    Generated summaries MUST NOT be represented as source truth.

The live G05/G02/G11 candidate `feat/g11-provider-adapters-a3-rebased` at `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810` contains the `iroka-g05-memory` crate, SQLite and PostgreSQL repositories, G02 authority/outbox code, PostgreSQL migrations and G11 checkpoint-quorum/publication code. Its workspace pins Rust 1.75. The G05 manifest pins `postgres 0.19.12`, `postgres-native-tls 0.5.0`, `native-tls 0.2.12`, `rusqlite 0.32.1`, `serde_jcs 0.2.0` and `ed25519-dalek 2.1.1`. This candidate remains a separate divergent branch, not an accepted TALORA dependency. Its narrow HTTP host binds only to loopback behind a trusted TLS-terminating reverse proxy and exposes `/v1/g05/execute`; that is not the TALORA task API or a complete G05 memory API surface.

## 8. Identity, authentication and authorization

-   TALORA backend authenticates the user and enforces its own
    organization/project/document roles before task submission.
-   Backend-to-backend IROKA calls MUST use short-lived,
    audience-restricted workload credentials and mutual TLS where
    supported. Mobile clients MUST never call privileged IROKA endpoints
    directly.
-   The live CIW candidate `feat/ciw-amharic-answer-only-chat` at `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` adds the `iroka-conversation` crate and browser chat. Its inspected HTTP surface includes conversation and generation/event routes under `/api/v1/conversations` and `/api/v1/generations/{assistant_id}/events`. It is a browser/conversation candidate, not a verified TALORA backend-to-backend task API. It changes shared Kernel identity/security code and is divergent from the G05/G02/G11 candidate. TALORA therefore uses only the approved private service-to-service API boundary; no browser-cookie or Android client authentication design is inferred from CIW.
-   IROKA MUST independently verify the calling workload, issuer,
    audience, expiry, revocation state, tenant, scope and requested
    capability.
-   Every task MUST be authorized for the exact project/document and
    data classification. User role or subscription status alone is
    insufficient.
-   Authorization MUST be revalidated before any persistent memory
    operation. Models and agents cannot manufacture principals, tenant
    membership, consent or grants.
-   All security-sensitive decisions MUST be auditable with correlation
    IDs, policy version, authorization result and evidence references,
    without logging full script contents by default.

## 9. Security and privacy controls

Minimum controls before production:

-   TLS in transit; mTLS for service-to-service where deployable;
    encryption at rest for databases, backups and object storage
-   secrets in server-side secret management; rotation and revocation;
    no secrets in APK, source, logs or analytics
-   strict tenant isolation and negative cross-tenant tests
-   least privilege, short-lived tokens, audience binding and
    replay/idempotency protection
-   bounded request sizes, output sizes, concurrency, timeouts and queue
    depth
-   secure headers, origin validation for browser endpoints, CSRF
    protections where cookie auth is used
-   audit integrity, tamper evidence and retention policy
-   threat modeling for prompt injection, malicious scripts, poisoned
    references, data exfiltration, model/provider compromise, dependency
    compromise and account takeover
-   vulnerability and dependency scanning, SBOM, pinned dependencies and
    reproducible release evidence
-   data minimization and redaction in logs, metrics and support
    diagnostics
-   incident response, backup/restore, key compromise and user
    notification procedures

G08 candidate documentation explicitly warns that SQLite-only state can
be rolled back by restoring a database snapshot; production
anti-rollback requires an independently protected monotonic anchor or
remote witness. The candidate threat model records independent security
review as not performed. No production-readiness claim is permitted
until these conditions are satisfied.

## 10. Localization and language contract

-   Ethiopia profile default: `am-ET`; English `en` is available. TALORA
    MUST preserve the user's selected locale and MUST NOT force Amharic
    when the user selects English.
-   Every request and result MUST carry an explicit BCP 47 locale. Model
    language detection may assist but MUST NOT silently translate or
    rewrite user content.
-   UTF-8 and Ethiopic Unicode MUST be preserved end-to-end, including
    combining marks, punctuation, mixed Ethiopic/Latin text, numerals,
    copy/paste, cursor movement and export.
-   Original text is immutable source content. Any normalized
    search/index representation MUST be derived and non-destructive.
-   Ethiopic font shaping, line breaking, pagination, accessibility and
    PDF/DOCX/Fountain/FDX export are TALORA client/document-engine
    responsibilities and require separate rendering tests; IROKA's
    language metadata does not prove rendering support.
-   Translation output MUST be marked draft/unverified until reviewed by
    an authorized human language reviewer. Evidence references alone do
    not authenticate a reviewer.
-   Unsupported transliteration or script conversion MUST preserve the
    original and return an explicit unsupported result. The inspected
    localization candidate only implements exact same-script
    pass-through and fails closed for cross-script conversion.
-   Ethiopian and Gregorian calendar identifiers MUST be explicit
    wherever calendar dates are used. Date-only values MUST remain
    distinct from instants; instants are stored canonically and rendered
    using an explicit IANA time zone. Ethiopia profile default time zone
    is `Africa/Addis_Ababa`.
-   Locale capability discovery MUST state per workflow whether support
    is `not_supported`, `input_only`, `basic_ui`, `reviewed_ui` or
    `full_workflow_verified`.
-   No claim of full Amharic AI, OCR, speech or translation support is
    allowed without a reviewed corpus, human evaluation and workflow
    acceptance evidence.

## 11. Cost, quotas and monetization controls

No provider, live price schedule, hosting price, or production usage
baseline was verified. Therefore this contract sets mandatory cost
controls but does not invent ETB prices.

### 11.1 Cost model

For each task, calculate and retain:

`task_cost = input_cost + output_cost + tool_cost + allocated_compute_cost + storage_cost + network_cost + applicable_tax`

For token-priced providers:

`input_cost = input_tokens × input_rate_per_token`\
`output_cost = output_tokens × output_rate_per_token`

Rates MUST be versioned with provider, model, currency, effective date
and source. Report both provider currency and ETB equivalent with the FX
source and timestamp. Never treat an FX conversion as a provider price
quote.

### 11.2 Mandatory limits

-   Hard per-task input, output, duration and monetary ceilings.
-   Per-user daily and monthly quotas.
-   Per-organization monthly budget and administrator-configurable
    limits.
-   Provider-level spend ceiling and circuit breaker.
-   Global owner-controlled monthly spend ceiling.
-   Preflight cost estimate and explicit denial/approval when the
    estimate exceeds a configured limit.
-   Actual usage reconciliation after every task; failed, retried and
    cancelled calls must still account for provider charges.
-   No silent quota overrun, automatic paid upgrade, or automatic
    top-up.
-   Every budget must have a defined action at exhaustion: deny, queue
    for next period, or request authorized purchase/approval.

### 11.3 Free and Premium policy

-   Free entitlement receives a finite, published IROKA allowance. Ads
    do not increase the allowance and must not be targeted using private
    script content.
-   Premium is a one-time purchase for the defined ad-free software
    features and a disclosed finite inference allowance. It MUST NOT
    promise unlimited lifetime hosted inference.
-   Additional inference, if later offered, requires a separately priced
    and explicitly approved mechanism; no automatic recurring charge.
-   Organization plans require administrator budgets, member quotas,
    audit reporting and contractual data-handling terms.
-   Ads MUST NOT appear inside scripts, exports, private project
    workspaces or IROKA-generated creative content. No
    private-content-based ad targeting or sale of unpublished works.
-   Provider, hosting, payment, ad-network and tax availability in
    Ethiopia must be verified before pricing or launch decisions.

### 11.4 Pre-provider approval gate

Before enabling any paid provider, the Owner must approve: provider and
model, deployment region, rate card, FX policy, free/premium quotas,
per-task ceiling, per-user and organization ceilings, global monthly
cap, retention/training terms, fallback behavior and a cost-monitoring
dashboard.

## 12. Reliability, observability and service levels

A production SLO is not asserted by this A2 proposal. A4 must establish
measurable targets for availability, task latency by capability,
cancellation latency, queue age, error rate, provider availability, cost
reconciliation and data recovery.

Every task MUST be traceable through a correlation ID across TALORA and
IROKA. Metrics MUST avoid script text and other sensitive content.
Readiness MUST fail when required identity, policy, memory or audit
dependencies are unavailable. TALORA's core editor and local data MUST
remain usable during IROKA outage.

## 13. Data retention and export

TALORA remains the canonical archive for scripts and production
documents. IROKA task payloads, temporary context, generated outputs and
memory records require separately declared retention periods. Default
temporary task retention SHOULD be the minimum necessary for delivery,
troubleshooting and dispute handling. Export and deletion behavior must
include backups, replicas, caches and derived indexes, with documented
exceptions for legal/audit records.

## 14. Dependency, verification and assurance gates

### 14.1 Before A3 integration implementation

1. Select one immutable, Owner-approved IROKA integration baseline; do not compose arbitrary divergent branches.
2. Reconcile G01/G02 authorization and tenant contracts, G03 task/result contracts, CIW transport, G05 memory contracts, G08 orchestration and G11 audit/assurance on one compatible dependency graph. Identify exact commits and test evidence for each included component.
3. Verify exact dependency licenses and internal cross-project rights before implementation. The current IROKA main README states that no explicit open-source license is granted; public visibility does not grant permission to copy, modify, redistribute or sublicense project material. D03 permits API/service integration only within this TALORA scope and does not grant source copying, vendoring, modification, SDK distribution or sublicensing.
4. Select the integration method (private authenticated service API only, or API plus a separately authorized/distributable SDK).
5. Record a proposed deployment topology and data-residency boundary. Production deployment remains a separate gate.
6. Keep the model-provider default disabled. A fake/local adapter may be used for development and deterministic tests. No live provider may receive private TALORA content until provider, region, retention, training, security, pricing and consent terms are separately approved.
7. Define memory defaults, project scoping, retention, correction, deletion and measurable deletion behavior before enabling persistent project memory.
8. Define Amharic/English evaluation data provenance, reviewer authority and measurable acceptance tests. Do not claim full Amharic capability from script pass-through or partial localization.
9. Define numeric quotas and ETB spend ceilings before enabling any paid inference path.
10. Complete automated verification, exact-HEAD A4 evidence and remediation of critical findings for the implemented integration scope.

### 14.1.1 Read-only component graph reconciliation — 19 November 2026

The IROKA main reference is commit 1aea1447eadf1d827d702fd6c4034fa058aac21e. Its root Cargo workspace currently lists only crates/iroka-kernel as a member. The API endpoints in this document are proposed contracts; the current main workspace does not contain a TALORA-facing service API crate. The main Cargo.toml blob is d64d3143b762589346fb19ee77e6f40d4af8c77c and Cargo.lock blob is ad864ae2b098c1cdea7a81d2d2fc8cdcf9fddf63. The workspace manifest marks the project LicenseRef-Proprietary; README.md separately states that no open-source license is granted by public visibility.

#### A2 contract/document candidates

| Workstream | Branch HEAD | Compare to main | Finding |
|---|---|---|---|
| G05 approved memory contract | architecture/g05-owner-approved-contract-v1 — f032e6583faebb7ad8ef3aab40a5aaad8862fe1c | Diverged; 1 ahead / 3 behind; merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472 | Owner-approved logical contract; implementation not started |
| G05 + G01/G02/G11 amendment | architecture/g05-g01-g02-g11-integration-contracts — 0e8009bee94b321211636656448837a0636232fd | Diverged; 4 ahead / 3 behind; same merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472 | Owner-approved design decisions; canonical organization authority and owning-domain prerequisites remain open |
| G08 orchestration A2 | architecture/g08-orchestration-a2-contract — 04c3bab0ba4de2e634ce28612c90ed7451ef9ceb | Diverged; 3 ahead / 302 behind; merge base 143311a655be68acea2700650b7f88c9fb085526 | A2 draft based on stale lineage; tenant-context and authority dependencies remain unresolved |
| CIW A2 contracts | docs/ciw-a2-integration-contracts — 843e5f1799a54335fa283e71f2d99c806b60a11d | Diverged; 14 ahead / 302 behind; merge base 143311a655be68acea2700650b7f88c9fb085526 | Documentation-only A2 candidate; not a current-main integration baseline |
| G03 Brain A2 contracts | architecture/brain-a1-a2-proposal — 774bc75f751b8e80e6135c349fb78394c02cf4fa | Diverged; 26 ahead / 118 behind; merge base a709fc473b23494839417449e34bebf4cb8be77a | Owner-approved design-only contract; not a merged runtime |
| TALORA contract proposal | docs/talora-iroka-a2-reconciliation-v0.1.1 — 81b04881c5178cbf6902b3c2f290b23a3d8c96be | 6 ahead / 0 behind main | Documentation-only A2 branch; no runtime dependency |

#### Runtime implementation candidates — not adopted

| Domain | Exact candidate branch HEAD | Compare to current main | Dependency/architecture evidence |
|---|---|---|---|
| G01/G02/G11 Kernel A3 candidate | feat/igacms-a3-implementation — bb8b9f0ee81b59e793c30cc5c9a0357d3ed48e4a | 0 ahead / 7 behind; branch is ancestor of main | PR #13 implementation merge is in main lineage; current Kernel API still does not supply the complete TALORA tenant/session/API service boundary |
| G05/G01/G02/G11 reviewer/SQLite candidate | feat/g05-g01-reviewer-proof-integration — 47edea227fdf1dc7b6ac1667b7e7f9cbb5b4cf39 | Diverged; 155 ahead / 3 behind; merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472 | Workspace adds G04/G05 crates; G05 uses rusqlite 0.32.1; branch adds reviewer proof, organization authority and policy lifecycle candidates |
| G05/G11 PostgreSQL multi-worker candidate | feat/g05-postgres-g11-multiworker-a3 — 2bfac619b9601330b3343f86277bb5ba29ae22b2 | Diverged; 334 ahead / 3 behind; same merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472 | Adds PostgreSQL 0.19.12, postgres-native-tls 0.5.0, native-tls 0.2.12 and tokio-postgres 0.7.18 alongside SQLite; separate lockfile/workspace |
| G08 durable coordinator | feat/g08-a3-durable-coordinator — 2cfcf8db9437824cc8181ad8af1e8d819b936e2c | Diverged; 81 ahead / 3 behind; merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472 | G08 modules added to Kernel on a separate branch; not composed with the G05 candidates |
| CIW answer-only chat | feat/ciw-amharic-answer-only-chat — 69f3c181791a8dd3c5baf3d18d4556f8f316b1a1 | Diverged; 172 ahead / 25 behind; merge base 813b24cbf81f049f2675fbb5492bdc9f262a9d87 | Adds iroka-conversation with SQLite and a separate workspace/lockfile; not current-main compatible by ancestry |
| G03 Brain cognitive core | feat/brain-a3-b01-cognitive-core — 9d68b580e06bb8335a626524d64b345c3a5a38aa | Diverged; 10 ahead / 3 behind; merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472 | Adds iroka-brain with serde/serde_json; does not establish a production model gateway or G04/G05/G08 adapters |

Cross-candidate comparisons confirm that these are not one ready-to-compose graph:
- G05 SQLite/reviewer branch versus G05 PostgreSQL branch: DIVERGED, 210 ahead / 31 behind, merge base c57e4298005222ce476f685972062983c78d626f.
- G05 PostgreSQL branch versus G08 A3: DIVERGED, 81 ahead / 334 behind, merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472.
- G05 PostgreSQL branch versus Brain A3: DIVERGED, 10 ahead / 334 behind, same merge base 1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472.
- CIW A3 versus G05 PostgreSQL: DIVERGED, 356 ahead / 172 behind, merge base 813b24cbf81f049f2675fbb5492bdc9f262a9d87.

The lockfiles are not identical across these candidate workspaces. The G05 SQLite candidate's Cargo.lock blob is 8944877dd6d2ac88a21e02c0ce84da9873033909; the G05 PostgreSQL candidate's is e01999aeab00fa657ac4f5d02ec36d4305ad880d; CIW's is c6caa987bb11aa8342bd5dd7981fefb646e0c7ac; Brain's is 5171bde5fd4a34737d20b3d0622f45367cc12025. Some versions overlap, but overlapping crate versions do not prove a compatible workspace, shared API or safe integration.

Additional verified interface gaps:
- The G03 A2 contract assigns reasoning/planning to G03 and requires authoritative G01 tenant context and G02 policy context; it is design-only and does not establish a running G03 service.
- The inspected Kernel request contract does not itself supply tenant membership, conversation ACLs or a signed/persisted policy lifecycle. Caller-supplied tenant identifiers are not authority.
- The G05/G01/G02/G11 amendment identifies the canonical organization-authority source and organization-scoped reviewer delegation as unresolved. G05 must fail closed until those owning-domain interfaces are approved and available.
- G08 A2 draft records a missing authoritative tenant resolver and stale Kernel lineage.
- CIW A2 contract records that the public Kernel API does not supply tenant membership, session lifecycle, conversation persistence or streaming.
- G04 executable retrieval API and G06 perception integration were not verified in the inspected Brain A2 report.

**D01 outcome:** RECONCILIATION PERFORMED; NO COMPATIBLE IMMUTABLE GRAPH SELECTED. Do not compose these branches by branch-name convention, cherry-pick, merge or assume compatible dependency versions. Further read-only exact-commit/API/dependency verification and a new Owner-reviewed baseline proposal are required. This is not A3 permission.

### 14.1.2 Exact-HEAD CI evidence

The following GitHub Actions runs were retrieved against the exact candidate HEADs. All listed runs completed with conclusion SUCCESS. The job performed formatting, compilation, the complete unit/contract test suite, production-feature exclusion checks and Clippy; CIW additionally checked browser JavaScript syntax and patch whitespace.

| Candidate HEAD | Workflow run | Result |
|---|---:|---|
| Kernel A3 `bb8b9f0ee81b59e793c30cc5c9a0357d3ed48e4a` | [42566869592](https://github.com/akefadaka-git/iroka/actions/runs/42566869592) | PASS |
| G05 reviewer/SQLite `47edea227fdf1dc7b6ac1667b7e7f9cbb5b4cf39` | [42957299023](https://github.com/akefadaka-git/iroka/actions/runs/42957299023) | PASS |
| G05 PostgreSQL/G11 `2bfac619b9601330b3343f86277bb5ba29ae22b2` | [43240878046](https://github.com/akefadaka-git/iroka/actions/runs/43240878046), [43240392654](https://github.com/akefadaka-git/iroka/actions/runs/43240392654) | PASS / PASS |
| G08 coordinator `2cfcf8db9437824cc8181ad8af1e8d819b936e2c` | [43230367894](https://github.com/akefadaka-git/iroka/actions/runs/43230367894) | PASS |
| CIW answer-only `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | [42562324737](https://github.com/akefadaka-git/iroka/actions/runs/42562324737) | PASS |
| Brain core `9d68b580e06bb8335a626524d64b345c3a5a38aa` | [42576912231](https://github.com/akefadaka-git/iroka/actions/runs/42576912231) | PASS |

These results prove only that each candidate passed its own branch-specific workflow at that exact commit. They do not prove that separate candidates can be composed, that their APIs/traits and tenant/policy/memory/audit contracts agree, that the combined workspace resolves, or that an integrated TALORA service API exists. No combined-graph workflow run was found or executed. The A4 exact-integrated-head verification remains NOT RUN.

## 14.2 Independent assessment and deployment gate

Owner direction `OD-2026-11-17-IR-01` governs independent-review timing. One integrated independent security and architecture assessment is deferred until implementation and A4 evidence reconciliation are complete, and must occur before any A5 deployment authorization or production release. It is not a per-PR or per-component implementation gate.

That assessment must cover identity and trust lifecycle, Owner authority, memory privacy and deletion, orchestration and execution isolation, supply-chain provenance, audit integrity, backup/restore/rollback, adversarial testing, localization, deployment configuration and residual risk.

No branch merge, deployment, provider activation, production key provisioning or production data use is authorized by this document. A5 remains a separate Owner decision.

## 14.4 Implementation-level component reconciliation — 19 November 2026

This section supersedes earlier runtime-graph assumptions in the
preceding design-branch reconciliation. All SHAs below were resolved
against live named refs on 19 November 2026.

| Workstream | Exact branch head | Main comparison / observed facts | Reconciliation finding |
|---|---|---|---|
| IROKA main | `main` — `1aea1447eadf1d827d702fd6c4034fa058aac21e` | Cargo workspace contains only `crates/iroka-kernel`; Rust 1.75. | Reference only; not approved baseline. |
| G03/G08 kernel | `implementation/a3-g08-workflow-graph` — `0680337b7dd0966374acd2649cd9197e56b8d92a` | 378 ahead / 3 behind main; Rust 1.75; exports G03 inference, premise, uncertainty and G08 workflow modules. Three G03 refs are ancestors (58, 73 and 41 commits). | Best inspected single G03/G08 kernel subset; not integrated with G05/G02/G11 or localization. No exact-head PR run returned. |
| G08 character workflow | `implementation/a3-g08-character-workflow-graph` — `0dbe0d58f312ef5ddf2be5d3f6b7dde6569d566b` | Rust 1.89.0; toolchain 1.100.0. | Separate divergent workflow line and MSRV break against Rust 1.75 baseline. |
| G05/G02/G11 | `feat/g11-provider-adapters-a3-rebased` — `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810` | 391 ahead / 3 behind main; kernel + `iroka-g05-memory`, Rust 1.75. G05 pins PostgreSQL 0.19.12, postgres-native-tls 0.5.0, native-tls 0.2.12, rusqlite 0.32.1, serde_jcs 0.2.0 and ed25519-dalek 2.1.1; lockfile has 154 packages including tokio-postgres/TLS. | Best G05/G02/G11 persistence/authority/checkpoint subset. Descends from G05 HTTP by 13 commits and G05 Postgres/multiworker by 57. No exact-head PR run returned. |
| G05 HTTP predecessor | `feat/g05-http-host-a3` — `c8991fc61170bc04d7aeaea390a76a85900c2232` | Run 43280580981 succeeded. Loopback-only behind TLS proxy; endpoint `/v1/g05/execute`. | Older predecessor; not TALORA task API. |
| G05 Postgres predecessor | `feat/g05-postgres-g11-multiworker-a3` — `2bfac619b9601330b3343f86277bb5ba29ae22b2` | Runs 43240878046 and 43240392654 succeeded. | Older predecessor; does not verify later G11 provider head. |
| CIW | `feat/ciw-amharic-answer-only-chat` — `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | 172 ahead / 25 behind main; adds `iroka-conversation` and browser routes. Exact-head run 42562324737 succeeded. | Browser/conversation API candidate, not verified private TALORA task API; diverges from G05/G11 (400 / 172 commits). |
| BRAIN/G04/G05 | `feat/brain-a3-b04-g05-memory-core` — `b27816c1c3b172c0a7503d6602cddeaa6008c6cb` | 163 ahead / 3 behind main; kernel + G04 contract + SQLite G05. | Older implementation line; shared kernel changes; no exact-head PR run returned. |
| BRAIN cognitive core | `feat/inga-neurogenetic-a3-foundation` — `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d` | 27 ahead / 3 behind main; `iroka-brain` depends on serde/serde_json. | Separate model-independent cognitive-core candidate. |
| Localization | `feat/a3-4-localization-completion` — `d51a971d295e7b75e3d17fc51202d99c1db1abab` | 59 ahead / 3 behind main; adds localization module/tests; diverges from G03/G08 (378 / 59 commits). | Separate kernel line; no exact-head PR run returned. |

### 14.4.1 Compatibility conclusions

1. G03/G08 and G05/G02/G11 are diverged histories: 378 commits on
   the G03/G08 side and 391 on the G05/G11 side. Both modify shared
   Kernel files, including `lib.rs`, identity/security, authority and
   policy modules. This is not a safe fast-forward or simple
   workspace-member addition.
2. CIW also changes Kernel identity/security code and is independently
   diverged from G05/G11. It cannot be combined by branch-name
   convention or cherry-picked without source-level reconciliation.
3. Localization and BRAIN are separate kernel/workspace lines.
4. G08 character workflow declares Rust 1.89.0/toolchain 1.100.0,
   while main and G05/G11 declare Rust 1.75.
5. G05/G11 adds PostgreSQL, tokio and TLS dependency families. They
   are pinned on that branch, but no merged lockfile or combined
   `cargo check/test` was run.
6. G11 HTTPS is checkpoint publication, not model inference. No
   `ModelAdapter`/`DeterministicFakeAdapter` implementation was
   verified on the exact inspected refs.
7. G05 exposes only `/v1/g05/execute`; CIW exposes conversation and
   generation/event routes. Neither establishes the contract's complete
   `GET /api/v1/capabilities`, `POST /api/v1/tasks`, task
   status/events/cancel and memory API as one private TALORA service.

### 14.4.2 Exact-head verification

| Exact candidate head | Workflow evidence | Result |
|---|---|---|
| CIW `69f3c181...` | 42562324737 — completed, success | PASS for isolated CIW head only |
| G05 HTTP `c8991fc6...` | 43280580981 — completed, success | PASS for predecessor only |
| G05 Postgres `2bfac619...` | 43240878046 and 43240392654 — completed, success | PASS for predecessor only |
| G08 coordinator `2cfcf8db...` | 43230367894 — completed, success; commit changes workflow triggers | Not evidence for G08 implementation head |
| G11 provider `8f7ddb9e...` | No PR-triggered run returned | NOT VERIFIED at current exact head |
| G03/G08 `0680337b...` | No PR-triggered run returned | NOT VERIFIED at current exact head |
| BRAIN/G05 `b27816c1...` | No PR-triggered run returned | NOT VERIFIED at current exact head |
| Localization `d51a971d...` | No PR-triggered run returned | NOT VERIFIED at current exact head |

The workflow lookup returns PR-triggered runs and the first page only.
An empty result does not prove no historical or push-triggered run
exists. No combined graph build, test, migration, SBOM or end-to-end
API run was performed.

**D01 outcome:** RECONCILIATION PERFORMED; NO COMPATIBLE IMMUTABLE GRAPH
SELECTED. No current-main or candidate branch is approved as the
integration baseline. This is not A3 permission.

## 15. Owner dispositions — 19 November 2026

The Owner submitted and approved the following exact dispositions. They are binding design constraints, not A3, merge or deployment authorization.

| ID | Owner disposition | Binding contract effect |
|---|---|---|
| D01 | RECONCILE | Do not adopt current main or any candidate branch automatically. Reconcile exact component commits, dependencies, ancestry and verification before selecting one immutable graph. No compatible graph is established by this assessment. |
| D02 | API | Private authenticated service API is the only initial integration method. No distributable SDK. |
| D03 | API_ONLY | API/service integration only. No source copying, vendoring, modification, redistribution, sublicensing or SDK packaging. |
| D04 | DEV_FIRST | Development/test profile first. No production topology, production creative data or data-residency claim until separately reviewed. |
| D05 | FAKE_LOCAL | Deterministic fake/local model adapter is the required initial mode; no exact inspected ref verifies it as implemented. Live external providers remain disabled. |
| D06 | HARD_CAPS | Hard preflight limits and ETB ceilings; no silent overrun, auto-top-up or paid provider activation without numeric Owner-approved budgets. Until budgets are approved, external paid spend is zero and paid calls are disabled. |
| D07 | OPTIN | Task context ephemeral by default; persistent project memory requires explicit opt-in, project scope, correction/deletion and retention controls. |
| D08 | REVIEWED | Amharic-first remains binding. Full-workflow claims require rights-cleared/reviewed corpora, competent reviewers and measurable acceptance tests. |
| D09 | MEASURE_FIRST | No production SLO or support commitment until topology and operational performance are measured and operating ownership is defined. |

The companion decision register is versioned separately. The D01 result and graph findings are recorded in §14.3 and the TALORA A2 closure assessment.

## 16. Acceptance criteria and status distinctions

### 16.1 Contract/design approval

- Versioned API and JSON schemas are specified and validate positive and negative fixtures.
- Authentication, authorization, tenant/project scoping, stale-revision handling, consent and memory boundaries are specified.
- Idempotency, cancellation, replay, retry, timeout and provider-outage semantics are specified.
- AI tasks cannot mutate TALORA documents without explicit user acceptance.
- Results specify provenance, uncertainty, attribution and usage/cost fields.
- Amharic/English locale behavior and Ethiopic preservation requirements are specified.
- Memory consent, project scoping, correction, deletion and audit requirements are specified.
- Cost quotas, ETB reporting, spend circuit breakers and no-top-up behavior are specified.
- Dependency licensing, cross-project rights and A3/A4/A5 gate separation are explicitly recorded.

### 16.2 Implementation verification (A4)

These design criteria do not prove implementation. A4 must validate implemented API/schema, authentication and tenant isolation, idempotency/cancellation, patch approval, provenance, localization, memory controls, cost enforcement, dependency/SBOM evidence and exact-commit test results. Every result must be labelled PASS, FAIL, BLOCKED or NOT RUN and tied to an exact commit and reproducible evidence.

### 16.3 Production authorization (A5)

Before A5, the integrated independent security/architecture assessment required by `OD-2026-11-17-IR-01` must be complete, findings remediated or explicitly risk-accepted, and the Owner must separately authorize deployment. Contract approval or A4 completion does not authorize A5.

**Current disposition:** Contract v0.1.2 aligns with all nine Owner dispositions dated 19 November 2026 and records the live component evidence. D01 reconciliation has been performed, but no single compatible immutable IROKA component graph was found; the integration baseline remains UNRESOLVED. The full TALORA API and deterministic model adapter are not verified. This is an A2 design artifact only. TALORA–IROKA A2 integration readiness is PARTIAL / NOT CLOSED. A3 implementation, merge and A5 deployment remain separate Owner decisions.
