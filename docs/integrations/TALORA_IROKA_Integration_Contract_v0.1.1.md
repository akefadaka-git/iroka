# TALORA--IROKA Integration Contract

**Document ID:** TALORA-IROKA-IC-001\
**Version:** 0.1.1\
**Status:** Reconciled A2 proposal; Owner decisions remain open; not implementation authorization\
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

The inspected G03 branch currently contains a `ModelAdapter` abstraction
and a `DeterministicFakeAdapter`. The fake adapter generates synthetic
fixture text and makes no provider/network call. It is suitable for
contract tests, not production inference. No live production model
provider was verified in the reconciled branch set.

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

G05 branch candidates provide SQLite and PostgreSQL repository
implementations and authority-oriented adapters, but the inspected work
is on divergent branches and is not integrated into `main`. The threat
model and authority contracts require independent verification before
production use.

## 8. Identity, authentication and authorization

-   TALORA backend authenticates the user and enforces its own
    organization/project/document roles before task submission.
-   Backend-to-backend IROKA calls MUST use short-lived,
    audience-restricted workload credentials and mutual TLS where
    supported. Mobile clients MUST never call privileged IROKA endpoints
    directly.
-   The current CIW HTTP candidate uses G01 Ed25519 credentials in
    Secure, HttpOnly, host-only cookies and delegates tenant membership,
    session checks and Kernel authorization to trusted adapters. It is a
    browser-oriented candidate, not a completed TALORA mobile
    authentication design.
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
3. Verify dependency licenses and internal cross-project reuse rights. IROKA is publicly visible but states `LicenseRef-Proprietary`; public visibility does not grant a license. Do not copy, package, modify or redistribute IROKA source unless explicit written authorization permits it.
4. Select the integration method (private authenticated service API only, or API plus a separately authorized/distributable SDK).
5. Record a proposed deployment topology and data-residency boundary. Production deployment remains a separate gate.
6. Keep the model-provider default disabled. A fake/local adapter may be used for development and deterministic tests. No live provider may receive private TALORA content until provider, region, retention, training, security, pricing and consent terms are separately approved.
7. Define memory defaults, project scoping, retention, correction, deletion and measurable deletion behavior before enabling persistent project memory.
8. Define Amharic/English evaluation data provenance, reviewer authority and measurable acceptance tests. Do not claim full Amharic capability from script pass-through or partial localization.
9. Define numeric quotas and ETB spend ceilings before enabling any paid inference path.
10. Complete automated verification, exact-HEAD A4 evidence and remediation of critical findings for the implemented integration scope.

### 14.2 Independent assessment and deployment gate

Owner direction `OD-2026-11-17-IR-01` governs independent-review timing. One integrated independent security and architecture assessment is deferred until implementation and A4 evidence reconciliation are complete, and must occur before any A5 deployment authorization or production release. It is not a per-PR or per-component implementation gate.

That assessment must cover identity and trust lifecycle, Owner authority, memory privacy and deletion, orchestration and execution isolation, supply-chain provenance, audit integrity, backup/restore/rollback, adversarial testing, localization, deployment configuration and residual risk.

No branch merge, deployment, provider activation, production key provisioning or production data use is authorized by this document. A5 remains a separate Owner decision.

## 15. A2 decision register

The companion document `TALORA-IROKA-A2-DECISION-REGISTER-v0.1.0.md` tracks the following unresolved decisions. Recommendations are not approvals:

- **D01 — Integration baseline:** exact IROKA commit and compatible component dependency graph.
- **D02 — Integration method:** private service API only, or API plus separately authorized SDK.
- **D03 — Cross-project rights:** explicit proprietary integration/source-reuse authorization and boundaries.
- **D04 — Deployment and residency:** supported topology, hosting region, data residency and operational owner.
- **D05 — Model provider:** provider strategy, or continued fake/local-only operation; private-content transmission remains disabled absent explicit approval.
- **D06 — Cost controls:** Free/Premium/organization quotas, provider rates, ETB conversion source and hard spend ceilings.
- **D07 — Memory governance:** opt-in defaults, scope, retention, correction, deletion and deletion SLAs.
- **D08 — Amharic/English assurance:** corpus rights/provenance, reviewer authority, evaluation thresholds and supported-workflow claims.
- **D09 — SLO and support:** target SLOs, incident response, support obligations and service ownership.

Each decision requires an explicit Owner disposition (APPROVE, AMEND, DEFER or REJECT) in the companion register. A deferred decision must have a defined boundary and block only the dependent capability or work package. No blank field or recommendation is approval.

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

**Current disposition:** Reconciled A2 proposal v0.1.1. D01–D09 remain pending Owner disposition. A2 closure, A3 implementation, merge and A5 deployment remain separate decisions.
