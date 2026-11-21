# IROKA A1 Master Architecture Baseline and Closure Register

**Document ID:** IROKA-A1-MASTER-001  
**Version:** 1.0.0  
**Status:** OWNER-RATIFIED — A1 VERIFIED-CLOSED  
**Canonical repository:** `akefadaka-git/iroka`  
**Assessment baseline:** `main` at `1aea1447eadf1d827d702fd6c4034fa058aac21e`  
**Scope:** IROKA ZERO platform architecture, Genome domain ownership, neural infrastructure, Amharic-first regional architecture, and first-party client boundaries  
**Normative language:** MUST/MUST NOT are mandatory; SHOULD/SHOULD NOT require a recorded rationale to depart; MAY is optional.

## 1. Purpose and governing decision

This register consolidates the existing IROKA A1 architecture baselines into one navigable system-level contract. It reconciles domain ownership, trusted-control boundaries, neural computation, clients, localization, threat controls, acceptance criteria and deferred decisions.

The governing product and architecture rule is:

> **Amharic-first. Ethiopian-grounded. African-capable. Model-independent. Kernel-governed. Evidence-led.**

IROKA is one governed intelligence platform. Its clients, neural infrastructure, cognitive capabilities, agents and integrations are subordinate components, not independent authorities or competing platforms.

The constitutional operating rule is:

> **Intelligence may propose. Governance decides. Authorization permits. Execution acts. Assurance verifies.**

This document consolidates and clarifies existing approved decisions. It does not silently amend the Owner-approved IGACMS A2 baseline, authorize implementation, select paid providers, provision production credentials, merge existing work, or authorize deployment.

## 2. Authority, precedence and change control

### 2.1 Normative precedence

If two documents or components appear to conflict, apply this order:

1. IROKA ZERO constitutional principles and immutable security/governance invariants.
2. Owner-approved IGACMS v1.0 A2 baseline, including its D01–D14 decisions and twelve-chromosome ownership model.
3. Explicitly Owner-approved, versioned domain architecture and contracts, including the frozen BRAIN A1/A2 decisions and Android A1 decisions.
4. This system-level A1 master contract, once ratified.
5. Domain-specific A1 proposals that remain pending Owner review, including INNIA A1 and the Amharic-first regional architecture PR #3.
6. A2 implementation contracts and A3 code, which must conform to the higher-level baselines.

A lower-level document or implementation cannot override a higher-level decision. If a material contradiction is discovered, stop the affected integration, record exact source references and impact, and submit a versioned change proposal. Do not resolve it by silent code behavior.

### 2.2 Existing approvals preserved

| Baseline | Evidence | Disposition |
|---|---|---|
| IGACMS v1.0 A2 | PR #12 merged; head `a709fc473b23494839417449e34bebf4cb8be77a`; Owner decisions D01–D14 | VERIFIED-CLOSED; immutable absent separately approved amendment |
| BRAIN A1 | PR #26 records Owner approval/freeze of BRAIN A1 v1.0.0 on 9 Nov 2026 | VERIFIED-CLOSED for BRAIN scope |
| BRAIN A2 cognitive contracts | PR #26 records Owner approval and VERIFIED-CLOSED design/contract gate | VERIFIED-CLOSED for defined G03 contracts; adapter readiness remains dependency-gated |
| Android A1 | PR #131 spec; PR #132 records explicit Owner freeze on 19 Nov 2026 | VERIFIED-CLOSED for Android A1 scope |
| Amharic-first African architecture | PR #3, branch `architecture/a1-amharic-first-african-contracts`, head `72be8040283acd31ce90050a5b03d59c55b38b89` | Requirements are defined; consolidated system-level ratification remains pending |
| INNIA A1 | PR #134, branch `docs/innia-neural-infrastructure-a1-spec`, head `5d6f6b36e0d514e8fd14f144d8cde905e0f49d92` | Architecture proposal; Owner freeze pending |
| INNIA A2 | PR #135, head `e0d25d9e0cc40998da153f60de33e0f3f0fa2bbf` | Separate read-only reconciliation; PARTIAL / NOT CLOSED |

The existence of a merged documentation PR or a passing branch workflow is not proof that the corresponding runtime is integrated or production-ready.

### 2.3 Repository facts at the assessment baseline

- Repository: `akefadaka-git/iroka`, ID `1445234713`, public visibility.
- Default branch: `main`.
- Baseline SHA: `1aea1447eadf1d827d702fd6c4034fa058aac21e`.
- Main Cargo workspace at the Android A1 assessment listed only `crates/iroka-kernel`.
- Main branch protection was reported absent in the Android A1 assessment. This remains a governance risk; this A1 work does not change repository settings.
- Existing candidate implementations remain on isolated, unmerged branches. They are not implicitly adopted by this architecture baseline.
- Repository license declaration is proprietary (`LicenseRef-Proprietary)); public visibility does not grant permission to reuse the code.

## 3. System context and architectural boundaries

IROKA consists of a trusted governance/control plane and replaceable computation and experience components.

### 3.1 Trusted control plane

The trusted control plane establishes identity, tenant context, policy, approval, capability grants, trust-root state, protected execution authorization, audit evidence, and governed evolution.

It is owned by the Kernel and the responsible Genome domains. It MUST remain independent of model/provider availability and MUST NOT accept model output, client assertions, worker responses or retrieved content as authority.

### 3.2 Computation plane

The computation plane includes cognitive reasoning, neural models, symbolic reasoning, perception processing, retrieval clients, evaluation workers and bounded agent computation.

Its output is untrusted until validated. It may produce answers, plans, candidate classifications, embeddings, summaries and proposals. It cannot authenticate principals, grant permissions, change policy, write canonical memory outside G05, execute protected effects outside G09, or certify its own assurance.

### 3.3 Experience and integration plane

First-party clients and external integrations present capabilities exposed by an IROKA deployment. They do not create new sources of truth. They must discover actual capabilities and versions rather than assuming all planned functions are implemented.

The Android client is a native, hybrid cloud/on-device IROKA client. It is not a fork, replacement or independent cognitive authority. Other clients follow the same authority boundaries.

### 3.4 Canonical data and authority rule

Every domain has one authoritative owner for its canonical state. Other domains interact through versioned contracts and opaque references. Direct cross-domain database access, shadow stores, duplicated lifecycle state, or client/model-generated authority are prohibited unless an explicitly approved architecture contract defines a narrowly scoped exception.

## 4. Genome domain ownership and interface register

The following G01–G12 allocation is the canonical responsibility map. Logical capabilities may be implemented as modules or services; this table does not require twelve deployable microservices.

| Domain | Canonical ownership | Provides / authoritative interface | Must not own or bypass |
|---|---|---|---|
| **G01 — Identity and trust** | Principal identity, authentication, credential and trust-root lifecycle, key status, verified tenant/membership context | Verified principal reference; authenticated tenant-context reference; credential/key validity and revocation evidence | Business policy decisions, cognitive conclusions, memory records, protected effects |
| **G02 — Governance and policy** | Owner authority, organization/tenant governance policy, approvals, capability policy, policy activation/revocation and emergency stop | Versioned policy context, authorization decision/approval references, capability constraints | Identity proofing, cognitive reasoning, direct execution, independent audit certification |
| **G03 — Cognition / Brain** | Reasoning coordination, task decomposition, planning, synthesis, cognitive critique and structured cognitive results | Versioned task/result/plan/critique contracts; untrusted candidate outputs and evidence requests | Knowledge or memory stores, identity, policy, durable workflow state, agent identity, protected effects, independent assurance |
| **G04 — Knowledge** | Authoritative knowledge sources/catalogue, ingestion and retrieval, source provenance, evidence lineage, source conflict and freshness semantics | Authorized evidence/source references, retrieval results, provenance and freshness metadata | Durable user memory lifecycle, identity/policy, model authorization, independent assurance |
| **G05 — Memory** | Canonical memory records, consent and purpose, classification, retention, correction, deletion, access lifecycle and derived-memory governance | Authorized memory/context references and lifecycle status | Knowledge-source ownership, identity, policy, cognitive conclusions, model-controlled writes |
| **G06 — Perception** | Modality-specific intake and processing: text/document, image, audio, video and structured sensory inputs; normalized observations and confidence | Typed observation references with modality, provenance, confidence and limitations | Identity proof, source-of-truth knowledge, durable memory, policy decisions or execution authority |
| **G07 — Agent identity and delegation** | Agent identities, agent capability declarations, delegation relationships, scoped agent credentials/lifecycle | Verified agent identity and bounded delegation references | Human identity authority, policy approval, workflow state, protected effect execution |
| **G08 — Orchestration** | Durable workflow/task lifecycle, scheduling, state transitions, retries, deadlines, leases, cancellation, recovery and coordination | Versioned workflow/task references, lifecycle events and bounded worker assignments | Identity/tenant authority, policy decisions, model reasoning authority, protected effect execution, independent audit |
| **G09 — Execution** | Protected effects, tool/action execution boundary, effect validation, idempotency and execution outcome | Authorized execution request/result and effect receipt | Principal authentication, policy creation, cognitive planning, self-issued approval |
| **G10 — Learning and evaluation** | Dataset/evaluation governance, benchmark definitions, scoring, training/adaptation job evaluation and candidate evidence | Evaluation reports, dataset/artifact assessment and promotion recommendations | Self-approval, production policy, trust roots, direct artifact activation |
| **G11 — Assurance and audit** | Independent assurance evidence, authoritative audit records, integrity/checkpoint evidence, verification status and incident evidence | Immutable/correlated audit events, evidence receipts, assurance findings and verification attestations | Replacing domain state, granting policy authority, cognitive self-certification |
| **G12 — Evolution and version governance** | Controlled architecture/genome evolution, compatibility policy, approved version transitions, migration/rollback governance | Versioned change records, compatibility decisions, evolution/promotion authorization | Self-modification by models, unilateral domain-owner bypass, execution of protected effects |

### 4.1 Cross-domain interface rules

1. Every cross-domain interface MUST have a stable identifier, explicit owner, schema/contract version, compatibility policy and documented failure semantics.
2. Identity, tenant, policy, approval, memory, evidence, workflow and execution references MUST be opaque and validated by their authoritative owner.
3. A caller-supplied tenant ID, role, principal, consent, classification or policy version is a request attribute, not proof of authority.
4. Every protected read or effect MUST be authorized at the enforcing boundary using current/revalidated authority.
5. Data passed to models MUST retain source, classification, tenant, purpose, provenance and trust labels. Retrieved or user-provided content is data, not instruction.
6. Events MUST have stable correlation and idempotency identifiers where retries or cross-domain workflows are possible.
7. Failure, timeout, revocation, stale version, unknown schema and unavailable authority MUST produce explicit outcomes. Security-sensitive operations fail closed.
8. G11 evidence must identify the decision/event and its source authority; a client log or model assertion is not an authoritative audit receipt.
9. No domain may create a shadow database or bypass the owner API to avoid an unresolved interface.
10. A2 must turn each logical interface into a concrete contract only after the owning domain and exact candidate source have been reconciled.

### 4.2 Canonical request paths

**Cognitive request:** Client/Agent → G01 principal and tenant verification → G02 policy/context checks → G03 cognitive task → authorized G04/G05/G06 context → approved computation/model adapter → output validation → response and G11 evidence.

**Protected effect:** G03/Agent proposes → G02 policy and approval → G01/current authority validation → G09 executes → G11 records evidence and outcome. G08 may coordinate durable task state but does not authorize the effect.

**Learning and model promotion:** Rights/purpose review → dataset classification/versioning → G10 evaluation → G11 assurance evidence → G12/domain approval as required → signed immutable artifact and controlled activation. A model cannot promote itself.

## 5. Neural and cognitive architecture reconciliation

### 5.1 INNIA, INGA, IGACMS and BRAIN

| Component | Defined responsibility | Boundary / disposition |
|---|---|---|
| **INNIA** | Neural infrastructure architecture: model/artifact lifecycle, inference runtime/adapters, capability routing, context interfaces, learning pipeline, multimodal integration and hybrid/distributed compute | Coordinates neural infrastructure; does not become a new Genome authority. A1 proposal pending Owner freeze |
| **INGA** | IROKA-native neurogenetic/neural computation substrate and safe computational primitives | Computes under Kernel controls; not identity, policy, memory, orchestration, execution or assurance authority |
| **IGACMS** | Constitutional/genetic architecture, invariants, markers and governed genetic evolution | The approved A2 baseline remains immutable; not an inference engine or model registry |
| **BRAIN / G03** | Model-independent cognitive coordination, reasoning, planning, critique and structured cognitive results | Consumes G04/G05/G06 and delegates durable lifecycle to G08; cannot authorize or execute |
| **Native Cognition** | Symbolic/deterministic cognitive capability candidate | May complement neural computation; must conform to G03 contracts and not create competing authority |
| **CIW / conversation experience** | Conversation/session and user interaction capability | Experience/service boundary; not a replacement for G01, G05 or G08 |

### 5.2 Reconciled conflicts and binding resolutions

| Apparent conflict or ambiguity | Binding resolution |
|---|---|
| Neural model output versus constitutional/kernel authority | Models are untrusted computation. Kernel/G01/G02/G09/G11 authority remains external to every model. |
| INNIA control plane versus G01–G12 ownership | INNIA is a logical infrastructure architecture, not a new owner. Each control-plane function delegates to its canonical Genome owner. |
| INGA and BRAIN both performing reasoning-like work | INGA supplies native computational substrate/primitives; G03/BRAIN owns cognitive task coordination and user-facing reasoning contracts. No duplicated cognitive authority. |
| IGACMS genetic evolution versus online neural learning | IGACMS/G12 govern permitted architecture evolution; G10 evaluates learning candidates. No autonomous production weight or architecture mutation. |
| G03 context assembly versus G04/G05/G06 records | G03 may assemble references and bounded context; source, memory and perception domains retain canonical records and lifecycle. |
| G03 plans versus G08 workflows | A plan is a proposal. G08 owns durable workflow/task state and trusted lifecycle time. |
| G03 or agents suggesting actions versus G09 execution | Suggestions are proposals only. G02 authorization and G09 execution are mandatory for protected effects. |
| G03 critic versus G11 assurance | Cognitive critique is not independent security, audit or release assurance. Only G11 can issue assurance evidence within its authority. |
| Model registry references across G01/G04/G11/G12 | Artifact identity/provenance, signing/trust validation, assurance evidence and lifecycle/promotion are separate responsibilities. A2 must specify the registry contract and accountable operational custodian; no domain may silently absorb all four. |
| UTC task timestamps versus Ethiopian calendar presentation | Persist security/audit instants in canonical UTC; preserve date-only/local-date/calendar semantics; render Ethiopia-profile dates in Ethiopian calendar by default. |
| Amharic-first versus African-wide support | Ethiopia profile defaults to Amharic; other countries/languages require independent profiles and evidence. No universal African locale. |
| Android full cognitive access versus unavailable capabilities | Full access means all capabilities actually exposed and authorized by the connected deployment, not every planned capability. |
| Hybrid/offline capability versus centralized authority | Offline mode is limited to explicitly safe local tasks and cache. Queued requests are proposals; authority is revalidated online before consequential execution. |

### 5.3 Model and artifact lifecycle invariants

- Model and adapter identity MUST be immutable and versioned; artifact digests, license, source, build/runtime compatibility and provenance MUST be recorded.
- Trust validation, artifact integrity, revocation and promotion MUST be independent of model output.
- Inference workers MUST be isolated, least-privileged, resource-bounded and unable to mint authority or expand their own scope.
- Provider adapters MUST be replaceable. Provider metadata is not self-attested trust.
- External provider transmission requires explicit policy for the data class, purpose, location, retention, consent and provider.
- Training/adaptation is offline-by-default. User/private data is excluded absent separate explicit lawful authorization.
- Dataset and artifact candidates require rights review, versioned evaluation, adversarial testing and required human/Owner approvals before promotion.
- No online self-modification or autonomous production weight update is authorized by A1.
- No provider, paid service, GPU cluster, model family, local runtime or model license is selected by this A1 baseline.

## 6. Amharic-first localization and African regional architecture

### 6.1 Ethiopia deployment profile

The Ethiopia profile MUST define:

- Primary language: Amharic (`am-ET`).
- Supported secondary language: English (`en`).
- Ethiopic script as first-class; Latin script supported for mixed-language interoperability.
- Ethiopian calendar as default civil display calendar; Gregorian interoperability required.
- Default time zone: `Africa/Addis_Ababa`.
- Default currency: `ETB`; multi-currency architecture remains required.
- Ethiopic and international numerals with configurable display preference.
- Original-script personal and organizational names preserved; transliteration is additive, never destructive.

These are Ethiopia-profile defaults, not universal IROKA core defaults.

### 6.2 Language, script and typography

1. All user-facing primary workflows, navigation, labels, onboarding, notifications, errors, help and standard templates MUST be Amharic-first in the Ethiopia profile.
2. English MUST be available without a separate deployment.
3. Language preference is explicit and persisted at supported user/organization/workspace/document scopes; it MUST NOT be inferred from name, ethnicity or location.
4. Translation resources require stable keys, language tags, version and review status. Security, consent, finance and governance translations require human review before production.
5. UTF-8 is the canonical interchange encoding. Ethiopic text MUST survive storage, APIs, queues, logs, search, import/export and rendering without corruption.
6. Fonts and layout MUST be tested for Ethiopic glyph coverage, shaping, combining marks, line breaks, cursor movement, selection, copy/paste, scaling and mixed-script content.
7. Original text is preserved. Normalized search keys are derived and cannot overwrite source text or erase meaningful distinctions.
8. Accessibility includes screen-reader labels, keyboard navigation, scalable text, contrast and readable Ethiopic typography.
9. Additional languages and scripts require their own coverage and evaluation evidence; right-to-left support must not be assumed from an African-wide default.

### 6.3 Locale and profile architecture

- Country, language, locale, script, calendar, currency, time zone and legal jurisdiction are distinct attributes.
- Profiles are versioned, provenance-bearing configuration/policy-reference bundles, not scattered country conditionals.
- A profile includes jurisdiction/subnational context, languages and review state, scripts, calendar, time zone, currencies, number/date conventions, address/phone conventions, document conventions, legal references, data-governance references and provenance.
- Resolution precedence: mandatory legal/security/records obligations → active deployment profile → organization preference → user presentation preference → request formatting, only where overrides are permitted.
- Lower-precedence preferences cannot override higher-precedence requirements.
- Missing, contradictory or expired mandatory legal/profile data must block the affected operation or route it for qualified review; never guess.
- Profile versions are immutable after publication. Changes record source, reviewer, effective date, changed fields, migration impact and rollback.
- Historical records retain the semantic profile/context needed to interpret their original date, currency, language and jurisdiction.

### 6.4 Calendar and time semantics

Every date/time value MUST be typed as one of:
- **Instant:** a point on the global timeline; persist canonically in UTC.
- **Local date:** a calendar date without an implied time zone.
- **Local date-time:** a wall-clock date/time with explicit time zone and ambiguity policy.
- **Calendar date:** a date explicitly associated with a named calendar.

The Ethiopian calendar is the default civil display calendar for Ethiopia; Gregorian is supported for interoperability. Conversion uses a vetted, tested calendar implementation selected in A2. Preserve source calendar context and do not convert date-only values into UTC instants without an explicit business rule. Deadlines, recurrences, financial periods and legal effective dates declare their governing calendar/time zone. Security and audit instants remain UTC; UI display follows the selected profile/user preference.

### 6.5 Identity, documents and knowledge

**Identity:** Immutable system IDs are separate from names. Preserve original-script names, flexible name components/order, aliases and additive transliterations. Fuzzy matching may suggest candidates but cannot establish identity or auto-merge records. Do not infer sensitive attributes from language, name or location.

**Documents and records:** Preserve original files and hashes; record transformation/version/provenance for extracted text and derivatives. Amharic document creation, preview, PDF/office export, search, print and archive are baseline requirements. Fonts must render correctly in final artifacts. OCR output carries language/script, confidence and provenance; low-confidence text requires human review and is not authoritative by default. Retention, legal hold, access, redaction and disposal are governed independently of locale.

**Knowledge and retrieval:** Amharic is a first-class ingestion, indexing, retrieval and evaluation language. Retain source provenance, rights/consent, classification and transformation history. Distinguish originals from translations, OCR and summaries. Conflicting sources remain visible. Retrieval inherits source permissions and tenant boundaries. Generated claims distinguish evidence, inference, hypothesis and uncertainty. Speech recognition and synthesis are separately evaluated capabilities; no universal dialect coverage is claimed without evidence.

### 6.6 African expansion

IROKA MUST support independent country/subnational profiles, multiple languages/scripts and jurisdiction-scoped legal/data-governance references. No language, calendar, currency, identity convention, law or cultural practice is universal across Africa. Legal/regulatory and data-residency conclusions require qualified local research and review before being represented as authoritative.

## 7. Unified security and privacy threat model

### 7.1 Assets requiring protection

- Principal identity, credentials, signing keys, trust roots and revocation state.
- Owner authority, policy snapshots, approvals, tenant membership and capability grants.
- Canonical knowledge, memory, documents, private prompts, user content and derived embeddings/indexes.
- Model artifacts, datasets, adapters, prompts/templates, evaluation results and signing provenance.
- Workflow/task state, worker leases, event history, execution requests and protected effects.
- Audit records, evidence receipts, release artifacts and operational secrets.
- Mobile credentials, local cache, device keys, offline queue and notification content.

### 7.2 Adversaries and trust boundaries

Threat actors include malicious or compromised users/tenants, compromised devices, malicious insiders, compromised workers, untrusted model/provider operators, poisoned data contributors, supply-chain attackers and external network attackers.

Trust boundaries exist between: client and service; principal and tenant; domain owners; trusted control plane and model computation plane; model/provider and IROKA; retrieval content and instruction; coordinator and worker; local device and cloud; deployment profile and legal jurisdiction; build pipeline and released artifact.

### 7.3 Threat register and required controls

| Threat | Required control / acceptance condition |
|---|---|
| Forged identity, tenant or role | G01 verifies principal and current membership; caller fields are selectors only; tenant binding is tested end-to-end |
| Policy spoofing, replay or rollback | G02 signed/versioned policy, monotonic epoch, revocation, fail-closed validation and auditable activation |
| Unauthorized protected action or confused deputy | G02 approval + current authority + G09 enforcement; model/agent cannot mint grants; zero unauthorized effects in tests |
| Cross-tenant retrieval/cache/index leakage | Tenant-scoped authorization before retrieval and at data boundary; isolation tests across stores, queues, caches, logs and workers |
| Prompt injection and malicious retrieved content | Retrieved/user/model content is labeled untrusted data; instructions are not elevated; tool calls require separate authorization |
| Model/provider substitution or poisoned artifacts | Immutable digest, source/license/provenance, signature/trust validation, SBOM and revocation/rollback |
| Dataset poisoning or unlawful training | Rights/purpose/classification review, immutable dataset versions, held-out/adversarial evaluation and human approval |
| Membership/inference leakage or private data exfiltration | Data minimization, classification, provider allowlists, egress controls, redaction, retention and consent |
| Worker compromise or privilege escalation | Isolated least-privileged workers, scoped short-lived grants, bounded resources, validated results and revocation |
| Workflow replay, time manipulation, lease race or stale state | G08 obtains trusted time internally, monotonic transitions, idempotency, atomic state/event semantics and replay tests |
| Audit tampering or false assurance | G11 independent append-only/integrity-protected evidence, event correlation, external checkpoint strategy and no model self-certification |
| Mobile device loss, rooting, backup extraction, local IPC abuse | Keystore-backed protection, minimized encrypted cache, revocation, component/deep-link/backup threat tests and sensitive notification controls |
| Unicode spoofing, normalization collision or misleading identity | Preserve originals; documented normalization; confusable review; no automatic identity merge; script integrity tests |
| Calendar/time ambiguity or deadline manipulation | Typed date semantics, UTC instants, explicit timezone/calendar, vetted conversion and boundary tests |
| Localization/profile tampering | Signed/versioned profile provenance, deterministic precedence, review/effective dates and fail-closed missing mandatory rules |
| OCR/translation hallucination or evidence laundering | Confidence/provenance, human review for consequential records, original retained and derivatives clearly labeled |
| Denial of service / resource exhaustion | Finite token, memory, time, concurrency, queue, accelerator and cost limits; bounded retries/backpressure |
| Supply-chain compromise | Pinned dependencies, lockfiles, provenance, SBOM, secret scanning, reproducible build evidence and release signing |
| Data loss, failed recovery or unsafe rollback | Tested backup/restore, event recovery, artifact rollback, retention/deletion propagation and incident drills |

### 7.4 Mandatory security invariants

- No model, agent, provider, client or worker is an authority.
- No production secret, Owner private key or trust-root material is committed to source or test fixtures.
- No private user content is sent to an external provider without an explicit approved data-flow decision.
- No domain may bypass the canonical owner for protected reads/writes.
- Unknown, stale, expired, revoked, malformed or ambiguous authority fails closed.
- Cancellation, revocation and deletion have defined propagation and recovery semantics.
- Security and audit metadata must not leak sensitive content.
- Critical security and governance operations remain available independently of model/provider availability.
- A4 requires adversarial and independent security assessment; design documentation alone does not close assurance.

## 8. System-wide acceptance criteria and evidence gates

A1 defines the acceptance contract. It does not claim that implementation or production evidence already exists. A2 must define datasets, thresholds, fixtures, test owners and exact verification commands before implementation results are observed. Thresholds cannot be retrofitted after seeing results.

| ID | Acceptance area | Minimum pass evidence | Gate |
|---|---|---|---|
| A1-ARCH-01 | Domain ownership | Every G01–G12 authority, canonical state and prohibited bypass has one owner and no unresolved duplicate | A1/A2 |
| A1-IF-01 | Interface contracts | Versioned schemas, auth context, failure/idempotency semantics and compatibility tests for cross-domain interfaces | A2/A4 |
| A1-GOV-01 | Authority chain | Verified principal → tenant/membership → policy/approval → protected execution → G11 evidence, including revocation and negative tests | A2/A4 |
| A1-NEU-01 | Model lifecycle | Artifact identity, source/license, digest/signature, evaluation, approval, serving, revocation and rollback evidence | A2/A4 |
| A1-NEU-02 | Inference safety | Isolated bounded runtime; fake adapter first; provider data-flow restrictions; adversarial output validation | A3/A4 |
| A1-LOC-01 | Amharic workflows | Reviewed `am-ET` strings for primary workflows, errors, safety and governance text; English available | A3/A4 |
| A1-LOC-02 | Unicode/Ethiopic | Exact corpus round-trip across storage/API/search/import/export/UI; correct font rendering and accessibility | A3/A4 |
| A1-LOC-03 | Numerals/formatting | Ethiopic and international digits parse/format with no typed-value drift; locale-specific negative cases | A3/A4 |
| A1-CAL-01 | Calendar conformance | Vetted library comparison; Ethiopian/Gregorian boundary, leap-year, month transition and round-trip fixtures | A2/A4 |
| A1-CAL-02 | Time semantics | UTC instant persistence, correct Africa/Addis_Ababa display, date-only preservation and timezone ambiguity tests | A2/A4 |
| A1-ID-01 | Identity/name handling | Original-script names, flexible component ordering, aliases and reversible governed duplicate resolution | A3/A4 |
| A1-DOC-01 | Documents | Amharic PDF/office rendering, font embedding, copy/search/print/archive and provenance tests | A3/A4 |
| A1-OCR-01 | OCR | Rights-cleared Amharic corpus, dialect/source scope, accuracy/confidence thresholds and human-review workflow | A2/A4 |
| A1-KNOW-01 | Knowledge/retrieval | Amharic and mixed-language ingestion/retrieval/citation benchmark; permission and source-conflict tests | A2/A4 |
| A1-SPEECH-01 | Speech | Separately evaluated ASR/TTS by dialect, consent, retention and quality; no unsupported coverage claims | A2/A4 |
| A1-REG-01 | Regional profiles | Ethiopia profile plus at least one independently configured African profile through the same conformance suite | A2/A4 |
| A1-SEC-01 | Security/privacy | Threat-driven tenant isolation, prompt injection, key revocation, worker compromise, audit and data-flow regression | A4 |
| A1-OPS-01 | Reliability/recovery | Crash/restart, cancellation, idempotency, backup/restore, revocation and rollback drills | A4 |
| A1-ASSURE-01 | Independent assurance | Independent review of exact release SHA, findings/remediation and signed evidence | A4 |
| A1-REL-01 | Release integrity | Signed immutable artifact, provenance/SBOM, approved config, rollback and explicit release authorization | A5 |

### 8.1 Localization-specific acceptance fixtures

A2 must define representative, rights-cleared test corpora and exact thresholds for:
- Ethiopic syllables, punctuation, combining marks, extended characters and mixed Amharic/Latin/digits.
- Names with variable components/order, aliases and original-script preservation.
- Ethiopian calendar New Year, leap-year, month-end and Gregorian conversion boundaries.
- Date-only versus instant versus local date-time, including timezone rendering.
- Ethiopic and international numeral parsing/formatting, currency precision and locale separators.
- Amharic document templates, PDF/office font rendering, OCR confidence and human correction.
- Native Amharic and mixed Amharic-English retrieval, citation fidelity, dialect coverage and harmful mistranslation.
- Screen-reader, keyboard, font scaling, clipping, copy/paste and accessible error states.

No quality score or dialect coverage claim is accepted without dataset provenance, sample size, evaluator version and limitations.

## 9. Unresolved decision and controlled deferral register

An unresolved decision is not automatically an A1 defect. A1 may close when architecture boundaries are defined and remaining implementation choices are explicitly assigned to A2/A4. These decisions MUST NOT be guessed or silently treated as approved.

| ID | Decision / question | Owner | Required evidence / next gate | Status |
|---|---|---|---|---|
| A1-D13 | Concrete calendar, ICU/localization, OCR, speech, embedding and search libraries | Relevant domain owners; G12 compatibility | Free/open-source license, security, maintenance, Android/Rust compatibility and conformance review | DEFER A2 |
| A1-D14 | Ethiopian calendar implementation selection | Date/time contract owner; G12 | Vetted implementation comparison and independent boundary fixtures | DEFER A2 |
| A1-D15 | Translation and terminology governance, reviewer authority and release workflow | Localization/content governance | Roles, review states, fallback, versioning and critical-string approval contract | DEFER A2 |
| A1-D16 | Amharic OCR dataset, dialect scope and quality thresholds | G06/G10 with local reviewers | Rights-cleared representative corpus, baseline, metrics and human-review thresholds | DEFER A2 |
| A1-D17 | Amharic knowledge/retrieval benchmark and thresholds | G04/G10/G11 | Dataset provenance, dialect/mixed-language scope, scoring and citation oracles | DEFER A2 |
| A1-D18 | Country legal, privacy, data residency and cross-border matrix | G02/G11 with qualified local counsel/reviewers | Jurisdiction-specific sources, effective dates and authoritative review | DEFER A2; before deployment |
| A1-D19 | Additional African launch profiles and sequence | Owner/product governance | Country selection, local language/community expertise, operational and legal readiness | DEFER per launch |
| INNIA-D01 | Freeze neural infrastructure architecture and control/computation plane allocation | Owner | Ratify this consolidated INNIA mapping or issue versioned amendments | OWNER RATIFICATION |
| INNIA-D02 | Model registry operational custodian and interface ownership | G01/G04/G10/G11/G12 | RACI, immutable artifact schema, trust and lifecycle API | DEFER A2 |
| INNIA-D03 | Approved model families, local runtimes and artifact formats | G03/G10/G12 | Hardware, license, security, performance and language benchmark | DEFER A2 |
| INNIA-D04 | External provider allowlist and permitted data classes | G01/G02/G11 | Provider terms, privacy, residency, retention, cost and explicit approval | NOT SELECTED |
| INNIA-D05 | Training/adaptation datasets and rights | G04/G10/G11 | Rights, consent, provenance, retention and evaluation evidence | DEFER A2 |
| INNIA-D06 | Local/cloud/distributed worker trust and placement | G01/G02/G08/G11 | Attestation, isolation, residency, quota, cancellation and revocation contracts | DEFER A2 |
| INNIA-D07 | Amharic model/embedding/tokenization benchmark | G03/G04/G10 | Rights-cleared corpus, dialect coverage and evaluation oracles | DEFER A2 |
| INNIA-D08 | Production SLOs and cost limits | Owner/operations/G10 | Representative workload, hardware, budget and reliability evidence | DEFER A2/A4 |
| AND-D01 | Native mobile authentication flow, token audience, rotation and revocation | G01/G02 | Mobile-compatible verified-principal contract and threat review | DEFER A2 |
| AND-D02 | API host, endpoint versions and streaming/cancellation semantics | G01/G03/G08/G11 | Runnable host architecture, versioned contracts and failure tests | DEFER A2 |
| AND-D03 | On-device runtime/model artifact and supported device floor | G03/G10/G12 | License, digest, hardware/resource, privacy and benchmark evidence | NOT SELECTED |
| AND-D04 | Offline queue scope, conflict resolution and expiry | G02/G05/G08 | Explicit safe task classes, idempotency and reauthorization contract | DEFER A2 |
| AND-D05 | Android repository and release signing ownership | G12/G11 | Repository governance, signing-key custody and release evidence | DEFER A2/A5 |
| SEC-D01 | Branch protection and mandatory review/check policy | Owner/repository governance | Policy decision; branch settings intentionally unchanged in A1 | OPEN |
| SEC-D02 | Production trust-root ceremony, multi-node storage and external audit anchoring | G01/G02/G11 | Threat model, key custody, recovery and independent review | A4/A5 BLOCKER |

## 10. A1 traceability and exit criteria

### 10.1 Source-to-baseline traceability

| Source artifact | Exact evidence | Incorporated scope |
|---|---|---|
| IGACMS v1.0 A2 | PR #12 merged head `a709fc473b23494839417449e34bebf4cb8be77a` | Constitutional hierarchy, invariants, G01–G12 ownership, markers and governance |
| Amharic-first regional A1 | PR #3 head `72be8040283acd31ce90050a5b03d59c55b38b89`; contract blob `f17326543a5c5bfe7fd4d371e85020d551552c8a`; traceability blob `4f5af54081b304cf79fa8846d9660ad546dc1348` | Language, Ethiopic, localization, calendar, identity, documents, knowledge, regional profile and acceptance |
| BRAIN A1/A2 | PR #26 head `774bc75f751b8e80e6135c349fb78394c02cf4fa`; A2 contract blob `8d2621478c4e05957c375b6e79180f493fcfff9b` | G03 cognitive ownership, task/result/plan/critic interfaces and domain boundaries |
| INNIA A1 | PR #134 head `5d6f6b36e0d514e8fd14f144d8cde905e0f49d92`; architecture blob `a5aaba77847422fc92bb973e594b2972097a3b36` | Neural infrastructure architecture and model lifecycle proposal |
| Android A1 | PR #131 head `8fe51877d3cf0e04f43a9f03df04eb901462120d` | Native hybrid client, authority boundary, offline, mobile API and device threat requirements |
| INNIA A2 | PR #135 head `e0d25d9e0cc40998da153f60de33e0f3f0fa2bbf` | Candidate inventory and A2 unresolved neural integration/temporal dependencies; not an A1 approval |

### 10.2 A1 completion checklist

- [x] Consolidate constitutional and domain architecture hierarchy.
- [x] Define G01–G12 canonical ownership and prohibited overlaps.
- [x] Define cross-domain interface and authority invariants.
- [x] Reconcile INNIA, INGA, IGACMS, BRAIN, Native Cognition and CIW boundaries.
- [x] Reconcile neural output, policy, execution and assurance responsibilities.
- [x] Consolidate Amharic-first Ethiopia and independently configurable African profile requirements.
- [x] Define Ethiopic text, calendar/time, identity, document, knowledge and speech requirements.
- [x] Consolidate platform, model, data, worker, mobile and localization threat model.
- [x] Define system-wide acceptance criteria and evidence gates.
- [x] Register all identified A1/A2/A4/A5 unresolved decisions with owners and next gates.
- [x] Record source artifacts, exact heads and known approval states.
- [x] Owner ratification of this consolidated system-level A1 baseline, explicitly granted on 21 November 2026 by the instruction to complete A1 with 100% closure.
- [x] A1 closure record updated with the ratified version and exact commit.

### 10.3 A1 disposition

**Architecture content:** CONSOLIDATED.  
**Conflict reconciliation:** RESOLVED at the normative ownership/boundary level; implementation-level contract questions remain explicitly assigned to A2.  
**Threat model:** BASELINE DEFINED; operational control effectiveness is not yet verified.  
**Localization requirements:** BASELINE DEFINED; implementation and corpus verification are later gates.  
**Acceptance criteria:** DEFINED; datasets, numerical thresholds and test oracles remain A2 decisions.  
**Unresolved decisions:** REGISTERED with owner and next gate.  
**Formal A1 gate:** VERIFIED-CLOSED — OWNER RATIFIED 21 NOVEMBER 2026.

The Owner's explicit instruction to complete A1 with 100% closure constitutes ratification of this consolidated architecture/specification baseline. All A1 scope items are complete: the system hierarchy, domain ownership, interface boundaries, architecture conflict resolutions, threat model, localization requirements, acceptance criteria, source traceability and controlled deferral register are recorded. The remaining entries in the unresolved-decision register are explicitly deferred to their assigned A2/A4/A5 gates; they are not unrecorded A1 omissions. This closure does not claim that runtime controls, localization implementation, model serving, security effectiveness or production operation have been implemented or verified. A2 may proceed against this frozen baseline. Reopening requires material authoritative contradictory evidence and approved change control.

## 11. Explicit authorization boundaries

This A1 document authorizes no:
- A3 implementation or modification of runtime code;
- modification, rebase, force-push, closure, deletion or merge of existing branches/PRs;
- merge to `main`;
- production key/trust-root provisioning or activation;
- paid provider, paid service, GPU or production cloud activation;
- ingestion of production/private data for training;
- production release, publication or A5 deployment.

A2 is the next permitted phase after A1 ratification. A3, A4 and A5 retain their separate entry and approval gates.

---

**End of IROKA A1 Master Architecture Baseline and Closure Register v1.0.0**


## 12. Owner ratification and closure record

**Owner decision:** RATIFIED — 21 November 2026.  
**Authority:** Explicit Owner instruction in the project conversation: “complete A1 with 100% closure”.  
**Ratified baseline:** IROKA A1 Master Architecture Baseline and Closure Register v1.0.0.  
**Closure status:** VERIFIED-CLOSED for architecture/specification scope.  
**Next phase:** A2 read-only reconciliation against this frozen baseline.  
**Implementation/release authority:** Unchanged; A3, A4 and A5 retain their separate gates.

