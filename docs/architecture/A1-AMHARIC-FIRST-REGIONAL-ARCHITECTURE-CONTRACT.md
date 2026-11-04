# A1 — Amharic-First Ethiopian and African Architecture Contract

**Contract ID:** IROKA-A1-REGIONAL-001  
**Version:** 1.0.0  
**Status:** Normative architecture baseline for new IROKA design and implementation  
**Authority:** Owner-directed A1 baseline  
**Scope:** Language, localization, calendar/time, identity, documents, knowledge, regional deployment, and cross-cutting Kernel controls

## 1. Purpose and governing rules

IROKA is an Amharic-first, Ethiopian-grounded and African-focused cognitive operating system. These requirements are foundational architecture constraints, not optional UI translations or post-launch enhancements.

The governing rules are:

1. **Amharic-first:** Amharic is the primary language and default experience for the Ethiopia deployment profile.
2. **African by design:** regional expansion uses explicit deployment profiles; Ethiopia's language, calendar, currency, laws, and institutions are not assumed to apply elsewhere.
3. **Preserve original meaning:** names, scripts, dates, numerals, documents, speech, and knowledge must not be silently normalized into lossy representations.
4. **Interoperate explicitly:** conversions between calendars, scripts, locales, currencies, and formats must be deliberate, traceable, and reversible where technically possible.
5. **Governed configuration:** regional settings are versioned, validated, auditable, and controlled; models and agents cannot change them.
6. **Evidence before capability claims:** a language or region is not declared supported until its acceptance tests pass for the relevant workflows.

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

## 2. Contract L — Language and script

### L.1 Ethiopia profile defaults

- The Ethiopia deployment profile MUST use Amharic (locale am-ET) as its default interface and system-interaction locale.
- English (locale en) MUST be available as a secondary language for the initial Ethiopia profile.
- User-selected language preferences MUST be supported without changing stored source content.
- New Ethiopia-profile experiences MUST be authored and reviewed in Amharic first; English MUST NOT be the only complete or authoritative interface.
- Language selection MUST be available during onboarding and later in account preferences.

### L.2 Unicode and Ethiopic script

- All text paths MUST use Unicode end-to-end and preserve Ethiopic characters, combining marks, punctuation, and mixed-script text.
- Storage, APIs, search indexes, logs, exports, notifications, and UI rendering MUST NOT corrupt Ethiopic text through ASCII-only assumptions, lossy transliteration, or incompatible encodings.
- Fonts and layout MUST support Ethiopic glyph coverage, shaping, line wrapping, cursor movement, selection, copy/paste, and accessible reading.
- Mixed Amharic/English content, numerals, punctuation, and directionality MUST render predictably. The system MUST NOT assume all African scripts share one direction or shaping model.
- Transliteration MAY be offered as an aid, but MUST never replace or overwrite the authoritative original-script value.

### L.3 Language-aware interaction

- System prompts, safety messages, consent, authorization explanations, errors, help, and critical workflow instructions MUST be available in Amharic for the Ethiopia profile.
- Amharic input MUST be accepted in search, identity, knowledge, document, and governance workflows.
- Language detection MAY assist routing but MUST NOT silently rewrite content or be treated as proof of user intent.
- When a requested language capability is unavailable or uncertain, IROKA MUST disclose the limitation and preserve original input.

### L.4 Support declarations

Every language capability MUST have a declared support level per workflow: NOT_SUPPORTED, INPUT_ONLY, BASIC_UI, REVIEWED_UI, or FULL_WORKFLOW_VERIFIED. Full support requires evidence for input, rendering, search, accessibility, document export, errors, and relevant AI/model behavior.

## 3. Contract LOC — Localization and regional formatting

- Locale MUST be explicit configuration, not inferred solely from IP address, device language, model output, or physical location.
- Locale-sensitive formatting MUST be centralized and consistent across UI, APIs, reports, notifications, generated documents, and exports.
- The system MUST support Ethiopic and Western digit presentation where appropriate. Numeric values MUST remain typed numeric values internally; localized rendering MUST not change their underlying value.
- Decimal separators, grouping separators, units, names, address formats, phone formats, and sorting rules MUST be locale-aware.
- Sorting and search MUST support Ethiopic text and preserve exact-match behavior alongside any normalized or transliterated search modes.
- Locale changes MUST NOT mutate stored names, legal records, timestamps, amounts, source documents, or audit evidence.
- Display values MUST be distinct from machine-readable canonical values. APIs MUST document canonical representations and MUST NOT rely on localized display strings for computation.

## 4. Contract CAL — Calendar, date, time, and chronology

### CAL.1 Calendar model

- The Ethiopia profile MUST use the Ethiopian calendar as its default human-facing calendar.
- Gregorian dates MUST be supported for interoperability, integrations, external standards, and users who select them.
- Calendar choice MUST be explicit in user preferences and regional profile policy. Gregorian interoperability MUST NOT displace the Ethiopian calendar in the primary Ethiopia experience.
- Date values MUST carry an unambiguous canonical representation and calendar identifier. A bare date string without calendar semantics MUST NOT be accepted where ambiguity is material.
- Ethiopian/Gregorian conversion MUST use a vetted, deterministic implementation with boundary and leap-year tests.
- The UI MUST clearly label the calendar when ambiguity is possible. It MUST NOT silently reinterpret an entered date.
- Historical dates, recurring events, deadlines, anniversaries, and date-only records MUST preserve their calendar semantics.

### CAL.2 Time zones and instants

- The Ethiopia profile MUST default to the IANA time zone Africa/Addis_Ababa.
- Other deployments and individual users MUST be able to select valid IANA time zones.
- Absolute instants MUST be stored in a canonical timezone-independent form (UTC) and rendered in the selected regional/user time zone.
- Date-only concepts MUST remain distinct from timestamps representing instants.
- APIs and event records MUST distinguish local calendar date, local time, time zone, and resolved instant whenever relevant.
- Recurrence MUST be defined in calendar/time-zone terms, not by repeatedly adding fixed seconds where that changes local wall-clock meaning.

## 5. Contract ID — Identity, names, and person representation

- Identity records MUST preserve a person's authoritative name exactly as supplied, including Ethiopic script, spacing, punctuation, and component order.
- Identity MUST support separately typed native-script name, optional Latin-script representation, preferred display name, and explicitly supplied aliases.
- The system MUST NOT assume Western first/middle/last-name structure or require a family name where the deployment context does not use one.
- Latin transliteration MUST NOT replace the native-script name or be treated as legally authoritative unless the relevant authority explicitly establishes it.
- Search MUST support native-script names and configured aliases without collapsing distinct people through aggressive normalization.
- Identity matching MUST use multiple verified attributes and governance rules; name similarity alone MUST NOT merge identities or establish identity equivalence.
- User-facing identity, consent, approval, and audit workflows MUST display names in a form recognizable and verifiable by the relevant user.
- Legal identity attributes MUST be deployment-profile-specific, data-minimized, access-controlled, and retained only under an approved purpose and retention policy.
- Agents and models MUST NOT invent, complete, translate, or normalize identity attributes as verified facts.

## 6. Contract DOC — Documents, records, and rendering

- Document workflows MUST support Amharic-first authoring, review, approval, search, display, print, and export for the Ethiopia profile.
- Document storage MUST preserve original uploaded bytes and a cryptographic digest. Extracted text, OCR output, translated text, and normalized representations MUST be derived artifacts linked to the source, never silent replacements.
- PDF generation and preview MUST embed or reliably provide suitable Ethiopic fonts and preserve text extraction, pagination, glyphs, and mixed-script layout.
- DOCX, spreadsheet, CSV, and other supported formats MUST be tested for Ethiopic round-trip fidelity before being declared supported.
- Templates MUST be locale- and deployment-profile-aware. Dates, numbers, names, currency, addresses, signatures, and legal notices MUST use the selected profile's rules.
- Document metadata MUST record source language, detected language (if any), declared language, calendar semantics for dates, and transformation history where relevant.
- OCR and speech/document extraction MUST retain confidence, provenance, page/region or time offsets where available, and a review state. Low-confidence extraction MUST NOT be silently promoted to verified fact.
- Human correction MUST preserve machine-extracted original and record who changed what and when.
- Signatures, approvals, timestamps, document identifiers, and audit references MUST remain stable across language rendering and export.
- No translation or OCR transformation may change legal or operational meaning without an explicit review/approval workflow.

## 7. Contract KNOW — Knowledge, retrieval, and reasoning

- Knowledge ingestion MUST accept Amharic and English for the Ethiopia profile, including Unicode text and supported document formats.
- Every knowledge item MUST retain provenance: source, owner/tenant, acquisition time, source language where known, transformations, access classification, and integrity metadata.
- Original source content MUST be retained separately from extracted, translated, summarized, chunked, embedded, or normalized derivatives.
- Retrieval MUST be evaluated on Amharic queries and Amharic source material, including mixed Amharic/English queries. English-only benchmark performance MUST NOT be used to claim Amharic capability.
- Indexing and retrieval MUST be tenant- and permission-aware. Language conversion, embeddings, summarization, or model adapters MUST NOT bypass source access controls.
- Translation and cross-lingual retrieval MUST identify translated or cross-language matches. The original source MUST remain accessible to authorized users.
- Amharic morphology, spelling variation, transliteration variation, names, and domain terminology MUST be represented in an explicit evaluation corpus and tested. Normalization MUST not erase distinctions relevant to identity, law, governance, or records.
- Reasoning outputs MUST distinguish source evidence, translated evidence, model inference, and uncertainty. Generated Amharic text MUST NOT be presented as a faithful quotation unless verified against the source.
- Knowledge quality MUST include Amharic-specific measures for retrieval relevance, factuality, provenance, language quality, and harmful mistranslation.
- Speech and handwriting support MUST be declared separately from printed-text support. No support claim is valid without workflow-specific evidence.

## 8. Contract REG — African regional deployment profiles

### REG.1 Profile architecture

- IROKA MUST implement regional configuration through versioned deployment profiles rather than scattered country-specific conditionals.
- A profile MUST define, at minimum: country/region identifier, supported/default languages, scripts, locale formats, calendar defaults, time-zone defaults, currencies, units, address/phone conventions, document conventions, and applicable legal/compliance configuration references.
- Profiles MUST be independently versioned, reviewable, testable, and auditable.
- A profile MUST NOT override global Kernel security, privacy, authorization, evidence, or Owner-governance requirements.
- Ethiopia is the first-class reference profile. Additional African profiles MUST be addable without changing core identity, trust, or authorization models.
- Users and organizations MAY have preferences that differ from profile defaults, subject to legal and organizational policy.
- Country, language, calendar, and currency MUST be separate dimensions; none may be inferred as a universal proxy for another.

### REG.2 Currency, units, and financial representation

- The Ethiopia profile MUST default to ETB for relevant financial display and entry workflows.
- The platform MUST support multiple currencies and explicit currency codes. Amounts MUST never be stored or computed as unqualified localized strings.
- Currency conversion MUST require an explicit rate source, rate timestamp, and conversion policy; a model-generated exchange rate MUST NOT be authoritative.
- Regional units and measurement conventions MUST be explicit and locale-aware.

### REG.3 Law, institutions, and data residency

- Legal and regulatory behavior MUST be implemented through reviewed jurisdiction-specific policy/configuration, not model inference or country-name heuristics.
- IROKA MUST NOT claim legal compliance for a country or region without documented assessment and accountable approval.
- Data residency, retention, cross-border transfer, consent, and access obligations MUST be configurable per deployment and enforced by platform security boundaries.
- Local, private-cloud, hybrid, and constrained-connectivity deployment modes MUST be considered. Offline operation MUST define synchronization, conflict resolution, revocation freshness, and audit-integrity behavior; it MUST NOT silently weaken authorization.
- Regional expansion MUST respect linguistic diversity within countries and organizations. A country profile MUST allow multiple official, working, and user-selected languages where required.

## 9. Cross-cutting Kernel and data requirements

- Locale, language, calendar, time zone, and regional profile are context attributes, not authorization credentials.
- Security decisions MUST use canonical typed values and stable identifiers, never localized display strings.
- Audit records MUST preserve canonical timestamps and relevant locale/profile context needed to interpret human-facing events.
- Policy and approval interfaces MUST present critical scope, risk, and consequence information in the user's supported language before consent or approval.
- Tenant isolation, least privilege, purpose limitation, encryption, retention, and deletion controls apply equally to original and derived multilingual data.
- Model providers MUST be replaceable. No single provider may be the sole source of Amharic correctness, calendar correctness, identity verification, or legal interpretation.
- Model-produced translation, transcription, extraction, or summaries used in consequential workflows MUST carry provenance and an appropriate verification state.
- Regional configuration changes MUST be versioned, approved according to policy, auditable, and safe to roll back.

## 10. Prohibited architectural shortcuts

The following are non-conforming:

1. English-only source-of-truth UI with Amharic added only as a later translation layer.
2. ASCII-only storage, search, logging, identifiers, or export assumptions for user text.
3. Treating Latin transliteration as the canonical identity name.
4. Treating Gregorian dates as the only date model or silently converting Ethiopian dates.
5. Hardcoding Ethiopian defaults into every African deployment.
6. Storing monetary amounts, dates, or localized numerals only as formatted strings.
7. Replacing source documents or source text with OCR, translation, summaries, or embeddings.
8. Declaring language support based only on model-provider claims or a successful demo.
9. Using English-only retrieval benchmarks to claim Amharic knowledge capability.
10. Allowing models or agents to change regional profiles, identity facts, legal settings, or authorization policy without governed approval.

## 11. Acceptance criteria and verification evidence

A1 contract conformance is verified by later implementation and assurance gates. This document alone does not prove runtime capability.

| ID | Acceptance criterion | Required evidence |
|---|---|---|
| A1-LANG-01 | Amharic is Ethiopia default; English is selectable | Profile/config and onboarding/UI tests |
| A1-LANG-02 | Ethiopic text survives end-to-end | Unicode round-trip tests across API, DB, search, logs and export |
| A1-LANG-03 | Critical user journeys work in Amharic | Reviewed Amharic UI and workflow acceptance suite |
| A1-LOC-01 | Locale formatting is centralized and typed | Tests for digits, dates, amounts, sorting and display |
| A1-CAL-01 | Ethiopian calendar default and Gregorian interoperability | Conversion boundary, leap-year, recurrence and round-trip tests |
| A1-CAL-02 | Instants and date-only values remain distinct | API/schema tests for UTC instants, local zones and civil dates |
| A1-ID-01 | Native-script identity is preserved; aliases remain distinct | Identity round-trip, search and non-merge tests |
| A1-DOC-01 | Amharic documents render and export faithfully | PDF/DOCX/spreadsheet print and extraction fixtures |
| A1-DOC-02 | OCR/translation derivatives retain source and review provenance | Source-to-derivative lineage and audit tests |
| A1-KNOW-01 | Amharic retrieval is evaluated on representative corpus | Versioned benchmark, relevance and provenance report |
| A1-KNOW-02 | Cross-lingual retrieval respects tenant permissions | Isolation and authorization tests |
| A1-REG-01 | Regional profiles are versioned and independently configurable | Schema validation, profile fixtures and rollback tests |
| A1-REG-02 | Ethiopian defaults do not leak into another profile | Cross-profile regression tests |
| A1-SEC-01 | Locale/profile cannot grant authority or bypass Kernel policy | Negative authorization tests and audit evidence |

Required fixtures MUST include Amharic-only, English-only and mixed-script text; Ethiopic and Western digits; Ethiopian/Gregorian boundary and leap-year dates; date-only values and timestamps; Amharic PDF/DOCX/spreadsheet samples; Amharic search with spelling/morphology variation; and at least one reviewed non-Ethiopian African profile proving the design is not Ethiopia-hardcoded.

## 12. Ownership, change control, and exceptions

- This contract is normative for new architecture and implementation work in IROKA ZERO.
- Changes to defaults, canonical representations, identity semantics, calendar semantics, regional profile boundaries, or acceptance criteria require explicit Owner approval and a versioned amendment.
- An exception MUST identify the affected requirement, reason, risk, compensating control, owner, expiry/review date, and approval evidence.
- No agent, model, contributor, dependency, or regional profile may self-approve an exception.
- An implementation that does not yet satisfy a requirement MUST be marked PARTIAL, MISSING, or NOT RUN; it MUST NOT be described as production-ready because this contract exists.

## 13. A1 exit criteria

A1 may be marked VERIFIED-CLOSED only when:

1. This contract is present in the destination repository on the authorized working branch.
2. The architecture index/strategy points to this contract.
3. The seven contract areas and cross-cutting controls have explicit acceptance criteria.
4. Conflicts with existing architecture documents have been identified and reconciled.
5. Unresolved policy choices are explicitly recorded for Owner decision rather than silently assumed.
6. A1 scope is frozen with a recorded baseline commit SHA.

A1 closure establishes the requirements baseline. It does NOT mean Amharic UI, Ethiopian calendar, OCR, speech, multilingual retrieval, regional profiles, or legal compliance have already been implemented or verified.

## 14. Explicitly deferred decisions

The following require evidence and/or separate Owner decisions before implementation:

- Initial sequence of African country profiles after Ethiopia.
- Exact official/working language set for each future country profile.
- Jurisdiction-specific legal, regulatory, data-residency, and retention rules.
- Approved Ethiopian calendar library and authoritative conversion test corpus.
- Approved Amharic fonts, typography stack, and accessibility test matrix.
- Amharic speech recognition/synthesis providers and quality thresholds.
- Handwriting OCR scope and acceptance thresholds.
- Currency-rate sources and financial conversion policy.
- Offline synchronization guarantees and maximum acceptable revocation staleness.

---

**Binding principle:** IROKA must serve people in their own languages and institutional contexts without sacrificing source fidelity, security, governance, or evidence. Amharic-first is the Ethiopia baseline; African-wide support is achieved through explicit, independently governed regional profiles.
