# A1 — Amharic-First Ethiopian and African Architecture Contract

**Status:** Owner-directed binding architecture baseline  
**Contract ID:** IROKA-A1-REGIONAL-001  
**Applies to:** IROKA ZERO kernel, services, clients, APIs, data models, documents, knowledge pipelines, integrations, deployment profiles and operational tooling  
**Normative language:** MUST / MUST NOT are mandatory; SHOULD / SHOULD NOT are strong defaults requiring a recorded rationale to depart; MAY is optional.

## 1. Governing decision

IROKA is **Amharic-first, Ethiopian-grounded and African-focused**. This is a foundational product and architecture property, not a translation layer or a post-MVP enhancement.

> **Amharic-first by default; country-aware by configuration; African-wide by design.**

The Ethiopia deployment profile MUST provide a complete Amharic-first experience. The platform MUST also support other African deployment contexts through explicit regional profiles. Ethiopian defaults MUST NOT be hardcoded as universal African rules.

This contract governs architecture and acceptance. It does not assert that the current implementation already satisfies these requirements.

## 2. L10N-01 — Language, script and typography

### Language policy
1. The Ethiopia profile MUST set Amharic (am-ET) as the primary system language and English (en) as a supported secondary language.
2. User-facing product surfaces MUST be Amharic-first in navigation, labels, onboarding, notifications, errors, help, system messages and standard templates. English MUST remain available without requiring a separate deployment.
3. Language preference MUST be configurable per user and, where appropriate, per organization, workspace, document and communication.
4. Language selection MUST be explicit and persisted. A user's language MUST NOT be inferred from name, ethnicity, location or other sensitive proxies.
5. Missing translations MUST use a declared fallback chain: user preference → deployment primary language → configured secondary fallback. The system MUST NOT silently substitute unreviewed machine-generated text as approved translation.
6. Every translatable resource MUST have a stable key, language tag, version and review state. Critical security, consent, financial and governance text MUST have human-reviewed translations before production use.

### Script and rendering
1. All services and clients MUST preserve Unicode text end-to-end. Ethiopic script MUST be first-class, including applicable Ethiopic syllabic blocks, punctuation, combining marks and extended characters.
2. Text storage, transport, logs, APIs, imports, exports, search indexes and message queues MUST use Unicode-capable encodings; UTF-8 is the canonical interchange encoding.
3. Clients MUST use fonts with adequate Ethiopic glyph coverage and MUST test shaping, line breaking, clipping, cursor movement, selection, copy/paste and mixed Ethiopic/Latin/numeric text.
4. Search and comparison MUST use a documented normalization policy. Original source text MUST be preserved; normalized search keys MUST NOT overwrite source text or collapse meaningful distinctions.
5. Layout MUST support mixed-script content and future right-to-left languages without assuming all African languages share one writing direction.
6. Accessibility MUST include screen-reader labels, keyboard navigation, scalable text, sufficient contrast and readable Ethiopic typography.

### Numerals and formatting
1. The platform MUST support Ethiopic numerals and international digits, with configurable display preference by deployment and user.
2. Numeric values MUST be stored as typed values, never as formatted display strings.
3. Parsing MUST be locale-aware and reject ambiguous or malformed input rather than guessing. Formatting MUST NOT change the underlying numeric value.
4. Financial amounts MUST carry explicit currency code and precision; date, decimal, grouping and percentage formatting MUST be locale-aware.

## 3. L10N-02 — Localization and regional profile model

1. Localization MUST be driven by versioned deployment profiles, not scattered conditionals or hardcoded country checks.
2. A profile MUST define, at minimum: country/territory identifier, subnational context where needed, primary and supported languages, script/font requirements, calendar, time zone, currency defaults, number/date conventions, address/phone conventions, document conventions and applicable legal/regulatory references.
3. Profiles MUST be versioned, auditable and independently testable. An update MUST identify its effective date and migration implications.
4. Organization and user preferences MAY override non-legal presentation defaults. They MUST NOT override mandatory legal, security or records-retention controls.
5. Shared platform services MUST consume profile interfaces; they MUST NOT embed Ethiopia-only defaults in core domain logic.
6. The initial Ethiopia profile MUST specify Amharic (am-ET) primary, English (en) secondary, Ethiopian calendar as default civil display calendar, Africa/Addis_Ababa as default time zone and ETB as default currency.
7. Other African profiles MUST be independently configurable. No single African language, calendar, currency, legal system, identity format or cultural convention may be treated as universal.
8. The system MUST distinguish country, language and locale. A language is not a country, and a country may have multiple official, national, regional and community languages.
9. Profile data MUST record provenance and review ownership. Legal and regulatory content MUST be reviewed by qualified local expertise before it is represented as authoritative.
10. A deployment MUST declare unsupported profile capabilities explicitly; it MUST NOT silently fall back to an incompatible calendar, currency or legal profile.

## 4. CAL-01 — Calendar, date and time

1. The Ethiopia profile MUST use the Ethiopian calendar as the default user-facing civil calendar.
2. Gregorian dates MUST be supported for interoperability, external systems, international standards and user preference. The platform MUST never assume Gregorian is the only valid civil calendar.
3. Every date value MUST have a declared semantic type:
   - **Instant:** a point on the global timeline, stored canonically in UTC and rendered in the selected time zone/calendar.
   - **Local date:** a calendar date without an implied time or time zone.
   - **Local date-time:** a wall-clock date and time with an explicit time zone and ambiguity policy.
   - **Calendar date:** a date explicitly associated with a named calendar system.
4. Conversion MUST use a tested calendar implementation with documented epoch, month lengths, leap-year rules and boundary behavior. Handwritten ad hoc conversion logic is prohibited.
5. The system MUST retain the original calendar context where a date was entered or legally recorded. Display conversion MUST NOT erase that context.
6. The default Ethiopia time zone MUST be Africa/Addis_Ababa; timestamps MUST be stored as instants and rendered using the relevant profile and user preference.
7. APIs and event payloads MUST identify calendar and time-zone semantics where ambiguity is possible. Date-only values MUST NOT be converted to UTC timestamps without an explicit business rule.
8. Recurrence, deadlines, reminders, payroll/financial periods, audit timestamps and legal effective dates MUST define which calendar and time zone govern them.
9. Tests MUST cover Ethiopian New Year boundaries, leap-year behavior, month transitions, Gregorian interoperability, time-zone rendering, invalid dates and round-trip preservation.
10. The UI MUST make the active calendar clear where ambiguity could affect decisions or records.

## 5. ID-01 — Identity, names and search

1. Identity models MUST separate immutable system identifiers from human names and display preferences.
2. A person MUST be able to retain their name in their original script, including Ethiopic, without forced Latin transliteration.
3. Name data MUST support structured and unstructured forms, multiple given/family/patronymic components, preferred display order, alternate spellings, transliterations and aliases where lawful and necessary.
4. The data model MUST NOT assume Western first-name/last-name ordering or require a family-name field to be populated.
5. Original-script name data MUST remain authoritative when supplied by the person or verified source. Transliteration is an additional representation, not a replacement.
6. Search MUST support Ethiopic and Latin representations, declared aliases and profile-aware normalization. Fuzzy matching MAY suggest candidates but MUST NOT alone establish identity or merge records.
7. Duplicate resolution MUST use governed evidence and an auditable review process. High-impact identity merges MUST be reversible or compensatable and require appropriate authorization.
8. Identity attributes MUST be purpose-limited and minimized. Sensitive demographic or community attributes MUST NOT be inferred from names, language or location.
9. APIs, exports and integrations MUST preserve Unicode names and stable identifiers. Interoperability mappings MUST retain source values and provenance.
10. The platform MUST distinguish legal identity, verified identity, preferred name and account handle; these concepts MUST NOT be conflated.

## 6. DOC-01 — Documents, records and communication

1. Document creation, editing, preview, signing, printing, export and archival MUST support Amharic and Ethiopic script as baseline capability.
2. PDF and office-format outputs MUST embed or otherwise reliably reference fonts needed for correct Ethiopic rendering. Rendered output MUST be tested, not assumed correct from source text.
3. Templates MUST be language-aware and support mixed-language content, Ethiopic numerals, profile-specific dates, local address conventions and user-approved terminology.
4. Every document MUST retain a stable document identifier independent of its displayed number or localized title.
5. Document numbering MUST be generated by a versioned numbering policy scoped to the owning organization/unit and document class. It MUST support profile-specific formats without encoding mutable presentation rules into primary keys.
6. The system MUST preserve the exact original uploaded or authored file, subject to retention and privacy policy, alongside extracted text and rendered derivatives. Derivatives MUST record source hash, transformation/version and provenance.
7. OCR and extraction MUST identify detected language/script and confidence. Amharic OCR MUST be a first-class capability; low-confidence extraction MUST be marked for human verification and MUST NOT silently become authoritative record text.
8. Search, indexing and metadata extraction MUST preserve original text and support Amharic queries. Indexing failures MUST be observable.
9. Document lifecycle, retention, legal hold, access, redaction and disposal MUST be governed independently of locale formatting.
10. Templates for legal, financial, governance and consent documents MUST receive qualified local review before operational use. Machine translation alone is insufficient approval.
11. Exports MUST preserve Unicode, date/calendar semantics, currency codes, document identifiers and provenance metadata.

## 7. KNOW-01 — Knowledge, retrieval and reasoning

1. Knowledge ingestion MUST accept Amharic content as a first-class source language, including documents, text, approved web sources, structured records and supported speech transcripts.
2. Every ingested item MUST retain provenance: source identity/location, acquisition time, source language/script when known, content hash, transformation history, access classification and applicable rights/consent.
3. Language identification MUST permit unknown or mixed; it MUST NOT force a single language label when evidence is insufficient.
4. Parsing, chunking, tokenization, indexing, embedding and retrieval MUST be evaluated on Amharic datasets and mixed Amharic-English content. English-only benchmarks are insufficient for release acceptance.
5. Retrieval MUST support original-language queries and, where configured, cross-language retrieval. Translated passages MUST be distinguishable from original source passages.
6. Generated answers MUST preserve source meaning, distinguish evidence from inference, expose uncertainty and cite retrievable source passages where the task requires evidence.
7. The system MUST NOT treat a translation, OCR transcript, model summary or inferred entity as equivalent to the original source.
8. Conflicting sources MUST remain distinguishable; the system MUST retain source dates, authority/provenance signals and conflict state rather than silently selecting one.
9. Knowledge access MUST inherit source permissions, tenant boundaries, purpose restrictions and retention rules. Retrieval MUST NOT bypass source authorization.
10. Amharic speech recognition and synthesis SHOULD receive priority in capability planning, but MUST be represented as separate evaluated capabilities with declared dialect, quality and coverage limitations. No claim of universal Amharic dialect coverage is permitted without evidence.
11. African language expansion MUST use per-language evaluation and community/local expert review. Support for Amharic MUST NOT be presented as support for all African languages.
12. Knowledge and reasoning evaluations MUST include factuality, citation fidelity, script integrity, dialect coverage, bias, harmful mistranslation and cross-language retrieval failure cases.

## 8. REG-01 — African regional architecture

1. IROKA MUST be capable of serving deployments across African countries and subnational contexts through modular profiles and extension points.
2. The architecture MUST not define a monolithic African locale. Language, calendar, currency, time zone, legal context, identity practice and document conventions MUST be independently configurable.
3. Country profiles MUST support multiple languages and scripts, and deployments MUST be able to select organizational working languages distinct from country profile defaults.
4. Legal/regulatory requirements MUST be represented as jurisdiction-scoped, versioned policy references with provenance, effective dates and qualified review. The platform MUST not invent or generalize legal rules across jurisdictions.
5. Currency and financial configuration MUST support ISO currency codes and multi-currency operation. Exchange rates MUST include source, timestamp and rate type; display conversion MUST NOT alter ledger values.
6. Address, phone, postal and administrative-area structures MUST be extensible and MUST NOT require a single global format.
7. Data residency, cross-border transfer, retention and privacy controls MUST be deployment-configurable and reviewed against applicable law. The system MUST fail closed where a required compliance decision is unresolved.
8. Regional extensions MUST use stable contracts and MUST NOT fork core identity, authorization, audit or tenant-isolation semantics.
9. Regional capability claims MUST be evidence-based and scoped to tested languages, jurisdictions and deployment configurations.
10. Local community, institutional and domain expertise SHOULD participate in terminology, usability, data governance and evaluation design.

## 9. Cross-cutting architecture constraints

- Unicode correctness, profile resolution and calendar semantics are platform services, not presentation-only utilities.
- Domain records MUST store canonical values and explicit semantic context; localized formatting belongs at the boundary.
- APIs MUST be explicit about locale-sensitive interpretation and MUST avoid ambiguous date, number, name and currency payloads.
- Logs and telemetry MUST preserve enough diagnostic context to investigate localization defects while minimizing personal data.
- Security controls, authorization, audit integrity and tenant isolation MUST remain invariant across languages and regional profiles.
- Localization MUST NOT weaken consent, access control, retention, cryptographic validation or audit requirements.
- All user-visible error and safety messages MUST be available in the deployment primary language before production activation.

## 10. Mandatory acceptance evidence

A1 implementation work is not considered verified merely because these requirements are documented. Before a later production-readiness claim, the following evidence is mandatory:

| ID | Acceptance evidence | Minimum pass condition |
|---|---|---|
| A1-L1 | Amharic UI and translation inventory | Primary workflows, errors and safety-critical messages have reviewed am-ET coverage |
| A1-L2 | Unicode/Ethiopic test suite | Round-trip storage/API/search/export and UI rendering preserve test corpus exactly |
| A1-L3 | Numeral and locale tests | Ethiopic and international digits parse/format without value drift |
| A1-C1 | Calendar conformance suite | Ethiopian/Gregorian boundary, leap and round-trip tests pass against a vetted implementation |
| A1-C2 | Time-zone tests | UTC persistence and Africa/Addis_Ababa rendering are correct; date-only values remain date-only |
| A1-I1 | Identity model and search tests | Original-script names, alternate forms and non-Western ordering work; fuzzy matches do not auto-merge |
| A1-D1 | Document rendering suite | Amharic PDF/office rendering, copy/search, print and archival checks pass |
| A1-D2 | OCR evaluation | Amharic corpus, confidence thresholds, human-review path and provenance are verified |
| A1-K1 | Knowledge evaluation | Amharic and mixed-language ingestion/retrieval/citation benchmark meets approved thresholds |
| A1-R1 | Regional profile conformance | Ethiopia profile passes; at least one additional African profile proves no Ethiopia-only assumptions in core |
| A1-S1 | Security/privacy regression | Localization and profile changes preserve tenant isolation, permissions, audit and retention controls |
| A1-G1 | Governance review | Qualified local review recorded for legal/financial/governance terminology and applicable jurisdictional rules |

Thresholds, representative datasets, dialect coverage and local reviewers MUST be defined in relevant A2 implementation contracts before implementation acceptance. No numerical quality threshold may be invented after test results are known.

## 11. Prohibited shortcuts

The following are non-conforming:
- Treating Amharic as a translation-only or future enhancement.
- Storing Ethiopic names or documents only as Latin transliterations.
- Assuming Gregorian calendar, UTC display, Western name order or a single global address format.
- Hardcoding Ethiopia's calendar, currency, time zone or laws into shared African core logic.
- Using English-only test corpora to claim Amharic or African language readiness.
- Silently converting calendars, numerals, currencies or source text.
- Automatically merging identities based only on fuzzy name similarity.
- Treating OCR or machine translation output as verified source evidence.
- Claiming pan-African language, legal or cultural coverage without country/language-specific evidence.

## 12. Change control and A1 exit criteria

1. This document is the binding A1 architecture baseline for the scope stated above.
2. Any exception MUST identify the requirement, reason, affected deployments, risk, compensating control, expiry/review date and approving authority. No silent exception is permitted.
3. Changes to the governing decision, mandatory requirements or cross-cutting invariants require explicit Owner approval and a versioned contract revision.
4. A1 exit requires: all seven contract areas defined; cross-cutting constraints recorded; acceptance evidence mapped; unresolved decisions explicitly registered; and repository evidence reviewed against this baseline.
5. A1 closure does NOT mean localization has been implemented, tested or deployed. It authorizes A2 evidence reconciliation and implementation-contract preparation only after the baseline has been recorded and reviewed.

## 13. Initial decision register

| Decision | Baseline |
|---|---|
| Primary Ethiopia language | Amharic (am-ET) |
| Secondary Ethiopia language | English (en) |
| Ethiopia calendar default | Ethiopian calendar |
| Gregorian interoperability | Required |
| Ethiopia time zone default | Africa/Addis_Ababa |
| Ethiopia currency default | ETB |
| Numerals | Ethiopic and international digits |
| Name handling | Original script preserved; transliteration additive |
| African architecture | Country-aware profiles; no universal African locale |
| Knowledge priority | Amharic first; additional languages evaluated independently |
| Current implementation status | Not established by this contract; requires A2/A4 evidence |

**Binding principle:** IROKA must be usable, understandable and trustworthy in Amharic and its Ethiopian operating context from its foundations, while remaining architecturally adaptable to Africa's linguistic, legal and institutional diversity.
