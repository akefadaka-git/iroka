# A2 — Amharic-First and African Regional Implementation Contracts

**Contract ID:** IROKA-A2-IMPL-001  
**Version:** 0.1.0  
**Status:** Normative implementation contract baseline; no runtime implementation authorized by this document alone  
**Parent:** IROKA-A1-REGIONAL-001  
**Applies to:** Kernel-adjacent platform services, clients, APIs, data stores, document and knowledge pipelines, integrations and deployment configuration

## 1. Conformance and design rules

1. A1 remains the governing requirement. If this document is ambiguous or weaker, A1 prevails.
2. These are logical contracts. Implementations may use different languages, databases or wire formats only if they preserve the semantics and pass the acceptance plan.
3. No regional default may be embedded in shared domain logic. Shared services consume a resolved, versioned profile.
4. Source values and canonical typed values are authoritative. Localized display values, transliterations, OCR, translations, summaries and embeddings are derived representations with provenance.
5. No lossy conversion may overwrite source data. Every transformation records its algorithm/provider version, input hash and output hash.
6. Unsupported or ambiguous interpretation must be explicit. High-impact operations fail closed rather than guessing.
7. All records that affect authorization, legal meaning, money, identity or audit must carry the profile and policy context needed to interpret them historically.
8. Security semantics are invariant across locales and regions. Localization must never change authorization, tenant isolation, audit, retention or cryptographic validation.

## 2. Logical service boundaries

| Contract | Service boundary | Owns | Must not own |
|---|---|---|---|
| L10N | Language and content resources | Resource keys, language tags, translations, review lifecycle and fallback | User identity, legal policy or model-generated authority |
| LOC | Locale formatting | Typed-value parsing/formatting, numeral and collation policies | Mutation of canonical values |
| REG | Regional profile registry/resolver | Versioned deployment profiles, provenance, precedence and effective dates | Unreviewed legal conclusions |
| CAL | Calendar/time | Calendar dates, instants, local date/time and conversions | UI-specific display strings |
| IDN | Person identity and names | Person records, original-script names, aliases and verified mappings | G01 service credentials or trust roots |
| DOC | Documents and records | Original files, derivatives, templates, numbering, retention metadata | Treating extracted text as original evidence |
| OCR | Document perception | Detection, OCR candidates, confidence and human-review state | Silent acceptance of low-confidence text |
| KNOW | Knowledge ingestion/retrieval | Provenance, source permissions, chunks, retrieval and citations | Authority to override source access controls |
| ASSURE | Cross-cutting assurance | Evaluation evidence, security regression and conformance reports | Self-approval of Owner-controlled policy |

## 3. L10N — Language resource contract

### 3.1 Resource record

Every translatable resource MUST have:
- `resource_key`: stable, non-localized identifier.
- `source_language`: BCP 47 language tag.
- `source_text`: immutable source string for that resource version.
- `translations[]`: language tag, translated text, version, status, reviewer, reviewed_at and source_version.
- `criticality`: ordinary, important or safety_critical.
- `context`: product surface, usage notes, placeholder schema and plural/gender constraints where applicable.
- `effective_from` and optional `retired_at`.

Translation states: `DRAFT`, `MACHINE_PROPOSED`, `IN_REVIEW`, `HUMAN_APPROVED`, `REJECTED`, `RETIRED`.

Machine-generated text MUST remain `MACHINE_PROPOSED` until reviewed. Critical security, consent, financial and governance strings require human approval. A missing translation follows the declared fallback chain but is visibly recorded as fallback; no fallback may masquerade as reviewed Amharic.

### 3.2 Locale selection

The resolved language is explicit and persisted. Resolution order:
1. Explicit operation/document language where allowed.
2. User preference.
3. Organization preference.
4. Deployment primary language.
5. Configured secondary fallback.

Mandatory safety/legal/security text uses the approved language resource for the applicable deployment and cannot be overridden by an unreviewed preference. Locale is not inferred from name, ethnicity, IP address or location.

## 4. LOC — Canonical value and formatting contract

1. APIs accept typed values plus an explicit locale/context when parsing is locale-sensitive.
2. Numeric values are stored as integer/decimal representations with explicit scale where relevant; formatted strings are never computational inputs.
3. Currency values carry ISO 4217 currency code, amount and precision. Exchange-rate records carry source, rate type, observed_at and base/quote currency.
4. Ethiopic and Western digit parsing/formatting are supported for the Ethiopia profile. Ambiguous separators or malformed input return a typed validation error; they are never guessed.
5. Unicode source text is preserved. Search normalization creates a separate derived key and records normalization version.
6. Collation, sorting and search modes are explicit: exact, normalized and optional transliterated/fuzzy. Fuzzy matching is advisory only.

## 5. REG — Regional profile contract

A profile is an immutable, versioned record with:
- `profile_id`, `version`, `status`, `effective_from`, `effective_until`.
- `jurisdiction.country` and optional `subnational[]`.
- `languages.primary`, `languages.supported[]`, review status and supported workflow level.
- `scripts[]`, font/rendering requirements and directionality.
- `calendar.default`, `calendar.supported[]`.
- `time_zone.default` as an IANA identifier.
- `currencies.default`, `currencies.supported[]` as ISO codes.
- numeral, decimal, grouping, date-display and collation policies.
- address and phone schemas with version identifiers.
- document conventions and numbering policy references.
- legal/regulatory references with jurisdiction, source, effective interval, reviewer and review status.
- data-governance references for residency, transfers, retention and classification.
- provenance: author, maintainer, reviewer, evidence URI/hash and reviewed_at.

Profile resolution returns the complete resolved profile, immutable version, provenance and any unresolved mandatory fields. Precedence is: non-overridable legal/security/records obligations → deployment profile → organization preferences → user preferences → request formatting. An unresolved mandatory field blocks the affected operation.

Profile updates create a new version; they never mutate a published version. Records store the profile version used at creation or material interpretation. Historical records are not silently reinterpreted.

### 5.1 Ethiopia profile fixture

The conformance fixture MUST set `am-ET` primary, `en` secondary, Ethiopic and Latin scripts, Ethiopian calendar default, Gregorian interoperability, `Africa/Addis_Ababa`, ETB, and Ethiopic plus Western digits. Legal and data-residency fields remain explicitly unresolved until qualified review; the fixture is not a compliance certification.

### 5.2 Second African profile fixture

A second non-Ethiopian fixture MUST be used to prove separation of country assumptions. The initial test fixture may use Kenya with English and Swahili, Gregorian calendar, `Africa/Nairobi` and KES. It is a technical conformance fixture only, not a legal or market-support claim. Its jurisdictional legal/data-governance fields remain `UNREVIEWED` until local review.

## 6. CAL — Calendar and time contract

Every temporal value has a semantic discriminator:
- `Instant`: UTC instant; rendered using selected zone and calendar.
- `LocalDate`: date-only value with explicit calendar identifier.
- `LocalDateTime`: wall-clock date/time, calendar, IANA zone and ambiguity policy.
- `CalendarDate`: year/month/day plus named calendar and calendar implementation/version.

Conversion operations return converted value, source semantics, target semantics, implementation/version and conversion status. Original entered value and calendar context remain available. Invalid dates, ambiguous local times and unsupported calendars return typed errors. Recurrences are expressed in local calendar/time-zone terms and resolved occurrence-by-occurrence; fixed-second addition is not an acceptable recurrence model.

## 7. IDN — Person identity and names contract

A person record separates:
- immutable `person_id`;
- original/native name value and script;
- optional structured name components, each retaining source order;
- optional preferred display name and display order;
- optional transliteration with method, language/script tag and provenance;
- aliases with source and verification state;
- verified identity references and evidence;
- tenant scope, lifecycle state and audit metadata.

The original supplied name is immutable evidence unless corrected through an auditable, authorized correction event. No Western first/middle/last assumption is mandatory. No family-name field is required. Fuzzy matching may produce candidate suggestions but cannot prove identity or merge records. Merge/duplicate resolution requires authorized human review, recorded evidence and a reversible/compensatable operation. G01 credential subject identifiers remain separate from person records.

## 8. DOC — Document and records contract

A document record includes stable document ID, tenant, owner, document class, source language, profile version, original file hash, original storage reference, retention class, access classification, created_at instant and audit provenance.

Every derivative (rendered PDF, extracted text, translation, preview, OCR transcript) records source hash, transformation type, tool/model/version, parameters, output hash, created_at and review status. The original remains retrievable subject to approved retention/legal-hold policy. Display numbering is generated by a versioned policy and is never the primary key.

Templates declare language, calendar, numeral and regional-profile requirements. Critical templates require human review. PDF/office outputs must preserve Ethiopic glyphs and provide selectable/searchable text where the format supports it.

## 9. OCR — Extraction and human verification contract

OCR output is a candidate derivative, never the source document. Each page/region result includes detected language/script (including unknown/mixed), extracted text, confidence, model/engine/version, source page/region, source hash, quality flags and review state.

Review states: `PENDING_REVIEW`, `ACCEPTED`, `CORRECTED`, `REJECTED`. Low-confidence output cannot populate authoritative identity, legal, financial or governance fields without human confirmation. Corrections retain the original OCR result and reviewer attribution.

## 10. KNOW — Knowledge and retrieval contract

Each source item stores stable source ID, tenant, source reference, content hash, acquired_at, source language/script (unknown/mixed allowed), rights/consent basis, access classification, retention policy and provenance. Every derived chunk, translation, summary and embedding links to the source ID/hash and transformation version.

Retrieval MUST enforce source permissions before ranking or generation. Results identify original versus translated/derived passages, source version and exact citation span. A citation must resolve to the source evidence it claims to represent. Conflicting sources remain separately addressable; model confidence does not resolve authority conflicts.

## 11. Cross-cutting API, persistence and audit rules

1. APIs distinguish canonical values from localized display values and include semantic identifiers where ambiguity is material.
2. UTF-8 is the canonical interchange encoding. Database, queue, logs and export paths must preserve Unicode without replacement or lossy transliteration.
3. Material operations record profile ID/version, locale, calendar semantics and transformation provenance where relevant.
4. Audit timestamps are UTC instants; user-facing rendering is separate.
5. Tenant and source authorization are checked before data access, indexing, retrieval, rendering or export.
6. Errors have stable machine codes and reviewed localized messages. The machine code is invariant across languages.
7. Profile and translation changes are auditable and cannot be initiated by a model or agent acting without authorized governance.
8. Data minimization applies to evaluation corpora; personal data requires documented lawful/consented use and access control.

## 12. Implementation and dependency selection gates

No library is selected by this contract. A2 dependency review MUST score candidate libraries for:
- Unicode/Ethiopic correctness and CLDR/ICU interoperability;
- Ethiopian calendar correctness and documented epoch/leap semantics;
- supported language/script coverage and rendering stack compatibility;
- license compatibility with repository distribution and deployment;
- security history, maintenance activity, release cadence and transitive dependency risk;
- offline operation, deterministic behavior, portability and resource footprint;
- test corpus availability and ability to reproduce conformance results.

Selection requires a recorded comparison, pinned version, license record, threat/dependency review, adapter boundary and fallback/upgrade plan. Handwritten calendar conversion and silent library substitution are prohibited.

## 13. Contract change control

A2 contract changes that weaken A1, alter identity authority, legal interpretation, security invariants, retention or profile precedence require explicit Owner approval. Implementation teams may propose extensions but cannot silently change normative semantics. No production capability claim is permitted without acceptance evidence tied to exact code, test data and dependency versions.
