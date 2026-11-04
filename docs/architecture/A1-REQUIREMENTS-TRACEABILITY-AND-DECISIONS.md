# A1 Requirements Traceability and Decision Register

**Contract ID:** IROKA-A1-TRACE-001  
**Status:** Binding A1 governance register  
**Parent:** [A1 Amharic-First Ethiopian and African Architecture Contract](A1-AMHARIC-FIRST-REGIONAL-ARCHITECTURE-CONTRACT.md)  
**Supporting contract:** [Regional Deployment Profile Contract](REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md)

## 1. Requirements traceability

| Requirement family | Binding source | Owning architecture area | Required A2 artifact | Release evidence |
|---|---|---|---|---|
| Language and translation lifecycle | L.1–L.4 | Client platform / content services | Language-resource schema, fallback and translation-review contract | Reviewed Amharic coverage, critical strings and fallback tests |
| Ethiopic script and typography | L.2 | Client platform / renderer | Unicode and font-support matrix | Ethiopic corpus round-trip and rendering evidence |
| Numerals and locale formatting | LOC | Localization / API boundary | Parsing and formatting contract | Ethiopic/international numeral tests without value drift |
| Regional profile model | REG, REG-002 | Platform configuration | Versioned profile schema and resolver | Profile conformance, provenance and upgrade tests |
| Ethiopian calendar | CAL | Date/time domain | Calendar adapter and supported-date contract | Vetted implementation and boundary tests |
| Gregorian interoperability | CAL | Date/time / integrations | Conversion and API semantics | Round-trip and interoperability tests |
| Time-zone semantics | CAL | Date/time domain | Instant/local-date/local-date-time API contract | UTC persistence and local rendering tests |
| Identity and names | ID | Identity / directory | Person-name and identity representation contract | Ethiopic names, ordering, alias and non-merge tests |
| Documents and records | DOC | Documents / records | Rendering, numbering, retention and provenance contracts | Amharic office/PDF rendering, archive and export tests |
| OCR and extraction | DOC | Perception / document intelligence | Amharic OCR evaluation and human-review contract | Corpus accuracy, confidence and correction evidence |
| Knowledge and retrieval | KNOW | Knowledge / memory / retrieval | Amharic ingestion, chunking, indexing and evaluation contract | Amharic and mixed-language retrieval/citation benchmark |
| Regional and legal boundaries | REG | Governance / deployment | Jurisdiction policy-reference and local-review contract | Qualified review, effective dates and unresolved-rule handling |
| Security invariants | Cross-cutting | Kernel / security / assurance | Localization security threat model | Tenant isolation, access, audit and retention regression |

## 2. Decision register

| ID | Decision | A1 baseline | State |
|---|---|---|---|
| A1-D01 | Product language strategy | Amharic-first; English supported | SET |
| A1-D02 | Ethiopia locale | `am-ET` primary; `en` secondary | SET |
| A1-D03 | Script integrity | Ethiopic first-class; UTF-8 canonical interchange | SET |
| A1-D04 | Numeral support | Ethiopic and international digits | SET |
| A1-D05 | Ethiopia calendar | Ethiopian calendar default; Gregorian interoperability | SET |
| A1-D06 | Ethiopia time zone | `Africa/Addis_Ababa` default | SET |
| A1-D07 | Ethiopia currency | `ETB` default; multi-currency architecture | SET |
| A1-D08 | Identity names | Original script preserved; transliteration additive | SET |
| A1-D09 | African regionalization | Independent country/subnational profiles; no universal African locale | SET |
| A1-D10 | Amharic knowledge | First-class ingestion, indexing, retrieval and evaluation | SET |
| A1-D11 | Speech | Prioritized, but separately evaluated by language/dialect | SET |
| A1-D12 | Legal/regulatory content | Jurisdiction-scoped, versioned and locally reviewed | SET |
| A1-D13 | Concrete implementation libraries | Deferred to A2 evidence and compatibility review | OPEN |
| A1-D14 | Ethiopian calendar implementation | Deferred to A2 conformance evaluation | OPEN |
| A1-D15 | Translation and terminology governance | Workflow/reviewer authority to be specified in A2 | OPEN |
| A1-D16 | Amharic OCR thresholds | Corpus and thresholds to be approved before evaluation | OPEN |
| A1-D17 | Knowledge benchmark thresholds | Dataset, dialect scope and thresholds to be approved before evaluation | OPEN |
| A1-D18 | Country legal/data residency matrix | Qualified local research and review required | OPEN |
| A1-D19 | Additional African launch profiles | Country selection and evidence deferred to A2 | OPEN |
| A1-D20 | Offline synchronization/revocation guarantees | Maximum staleness and conflict policy deferred to A2 | OPEN |

## 3. Explicit non-decisions

A1 does not select or certify a particular calendar/localization/OCR/speech/embedding/search library; any country's legal compliance or data-residency conclusion; pan-African language or dialect coverage; model accuracy thresholds; or production readiness. These require controlled A2/A4 evidence.

## 4. Requirement change control

Any change to a SET decision or mandatory requirement MUST record the requirement ID, proposed change, rationale, affected countries/languages/tenants/records/interfaces, compatibility and migration analysis, security/privacy/legal impact, acceptance-test changes, risk owner, approval authority and effective version. No requirement may be weakened solely because implementation is difficult or a dependency lacks support.

## 5. A1 exit checklist

- [x] Language and script requirements defined.
- [x] Localization and profile requirements defined.
- [x] Calendar and time semantics defined.
- [x] Identity and name requirements defined.
- [x] Document and records requirements defined.
- [x] Knowledge and retrieval requirements defined.
- [x] African regional architecture requirements defined.
- [x] Cross-cutting security and data constraints defined.
- [x] Acceptance evidence mapped to requirement families.
- [x] Open decisions explicitly recorded.
- [ ] Repository implementation inventory reconciled against every requirement.
- [ ] Owner review and formal A1 closure recorded.

The final two items are evidence/review gates. Documentation alone cannot satisfy them.

## 6. Gate rule

A1 completion means the requirements baseline is sufficiently defined to begin A2 reconciliation. It does not mean requirements are implemented, verified, deployed or production-ready. A2 MUST preserve this baseline unless authoritative evidence establishes a material contradiction and the Owner approves a versioned change.
