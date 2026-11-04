# A1 Requirements Traceability and Decision Register

**Contract ID:** IROKA-A1-TRACE-001  
**Status:** Binding A1 governance register  
**Parent contract:** [A1 Amharic-First Ethiopian and African Architecture](A1-AMHARIC-FIRST-ETHIOPIAN-AFRICAN-CONTRACT.md)  
**Supporting contract:** [Regional Deployment Profile Contract](REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md)

## 1. Traceability matrix

| Requirement family | Binding source | Owning architecture area | Required A2 artifact | Verification evidence required before release |
|---|---|---|---|---|
| Language and translation lifecycle | L10N-01 | Client platform / content services | Language-resource schema, fallback and translation-review contract | Amharic workflow coverage, reviewed critical strings, fallback tests |
| Ethiopic script and typography | L10N-01 | Client platform / document renderer | Unicode and font-support matrix | Ethiopic corpus round-trip and rendering evidence |
| Numerals and locale formatting | L10N-01 | Localization service / API boundary | Parsing and formatting contract | Ethiopic/international numeral tests with no value drift |
| Regional profile model | L10N-02, REG-01, REG-002 | Platform configuration | Versioned profile schema and resolution algorithm | Profile conformance, version provenance and upgrade tests |
| Ethiopian calendar | CAL-01 | Date/time domain service | Calendar adapter and supported-date contract | Vetted implementation conformance and boundary tests |
| Gregorian interoperability | CAL-01 | Date/time domain service / integrations | Conversion and API semantics | Round-trip and external interoperability tests |
| Time-zone semantics | CAL-01 | Date/time domain service | Instant/local-date/local-date-time API contract | UTC persistence and local rendering tests |
| Identity and names | ID-01 | Identity / directory | Person-name and identity-representation contract | Ethiopic names, ordering, alias and duplicate-review tests |
| Documents and records | DOC-01 | Document / records | Rendering, numbering, retention and provenance contracts | Amharic office/PDF rendering, archive and export tests |
| OCR and extraction | DOC-01 | Perception / document intelligence | Amharic OCR evaluation and human-review contract | Corpus-based accuracy, confidence and correction evidence |
| Knowledge and retrieval | KNOW-01 | Knowledge / memory / retrieval | Amharic ingestion, chunking, indexing and evaluation contract | Amharic and mixed-language retrieval/citation benchmark |
| Regional and legal boundaries | REG-01 | Governance / deployment | Jurisdiction policy-reference and review contract | Qualified local review, effective-date and unresolved-rule handling |
| Security invariants | Cross-cutting constraints | Kernel / security / assurance | Localization security threat model | Tenant isolation, access, audit and retention regression |

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
| A1-D11 | Speech | Amharic speech recognition/synthesis prioritized but separately evaluated | SET |
| A1-D12 | Legal/regulatory content | Jurisdiction-scoped, versioned and locally reviewed | SET |
| A1-D13 | Concrete implementation libraries | Deferred to A2 evidence and compatibility review | OPEN |
| A1-D14 | Ethiopian calendar implementation selection | Deferred to A2 conformance evaluation | OPEN |
| A1-D15 | Translation and terminology governance | Workflow and reviewer authority to be specified in A2 | OPEN |
| A1-D16 | Amharic OCR quality thresholds | Dataset and thresholds to be approved before evaluation | OPEN |
| A1-D17 | Knowledge benchmark thresholds | Dataset, dialect scope and thresholds to be approved before evaluation | OPEN |
| A1-D18 | Country legal/data residency matrix | Qualified local research and review required | OPEN |
| A1-D19 | Additional African launch profiles | Country selection and evidence deferred to A2 | OPEN |

## 3. Explicit non-decisions

The A1 baseline does NOT select or certify:

- A particular calendar, ICU, localization, OCR, speech, embedding or search library.
- A legal interpretation, regulatory compliance position or data-residency conclusion for any country.
- Pan-African language coverage or universal dialect coverage.
- OCR, speech recognition, translation or retrieval accuracy thresholds.
- A specific country launch sequence beyond the Ethiopia baseline.
- Production readiness of the current software.

These are controlled A2/A4 decisions and require evidence.

## 4. Requirement change control

Every proposed change to a SET decision or mandatory requirement MUST include:

1. Requirement/decision ID and exact proposed change.
2. Technical, user, operational and regional rationale.
3. Affected countries, languages, tenants, records and interfaces.
4. Compatibility and migration analysis.
5. Security, privacy, legal and data-governance impact.
6. Acceptance-test changes and evidence.
7. Risk owner, approval authority and effective version.

No requirement may be weakened solely because an implementation is difficult or a current dependency lacks support.

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
- [ ] Repository-wide implementation inventory reconciled against every requirement.
- [ ] Owner review and formal A1 closure recorded.

The final two items are evidence/review gates, not missing architecture domains. Documentation alone cannot satisfy them.

## 6. Gate rule

A1 completion means the architecture baseline is sufficiently defined to begin A2 reconciliation. It does not mean A1 requirements are implemented, verified, deployed or production-ready. A2 MUST preserve this baseline unless a material contradiction is supported by authoritative evidence and approved through change control.
