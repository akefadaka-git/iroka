# A2 — Amharic/Ethiopic and Regional Acceptance Test Plan

**Contract ID:** IROKA-A2-TEST-001  
**Version:** 0.1.0  
**Status:** Pre-implementation acceptance baseline  
**Parent:** IROKA-A1-REGIONAL-001; IROKA-A2-IMPL-001

## 1. Purpose and test governance

This plan freezes measurable acceptance criteria before implementation and before evaluation results are observed. Thresholds must not be relaxed after a failed run merely to obtain a pass. Any proposed change requires a versioned change request, rationale, impact analysis and Owner approval where it changes A1 obligations.

Test results are valid only when they identify:
- exact source commit SHA and build/toolchain;
- dependency/model/renderer versions and configuration;
- dataset ID, version, license/consent basis, split and content hash;
- test command, environment and run URL/log;
- metric definition, denominator, threshold and measured result;
- reviewer and disposition for exceptions.

Datasets must be legally usable, consented where required, de-identified where possible, tenant-isolated and documented. Public availability alone is not proof of permission for every processing purpose. Test corpus authorship, dialect/region, genre, print quality and annotation method must be recorded.

## 2. Mandatory deterministic conformance gates

| ID | Test domain | Minimum fixture / coverage | Pass threshold |
|---|---|---|---|
| UNI-01 | Unicode source preservation | At least 2,000 strings spanning Ethiopic syllabics, punctuation, combining marks, extended characters, Latin, digits and mixed text | 100% byte/code-point-preserving round trip through storage, API, queue, search source field and export; zero replacement characters or dropped marks |
| UNI-02 | Normalization isolation | Corpus includes canonically equivalent and visually similar but distinct strings | 100% original-source preservation; normalized keys are separate and versioned; zero source mutation |
| UI-01 | Ethiopic rendering | At least 500 representative strings across supported font/browser/device matrix | Zero missing-glyph tofu, clipping, overlap or lost marks in approved viewport matrix; all defects blocking |
| UI-02 | Text interaction | 200 scripted cases for cursor movement, selection, copy/paste, wrapping, scaling and mixed-script input | 100% pass; no corruption or inaccessible critical control |
| NUM-01 | Numeral parsing/formatting | At least 500 values including Ethiopic/Western digits, signs, decimals, grouping, percentages and malformed/ambiguous input | 100% exact numeric-value preservation; 100% malformed/ambiguous inputs rejected or explicitly disambiguated |
| CAL-01 | Ethiopian/Gregorian conversion | Exhaustive day-level conversion over supported product date range; initial baseline 1900-01-01 through 2100-12-31 Gregorian, plus explicit out-of-range cases | 100% valid dates convert; 100% round-trip to same civil day; 100% invalid dates rejected; independent reference oracle |
| CAL-02 | Calendar boundaries | Ethiopian New Year, Pagume, leap-year transitions, month ends, Gregorian leap days and century boundaries | 100% expected outcomes against approved independent reference vectors |
| TIME-01 | Instant and local-time semantics | UTC persistence, Africa/Addis_Ababa rendering, date-only and local date-time fixtures | 100% expected instant/rendering; date-only values never acquire an implicit time or UTC shift |
| TIME-02 | Recurrence | Monthly/yearly local-calendar events and zone transitions for all supported profiles | 100% expected wall-clock occurrences; no fixed-seconds recurrence drift |
| IDN-01 | Name fidelity | At least 1,000 synthetic or consented records with original-script, unstructured, varied component order and aliases | 100% original name preservation; zero forced transliterations; zero requirement for family name |
| IDN-02 | Identity matching | At least 500 duplicate/non-duplicate pairs, including same-name different-person and transliteration collision cases | Zero automatic merges; 100% candidate suggestions clearly non-authoritative; every merge requires auditable authorization |
| L10N-01 | Critical translations | 100% of security, consent, safety, financial and governance strings inventoried | 100% human-reviewed and approved before production; zero machine-only critical strings |
| L10N-02 | Primary workflow language | All P0 workflows plus at least 95% of all visible user-facing strings | 100% reviewed Amharic coverage for P0; >=98% reviewed coverage for remaining in-scope UI; unreviewed fallback visibly identified |
| DOC-01 | Document rendering | At least 100 documents across letters, tables, long text, mixed language, Ethiopic digits and headers/footers | Zero missing glyphs, text clipping, pagination corruption or identifier loss; all critical templates human-reviewed |
| DOC-02 | Document round-trip | 100 source files across supported formats | Original hash preserved 100%; derivative links to source hash and tool/version 100%; searchable/selectable text where format supports it |
| SEC-01 | Authorization invariance | Full localization/profile test suite with cross-tenant and unauthorized access probes | Zero cross-tenant disclosure; zero permission bypass; zero weakening of approval, revocation, audit or retention checks |
| REG-01 | Profile conformance | Ethiopia fixture plus at least one distinct African profile fixture (initial technical fixture: Kenya) | 100% required schema validation; 100% deterministic precedence; zero Ethiopia-only default leakage into shared services |
| REG-02 | Profile lifecycle | Version upgrade, expiry, missing legal reference, stale cache and rollback scenarios | 100% historical version interpretability; mandatory unresolved obligations fail closed; stale profile invalidation meets configured bound |
| AUD-01 | Provenance | All locale, calendar, OCR, document and knowledge transformations | 100% of material derived records contain source hash, transform/version, timestamp and actor/system provenance |

## 3. Amharic OCR evaluation

### 3.1 Dataset
Before model selection is finalized, freeze a representative, rights-cleared dataset containing at least:
- 1,000 pages of printed Amharic;
- 10,000 manually transcribed lines;
- at least 3 document genres (e.g. narrative prose, forms/tables, official/business documents);
- clean, skewed, low-resolution and moderately degraded capture conditions;
- a held-out test split not used for training, tuning or threshold selection.

Record script, typography, print/capture condition, genre and annotation adjudication. Do not claim handwriting support from this printed-text test.

### 3.2 Metrics and pass thresholds
- Character Error Rate (CER) <= 5% on clean printed pages.
- CER <= 12% on the defined degraded-print subset.
- Word Error Rate (WER) <= 10% on clean printed pages.
- WER <= 20% on the defined degraded-print subset.
- At least 95% of pages must include calibrated confidence and page/region provenance.
- 100% of low-confidence or critical-field OCR results must enter human review; zero silent promotion to authoritative data.
- Report per-genre and per-condition results; aggregate scores cannot hide a failed subset.

The test owner must publish CER/WER tokenization and normalization rules before scoring. Human reference transcription must be independently checked; disagreements are adjudicated before test execution.

## 4. Amharic knowledge/retrieval evaluation

### 4.1 Dataset and task set
Freeze at least 1,000 Amharic or mixed Amharic-English query/evidence cases, with:
- source passages and exact answer-supporting spans;
- answerable, unanswerable and conflicting-source cases;
- multiple genres and a documented language/dialect/orthography profile;
- tenant and access-control labels;
- at least two independent annotators per case and adjudication for disagreements.

The held-out set must remain inaccessible to tuning. English-only benchmarks do not satisfy this gate.

### 4.2 Metrics and pass thresholds
- Recall@10 >= 0.90 on answerable cases.
- nDCG@10 >= 0.80 using adjudicated graded relevance.
- Citation span precision >= 0.95.
- Citation span recall >= 0.90.
- Unsupported factual claim rate <= 2% on the held-out answer set.
- Unanswerable-case correct abstention >= 95%.
- Cross-tenant unauthorized retrieval: zero successful disclosures in the security test suite.
- Original versus translated/derived source labeling: 100% correct.

Report per-language/mixed-language and per-genre slices. No pan-African language claim may be inferred from Amharic results.

## 5. Speech capability gates

Speech recognition and speech synthesis are separate capabilities and require separate datasets, metrics and support declarations. Before any Amharic speech release claim:
- define dialect and speaker coverage explicitly;
- collect a rights-cleared, consented held-out speech corpus;
- report WER for recognition by dialect, noise condition and speaker group;
- report intelligibility and human-rated pronunciation/meaning preservation for synthesis;
- define minimum sample sizes and thresholds in a versioned speech annex before testing.

Until that annex and evidence exist, speech status remains NOT_VERIFIED; no numerical quality claim is permitted.

## 6. Regional conformance and anti-assumption tests

The initial Ethiopia and Kenya fixtures are technical profile fixtures, not declarations of legal compliance or full country support.

Required tests:
1. Change country profile without changing shared domain code; profile resolution must supply the correct language, calendar, zone, currency and address conventions.
2. Change user language without changing country, legal jurisdiction, stored source text or calendar semantics.
3. Change display calendar without mutating canonical instants or source-entered calendar dates.
4. Change display currency without mutating transaction/ledger currency or amount.
5. Expire or remove a required legal/data-governance reference; affected regulated operation must fail closed.
6. Verify a regional extension cannot alter identity authority, cryptographic trust, tenant isolation, audit or retention invariants.
7. Verify country, language, script, calendar and currency are independently configurable; no one is inferred from another.

Pass: 100% of deterministic profile tests; zero hardcoded Ethiopia-only branches in shared profile-driven services, established through static inspection and mutation tests.

## 7. Accessibility and human review

- User-facing critical workflows must meet WCAG 2.2 AA for applicable criteria.
- All P0 workflows must be keyboard operable and expose meaningful accessible names/roles/states.
- Ethiopic text must remain readable at 200% zoom without loss of critical content or function.
- Human reviewers must be identified by role, competence, review date and decision. Automated scores do not replace required legal, terminology or document review.

## 8. Gate result semantics

Each test is recorded as PASS, FAIL, BLOCKED, NOT RUN or NOT APPLICABLE with evidence. A missing corpus, missing independent oracle, missing reviewer or missing exact-SHA run is BLOCKED/NOT RUN, never PASS. Averages cannot mask a failed critical slice. All blocking failures must be fixed and rerun against the exact candidate SHA.

## 9. Pre-implementation freeze checklist

- [ ] A2 implementation contracts reviewed against A1.
- [ ] Dataset sources, permissions, privacy and retention documented.
- [ ] Test corpus IDs, hashes, splits and annotation protocols frozen.
- [ ] Independent calendar reference vectors selected and versioned.
- [ ] OCR and retrieval metric definitions frozen.
- [ ] Thresholds approved before any threshold-setting evaluation run.
- [ ] Ethiopia and second-country profile fixtures reviewed.
- [ ] Critical Amharic terminology and translation reviewers assigned.
- [ ] Security regression scenarios mapped to existing G01/G02/G11 controls.
- [ ] Candidate library evaluation criteria and license/security review plan agreed.

**No implementation acceptance may be declared until this plan is executable, reproducible and tied to the exact implementation SHA.**
