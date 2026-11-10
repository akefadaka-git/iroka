# IROKA Ethical Intelligence and Human-Flourishing Programme — A3 Implementation Plan

**Document ID:** IROKA-ETHICS-PROSperity-A3-PLAN-001  
**Version:** 1.0.0  
**Status:** IMPLEMENTATION AUTHORIZED — IN PROGRESS  
**A2 parent:** `IROKA-ETHICS-PROSPERITY-A2-001 v1.0.0`  
**A1 parent commit:** `ece317f30bac1c09ddb6a136439651a959a9a612`  
**A3 branch:** `feat/ethical-prosperity-a3-foundation`  
**Base main SHA:** `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`

## 1. Implementation strategy

Implement small, reviewable increments in the existing IROKA architecture. Reuse the twelve canonical chromosomes and the trusted-kernel interfaces. Do not create parallel identity, authority, consent, reviewer, memory, delegation or audit registries.

The first vertical slice is a pure, deterministic Rust library surface inside `iroka-kernel` for evidence-source classification and observable behavioral assessment. It does not call models, persist data, make authorization decisions or perform side effects.

## 2. A3 increments

| Increment | Scope | Required evidence | Status |
|---|---|---|---|
| A3.1 | Ethical evidence taxonomy, provenance references, validation | Unit/contract tests; source-kind separation; malformed-input rejection | IMPLEMENTED — CI VERIFIED |
| A3.2 | Observable character traits and evidence-linked assessments | Adversarial tests; no scalar score; missing-evidence rejection | IMPLEMENTED — CI VERIFIED |
| A3.3 | Bounded operational self-model and verified/declared/inferred/unavailable claims | Evidence binding tests; no self-authorization | IMPLEMENTED — CI VERIFIED |
| A3.4 | Knowledge and cultural provenance, Maale/Amharic localization adapters | Provenance, licence, human-review and ambiguity tests | PARTIAL — metadata contracts CI VERIFIED; localization adapters remain |
| A3.5 | Teacher/mentor/advisor/researcher/coach/creator task profiles | Learning-quality and high-impact safeguard tests | IMPLEMENTED — CI VERIFIED |
| A3.6 | Prosperity intelligence and scenario models using synthetic inputs | Formula, sensitivity, downside and no-guarantee tests | IMPLEMENTED — CI VERIFIED |
| A3.7 | Candidate human-flourishing metric definitions and synthetic-only impact evaluation contracts | Baseline, adverse-outcome, small-cell disclosure, privacy boundary and correlation/causation tests | IMPLEMENTATION ADDED — EXACT-HEAD CI PENDING |
| A3.8 | Canonical G01–G12 adapter integration and cross-domain adversarial verification | Exact-provider binding, fail-closed, audit and independent review evidence | NOT STARTED |

## 3. A3.1/A3.2 implementation constraints

- Distinguish biblical primary text, theological interpretation, cultural tradition, empirical evidence, legal/policy material and generated synthesis.
- Do not encode a biblical corpus or declare a theological interpretation authoritative in code.
- Preserve language, source version, provenance and licence state as explicit metadata.
- Represent behavioral traits as observable categories and evidence-linked outcomes, not numeric virtue scores.
- Evidence assessments are assurance signals only and cannot grant access or override policy.
- Reject malformed records and references to missing evidence.
- No external dependencies, network access, database, model calls, persistent storage or production data in this first slice.
- Keep all existing G01/G02/G05/G11 and IGACMS interfaces authoritative.

## 4. Dependency and stop conditions

Stop or keep the affected feature disabled when:
- G01 reviewer-proof verification or G02 delegation authority is unavailable for a privileged path;
- G05 consent/reviewer provider is absent or incompatible;
- source licensing, community consent or language-review authority is unresolved;
- an implementation requires a real-person/community dataset;
- an operation would train a model, mutate canonical genome, activate durable memory or perform a protected effect;
- a change would modify existing constitutional ownership or bypass G11 evidence.

Open Owner decisions OD-01 through OD-08 and OD-10 remain gates as recorded in the A2 closure document. OD-09 is resolved by the previously approved roadmap.

## 5. Verification strategy

For every increment:
1. Add deterministic unit and adversarial tests.
2. Run formatting, compile, tests and Clippy on the exact branch head using repository CI where available.
3. Inspect exact workflow run/job evidence; do not infer success from a PR existing.
4. Review changed-file scope and ensure no unrelated branch work was modified.
5. Record exact commit SHA, tests, limitations and unresolved issues.
6. Keep the PR draft until implementation and review evidence justify a readiness change.

A4 requires independent review where applicable and is not completed by A3 CI. A5 release/deployment requires a separate explicit Owner authorization.

## 6. Verified implementation evidence

At exact PR head `b20cb0166cb1d720a2b7e5dd191e8ee10defc46c`, GitHub Actions Rust kernel verification run `42848561207` completed successfully. The job passed formatting, all-target compilation, the production-feature bypass check, the complete unit/contract suite and Clippy. This verifies the code at that exact commit only; it is not independent security assurance, A4 closure or production readiness.

A3.1/A3.2 evidence primitives and A3.3 operational self-model contracts are implemented and passed that exact-head CI run. A3.4 cultural-context metadata contracts also passed exact-head CI run `42849369832` at `93667e78a2e078944c79d85da8cc9878656f8aa4`. A3.4 remains partial: actual localization/conversion adapters and authoritative community review are not implemented. A3.5 task-profile and human-review safeguard contracts passed exact-head CI run `42850125260` at `5f5759cb7237a53e5101d433ece99e6980217e21`. A3.6 deterministic synthetic scenario arithmetic is implemented and exact-head CI verified at `1b00364f49d8949d10d4aa15e5543c77b50bc57f` by run `42851519555`.

## 7. Current increment and limitations

A3.1/A3.2 implement a minimal evidence taxonomy and evidence-linked behavioral review primitives in the existing Rust kernel. A3.3 adds bounded operational self-model claims. These are foundational interfaces only. They do not implement a full ethical reasoning engine, source corpus, cultural knowledge system, teaching product, prosperity engine or impact measurement system.


## 8. A3.4/A3.6 reconciliation — 2026-11-10

### A3.4 — PARTIAL, metadata foundation verified

The exact-scope evidence is run `42849369832` at commit `93667e78a2e078944c79d85da8cc9878656f8aa4`. It verifies the cultural-context metadata contracts. It does not verify a complete localization product or authoritative language content. Remaining work is limited by the A2 contract and OD-03:

- implement and test bounded, provenance-preserving localization/conversion adapter interfaces without inventing Maale orthography;
- preserve source values and expose ambiguity for script/calendar conversions; do not silently normalize uncertain forms;
- require qualified Maale language/community review before treating orthography, translations or community content as authoritative;
- do not create a programme-owned consent or reviewer registry; reuse canonical G05/G01/G02 providers when those providers are available and verified;
- keep real community data and durable retention disabled until the applicable consent, authority and data-governance gates are resolved.

### A3.6 — IMPLEMENTED, EXACT-HEAD CI VERIFIED

At code commit `1b00364f49d8949d10d4aa15e5543c77b50bc57f` (the pre-reconciliation implementation head), GitHub Actions run [42851519555](https://github.com/akefadaka-git/iroka/actions/runs/42851519555) completed successfully. Job `Format, compile, test and lint` passed checkout, stable Rust setup, formatting, all-target compilation, production-feature bypass check, complete unit/contract tests, Clippy and job completion. This is exact-commit CI evidence, not independent assurance, A4 closure or production readiness.

A3.6 remains synthetic-only operating scenario arithmetic. It does not include market-data ingestion, tax, capex, investment advice, guarantees, financial transactions or production forecasting.

### Reconciled disposition

- A3.4: `PARTIAL — METADATA CONTRACTS CI VERIFIED; LOCALIZATION ADAPTERS AND QUALIFIED MAALE COMMUNITY REVIEW OUTSTANDING`.
- A3.6: `IMPLEMENTED — EXACT-HEAD CI VERIFIED`.
- No A2 decision is reopened or changed. No new authority, consent, reviewer or localization registry is created by this reconciliation.
- A3.7 and A3.8 remain not started. A4 independent verification and A5 activation/deployment remain separate gates. PR #47 remains draft, open and unmerged.


## 10. A3.7 human-flourishing metric contracts — 2026-11-10

### Scope and Owner-decision boundary

A3.7 defines candidate measurement vocabulary and synthetic-only comparison contracts. It does not select final programme targets, collect real participant/community data, establish a baseline, certify impact, or authorize interventions. OD-06 remains OPEN: candidate indicators only; real data collection is deferred pending Owner decisions and privacy/consent governance.

Candidate domains represented by the technical vocabulary are education, livelihood, health access, food security, water access, dignity and fairness, community wellbeing, and environmental stewardship. These are measurement categories, not claims that IROKA currently improves these outcomes.

### Technical contracts

- Metric definitions require stable identifiers, domain, unit, directionality, numerator label, and denominator label for rate metrics.
- Aggregate observations are explicitly synthetic-only and cannot represent person-level records.
- Rate values are bounded to 0–10,000 basis points.
- Baseline/follow-up comparisons validate metric identity and units, calculate descriptive change, and distinguish improvement, deterioration, no change, and monitor-only signals.
- Adverse-outcome indicators can be represented explicitly; worsening adverse indicators are not hidden by positive aggregate movement.
- Small-cell suppression requires a nontrivial configured cohort threshold. It is a disclosure guard only, not differential privacy or proof of anonymization.
- The comparison primitive always reports causal attribution as not established. Temporal change is not proof of programme causation.

### Explicit limits

No real data ingestion, participant identifiers, subgroup profiling, durable retention, model training, health diagnosis, financial advice, intervention, or protected execution is added. The module does not determine the final metric set or thresholds. OD-04/OD-05/OD-06/OD-07/OD-08 remain open and continue to gate real-world programme deployment or data collection.
