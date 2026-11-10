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
| A3.4 | Knowledge and cultural provenance, Maale/Amharic localization adapters | Provenance, licence, human-review and ambiguity tests | IMPLEMENTED — CI PENDING |
| A3.5 | Teacher/mentor/advisor/researcher/coach/creator task profiles | Learning-quality and high-impact safeguard tests | NOT STARTED |
| A3.6 | Prosperity intelligence and scenario models using synthetic inputs | Formula, sensitivity, downside and no-guarantee tests | NOT STARTED |
| A3.7 | Human-flourishing metric definitions and impact evaluation | Baseline, adverse-outcome, privacy and correlation/causation tests | NOT STARTED |
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

A3.1/A3.2 evidence primitives and A3.3 operational self-model contracts are implemented and passed that exact-head CI run. A3.4 cultural-context metadata is now implemented; its exact-head verification is pending.

## 7. Current increment and limitations

A3.1/A3.2 implement a minimal evidence taxonomy and evidence-linked behavioral review primitives in the existing Rust kernel. A3.3 adds bounded operational self-model claims. These are foundational interfaces only. They do not implement a full ethical reasoning engine, source corpus, cultural knowledge system, teaching product, prosperity engine or impact measurement system.
