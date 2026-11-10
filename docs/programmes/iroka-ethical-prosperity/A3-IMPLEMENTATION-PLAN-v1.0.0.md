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
| A3.4 | Knowledge and cultural provenance, Maale/Amharic localization adapters | Provenance, licence, human-review and ambiguity tests | IMPLEMENTED — TECHNICAL ADAPTERS EXACT-COMMIT CI VERIFIED; AUTHORITATIVE MAALE CONTENT REVIEW PENDING |
| A3.5 | Teacher/mentor/advisor/researcher/coach/creator task profiles | Learning-quality and high-impact safeguard tests | IMPLEMENTED — CI VERIFIED |
| A3.6 | Prosperity intelligence and scenario models using synthetic inputs | Formula, sensitivity, downside and no-guarantee tests | IMPLEMENTED — CI VERIFIED |
| A3.7 | Human-flourishing metric definitions and impact evaluation | Baseline, adverse-outcome, privacy and correlation/causation tests | IMPLEMENTED — EXACT-COMMIT CI VERIFIED; CANDIDATE METRICS ONLY, OD-06 OPEN |
| A3.8 | Canonical G01–G12 adapter integration and cross-domain adversarial verification | Exact-provider binding, fail-closed, audit and independent review evidence | PARTIAL — provider reconciliation complete; G01 reviewer-proof and G02 organization-delegation providers remain missing; G11 memory-lifecycle adapter is a separate unmerged candidate |

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


## 8. A3.4/A3.6/A3.7 implementation reconciliation — 2026-11-10

### A3.4 — TECHNICAL IMPLEMENTATION VERIFIED; COMMUNITY CONTENT AUTHORITY PENDING

- Localization adapter implementation passed exact-commit GitHub Actions run [42867694535](https://github.com/akefadaka-git/iroka/actions/runs/42867694535) at tested code commit `caf183039a70ac9a10b8cb76e1b2cfe80132c5bb`.
- The implementation preserves source text and provenance, records candidate translation/review evidence without authenticating reviewer authority, fails closed on unsupported script conversion, and provides deterministic Ethiopian/Gregorian conversion with boundary and leap-day tests.
- No Maale orthography, translation or cultural claim is asserted as authoritative. Qualified reviewers/community authority have been identified by the Owner, but signed/documented review evidence has not been verified in this repository.
- PR #48 remains OPEN, DRAFT and UNMERGED. Community review and its evidence gate remain pending; no real community data or durable retention is enabled.

### A3.6 — IMPLEMENTED; EXACT-COMMIT CI VERIFIED

- Synthetic-only scenario arithmetic passed run [42851519555](https://github.com/akefadaka-git/iroka/actions/runs/42851519555) at `1b00364f49d8949d10d4aa15e5543c77b50bc57f`.
- No market-data ingestion, tax model, capex, investment advice, guarantees, financial transactions or production forecasting is included.

### A3.7 — IMPLEMENTED; EXACT-COMMIT CI VERIFIED

- Candidate human-flourishing metric definitions and synthetic aggregate-only baseline/follow-up comparisons passed run [42869939448](https://github.com/akefadaka-git/iroka/actions/runs/42869939448) at tested implementation commit `e412d491f12d439ae24e149b35ba901b780435b1`.
- Eight candidate domains are covered: education, livelihood, health access, food security, water access, dignity/fairness, community wellbeing and environmental stewardship.
- Contract tests cover metric validation, rate bounds, suppression behavior, adverse-outcome deterioration, mismatches and non-causal interpretation.
- OD-06 remains OPEN. These are candidate metrics only; no real-world data collection, participant-level data or causal impact claim is authorized. Small-cell suppression is not differential privacy or a guarantee of anonymization.
- PR #49 remains OPEN, DRAFT and UNMERGED.

### Reconciled disposition

- A3.4: `TECHNICAL IMPLEMENTATION — EXACT-COMMIT CI VERIFIED; AUTHORITATIVE MAALE CONTENT REVIEW — PENDING`.
- A3.6: `IMPLEMENTED — EXACT-COMMIT CI VERIFIED`.
- A3.7: `IMPLEMENTED — EXACT-COMMIT CI VERIFIED; CANDIDATE METRICS ONLY; OD-06 OPEN`.
- A2 remains VERIFIED-CLOSED. No Owner decision is reopened or changed.
- A4 independent verification and A5 activation/deployment remain separate gates. PRs #47, #48 and #49 remain draft, open and unmerged.

## 11. A3.8 canonical-provider integration readiness — 2026-11-10

A3.8 has undergone a bounded provider-dependency reconciliation. The existing G01 credential, G02 Owner-approval and G11 decision-audit primitives are not equivalent to every cross-domain authority required by G05. Full A3.8 closure must not be claimed by wiring a nearby but semantically different provider.

### Verified available capabilities

- **G01 identity:** the kernel has concrete Ed25519 credential verification, trusted issuer/key snapshots, exact audience and credential validity checks, and fail-closed revocation checks. This authenticates a principal; it does not prove that a designated human approved a particular memory record.
- **G02 Owner authority:** the kernel has Owner-signed, exact-scope approvals, key/approval revocation checks and replay-protected approval consumption. This is direct Owner authority, not organization-scoped delegation.
- **G11 decision audit:** the kernel has a durable append-only, hash-chained decision event sink. It is not the memory-lifecycle event stream and must not be overloaded.

### Exact unresolved integration dependencies

1. **G01 reviewer-proof verification — MISSING.** The G05 G01ReviewerProofAuthority port has no concrete G01-owned verifier in the inspected integration branch that verifies current reviewer-to-key binding, canonical signed approval bytes/domain separation, exact tenant/organization/reviewer/designation-version/memory/record/digest/purpose/classification scope and current revocation at use. A verified credential or Owner signature cannot substitute for this proof.
2. **G02 organization-scoped delegation — MISSING.** The inspected kernel security store has tenant membership and policy/revocation state but no canonical organization-delegation registry or designation/revocation action. Global capability and tenant membership are not organization roles. The authoritative organization source/provider and its governance owner remain unidentified; no new registry is invented here.
3. **G11 memory-lifecycle integration — CANDIDATE IN SEPARATE PR.** PR #43 implements a distinct versioned, content-free G11 memory lifecycle event stream and a G05 adapter with outbox/idempotency tests. Exact head 84b56386879928d28040d0a2c4e502efd1b2ae2c passed workflow run [42820878358](https://github.com/akefadaka-git/iroka/actions/runs/42820878358). PR #43 remains OPEN, DRAFT and UNMERGED on a separate G05 branch; its implementation is not yet part of this programme branch. It does not provide cross-database atomicity or multi-node guarantees.

### Safe disposition

- Reuse existing G01 credentials/revocation, G02 Owner approval, and G11 decision-audit primitives only for their documented semantics.
- Keep organization-scoped reviewer approval and durable memory activation fail-closed until the missing canonical providers exist and pass adversarial integration tests.
- Do not create a parallel identity, reviewer, consent, delegation, memory or audit registry in this programme.
- Do not treat PR #43's separate G11 candidate as integrated into the programme until its branch dependency and review disposition are resolved.
- A3.8 remains PARTIAL. A4 independent assurance and A5 activation/deployment remain separate.

This readiness record is an evidence disposition, not an authorization to change G01/G02 ownership or invent an organization-authority source.
