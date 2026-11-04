# A2 — Repository Reconciliation and Historical Disposition Register

**Contract ID:** IROKA-A2-RECON-001  
**Version:** 0.1.0  
**Status:** Read-only evidence register with explicit proposed dispositions  
**Repository:** `akefadaka-git/iroka`  
**A1 baseline:** IROKA-A1-REGIONAL-001 v1.0.0

## 1. Snapshot and scope

Repository state inspected on 2026-11-04 through the connected GitHub repository integration. This register records branch heads and exact comparison evidence available during the A2 pass. It does not claim access to unpushed local work, private external repositories, deleted Git objects not reachable from inspected refs, or third-party services not linked to this repository.

| Ref | SHA / comparison | Evidence | Disposition |
|---|---|---|---|
| `main` | `143311a655be68acea2700650b7f88c9fb085526` | Repository baseline; unchanged during A2 | Preserve as protected baseline |
| `foundation/kernel-v0.1` | `8f848a59a354334a26a2af508ba5e482b347d811`; 55 commits ahead, 0 behind main | Rust workspace/kernel foundation, initial identity, policy, governance, audit and workflow files | Historical implementation source; retain for provenance and comparison |
| `security/g01-trust-lifecycle-g02-owner-approval` | `710b36a506d3277c7b307a01522629db43b4698f`; 153 commits ahead, 0 behind main | Expanded G01/G02 trust lifecycle and Owner approval, security store, audit sink, A1 docs; PR #2 draft | Working security/A1 source baseline; preserve; not merged |
| `architecture/a1-amharic-first-african-contracts` | `72be8040283acd31ce90050a5b03d59c55b38b89`; 4 commits ahead, 0 behind main | A1 parent contract, regional profile contract, traceability register and README edits | Preserve as duplicate/overlap source; do not merge until path/ID/content reconciliation |
| `architecture/a2-reconciliation-contracts` | Created from `710b36a506d3277c7b307a01522629db43b4698f`; current A2 head is the final reconciliation-register commit in this workstream | A2 contracts and test-plan workstream | Dedicated A2 working branch; no merge/deploy |

## 2. Implementation history reconciliation

### 2.1 Kernel foundation

At `foundation/kernel-v0.1`, the Rust workspace includes the `iroka-kernel` crate and modules for assurance, decisions, governance, identity, identity cryptography, policy, requests and authorization service. The source establishes a governed authorization foundation. It does not establish Amharic UI, localization, Ethiopic rendering, Ethiopian calendar, person-name directory, document/OCR or knowledge retrieval support.

### 2.2 Security expansion

The security branch adds trust lifecycle and security-store work, including durable trust/revocation state, Owner-signed approvals/commands and a SQLite single-node security registry. The branch's PR #2 description records that production trust roots/Owner keys have not been provisioned, multi-node shared transactional guarantees are outstanding, G09 side-effect execution is not implemented and general G11 audit integration remains incomplete. Those are explicit open gates, not localization evidence.

The A1 implementation inventory was inspected at code SHA `2877e26643332ef26c886001e965950bd3dec958`. It is a point-in-time snapshot of 38 tree entries and explicitly limits absence findings to that SHA. The present A2 review confirms that the foundation and security branches are kernel-focused. A complete product-surface audit still requires checking any subsequently added clients, external integrations and unpushed work.

### 2.3 A1 documentation branch conflict

The architecture branch contains:
- `docs/architecture/A1-AMHARIC-FIRST-ETHIOPIAN-AFRICAN-CONTRACT.md`
- `docs/architecture/REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md`
- `docs/architecture/A1-REQUIREMENTS-TRACEABILITY-AND-DECISIONS.md`
- README changes.

The security branch contains:
- `docs/architecture/A1-AMHARIC-FIRST-REGIONAL-ARCHITECTURE-CONTRACT.md`
- `docs/architecture/REGIONAL-DEPLOYMENT-PROFILE-CONTRACT.md`
- `docs/architecture/A1-REQUIREMENTS-TRACEABILITY-AND-DECISIONS.md`
- `docs/architecture/A1-IMPLEMENTATION-INVENTORY.md`
- strategy updates.

Both parent A1 documents declare contract ID `IROKA-A1-REGIONAL-001`; both profile documents declare `IROKA-A1-REG-002`; both traceability documents declare `IROKA-A1-TRACE-001`. They are not byte-identical. Their requirements are substantially overlapping, with different section identifiers, structure and detail. Merging both versions unchanged would create duplicate normative documents and ambiguous references.

**Line-level semantic comparison completed:** the two parent contracts are not interchangeable duplicates. The security-branch document (236 lines) uniquely includes formal version/authority/scope metadata, support-level declarations, explicit language-aware interaction, speech prioritization, currency/units and law/data-residency sections, Kernel invariants, prohibited shortcuts and deferred decisions. The architecture-branch document (196 lines) uniquely provides a sharper governing principle, explicit per-user/organization/workspace/document language preferences, translation fallback and review states, typography/accessibility details, typed temporal semantics, richer person-name/search/duplicate-resolution rules, detailed document/OCR provenance, knowledge citation/conflict rules, and explicit acceptance gates. Both share the same contract ID but differ materially in normative content.

**Disposition:** neither parent contract may be discarded or treated as a complete substitute. Use the security-branch path as the provisional canonical file path because it is already referenced by the security-branch strategy and inventory, but construct the canonical A1 v1.1 candidate as a semantic union of both documents. Preserve the stronger or more specific requirement wherever the clauses are compatible. Where clauses differ in scope or strength, record the exact clause pair and retain the stricter safeguard unless it contradicts an Owner decision. No existing A1 file is overwritten in this pass; no duplicate branch is deleted, rewritten or merged. The canonicalization map must include each source section, retained/combined clause, destination section and disposition. The Owner must review any change that materially affects A1 scope or requirement strength before the canonical document replaces the current v1.0.0 baseline.

The two profile contracts are substantially equivalent in required fields and precedence. Their differences are mainly naming/detail and example presentation: the architecture branch gives a structured list example and explicit `UNREVIEWED` legal/data-governance semantics; the security branch supplies a fuller illustrative YAML profile and an A1/A2 boundary. Combine these details in one supporting contract without changing profile semantics.

The two traceability registers are also overlapping but not identical. The security-branch version explicitly includes offline synchronization/revocation as an open decision and gives a detailed A1 exit checklist; the architecture-branch version expands explicit non-decisions and the traceability matrix. Retain both sets of requirements and decision rows in the canonical register. Keep contract IDs singular and update all cross-references atomically.

### 2.4 Main and README

Main remains at the repository baseline. The architecture branch's README edits are not automatically adopted; they must be reviewed separately for project-level accuracy and must not overwrite unrelated README content.

## 3. A1 requirement-to-code status at inspected evidence

| A1 area | Existing evidence | Status |
|---|---|---|
| G01 credential identity and trust | Rust kernel identity/crypto/trust modules | PARTIAL; system principals only, not person identity |
| G02 signed Owner authority | Owner approval and governance modules on security branch | PARTIAL; no provisioned live Owner keys or full operational governance UI |
| G11 assurance/audit | Assurance and audit-store modules | PARTIAL; broader integrations and external checkpointing remain open |
| Amharic language resources and reviewed UI | No runtime language catalog/client evidence in inspected kernel tree | MISSING at inspected code SHA |
| Ethiopic typography and client rendering | No client renderer/font matrix evidence | MISSING at inspected code SHA |
| Locale/numeral service | No implementation evidence | MISSING at inspected code SHA |
| Regional profile registry/resolver | Contract documentation only | MISSING at inspected code SHA |
| Ethiopian/Gregorian calendar and time semantics | No implementation evidence | MISSING at inspected code SHA |
| Person names and Ethiopic identity search | No person-directory model; credential subject is not person identity | MISSING at inspected code SHA |
| Document generation/rendering/records | No implementation evidence | MISSING at inspected code SHA |
| Amharic OCR | No OCR pipeline/corpus/evaluation | MISSING at inspected code SHA |
| Amharic knowledge ingestion/retrieval | No ingestion/index/retrieval implementation evidence | MISSING at inspected code SHA |
| Amharic speech | No adapter or evaluation evidence | NOT VERIFIED |
| Second African profile | Architecture fixture only; no runtime conformance evidence | MISSING |
| Cross-region security invariance | Security foundation exists, but no profile mutation regression suite | NOT VERIFIED |

Absence labels are scoped to inspected commits and paths. They are not claims about unpushed or unlinked external systems.

## 4. Required A2 reconciliation actions

1. Perform line-level semantic comparison of the two A1 parent contracts and supporting duplicate-ID documents.
2. Build a complete reachable-commit and file-path inventory for all four pre-existing branches; record historical candidate files and supersession links.
3. Review all README and implementation-strategy changes independently.
4. Inspect all current product surfaces and external integrations if they become available in the repository or connected sources.
5. Map every A1 requirement to an owner, proposed service boundary, API/data contract, implementation location, acceptance test and release evidence.
6. Record all unsupported capabilities as gaps; do not retrofit a claim of implementation based on documentation.
7. Select libraries only after the criteria in IROKA-A2-IMPL-001 are evaluated and recorded.
8. Freeze test corpora, references and thresholds before implementation and model tuning.

## 5. Non-actions and safeguards

- `main` was not modified.
- No historical branch was deleted, force-pushed, merged or rebased.
- PR #2 remains draft and unmerged.
- No runtime implementation, dependency addition, test execution or deployment is claimed by this register.
- Existing kernel/security functionality and unrelated changes must be preserved.
- No A1 requirement is weakened to match the current implementation.

## 6. A2 exit conditions

A2 may close only when:
- duplicate A1 documents have a reviewed canonicalization/disposition map;
- all reachable active-branch implementation material is inventoried with exact SHAs;
- historical candidate sources have explicit keep/merge/supersede/reject dispositions;
- A1-to-code-to-test traceability has no unowned requirement;
- implementation contracts are reviewed and versioned;
- measurable test corpora, metric definitions and thresholds are frozen;
- regional test fixtures are independently reviewed;
- unresolved legal, data-governance, dialect and library decisions remain explicit and are not misrepresented as complete.

A2 closure authorizes a separately scoped implementation phase; it does not itself authorize production deployment or imply Amharic-first readiness.


## 7. Post-register exact-SHA addendum

The initial snapshot above has been superseded by the exact-SHA evidence report:
[`A2-EXACT-SHA-RECONCILIATION-EVIDENCE.md`](A2-EXACT-SHA-RECONCILIATION-EVIDENCE.md).

The later read-only inspection established five active branches, not four pre-existing branches; PR #3 for the independent A1 architecture branch is open, draft and unmerged. The A2 branch is a direct five-commit documentation continuation of the security branch at the initial A2 snapshot. Following the interface and exact-SHA supplements, the A2 branch is seven commits ahead of security and contains five A2 documents.

Use the exact-SHA evidence report as the authoritative current branch/tree/PR inventory. This original register remains the semantic reconciliation record and its historical observations are not retroactively rewritten.
