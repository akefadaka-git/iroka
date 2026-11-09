# A1 Implementation Inventory — Evidence Snapshot

**Contract ID:** IROKA-A1-INVENTORY-001  
**Status:** Initial read-only inventory; gaps recorded  
**Code baseline inspected:** `2877e26643332ef26c886001e965950bd3dec958`  
**Repository:** `akefadaka-git/iroka`  
**Code branch inspected:** `security/g01-trust-lifecycle-g02-owner-approval`  
**Inventory method:** Git tree and targeted source/contract reads; no source files changed by this inspection.

## 1. Scope and limitation

This is a point-in-time inventory of the destination repository's Rust/kernel implementation at the exact code SHA above. It is not a claim that no implementation exists in an uninspected historical repository, external service, unpublished working tree or future branch. A2 must extend the inventory to all active branches, historical candidate material, UI/client surfaces and external integrations.

The inspected Git tree contains 38 entries, including the Rust workspace, one kernel crate, its source modules, one integration test, the Rust workflow, implementation strategy and architecture documents.

## 2. Observed implementation

| Area | Evidence at inspected SHA | Assessment against A1 |
|---|---|---|
| G01 credential verification | `identity_crypto.rs`, `trust_lifecycle.rs`, `security_store.rs`; Ed25519 compact-JWS and trust/revocation lifecycle | Security principal verification exists. This is not multilingual person identity or name management. |
| G01 principal model | `identity.rs`; opaque subject, issuer and credential ID | Does not define original-script names, Ethiopic name components, aliases, transliteration or localized identity presentation. |
| G02 Owner approvals | `owner_approval.rs`, `G02-GOVERNANCE-CONTRACT.md` | Signed approval and authority boundary exist. Amharic governance UI and localized approval explanations are not evidenced. |
| G11 decision audit | `assurance.rs`, `audit_store.rs`, `G11-AUDIT-INTEGRITY-CONTRACT.md` | Audit sink exists; no evidence here of locale/profile context capture across all future domain events. |
| Language resources / Amharic UI | No language catalog, client app or translation workflow in inspected tree | MISSING at this code baseline. |
| Ethiopic typography / fonts | No client rendering or font assets in inspected tree | MISSING at this code baseline. |
| Localization/profile runtime | No regional profile schema, resolver or profile storage implementation in inspected tree | MISSING at this code baseline; architecture contract is documentation only. |
| Numeral parsing/formatting | No locale-aware numeral module or tests in inspected tree | MISSING at this code baseline. |
| Ethiopian/Gregorian calendar | No calendar/date-time domain module or conformance tests in inspected tree | MISSING at this code baseline. |
| Time-zone semantics | No date/time service or profile-aware rendering in inspected tree | MISSING at this code baseline. |
| Person names and identity search | No person directory/name model/search module in inspected tree | MISSING at this code baseline; do not confuse credential subject IDs with person identity. |
| Document authoring/rendering/records | No document service, PDF/office renderer or template implementation in inspected tree | MISSING at this code baseline. |
| Amharic OCR | No OCR pipeline or evaluation corpus in inspected tree | MISSING at this code baseline. |
| Knowledge ingestion/retrieval | No ingestion, tokenizer, index, embedding or retrieval implementation in inspected tree | MISSING at this code baseline. |
| Amharic speech | No speech recognition/synthesis adapter or evaluation evidence in inspected tree | MISSING at this code baseline. |
| African country profiles | No second country profile or cross-profile conformance fixtures in inspected tree | MISSING at this code baseline. |

## 3. Evidence boundary

- The earlier Rust verification associated with the code line is evidence for the kernel tests and build checks only. It is not A1 localization acceptance evidence.
- The presence of A1 architecture documents proves requirements were recorded; it does not prove runtime conformance.
- The absence of a module in this inspected tree is recorded as MISSING **at this SHA**, not as a claim about all historical or external work.
- No Amharic language quality, calendar correctness, OCR accuracy, speech quality, retrieval relevance or country-law compliance claim is supported by this inventory.

## 4. Required A2 work

1. Reconcile this inventory against every active destination branch and any approved historical candidate sources, without modifying unrelated work.
2. Establish the complete product surface inventory (clients, APIs, admin tools, CLI, documents and integrations).
3. Specify the localization/profile data contracts and select libraries only after Unicode, calendar, license, security and maintenance review.
4. Define the canonical identity-person model separately from G01 credential principals.
5. Define date/time semantic types and choose a vetted Ethiopian calendar implementation with an authoritative test corpus.
6. Define Amharic document, OCR, knowledge and speech datasets with rights, provenance, dialect coverage and human-review governance.
7. Set measurable acceptance thresholds before running evaluations; do not tune thresholds after observing results.
8. Map every A1 requirement to implementation owner, code path, test, evidence artifact and release gate.

## 5. Status

A1 architecture domains are defined in the normative contract and traceability register. Repository implementation reconciliation is **PARTIAL**: the trusted-kernel slice was inspected, but the complete active-branch/product-surface inventory remains an A2 task. Amharic-first runtime capability is **NOT VERIFIED** and is not production-ready.
