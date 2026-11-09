# IROKA Brain A3 — G04 Knowledge and Evidence Adapter Proposal

**Document ID:** IROKA-BRAIN-A3-G04-ADAPTER-001  
**Version:** 0.1.0  
**Status:** OWNER-APPROVED BOUNDARY — A3 IMPLEMENTATION AUTHORIZED WITH DEPENDENCY LIMITS  
**Parent:** IROKA-BRAIN-A2-COGNITIVE-CONTRACTS-001 v1.0.0 (Owner-approved)  
**Work package:** A3-B03 — Knowledge/evidence  
**Date:** 2026-11-09

## 1. Purpose and current blocker

Define a reviewable G03↔G04 boundary for knowledge retrieval and evidence provenance without creating a second knowledge store inside G03.

The approved A2 Brain contract assigns:
- G03: cognitive coordination, reasoning, planning and cognitive critique.
- G04: knowledge sources, retrieval and evidence provenance.

The pinned repository baseline used by B02 is main `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`. A repository-tree inspection found no G04 source crate, G04 API/contract document, knowledge-source registry, retrieval adapter, or provenance verification implementation. A2 provides generic opaque input/evidence references, but does not define the authoritative G04 API, source lifecycle or provenance semantics.

**Disposition:** The Owner approved this boundary on 2026-11-09. The authoritative logical G04/KNOW contract is present in the Owner-approved A2 implementation contract (section 10) and A2 API/data contract (section 4.6). The repository still has no G04 provider/runtime or source registry. A3 may implement the typed adapter boundary only; provider/runtime implementation, production source access and source ingestion remain separate, explicitly gated work. No parallel G03 knowledge subsystem is permitted.

## 2. Non-negotiable ownership

1. G04 remains the sole authority for source registration, source lifecycle, retrieval, provenance, freshness and evidence revocation.
2. G03 may request evidence and synthesize returned evidence; it may not register authoritative sources, alter source metadata, mint provenance, or independently promote unverified material to verified evidence.
3. G01 supplies the verified principal and opaque tenant context. The tenant ID in a request is a selector only.
4. G02 determines whether the principal may access a source or evidence class. G04 enforces the authoritative access decision at its boundary; G03 does not reconstruct authorization.
5. G11 receives minimal correlated retrieval/decision metadata through its approved interface. G03 must not create a parallel audit ledger.
6. G10 owns evaluation. G03 critic output and retrieval scores are not independent assurance.

## 3. Proposed request contract

Proposed envelope: `iroka.g04.retrieval-request`, contract version `1.0`.

Required fields:
- `schema_id`, `contract_version`, `request_id`, `correlation_id`;
- opaque `principal_ref` and opaque `tenant_context_ref` issued by trusted G01;
- opaque `policy_context_ref` issued by trusted G02;
- bounded query or typed retrieval intent;
- optional opaque source/collection selectors;
- requested result limit and byte/token budget;
- accepted evidence formats and freshness requirements;
- purpose/task reference and data-classification ceiling.

The request must not accept a caller-asserted principal, tenant membership, policy decision, source trust level, license status or provenance result. Unknown schema versions, unsupported fields, oversized queries, invalid budgets and missing trusted context are rejected.

A G03 caller must not send a tenant ID as authority. G04 resolves tenant scope from the opaque server-issued context and verifies it against current authorization.

## 4. Proposed response contract

Proposed envelope: `iroka.g04.evidence-bundle`, contract version `1.0`.

Each evidence item should include:
- opaque immutable `evidence_ref` and authoritative `source_ref`;
- source version/revision and source-content digest;
- exact locator (document/page/section/paragraph/chunk or structured record key);
- returned excerpt or structured payload with explicit truncation metadata;
- source publication/creation time when known;
- retrieval time and source freshness state;
- provenance verification state and the verifier/contract version;
- license/permission reference and attribution requirements;
- classification and tenant-scope reference;
- integrity status and any revocation/supersession marker.

The bundle must distinguish at least:
- `verified_current`;
- `verified_stale`;
- `unverified`;
- `revoked`;
- `superseded`;
- `unavailable`.

Only G04 may assign these authoritative states. Missing or unverifiable metadata is represented explicitly; it is never inferred as verified. An empty result is a valid result and must not be filled with fabricated citations.

## 5. Provenance and trust requirements

- Source registration must bind source identity, owner, origin, acquisition method, source version, content digest, license/permission evidence, attribution and allowed use.
- Source changes produce a new immutable revision; prior revisions remain addressable as historical evidence but may be marked stale or superseded.
- Revocation is authoritative and must be checked at retrieval time; stale caches require explicit maximum age and fail closed after expiry.
- A content digest establishes byte identity only; it does not prove truth, authorship, license or permission.
- A model-generated citation or source title is not provenance evidence.
- Source content is untrusted data. Embedded instructions are never executable policy or system instructions.
- Conflicting sources are returned with their independent provenance and timestamps; G04 does not silently collapse conflict into a single asserted truth.

## 6. G03 consumption rules

G03 may:
- rank and synthesize returned evidence within its task budget;
- preserve evidence references and locators in its result;
- distinguish direct evidence, inference and uncertainty;
- abstain when evidence is missing, stale, revoked, conflicting or outside the task's classification ceiling.

G03 may not:
- alter a source's trust, license, tenant or revocation state;
- cite content not present in the returned evidence bundle;
- describe a retrieval score as a truth probability;
- convert `unverified` or `verified_stale` into `verified_current`;
- store an independent copy as a second authoritative knowledge base;
- route restricted content to an external model provider.

## 7. Required negative and adversarial tests

1. Forged or expired principal/tenant/policy context is rejected.
2. Cross-tenant source selectors cannot disclose evidence.
3. Revoked source/revision is denied or returned only as explicitly revoked historical evidence under policy.
4. Stale source and expired freshness cache cannot be labeled current.
5. Modified content digest fails integrity verification.
6. Unknown source, locator or evidence reference cannot be fabricated into a citation.
7. License/permission absence or incompatible use blocks retrieval or downstream use.
8. Oversized query/result and excessive result count terminate within fixed budgets.
9. Prompt injection in retrieved content is treated as untrusted data.
10. Conflicting source revisions remain distinguishable.
11. G04 outage produces typed unavailability/abstention; no fallback to an unapproved G03 store.
12. G11 audit outage follows the approved fail-closed policy for security-relevant retrieval.
13. Duplicate/replayed request IDs are idempotent or explicitly rejected.
14. Amharic/Ethiopic text, Unicode normalization, source locators and original script are preserved losslessly; transliteration is a separate labeled representation.

## 8. Implementation gates

B03 code remains blocked until all are satisfied:
- Owner approval of this boundary: SATISFIED (2026-11-09).
- Normative logical G04/KNOW source: `docs/architecture/A2-IMPLEMENTATION-CONTRACTS.md` section 10 and `docs/architecture/A2-API-DATA-AND-EVENT-CONTRACTS.md` section 4.6, both pinned to the approved A2 baseline.
- No G04 provider/runtime, source registry or production retrieval implementation exists on the pinned `main` baseline; the adapter must remain provider-agnostic and must not create a second source authority.
- G01/G02 references remain opaque and must be resolved/enforced by the authoritative provider; this adapter does not authenticate or authorize them.
- G11 retrieval-event integration requires a versioned G11 domain-event extension; the current G11 event schema is intentionally narrow and must not be overloaded.
- G10 evaluation integration is deferred until its owner contract is available; it is not fabricated by B03.
- Only synthetic fixtures are used. Each real source requires independent provenance, licence and permitted-use verification.
- Isolated implementation branch and exact-head CI/security test matrix are required before B03 can be called verified.

## 9. Explicit non-goals

This proposal does not authorize:
- building a G03-owned knowledge database, index or source registry;
- ingesting public web content, user files or third-party corpora;
- using unlicensed or unverified Maale, Amharic, English or other language corpora;
- activating paid/external retrieval or model providers;
- production data processing, deployment, merge, publication or release;
- G09 tool execution or protected side effects.

## 10. Owner disposition

Owner decision: APPROVED on 2026-11-09. The A2 logical G04/KNOW contract is the normative upstream contract. The absence of a G04 runtime/provider is recorded as an implementation dependency, not a reason to invent a G03-owned source store.

Current disposition:
- A3-B03 = IMPLEMENTATION IN PROGRESS / ADAPTER ONLY; provider/runtime and production retrieval remain NOT IMPLEMENTED.
- A3-B04 (G05) and A3-B05 (G06) remain independently blocked by their missing owner contracts.
- No G04 implementation is claimed.


## 11. Owner approval record

- Decision: APPROVE the proposed G04 ownership and G03↔G04 boundary.
- Date: 2026-11-09.
- Scope: typed adapter contract and validation implementation on an isolated branch.
- Exclusions: no G03 knowledge store, no real-source ingestion, no production provider, no merge, no deployment, no production activation.
- Authoritative logical contract: A2 implementation contract §10 and A2 API/data contract §4.6.
