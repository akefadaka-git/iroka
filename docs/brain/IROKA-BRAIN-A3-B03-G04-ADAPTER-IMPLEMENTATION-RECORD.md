# IROKA Brain A3-B03 — G04 Adapter Implementation Record

**Record ID:** IROKA-BRAIN-A3-B03-IMPL-001  
**Version:** 0.1.0  
**Status:** IMPLEMENTED — ADAPTER CONTRACT ONLY; VERIFICATION PENDING  
**Owner boundary approval:** 2026-11-09  
**Implementation branch:** `feat/brain-a3-b03-g04-contract-adapter`  
**Parent implementation baseline:** B02 authorization composition HEAD `d5d519ee8b29e9cf8c618b3b357825e7740fe86a`

## 1. Authoritative contract sources

- `docs/architecture/A2-IMPLEMENTATION-CONTRACTS.md` §10 — KNOW source and retrieval ownership, provenance, permission enforcement and citation rules.
- `docs/architecture/A2-API-DATA-AND-EVENT-CONTRACTS.md` §4.6 — logical source and derived-item schema; §5 — required KNOW operations.
- Owner-approved G04 boundary proposal: `docs/brain/IROKA-BRAIN-A3-G04-ADAPTER-PROPOSAL-001.md`.

The A2 contracts define the logical G04/KNOW authority. The pinned `main` baseline `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472` does not contain a G04 provider/runtime, source registry or retrieval engine.

## 2. Implemented in this increment

A new isolated workspace crate, `iroka-g04-contract`, provides:

- Versioned `iroka.g04.retrieval-request` and `iroka.g04.evidence-bundle` typed envelopes.
- Opaque G01 principal/tenant and G02 policy context references.
- Bounded query, result-count and byte budgets; explicit source selectors and accepted media types.
- Immutable source revision reference and source SHA-256, exact locator, excerpt SHA-256, retrieval/source timestamps, classification, license reference and attribution requirement.
- Explicit freshness, provenance and license states. The adapter never upgrades a state.
- A provider trait owned by the G04 integration boundary and a validating adapter for correlation, tenant binding, selected sources, digest integrity, content permission, format and resource limits.
- Synthetic tests for normal evidence, cross-tenant response, correlation mismatch, tampered excerpt, revoked/unlicensed content exposure, unverified metadata-only response, duplicate references, source-selector mismatch and budget overruns.

## 3. Trust boundary and limitations

This crate is a typed client/contract adapter, **not** an authorization engine. It does not authenticate opaque references. A real G04 provider MUST resolve G01 and G02 references against their authoritative services and enforce source authorization before retrieval/ranking. It must enforce the request freshness bound and classification ceiling, and it remains authoritative for source lifecycle, provenance, freshness and revocation.

No source registry, persistent knowledge store, crawler, index, ranking engine, real-source ingestion or production provider is included. No real corpus is used. No G03-owned knowledge database is created.

The adapter's tenant comparison is a response-binding check, not proof that the tenant reference itself is authentic. Likewise, an excerpt digest proves returned-byte integrity only; it does not prove source authenticity, truth, license or permission.

The current G11 schema is intentionally narrow. This increment does not overload it with retrieval events. A versioned G11 domain-event extension and G10 evaluation integration require their own contract reconciliation.

## 4. Verification gates

- Exact-head formatting, workspace compile, locked dependency check, tests and Clippy: PENDING.
- Independent security review (A4): NOT RUN.
- Live provider conformance: NOT RUN; provider does not exist in the pinned baseline.
- Real-source provenance/licence verification: NOT RUN; synthetic fixtures only.
- Multi-node persistence, operational recovery, production key ceremony and deployment: NOT IN SCOPE.
- Merge/deployment/production activation: NOT AUTHORIZED.

## 5. Exit status

B03 has a concrete, isolated adapter implementation candidate. It is **PARTIAL**, not production-ready and not VERIFIED-CLOSED. Closure requires exact-head CI, independent security review, and a separately approved authoritative G04 provider/runtime with conformance evidence.