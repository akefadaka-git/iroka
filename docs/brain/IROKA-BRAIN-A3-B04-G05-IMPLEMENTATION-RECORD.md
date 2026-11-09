# G05 A3 B04 — Implementation Record

- Contract: `IROKA-G05-MEM-001` v1.0.0 (Owner-approved)
- Stage: A3 implementation
- Status: PARTIAL — domain core and fail-closed primitives implemented; production adapters are not.
- Base: G04 adapter branch `feat/brain-a3-b03-g04-contract-adapter`, commit `4e0c954516b4a471e2f36760b665add0a98efe9f`
- Branch: `feat/brain-a3-b04-g05-memory-core`

## Implemented

The new `iroka-g05-memory` Rust workspace crate provides:

- Versioned G05 record, provenance, approval receipt, access context, lifecycle, operation and content-free audit-event types.
- Canonical SHA-256 content integrity validation.
- Bounded working-memory expiry validation.
- Episodic opt-in reference requirement.
- Rejection of Restricted-classification working memory.
- Durable candidate/proposal state and a separate record-bound approval validation primitive.
- Approval binding to exact memory ID, tenant, subject and content digest, with issue/expiry checks.
- Explicit default-deny cross-principal sharing validation and tenant-scope checks.
- A lifecycle transition matrix that does not permit direct or implicit durable activation.
- Governance and repository adapter traits documenting G01/tenant/G02/reviewer/G11 boundaries and authorization-before-content-access requirements.
- Durable activation preflight delegates cryptographic approval and designated-reviewer verification to the trusted governance port; reviewer authority is resolved by that adapter rather than a caller-supplied organizational flag.
- Two-phase retrieval authorization: G02 preflight before metadata lookup, then authorization against stored tenant/subject/purpose/classification/state/expiry before content access.
- Metadata-only repository return type excludes content; mutation repository methods require an atomic G11 outbox event.
- Episodic capture preflight verifies opt-in through the trusted governance port; an opt-in reference alone is not treated as consent.
- Synthetic unit tests for the core invariants.

The crate deliberately does not implement identity verification, tenant resolution, policy evaluation, cryptographic reviewer verification, G11 audit storage, or a production persistence provider.

## Contract decisions enforced in code

| Decision | Implementation evidence |
|---|---|
| D1 — explicit approval for every durable record | durable activation binding validator; no direct Proposed/PendingReview → Active transition |
| D2 — episodic opt-in | episodic candidates require an opt-in reference |
| D3 — personal inspect/deletion rights | logical operation types and repository boundary; service workflow remains pending |
| D4 — designated human reviewer | approval-verification port receives durable receipt and organizational scope; concrete reviewer authority adapter pending |
| D5 — defer semantic/vector retrieval | no embedding, vector database, or semantic index dependency added |
| D6 — default-deny sharing | explicit policy authorization required by sharing validator |
| D7 — no Restricted working memory | validator rejects it |

## Explicit A3 gaps

1. No concrete adapter yet binds the G05 governance port to the existing G01 → tenant authority → G02 composition path. This must reuse the canonical Kernel composition and must not introduce a second authorization engine.
2. No concrete designated-reviewer signature/authority verifier. The verifier must consume the approved G02/Owner authority model; G05 must not invent a parallel trust root.
3. No persistent G05 repository or schema migration. Storage encryption, key ownership, transactional versioning, backup handling, retention and deletion semantics need a verified design before content persistence.
4. No atomic G11 outbox/transaction adapter. A G05 mutation cannot be reported complete until its required audit guarantee is met.
5. Personal inspection, correction, deletion, retention holds, expiry workers, idempotency and recovery workflows are not yet implemented.
6. No production source ingestion or real-user data is permitted in this stage.
7. The code has not yet passed exact-HEAD CI; A4 security review is not run. The crate currently contains 13 synthetic unit tests.

## Required next work

- Compile and test the exact branch head with the repository's locked workspace CI matrix.
- Fix all compiler, test, formatting and Clippy failures.
- Inspect current G01/G02/G11 public integration surfaces on the stacked base and implement only adapters that can be safely composed without weakening their authority.
- Add transactional persistence only after encryption/key-management and deletion/backup semantics are specified and verified.
- Add tests for authorization-before-content-access, reviewer designation, audit failure, tenant isolation, opt-in revocation, deletion/resurrection, concurrency and idempotency.
- Keep PR draft and unmerged. A4 and A5 remain separate gates.

## Safety statement

This is a non-production domain core. It is not a memory service, secure database, consent authority, authorization engine, or deployment-ready capability. No real-user memory was ingested. No merge, signing, release, deployment, or production activation is authorized by this record.
