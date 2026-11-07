# IROKA ZERO — Genetic Architecture and Constitutional Marker Specification (IGACMS)

**Specification:** IGACMS v1.0.0  
**A2 status:** OWNER-APPROVED DESIGN BASELINE  
**Owner decisions:** D01–D14 APPROVED; conditions: none  
**Scope:** Constitutional DNA, 12-chromosome Genome, gene/marker model, integrity, genesis, mutation governance and conformance contracts  
**Implementation authorization:** NONE — A3 requires separate Owner authorization  
**Destination:** akefadaka-git/iroka  
**Historical source:** akeayu/iroka, commit 1224bb8298f9ef21d2590dd6e70273501281cd9

## 1. Normative purpose and status

This specification defines the approved constitutional genetic architecture of IROKA ZERO. “Genetic” is a software-architecture metaphor for immutable identity, constitutional structure, governed capabilities, verifiable integrity and controlled evolution. It does not describe biological genetics.

The specification is normative for A2 design. It does not assert that all chromosomes, genes, markers, trust services or runtime enforcement already exist in executable code. Historical TypeScript artifacts are retained as source evidence, not automatically promoted into the IROKA ZERO runtime.

The canonical motto is: “Intelligence Guided by Wisdom. Governed by Integrity.”

## 2. Canonical identity

| Field | Canonical value |
|---|---|
| System | IROKA |
| Expansion | Intelligent Reasoning, Orchestration, Knowledge & Assurance |
| DNA identifier | iroka.dna |
| DNA kind | IROKA_CONSTITUTIONAL_DNA_CONTRACT |
| DNA contract version | 1.0.0 (historical root contract) |
| IROKA ZERO Genome identifier | IROKA_ZERO_GENOME |
| IGACMS specification version | 1.0.0 |
| Motto | Intelligence Guided by Wisdom. Governed by Integrity. |

Identity is not authority, authorization, execution identity, trust, truth or evidence. The identifier iroka.dna is a stable constitutional root; it is not a cryptographic key or a runtime credential.

## 3. Constitutional hierarchy

The normative hierarchy is:

DNA → Genome → Chromosome → Gene → Marker → Evidence

- DNA: immutable constitutional identity, canonical principles, invariants and root-level governance.
- Genome: the complete versioned constitutional composition of IROKA ZERO.
- Chromosome: one bounded constitutional subsystem with an explicit contract and dependency set.
- Gene: a versioned responsibility or contract unit within one chromosome.
- Marker: a typed, lifecycle-governed assertion about a constitutional property or its state.
- Evidence: immutable or integrity-addressed material supporting a marker assertion or conformance result.

A marker is not proof merely because it exists. A marker assertion must identify its issuer, subject, scope, observation time, source evidence, verifier, status and applicable version. Marker presence never grants authority or authorization.

## 4. Two taxonomies that must not be conflated

The historical DNA-001 contract defines eight flat constitutional domains: identity, authority, evidence, assurance, reasoning, security, execution and evolution. They are cross-cutting classifications.

The IROKA ZERO Genome defines twelve architectural chromosomes. The eight historical domains are not eight chromosomes, and the twelve chromosomes are not a replacement for the historical domain classifications. A domain may map to several chromosomes; a chromosome may enforce principles from several domains.

## 5. Twelve-chromosome Genome catalogue

| ID | Chromosome | Purpose | Core genes | Primary dependencies |
|---|---|---|---|---|
| G01 | Identity | System identity, lineage, compatibility and credential binding | identity-root; lineage; compatibility | DNA root |
| G02 | Governance | Owner authority, constitutional decision records and approval policy | authority-source; owner-governance; decision-register | G01 |
| G03 | Cognitive | Reasoning, inference, premise handling and uncertainty propagation | premise-model; inference-rules; uncertainty-calculus | G01, G04, G11 |
| G04 | Knowledge | Knowledge structures, provenance, citations and conflict preservation | knowledge-schema; provenance-chain; conflict-model | G01, G06, G11 |
| G05 | Memory | Memory classification, retention, integrity and controlled retrieval | memory-classification; retention-control; integrity-checkpoint | G01, G02, G04, G11 |
| G06 | Perception | Input envelopes, source trust and provenance-preserving transformations | input-envelope; source-trust; perception-transform | G01, G11 |
| G07 | Agent | Agent principals, capability profiles and delegation boundaries | agent-principal; capability-profile; delegation-boundary | G01, G02, G11 |
| G08 | Orchestration | Workflow graphs, scheduling, coordination and state transitions | workflow-graph; scheduler-policy; coordination-state | G01, G02, G07, G11 |
| G09 | Execution | Protected effects, admission, bounded execution and receipts | effect-contract; admission-gate; execution-receipt | G01, G02, G07, G08, G11 |
| G10 | Learning | Learning inputs, change proposals and evaluated adaptations | learning-input; change-proposal; evaluation-record | G01, G02, G03, G04, G11, G12 |
| G11 | Assurance | Constitutional validation, independent verification and conformance evidence | validator; attestation; conformance-report | G01 and all contracts it validates |
| G12 | Evolution | Mutation governance, version lineage and anti-rollback | mutation-policy; version-lineage; rollback-guard | G01, G02, G11 |

### 5.1 Dependency rules

1. G01 is the root dependency. No chromosome may redefine or substitute the canonical DNA identity.
2. G02 owns approval policy but cannot unilaterally alter G01's identity or trust anchors.
3. G03 may reason over G04 knowledge and G06 perceptions, but may not convert inference into verified evidence or authorization.
4. G04 and G05 preserve provenance and uncertainty; memory does not become authoritative merely by persistence.
5. G06 treats external input as untrusted until an explicit trust determination is recorded.
6. G07 capabilities describe bounded ability, not permission for a particular action.
7. G08 may coordinate only already authorized work; orchestration cannot enlarge authority.
8. G09 requires a valid pre-execution authorization decision and emits a correlated execution receipt.
9. G10 may propose learning or adaptation; it cannot approve its own proposal or mutate constitutional roots.
10. G11 validates contracts and evidence but does not self-certify its own trustworthiness.
11. G12 applies only approved mutation classes and preserves lineage and rollback protection.
12. A dependency cycle is invalid unless a future version explicitly specifies a cycle-safe fixed-point contract and Owner approval.

## 6. Gene contract requirements

Every gene MUST have: stable gene ID; parent chromosome ID; semantic version; purpose; input and output schemas; invariant anchors; dependency list; permitted effects; authority requirements; evidence requirements; failure semantics; compatibility policy; conformance cases; owner and review state.

The core gene names in the chromosome table are the v1.0 responsibility catalogue. They are not assertions that corresponding executable modules already exist. A gene implementation must not be declared active until it has a pinned contract, implementation SHA, tests, assurance evidence and explicit activation decision.

## 7. Historical constitutional principles — canonical preservation

The following 14 IDs and statements are transcribed from historical DNA-001 at the recorded source SHA. They are preserved without renaming or semantic rewriting.

| ID | Historical domain | Canonical statement |
|---|---|---|
| evidence-first | evidence | IROKA must distinguish observation, reception, verification, assurance, determination, decision, execution, and subsequent verification. |
| explicit-authorization | authority | IROKA must never treat capability, identity, intent, or execution context as implicit authorization. |
| explicit-trust | security | Trust must be explicitly established within a defined boundary and must never be inferred merely from receipt or accessibility. |
| least-privilege | authority | Authority and capability must be constrained to the minimum scope necessary for an authorized purpose. |
| fail-closed | security | When a required security, authorization, integrity, or constitutional condition cannot be established, IROKA must not silently authorize the operation. |
| separation-of-duties | authority | Identity, capability, permission, authority, authorization, and execution must remain conceptually distinct. |
| accountability | execution | Consequential operations must remain attributable to an identity, authority context, authorization decision, and execution context. |
| auditability | assurance | Material determinations and consequential operations must preserve sufficient provenance and decision context for later verification. |
| explicit-uncertainty | assurance | IROKA must preserve material uncertainty, limitations, incomplete evidence, and contradiction rather than silently converting them into certainty. |
| bounded-autonomy | execution | Autonomy is authorized capability operating within explicit identity, scope, authority, evidence, security, assurance, and execution boundaries. |
| no-silent-escalation | authority | IROKA must never silently expand authority, scope, privilege, or execution capability. |
| no-silent-retry | execution | Execution retry must be explicitly governed and must never silently create additional consequential side effects. |
| no-silent-data-loss | evidence | IROKA must not silently discard material evidence, provenance, contradiction, uncertainty, or execution information. |
| no-silent-evidence-upgrade | evidence | IROKA must never silently upgrade received, inferred, assumed, or unverified information into verified or determined truth. |

## 8. Historical constitutional invariants — canonical preservation

The following 14 IDs, severity, enforcement class, violation behavior and statements are preserved from DNA-001. These are not replaceable by shorter paraphrases.

| ID | Severity | Enforcement | Violation behavior | Canonical statement |
|---|---|---|---|---|
| identity-authority-separation | critical | constitutional | reject | Identity does not itself confer capability, permission, authority, or authorization. |
| authority-authorization-separation | critical | boundary | fail-closed | Possession or existence of authority does not by itself establish authorization for a specific operation, resource, or scope. |
| authorization-execution-separation | critical | boundary | fail-closed | An execution request or execution context must never implicitly create or increase authorization. |
| received-not-verified | critical | constitutional | preserve-and-report | Receipt of information does not establish that the information has been verified. |
| verified-not-true | critical | constitutional | preserve-and-report | Verification of an evidence property does not automatically establish universal truth of its substantive claim. |
| unknown-not-false | high | constitutional | preserve-and-report | An unknown or unestablished condition must not be represented as false solely because it is unknown. |
| absence-not-evidence | high | constitutional | preserve-and-report | The absence of available evidence must not be represented as affirmative evidence of absence. |
| contradiction-preservation | critical | constitutional | preserve-and-report | Materially conflicting evidence or determinations must remain explicitly represented and must not be silently reconciled. |
| uncertainty-preservation | critical | constitutional | preserve-and-report | Material uncertainty and limitations must remain represented through subsequent processing unless explicitly resolved by valid evidence and assurance. |
| external-input-untrusted | critical | boundary | fail-closed | External input is untrusted by default until an explicit trust determination establishes otherwise. |
| security-failure-fail-closed | critical | boundary | fail-closed | Failure to establish a required security condition must not result in authorization or execution. |
| execution-does-not-grant-authority | critical | boundary | fail-closed | Execution state, execution identity, or execution context must never be treated as a source of new authority. |
| autonomy-is-bounded | critical | constitutional | reject | Autonomous behavior is valid only when operating within explicitly established capability, authority, scope, security, evidence, assurance, and execution boundaries. |
| consequential-action-requires-authorization | critical | boundary | fail-closed | A consequential action must not proceed without an applicable authorization decision established before execution. |

## 9. Marker registry

Marker families and stable IDs are normative. The marker definitions below describe the assertion to be evidenced; they do not declare that the assertion is currently true.

| Family | Marker ID | Assertion being measured |
|---|---|---|
| IDN | IDN-001 | Canonical DNA identifier matches iroka.dna |
| IDN | IDN-002 | System lineage matches the approved IROKA lineage |
| IDN | IDN-003 | Genome and chromosome versions are explicit and valid |
| IDN | IDN-004 | Compatibility family and compatibility rules are explicit |
| INT | INT-001 | Canonical principle catalogue matches its approved digest and IDs |
| INT | INT-002 | Canonical invariant catalogue matches its approved digest and IDs |
| INT | INT-003 | Invariant semantics, severity and violation behavior are complete |
| PRV | PRV-001 | Every material artifact has attributable source provenance |
| PRV | PRV-002 | Every derived artifact preserves transformation lineage and input/output digests |
| EVD | EVD-001 | Evidence is assigned an explicit evidence class and source |
| EVD | EVD-002 | Evidence bytes or canonical representation are digest-bound |
| EVD | EVD-003 | Evidence verification state and verifier identity are explicit |
| AUT | AUT-001 | Authority is bounded by subject, purpose, resource and scope |
| AUT | AUT-002 | Owner-controlled constitutional changes carry the required approval record |
| AZN | AZN-001 | Protected operations have explicit, operation-specific authorization |
| AZN | AZN-002 | Authorization has an explicit validity interval and revocation semantics |
| SEC | SEC-001 | Trust-root status, provenance, validity and revocation are verifiable |
| SEC | SEC-002 | Missing or failed security conditions resolve to a non-authorizing state |
| ASN | ASN-001 | Required conformance evidence is complete for the declared claim |
| ASN | ASN-002 | Verification is independent of the producer for claims requiring independent assurance |
| LFC | LFC-001 | Marker, artifact and chromosome lifecycle transitions are valid |
| LFC | LFC-002 | No lifecycle transition silently discards history or changes meaning |
| EVO | EVO-001 | Version and epoch lineage is monotonic and ancestry-linked |
| EVO | EVO-002 | Mutation is covered by the correct approval class |
| EVO | EVO-003 | Rollback to an unapproved or revoked state is rejected |
| CNF | CNF-001 | Cross-chromosome dependencies and invariants are internally consistent |
| CNF | CNF-002 | The canonical fingerprint covers the complete approved constitutional payload |

### 9.1 Marker assertion schema

Each assertion MUST include: assertion_id; marker_id; subject_id; genome_version; chromosome_version; asserted_state; issuer; issued_at; valid_from; optional valid_until; evidence_refs[]; verifier; verification_method; signature_ref; supersedes_ref; and status.

Marker states are: DEFINED, OBSERVED, VERIFIED, ATTESTED, FAILED, REVOKED, UNKNOWN and NOT_APPLICABLE. DEFINED is a schema state, not a passed assertion. VERIFIED requires a recorded verification procedure and evidence. ATTESTED additionally requires a valid trusted signature. REVOKED is terminal for that assertion; a replacement assertion receives a new ID and links to the revoked one. UNKNOWN and NOT_APPLICABLE must never be silently mapped to PASS.

## 10. Cryptographic integrity and canonical fingerprint

1. The canonical constitutional payload MUST use deterministic JSON canonicalization conforming to RFC 8785 (JCS), UTF-8 encoding and duplicate-key rejection. Non-finite numbers, ambiguous encodings, unpaired surrogates and unsupported values are rejected.
2. The fingerprint algorithm is SHA-256. The digest is computed over the exact canonical UTF-8 payload bytes.
3. The fingerprint payload MUST include the DNA identity and contract version; complete Genome manifest; all 12 chromosome contracts; gene catalogue; marker definitions and schema versions; canonical principles and invariants; dependency graph; mutation policy; compatibility manifest; and historical disposition references.
4. The payload MUST NOT include its own digest, signature, attestation envelope or any field derived from the digest. This prevents self-reference and circular hashing.
5. Fingerprint equality proves equality of the fingerprinted canonical bytes under the assumed collision resistance; it does not prove source authenticity, authorization, truth or runtime conformance.
6. Digital attestations use Ed25519 signatures over a domain-separated, versioned signing envelope. Verification requires a pinned trust root, key identifier, key status, algorithm identifier, signature and revocation/validity check. Unknown or revoked keys fail closed.
7. Keys used for signing, key recovery, key rotation and trust-root administration are separate operational assets. This A2 specification does not create, provision, expose or store production private keys.
8. A fingerprint must be reproducible by an independent verifier from the same canonical payload. A producer's self-reported digest is not independent verification.

## 11. Genesis and trust-root contract

Genesis is the immutable constitutional origin record, not runtime initialization, deployment, a blockchain block, a root certificate or an authorization grant.

The v1 genesis envelope identifier is iroka.genesis.v1. It binds: DNA identity and version; Genome and 12 chromosome manifest; canonical payload digest; canonicalization and hash algorithm IDs; initial epoch; parent reference (null only for epoch zero); Owner approval record reference; trust-root public-key identifiers and provenance; genesis attestation; and audit evidence references.

Genesis MUST be unique, immutable, idempotent, non-deletable and permanently reachable from every later epoch. The genesis signature attests to the approved payload; it does not create authority by itself. The Owner approval record and trust-root policy define authority. The initial epoch is zero. Later epochs must link to the prior approved epoch and fingerprint.

The signed envelope excludes signature bytes from the payload digest, then signs a domain-separated representation containing the envelope type, version, payload digest, epoch and trust-root key identifier. Signature verification and trust-root lifecycle checks are mandatory before protected operations.

## 12. Mutation and evolution governance

| Class | Change type | Required control |
|---|---|---|
| M0 | No semantic change; formatting or metadata-only | Automated canonical diff and provenance |
| M1 | Editorial clarification with no normative semantic effect | Review, semantic equivalence note and version patch |
| M2 | Additive non-breaking gene/marker extension | Compatibility review, schema validation, conformance vectors |
| M3 | Behavior or compatibility change within approved constitutional boundaries | Security and impact review, migration/rollback plan, Owner approval where authority or protected behavior changes |
| M4 | Principle, invariant, marker meaning, dependency or constitutional enforcement change | Explicit Owner approval, independent review, new fingerprint, migration and regression evidence |
| M5 | DNA identity, genesis, trust-root policy or constitutional root change | Explicit Owner authorization, enhanced independent review, dual-control operational procedure, new epoch and anti-rollback evidence |

No chromosome, agent, model, validator or evolution service may approve its own M4/M5 change. A rejected or revoked mutation remains in the audit history. No silent mutation, downgrade, retry or evidence promotion is permitted.

## 13. Cross-chromosome invariants

- G01 identity never implies G02 authority.
- G02 authority never implies G09 authorization.
- G07 capability never implies permission for a specific G09 effect.
- G08 orchestration never creates or broadens authority.
- G03 inference never silently upgrades G04/G06 evidence.
- G05 persistence never converts uncertain information into verified truth.
- G06 external input is untrusted by default.
- G09 execution never creates authority and must produce an attributable receipt.
- G10 learning can propose but cannot approve constitutional mutation.
- G11 assurance evidence is not self-authenticating.
- G12 evolution preserves ancestry and rejects unapproved rollback.
- No chromosome may bypass G11 validation for a protected constitutional transition.

## 14. Versioning and compatibility

The DNA root version changes only through M5. Genome major version denotes breaking constitutional compatibility; minor denotes additive compatible contract extensions; patch denotes non-semantic corrections. Chromosome, gene and marker schemas are independently versioned but bound by the Genome manifest. Stable IDs are never reused. Retired IDs remain resolvable to their disposition and history.

Compatibility must be explicit: identical, backward-compatible, forward-incompatible or breaking. Unknown major versions and missing mandatory chromosome contracts fail closed. No consumer may infer compatibility from a matching display name.

## 15. Failure semantics

Invalid identity, malformed canonical payload, missing mandatory chromosome, invalid dependency graph, duplicate stable ID, invalid marker schema, missing required evidence, invalid signature, unknown/revoked trust root, unauthorized mutation, stale epoch or rollback attempt MUST NOT result in authorization or activation.

Outcomes are PASS, FAIL, INDETERMINATE, NOT_RUN or NOT_APPLICABLE. Missing evidence is INDETERMINATE or NOT_RUN, never PASS. Contradiction and uncertainty are preserved and escalated. A fail-closed result blocks the protected operation but must retain diagnostic evidence.

## 16. A2 acceptance criteria

A2 design acceptance is achieved when the Owner-approved decisions are recorded; historical principles and invariants are preserved verbatim; the eight-domain/twelve-chromosome distinction is explicit; all 12 chromosome contracts and dependencies are defined; all 27 marker IDs and assertion semantics are defined; canonical fingerprint and genesis boundaries are specified without circularity; M0–M5 governance is specified; the historical artifact inventory is dispositioned; threat, verification and migration plans are cross-linked; and no implementation or production readiness claim is inferred from documents.

A2 closure does not mean that A3 code exists, runtime enforcement passes, production trust roots are provisioned or deployment is authorized.

## 17. Owner approval record

D01–D14 were explicitly approved by the Owner with no conditions. The approved decisions are recorded in the conversation approval dated 2026-11-07 and in the associated IGACMS A2 closure record. D14 remains binding: implementation is not authorized by this specification.

## 18. References

- Historical DNA source: akeayu/iroka at 1224bb8298f9ef21d2590dd6e70273501281cd9, src/core/_legacy/dna/
- DNA-001: dna.ts, blob 7206f07941455c976af889884ec873da73349737
- DNA-002: identity-genome.ts, blob 38f6b86151d8f85c7a32d9dfbd48c0795cbe4ee3
- DNA-012: validator.ts, blob a6446ea08890da3ea195b1d977d0a9aed0c4ba64
- DNA-013: fingerprint.ts, blob d3fd1fcfaee32e3a13ca123c3f319ae8df750696
- DNA-014: registry.ts, blob bed353b724e4adf82e3d707eb793fa880be83656
- DNA-015: runtime-guard.ts, blob 08110f25282731af107ab11af2aaf4f6d4f4dec7
- DNA-044: genesis.ts, blob 3e16d2943889eca647a50b568f327261b94f1efd
- Historical build configuration: tsconfig.json at the same historical commit; excludes src/core/_legacy/**.
