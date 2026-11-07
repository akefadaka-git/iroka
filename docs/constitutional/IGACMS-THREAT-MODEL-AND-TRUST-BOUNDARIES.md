# IGACMS — Threat Model and Trust-Boundary Contract

**Contract:** IGACMS-THREAT-001 v1.0.0  
**Applies to:** DNA root, Genome manifest, 12 chromosomes, genes, markers, evidence, fingerprint, genesis, trust roots and mutation lifecycle  
**Status:** A2 design baseline; runtime controls NOT IMPLEMENTED/NOT VERIFIED  
**Security posture:** fail closed for protected transitions.

## 1. Assets and security objectives

Protected assets:
1. Canonical DNA identity and root contract.
2. Genome manifest and chromosome/gene/marker definitions.
3. Historical principle and invariant wording and lineage.
4. Marker assertions, evidence bytes, provenance and verification records.
5. Canonical fingerprint payload and digest.
6. Genesis record, epoch chain and trust-root public-key metadata.
7. Owner approval records and mutation history.
8. Registry, conformance reports and audit evidence.
9. Private signing keys and recovery material (operational secrets; never stored in this repository).

Security objectives:
- authenticity: only approved, attributable sources are accepted;
- integrity: canonical payloads and evidence are tamper-evident;
- authorization: protected changes require scoped, valid approval before mutation;
- availability: failure must not silently degrade to permissive operation;
- non-repudiation/accountability: protected transitions are attributable and auditable;
- confidentiality: private keys and restricted evidence are not disclosed;
- rollback resistance: revoked, superseded or stale epochs cannot be reactivated silently.

## 2. Trust boundaries

| Boundary | Untrusted side | Trusted only after | Required decision |
|---|---|---|---|
| Repository ingestion | branch content, forks, archives, external commits | exact SHA, provenance and review | retain/reject/hold |
| DNA-to-Genome translation | inferred mappings and generated specs | traceability review and Owner approval for semantic changes | accept/adapt/defer |
| Marker assertion | issuer claims and attached evidence | schema validation, source verification and trusted attestation | verified/unknown/failed |
| Fingerprint computation | caller-provided serialized bytes | canonicalization and independent recomputation | match/mismatch |
| Signature verification | signature and key identifier | key provenance, validity, scope and revocation check | valid/invalid/indeterminate |
| Genesis | proposed genesis payload | DNA/Genome validation, fingerprint, Owner approval and trusted signature | ratify/reject |
| Mutation | proposed patch, agent/model output | mutation-class policy and required approval | allow/deny/require approval |
| Runtime enforcement | service request and execution context | kernel-side authorization and valid chromosome state | admit/reject |
| Audit | event producer and storage backend | integrity protection, correlation and independent verification | trusted/untrusted |

No input becomes trusted merely because it is stored in Git, included in a marker, produced by an agent, or signed by an unknown key.

## 3. Threat catalogue

| Threat ID | Threat / abuse case | Impact | Required control | A2 disposition |
|---|---|---|---|---|
| TM-001 | DNA identity substitution or namespace collision | constitutional impersonation | canonical identity tuple, unique ID, root-bound manifest, fail-closed validation | specified |
| TM-002 | Genome or chromosome omission | incomplete or downgraded constitutional state | exact required chromosome set, manifest digest, no implicit defaults | specified |
| TM-003 | Gene/marker identifier reuse | semantic aliasing and evidence confusion | never reuse IDs; tombstone retired IDs; immutable history | specified |
| TM-004 | Forged marker assertion | false conformance claim | typed assertion, evidence digest, issuer authentication and independent verification | specified |
| TM-005 | Evidence laundering or source substitution | unsupported claims become “verified” | source lineage, transformation hashes, evidence state separation | specified |
| TM-006 | Fingerprint ambiguity or canonicalization differential | different payloads produce inconsistent trust decisions | RFC 8785 canonicalization, duplicate-key rejection, independent implementation vectors | specified |
| TM-007 | Signature forgery or unknown key acceptance | unauthorized genesis/mutation | Ed25519 verification, pinned trust root, key status and revocation checks | specified |
| TM-008 | Trust-root compromise | forged constitutional changes | key isolation, rotation/revocation, recovery and enhanced M5 controls | operational design required before A3 |
| TM-009 | Replay of an old valid approval | stale authorization reused | nonce/operation binding, validity interval, single-use or idempotency semantics, audit correlation | specified |
| TM-010 | Rollback to old or revoked Genome | reactivation of vulnerable state | monotonic epoch, parent digest, anti-rollback state and revocation checks | specified |
| TM-011 | Agent/model self-authorization | privilege escalation | separation of proposal, approval, authorization and execution; independent Owner authority | specified |
| TM-012 | Confused deputy across chromosomes | authority leaks through orchestration or delegation | explicit capability scope and target resource checks at G09 | specified |
| TM-013 | Validator bypass or partial validation | invalid constitutional state accepted | mandatory complete validator at activation boundaries; fail-closed | specified; runtime proof pending A3 |
| TM-014 | Circular fingerprint/genesis dependency | unverifiable or unstable digest | hash payload excludes digest/signature/attestation envelope; domain-separated signing | specified |
| TM-015 | Audit truncation, reordering or deletion | inability to reconstruct protected changes | append-only evidence chain, checkpointing, external anchoring policy | A3 design/implementation gate |
| TM-016 | Silent mutation through learning/evolution | unauthorized constitutional drift | G10 proposal-only, G12 mutation classes, M4/M5 Owner approval | specified |
| TM-017 | Supply-chain substitution of validator or crypto library | malicious verification path | pinned dependencies, SBOM, reproducible builds, signed provenance, independent review | A3 gate |
| TM-018 | Denial of service against validation or revocation | availability failure or permissive fallback | bounded parsing, timeouts, cached revocation policy with expiry; protected operations fail closed | specified |
| TM-019 | Cross-chromosome dependency cycle | inconsistent evaluation or bypass | acyclic dependency graph by default; explicit cycle rejection | specified |
| TM-020 | False claim of active enforcement based on legacy code | assurance overstatement | source/build/runtime evidence separation and exact-SHA reporting | specified |

## 4. Adversary capabilities

The design assumes an adversary may:
- submit malformed, oversized or adversarially structured payloads;
- control an untrusted repository branch, package, agent or model output;
- replay an earlier signed message or approval;
- alter, omit or reorder marker/evidence records;
- exploit parser differentials, duplicate JSON keys or Unicode edge cases;
- compromise an application-level service or one agent identity;
- cause network, clock, storage, revocation or audit-service outages;
- attempt to use a valid but out-of-scope credential;
- attempt to induce a validator to accept partial or unknown state.

The design does not assume compromise of the Owner's independent approval authority and all independently held trust roots simultaneously. That residual scenario requires separate recovery and governance controls.

## 5. Required security invariants

1. Identity does not confer authority.
2. Authority does not confer operation-specific authorization.
3. Authorization is checked before protected execution.
4. A model or agent can propose but cannot approve its own protected action.
5. Unknown, missing, revoked or invalid trust state never becomes allow.
6. Evidence receipt is distinct from evidence verification and substantive truth.
7. Fingerprint equality is distinct from signature authenticity.
8. A signature is valid only for the exact domain-separated payload and authorized key scope.
9. Genesis is immutable and cannot be rerun or silently superseded.
10. A mutation's approval class cannot be lowered by the proposing component.
11. Every protected state transition produces a correlated audit/evidence record.
12. A failure to persist required audit evidence blocks the protected transition unless a separately approved, bounded recovery protocol explicitly governs it.

## 6. Cryptographic and key-custody contract

- Digest: SHA-256 over RFC 8785 canonical UTF-8 bytes.
- Signature profile: Ed25519, with algorithm and envelope version explicitly bound.
- Trust roots: public key identifiers, public-key digests, provenance, activation interval, revocation state, allowed purposes and issuer scope.
- Key custody: private keys are held outside source control in an approved secure custody mechanism. No private key, seed, recovery phrase or secret is placed in Git, logs, fixtures or test output.
- Key rotation: new key is authorized by the currently valid governance policy; transition records link old and new key IDs; revocation takes effect for future protected operations.
- Revocation: an unavailable revocation source is INDETERMINATE; protected operations fail closed when freshness is required.
- Separation: genesis signing, routine attestation and operational service credentials must not share an unrestricted private key.
- Recovery: recovery requires a predeclared independent authority path, evidence preservation and explicit Owner-approved procedure; a compromised key cannot authorize its own replacement.

## 7. Residual risks and A3 prerequisites

The A2 design does not prove:
- production trust roots exist or are safely provisioned;
- key custody or recovery services are operational;
- validator enforcement is wired into every runtime boundary;
- audit evidence is externally checkpointed;
- crypto implementation is constant-time or independently audited;
- the active build includes the historical DNA source;
- bare-metal or production environments satisfy these controls.

These are explicit A3/A4 gates. No production-ready or runtime-conformant claim is permitted until exact-SHA evidence proves them.
