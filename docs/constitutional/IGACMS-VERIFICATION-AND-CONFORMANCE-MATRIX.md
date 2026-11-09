# IGACMS — Verification and Conformance Matrix

**Contract:** IGACMS-CONF-001 v1.0.0  
**Status:** A2 verification design; no runtime tests claimed  
**Parent:** IGACMS v1.0.0 Owner-approved baseline

## 1. Result vocabulary

- PASS: exact test procedure ran and expected result was observed on the stated SHA/environment.
- FAIL: test ran and a prohibited or unexpected result occurred.
- INDETERMINATE: evidence is incomplete or an oracle/source is unavailable.
- NOT RUN: no execution evidence exists.
- NOT APPLICABLE: the case is outside the declared scope with a recorded reason.
- BLOCKED: a required prerequisite is missing.

A document review is not a runtime test. A test definition is not a test result. A green build of code that excludes the legacy DNA directory is not evidence that the legacy DNA is active.

## 2. A2 design verification register

| Gate | Verification | Evidence reviewed | Result |
|---|---|---|---|
| A2-IG-01 | Canonical identity and hierarchy consistency | DNA-001 and DNA-002 exact source; approved IGACMS baseline | PASS |
| A2-IG-02 | Eight historical domains distinguished from 12 chromosomes | DNA-001 source and chromosome catalogue | PASS |
| A2-IG-03 | Canonical principle inventory count and IDs | DNA-001 exact source | PASS — 14 |
| A2-IG-04 | Canonical invariant inventory count and IDs | DNA-001 exact source | PASS — 14 |
| A2-IG-05 | Historical numbered artifact inventory | recursive tree at 1224bb8298f9ef21d2590dd6e70273501281cd9 | PASS — DNA-001..045 |
| A2-IG-06 | Historical file inventory | exact path/blob SHA list | PASS — 48 files |
| A2-IG-07 | DNA-012 domain consistency | DNA-001 versus DNA-012 required-domain list | PASS — inconsistency identified and recorded |
| A2-IG-08 | Historical fingerprint coverage versus new Genome | DNA-013 input schema versus IGACMS v1.0 payload | PASS — coverage gap identified |
| A2-IG-09 | Historical runtime inclusion | historical tsconfig.json | PASS — legacy path excluded |
| A2-IG-10 | New 12 chromosome contracts | IGACMS baseline | PASS — design contract defined |
| A2-IG-11 | Marker registry | 11 families, 27 stable IDs, assertion lifecycle | PASS — design contract defined |
| A2-IG-12 | Fingerprint/genesis non-circularity | IGACMS integrity and genesis clauses | PASS — design contract defined |
| A2-IG-13 | Mutation classes and approval gates | M0–M5 policy | PASS — design contract defined |
| A2-IG-14 | Threat model and trust boundaries | IGACMS-THREAT-001 | PASS — design contract defined |
| A2-IG-15 | Migration and rollback design | IGACMS-MIGRATION-001 | PASS — design contract defined |
| A2-IG-16 | Owner decisions | D01–D14 Owner instruction, no conditions | PASS — 14/14 |

These PASS results apply to the A2 specification/reconciliation review only. They do not mean runtime code or cryptographic operations passed.

## 3. Required A3 executable test suites

| Suite | Test focus | Mandatory adversarial cases | Expected critical threshold |
|---|---|---|---|
| IG-IDN | DNA/Genome identity | wrong ID, wrong lineage, duplicate IDs, unsupported major version | 0 invalid identities accepted |
| IG-CHR | chromosome manifest | missing/extra chromosome, dependency cycle, duplicate chromosome, wrong version | 0 malformed Genomes accepted |
| IG-GENE | gene contract | missing schema, unauthorized effect, dependency mismatch | 0 invalid gene contracts activated |
| IG-MRK | marker assertion | forged issuer, missing evidence, revoked assertion, UNKNOWN mapped to PASS | 0 invalid assertions accepted |
| IG-PRN | principles/invariants | altered statement, changed domain/severity/behavior, duplicate ID | 100% canonical catalog match |
| IG-FPR | fingerprint | canonicalization differential, duplicate key, unsupported value, payload omission, changed digest | 0 mismatch accepted |
| IG-SIG | attestation | invalid signature, wrong key, wrong purpose, revoked/unknown key, wrong envelope | 0 invalid signatures accepted |
| IG-GEN | genesis | missing approval, repeated genesis, wrong fingerprint, missing trust root, circular digest | 0 invalid genesis records ratified |
| IG-AUT | authority and authorization | identity-to-authority confusion, capability-as-permission, expired scope, replay | 0 unauthorized actions admitted |
| IG-MUT | mutation governance | M4/M5 attempted by agent, downgrade class, missing approval, silent mutation | 0 unauthorized mutations applied |
| IG-EVO | evolution/rollback | stale epoch, forked lineage, revoked parent, rollback to older fingerprint | 0 unauthorized rollback accepted |
| IG-AUD | audit and evidence | missing event, reordered event, deleted evidence, failed checkpoint | 100% protected transitions correlated |
| IG-CRS | cross-chromosome invariants | G08 authority expansion, G10 self-approval, G09 bypass of G11 | 0 cross-boundary violations |
| IG-REC | recovery | key revocation outage, audit store outage, interrupted mutation, partial write | no permissive fallback or silent loss |

## 4. Required test case record

Every executable case records: test ID; requirement and invariant IDs; suite; class (positive, negative, boundary, fault-injection, adversarial or regression); preconditions; immutable fixture ID and digest; exact procedure; exact expected result; severity; environment; verifier; exact source SHA; dependency lock; start/end; exit code; raw evidence reference; result status.

Every fixed defect gets a stable regression test linked to the source and fixing commits. Fixtures must not contain production secrets. Test signatures use synthetic test keys clearly marked non-production.

## 5. Mandatory negative and boundary tests

- absent DNA root; malformed identity; unsupported contract major version;
- each of the 12 chromosomes missing individually and all required combinations;
- duplicated IDs at DNA, Genome, chromosome, gene and marker levels;
- invalid dependency edges and cycles;
- each marker state transition, including VERIFIED to REVOKED and attempts to revive a revoked assertion;
- canonical JSON duplicate keys, reordered keys, invalid Unicode, non-finite numeric values and unknown fields;
- SHA-256 mismatch, signature mismatch, unknown/revoked trust root and stale revocation evidence;
- Owner approval bound to a different payload, version, mutation class, scope or epoch;
- M4/M5 request from G10 or G12 without Owner approval;
- repeated genesis, second epoch-zero genesis and genesis mutation;
- replayed approval, expired authorization, wrong resource, wrong purpose and cross-agent delegation;
- audit store unavailable during a protected operation;
- interrupted mutation before and after commit boundary;
- attempted rollback to a prior but revoked Genome.

## 6. Independence and assurance

The producer must not be the sole verifier of its own fingerprint, signature, marker assertion or conformance result. Independent verification means a separately executed implementation or independently controlled verification path, not merely a second wrapper around the same function.

Critical security invariants have zero tolerance. Aggregate percentages cannot mask one critical failure. NOT RUN, BLOCKED and INDETERMINATE never count as PASS.

## 7. A2/A3/A4 boundary

A2 defines the test architecture and expected outcomes. A3 builds the validator, marker registry, fingerprint/genesis services and test harness after separate authorization. A4 executes them against exact SHAs and records evidence. No test has been run by this document's creation. Production and hardware conformance remain outside this A2 closure.
