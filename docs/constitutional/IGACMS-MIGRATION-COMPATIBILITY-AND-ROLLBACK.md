# IGACMS — Migration, Compatibility and Rollback Plan

**Contract:** IGACMS-MIGRATION-001 v1.0.0  
**Status:** A2 design baseline; implementation and migration execution not authorized  
**Source baseline:** historical DNA tree 1224bb8298f9ef21d2590dd6e70273501281cd9  
**Target baseline:** IROKA ZERO IGACMS v1.0.0

## 1. Migration objectives

- Preserve every historical artifact and its original commit/blob identity.
- Establish one canonical IROKA ZERO genetic hierarchy without renaming historical DNA artifacts.
- Map historical domains and modules to new chromosomes without pretending the taxonomies are equivalent.
- Preserve original principle/invariant wording and historical fingerprint/genesis evidence.
- Prevent silent loss, semantic downgrade, unauthorized activation or rollback.
- Keep all production credentials, trust-root changes and runtime promotion outside A2.

## 2. Source and target boundaries

Historical source: akeayu/iroka at commit 1224bb8298f9ef21d2590dd6e70273501281cd9. The 48-file DNA directory is legacy reference material. The inspected historical tsconfig excludes src/core/_legacy/**.

Destination: ake fadaka-git/iroka. IGACMS documents are added under docs/constitutional on a dedicated branch. No historical TypeScript files are copied into active destination source paths in A2. Existing native OS A2 documents and kernel branches remain untouched.

## 3. Migration phases

| Phase | Activity | Required output | Gate |
|---|---|---|---|
| M0 | Freeze historical evidence | source SHA, 48-file inventory, blob digests | A2 complete |
| M1 | Normalize contract model | canonical DNA, Genome, chromosome, gene, marker schemas | A2 approved |
| M2 | Map historical artifacts | disposition register and semantic traceability | A2 approved |
| M3 | Define compatibility | old DNA version to IGACMS Genome compatibility matrix | A2 approved |
| M4 | Implement adapters/validators | code, schema validators, migration tooling | A3 authorization |
| M5 | Reconcile fingerprints/genesis | new complete payload fingerprint and approved genesis envelope | A3 authorization plus Owner approvals |
| M6 | Verify and stage activation | exact-SHA test and independent assurance report | A4 evidence |
| M7 | Promote runtime | controlled activation with rollback proof | separate deployment authorization |

## 4. Compatibility rules

- Historical DNA-001 version 1.0.0 remains a preserved historical root contract.
- DNA-002 identity genome is mapped to G01 identity semantics; it is not reinterpreted as the complete 12-chromosome Genome.
- DNA-003 principles and DNA-004 invariants remain canonical and are referenced by stable IDs.
- DNA-005 through DNA-011 domain artifacts are mapped to the chromosome responsibilities in the disposition register.
- DNA-012 validator is a historical implementation candidate; its reasoning-domain omission must be fixed in a separately authorized implementation change and covered by regression.
- DNA-013 historical fingerprint remains valid only for its historical payload schema and inputs. It is not a valid digest of the new Genome.
- DNA-014 registry and DNA-015 runtime guard are preserved as historical artifacts and must be independently mapped to the new registry and boundary contracts.
- DNA-044 genesis is preserved as a historical semantic contract. The new IROKA ZERO genesis envelope must be a separately versioned record and must not overwrite historical genesis.
- DNA-045 consensus is preserved as an extension-review artifact outside the DNA-044 genesis sequence.
- Historical IDs are never reused for new chromosomes, genes or markers. New IGACMS identifiers use explicit namespaces and versioned schemas.

## 5. Canonical data migration rules

1. Preserve original source files and blobs; do not rewrite source artifacts to match the new model.
2. Every mapped record contains historical source repository, commit, path, blob SHA, historical artifact ID, new target ID, mapping rationale, reviewer, confidence and disposition.
3. A one-to-many mapping is explicit; a many-to-one mapping retains every source reference.
4. Conflicting semantics are represented as conflicts and escalated; they are not silently resolved by choosing the newest artifact.
5. Unknown or unsupported fields are retained as opaque source data or cause a typed migration error; they are not dropped.
6. Historical fingerprints are retained as historical evidence, not recomputed under a new schema and then mislabelled as the original.
7. Historical signatures and genesis records are never regenerated with new keys.
8. Any derived migration artifact receives its own digest and points to all source digests.

## 6. Rollback and recovery

Rollback is a controlled transition to a previously approved and non-revoked Genome epoch. It is not an unrestricted git reset or a way to re-enable a vulnerable state.

Rollback requires:
- a target epoch and fingerprint that remain approved and non-revoked;
- a recorded reason, scope, operator and approval;
- compatibility checks for state/data schemas;
- preservation of the current epoch and its evidence;
- a rollback transaction ID and audit record;
- independent verification of the target fingerprint and signature;
- explicit confirmation that rollback does not re-enable a revoked key or revoked marker assertion.

If the current state is partially written, the system must recover deterministically from a transaction boundary or remain unavailable for protected operations. No silent partial commit or evidence loss is permitted. If no safe rollback target exists, fail closed and escalate; do not invent a fallback.

## 7. Upgrade and rollback acceptance

- Every upgrade produces a complete manifest and fingerprint before activation.
- The prior approved manifest remains addressable and immutable.
- An activation cannot proceed with missing mandatory chromosomes, unknown major versions, invalid signatures or unresolved critical contradictions.
- A rollback cannot lower the monotonic epoch counter or bypass revocation.
- A recovery exercise must prove that audit history and source evidence remain intact.
- Migration tooling must be idempotent and must not create duplicate identities, genes or marker assertions on retry.

## 8. A3 entry prerequisites

A3 requires separately authorized scope and exact repository target; machine-readable schemas; implementation ownership for every chromosome/gene; code placement and module contracts; dependency and supply-chain review; synthetic fixtures; validator and fingerprint golden vectors; trust-root custody design; migration/rollback implementation plan; and explicit acceptance gates. This document does not authorize those implementation activities.
