# IGACMS — Historical DNA Inventory and Disposition Register

**Register:** IGACMS-HIST-DISP-001 v1.0.0  
**Source repository:** akeayu/iroka (historical reference only)  
**Exact source commit:** 1224bb8298f9ef21d2590dd6e70273501281cd9  
**Tree status:** complete, not truncated  
**Inventory:** 48 files under src/core/_legacy/dna/ (45 numbered DNA artifacts plus 3 test specifications)  
**Disposition rule:** preserve source bytes and history; no automatic runtime promotion or deletion.

## 1. Reconciliation conclusion

The inspected historical tree contains DNA-001 through DNA-045. The Owner decision D03 expressly preserves DNA-001 through DNA-044; the additional DNA-045 consensus artifact is also retained because it is present in the historical source and falls within the broader requirement to preserve historical work. DNA-045 is recorded as a post-genesis extension and is not silently inserted into the DNA-044 genesis sequence.

All 48 files remain historical source evidence. The proposed IROKA ZERO Genome is a new constitutional architecture layer. Historical modules are candidates for semantic adaptation, not direct drop-in implementations. Any A3 port requires an independent contract mapping, code review, test adaptation and explicit authorization.

## 2. Exact artifact inventory

Disposition values:
- RETAIN-HISTORICAL: preserve exact historical source and provenance.
- ADAPT-SEMANTICS: map selected contract semantics to the new chromosome/gene model; do not copy code automatically.
- TEST-EVIDENCE-ONLY: preserve historical tests as test-design evidence; they are not current passing evidence.
- EXTENSION-REVIEW: preserve an artifact beyond the explicit DNA-001..044 genesis range and require separate lineage review.

| Historical ID | File | Blob SHA | A2 disposition | Candidate mapping |
|---|---|---|---|---|
| DNA-001 | dna.ts | 7206f07941455c976af889884ec873da73349737 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | DNA root; all chromosomes |
| DNA-002 | identity-genome.ts | 38f6b86151d8f85c7a32d9dfbd48c0795cbe4ee3 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G01 |
| DNA-003 | principles.ts | 1b358313b4d1c7612d9938a150f1b6061ababa1e | RETAIN-HISTORICAL; ADAPT-SEMANTICS | Cross-cutting constitutional principles; G11 |
| DNA-004 | invariants.ts | 012a25088b021036ff14288dc53913b01966ab01 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | Cross-cutting invariants; G11 |
| DNA-005 | capabilities.ts | 867dcc311604e717258e034ab3589b382ff02dce | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G07, G09 |
| DNA-006 | authority.ts | a46aec19423a0b2abfc1e7fc6e5f0b36fabae2a5 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02 |
| DNA-007 | evidence.ts | a913d5bdb88c39a5ece6e29591dfd35cf329e862 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G04, G06, G11 |
| DNA-008 | assurance.ts | 3e622b9b5fc442efa6b71720fcf14ff394202614 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11 |
| DNA-009 | security.ts | dc9d7cedc99c5b0eb68d20cf6e458c911cd4996a | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G01, G02, G07, G09, G11 |
| DNA-010 | execution.ts | 8f9db5db279f78b74af36c95a142935fd293bea4 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G08, G09 |
| DNA-011 | evolution.ts | 919e6cfc4f37b5196aac6a4ebfba3970c47e2994 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G10, G12 |
| DNA-012 | validator.ts | a6446ea08890da3ea195b1d977d0a9aed0c4ba64 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11 |
| DNA-013 | fingerprint.ts | d3fd1fcfaee32e3a13ca123c3f319ae8df750696 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11; new full-Genome fingerprint |
| DNA-014 | registry.ts | bed353b724e4adf82e3d707eb793fa880be83656 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | Genome registry; G11 |
| DNA-015 | runtime-guard.ts | 08110f25282731af107ab11af2aaf4f6d4f4dec7 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G09, G11 |
| DNA-016 | authorization.ts | 714faec0d7bc5c704e72101feb069b1857365133 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G07, G09 |
| DNA-017 | admission.ts | 16bc3c5975950d23f3f0fde6e8b7afe367a613dc | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G09 |
| DNA-018 | audit.ts | ef22b347977d2cd0a7a4f30ac72a78a3c408682c | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11 |
| DNA-019 | knowledge.ts | 798de6c52a90f5b0ff4ade48cac59bb7aa57b89a | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G04 |
| DNA-020 | reasoning.ts | c29a948508c113e609f5b4e254b540da374ae018 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G03 |
| DNA-021 | orchestration.ts | 346a98560c0d21276dd2d1074c1e4bd9b789e87b | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G08 |
| DNA-022 | subject.ts | 40c23b5fd022d5bd947bfea6d2ebcd5b0af8112f | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G01, G07 |
| DNA-023 | policy.ts | 1a333e95ebda9701e25c6b489b05191097023087 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G07, G09 |
| DNA-024 | goal.ts | 47e6af6e9ff9134e451e0fd180eb8a656ad790f0 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G03, G08 |
| DNA-025 | value.ts | 6f08c8fcd2257587116f4c464a443f262e48f8e1 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G03, G04 |
| DNA-026 | temporal.ts | b0fbdbdd6ecee21b964a580098bf97aec71340fe | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G05, G08, G09, G12 |
| DNA-027 | uncertainty.ts | 44b84bc71f6735fe43c4acd115fc84b1b1b006f0 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G03, G04, G11 |
| DNA-028 | contradiction.ts | 1587fb402f7a1c05227a4254dcf84dcbfe29dcf8 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G03, G04, G11 |
| DNA-029 | oversight.ts | 1d68376bfb2d36195238f459caf6dce50f32b389 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G11, G12 |
| DNA-030 | memory.ts | 8debe3de23b31281db7756e7fa7cace639931a39 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G05 |
| DNA-031 | learning.ts | 73eec3bb9ef1c31a0f22d3cc4b227713b89efa44 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G10 |
| DNA-032 | model-governance.ts | 220179935acc2ef63c28f4864978d84751482dfd | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G10, G11 |
| DNA-033 | incident.ts | 83d117c3d946369c46c0f86b6552e1a6106af9a6 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G09, G11, G12 |
| DNA-034 | amendment.ts | 57b259ea5cb8a8b08e40647c3e007e8892b49e65 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G12 |
| DNA-035 | privacy.ts | c8dd7456c20a1ec36715146dece32880fec23b5f | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G02, G05, G06 |
| DNA-036 | notarization.ts | e8d16fbaaf6d1ed516ed4f1c87741e54612d1ebb | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11, G12 |
| DNA-037 | attestation.ts | bdf4fd6dd11ca7678078a2b89d65145f482a6d21 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11 |
| DNA-038 | replay.ts | b150c6f205da67fb9f144d706f042c79d3007455 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G09, G11 |
| DNA-039 | interoperability.ts | d42f562cad3e0d04efea0ce56e281e28147988e0 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G04, G07, G08 |
| DNA-040 | sandbox.ts | 1f25888ecc3088c835aa5db96e40a0bb2bb0bb10 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G07, G09 |
| DNA-041 | boundary.ts | 5157d5f2ed1bfae3edb178cc58ef55efae957b72 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G01, G02, G07, G09 |
| DNA-042 | observability.ts | f521cbdb2098289599481081d3a8501c41d2b466 | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G11 |
| DNA-043 | errors.ts | b795dcbbee4533942a0d551ca20600be7551dc3e | RETAIN-HISTORICAL; ADAPT-SEMANTICS | All; typed failure semantics |
| DNA-044 | genesis.ts | 3e16d2943889eca647a50b568f327261b94f1efd | RETAIN-HISTORICAL; ADAPT-SEMANTICS | G01, G02, G11, G12 |
| DNA-045 | consensus.ts | edd58b38fb2f2098aeea9716d0eba0897a753811 | EXTENSION-REVIEW; RETAIN-HISTORICAL | G02, G03, G11; outside DNA-044 genesis sequence |
| TEST | dna.validation.spec.ts | e3727afb62fb646eb1d1610a85d54936e49e3ac3 | TEST-EVIDENCE-ONLY | Historical DNA-001 contract behavior |
| TEST | smoke.spec.ts | a1c5b655d097be366dcea25fde0bb42e1c43ed1b | TEST-EVIDENCE-ONLY | Historical smoke coverage |
| TEST | validator.contract.spec.ts | d0e1d390bb2998ff7fdf586c9cfb9f9e81077cb5 | TEST-EVIDENCE-ONLY | Historical DNA-012 validator behavior |

## 3. Confirmed historical findings

### 3.1 DNA-001 root contract

DNA-001 defines iroka.dna, IROKA_CONSTITUTIONAL_DNA_CONTRACT version 1.0.0, eight domains, 14 canonical principles and 14 canonical invariants. The exact principle and invariant IDs and statements are preserved in IGACMS-V1.0-A2-OWNER-APPROVED-BASELINE.md.

### 3.2 DNA-002 is not the IROKA ZERO 12-chromosome Genome

DNA-002 defines an identity genome containing the stable system ID, identity namespace, lineage and compatibility family. It explicitly does not identify an actor, process, deployment, execution, resource, request or session. It is mapped to G01 as historical identity semantics; it is not evidence that G01–G12 are implemented.

### 3.3 DNA-012 domain omission

DNA-001 declares the reasoning domain. DNA-012's REQUIRED_CONSTITUTIONAL_DOMAINS list at the inspected source commit contains identity, authority, evidence, assurance, security, execution and evolution, but omits reasoning. This is a confirmed source inconsistency. Because the entire historical directory is excluded by tsconfig, this is recorded as a historical validator defect and A3 remediation candidate, not as a live runtime defect on the destination repository.

### 3.4 DNA-013 fingerprint coverage

DNA-013 uses SHA-256 over a canonicalized input containing DNA-001, principles, invariants, capabilities, authority, evidence, assurance, security, execution and evolution. The validator is run as a precondition, and the registry records a validator dependency, but the fingerprint input schema does not contain the validator as a payload field. It does not include DNA-002 identity-genome, the new 12-chromosome Genome catalogue, the new IGACMS gene catalogue or the v1.0 marker registry. Its historical fingerprint must not be reused as proof of the new Genome's integrity.

### 3.5 DNA-014 registry and DNA-015 runtime guard

DNA-014 provides an immutable, explicit historical artifact registry and states that registry membership does not grant authority or authorization. DNA-015 defines constitutional runtime guard boundaries. These are historical design/code artifacts; their presence does not prove active IROKA ZERO enforcement.

### 3.6 DNA-044 genesis

DNA-044 defines a constitutional genesis record and extensive invariants. Its own module documentation explicitly states that it does not physically establish the initial trust root, create the initial audit chain, compute the initial fingerprint, sign the attestation, notarize the record or execute the oversight review. Those operations must not be claimed complete from the TypeScript contract alone.

### 3.7 Build exclusion

At the same historical commit, tsconfig.json excludes src/core/_legacy/**. Successful TypeScript compilation of the active project therefore cannot be used as proof that the legacy DNA modules are compiled or enforced by the active runtime.

## 4. Historical domain-to-chromosome mapping

| Historical domain | Primary chromosome mappings | Mapping rule |
|---|---|---|
| identity | G01; supporting G07 | System identity is G01; actor/agent identity is separated into G07 |
| authority | G02, G07, G08, G09 | Governance, capabilities, delegation and operation-specific authorization remain separate |
| evidence | G04, G06, G11 | Source input, knowledge provenance and assurance evidence remain distinct |
| assurance | G11; supporting G03/G04 | Validation and conformance belong to G11; uncertainty and contradiction are preserved by cognitive/knowledge contracts |
| reasoning | G03 | Inference and premise semantics map to the Cognitive chromosome |
| security | G01, G02, G07, G09, G11 | Identity trust, Owner governance, agent capability, execution admission and independent assurance |
| execution | G08, G09 | Coordination is distinct from protected effects |
| evolution | G10, G12 | Learning proposals are distinct from constitutional mutation and version lineage |

This is a semantic mapping, not a one-to-one rename. The mapping does not authorize code copying or deletion of historical modules.

## 5. Disposition policy

1. Preserve the historical repository and all 48 inventoried files unchanged.
2. Do not move or copy the legacy code into the active destination tree during A2.
3. Preserve historical tests as test-design evidence, not as current PASS evidence.
4. Adapt contract semantics only after a gene-level traceability record exists.
5. Resolve DNA-045 separately because it post-dates the DNA-044 genesis sequence.
6. Never rewrite historical artifact IDs, fingerprints, signatures, genesis references or commit history.
7. A3 migration requires an explicit Owner authorization and exact-SHA implementation scope.
