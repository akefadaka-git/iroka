# IROKA A2 Character Gene Contracts

**Contract ID:** IROKA-A2-CHARACTER-GENE-001  
**Version:** 1.0.0  
**Status:** A2 normative logical contract proposal  
**Parent:** Owner-approved IROKA Character Constitution v1.0.0  
**Coverage:** 12 chromosomes, 36 existing genes

## 1. Purpose

Translate the frozen A1 character constitution into gene-specific logical input/output contracts, authority boundaries, failure semantics and conformance expectations. This is contract definition, not runtime implementation.

## 2. Contract model

Each gene contract defines gene-specific required input fields and their meaning; shared provenance and version-bound evidence requirements; gene-specific output fields and decision semantics; applicable character virtues; explicit failure behavior; positive and negative conformance identifiers; and an authority boundary.

The machine-readable register is `IROKA-A2-CHARACTER-GENE-CONTRACTS-v1.0.0.json`. The positive/negative test catalogue is `IROKA-A2-CHARACTER-CONFORMANCE-CATALOG-v1.0.0.json`.

## 3. Gene coverage and contract discipline

The register contains 36 distinct gene contracts, exactly three under each of the 12 existing chromosomes. Required inputs and outputs are specific to each gene's responsibility; they are not generic placeholder schemas. Shared evidence fields are additive and cannot replace gene-specific semantics.

## 4. A2 reconciliation requirements

1. Resolve each gene ID against the canonical genome.
2. Resolve the existing input and output schema references for that exact gene.
3. Compare every proposed field with the approved gene purpose, invariant anchors, permitted effects, authority requirements, evidence requirements and failure semantics.
4. Record additive, mapped, conflicting, redundant and missing fields.
5. Reject silent weakening, external `$ref` dependencies, schema drift and generic catch-all payloads.
6. Generate separate input/output JSON Schemas only from reconciled gene-specific contracts.
7. Validate all local `$ref` targets and execute positive/negative conformance vectors against the exact commit.

## 5. A2 exit criteria

- [x] 36 gene-specific logical character contracts defined.
- [x] 12 chromosome coverage preserved.
- [x] 72 positive/negative behavioral test designs defined.
- [ ] Exact reconciliation against all 72 existing gene IO schemas.
- [ ] Machine-readable JSON Schema deltas generated.
- [ ] Schema resolver and internal `$ref` validation run.
- [ ] Executable conformance tests and exact-head CI run.
- [ ] Independent A2 review and closure record.

## 6. Stage boundary

A2 is design and reconciliation only. No runtime code, training, model behavior activation, production keys, merge or deployment is authorized. A3 requires separate Owner approval.
