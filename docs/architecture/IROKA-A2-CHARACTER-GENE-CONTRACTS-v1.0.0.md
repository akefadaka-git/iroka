# IROKA A2 Character Gene Contracts

**Contract ID:** IROKA-A2-CHARACTER-GENE-001  
**Version:** 1.0.0  
**Status:** A2 logical contracts reconciled to the Owner-approved gene IO proposal; schema execution and independent review remain open  
**Parent:** Owner-approved IROKA Character Constitution v1.0.0  
**Coverage:** 12 chromosomes, 36 existing genes

## 1. Purpose

Translate the frozen A1 character constitution into gene-specific logical input/output contracts, authority boundaries, failure semantics and conformance expectations. This is contract definition, not runtime implementation.

## 2. Contract model

Each gene contract defines gene-specific required input fields and their meaning; shared provenance and version-bound evidence requirements; gene-specific output fields and decision semantics; applicable character virtues; explicit failure behavior; positive and negative conformance identifiers; and an authority boundary.

The machine-readable register is `IROKA-A2-CHARACTER-GENE-CONTRACTS-v1.0.0.json`. The positive/negative test catalogue is `IROKA-A2-CHARACTER-CONFORMANCE-CATALOG-v1.0.0.json`. The 72-file schema audit is `IROKA-A2-CHARACTER-SCHEMA-RECONCILIATION-v1.0.0.json`.

## 3. Gene coverage and contract discipline

The register contains 36 distinct gene contracts, exactly three under each of the 12 existing chromosomes. Required inputs and outputs are specific to each gene's responsibility; they are not generic placeholder schemas. Shared evidence fields are additive and cannot replace gene-specific semantics.

## 4. A2 reconciliation requirements

1. Resolve each gene ID against the canonical genome.
2. Resolve the existing input and output schema references for that exact gene against the Owner-approved gene IO proposal branch and pin the source commit.
3. Compare every proposed field with the approved gene purpose, invariant anchors, permitted effects, authority requirements, evidence requirements and failure semantics.
4. Record additive, mapped, conflicting, redundant and missing fields.
5. Reject silent weakening, external `$ref` dependencies, schema drift and generic catch-all payloads.
6. Do not add schema fields unless the reconciliation demonstrates a real contract gap; the current character overlay reuses existing gene-specific IO fields and does not modify the 72 baseline schemas.
7. Validate all local `$ref` targets and execute positive/negative conformance vectors against the exact commit.

## 5. A2 exit criteria

- [x] 36 gene-specific logical character contracts defined.
- [x] 12 chromosome coverage preserved.
- [x] 72 positive/negative behavioral test designs defined.
- [x] Reconcile all 36 input/output contract definitions and inspect all 72 referenced schema files for matching schema IDs, required-field coverage, closed objects and resolvable local JSON Pointer references.
- [x] No JSON Schema delta required for this overlay; existing 72 schemas remain unchanged. Any future delta requires separate field-level justification.
- [ ] Full automated resolver, external-reference prohibition scan and reference-cycle detection run.
- [ ] Executable conformance tests and exact-head CI run (72 cases are designed, not executed).
- [ ] Independent A2 review and closure record.

## 6. Reconciliation evidence\n\nThe referenced gene IO baseline is `architecture/genesis-gene-contract-amendment-proposal` at `8e4a8b5582d47d430539ae7b56aac75f0991c8a4`, with proposal blob `0dea137514313a2f59bec7be4df53bec05330b45`. The 36 input/output contract definitions and 72 schema files were inspected. The checked invariants were schema `$id` equality, required-field coverage including the mandatory top-level `version_bound_evidence`, `additionalProperties: false`, and resolution of encountered local JSON Pointer `$ref` targets. All 72 inspected schema files passed these checks. The source schema branch remains separate from this A2 branch; no schema files were copied or modified. Full automated resolver/cycle checks and external-reference policy scan remain open.\n\n## 7. Stage boundary

A2 is design and reconciliation only. No runtime code, training, model behavior activation, production keys, merge or deployment is authorized. A3 requires separate Owner approval.
