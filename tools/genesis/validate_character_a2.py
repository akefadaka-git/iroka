#!/usr/bin/env python3
"""Fail-closed A2 character overlay, schema binding and catalog verifier.

This verifies A2 contract-to-schema traceability and executes the existing
gene-IO JSON Schema fixtures. It does not claim to execute A3 character
semantics or activate any runtime behavior.
"""
import json
import sys
from pathlib import Path

from validate_gene_schemas import ROOT, check_ref_graph, load
from jsonschema import Draft202012Validator

CONTRACTS = ROOT / "docs/architecture/IROKA-A2-CHARACTER-GENE-CONTRACTS-v1.0.0.json"
CATALOG = ROOT / "docs/architecture/IROKA-A2-CHARACTER-CONFORMANCE-CATALOG-v1.0.0.json"
RECONCILIATION = ROOT / "docs/architecture/IROKA-A2-CHARACTER-SCHEMA-RECONCILIATION-v1.0.0.json"
A1 = ROOT / "docs/architecture/IROKA-A1-CHARACTER-RECONCILIATION-v1.0.0.json"
GENOME = ROOT / "crates/iroka-kernel/igacms/genome-v1.0.0.json"
GENE_IO = ROOT / "docs/architecture/GENESIS-GENE-IO-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
FIXTURES = ROOT / "crates/iroka-kernel/igacms/conformance/gene-io-v1.0.0.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expect_rejected(schema, expected_fragment):
    try:
        check_ref_graph(schema)
    except Exception as exc:
        require(expected_fragment in str(exc), "Reference-graph probe failed for the wrong reason: " + str(exc))
        return
    raise ValueError("Reference-graph probe unexpectedly passed: " + expected_fragment)


def verify_reference_engine():
    # Prove that the resolver handles RFC 6901 escaping and detects the
    # negative conditions it is expected to reject.
    escaped = {
        "$defs": {"a/b~c": {"type": "string"}},
        "properties": {"value": {"$ref": "#/$defs/a~1b~0c"}},
    }
    check_ref_graph(escaped)
    expect_rejected(
        {"properties": {"value": {"$ref": "https://example.invalid/schema.json"}}},
        "External $ref forbidden",
    )
    expect_rejected(
        {
            "$defs": {
                "left": {"$ref": "#/$defs/right"},
                "right": {"$ref": "#/$defs/left"},
            },
            "properties": {"value": {"$ref": "#/$defs/left"}},
        },
        "Cyclic internal $ref dependency",
    )
    try:
        check_ref_graph({"properties": {"value": {"$ref": "#/$defs/missing"}}})
    except Exception:
        pass
    else:
        raise ValueError("Unresolved local JSON Pointer probe unexpectedly passed")


def main():
    contracts_doc = load(CONTRACTS)
    catalog_doc = load(CATALOG)
    reconciliation_doc = load(RECONCILIATION)
    a1_doc = load(A1)
    genome_doc = load(GENOME)
    gene_io_doc = load(GENE_IO)
    fixtures_doc = load(FIXTURES)

    require(contracts_doc.get("scope", {}).get("chromosomes") == 12, "Character contract chromosome count is not 12")
    require(contracts_doc.get("scope", {}).get("genes") == 36, "Character contract gene count is not 36")
    require(contracts_doc.get("scope", {}).get("new_chromosomes") == 0, "Character amendment adds chromosomes")
    require(contracts_doc.get("scope", {}).get("new_genes") == 0, "Character amendment adds genes")
    require(contracts_doc.get("scope", {}).get("runtime_code_changes") == 0, "A2 contract unexpectedly claims runtime changes")
    require(gene_io_doc.get("status") == "OWNER_APPROVED_NORMATIVE_BASELINE", "GENESIS IO baseline is not Owner-approved")

    character_contracts = {item["gene_id"]: item for item in contracts_doc.get("gene_contracts", [])}
    a1_genes = {item["gene_id"]: item for item in a1_doc.get("genes", [])}
    genome_genes = {item["id"]: item for item in genome_doc.get("genes", [])}
    io_contracts = {item["gene_id"]: item for item in gene_io_doc.get("contracts", [])}
    fixture_cases = {item["gene_id"]: item for item in fixtures_doc.get("cases", [])}
    catalog_cases = catalog_doc.get("cases", [])
    reconciliation_genes = {item["gene_id"]: item for item in reconciliation_doc.get("genes", [])}

    require(len(character_contracts) == 36, "Expected 36 unique character gene contracts")
    require(len(a1_genes) == 36, "Expected 36 A1 character reconciliation genes")
    require(len(genome_genes) == 36, "Expected 36 canonical Genome genes")
    require(len(io_contracts) == 36, "Expected 36 approved GENESIS IO contracts")
    require(len(fixture_cases) == 36, "Expected 36 executable GENESIS IO fixture cases")
    require(len(catalog_cases) == 72, "Expected 72 character conformance design cases")
    require(len(reconciliation_genes) == 36, "Expected 36 schema reconciliation entries")
    require(set(character_contracts) == set(a1_genes) == set(genome_genes) == set(io_contracts) == set(fixture_cases) == set(reconciliation_genes),
            "Character contracts, A1, Genome, GENESIS IO and reconciliation gene sets differ")

    catalog_by_gene = {}
    catalog_ids = set()
    for case in catalog_cases:
        case_id = case.get("case_id")
        gene_id = case.get("gene_id")
        polarity = case.get("polarity")
        require(case_id and case_id not in catalog_ids, "Missing or duplicate character case ID: " + str(case_id))
        require(polarity in ("positive", "negative"), "Invalid character case polarity: " + str(case_id))
        catalog_ids.add(case_id)
        catalog_by_gene.setdefault(gene_id, {})[polarity] = case

    schema_ids = set()
    schema_paths = set()
    external_refs = 0
    local_refs = 0
    executed_positive = 0
    executed_negative = 0
    input_controls = 0
    output_assertions = 0

    for gene_id, contract in character_contracts.items():
        a1_gene = a1_genes[gene_id]
        genome_gene = genome_genes[gene_id]
        io_contract = io_contracts[gene_id]
        fixture = fixture_cases[gene_id]
        reconciliation = reconciliation_genes[gene_id]
        baseline = contract["gene_io_baseline"]

        require(contract.get("chromosome_id") == a1_gene.get("chromosome_id"), "Chromosome mismatch: " + gene_id)
        require(contract.get("character_virtues") == a1_gene.get("virtues"), "Virtue mapping mismatch: " + gene_id)
        require(contract.get("character_obligation") == a1_gene.get("character_obligation"), "Character obligation mismatch: " + gene_id)
        require(contract.get("prohibited_behavior") == a1_gene.get("prohibited_behavior"), "Prohibited behavior mismatch: " + gene_id)
        require(contract.get("chromosome_id") == gene_id[1:3] + ".", "Character chromosome mapping mismatch: " + gene_id)
        require(genome_gene.get("chromosome_id") == "G" + gene_id[1:3], "Genome chromosome mapping mismatch: " + gene_id)
        require(contract.get("gene_invariant_anchors") == genome_gene.get("invariant_anchors"),
                "Character contract invariant anchors differ from Genome: " + gene_id)
        require(contract.get("permitted_effects") == genome_gene.get("permitted_effects"),
                "Character contract permitted effects differ from Genome: " + gene_id)
        require(contract.get("authority_requirements") == genome_gene.get("authority_requirements"),
                "Character contract authority requirements differ from Genome: " + gene_id)
        require(contract.get("failure_semantics") == genome_gene.get("failure_semantics"),
                "Character contract failure semantics differ from Genome: " + gene_id)
        require(contract.get("semantic_reconciliation", {}).get("review_status") == "VERIFIED_CLOSED",
                "Gene semantic review is not VERIFIED_CLOSED: " + gene_id)

        cases_for_gene = catalog_by_gene.get(gene_id, {})
        require(set(cases_for_gene) == {"positive", "negative"}, "Gene must have exactly one positive and one negative case: " + gene_id)
        expected_case_ids = {
            cases_for_gene["positive"]["case_id"],
            cases_for_gene["negative"]["case_id"],
        }
        require(cases_for_gene["positive"]["case_id"] == a1_gene.get("positive_case_id"),
                "A1 positive case traceability mismatch: " + gene_id)
        require(cases_for_gene["negative"]["case_id"] == a1_gene.get("negative_case_id"),
                "A1 negative case traceability mismatch: " + gene_id)
        for polarity in ("positive", "negative"):
            require(bool(cases_for_gene[polarity].get("scenario"))
                    and bool(cases_for_gene[polarity].get("expected"))
                    and bool(cases_for_gene[polarity].get("assertions")),
                    "Incomplete character test design: " + gene_id + "/" + polarity)
        require(set(contract.get("conformance_case_ids", [])) == expected_case_ids,
                "Contract/catalog case IDs disagree: " + gene_id)

        require(contract.get("permitted_effects") == (["declared-protected-effect"] if gene_id.startswith("g09.") else ["none"]),
                "Unexpected permitted effect boundary: " + gene_id)
        require(contract.get("authority_requirements") == (["operation-specific-authorization"] if gene_id.startswith("g09.") else ["none"]),
                "Unexpected authority boundary: " + gene_id)

        require(fixture.get("case_id") == io_contract.get("conformance", {}).get("case_id"),
                "GENESIS fixture/contract case ID mismatch: " + gene_id)
        require(baseline.get("input_schema_id") == io_contract["input_contract"]["schema_id"],
                "Input schema ID differs from approved GENESIS contract: " + gene_id)
        require(baseline.get("output_schema_id") == io_contract["output_contract"]["schema_id"],
                "Output schema ID differs from approved GENESIS contract: " + gene_id)
        require(baseline.get("input_schema_path") == io_contract["input_contract"]["file_path"],
                "Input schema path differs from approved GENESIS contract: " + gene_id)
        require(baseline.get("output_schema_path") == io_contract["output_contract"]["file_path"],
                "Output schema path differs from approved GENESIS contract: " + gene_id)

        for side in ("input", "output"):
            schema_id_key = side + "_schema_id"
            schema_path_key = side + "_schema_path"
            schema_id = baseline[schema_id_key]
            schema_path = baseline[schema_path_key]
            require(schema_path not in schema_paths, "Duplicate schema path: " + schema_path)
            require(schema_id not in schema_ids, "Duplicate schema ID: " + schema_id)
            schema_paths.add(schema_path)
            schema_ids.add(schema_id)

            schema = load(ROOT / schema_path)
            require(schema.get("$id") == schema_id, "Schema $id mismatch: " + gene_id + "/" + side)
            require(schema.get("$schema") == gene_io_doc["schema_convention"]["dialect"],
                    "Schema dialect mismatch: " + gene_id + "/" + side)
            require(schema.get("type") == "object" and schema.get("additionalProperties") is False,
                    "Schema root must be a closed object: " + gene_id + "/" + side)
            require(set(schema.get("required", [])) == set(baseline[side + "_required_fields"]),
                    "Required fields differ from frozen character baseline: " + gene_id + "/" + side)
            Draft202012Validator.check_schema(schema)
            check_ref_graph(schema)

            all_refs = []

            def collect_refs(node):
                if isinstance(node, dict):
                    if "$ref" in node:
                        all_refs.append(node["$ref"])
                    for value in node.values():
                        collect_refs(value)
                elif isinstance(node, list):
                    for value in node:
                        collect_refs(value)

            collect_refs(schema)
            external_refs += sum(1 for ref in all_refs if not isinstance(ref, str) or not ref.startswith("#"))
            local_refs += sum(1 for ref in all_refs if isinstance(ref, str) and ref.startswith("#"))

            fixture_side = fixture[side]
            require(fixture_side.get("schema_path") == schema_path, "Fixture schema path mismatch: " + gene_id + "/" + side)
            validator = Draft202012Validator(schema)
            require(not list(validator.iter_errors(fixture_side["positive"]["instance"])),
                    "Positive schema fixture rejected: " + gene_id + "/" + side)
            require(bool(list(validator.iter_errors(fixture_side["negative"]["instance"]))),
                    "Negative schema fixture accepted: " + gene_id + "/" + side)
            executed_positive += 1
            executed_negative += 1

            if side == "input":
                properties = set(schema.get("properties", {}))
                for control in contract.get("character_input_controls", []):
                    require(control.get("field") in properties,
                            "Character input control refers to an unknown schema field: " + gene_id + "/" + str(control.get("field")))
                    input_controls += 1
            else:
                properties = set(schema.get("properties", {}))
                for assertion in contract.get("character_output_assertions", []):
                    for field in assertion.get("observable_fields", []):
                        require(field in properties,
                                "Character output assertion refers to an unknown schema field: " + gene_id + "/" + field)
                        output_assertions += 1

            if side == "input":
                require(reconciliation["input"]["path"] == schema_path, "Reconciliation input path mismatch: " + gene_id)
                require(reconciliation["input"]["schema_id"] == schema_id, "Reconciliation input ID mismatch: " + gene_id)
            else:
                require(reconciliation["output"]["path"] == schema_path, "Reconciliation output path mismatch: " + gene_id)
                require(reconciliation["output"]["schema_id"] == schema_id, "Reconciliation output ID mismatch: " + gene_id)

        for polarity in ("positive", "negative"):
            case = cases_for_gene[polarity]
            require(set(case.get("required_schema_ids", [])) == {
                baseline["input_schema_id"], baseline["output_schema_id"]
            }, "Character case schema IDs mismatch: " + gene_id + "/" + polarity)
            require(case.get("existing_gene_io_case_id") == fixture["case_id"],
                    "Character case does not bind to existing GENESIS IO case: " + gene_id + "/" + polarity)

    require(len(schema_paths) == 72 and len(schema_ids) == 72, "Expected exactly 72 unique input/output schema files and IDs")
    require(executed_positive == 72 and executed_negative == 72, "Expected 72 positive and 72 negative executable schema vectors")
    require(external_refs == 0, "External schema references found: " + str(external_refs))
    require(catalog_doc.get("contract_ref") == "docs/architecture/IROKA-A2-CHARACTER-GENE-CONTRACTS-v1.0.0.json",
            "Character catalog contract reference mismatch")
    require(catalog_doc.get("schema_reconciliation_ref") == "IROKA-A2-CHARACTER-SCHEMA-RECONCILIATION-001",
            "Character catalog reconciliation ID mismatch")
    require(catalog_doc.get("schema_reconciliation_path") == "docs/architecture/IROKA-A2-CHARACTER-SCHEMA-RECONCILIATION-v1.0.0.json",
            "Character catalog reconciliation path mismatch")
    require(catalog_doc.get("execution_policy", {}).get("executed") is False
            and catalog_doc.get("execution_policy", {}).get("runtime_tests_not_authorized_in_A2") is True,
            "Character behavioral designs must remain explicitly unexecuted in A2")
    require(catalog_doc.get("case_count") == 72 and catalog_doc.get("genes_covered") == 36,
            "Character catalog metadata mismatch")
    require(all(catalog_by_gene.get(gene_id, {}).keys() == {"positive", "negative"} for gene_id in character_contracts),
            "One or more genes lack a positive/negative character design pair")

    verify_reference_engine()

    # The character scenarios are normative A2 designs. They are not runtime
    # behavior tests; A3 implementation is still a separately authorized gate.
    report = {
        "status": "PASS_A2_SCHEMA_BINDING_AND_EXECUTABLE_SCHEMA_CONFORMANCE",
        "scope": "A2 character contracts only; no runtime or authority activation",
        "genes": len(character_contracts),
        "chromosomes": 12,
        "character_design_cases": len(catalog_cases),
        "schema_files_resolved": len(schema_paths),
        "unique_schema_ids": len(schema_ids),
        "external_refs_found": external_refs,
        "local_refs_resolved": local_refs,
        "reference_cycle_probe": "PASS — synthetic cycle rejected",
        "external_reference_probe": "PASS — external reference rejected",
        "unresolved_pointer_probe": "PASS — unresolved local pointer rejected",
        "json_pointer_escape_probe": "PASS",
        "executed_schema_positive_vectors": executed_positive,
        "executed_schema_negative_vectors": executed_negative,
        "character_input_controls_bound": input_controls,
        "character_output_assertions_bound": output_assertions,
        "gene_semantic_reviews_verified_closed": sum(
            1 for item in character_contracts.values()
            if item.get("semantic_reconciliation", {}).get("review_status") == "VERIFIED_CLOSED"
        ),
        "character_behavioral_execution": "NOT RUN — A3 implementation not authorized",
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL-CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(1)
