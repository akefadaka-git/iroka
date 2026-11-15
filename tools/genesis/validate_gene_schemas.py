#!/usr/bin/env python3
"""Fail-closed resolver and executable conformance runner for GENESIS gene IO."""
import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
GENOME = ROOT / "crates/iroka-kernel/igacms/genome-v1.0.0.json"
CONTRACTS = ROOT / "docs/architecture/GENESIS-GENE-IO-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
FIXTURES = ROOT / "crates/iroka-kernel/igacms/conformance/gene-io-v1.0.0.json"


def load(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def pointer(root, ref):
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        raise ValueError("Only local JSON Pointer $refs are permitted: " + str(ref))
    node = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def dereference(schema, fragment):
    seen = set()
    while isinstance(fragment, dict) and "$ref" in fragment:
        ref = fragment["$ref"]
        if ref in seen:
            raise ValueError("Cyclic property $ref: " + ref)
        seen.add(ref)
        if not isinstance(ref, str) or not ref.startswith("#"):
            raise ValueError("External $ref forbidden: " + str(ref))
        fragment = pointer(schema, ref)
    return fragment


def refs(node):
    if isinstance(node, dict):
        out = [node["$ref"]] if "$ref" in node else []
        for value in node.values():
            out.extend(refs(value))
        return out
    if isinstance(node, list):
        out = []
        for value in node:
            out.extend(refs(value))
        return out
    return []


def check_ref_graph(schema):
    graph = {}

    def collect(ref):
        if ref in graph:
            return
        target = pointer(schema, ref)
        graph[ref] = refs(target)
        for child in graph[ref]:
            if not isinstance(child, str) or not child.startswith("#"):
                raise ValueError("External $ref forbidden: " + str(child))
            collect(child)

    for ref in refs(schema):
        if not isinstance(ref, str) or not ref.startswith("#"):
            raise ValueError("External $ref forbidden: " + str(ref))
        collect(ref)

    active = set()
    done = set()

    def visit(ref):
        if ref in done:
            return
        if ref in active:
            raise ValueError("Cyclic internal $ref dependency: " + ref)
        active.add(ref)
        for child in graph.get(ref, []):
            visit(child)
        active.remove(ref)
        done.add(ref)

    for ref in graph:
        visit(ref)


def contract_type(declaration):
    """Translate the approved field-level type notation into JSON Schema expectations."""
    if declaration.startswith("enum(") and declaration.endswith(")"):
        values = declaration[5:-1].split("|")
        if not values or any(not value for value in values):
            raise ValueError("Invalid enum declaration: " + declaration)
        return "string", values, None

    if declaration.endswith("|null"):
        base = declaration[:-5]
        if base not in {"string", "integer", "boolean", "object"}:
            raise ValueError("Unsupported nullable contract type: " + declaration)
        return [base, "null"], None, None

    if declaration.endswith("[]"):
        item_type = declaration[:-2]
        if item_type not in {"string", "integer", "boolean", "object"}:
            raise ValueError("Unsupported array item type: " + declaration)
        return "array", None, item_type

    if declaration == "array":
        return "array", None, None

    if declaration in {"string", "integer", "boolean", "object"}:
        return declaration, None, None

    raise ValueError("Unsupported approved contract type: " + declaration)


def check_contract_schema(gene_id, side, spec, schema):
    """Require the schema's field set, requiredness, types and enums to match its approved contract."""
    declared = spec.get("properties")
    if not isinstance(declared, list):
        raise ValueError("Contract properties must be a list: " + gene_id + "/" + side)

    declared_names = [field["name"] for field in declared]
    if len(declared_names) != len(set(declared_names)):
        raise ValueError("Duplicate contract property: " + gene_id + "/" + side)

    contract_required = {field["name"] for field in declared if field.get("required") is True}
    listed_required = set(spec.get("required", []))
    if contract_required != listed_required:
        raise ValueError("Contract required list disagrees with property flags: " + gene_id + "/" + side)

    schema_properties = schema.get("properties", {})
    expected_names = set(declared_names) | {"version_bound_evidence"}
    if set(schema_properties) != expected_names:
        missing = sorted(expected_names - set(schema_properties))
        extra = sorted(set(schema_properties) - expected_names)
        raise ValueError(
            "Schema property set mismatch: " + gene_id + "/" + side
            + " missing=" + repr(missing) + " extra=" + repr(extra)
        )

    expected_required = contract_required | {"version_bound_evidence"}
    if set(schema.get("required", [])) != expected_required:
        raise ValueError("Schema required fields mismatch: " + gene_id + "/" + side)

    for field in declared:
        name = field["name"]
        expected, enum_values, item_type = contract_type(field["type"])
        actual = dereference(schema, schema_properties[name])
        actual_type = actual.get("type")

        if isinstance(expected, list):
            if not isinstance(actual_type, list) or sorted(actual_type) != sorted(expected):
                raise ValueError("Nullable type mismatch: " + gene_id + "/" + side + "/" + name)
        elif actual_type != expected:
            raise ValueError("Field type mismatch: " + gene_id + "/" + side + "/" + name)

        if enum_values is not None and actual.get("enum") != enum_values:
            raise ValueError("Enum values mismatch: " + gene_id + "/" + side + "/" + name)
        if item_type is not None:
            items = actual.get("items")
            if not isinstance(items, dict) or items.get("type") != item_type:
                raise ValueError("Array item type mismatch: " + gene_id + "/" + side + "/" + name)



def invalid_value(declaration):
    """Return a value that must violate the approved field's declared JSON type."""
    if declaration.startswith("enum("):
        return "__GENESIS_INVALID_ENUM_VALUE__"
    if declaration.endswith("|null"):
        base = declaration[:-5]
        return {"string": True, "integer": "not-an-integer", "boolean": "not-a-boolean", "object": "not-an-object"}[base]
    if declaration.endswith("[]") or declaration == "array":
        return "not-an-array"
    return {
        "string": 17,
        "integer": "not-an-integer",
        "boolean": "not-a-boolean",
        "object": "not-an-object",
    }[declaration]


def check_negative_mutations(validator, instance, spec, gene_id, side):
    """Exercise type, enum, array-item and closed-object rejection beyond missing-field tests."""
    rejected = 0
    for field in spec["properties"]:
        name = field["name"]
        if name not in instance:
            continue
        candidate = copy.deepcopy(instance)
        candidate[name] = invalid_value(field["type"])
        if validator.is_valid(candidate):
            raise ValueError("Invalid field value accepted: " + gene_id + "/" + side + "/" + name)
        rejected += 1

        if field["type"] == "string[]":
            candidate = copy.deepcopy(instance)
            candidate[name] = [17]
            if validator.is_valid(candidate):
                raise ValueError("Invalid array item accepted: " + gene_id + "/" + side + "/" + name)
            rejected += 1

    candidate = copy.deepcopy(instance)
    candidate["__unexpected_contract_field__"] = True
    if validator.is_valid(candidate):
        raise ValueError("Undeclared top-level property accepted: " + gene_id + "/" + side)
    rejected += 1

    candidate = copy.deepcopy(instance)
    candidate["version_bound_evidence"] = "not-an-object"
    if validator.is_valid(candidate):
        raise ValueError("Non-object version-bound evidence accepted: " + gene_id + "/" + side)
    rejected += 1
    return rejected


def main():
    proposal = load(CONTRACTS)
    genome = load(GENOME)
    fixtures = load(FIXTURES)

    if proposal.get("status") != "OWNER_APPROVED_NORMATIVE_BASELINE":
        raise ValueError("Gene contract amendment is not Owner-approved")

    contracts = {item["gene_id"]: item for item in proposal["contracts"]}
    genes = {item["id"]: item for item in genome["genes"]}
    cases = {item["gene_id"]: item for item in fixtures["cases"]}
    if (
        len(contracts) != 36 or len(genes) != 36 or len(cases) != 36
        or set(contracts) != set(genes) or set(contracts) != set(cases)
    ):
        raise ValueError("Expected exactly 36 matching gene contracts, Genome genes and conformance cases")

    resolved = positive = negative = mutation_negatives = 0
    underspecified_arrays = []
    schema_ids = set()
    schema_paths = set()

    for gene_id, gene in genes.items():
        contract = contracts[gene_id]
        case = cases[gene_id]
        if (
            case["case_id"] != contract["conformance"]["case_id"]
            or case["case_id"] not in gene["conformance_cases"]
        ):
            raise ValueError("Conformance case ID mismatch: " + gene_id)

        for side in ("input", "output"):
            spec = contract[side + "_contract"]
            relative_path = spec["file_path"]
            if relative_path in schema_paths:
                raise ValueError("Duplicate schema file path: " + relative_path)
            schema_paths.add(relative_path)

            expected_reference = relative_path.replace("crates/iroka-kernel/igacms/", "")
            if gene[side + "_schema"] != expected_reference:
                raise ValueError("Genome reference mismatch: " + gene_id + "/" + side)

            path = ROOT / relative_path
            schema = load(path)
            schema_id = schema.get("$id")
            if schema_id in schema_ids:
                raise ValueError("Duplicate schema ID: " + str(schema_id))
            schema_ids.add(schema_id)

            if schema_id != spec["schema_id"] or schema.get("$schema") != proposal["schema_convention"]["dialect"]:
                raise ValueError("Stable schema ID/dialect mismatch: " + str(path))
            if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise ValueError("Root object must be closed: " + str(path))

            check_contract_schema(gene_id, side, spec, schema)
            for field in spec["properties"]:
                if field["type"] == "array":
                    array_schema = dereference(schema, schema.get("properties", {}).get(field["name"], {}))
                    item_schema = array_schema.get("items")
                    if not isinstance(item_schema, dict) or not item_schema:
                        underspecified_arrays.append({
                            "gene_id": gene_id, "side": side, "field": field["name"],
                            "schema_path": relative_path,
                            "issue": "approved contract declares generic array without item structure"
                        })
            version_evidence = dereference(schema, schema.get("properties", {}).get("version_bound_evidence", {}))
            if version_evidence.get("type") != "object":
                raise ValueError("Version-bound evidence must be an object: " + str(path))
            if "version_bound_evidence" not in schema.get("required", []):
                raise ValueError("Version-bound evidence requirement missing: " + str(path))

            required = set(schema.get("required", []))
            if "provenance" not in required:
                evidence = schema.get("$defs", {}).get("evidence", {})
                if (
                    "evidence" not in required
                    or not {"provenance", "version_bound_evidence"}.issubset(set(evidence.get("required", [])))
                ):
                    raise ValueError("Provenance evidence requirement missing: " + str(path))

            Draft202012Validator.check_schema(schema)
            check_ref_graph(schema)

            validator = Draft202012Validator(schema)
            vectors = case[side]
            if vectors["schema_path"] != relative_path:
                raise ValueError("Fixture path mismatch: " + gene_id + "/" + side)
            if list(validator.iter_errors(vectors["positive"]["instance"])):
                raise ValueError("Positive vector rejected: " + gene_id + "/" + side)
            positive += 1
            if not list(validator.iter_errors(vectors["negative"]["instance"])):
                raise ValueError("Negative vector accepted: " + gene_id + "/" + side)
            negative += 1
            mutation_negatives += check_negative_mutations(
                validator, vectors["positive"]["instance"], spec, gene_id, side
            )
            resolved += 1

    if (resolved, positive, negative) != (72, 72, 72):
        raise ValueError("Incomplete closure counts")
    print("PASS: all 72/72 Genome schema references resolve to gene-specific files")
    print("PASS: all 72 schemas match approved field sets, requiredness, types and enum values")
    print("PASS: all schemas are valid Draft 2020-12 with unique stable IDs and closed object contracts")
    print("PASS: all internal $refs resolve; external refs and cycles rejected")
    print("PASS: 36 gene cases; 72 positive vectors and 72 missing-field negatives")
    print("PASS: " + str(mutation_negatives) + " generated invalid-type, enum, array-item and unknown-field mutations rejected")
    print("UNRESOLVED: " + str(len(underspecified_arrays)) + " generic array fields lack approved item contracts")
    for item in underspecified_arrays:
        print("CONTRACT-GAP: " + item["gene_id"] + "/" + item["side"] + "/" + item["field"])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL-CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(1)
