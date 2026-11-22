#!/usr/bin/env python3
"""Resolve, validate and execute conformance vectors for the 53 approved GENESIS collection contracts."""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
APPROVED = ROOT / "docs/architecture/GENESIS-GENE-IO-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
GENOME = ROOT / "crates/iroka-kernel/igacms/genome-v1.0.0.json"
AUDIT = ROOT / "docs/architecture/GENESIS-GENE-NESTED-CONTRACT-GAPS-A1-AUDIT.json"
AMENDMENT = ROOT / "docs/architecture/GENESIS-GENE-COLLECTION-ITEM-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
FIXTURES = ROOT / "crates/iroka-kernel/igacms/conformance/collection-items-v1.0.0.json"


def load(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def resolve_local(schema, ref):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError("Only local JSON Pointer references are allowed: " + repr(ref))
    node = schema
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def validate_semantic_collection(values, rules, key):
    if "minItems" in rules and len(values) < rules["minItems"]:
        raise ValueError(key + ": collection violates minItems")
    unique_by = rules.get("uniqueBy", [])
    if unique_by:
        seen = set()
        for item in values:
            identity = tuple(json.dumps(item.get(name), sort_keys=True) for name in unique_by)
            if identity in seen:
                raise ValueError(key + ": duplicate collection identity " + repr(identity))
            seen.add(identity)


def main():
    approved, genome, audit, amendment, fixtures = map(
        load, (APPROVED, GENOME, AUDIT, AMENDMENT, FIXTURES)
    )
    if amendment.get("status") != "OWNER_APPROVED_NORMATIVE_BASELINE":
        raise ValueError("Collection amendment is not Owner-approved")
    if fixtures.get("status") != "OWNER_APPROVED_CONFORMANCE_VECTORS":
        raise ValueError("Collection conformance vectors are not approved")

    declared = {
        (contract["gene_id"], side, field["name"])
        for contract in approved["contracts"]
        for side in ("input", "output")
        for field in contract[side + "_contract"]["properties"]
        if field["type"] == "array"
    }
    audited = {(x["gene_id"], x["side"], x["field"]) for x in audit["unresolved_fields"]}
    entries = amendment["collections"]
    actual = {(x["gene_id"], x["side"], x["field"]) for x in entries}
    if len(entries) != 53 or len(actual) != 53 or actual != declared or actual != audited:
        raise ValueError("Coverage mismatch: expected exactly the 53 approved generic-array fields")

    genes = {gene["id"]: gene for gene in genome["genes"]}
    invariant_ids = {item["id"] for item in genome["invariants"]}
    fixture_map = {case["collection_id"]: case for case in fixtures["cases"]}
    if len(fixture_map) != 53 or set(fixture_map) != {
        f'{x["gene_id"]}:{x["side"]}:{x["field"]}' for x in entries
    }:
        raise ValueError("Conformance fixture coverage mismatch")
    declared_negative_count = sum(len(case["negative"]) for case in fixtures["cases"])
    if fixtures.get("negative_vector_count") != declared_negative_count:
        raise ValueError("Conformance fixture negative_vector_count metadata mismatch")

    positive_count = negative_count = semantic_checks = resolved_refs = 0
    for entry in entries:
        gene_id, side, field = entry["gene_id"], entry["side"], entry["field"]
        key = gene_id + "/" + side + "/" + field
        gene = genes[gene_id]
        context = entry["gene_context"]
        for name in ("chromosome_id", "purpose", "dependencies", "permitted_effects",
                     "authority_requirements", "evidence_requirements", "failure_semantics",
                     "compatibility_policy"):
            if context[name] != gene[name]:
                raise ValueError(key + ": Genome context drift in " + name)
        if context["gene_version"] != gene["version"]:
            raise ValueError(key + ": Genome version drift")
        if {x["id"] for x in context["invariant_anchors"]} != set(gene["invariant_anchors"]):
            raise ValueError(key + ": invariant anchor drift")
        if any(x["id"] not in invariant_ids for x in context["invariant_anchors"]):
            raise ValueError(key + ": unknown invariant anchor")

        schema_path = ROOT / "crates/iroka-kernel/igacms/schemas/genes" / (gene_id[4:] + "." + side + ".schema.json")
        schema = load(schema_path)
        Draft202012Validator.check_schema(schema)
        prop = schema.get("properties", {}).get(field)
        if not isinstance(prop, dict) or prop.get("type") != "array":
            raise ValueError(key + ": schema field is not an array")
        ref = prop.get("items", {}).get("$ref")
        actual_item = resolve_local(schema, ref)
        resolved_refs += 1
        if not isinstance(actual_item, dict):
            raise ValueError(key + ": item reference did not resolve to a schema")
        comparable = {k: v for k, v in actual_item.items() if k != "$anchor"}
        expected_item = entry["item_schema"]["items"]
        if comparable != expected_item:
            raise ValueError(key + ": resolved item schema differs from approved amendment")
        expected_anchor = f'{gene_id.replace(".", "-")}-{side}-{field}-item-v1-0-0'
        if actual_item.get("$anchor") != expected_anchor:
            raise ValueError(key + ": stable item anchor mismatch")
        rules = entry.get("collection_rules", {})
        if prop.get("x-genesis-collection-rules") != rules:
            raise ValueError(key + ": collection validation rules differ from amendment")
        if "minItems" in rules and prop.get("minItems") != rules["minItems"]:
            raise ValueError(key + ": minItems rule not enforced by schema")
        if actual_item.get("type") == "string" and rules.get("uniqueBy"):
            raise ValueError(key + ": primitive string collection cannot declare uniqueBy")
        if actual_item.get("type") == "string" and rules.get("uniqueItems") is not False and prop.get("uniqueItems") is not True:
            raise ValueError(key + ": string identifier collection must enforce uniqueItems")

        case_id = f"{gene_id}:{side}:{field}"
        case = fixture_map[case_id]
        if case["schema_path"] != str(schema_path.relative_to(ROOT)):
            raise ValueError(key + ": fixture schema path mismatch")
        array_schema = dict(prop)
        array_schema["items"] = actual_item
        validator = Draft202012Validator(array_schema)
        positive = case["positive"]
        if positive.get("expected") != "ACCEPT" or not validator.is_valid(positive["instance"]):
            raise ValueError(key + ": positive conformance vector rejected")
        validate_semantic_collection(positive["instance"], rules, key)
        positive_count += 1
        for negative in case["negative"]:
            if negative.get("expected") != "REJECT":
                raise ValueError(key + ": negative vector has incorrect expected disposition")
            if negative.get("validation") == "semantic":
                try:
                    validate_semantic_collection(negative["instance"], rules, key)
                except ValueError:
                    pass
                else:
                    raise ValueError(key + ": semantic negative vector accepted: " + negative["case_id"])
            elif validator.is_valid(negative["instance"]):
                raise ValueError(key + ": invalid vector accepted: " + negative["case_id"])
            negative_count += 1
        if rules.get("uniqueBy"):
            duplicate = positive["instance"] * 2
            try:
                validate_semantic_collection(duplicate, rules, key)
            except ValueError:
                semantic_checks += 1
            else:
                raise ValueError(key + ": duplicate uniqueBy identity was not rejected")

    print("PASS: exact coverage of all 53 approved generic-array fields")
    print("PASS: all 53 schema item references resolve to the approved, anchored item schema")
    print("PASS: gene purpose, invariant anchors, dependencies, effects, authority and failure context match Genome")
    print("PASS: " + str(positive_count) + " positive collection vectors")
    print("PASS: " + str(negative_count) + " negative item vectors")
    print("PASS: " + str(semantic_checks) + " uniqueBy semantic rejection cases")
    print("PASS: " + str(resolved_refs) + " local item-schema references resolved")
    print("LIMIT: cross-collection references, graph acyclicity, chronology and partition invariants remain separate semantic integration tests; schema validation alone does not claim to enforce them.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL-CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(1)
