#!/usr/bin/env python3
"""Validate the proposed 53 GENESIS collection-item contracts without changing the normative baseline."""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
APPROVED = ROOT / "docs/architecture/GENESIS-GENE-IO-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
GENOME = ROOT / "crates/iroka-kernel/igacms/genome-v1.0.0.json"
AUDIT = ROOT / "docs/architecture/GENESIS-GENE-NESTED-CONTRACT-GAPS-A1-AUDIT.json"
AMENDMENT = ROOT / "docs/architecture/GENESIS-GENE-COLLECTION-ITEM-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"


def load(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def sample(schema):
    types = schema.get("type")
    if isinstance(types, list):
        types = next((value for value in types if value != "null"), "null")
    if "enum" in schema:
        return schema["enum"][0]
    if types == "object":
        return {name: sample(child) for name, child in schema.get("properties", {}).items()
                if name in schema.get("required", [])}
    if types == "array":
        return [sample(schema["items"])] if schema.get("minItems", 0) > 0 else []
    if types == "string":
        if schema.get("format") == "date-time":
            return "2026-01-01T00:00:00Z"
        return "sample"
    if types == "integer":
        return schema.get("minimum", 1)
    if types == "number":
        return schema.get("minimum", 0.5)
    if types == "boolean":
        return False
    if types == "null":
        return None
    raise ValueError("Unsupported sample schema type: " + repr(types))


def main():
    approved, genome, audit, amendment = map(load, (APPROVED, GENOME, AUDIT, AMENDMENT))
    if amendment.get("status") != "DERIVED_OWNER_REVIEW_REQUIRED_NOT_NORMATIVE":
        raise ValueError("Amendment must remain non-normative pending Owner approval")

    declared = set()
    for contract in approved["contracts"]:
        for side in ("input", "output"):
            for field in contract[side + "_contract"]["properties"]:
                if field["type"] == "array":
                    declared.add((contract["gene_id"], side, field["name"]))
    audited = {(x["gene_id"], x["side"], x["field"]) for x in audit["unresolved_fields"]}
    entries = amendment["collections"]
    actual = {(x["gene_id"], x["side"], x["field"]) for x in entries}
    if len(entries) != 53 or len(actual) != 53 or actual != declared or actual != audited:
        raise ValueError("Collection coverage mismatch: expected 53 exact generic-array declarations")

    genes = {gene["id"]: gene for gene in genome["genes"]}
    invariant_ids = {item["id"] for item in genome["invariants"]}
    positive = negative = uniqueness = 0

    for entry in entries:
        gene = genes[entry["gene_id"]]
        context = entry["gene_context"]
        for key in ("chromosome_id", "gene_version", "purpose", "dependencies",
                    "permitted_effects", "authority_requirements", "evidence_requirements",
                    "failure_semantics", "compatibility_policy"):
            source_key = "version" if key == "gene_version" else key
            if context[key] != gene[source_key]:
                raise ValueError("Gene context drift: " + entry["gene_id"] + "/" + key)
        if {x["id"] for x in context["invariant_anchors"]} != set(gene["invariant_anchors"]):
            raise ValueError("Invariant anchor drift: " + entry["gene_id"])
        if any(x["id"] not in invariant_ids for x in context["invariant_anchors"]):
            raise ValueError("Unknown invariant anchor: " + entry["gene_id"])

        schema = entry["item_schema"]
        Draft202012Validator.check_schema(schema)
        if schema.get("type") != "array" or not isinstance(schema.get("items"), dict):
            raise ValueError("Missing explicit item schema: " + entry["gene_id"] + "/" + entry["field"])
        item_schema = schema["items"]
        if item_schema.get("type") == "object":
            if item_schema.get("additionalProperties") is not False:
                raise ValueError("Object item must reject unknown properties")
            if set(item_schema.get("required", [])) != set(item_schema.get("properties", {})):
                raise ValueError("Every declared item member must be required in this amendment")
        elif item_schema.get("type") == "string":
            if item_schema.get("minLength", 0) < 1:
                raise ValueError("String references must be non-empty")
        else:
            raise ValueError("Unsupported or implicit item shape")

        rules = entry.get("collection_rules", {})
        unique_by = rules.get("uniqueBy", [])
        if item_schema["type"] == "object":
            if any(key not in item_schema["properties"] for key in unique_by):
                raise ValueError("uniqueBy references undeclared item property")
        elif unique_by:
            raise ValueError("uniqueBy cannot target primitive item")

        validator = Draft202012Validator(schema)
        valid_item = sample(item_schema)
        candidate = [valid_item] if schema.get("minItems", rules.get("minItems", 0)) > 0 else []
        if not validator.is_valid(candidate):
            raise ValueError("Generated positive item rejected: " + entry["gene_id"] + "/" + entry["field"])
        positive += 1

        if item_schema["type"] == "object":
            bad = dict(valid_item)
            bad["__undeclared__"] = True
            if validator.is_valid([bad]):
                raise ValueError("Unknown item property accepted: " + entry["gene_id"] + "/" + entry["field"])
            negative += 1
            required = item_schema["required"]
            if required:
                bad = dict(valid_item)
                bad.pop(required[0])
                if validator.is_valid([bad]):
                    raise ValueError("Missing item member accepted: " + entry["gene_id"] + "/" + entry["field"])
                negative += 1
        else:
            if validator.is_valid([17]):
                raise ValueError("Invalid primitive item accepted: " + entry["gene_id"] + "/" + entry["field"])
            negative += 1

        if unique_by:
            duplicate = [valid_item, dict(valid_item)]
            if len({tuple(json.dumps(item.get(key), sort_keys=True) for key in unique_by)
                    for item in duplicate}) != 1:
                raise ValueError("Uniqueness test fixture construction failed")
            uniqueness += 1

    print("PASS: exact coverage of all 53 approved generic-array fields")
    print("PASS: all 53 collections have explicit Draft 2020-12 item schemas")
    print("PASS: gene purpose, invariant anchors, dependencies, effects, authority and failure context match Genome")
    print("PASS: " + str(positive) + " generated positive collection instances")
    print("PASS: " + str(negative) + " generated invalid-item rejection cases")
    print("PASS: " + str(uniqueness) + " object-collection uniqueness keys resolve to declared properties")
    print("NOTE: cross-item reference, chronology, graph, partition and policy rules are recorded as semantic acceptance obligations; runtime enforcement is not claimed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL-CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(1)
