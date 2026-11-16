#!/usr/bin/env python3
"""Static A3 audit for the frozen 36-gene IO schema baseline and A2 traceability."""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs/architecture/IROKA-A2-CHARACTER-GENE-CONTRACTS-v1.0.0.json"
CATALOG_PATH = ROOT / "docs/architecture/IROKA-A2-CHARACTER-CONFORMANCE-CATALOG-v1.0.0.json"
SCHEMA_ROOT = ROOT / "crates/iroka-kernel/igacms/schemas/genes"
errors: list[str] = []

def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path.relative_to(ROOT)}: invalid/unreadable JSON: {exc}")
        return {}

def resolve_pointer(doc, pointer: str):
    if pointer == "#":
        return doc
    if not pointer.startswith("#/"):
        raise ValueError(f"non-local or unsupported reference: {pointer}")
    node = doc
    for token in pointer[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[token]
    return node

def walk_refs(node, path="$"):
    if isinstance(node, dict):
        ref = node.get("$ref")
        if ref is not None:
            try:
                resolve_pointer(document, ref)
            except Exception as exc:
                errors.append(f"{schema_path}: unresolved $ref at {path}: {ref} ({exc})")
        for key, value in node.items():
            walk_refs(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            walk_refs(value, f"{path}/{index}")

contracts = load(CONTRACT_PATH)
catalog = load(CATALOG_PATH)
genes = contracts.get("gene_contracts", [])
cases = catalog.get("cases", [])
reviews = catalog.get("gene_review_records", [])
if len(genes) != 36:
    errors.append(f"expected 36 gene contracts, found {len(genes)}")
if len(reviews) != 36:
    errors.append(f"expected 36 review records, found {len(reviews)}")
if len(cases) != 72:
    errors.append(f"expected 72 conformance cases, found {len(cases)}")
if len({g.get("gene_id") for g in genes}) != 36:
    errors.append("gene IDs are not unique")
if len({c.get("case_id") for c in cases}) != 72:
    errors.append("case IDs are not unique")
case_ids = {c.get("case_id") for c in cases}
for gene in genes:
    gid = gene.get("gene_id", "<missing>")
    baseline = gene.get("gene_io_baseline", {})
    for direction in ("input", "output"):
        path = ROOT / baseline.get(f"{direction}_schema_path", "")
        if not path.is_file():
            errors.append(f"{gid}: missing {direction} schema {path.relative_to(ROOT)}")
            continue
        schema_path = path.relative_to(ROOT).as_posix()
        document = load(path)
        expected_id = baseline.get(f"{direction}_schema_id")
        if document.get("$id") != expected_id:
            errors.append(f"{gid}: {direction} $id mismatch")
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{gid}: {direction} is not Draft 2020-12")
        if document.get("additionalProperties") is not False:
            errors.append(f"{gid}: {direction} top-level object is not closed")
        required = set(document.get("required", []))
        properties = set(document.get("properties", {}))
        expected_required = set(baseline.get(f"{direction}_required_fields", []))
        expected_properties = {p.get("name") for p in baseline.get(f"{direction}_properties", [])}
        if required != expected_required:
            errors.append(f"{gid}: {direction} required fields differ from frozen A2 inventory")
        if properties != expected_properties:
            errors.append(f"{gid}: {direction} properties differ from frozen A2 inventory")
        if "version_bound_evidence" not in required or "version_bound_evidence" not in properties:
            errors.append(f"{gid}: {direction} missing required version_bound_evidence")
        walk_refs(document)
    mapped = set(gene.get("conformance_case_ids", []))
    actual = {c.get("case_id") for c in cases if c.get("gene_id") == gid}
    if mapped != actual or len(actual) != 2:
        errors.append(f"{gid}: case-to-contract mapping mismatch")
    if not mapped.issubset(case_ids):
        errors.append(f"{gid}: references unknown conformance case")
for review in reviews:
    if review.get("review_status") != "VERIFIED_CLOSED":
        errors.append(f"{review.get('gene_id')}: A2 review is not closed")
    if set(review.get("case_ids", [])) - case_ids:
        errors.append(f"{review.get('gene_id')}: review references unknown case")

# A3 G12 rollback-guard amendment audit. These v1.1.0 schemas are additive;
# the frozen A2 v1.0.0 schema files above remain unchanged.
A3_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g12.rollback-guard.input.schema.json"
A3_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g12.rollback-guard.output.schema.json"
A3_VECTORS = ROOT / "docs/architecture/a3/g12-rollback-guard-conformance-v1.1.0.json"
a3_input = load(A3_INPUT)
a3_output = load(A3_OUTPUT)
a3_vectors = load(A3_VECTORS)
for schema_path_obj, document in ((A3_INPUT, a3_input), (A3_OUTPUT, a3_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if a3_input.get("$id") != "https://iroka.dev/schemas/genes/g12.rollback-guard/input/1.1.0":
    errors.append("G12 A3 input schema ID/version mismatch")
if a3_output.get("$id") != "https://iroka.dev/schemas/genes/g12.rollback-guard/output/1.1.0":
    errors.append("G12 A3 output schema ID/version mismatch")
input_props = a3_input.get("properties", {})
for field in ("current_epoch", "candidate_epoch", "revocation_floor", "revocation_floor_revision"):
    if input_props.get(field, {}).get("minimum") != 0:
        errors.append(f"G12 A3 input: {field} must have minimum 0")
for field in ("current_digest", "candidate_digest"):
    if input_props.get(field, {}).get("$ref") != "#/$defs/digest":
        errors.append(f"G12 A3 input: {field} must use the SHA-256 digest definition")
auth = input_props.get("rollback_authorization", {})
if not any(option.get("type") == "null" for option in auth.get("oneOf", [])):
    errors.append("G12 A3 input: null must explicitly represent absent rollback authorization")
auth_objects = [o for o in auth.get("oneOf", []) if o.get("type") == "object"]
if not auth_objects or auth_objects[0].get("properties", {}).get("payload", {}).get("properties", {}).get("capability", {}).get("const") != "system.rollback":
    errors.append("G12 A3 input: Owner authorization must be scoped to system.rollback")
if "allOf" not in a3_output or len(a3_output.get("allOf", [])) < 4:
    errors.append("G12 A3 output: conditional allow/deny/effective-state invariants missing")
if a3_vectors.get("gene_id") != "g12.rollback-guard" or a3_vectors.get("version") != "1.1.0":
    errors.append("G12 A3 conformance catalog identity/version mismatch")
a3_cases = a3_vectors.get("cases", [])
a3_case_ids = {case.get("case_id") for case in a3_cases}
if len(a3_cases) != 10 or len(a3_case_ids) != 10:
    errors.append(f"G12 A3 expected 10 unique conformance cases, found {len(a3_cases)}")
if "RG-A3-N01" not in a3_case_ids:
    errors.append("G12 A3 absolute revocation-floor adversarial case missing")
if a3_vectors.get("chromosome_count") != 12 or a3_vectors.get("gene_count") != 36:
    errors.append("G12 A3 amendment changes the fixed 12-chromosome/36-gene genome")

if errors:
    print("A3_SCHEMA_BASELINE_AUDIT=FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)
print("A3_SCHEMA_BASELINE_AUDIT=PASS")
print("chromosomes=12 (contract scope assertion)")
print(f"genes={len(genes)}")
print(f"schemas={len(genes) * 2}")
print(f"conformance_cases={len(cases)}")
print(f"review_records={len(reviews)}")
print("required_version_bound_evidence=72/72")
print("local_refs=RESOLVED")
print("case_mapping=PASS")
print("g12_rollback_guard_v1_1_0=PASS")
print(f"g12_a3_conformance_cases={len(a3_cases)}")
