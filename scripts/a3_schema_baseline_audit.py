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
