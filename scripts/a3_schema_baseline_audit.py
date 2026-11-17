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


# A3 G12 version-lineage v1.1.0 additive contract audit.
VL_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g12.version-lineage.input.schema.json"
VL_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g12.version-lineage.output.schema.json"
VL_VECTORS = ROOT / "docs/architecture/a3/g12-version-lineage-conformance-v1.1.0.json"
vl_input = load(VL_INPUT)
vl_output = load(VL_OUTPUT)
vl_vectors = load(VL_VECTORS)
for schema_path_obj, document in ((VL_INPUT, vl_input), (VL_OUTPUT, vl_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if vl_input.get("$id") != "https://iroka.dev/schemas/genes/g12.version-lineage/input/1.1.0":
    errors.append("G12 version-lineage A3 input schema ID/version mismatch")
if vl_output.get("$id") != "https://iroka.dev/schemas/genes/g12.version-lineage/output/1.1.0":
    errors.append("G12 version-lineage A3 output schema ID/version mismatch")
vl_required = set(vl_input.get("required", []))
for field in ("artifact", "artifact_digest", "version", "parent_version", "parent_digest",
              "mutation_ref", "epoch", "provenance", "version_bound_evidence"):
    if field not in vl_required:
        errors.append(f"G12 version-lineage A3 input missing required field: {field}")
if len(vl_input.get("allOf", [])) < 2:
    errors.append("G12 version-lineage A3 root/non-root parent invariants missing")
if len(vl_output.get("allOf", [])) < 2:
    errors.append("G12 version-lineage A3 allow/deny output invariants missing")
vl_cases = vl_vectors.get("cases", [])
vl_case_ids = {case.get("case_id") for case in vl_cases}
if vl_vectors.get("gene_id") != "g12.version-lineage" or vl_vectors.get("version") != "1.1.0":
    errors.append("G12 version-lineage A3 conformance catalog identity/version mismatch")
if len(vl_cases) != 12 or len(vl_case_ids) != 12:
    errors.append(f"G12 version-lineage A3 expected 12 unique conformance vectors, found {len(vl_cases)}")
if vl_vectors.get("chromosome_count") != 12 or vl_vectors.get("gene_count") != 36:
    errors.append("G12 version-lineage A3 amendment changes the fixed genome")


# A3 G01 identity-root v1.1.0 additive contract audit.
G01_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g01.identity-root.input.schema.json"
G01_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g01.identity-root.output.schema.json"
G01_VECTORS = ROOT / "docs/architecture/a3/g01-identity-root-conformance-v1.1.0.json"
g01_input = load(G01_INPUT)
g01_output = load(G01_OUTPUT)
g01_vectors = load(G01_VECTORS)
for schema_path_obj, document in ((G01_INPUT, g01_input), (G01_OUTPUT, g01_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if g01_input.get("$id") != "https://iroka.dev/schemas/genes/g01.identity-root/input/1.1.0":
    errors.append("G01 A3 input schema ID/version mismatch")
if g01_output.get("$id") != "https://iroka.dev/schemas/genes/g01.identity-root/output/1.1.0":
    errors.append("G01 A3 output schema ID/version mismatch")
g01_required = set(g01_input.get("required", []))
for field in ("key_id", "public_key_base64url", "algorithm_policy_version", "provenance", "version_bound_evidence"):
    if field not in g01_required:
        errors.append(f"G01 A3 input missing required field: {field}")
if g01_input.get("properties", {}).get("algorithm", {}).get("const") != "EdDSA":
    errors.append("G01 A3 input must constrain algorithm to EdDSA")
if len(g01_output.get("allOf", [])) < 4:
    errors.append("G01 A3 output lacks verified/trust_decision consistency conditions")
g01_cases = g01_vectors.get("cases", [])
g01_case_ids = {case.get("case_id") for case in g01_cases}
if g01_vectors.get("gene_id") != "g01.identity-root" or g01_vectors.get("version") != "1.1.0":
    errors.append("G01 A3 conformance catalog identity/version mismatch")
if len(g01_cases) != 5 or len(g01_case_ids) != 5:
    errors.append(f"G01 A3 expected 5 unique conformance vectors, found {len(g01_cases)}")
if g01_vectors.get("chromosome_count") != 12 or g01_vectors.get("gene_count") != 36:
    errors.append("G01 A3 amendment changes the fixed genome")



# A3 G01 identity-lineage v1.1.0 additive contract audit.
GL_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g01.lineage.input.schema.json"
GL_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g01.lineage.output.schema.json"
GL_VECTORS = ROOT / "docs/architecture/a3/g01-lineage-conformance-v1.1.0.json"
gl_input, gl_output, gl_vectors = load(GL_INPUT), load(GL_OUTPUT), load(GL_VECTORS)
for schema_path_obj, document in ((GL_INPUT, gl_input), (GL_OUTPUT, gl_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if gl_input.get("$id") != "https://iroka.dev/schemas/genes/g01.lineage/input/1.1.0":
    errors.append("G01 lineage input schema ID/version mismatch")
if gl_output.get("$id") != "https://iroka.dev/schemas/genes/g01.lineage/output/1.1.0":
    errors.append("G01 lineage output schema ID/version mismatch")
if gl_input.get("properties", {}).get("lineage_chain", {}).get("maxItems") != 128:
    errors.append("G01 lineage maximum depth must be 128")
if len(gl_output.get("allOf", [])) < 2:
    errors.append("G01 lineage output consistency conditions missing")
gl_cases = gl_vectors.get("cases", [])
if gl_vectors.get("gene_id") != "g01.lineage" or gl_vectors.get("version") != "1.1.0":
    errors.append("G01 lineage conformance catalog identity/version mismatch")
if len(gl_cases) != 5 or len({case.get("case_id") for case in gl_cases}) != 5:
    errors.append(f"G01 lineage expected 5 unique conformance vectors, found {len(gl_cases)}")
if gl_vectors.get("chromosome_count") != 12 or gl_vectors.get("gene_count") != 36:
    errors.append("G01 lineage amendment changes the fixed genome")



# A3 G02 authority-source v1.1.0 additive contract audit.
G02_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g02.authority-source.input.schema.json"
G02_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g02.authority-source.output.schema.json"
G02_VECTORS = ROOT / "docs/architecture/a3/g02-authority-source-conformance-v1.1.0.json"
g02_input, g02_output, g02_vectors = load(G02_INPUT), load(G02_OUTPUT), load(G02_VECTORS)
for schema_path_obj, document in ((G02_INPUT, g02_input), (G02_OUTPUT, g02_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if g02_input.get("$id") != "https://iroka.dev/schemas/genes/g02.authority-source/input/1.1.0":
    errors.append("G02 authority-source input schema ID/version mismatch")
if g02_output.get("$id") != "https://iroka.dev/schemas/genes/g02.authority-source/output/1.1.0":
    errors.append("G02 authority-source output schema ID/version mismatch")
g02_required = set(g02_input.get("required", []))
for field in ("authority_id", "source_type", "mandate_ref", "valid_from", "valid_until",
              "principal_registration", "mandate", "provenance", "version_bound_evidence"):
    if field not in g02_required:
        errors.append(f"G02 authority-source input missing required field: {field}")
if len(g02_output.get("allOf", [])) < 2:
    errors.append("G02 authority-source output status/scope consistency conditions missing")
g02_cases = g02_vectors.get("cases", [])
if g02_vectors.get("gene_id") != "g02.authority-source" or g02_vectors.get("version") != "1.1.0":
    errors.append("G02 authority-source conformance catalog identity/version mismatch")
if len(g02_cases) != 5 or len({case.get("case_id") for case in g02_cases}) != 5:
    errors.append(f"G02 authority-source expected 5 unique conformance vectors, found {len(g02_cases)}")
if g02_vectors.get("chromosome_count") != 12 or g02_vectors.get("gene_count") != 36:
    errors.append("G02 authority-source amendment changes the fixed genome")



# A3 G02 Owner-governance v1.1.0 additive contract audit.
OG_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g02.owner-governance.input.schema.json"
OG_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g02.owner-governance.output.schema.json"
OG_VECTORS = ROOT / "docs/architecture/a3/g02-owner-governance-conformance-v1.1.0.json"
og_input, og_output, og_vectors = load(OG_INPUT), load(OG_OUTPUT), load(OG_VECTORS)
for schema_path_obj, document in ((OG_INPUT, og_input), (OG_OUTPUT, og_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if og_input.get("$id") != "https://iroka.dev/schemas/genes/g02.owner-governance/input/1.1.0":
    errors.append("G02 Owner-governance input schema ID/version mismatch")
if og_output.get("$id") != "https://iroka.dev/schemas/genes/g02.owner-governance/output/1.1.0":
    errors.append("G02 Owner-governance output schema ID/version mismatch")
og_required = set(og_input.get("required", []))
for field in ("owner_id", "decision_id", "scope", "approval_digest", "signature", "issued_at",
              "expires_at", "approval", "register_snapshot", "provenance", "version_bound_evidence"):
    if field not in og_required:
        errors.append(f"G02 Owner-governance input missing required field: {field}")
if og_output.get("properties", {}).get("execution_authorized", {}).get("const") is not False:
    errors.append("G02 Owner-governance output must hard-code execution_authorized=false")
if len(og_output.get("allOf", [])) < 4:
    errors.append("G02 Owner-governance output status/scope/safeguard invariants missing")
og_cases = og_vectors.get("cases", [])
if og_vectors.get("gene_id") != "g02.owner-governance" or og_vectors.get("version") != "1.1.0":
    errors.append("G02 Owner-governance conformance catalog identity/version mismatch")
if len(og_cases) != 6 or len({case.get("case_id") for case in og_cases}) != 6:
    errors.append(f"G02 Owner-governance expected 6 unique conformance vectors, found {len(og_cases)}")
if og_vectors.get("chromosome_count") != 12 or og_vectors.get("gene_count") != 36:
    errors.append("G02 Owner-governance amendment changes the fixed genome")



# A3 G03 premise-model v1.1.0 additive contract audit.
PM_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g03.premise-model.input.schema.json"
PM_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g03.premise-model.output.schema.json"
PM_VECTORS = ROOT / "docs/architecture/a3/g03-premise-model-conformance-v1.1.0.json"
pm_input, pm_output, pm_vectors = load(PM_INPUT), load(PM_OUTPUT), load(PM_VECTORS)
for schema_path_obj, document in ((PM_INPUT, pm_input), (PM_OUTPUT, pm_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if pm_input.get("$id") != "https://iroka.dev/schemas/genes/g03.premise-model/input/1.1.0":
    errors.append("G03 premise-model input schema ID/version mismatch")
if pm_output.get("$id") != "https://iroka.dev/schemas/genes/g03.premise-model/output/1.1.0":
    errors.append("G03 premise-model output schema ID/version mismatch")
pm_required = set(pm_input.get("required", []))
for field in ("premises", "context_id", "model_version", "normalization_policy_version", "provenance", "version_bound_evidence"):
    if field not in pm_required:
        errors.append(f"G03 premise-model input missing required field: {field}")
pm_output_props = pm_output.get("properties", {})
if "normalized_premises" not in pm_output_props or "unresolved_premises" not in pm_output_props:
    errors.append("G03 premise-model must expose normalized and unresolved premise partitions")
if len(pm_output.get("allOf", [])) < 2:
    errors.append("G03 premise-model output digest/disposition consistency conditions missing")
pm_cases = pm_vectors.get("cases", [])
if pm_vectors.get("gene_id") != "g03.premise-model" or pm_vectors.get("version") != "1.1.0":
    errors.append("G03 premise-model conformance catalog identity/version mismatch")
if len(pm_cases) != 6 or len({case.get("case_id") for case in pm_cases}) != 6:
    errors.append(f"G03 premise-model expected 6 unique conformance vectors, found {len(pm_cases)}")
if pm_vectors.get("chromosome_count") != 12 or pm_vectors.get("gene_count") != 36:
    errors.append("G03 premise-model amendment changes the fixed genome")



# A3 G03 inference-rules v1.1.0 additive contract audit.
IR_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g03.inference-rules.input.schema.json"
IR_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g03.inference-rules.output.schema.json"
IR_VECTORS = ROOT / "docs/architecture/a3/g03-inference-rules-conformance-v1.1.0.json"
ir_input, ir_output, ir_vectors = load(IR_INPUT), load(IR_OUTPUT), load(IR_VECTORS)
for schema_path_obj, document in ((IR_INPUT, ir_input), (IR_OUTPUT, ir_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if ir_input.get("$id") != "https://iroka.dev/schemas/genes/g03.inference-rules/input/1.1.0":
    errors.append("G03 inference-rules input schema ID/version mismatch")
if ir_output.get("$id") != "https://iroka.dev/schemas/genes/g03.inference-rules/output/1.1.0":
    errors.append("G03 inference-rules output schema ID/version mismatch")
ir_required = set(ir_input.get("required", []))
for field in ("rules", "premises", "premise_set_digest", "query", "rule_version", "rule_set_digest",
              "confidence_policy_version", "evaluator_version", "provenance", "version_bound_evidence"):
    if field not in ir_required:
        errors.append(f"G03 inference-rules input missing required field: {field}")
ir_output_props = ir_output.get("properties", {})
if "conclusion_set" not in ir_output_props or "applied_rule_ids" not in ir_output_props or "unsupported_steps" not in ir_output_props:
    errors.append("G03 inference-rules output missing conclusion/applied/unsupported trace fields")
ir_cases = ir_vectors.get("cases", [])
if ir_vectors.get("gene_id") != "g03.inference-rules" or ir_vectors.get("version") != "1.1.0":
    errors.append("G03 inference-rules conformance catalog identity/version mismatch")
if len(ir_cases) != 6 or len({case.get("case_id") for case in ir_cases}) != 6:
    errors.append(f"G03 inference-rules expected 6 unique conformance vectors, found {len(ir_cases)}")
if ir_vectors.get("chromosome_count") != 12 or ir_vectors.get("gene_count") != 36:
    errors.append("G03 inference-rules amendment changes the fixed genome")



# A3 G03 uncertainty-calculus v1.1.0 additive contract audit.
UC_INPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g03.uncertainty-calculus.input.schema.json"
UC_OUTPUT = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes/g03.uncertainty-calculus.output.schema.json"
UC_VECTORS = ROOT / "docs/architecture/a3/g03-uncertainty-calculus-conformance-v1.1.0.json"
uc_input, uc_output, uc_vectors = load(UC_INPUT), load(UC_OUTPUT), load(UC_VECTORS)
for schema_path_obj, document in ((UC_INPUT, uc_input), (UC_OUTPUT, uc_output)):
    schema_path = schema_path_obj.relative_to(ROOT).as_posix()
    if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_path}: not JSON Schema Draft 2020-12")
    if document.get("additionalProperties") is not False:
        errors.append(f"{schema_path}: top-level object is not closed")
    walk_refs(document)
if uc_input.get("$id") != "https://iroka.dev/schemas/genes/g03.uncertainty-calculus/input/1.1.0":
    errors.append("G03 uncertainty-calculus input schema ID/version mismatch")
if uc_output.get("$id") != "https://iroka.dev/schemas/genes/g03.uncertainty-calculus/output/1.1.0":
    errors.append("G03 uncertainty-calculus output schema ID/version mismatch")
uc_required = set(uc_input.get("required", []))
for field in ("inference_id", "premise_set_digest", "calculation_method", "method_version",
              "calibration_profile", "hypotheses", "provenance", "version_bound_evidence"):
    if field not in uc_required:
        errors.append(f"G03 uncertainty-calculus input missing required field: {field}")
uc_output_props = uc_output.get("properties", {})
if "hypothesis_estimates" not in uc_output_props or "unresolved_evidence" not in uc_output_props:
    errors.append("G03 uncertainty-calculus output missing estimate/unresolved evidence fields")
if uc_output_props.get("evidence", {}).get("properties", {}).get("normalization_scope", {}).get("const") != "independent_per_hypothesis":
    errors.append("G03 uncertainty-calculus must not normalize probabilities across hypotheses")
uc_cases = uc_vectors.get("cases", [])
if uc_vectors.get("gene_id") != "g03.uncertainty-calculus" or uc_vectors.get("version") != "1.1.0":
    errors.append("G03 uncertainty-calculus conformance catalog identity/version mismatch")
if len(uc_cases) != 7 or len({case.get("case_id") for case in uc_cases}) != 7:
    errors.append(f"G03 uncertainty-calculus expected 7 unique conformance vectors, found {len(uc_cases)}")
if uc_vectors.get("chromosome_count") != 12 or uc_vectors.get("gene_count") != 36:
    errors.append("G03 uncertainty-calculus amendment changes the fixed genome")

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
print("g12_version_lineage_v1_1_0=PASS")
print(f"g12_version_lineage_a3_conformance_cases={len(vl_cases)}")
print("g01_identity_root_v1_1_0=PASS")
print(f"g01_identity_root_a3_conformance_cases={len(g01_cases)}")
print("g01_lineage_v1_1_0=PASS")
print(f"g01_lineage_a3_conformance_cases={len(gl_cases)}")
print("g02_authority_source_v1_1_0=PASS")
print(f"g02_authority_source_a3_conformance_cases={len(g02_cases)}")
print("g02_owner_governance_v1_1_0=PASS")
print(f"g02_owner_governance_a3_conformance_cases={len(og_cases)}")
print("g03_premise_model_v1_1_0=PASS")
print(f"g03_premise_model_a3_conformance_cases={len(pm_cases)}")
print("g03_inference_rules_v1_1_0=PASS")
print(f"g03_inference_rules_a3_conformance_cases={len(ir_cases)}")
print("g03_uncertainty_calculus_v1_1_0=PASS")
print(f"g03_uncertainty_calculus_a3_conformance_cases={len(uc_cases)}")
