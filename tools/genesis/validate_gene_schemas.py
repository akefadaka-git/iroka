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
AUTHORIZATION_SCOPES = ROOT / "crates/iroka-kernel/igacms/registries/authorization-scopes-v1.0.0.json"


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


R04_SCOPE_FIELDS = {
    ("g02.authority-source", "output"): "scope",
    ("g02.owner-governance", "input"): "scope",
    ("g02.owner-governance", "output"): "authorized_scope",
    ("g09.effect-contract", "output"): "required_authorization",
}


def check_r04_scope_registry(gene_id, side, schema, registry):
    """Bind R-04 scope arrays to the exact canonical registry and reject unknown forms."""
    field = R04_SCOPE_FIELDS.get((gene_id, side))
    if field is None:
        return 0
    identifiers = [entry["id"] for entry in registry.get("scopes", [])]
    if not identifiers or len(identifiers) != len(set(identifiers)):
        raise ValueError("R-04 registry must contain unique canonical identifiers")
    if registry.get("registry_id") != "iroka.authorization-scopes.v1" or registry.get("version") != "1.0.0":
        raise ValueError("R-04 authorization scope registry identity/version mismatch")
    for identifier in identifiers:
        parts = identifier.split(":")
        if len(parts) != 3 or any(not part or not part.isascii() or part.lower() != part or not all(ch.islower() or ch.isdigit() or ch == "-" for ch in part) for part in parts):
            raise ValueError("R-04 malformed or non-canonical registry identifier: " + identifier)
    item_schema = schema.get("properties", {}).get(field, {}).get("items", {})
    if item_schema.get("type") != "string" or item_schema.get("enum") != identifiers:
        raise ValueError("R-04 schema vocabulary differs from canonical registry: " + gene_id + "/" + side + "/" + field)
    validator = Draft202012Validator(item_schema)
    for identifier in identifiers:
        if not validator.is_valid(identifier):
            raise ValueError("R-04 registered identifier rejected: " + identifier)
    for invalid in ("execution:*:execute", "Execution:effect:execute", " execution:effect:execute", "execution:effect:unknown", "execution:effect", "executión:effect:execute"):
        if validator.is_valid(invalid):
            raise ValueError("R-04 invalid/unknown scope accepted: " + invalid)
    return len(identifiers) + 5


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
    evidence_field = "version_bound_evidence" if side == "input" else "evidence"
    expected_names = set(declared_names) | {evidence_field}
    if set(schema_properties) != expected_names:
        missing = sorted(expected_names - set(schema_properties))
        extra = sorted(set(schema_properties) - expected_names)
        raise ValueError(
            "Schema property set mismatch: " + gene_id + "/" + side
            + " missing=" + repr(missing) + " extra=" + repr(extra)
        )

    expected_required = contract_required | {evidence_field}
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
    if side == "input":
        candidate["version_bound_evidence"] = "not-an-object"
    else:
        candidate["evidence"]["version_bound_evidence"] = "not-an-object"
    if validator.is_valid(candidate):
        raise ValueError("Non-object version-bound evidence accepted: " + gene_id + "/" + side)
    rejected += 1
    return rejected



NESTED_OBJECT_FIELDS = {
    ("g03.uncertainty-calculus", "output"): ["uncertainty_bounds"],
    ("g04.knowledge-schema", "output"): ["normalized_schema"],
    ("g07.capability-profile", "input"): ["resource_limits"],
    ("g07.capability-profile", "output"): ["limits"],
    ("g08.scheduler-policy", "input"): ["priorities", "quotas", "deadlines"],
    ("g08.scheduler-policy", "output"): ["normalized_policy"],
    ("g08.coordination-state", "input"): ["lease_epochs"],
    ("g08.coordination-state", "output"): ["canonical_state"],
    ("g10.evaluation-record", "input"): ["baseline_metrics", "candidate_metrics"],
}


def check_nested_object_contracts(validator, instance, gene_id, side):
    """Exercise R-03 nested object closure and required-member rejection."""
    rejected = 0
    for name in NESTED_OBJECT_FIELDS.get((gene_id, side), []):
        schema = validator.schema["properties"][name]
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            raise ValueError("R-03 nested object must be closed: " + gene_id + "/" + side + "/" + name)
        required = schema.get("required", [])
        if not required or not set(required).issubset(set(schema.get("properties", {}))):
            raise ValueError("R-03 nested object must declare required members: " + gene_id + "/" + side + "/" + name)
        value = instance.get(name)
        if not isinstance(value, dict) or not validator.evolve(schema=schema).is_valid(value):
            raise ValueError("R-03 positive nested object invalid: " + gene_id + "/" + side + "/" + name)
        candidate = copy.deepcopy(instance)
        candidate[name]["__unexpected_nested_field__"] = True
        if validator.is_valid(candidate):
            raise ValueError("R-03 nested unknown property accepted: " + gene_id + "/" + side + "/" + name)
        rejected += 1
        candidate = copy.deepcopy(instance)
        del candidate[name][required[0]]
        if validator.is_valid(candidate):
            raise ValueError("R-03 missing nested required property accepted: " + gene_id + "/" + side + "/" + name)
        rejected += 1
    return rejected



def check_r03_semantics(instance, gene_id, side):
    """Check cross-field invariants that JSON Schema cannot express by itself."""
    def unique(items, key):
        values = [item[key] for item in items]
        return len(values) == len(set(values))

    if gene_id == "g03.uncertainty-calculus" and side == "output":
        bounds = instance["uncertainty_bounds"]
        for hypothesis in bounds["hypotheses"]:
            if hypothesis["lower_bound"] > hypothesis["upper_bound"]:
                raise ValueError("R-03 uncertainty lower_bound exceeds upper_bound")

    if gene_id == "g04.knowledge-schema" and side == "output":
        normalized = instance["normalized_schema"]
        if not set(normalized["required_fields"]).issubset(set(normalized["properties"])):
            raise ValueError("R-03 normalized schema requires an undeclared property")
        for name, definition in normalized["properties"].items():
            if definition["required"] != (name in normalized["required_fields"]):
                raise ValueError("R-03 normalized schema required flags disagree")

    if gene_id == "g07.capability-profile" and side == "input":
        limits = instance["resource_limits"]["limits"]
        if not unique(limits, "resource"):
            raise ValueError("R-03 resource limit dimensions must be unique")
        if any(entry["value"] > entry["maximum"] for entry in limits):
            raise ValueError("R-03 requested resource limit exceeds its maximum")

    if gene_id == "g07.capability-profile" and side == "output":
        limits = instance["limits"]
        maps = {}
        for stage in ("requested", "policy_imposed", "effective"):
            entries = limits[stage]["limits"]
            if not unique(entries, "resource"):
                raise ValueError("R-03 capability limit dimensions must be unique")
            maps[stage] = {entry["resource"]: entry for entry in entries}
        for resource, effective in maps["effective"].items():
            requested = maps["requested"].get(resource)
            imposed = maps["policy_imposed"].get(resource)
            if requested is None or imposed is None:
                raise ValueError("R-03 effective limit lacks requested or policy-imposed counterpart")
            if effective["unit"] != requested["unit"] or effective["unit"] != imposed["unit"]:
                raise ValueError("R-03 resource limit units disagree")
            if effective["value"] > min(requested["value"], imposed["value"]):
                raise ValueError("R-03 effective limit exceeds requested or policy-imposed limit")

    if gene_id == "g08.scheduler-policy" and side == "input":
        priorities = instance["priorities"]["by_task_class"]
        quotas = instance["quotas"]["by_task_class"]
        deadlines = instance["deadlines"]["by_task_class"]
        if not unique(priorities, "class_id"):
            raise ValueError("R-03 scheduler priority class identifiers must be unique")
        quota_keys = [(q["class_id"], q["resource"]) for q in quotas]
        if len(quota_keys) != len(set(quota_keys)) or not unique(deadlines, "class_id"):
            raise ValueError("R-03 scheduler quota class/resource pairs and deadline class identifiers must be unique")
        if any(q["window_seconds"] <= 0 for q in quotas):
            raise ValueError("R-03 quota measurement windows must be positive")

    if gene_id == "g08.scheduler-policy" and side == "output":
        policy = instance["normalized_policy"]
        if policy["priorities"]["ordering"] != "ascending" or policy["priorities"]["lower_number_is_higher"] is not True:
            raise ValueError("R-03 normalized scheduler priority ordering is not canonical")
        if not unique(policy["priorities"]["by_task_class"], "class_id"):
            raise ValueError("R-03 normalized scheduler priority class identifiers must be unique")
        quota_keys = [(q["class_id"], q["resource"]) for q in policy["quotas"]["by_task_class"]]
        if len(quota_keys) != len(set(quota_keys)):
            raise ValueError("R-03 normalized scheduler quota dimensions must be unique per class")

    if gene_id == "g08.coordination-state" and side == "input":
        epochs = instance["lease_epochs"]["epochs"]
        if not unique(epochs, "participant_id"):
            raise ValueError("R-03 lease epoch participant identifiers must be unique")

    if gene_id == "g08.coordination-state" and side == "output":
        state = instance["canonical_state"]
        if not unique(state["participants"], "participant_id"):
            raise ValueError("R-03 canonical state participant identifiers must be unique")
        if len(state["checkpoint_refs"]) != len(set(state["checkpoint_refs"])):
            raise ValueError("R-03 canonical checkpoint references must be unique")

    if gene_id == "g10.evaluation-record" and side == "input":
        baseline = {m["metric_id"]: m for m in instance["baseline_metrics"]["metrics"]}
        candidate = {m["metric_id"]: m for m in instance["candidate_metrics"]["metrics"]}
        if set(baseline) != set(candidate):
            raise ValueError("R-03 baseline/candidate metric identifiers must match")
        for metric_id in baseline:
            left, right = baseline[metric_id], candidate[metric_id]
            if (left["unit"], left["aggregation"], left["window_seconds"]) != (right["unit"], right["aggregation"], right["window_seconds"]):
                raise ValueError("R-03 baseline/candidate metric definitions are not comparable")




def check_r03_semantic_rejections(instance, gene_id, side):
    """Prove the semantic checker rejects deliberately inconsistent nested records."""
    rejected = 0
    candidates = []
    if gene_id == "g03.uncertainty-calculus" and side == "output":
        candidate = copy.deepcopy(instance)
        candidate["uncertainty_bounds"]["hypotheses"][0]["lower_bound"] = 0.9
        candidates.append(candidate)
    if gene_id == "g04.knowledge-schema" and side == "output":
        candidate = copy.deepcopy(instance)
        candidate["normalized_schema"]["required_fields"].append("undeclared_property")
        candidates.append(candidate)
    if gene_id == "g07.capability-profile" and side == "input":
        candidate = copy.deepcopy(instance)
        candidate["resource_limits"]["limits"][0]["value"] = candidate["resource_limits"]["limits"][0]["maximum"] + 1
        candidates.append(candidate)
    if gene_id == "g07.capability-profile" and side == "output":
        candidate = copy.deepcopy(instance)
        candidate["limits"]["effective"]["limits"][0]["value"] = candidate["limits"]["requested"]["limits"][0]["value"] + 1
        candidates.append(candidate)
    if gene_id == "g08.scheduler-policy" and side == "input":
        candidate = copy.deepcopy(instance)
        candidate["quotas"]["by_task_class"].append(copy.deepcopy(candidate["quotas"]["by_task_class"][0]))
        candidates.append(candidate)
    if gene_id == "g08.scheduler-policy" and side == "output":
        candidate = copy.deepcopy(instance)
        candidate["normalized_policy"]["quotas"]["by_task_class"].append(copy.deepcopy(candidate["normalized_policy"]["quotas"]["by_task_class"][0]))
        candidates.append(candidate)
    if gene_id == "g08.coordination-state" and side == "input":
        candidate = copy.deepcopy(instance)
        candidate["lease_epochs"]["epochs"].append(copy.deepcopy(candidate["lease_epochs"]["epochs"][0]))
        candidates.append(candidate)
    if gene_id == "g08.coordination-state" and side == "output":
        candidate = copy.deepcopy(instance)
        candidate["canonical_state"]["participants"].append(copy.deepcopy(candidate["canonical_state"]["participants"][0]))
        candidates.append(candidate)
    if gene_id == "g10.evaluation-record" and side == "input":
        candidate = copy.deepcopy(instance)
        candidate["candidate_metrics"]["metrics"][0]["window_seconds"] += 1
        candidates.append(candidate)

    if gene_id == "g08.scheduler-policy" and side == "input":
        # A task class may have multiple quotas, provided each resource dimension is unique.
        candidate = copy.deepcopy(instance)
        additional_quota = copy.deepcopy(candidate["quotas"]["by_task_class"][0])
        additional_quota["resource"] = "memory"
        additional_quota["unit"] = "gibibytes"
        candidate["quotas"]["by_task_class"].append(additional_quota)
        check_r03_semantics(candidate, gene_id, side)

    for candidate in candidates:
        try:
            check_r03_semantics(candidate, gene_id, side)
        except ValueError:
            rejected += 1
        else:
            raise ValueError("R-03 inconsistent cross-field mutation accepted: " + gene_id + "/" + side)
    return rejected



def main():
    proposal = load(CONTRACTS)
    genome = load(GENOME)
    fixtures = load(FIXTURES)
    authorization_scopes = load(AUTHORIZATION_SCOPES)

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

    resolved = positive = negative = mutation_negatives = nested_mutation_negatives = nested_semantic_negatives = r04_scope_assertions = 0
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
            r04_scope_assertions += check_r04_scope_registry(gene_id, side, schema, authorization_scopes)
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
            if side == "input":
                version_evidence = dereference(schema, schema.get("properties", {}).get("version_bound_evidence", {}))
                if version_evidence.get("type") != "object":
                    raise ValueError("Input version-bound evidence must be an object: " + str(path))
                if "version_bound_evidence" not in schema.get("required", []):
                    raise ValueError("Input version-bound evidence requirement missing: " + str(path))
            else:
                evidence = dereference(schema, schema.get("properties", {}).get("evidence", {}))
                if evidence.get("type") != "object" or evidence.get("additionalProperties") is not False:
                    raise ValueError("Output evidence wrapper must be a closed object: " + str(path))
                if not {"provenance", "version_bound_evidence"}.issubset(set(evidence.get("required", []))):
                    raise ValueError("Output evidence wrapper must require provenance and version-bound evidence: " + str(path))
                for name in ("provenance", "version_bound_evidence"):
                    nested = dereference(schema, evidence.get("properties", {}).get(name, {}))
                    if nested.get("type") != "object":
                        raise ValueError("Output evidence member must be an object: " + name + " in " + str(path))

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
            nested_mutation_negatives += check_nested_object_contracts(
                validator, vectors["positive"]["instance"], gene_id, side
            )
            check_r03_semantics(vectors["positive"]["instance"], gene_id, side)
            nested_semantic_negatives += check_r03_semantic_rejections(
                vectors["positive"]["instance"], gene_id, side
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
    print("PASS: " + str(nested_mutation_negatives) + " R-03 nested unknown-field and missing-required mutations rejected")
    print("PASS: " + str(nested_semantic_negatives) + " R-03 inconsistent cross-field mutations rejected")
    print("PASS: R-03 cross-field invariants for uncertainty, normalized schema, resource limits, scheduler policy, coordination state and metric comparability")
    print("PASS: R-04 canonical authorization scope registry; " + str(r04_scope_assertions) + " registered/invalid identifier assertions across four schema fields")
    print("PASS: R-04 canonical authorization scope registry; " + str(r04_scope_assertions) + " registered/invalid identifier assertions across four schema fields")
    print("UNRESOLVED: " + str(len(underspecified_arrays)) + " generic array fields lack approved item contracts")
    for item in underspecified_arrays:
        print("CONTRACT-GAP: " + item["gene_id"] + "/" + item["side"] + "/" + item["field"])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL-CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(1)
