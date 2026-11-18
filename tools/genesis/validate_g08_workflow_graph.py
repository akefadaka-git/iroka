#!/usr/bin/env python3
"""Validate G08 workflow-graph A3 JSON Schemas and structural fixtures."""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "crates/iroka-kernel/igacms/schemas/a3/genes"
INPUT = SCHEMAS / "g08.workflow-graph.input.schema.json"
OUTPUT = SCHEMAS / "g08.workflow-graph.output.schema.json"

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def assert_valid(validator: Draft202012Validator, value: dict) -> None:
    errors = list(validator.iter_errors(value))
    if errors:
        raise AssertionError("; ".join(error.message for error in errors))

def assert_invalid(validator: Draft202012Validator, value: dict) -> None:
    if validator.is_valid(value):
        raise AssertionError("negative G08 schema vector unexpectedly accepted")

def main() -> None:
    input_schema = load(INPUT)
    output_schema = load(OUTPUT)
    Draft202012Validator.check_schema(input_schema)
    Draft202012Validator.check_schema(output_schema)
    input_validator = Draft202012Validator(input_schema)
    output_validator = Draft202012Validator(output_schema)

    digest = "a" * 64
    provenance = {
        "source_ref": "synthetic:test",
        "revision_ref": "revision:demo:1",
        "workflow_registry_ref": "registry:workflow:1",
        "operation_registry_ref": "registry:operation:1",
        "dependency_registry_ref": "registry:dependency:1",
        "checkpoint_registry_ref": "registry:checkpoint:1",
        "node_operations": [{
            "node_id": "node.fetch",
            "operation_ref": "operation.fetch",
            "implementation_digest": "b" * 64,
            "configuration_digest": digest,
            "operation_provenance_ref": "operation-source:node.fetch",
            "configuration_provenance_ref": "configuration-source:node.fetch",
            "checkpoint_ref": None,
            "checkpoint_provenance_ref": None
        }],
        "dependency_edges": [],
        "validation_input_refs": [
            "synthetic:test", "revision:demo:1", "registry:workflow:1",
            "registry:operation:1", "registry:dependency:1", "registry:checkpoint:1",
            "input:workflow", "input:operations"
        ]
    }
    evidence = {
        "workflow_registry_digest": "c" * 64,
        "operation_registry_digest": "d" * 64,
        "dependency_registry_digest": "e" * 64,
        "checkpoint_registry_digest": "f" * 64,
        "graph_revision_digest": "1" * 64,
        "schema_version": "1.0.0",
        "configuration_digest_algorithm": "SHA-256",
        "graph_validator_version": "1.0.0"
    }
    node = {
        "node_id": "node.fetch",
        "node_type": "fetch",
        "operation_ref": "operation.fetch",
        "configuration_digest": digest,
        "checkpoint_ref": None,
        "safe_stop": False,
        "recovery_node_id": None
    }
    positive_input = {
        "workflow_id": "workflow.demo",
        "nodes": [node],
        "edges": [],
        "graph_version": "1.0.0",
        "provenance": provenance,
        "version_bound_evidence": evidence
    }
    assert_valid(input_validator, positive_input)

    for mutate in (
        lambda value: value.pop("workflow_id"),
        lambda value: value["nodes"][0].update({"unexpected": True}),
        lambda value: value["nodes"][0].update({"configuration_digest": "NOT-A-DIGEST"}),
        lambda value: value["version_bound_evidence"].pop("graph_revision_digest"),
        lambda value: value["provenance"].pop("node_operations"),
        lambda value: value.update({"unapproved_field": True}),
        lambda value: value.update({"graph_version": "latest"})
    ):
        candidate = json.loads(json.dumps(positive_input))
        mutate(candidate)
        assert_invalid(input_validator, candidate)

    positive_output = {
        "workflow_id": "workflow.demo",
        "graph_digest": digest,
        "topological_order": ["node.fetch"],
        "validation_status": "valid",
        "evidence": {
            "findings": [],
            "provenance": provenance,
            "version_bound_evidence": evidence
        },
        "version_bound_evidence": evidence
    }
    assert_valid(output_validator, positive_output)
    for mutate in (
        lambda value: value.update({"validation_status": "authorized"}),
        lambda value: value.update({"graph_digest": "invalid"}),
        lambda value: value["topological_order"].append("node.fetch"),
        lambda value: value["evidence"].update({"extra": True}),
        lambda value: value["evidence"]["provenance"].pop("dependency_edges"),
        lambda value: value.pop("evidence")
    ):
        candidate = json.loads(json.dumps(positive_output))
        mutate(candidate)
        assert_invalid(output_validator, candidate)

    print("PASS: G08 workflow-graph input/output Draft 2020-12 schemas")
    print("PASS: 1 positive input + 7 negative input schema vectors")
    print("PASS: 1 positive output + 6 negative output schema vectors")

if __name__ == "__main__":
    main()
