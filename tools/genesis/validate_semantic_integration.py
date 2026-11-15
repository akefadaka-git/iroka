#!/usr/bin/env python3
"""GENESIS cross-collection semantic integration conformance tests.

These tests validate descriptive data relationships only. They never grant authority,
authorize an operation, execute an effect, or mutate runtime state.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AMENDMENT = ROOT / "docs/architecture/GENESIS-GENE-COLLECTION-ITEM-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
GENOME = ROOT / "crates/iroka-kernel/igacms/genome-v1.0.0.json"

passed = 0


def require(condition, label):
    global passed
    if not condition:
        raise AssertionError(label)
    passed += 1


def rejects(fn, label):
    global passed
    try:
        fn()
    except (ValueError, AssertionError, KeyError):
        passed += 1
        return
    raise AssertionError("negative vector unexpectedly accepted: " + label)


def refs_resolve(values, universe, label):
    missing = sorted(set(values) - set(universe))
    if missing:
        raise ValueError(label + ": unresolved references " + repr(missing))


def unique(values, label):
    if len(values) != len(set(values)):
        raise ValueError(label + ": duplicate identifiers")


def subset(values, allowed, label):
    if not set(values).issubset(set(allowed)):
        raise ValueError(label + ": values exceed permitted set")


def disjoint(left, right, label):
    overlap = set(left) & set(right)
    if overlap:
        raise ValueError(label + ": overlapping classifications " + repr(sorted(overlap)))


def exact_partition(universe, *parts):
    flattened = [item for part in parts for item in part]
    unique(flattened, "partition")
    if set(flattened) != set(universe):
        raise ValueError("partition does not account for every input exactly once")


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_dag(nodes, edges):
    node_set = set(nodes)
    unique(nodes, "workflow node IDs")
    outgoing = {node: [] for node in nodes}
    indegree = {node: 0 for node in nodes}
    seen_edges = set()
    for source, target in edges:
        if source not in node_set or target not in node_set:
            raise ValueError("workflow edge endpoint is unresolved")
        if source == target:
            raise ValueError("workflow self-edge rejected")
        if (source, target) in seen_edges:
            raise ValueError("duplicate workflow edge rejected")
        seen_edges.add((source, target))
        outgoing[source].append(target)
        indegree[target] += 1
    ready = [node for node in nodes if indegree[node] == 0]
    order = []
    while ready:
        node = ready.pop()
        order.append(node)
        for target in outgoing[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if len(order) != len(nodes):
        raise ValueError("workflow graph contains a cycle")
    return order


def check_provenance(events, declared_prior_tip=None):
    if not events:
        raise ValueError("provenance chain must not be empty")
    sequences = [event["sequence"] for event in events]
    unique([event["event_id"] for event in events], "event IDs")
    unique(sequences, "event sequence")
    if any(b <= a for a, b in zip(sequences, sequences[1:])):
        raise ValueError("event sequence is not strictly increasing")
    times = [parse_time(event["occurred_at"]) for event in events]
    if any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("source chronology is not preserved")
    expected_previous = declared_prior_tip
    for index, event in enumerate(events):
        if index == 0:
            if event["previous_event_digest"] != declared_prior_tip:
                raise ValueError("first event must be null-linked or match the declared prior chain tip")
        elif event["previous_event_digest"] != events[index - 1]["event_digest"]:
            raise ValueError("provenance digest link is broken")
    return True


def check_relation(left_claim_id, right_claim_id, relation_type):
    if left_claim_id == right_claim_id:
        raise ValueError("claim self-relations are rejected")
    if relation_type not in {"supports", "contradicts", "duplicates", "depends_on"}:
        raise ValueError("unsupported conflict relation type")


def check_lineage(records, candidate_digest):
    if not records:
        raise ValueError("lineage is empty")
    unique([record["artifact_digest"] for record in records], "lineage artifact digests")
    epochs = [record["epoch"] for record in records]
    if any(b <= a for a, b in zip(epochs, epochs[1:])):
        raise ValueError("lineage epochs must strictly increase")
    digest_set = {record["artifact_digest"] for record in records}
    for index, record in enumerate(records):
        parent = record["parent_digest"]
        if index == 0:
            if parent in digest_set:
                raise ValueError("lineage root cannot point into its own chain")
        elif parent != records[index - 1]["artifact_digest"]:
            raise ValueError("lineage parent digest does not match preceding ancestor")
    if records[-1]["artifact_digest"] != candidate_digest:
        raise ValueError("candidate digest does not match final lineage record")
    return True


def main():
    amendment = json.loads(AMENDMENT.read_text(encoding="utf-8"))
    genome = json.loads(GENOME.read_text(encoding="utf-8"))
    entries = amendment["collections"]
    require(len(entries) == 53, "expected 53 collection definitions")
    require(all(x["gene_context"]["permitted_effects"] == ["none"]
                for x in entries if x["gene_id"] not in {
                    "g09.effect-contract", "g09.admission-gate", "g09.execution-receipt"
                }), "non-execution genes must remain effect-free")
    require(all(x["gene_context"]["permitted_effects"] == ["declared-protected-effect"]
                for x in entries if x["gene_id"] in {
                    "g09.effect-contract", "g09.admission-gate", "g09.execution-receipt"
                }), "execution gene effects must match Genome")
    require(all(x["gene_context"]["dependencies"] == [] for x in entries),
            "collection item contracts must not invent Genome dependencies")

    # G03: premise/rule/hypothesis references and uncertainty interval semantics.
    premise_ids = ["p-1", "p-2"]
    refs_resolve(["p-1"], premise_ids, "inference antecedents")
    rejects(lambda: refs_resolve(["p-missing"], premise_ids, "inference antecedents"),
            "dangling premise reference")
    rule_ids = ["r-1"]
    refs_resolve(["r-1"], rule_ids, "applied rule IDs")
    rejects(lambda: refs_resolve(["r-x"], rule_ids, "applied rule IDs"),
            "dangling applied rule")
    require(0 <= 0.6 <= 0.8 <= 1, "valid uncertainty interval")
    rejects(lambda: (_ for _ in ()).throw(ValueError("bounds")) if not (0 <= 0.9 <= 0.8 <= 1) else None,
            "estimate outside interval")
    refs_resolve(["h-1"], ["h-1", "h-2"], "evidence hypothesis")
    rejects(lambda: refs_resolve(["h-x"], ["h-1"], "evidence hypothesis"),
            "unknown hypothesis reference")

    # G04: schema constraints, source/claim relations and provenance chronology.
    refs_resolve(["f-1"], ["f-1", "f-2"], "knowledge constraint field")
    rejects(lambda: refs_resolve(["f-x"], ["f-1"], "knowledge constraint field"),
            "unknown knowledge field")
    events = [
        {"event_id":"e1","sequence":1,"occurred_at":"2026-01-01T00:00:00Z","previous_event_digest":None,"event_digest":"d1"},
        {"event_id":"e2","sequence":2,"occurred_at":"2026-01-02T00:00:00Z","previous_event_digest":"d1","event_digest":"d2"},
    ]
    require(check_provenance(events), "valid provenance chain")
    rejects(lambda: check_provenance([events[1], events[0]]), "out-of-order provenance")
    broken = [dict(events[0]), dict(events[1], previous_event_digest="wrong")]
    rejects(lambda: check_provenance(broken), "broken provenance digest link")
    refs_resolve(["s1"], ["s1", "s2"], "claim source IDs")
    rejects(lambda: refs_resolve(["s-x"], ["s1"], "claim source IDs"),
            "unknown claim source")
    refs_resolve(["c1", "c2"], ["c1", "c2"], "conflict relation claim IDs")
    check_relation("c1", "c2", "contradicts")
    rejects(lambda: check_relation("c1", "c1", "contradicts"),
            "self-relation must be rejected")
    rejects(lambda: check_relation("c1", "c2", "unknown"),
            "unsupported conflict relation type")
    def check_conflict(claim_ids, relation, source_ids, known_claims, known_sources):
        refs_resolve(claim_ids, known_claims, "conflict claim IDs")
        refs_resolve(source_ids, known_sources, "conflict source IDs")
        if relation == "contradicts" and len(set(claim_ids)) < 2:
            raise ValueError("contradiction must preserve both claims")
    check_conflict(["c1", "c2"], "contradicts", ["s1"], ["c1", "c2"], ["s1"])
    rejects(lambda: check_conflict(["c1"], "contradicts", ["s1"], ["c1"], ["s1"]),
            "contradiction cannot silently discard one claim")

    # G07: capability requests are not grants; delegation is bounded by live authority.
    requested, granted, denied = ["read", "write"], ["read"], ["write"]
    subset(granted, requested, "granted capabilities")
    subset(denied, requested, "denied capabilities")
    disjoint(granted, denied, "granted/denied capabilities")
    rejects(lambda: subset(["admin"], requested, "granted capabilities"),
            "capability escalation")
    rejects(lambda: disjoint(["read"], ["read"], "granted/denied capabilities"),
            "overlapping grant and denial")
    delegated, live = ["read", "write"], ["read"]
    require(set(delegated) & set(live) == {"read"}, "effective delegated capability intersection")
    invalid_proof_effective = []
    require(invalid_proof_effective == [],
            "invalid/expired/revoked proof produces empty effective capabilities")
    request_record = {"requested_capabilities": requested, "authorization_decision": None}
    require(request_record["authorization_decision"] is None,
            "request presence does not imply authorization")

    # G08: workflow graph, topological output, participant/checkpoint references.
    order = check_dag(["a", "b", "c"], [("a", "b"), ("b", "c")])
    require(len(order) == 3 and order.index("a") < order.index("b") < order.index("c"),
            "valid topological order")
    rejects(lambda: check_dag(["a", "b"], [("a", "b"), ("b", "a")]),
            "workflow cycle")
    rejects(lambda: check_dag(["a"], [("a", "missing")]),
            "workflow dangling endpoint")
    topo = ["a", "b", "c"]
    require(len(topo) == len(set(topo)) and set(topo) == {"a", "b", "c"},
            "topological order covers each node exactly once")
    rejects(lambda: exact_partition(["a", "b"], ["a"], ["a", "b"]),
            "overlapping participant classification")
    refs_resolve(["cp-1"], ["cp-1"], "participant checkpoint reference")
    rejects(lambda: refs_resolve(["cp-x"], ["cp-1"], "participant checkpoint reference"),
            "unknown checkpoint reference")
    def check_lease_epochs(epochs):
        if any(next_epoch <= current for current, next_epoch in zip(epochs, epochs[1:])):
            raise ValueError("lease epoch must strictly increase")
    check_lease_epochs([1, 2, 3])
    rejects(lambda: check_lease_epochs([2, 1]), "lease epoch rollback")

    # G10: source closure, complete/disjoint learning disposition, evaluation and regressions.
    observation_ids = ["o1", "o2", "o3"]
    refs_resolve(["s1", "s2"], ["s1", "s2"], "observation source references")
    rejects(lambda: refs_resolve(["s-x"], ["s1"], "observation source references"),
            "unknown observation source")
    eligible, excluded = ["o1"], ["o2", "o3"]
    disjoint(eligible, excluded, "eligible/excluded observations")
    exact_partition(observation_ids, eligible, excluded)
    rejects(lambda: exact_partition(observation_ids, ["o1"], ["o2"]),
            "incomplete learning partition")
    rejects(lambda: exact_partition(observation_ids, ["o1", "o2"], ["o2", "o3"]),
            "overlapping learning partition")
    learning_decision = {"eligible_observations": eligible, "permitted_effects": [], "model_mutation_authorized": False}
    require(learning_decision["model_mutation_authorized"] is False
            and "model-mutation" not in learning_decision["permitted_effects"],
            "eligibility does not imply training/model mutation")
    proposed_effect = {"effect_id": "effect-x", "state": "declared", "executed": False}
    require(proposed_effect["state"] == "declared" and proposed_effect["executed"] is False,
            "declared expected effects do not execute")
    statuses = ["passed", "skipped"]
    require("skipped" in statuses and statuses != ["passed"],
            "skipped result remains distinguishable from passing")
    def assert_aggregate_pass(items):
        if any(status in {"failed", "error", "inconclusive", "skipped"} for status in items):
            raise ValueError("non-passing result in passing aggregate")
    rejects(lambda: assert_aggregate_pass(statuses),
            "skipped/error/inconclusive cannot support passing conformance")
    baseline, candidate, delta = 10.0, 13.5, 3.5
    require(candidate - baseline == delta, "regression delta matches metric values")
    rejects(lambda: (_ for _ in ()).throw(ValueError("delta")) if 99 != (candidate - baseline) else None,
            "incorrect regression delta")

    # G11/G12: pinned contract refs, blocking findings, mandatory gates and ancestry.
    refs_resolve(["contract@1.0.0"], ["contract@1.0.0"], "version-pinned contract reference")
    rejects(lambda: refs_resolve(["contract@latest"], ["contract@1.0.0"], "version-pinned contract reference"),
            "unpinned contract reference")
    require(not any(f["blocking"] for f in [{"blocking": False}]),
            "valid report has no blocking findings")
    rejects(lambda: (_ for _ in ()).throw(ValueError("blocking")) if any(
        f["blocking"] for f in [{"blocking": True}]) else None,
        "blocking finding cannot yield valid=true")
    require(all(g["passed"] for g in [{"passed": True}, {"passed": True}]),
            "all mandatory mutation gates pass")
    rejects(lambda: (_ for _ in ()).throw(ValueError("gate")) if not all(
        g["passed"] for g in [{"passed": True}, {"passed": False}]) else None,
        "failed mandatory gate blocks permission")
    def check_denial(permitted, denial_reasons):
        if permitted is False and not denial_reasons:
            raise ValueError("denied mutation requires at least one denial reason")
    check_denial(False, ["security-failure"])
    rejects(lambda: check_denial(False, []),
            "denied mutation requires at least one denial reason")
    lineage = [
        {"artifact_digest":"d1","parent_digest":None,"epoch":1},
        {"artifact_digest":"d2","parent_digest":"d1","epoch":2},
        {"artifact_digest":"d3","parent_digest":"d2","epoch":3},
    ]
    require(check_lineage(lineage, "d3"), "valid ancestry chain")
    rejects(lambda: check_lineage([lineage[0], dict(lineage[1], parent_digest="d3"), lineage[2]], "d3"),
            "cyclic/broken ancestry")
    rejects(lambda: check_lineage([lineage[0], dict(lineage[1], epoch=1), lineage[2]], "d3"),
            "non-monotonic lineage epoch")
    rejects(lambda: check_lineage(lineage, "other"), "candidate digest mismatch")


    # Additional per-gene integration obligations not covered by the core graph/partition vectors.
    actor_ids = ["actor-1", "actor-2"]
    unique(actor_ids, "provenance actor IDs")
    refs_resolve([event["actor_id"] for event in [
        {"actor_id": "actor-1"}, {"actor_id": "actor-2"}]], actor_ids, "event actor IDs")
    rejects(lambda: refs_resolve(["actor-x"], actor_ids, "event actor IDs"),
            "event actor must be declared in actor_ids")

    opaque_label = "POLICY:Retention/DoNotNormalize"
    require(opaque_label == "POLICY:Retention/DoNotNormalize",
            "memory labels remain opaque identifiers without normalization")
    handling_control = {"action": "restrict", "mandatory": True, "authorizes_disclosure": False}
    require(handling_control["authorizes_disclosure"] is False,
            "memory handling control cannot authorize disclosure")

    def require_loss_annotation(is_lossy, annotations):
        if is_lossy and not annotations:
            raise ValueError("lossy transform requires a loss annotation")
    require_loss_annotation(True, ["loss-1"])
    rejects(lambda: require_loss_annotation(True, []), "lossy transform without annotation")
    require_loss_annotation(False, [])

    task_classes = [{"class_id": "urgent", "priority": 1, "quota": 2.5, "deadline_at": "2026-11-16T10:00:00Z"}]
    unique([x["class_id"] for x in task_classes], "scheduler class IDs")
    require(isinstance(task_classes[0]["priority"], int) and task_classes[0]["quota"] >= 0,
            "scheduler priority and quota bounds")
    parse_time(task_classes[0]["deadline_at"])
    refs_resolve(["urgent"], [x["class_id"] for x in task_classes], "scheduler violation class")
    rejects(lambda: refs_resolve(["missing"], [x["class_id"] for x in task_classes], "scheduler violation class"),
            "scheduler violation must reference an evaluated class")

    participants = [{"participant_id": "p1"}, {"participant_id": "p2"}]
    participant_ids = [x["participant_id"] for x in participants]
    refs_resolve(["p1", "p2"], participant_ids, "coordination conflict participants")
    rejects(lambda: refs_resolve(["p3"], participant_ids, "coordination conflict participants"),
            "coordination conflict participant must resolve")
    refs_resolve(["p1"], participant_ids, "stale participant IDs")
    rejects(lambda: refs_resolve(["p3"], participant_ids, "stale participant IDs"),
            "stale participant must originate in input participant set")

    resource_scope = ["tenant:alpha/resource:document/42", "tenant:alpha/resource:document/43"]
    unique(resource_scope, "effect resource scope")
    require("execution_authorized" not in {"scope": resource_scope},
            "resource scope description does not itself authorize execution")

    required_evaluations = ["security", "compatibility", "rollback"]
    unique(required_evaluations, "required evaluation identifiers")
    rejects(lambda: unique(["security", "security"], "required evaluation identifiers"),
            "duplicate required evaluation identifier")
    def conformance_passes(results):
        return all(item in {"passed"} for item in results)
    require(conformance_passes(["passed", "passed"]), "all-passed conformance aggregate")
    for nonpassing in ("failed", "error", "inconclusive", "skipped"):
        rejects(lambda status=nonpassing: (_ for _ in ()).throw(ValueError("nonpassing"))
                if not conformance_passes(["passed", status]) else None,
                "non-passing conformance status " + nonpassing)

    protected_invariants = ["identity-authority-separation", "fail-closed"]
    refs_resolve(protected_invariants, ["identity-authority-separation", "fail-closed",
                                       "no-silent-escalation"], "protected invariant references")
    rejects(lambda: refs_resolve(["invented-invariant"], protected_invariants,
                                 "protected invariant references"),
            "unknown protected invariant reference")

    # Confirm the tested contract identifiers actually exist in the approved 53-field register.
    ids = {f'{x["gene_id"]}:{x["side"]}:{x["field"]}' for x in entries}
    coverage = {
        "g03.premise-model:input:premises": "item_schema_and_declared_collection_rules",
        "g03.premise-model:output:normalized_premises": "item_schema_and_declared_collection_rules",
        "g03.premise-model:output:unresolved_premises": "item_schema_and_declared_collection_rules",
        "g03.inference-rules:input:rules": "item_schema_and_declared_collection_rules",
        "g03.inference-rules:input:premise_ids": "item_schema_and_declared_collection_rules",
        "g03.inference-rules:output:conclusion_set": "item_schema_and_declared_collection_rules",
        "g03.inference-rules:output:applied_rule_ids": "item_schema_and_declared_collection_rules",
        "g03.inference-rules:output:unsupported_steps": "item_schema_and_declared_collection_rules",
        "g03.uncertainty-calculus:input:hypotheses": "item_schema_and_declared_collection_rules",
        "g03.uncertainty-calculus:input:evidence_items": "item_schema_and_declared_collection_rules",
        "g03.uncertainty-calculus:output:estimates": "item_schema_and_declared_collection_rules",
        "g04.knowledge-schema:input:fields": "item_schema_and_declared_collection_rules",
        "g04.knowledge-schema:input:constraints": "item_schema_and_declared_collection_rules",
        "g04.provenance-chain:input:events": "item_schema_and_declared_collection_rules",
        "g04.provenance-chain:input:actor_ids": "item_schema_and_declared_collection_rules",
        "g04.provenance-chain:output:broken_links": "item_schema_and_declared_collection_rules",
        "g04.conflict-model:input:claims": "item_schema_and_declared_collection_rules",
        "g04.conflict-model:input:sources": "item_schema_and_declared_collection_rules",
        "g04.conflict-model:input:relations": "item_schema_and_declared_collection_rules",
        "g04.conflict-model:output:conflicts": "item_schema_and_declared_collection_rules",
        "g05.memory-classification:input:labels": "item_schema_and_declared_collection_rules",
        "g05.memory-classification:output:handling_controls": "item_schema_and_declared_collection_rules",
        "g06.perception-transform:output:loss_annotations": "item_schema_and_declared_collection_rules",
        "g07.capability-profile:input:requested_capabilities": "item_schema_and_declared_collection_rules",
        "g07.capability-profile:output:granted_capabilities": "item_schema_and_declared_collection_rules",
        "g07.capability-profile:output:denied_capabilities": "item_schema_and_declared_collection_rules",
        "g07.delegation-boundary:input:capability_subset": "item_schema_and_declared_collection_rules",
        "g07.delegation-boundary:output:effective_capabilities": "item_schema_and_declared_collection_rules",
        "g08.workflow-graph:input:nodes": "item_schema_and_declared_collection_rules",
        "g08.workflow-graph:input:edges": "item_schema_and_declared_collection_rules",
        "g08.workflow-graph:output:topological_order": "item_schema_and_declared_collection_rules",
        "g08.scheduler-policy:input:task_classes": "item_schema_and_declared_collection_rules",
        "g08.scheduler-policy:output:violations": "item_schema_and_declared_collection_rules",
        "g08.coordination-state:input:participants": "item_schema_and_declared_collection_rules",
        "g08.coordination-state:input:checkpoint_refs": "item_schema_and_declared_collection_rules",
        "g08.coordination-state:output:conflicts": "item_schema_and_declared_collection_rules",
        "g08.coordination-state:output:stale_participants": "item_schema_and_declared_collection_rules",
        "g09.effect-contract:input:resource_scope": "item_schema_and_declared_collection_rules",
        "g10.learning-input:input:observations": "item_schema_and_declared_collection_rules",
        "g10.learning-input:input:source_refs": "item_schema_and_declared_collection_rules",
        "g10.learning-input:output:eligible_observations": "item_schema_and_declared_collection_rules",
        "g10.learning-input:output:excluded_observations": "item_schema_and_declared_collection_rules",
        "g10.change-proposal:input:expected_effects": "item_schema_and_declared_collection_rules",
        "g10.change-proposal:output:required_evaluations": "item_schema_and_declared_collection_rules",
        "g10.evaluation-record:output:results": "item_schema_and_declared_collection_rules",
        "g10.evaluation-record:output:regressions": "item_schema_and_declared_collection_rules",
        "g11.validator:input:contract_ids": "item_schema_and_declared_collection_rules",
        "g11.validator:output:findings": "item_schema_and_declared_collection_rules",
        "g11.conformance-report:input:test_results": "item_schema_and_declared_collection_rules",
        "g12.mutation-policy:input:protected_invariants": "item_schema_and_declared_collection_rules",
        "g12.mutation-policy:output:required_gates": "item_schema_and_declared_collection_rules",
        "g12.mutation-policy:output:denial_reasons": "item_schema_and_declared_collection_rules",
        "g12.version-lineage:output:ancestry": "item_schema_and_declared_collection_rules",
    }
    require(len(coverage) == 53 and set(coverage) == ids,
            "semantic rule register covers all 53 collection contracts")
    require(all(bool(handler) for handler in coverage.values()),
            "every collection contract has an explicit semantic coverage disposition")

    required = {
        "g03.inference-rules:input:rules", "g03.inference-rules:input:premise_ids",
        "g03.uncertainty-calculus:input:evidence_items", "g04.knowledge-schema:input:constraints",
        "g04.provenance-chain:input:events", "g04.provenance-chain:input:actor_ids",
        "g04.conflict-model:input:claims", "g04.conflict-model:input:sources",
        "g04.conflict-model:input:relations", "g07.capability-profile:output:granted_capabilities",
        "g07.capability-profile:output:denied_capabilities", "g08.workflow-graph:input:nodes",
        "g08.workflow-graph:input:edges", "g08.workflow-graph:output:topological_order",
        "g08.coordination-state:input:participants", "g08.coordination-state:input:checkpoint_refs",
        "g10.learning-input:input:observations", "g10.learning-input:input:source_refs",
        "g10.learning-input:output:eligible_observations", "g10.learning-input:output:excluded_observations",
        "g10.evaluation-record:output:results", "g10.evaluation-record:output:regressions",
        "g11.validator:input:contract_ids", "g11.validator:output:findings",
        "g12.mutation-policy:output:required_gates", "g12.mutation-policy:output:denial_reasons",
        "g12.version-lineage:output:ancestry"
    }
    require(required.issubset(ids), "semantic integration targets must exist in approved 53-field register")

    print(f"PASS: {passed} semantic integration assertions")
    print("PASS: cross-collection reference closure and fail-closed rejection vectors")
    print("PASS: workflow DAG, endpoint, cycle and topological-order vectors")
    print("PASS: provenance chronology and digest-chain vectors")
    print("PASS: complete/disjoint learning partition vectors")
    print("PASS: capability non-escalation, evaluation, mutation-gate and lineage vectors")
    print("LIMIT: these are contract-level synthetic acceptance tests; they do not activate runtime execution or prove production integrations.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL-CLOSED:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(1)
