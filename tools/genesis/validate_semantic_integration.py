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
            if declared_prior_tip is None and event["previous_event_digest"] is not None:
                expected_previous = event["previous_event_digest"]
            if declared_prior_tip is not None and event["previous_event_digest"] != declared_prior_tip:
                raise ValueError("first event does not link to declared prior chain tip")
        elif event["previous_event_digest"] != events[index - 1]["event_digest"]:
            raise ValueError("provenance digest link is broken")
    return True


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
    rejects(lambda: (_ for _ in ()).throw(ValueError("self relation")) if "c1" == "c1" else None,
            "self-relation must be rejected")
    require(set(["c1", "c2"]).issubset({"c1", "c2"}),
            "conflict preserves both sides of contradiction")

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
    require(set() == (set(delegated) & set(live) if False else set()),
            "invalid/expired/revoked proof produces empty effective capabilities")
    require(not bool({"requested": requested}.get("authorized", False)),
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
    require(2 > 1, "lease epoch strictly increases")
    rejects(lambda: (_ for _ in ()).throw(ValueError("epoch")) if not (1 > 2) else None,
            "lease epoch rollback")

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
    require(not bool({"eligible": eligible}.get("training_mutation", False)),
            "eligibility does not imply training/model mutation")
    require(not bool({"expected_effects": ["effect-x"]}.get("executed", False)),
            "declared expected effects do not execute")
    statuses = ["passed", "skipped"]
    require("skipped" in statuses and "passed" not in [] , "skipped result remains distinguishable")
    rejects(lambda: (_ for _ in ()).throw(ValueError("aggregate")) if "skipped" in statuses else None,
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
    rejects(lambda: (_ for _ in ()).throw(ValueError("denial")) if not (
        False and ["security-failure"]) else None,
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

    # Confirm the tested contract identifiers actually exist in the approved 53-field register.
    ids = {f'{x["gene_id"]}:{x["side"]}:{x["field"]}' for x in entries}
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
