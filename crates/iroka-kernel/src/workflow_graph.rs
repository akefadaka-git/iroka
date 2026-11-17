//! G08 deterministic workflow graph validation and topological ordering.
//! This module validates dependency structure; it does not schedule or execute operations.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNode {
    pub node_id: String,
    pub node_type: String,
    pub operation_ref: String,
    pub configuration_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub dependency_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphInput {
    pub workflow_id: String,
    pub nodes: Vec<WorkflowNode>,
    pub edges: Vec<WorkflowEdge>,
    pub graph_version: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphEvidence {
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphOutput {
    pub workflow_id: String,
    pub graph_digest: String,
    pub topological_order: Vec<String>,
    pub validation_status: String,
    pub evidence: WorkflowGraphEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

fn canonical<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).ok()?).ok()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'_' | b'-' | b'.' | b':')
        })
}

fn invalid_output(input: &WorkflowGraphInput, status: &str, graph_digest: String) -> WorkflowGraphOutput {
    WorkflowGraphOutput {
        workflow_id: input.workflow_id.clone(),
        graph_digest,
        topological_order: Vec::new(),
        validation_status: status.into(),
        evidence: WorkflowGraphEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence: input.version_bound_evidence.clone(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}

/// Validate references, reject self-edges and cycles, then emit a stable topological order.
pub fn evaluate_workflow_graph(input: &WorkflowGraphInput) -> Result<WorkflowGraphOutput, String> {
    if !valid_identifier(&input.workflow_id)
        || input.graph_version.trim().is_empty()
        || input.nodes.is_empty()
        || input.provenance.is_empty()
        || input.version_bound_evidence.is_empty()
    {
        return Err("workflow_identity_version_or_evidence_invalid".into());
    }
    let mut nodes = input.nodes.clone();
    let mut edges = input.edges.clone();
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    let graph_material = (input.workflow_id.as_str(), input.graph_version.as_str(), &nodes, &edges);
    let graph_digest = canonical(&graph_material)
        .map(|bytes| digest(&bytes))
        .ok_or_else(|| "workflow_graph_canonicalization_failed".to_owned())?;

    let mut node_ids = BTreeSet::new();
    for node in &nodes {
        if !valid_identifier(&node.node_id)
            || node.node_type.trim().is_empty()
            || node.operation_ref.trim().is_empty()
            || node.configuration_digest.len() != 64
            || !node.configuration_digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !node_ids.insert(node.node_id.as_str())
        {
            return Ok(invalid_output(input, "invalid_reference", graph_digest));
        }
    }

    let mut edge_ids = BTreeSet::new();
    let mut edge_pairs = BTreeSet::new();
    let mut indegree: BTreeMap<String, usize> =
        node_ids.iter().map(|id| ((*id).to_owned(), 0)).collect();
    let mut outgoing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in &edges {
        if !valid_identifier(&edge.edge_id)
            || edge.dependency_type.trim().is_empty()
            || !edge_ids.insert(edge.edge_id.as_str())
            || !edge_pairs.insert((edge.from_node_id.as_str(), edge.to_node_id.as_str()))
            || !node_ids.contains(edge.from_node_id.as_str())
            || !node_ids.contains(edge.to_node_id.as_str())
            || edge.from_node_id == edge.to_node_id
        {
            return Ok(invalid_output(input, "invalid_reference", graph_digest));
        }
        outgoing
            .entry(edge.from_node_id.clone())
            .or_default()
            .insert(edge.to_node_id.clone());
        *indegree.entry(edge.to_node_id.clone()).or_default() += 1;
    }

    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter_map(|(node, degree)| (*degree == 0).then_some(node.clone()))
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(node) = ready.pop_first() {
        order.push(node.clone());
        if let Some(targets) = outgoing.get(&node) {
            for target in targets {
                let degree = indegree.get_mut(target).expect("validated edge target");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(target.clone());
                }
            }
        }
    }
    let status = if order.len() == nodes.len() { "valid" } else { "cycle" };
    if status == "cycle" {
        order.clear();
    }
    Ok(WorkflowGraphOutput {
        workflow_id: input.workflow_id.clone(),
        graph_digest,
        topological_order: order,
        validation_status: status.into(),
        evidence: WorkflowGraphEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence: input.version_bound_evidence.clone(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: &str) -> WorkflowNode {
        WorkflowNode {
            node_id: id.into(),
            node_type: "task".into(),
            operation_ref: format!("operation:{id}"),
            configuration_digest: "a".repeat(64),
        }
    }

    fn input() -> WorkflowGraphInput {
        WorkflowGraphInput {
            workflow_id: "workflow-1".into(),
            nodes: vec![node("node-c"), node("node-a"), node("node-b")],
            edges: vec![
                WorkflowEdge {
                    edge_id: "edge-ab".into(),
                    from_node_id: "node-a".into(),
                    to_node_id: "node-b".into(),
                    dependency_type: "requires".into(),
                },
                WorkflowEdge {
                    edge_id: "edge-bc".into(),
                    from_node_id: "node-b".into(),
                    to_node_id: "node-c".into(),
                    dependency_type: "requires".into(),
                },
            ],
            graph_version: "1.0.0".into(),
            provenance: BTreeMap::from([("source".into(), json!("synthetic"))]),
            version_bound_evidence: BTreeMap::from([("genome_digest".into(), json!("b".repeat(64)))]),
        }
    }

    #[test]
    fn emits_stable_complete_topological_order() {
        let result = evaluate_workflow_graph(&input()).unwrap();
        assert_eq!(result.validation_status, "valid");
        assert_eq!(result.topological_order, vec!["node-a", "node-b", "node-c"]);
        assert_eq!(result.graph_digest.len(), 64);
    }

    #[test]
    fn rejects_missing_endpoints_self_edges_and_duplicate_ids() {
        let mut value = input();
        value.edges[0].to_node_id = "missing-node".into();
        assert_eq!(evaluate_workflow_graph(&value).unwrap().validation_status, "invalid_reference");
        let mut value = input();
        value.edges[0].to_node_id = value.edges[0].from_node_id.clone();
        assert_eq!(evaluate_workflow_graph(&value).unwrap().validation_status, "invalid_reference");
        let mut value = input();
        value.nodes.push(node("node-a"));
        assert_eq!(evaluate_workflow_graph(&value).unwrap().validation_status, "invalid_reference");
    }

    #[test]
    fn detects_cycles_without_emitting_partial_order() {
        let mut value = input();
        value.edges.push(WorkflowEdge {
            edge_id: "edge-ca".into(),
            from_node_id: "node-c".into(),
            to_node_id: "node-a".into(),
            dependency_type: "requires".into(),
        });
        let result = evaluate_workflow_graph(&value).unwrap();
        assert_eq!(result.validation_status, "cycle");
        assert!(result.topological_order.is_empty());
    }

    #[test]
    fn rejects_invalid_configuration_digest() {
        let mut value = input();
        value.nodes[0].configuration_digest = "bad".into();
        assert_eq!(evaluate_workflow_graph(&value).unwrap().validation_status, "invalid_reference");
    }

    #[test]
    fn rejects_missing_provenance_and_evidence() {
        let mut value = input();
        value.provenance.clear();
        assert!(evaluate_workflow_graph(&value).is_err());
        let mut value = input();
        value.version_bound_evidence.clear();
        assert!(evaluate_workflow_graph(&value).is_err());
    }
}
