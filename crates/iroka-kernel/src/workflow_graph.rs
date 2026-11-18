//! G08 workflow-graph contract evaluator.
//!
//! This module validates immutable workflow graph structure only. It never schedules,
//! invokes, authorizes, or performs a node operation. Registry adapters are trusted
//! boundaries and must return only authenticated, immutable registry snapshots.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const WORKFLOW_GRAPH_VALIDATOR_VERSION: &str = "1.0.0";
const CONFIGURATION_DIGEST_ALGORITHM: &str = "SHA-256";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphNode {
    pub node_id: String,
    pub node_type: String,
    pub operation_ref: String,
    pub configuration_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub dependency_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphInput {
    pub workflow_id: String,
    pub nodes: Vec<WorkflowGraphNode>,
    pub edges: Vec<WorkflowGraphEdge>,
    pub graph_version: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowRevisionBinding {
    pub workflow_id: String,
    pub revision_ref: String,
    pub graph_version: String,
    pub revision_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowOperationBinding {
    pub operation_ref: String,
    pub node_type: String,
    pub implementation_digest: String,
    pub effect_class: String,
    pub configuration_digests: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowDependencyKind {
    pub dependency_type: String,
    /// "success" means the prerequisite must succeed; "completion" means terminal completion.
    pub satisfaction_rule: String,
    /// "block" prevents dependent progression on prerequisite failure; "continue" is ordering-only.
    pub failure_behavior: String,
}

/// Implementations must resolve from authenticated, immutable, versioned snapshots.
/// Untrusted workflow input must never supply or replace these registries.
pub trait WorkflowGraphRegistry {
    fn workflow_revision(&self, workflow_id: &str) -> Option<&WorkflowRevisionBinding>;
    fn operation_binding(&self, operation_ref: &str) -> Option<&WorkflowOperationBinding>;
    fn dependency_kind(&self, dependency_type: &str) -> Option<&WorkflowDependencyKind>;
    fn workflow_registry_digest(&self) -> &str;
    fn operation_registry_digest(&self) -> &str;
    fn dependency_registry_digest(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphEvidence {
    pub findings: Vec<String>,
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

#[derive(Serialize)]
struct GraphDigestMaterial<'a> {
    workflow_id: &'a str,
    graph_version: &'a str,
    revision_digest: &'a str,
    nodes: Vec<&'a WorkflowGraphNode>,
    edges: Vec<&'a WorkflowGraphEdge>,
    workflow_registry_digest: &'a str,
    operation_registry_digest: &'a str,
    dependency_registry_digest: &'a str,
    validator_version: &'a str,
    configuration_digest_algorithm: &'static str,
}

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json(
        &serde_json::to_value(value).map_err(|_| "workflow_graph_serialization_failed")?,
    )
    .map_err(|_| "workflow_graph_canonicalization_failed")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_semver(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
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

fn required_evidence<'a>(
    evidence: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, String> {
    evidence
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("workflow_graph_evidence_missing:{key}"))
}

fn sorted_graph<'a>(
    input: &'a WorkflowGraphInput,
    revision: &WorkflowRevisionBinding,
    registry: &impl WorkflowGraphRegistry,
) -> Result<
    (
        String,
        Vec<&'a WorkflowGraphNode>,
        Vec<&'a WorkflowGraphEdge>,
    ),
    String,
> {
    let mut nodes: Vec<_> = input.nodes.iter().collect();
    let mut edges: Vec<_> = input.edges.iter().collect();
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    edges.sort_by(|left, right| {
        (
            &left.edge_id,
            &left.from_node_id,
            &left.to_node_id,
            &left.dependency_type,
        )
            .cmp(&(
                &right.edge_id,
                &right.from_node_id,
                &right.to_node_id,
                &right.dependency_type,
            ))
    });
    let material = GraphDigestMaterial {
        workflow_id: &input.workflow_id,
        graph_version: &input.graph_version,
        revision_digest: &revision.revision_digest,
        nodes,
        edges,
        workflow_registry_digest: registry.workflow_registry_digest(),
        operation_registry_digest: registry.operation_registry_digest(),
        dependency_registry_digest: registry.dependency_registry_digest(),
        validator_version: WORKFLOW_GRAPH_VALIDATOR_VERSION,
        configuration_digest_algorithm: CONFIGURATION_DIGEST_ALGORITHM,
    };
    let graph_digest = digest(&material)?;
    let mut nodes: Vec<_> = input.nodes.iter().collect();
    let mut edges: Vec<_> = input.edges.iter().collect();
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    edges.sort_by(|left, right| {
        (
            &left.edge_id,
            &left.from_node_id,
            &left.to_node_id,
            &left.dependency_type,
        )
            .cmp(&(
                &right.edge_id,
                &right.from_node_id,
                &right.to_node_id,
                &right.dependency_type,
            ))
    });
    Ok((graph_digest, nodes, edges))
}

fn topological_order(
    input: &WorkflowGraphInput,
    registry: &impl WorkflowGraphRegistry,
) -> Result<Vec<String>, Vec<String>> {
    let mut findings = Vec::new();
    let mut node_ids = BTreeSet::new();
    for node in &input.nodes {
        if !valid_identifier(&node.node_id)
            || !valid_identifier(&node.node_type)
            || !valid_identifier(&node.operation_ref)
            || !valid_digest(&node.configuration_digest)
            || !node_ids.insert(node.node_id.as_str())
        {
            findings.push("node_identity_or_configuration_invalid".to_owned());
            continue;
        }
        let Some(operation) = registry.operation_binding(&node.operation_ref) else {
            findings.push(format!("operation_not_registered:{}", node.operation_ref));
            continue;
        };
        if operation.operation_ref != node.operation_ref
            || operation.node_type != node.node_type
            || !valid_digest(&operation.implementation_digest)
            || !operation
                .configuration_digests
                .contains(&node.configuration_digest)
        {
            findings.push(format!("operation_binding_mismatch:{}", node.node_id));
        }
    }
    if node_ids.len() != input.nodes.len() {
        findings.push("duplicate_or_invalid_node_id".to_owned());
    }

    let mut edge_ids = BTreeSet::new();
    let mut edge_pairs = BTreeSet::new();
    let mut indegree: BTreeMap<String, usize> = node_ids
        .iter()
        .map(|node_id| ((*node_id).to_owned(), 0))
        .collect();
    let mut outgoing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in &input.edges {
        let valid_edge = valid_identifier(&edge.edge_id)
            && valid_identifier(&edge.from_node_id)
            && valid_identifier(&edge.to_node_id)
            && valid_identifier(&edge.dependency_type)
            && edge_ids.insert(edge.edge_id.as_str())
            && edge_pairs.insert((edge.from_node_id.as_str(), edge.to_node_id.as_str()));
        if !valid_edge
            || edge.from_node_id == edge.to_node_id
            || !node_ids.contains(edge.from_node_id.as_str())
            || !node_ids.contains(edge.to_node_id.as_str())
        {
            findings.push(format!(
                "edge_reference_or_identity_invalid:{}",
                edge.edge_id
            ));
            continue;
        }
        let Some(kind) = registry.dependency_kind(&edge.dependency_type) else {
            findings.push(format!(
                "dependency_kind_not_registered:{}",
                edge.dependency_type
            ));
            continue;
        };
        let semantics_match = match edge.dependency_type.as_str() {
            "required" => kind.satisfaction_rule == "success" && kind.failure_behavior == "block",
            "ordering" => kind.satisfaction_rule == "completion" && kind.failure_behavior == "continue",
            _ => false,
        };
        if kind.dependency_type != edge.dependency_type || !semantics_match
        {
            findings.push(format!(
                "dependency_kind_binding_invalid:{}",
                edge.dependency_type
            ));
            continue;
        }
        *indegree
            .get_mut(&edge.to_node_id)
            .expect("validated endpoint") += 1;
        outgoing
            .entry(edge.from_node_id.clone())
            .or_default()
            .insert(edge.to_node_id.clone());
    }
    if !findings.is_empty() {
        findings.sort();
        findings.dedup();
        return Err(findings);
    }

    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter_map(|(node_id, degree)| (*degree == 0).then_some(node_id.clone()))
        .collect();
    let mut order = Vec::with_capacity(node_ids.len());
    while let Some(node_id) = ready.pop_first() {
        order.push(node_id.clone());
        if let Some(targets) = outgoing.get(&node_id) {
            for target in targets {
                let degree = indegree.get_mut(target).expect("known graph node");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(target.clone());
                }
            }
        }
    }
    if order.len() != node_ids.len() {
        return Err(vec!["dependency_cycle_detected".to_owned()]);
    }
    Ok(order)
}

/// Validate a graph against trusted immutable registries. A valid result is structural
/// evidence only: it does not authorize, schedule, or execute any referenced operation.
pub fn evaluate_workflow_graph(
    input: &WorkflowGraphInput,
    registry: &impl WorkflowGraphRegistry,
) -> Result<WorkflowGraphOutput, String> {
    if !valid_identifier(&input.workflow_id)
        || !valid_semver(&input.graph_version)
        || input.nodes.is_empty()
        || input.nodes.len() > 10_000
        || input.edges.len() > 50_000
        || input.provenance.is_empty()
        || input.version_bound_evidence.is_empty()
    {
        return Err("workflow_graph_input_invalid".into());
    }
    let source_ref = required_evidence(&input.provenance, "source_ref")?;
    let revision_ref = required_evidence(&input.provenance, "revision_ref")?;
    if source_ref.len() > 512 || revision_ref.len() > 512 {
        return Err("workflow_graph_provenance_invalid".into());
    }
    let workflow_registry_digest = registry.workflow_registry_digest();
    let operation_registry_digest = registry.operation_registry_digest();
    let dependency_registry_digest = registry.dependency_registry_digest();
    for value in [
        workflow_registry_digest,
        operation_registry_digest,
        dependency_registry_digest,
    ] {
        if !valid_digest(value) {
            return Err("workflow_graph_registry_digest_invalid".into());
        }
    }
    let bound = &input.version_bound_evidence;
    if required_evidence(bound, "workflow_registry_digest")? != workflow_registry_digest
        || required_evidence(bound, "operation_registry_digest")? != operation_registry_digest
        || required_evidence(bound, "dependency_registry_digest")? != dependency_registry_digest
        || required_evidence(bound, "configuration_digest_algorithm")?
            != CONFIGURATION_DIGEST_ALGORITHM
        || required_evidence(bound, "graph_validator_version")? != WORKFLOW_GRAPH_VALIDATOR_VERSION
    {
        return Err("workflow_graph_version_binding_mismatch".into());
    }
    let Some(revision) = registry.workflow_revision(&input.workflow_id) else {
        return Err("workflow_revision_not_registered".into());
    };
    if revision.workflow_id != input.workflow_id
        || revision.revision_ref != revision_ref
        || revision.graph_version != input.graph_version
        || !valid_digest(&revision.revision_digest)
        || required_evidence(bound, "graph_revision_digest")? != revision.revision_digest
    {
        return Err("workflow_revision_binding_mismatch".into());
    }
    let (graph_digest, _nodes, _edges) = sorted_graph(input, revision, registry)?;
    let (validation_status, topological_order, findings) = match topological_order(input, registry)
    {
        Ok(order) => ("valid".to_owned(), order, Vec::new()),
        Err(findings)
            if findings
                .iter()
                .any(|item| item == "dependency_cycle_detected") =>
        {
            ("cycle".to_owned(), Vec::new(), findings)
        }
        Err(findings) => ("invalid_reference".to_owned(), Vec::new(), findings),
    };
    Ok(WorkflowGraphOutput {
        workflow_id: input.workflow_id.clone(),
        graph_digest,
        topological_order,
        validation_status,
        evidence: WorkflowGraphEvidence {
            findings,
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

    struct TestRegistry {
        revision: WorkflowRevisionBinding,
        operations: BTreeMap<String, WorkflowOperationBinding>,
        dependencies: BTreeMap<String, WorkflowDependencyKind>,
        workflow_digest: String,
        operation_digest: String,
        dependency_digest: String,
    }

    impl WorkflowGraphRegistry for TestRegistry {
        fn workflow_revision(&self, workflow_id: &str) -> Option<&WorkflowRevisionBinding> {
            (workflow_id == self.revision.workflow_id).then_some(&self.revision)
        }
        fn operation_binding(&self, operation_ref: &str) -> Option<&WorkflowOperationBinding> {
            self.operations.get(operation_ref)
        }
        fn dependency_kind(&self, dependency_type: &str) -> Option<&WorkflowDependencyKind> {
            self.dependencies.get(dependency_type)
        }
        fn workflow_registry_digest(&self) -> &str {
            &self.workflow_digest
        }
        fn operation_registry_digest(&self) -> &str {
            &self.operation_digest
        }
        fn dependency_registry_digest(&self) -> &str {
            &self.dependency_digest
        }
    }

    fn registry() -> TestRegistry {
        let operation = |node_type: &str| WorkflowOperationBinding {
            operation_ref: format!("operation.{node_type}"),
            node_type: node_type.into(),
            implementation_digest: "a".repeat(64),
            effect_class: "none".into(),
            configuration_digests: ["b".repeat(64)].into_iter().collect(),
        };
        TestRegistry {
            revision: WorkflowRevisionBinding {
                workflow_id: "workflow.demo".into(),
                revision_ref: "revision:demo:1".into(),
                graph_version: "1.0.0".into(),
                revision_digest: "c".repeat(64),
            },
            operations: BTreeMap::from([
                ("operation.fetch".into(), operation("fetch")),
                ("operation.transform".into(), operation("transform")),
                ("operation.review".into(), operation("review")),
            ]),
            dependencies: BTreeMap::from([
                (
                    "required".into(),
                    WorkflowDependencyKind {
                        dependency_type: "required".into(),
                        satisfaction_rule: "success".into(),
                        failure_behavior: "block".into(),
                    },
                ),
                (
                    "ordering".into(),
                    WorkflowDependencyKind {
                        dependency_type: "ordering".into(),
                        satisfaction_rule: "completion".into(),
                        failure_behavior: "continue".into(),
                    },
                ),
            ]),
            workflow_digest: "d".repeat(64),
            operation_digest: "e".repeat(64),
            dependency_digest: "f".repeat(64),
        }
    }

    fn input(registry: &TestRegistry) -> WorkflowGraphInput {
        WorkflowGraphInput {
            workflow_id: "workflow.demo".into(),
            nodes: vec![
                WorkflowGraphNode {
                    node_id: "node.fetch".into(),
                    node_type: "fetch".into(),
                    operation_ref: "operation.fetch".into(),
                    configuration_digest: "b".repeat(64),
                },
                WorkflowGraphNode {
                    node_id: "node.transform".into(),
                    node_type: "transform".into(),
                    operation_ref: "operation.transform".into(),
                    configuration_digest: "b".repeat(64),
                },
                WorkflowGraphNode {
                    node_id: "node.review".into(),
                    node_type: "review".into(),
                    operation_ref: "operation.review".into(),
                    configuration_digest: "b".repeat(64),
                },
            ],
            edges: vec![
                WorkflowGraphEdge {
                    edge_id: "edge.fetch-transform".into(),
                    from_node_id: "node.fetch".into(),
                    to_node_id: "node.transform".into(),
                    dependency_type: "required".into(),
                },
                WorkflowGraphEdge {
                    edge_id: "edge.transform-review".into(),
                    from_node_id: "node.transform".into(),
                    to_node_id: "node.review".into(),
                    dependency_type: "required".into(),
                },
            ],
            graph_version: "1.0.0".into(),
            provenance: BTreeMap::from([
                ("source_ref".into(), json!("synthetic:test")),
                ("revision_ref".into(), json!("revision:demo:1")),
            ]),
            version_bound_evidence: BTreeMap::from([
                (
                    "workflow_registry_digest".into(),
                    json!(registry.workflow_digest.clone()),
                ),
                (
                    "operation_registry_digest".into(),
                    json!(registry.operation_digest.clone()),
                ),
                (
                    "dependency_registry_digest".into(),
                    json!(registry.dependency_digest.clone()),
                ),
                ("graph_revision_digest".into(), json!("c".repeat(64))),
                (
                    "configuration_digest_algorithm".into(),
                    json!(CONFIGURATION_DIGEST_ALGORITHM),
                ),
                (
                    "graph_validator_version".into(),
                    json!(WORKFLOW_GRAPH_VALIDATOR_VERSION),
                ),
            ]),
        }
    }

    #[test]
    fn accepts_complete_deterministic_topological_order() {
        let registry = registry();
        let input = input(&registry);
        let output = evaluate_workflow_graph(&input, &registry).unwrap();
        assert_eq!(output.validation_status, "valid");
        assert_eq!(
            output.topological_order,
            vec!["node.fetch", "node.transform", "node.review"]
        );
        assert!(output.evidence.findings.is_empty());
        assert_eq!(output.graph_digest.len(), 64);
    }

    #[test]
    fn graph_digest_is_independent_of_input_vector_order() {
        let registry = registry();
        let mut first = input(&registry);
        let mut second = first.clone();
        second.nodes.reverse();
        second.edges.reverse();
        assert_eq!(
            evaluate_workflow_graph(&first, &registry)
                .unwrap()
                .graph_digest,
            evaluate_workflow_graph(&second, &registry)
                .unwrap()
                .graph_digest
        );
        first.nodes.swap(0, 1);
        assert_eq!(
            evaluate_workflow_graph(&first, &registry)
                .unwrap()
                .topological_order,
            vec!["node.fetch", "node.transform", "node.review"]
        );
    }

    #[test]
    fn rejects_unknown_or_mutable_workflow_revision() {
        let registry = registry();
        let mut value = input(&registry);
        value.graph_version = "2.0.0".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_revision_binding_mismatch".into())
        );
    }

    #[test]
    fn rejects_registry_digest_substitution() {
        let registry = registry();
        let mut value = input(&registry);
        value
            .version_bound_evidence
            .insert("operation_registry_digest".into(), json!("0".repeat(64)));
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_version_binding_mismatch".into())
        );
    }

    #[test]
    fn rejects_operation_substitution_and_configuration_drift() {
        let registry = registry();
        let mut value = input(&registry);
        value.nodes[0].operation_ref = "operation.review".into();
        let output = evaluate_workflow_graph(&value, &registry).unwrap();
        assert_eq!(output.validation_status, "invalid_reference");
        assert!(output.topological_order.is_empty());
        let mut value = input(&registry);
        value.nodes[0].configuration_digest = "0".repeat(64);
        let output = evaluate_workflow_graph(&value, &registry).unwrap();
        assert_eq!(output.validation_status, "invalid_reference");
    }

    #[test]
    fn rejects_missing_duplicate_self_and_unknown_dependency_references() {
        let registry = registry();
        let mut value = input(&registry);
        value.edges[0].to_node_id = "node.unknown".into();
        let output = evaluate_workflow_graph(&value, &registry).unwrap();
        assert_eq!(output.validation_status, "invalid_reference");
        assert!(output.topological_order.is_empty());
        let mut value = input(&registry);
        value.edges[0].from_node_id = value.edges[0].to_node_id.clone();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry)
                .unwrap()
                .validation_status,
            "invalid_reference"
        );
        let mut value = input(&registry);
        value.edges[0].dependency_type = "unregistered".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry)
                .unwrap()
                .validation_status,
            "invalid_reference"
        );
        let mut value = input(&registry);
        value.nodes.push(value.nodes[0].clone());
        assert_eq!(
            evaluate_workflow_graph(&value, &registry)
                .unwrap()
                .validation_status,
            "invalid_reference"
        );
    }

    #[test]
    fn cycle_never_emits_topological_order() {
        let registry = registry();
        let mut value = input(&registry);
        value.edges.push(WorkflowGraphEdge {
            edge_id: "edge.review-fetch".into(),
            from_node_id: "node.review".into(),
            to_node_id: "node.fetch".into(),
            dependency_type: "required".into(),
        });
        let output = evaluate_workflow_graph(&value, &registry).unwrap();
        assert_eq!(output.validation_status, "cycle");
        assert!(output.topological_order.is_empty());
        assert!(output
            .evidence
            .findings
            .contains(&"dependency_cycle_detected".into()));
    }

    #[test]
    fn rejects_non_semver_versions_and_revision_reference_substitution() {
        let registry = registry();
        let mut value = input(&registry);
        value.graph_version = "latest".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_input_invalid".into())
        );
        let mut value = input(&registry);
        value.provenance.insert("revision_ref".into(), json!("revision:other:2"));
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_revision_binding_mismatch".into())
        );
    }

    #[test]
    fn rejects_dependency_semantics_substitution_and_unknown_effect_class() {
        let mut registry = registry();
        registry.dependencies.get_mut("required").unwrap().failure_behavior = "continue".into();
        let value = input(&registry);
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );
        let mut registry = registry();
        registry.operations.get_mut("operation.fetch").unwrap().effect_class = "unregistered".into();
        let value = input(&registry);
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );
    }

    #[test]
    fn rejects_missing_provenance_and_non_version_bound_evidence() {
        let registry = registry();
        let mut value = input(&registry);
        value.provenance.clear();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_input_invalid".into())
        );
        let mut value = input(&registry);
        value.version_bound_evidence.remove("graph_revision_digest");
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_evidence_missing:graph_revision_digest".into())
        );
    }
}
