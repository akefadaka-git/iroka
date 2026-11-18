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
    pub checkpoint_ref: Option<String>,
    pub safe_stop: bool,
    pub recovery_node_id: Option<String>,
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
    pub provenance: WorkflowGraphProvenance,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNodeOperationProvenance {
    pub node_id: String,
    pub operation_ref: String,
    pub implementation_digest: String,
    pub configuration_digest: String,
    pub operation_provenance_ref: String,
    pub configuration_provenance_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDependencyEdgeProvenance {
    pub edge_id: String,
    pub dependency_type: String,
    pub provenance_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphProvenance {
    pub source_ref: String,
    pub revision_ref: String,
    pub workflow_registry_ref: String,
    pub operation_registry_ref: String,
    pub dependency_registry_ref: String,
    pub checkpoint_registry_ref: String,
    pub node_operations: Vec<WorkflowNodeOperationProvenance>,
    pub dependency_edges: Vec<WorkflowDependencyEdgeProvenance>,
    pub validation_input_refs: Vec<String>,
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
    pub configurations: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowDependencyKind {
    pub dependency_type: String,
    pub mandatory: bool,
    pub conditionality: String,
    /// "success" means the prerequisite must succeed; "completion" means terminal completion.
    pub satisfaction_rule: String,
    /// "block" prevents dependent progression on prerequisite failure; "continue" is ordering-only.
    pub failure_behavior: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowCheckpointBinding {
    pub checkpoint_ref: String,
    pub workflow_id: String,
    pub graph_version: String,
    pub node_id: String,
    pub configuration_digest: String,
    pub immutable: bool,
}

/// Implementations must resolve from authenticated, immutable, versioned snapshots.
/// Untrusted workflow input must never supply or replace these registries.
pub trait WorkflowGraphRegistry {
    fn workflow_revision(&self, workflow_id: &str) -> Option<&WorkflowRevisionBinding>;
    fn operation_binding(&self, operation_ref: &str) -> Option<&WorkflowOperationBinding>;
    fn dependency_kind(&self, dependency_type: &str) -> Option<&WorkflowDependencyKind>;
    fn checkpoint_binding(&self, checkpoint_ref: &str) -> Option<&WorkflowCheckpointBinding>;
    fn effect_class_registered(&self, effect_class: &str) -> bool;
    fn workflow_registry_digest(&self) -> &str;
    fn operation_registry_digest(&self) -> &str;
    fn dependency_registry_digest(&self) -> &str;
    fn checkpoint_registry_digest(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGraphEvidence {
    pub findings: Vec<String>,
    pub provenance: WorkflowGraphProvenance,
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
    checkpoint_registry_digest: &'a str,
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

fn sorted_graph_digest(
    input: &WorkflowGraphInput,
    revision: &WorkflowRevisionBinding,
    registry: &impl WorkflowGraphRegistry,
) -> Result<String, String> {
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
        checkpoint_registry_digest: registry.checkpoint_registry_digest(),
        validator_version: WORKFLOW_GRAPH_VALIDATOR_VERSION,
        configuration_digest_algorithm: CONFIGURATION_DIGEST_ALGORITHM,
    };
    digest(&material)
}

fn validate_provenance(
    input: &WorkflowGraphInput,
    registry: &impl WorkflowGraphRegistry,
) -> Result<(), String> {
    let provenance = &input.provenance;
    for value in [
        provenance.source_ref.as_str(),
        provenance.revision_ref.as_str(),
        provenance.workflow_registry_ref.as_str(),
        provenance.operation_registry_ref.as_str(),
        provenance.dependency_registry_ref.as_str(),
        provenance.checkpoint_registry_ref.as_str(),
    ] {
        if value.is_empty() || value.len() > 512 {
            return Err("workflow_graph_provenance_invalid".into());
        }
    }
    if provenance.validation_input_refs.is_empty()
        || provenance.validation_input_refs.len() > 256
        || provenance.validation_input_refs.iter().any(|value| {
            value.is_empty() || value.len() > 512
        })
        || provenance.validation_input_refs.iter().collect::<BTreeSet<_>>().len()
            != provenance.validation_input_refs.len()
    {
        return Err("workflow_graph_validation_input_provenance_invalid".into());
    }
    if provenance.node_operations.len() != input.nodes.len()
        || provenance.dependency_edges.len() != input.edges.len()
    {
        return Err("workflow_graph_provenance_coverage_incomplete".into());
    }
    let mut node_provenance = BTreeMap::new();
    for item in &provenance.node_operations {
        if item.operation_provenance_ref.is_empty()
            || item.configuration_provenance_ref.is_empty()
            || node_provenance.insert(item.node_id.as_str(), item).is_some()
        {
            return Err("workflow_graph_node_provenance_invalid".into());
        }
    }
    for node in &input.nodes {
        let Some(item) = node_provenance.get(node.node_id.as_str()) else {
            return Err("workflow_graph_node_provenance_missing".into());
        };
        let Some(operation) = registry.operation_binding(&node.operation_ref) else {
            return Err("workflow_graph_operation_provenance_unresolved".into());
        };
        if item.operation_ref != node.operation_ref
            || item.implementation_digest != operation.implementation_digest
            || item.configuration_digest != node.configuration_digest
        {
            return Err("workflow_graph_node_provenance_binding_mismatch".into());
        }
    }
    let mut edge_provenance = BTreeMap::new();
    for item in &provenance.dependency_edges {
        if item.provenance_ref.is_empty()
            || edge_provenance.insert(item.edge_id.as_str(), item).is_some()
        {
            return Err("workflow_graph_edge_provenance_invalid".into());
        }
    }
    for edge in &input.edges {
        let Some(item) = edge_provenance.get(edge.edge_id.as_str()) else {
            return Err("workflow_graph_edge_provenance_missing".into());
        };
        if item.dependency_type != edge.dependency_type {
            return Err("workflow_graph_edge_provenance_binding_mismatch".into());
        }
    }
    if provenance.workflow_registry_ref.is_empty()
        || provenance.operation_registry_ref.is_empty()
        || provenance.dependency_registry_ref.is_empty()
        || provenance.checkpoint_registry_ref.is_empty()
        || registry.workflow_registry_digest().is_empty()
        || registry.operation_registry_digest().is_empty()
        || registry.dependency_registry_digest().is_empty()
        || registry.checkpoint_registry_digest().is_empty()
    {
        return Err("workflow_graph_registry_provenance_missing".into());
    }
    Ok(())
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
        let configuration_matches = operation
            .configurations
            .get(&node.configuration_digest)
            .and_then(|configuration| digest(configuration).ok())
            .is_some_and(|actual_digest| actual_digest == node.configuration_digest);
        if operation.operation_ref != node.operation_ref
            || operation.node_type != node.node_type
            || !valid_digest(&operation.implementation_digest)
            || !valid_identifier(&operation.effect_class)
            || !registry.effect_class_registered(&operation.effect_class)
            || !configuration_matches
        {
            findings.push(format!("operation_binding_mismatch:{}", node.node_id));
        }
        if let Some(checkpoint_ref) = &node.checkpoint_ref {
            let checkpoint_matches = registry
                .checkpoint_binding(checkpoint_ref)
                .is_some_and(|checkpoint| {
                    checkpoint.checkpoint_ref == *checkpoint_ref
                        && checkpoint.workflow_id == input.workflow_id
                        && checkpoint.graph_version == input.graph_version
                        && checkpoint.node_id == node.node_id
                        && checkpoint.configuration_digest == node.configuration_digest
                        && checkpoint.immutable
                });
            if !valid_identifier(checkpoint_ref) || !checkpoint_matches {
                findings.push(format!("checkpoint_binding_invalid:{}", node.node_id));
            }
        } else if node.safe_stop {
            findings.push(format!("safe_stop_checkpoint_missing:{}", node.node_id));
        }
        match (&node.safe_stop, &node.recovery_node_id) {
            (true, Some(recovery_id))
                if valid_identifier(recovery_id)
                    && recovery_id != &node.node_id
                    && node_ids.contains(recovery_id.as_str()) => {}
            (true, _) => findings.push(format!("safe_stop_recovery_path_invalid:{}", node.node_id)),
            (false, Some(_)) => {
                findings.push(format!("unexpected_recovery_path:{}", node.node_id));
            }
            (false, None) => {}
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
            "required" => {
                kind.mandatory
                    && kind.conditionality == "unconditional"
                    && kind.satisfaction_rule == "success"
                    && kind.failure_behavior == "block"
            }
            "ordering" => {
                kind.mandatory
                    && kind.conditionality == "unconditional"
                    && kind.satisfaction_rule == "completion"
                    && kind.failure_behavior == "continue"
            }
            _ => false,
        };
        if kind.dependency_type != edge.dependency_type || !semantics_match {
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
        || input.version_bound_evidence.is_empty()
    {
        return Err("workflow_graph_input_invalid".into());
    }
    if input.provenance.source_ref.is_empty()
        || input.provenance.revision_ref.is_empty()
        || input.provenance.source_ref.len() > 512
        || input.provenance.revision_ref.len() > 512
    {
        return Err("workflow_graph_provenance_invalid".into());
    }
    let workflow_registry_digest = registry.workflow_registry_digest();
    let operation_registry_digest = registry.operation_registry_digest();
    let dependency_registry_digest = registry.dependency_registry_digest();
    let checkpoint_registry_digest = registry.checkpoint_registry_digest();
    for value in [
        workflow_registry_digest,
        operation_registry_digest,
        dependency_registry_digest,
        checkpoint_registry_digest,
    ] {
        if !valid_digest(value) {
            return Err("workflow_graph_registry_digest_invalid".into());
        }
    }
    let bound = &input.version_bound_evidence;
    let expected_keys = [
        "workflow_registry_digest",
        "operation_registry_digest",
        "dependency_registry_digest",
        "checkpoint_registry_digest",
        "graph_revision_digest",
        "configuration_digest_algorithm",
        "graph_validator_version",
    ];
    if bound.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !bound.contains_key(*key))
    {
        return Err("workflow_graph_version_evidence_invalid".into());
    }
    if required_evidence(bound, "workflow_registry_digest")? != workflow_registry_digest
        || required_evidence(bound, "operation_registry_digest")? != operation_registry_digest
        || required_evidence(bound, "dependency_registry_digest")? != dependency_registry_digest
        || required_evidence(bound, "checkpoint_registry_digest")? != checkpoint_registry_digest
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
        || revision.revision_ref != input.provenance.revision_ref
        || revision.graph_version != input.graph_version
        || !valid_digest(&revision.revision_digest)
        || required_evidence(bound, "graph_revision_digest")? != revision.revision_digest
    {
        return Err("workflow_revision_binding_mismatch".into());
    }
    validate_provenance(input, registry)?;
    let graph_digest = sorted_graph_digest(input, revision, registry)?;
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
        checkpoints: BTreeMap<String, WorkflowCheckpointBinding>,
        effect_classes: BTreeSet<String>,
        workflow_digest: String,
        operation_digest: String,
        dependency_digest: String,
        checkpoint_digest: String,
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

        fn checkpoint_binding(&self, checkpoint_ref: &str) -> Option<&WorkflowCheckpointBinding> {
            self.checkpoints.get(checkpoint_ref)
        }

        fn effect_class_registered(&self, effect_class: &str) -> bool {
            self.effect_classes.contains(effect_class)
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

        fn checkpoint_registry_digest(&self) -> &str {
            &self.checkpoint_digest
        }
    }

    fn registry() -> TestRegistry {
        let operation = |node_type: &str| {
            let configuration = json!({"mode": node_type, "version": 1});
            let configuration_digest = digest(&configuration).unwrap();
            WorkflowOperationBinding {
                operation_ref: format!("operation.{node_type}"),
                node_type: node_type.into(),
                implementation_digest: "a".repeat(64),
                effect_class: "none".into(),
                configurations: BTreeMap::from([(configuration_digest, configuration)]),
            }
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
                        mandatory: true,
                        conditionality: "unconditional".into(),
                        satisfaction_rule: "success".into(),
                        failure_behavior: "block".into(),
                    },
                ),
                (
                    "ordering".into(),
                    WorkflowDependencyKind {
                        dependency_type: "ordering".into(),
                        mandatory: true,
                        conditionality: "unconditional".into(),
                        satisfaction_rule: "completion".into(),
                        failure_behavior: "continue".into(),
                    },
                ),
            ]),
            checkpoints: BTreeMap::new(),
            effect_classes: ["none", "read", "write", "external", "protected"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            workflow_digest: "d".repeat(64),
            operation_digest: "e".repeat(64),
            dependency_digest: "f".repeat(64),
            checkpoint_digest: "1".repeat(64),
        }
    }

    fn input(registry: &TestRegistry) -> WorkflowGraphInput {
        let mut nodes = vec![
            WorkflowGraphNode {
                node_id: "node.fetch".into(),
                node_type: "fetch".into(),
                operation_ref: "operation.fetch".into(),
                configuration_digest: registry.operations["operation.fetch"]
                    .configurations
                    .keys()
                    .next()
                    .unwrap()
                    .clone(),
                checkpoint_ref: None,
                safe_stop: false,
                recovery_node_id: None,
            },
            WorkflowGraphNode {
                node_id: "node.transform".into(),
                node_type: "transform".into(),
                operation_ref: "operation.transform".into(),
                configuration_digest: registry.operations["operation.transform"]
                    .configurations
                    .keys()
                    .next()
                    .unwrap()
                    .clone(),
                checkpoint_ref: None,
                safe_stop: false,
                recovery_node_id: None,
            },
            WorkflowGraphNode {
                node_id: "node.review".into(),
                node_type: "review".into(),
                operation_ref: "operation.review".into(),
                configuration_digest: registry.operations["operation.review"]
                    .configurations
                    .keys()
                    .next()
                    .unwrap()
                    .clone(),
                checkpoint_ref: None,
                safe_stop: false,
                recovery_node_id: None,
            },
        ];
        let edges = vec![
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
        ];
        let node_operations = nodes
            .iter()
            .map(|node| {
                let operation = &registry.operations[&node.operation_ref];
                WorkflowNodeOperationProvenance {
                    node_id: node.node_id.clone(),
                    operation_ref: node.operation_ref.clone(),
                    implementation_digest: operation.implementation_digest.clone(),
                    configuration_digest: node.configuration_digest.clone(),
                    operation_provenance_ref: format!("operation-source:{}", node.node_id),
                    configuration_provenance_ref: format!("configuration-source:{}", node.node_id),
                }
            })
            .collect();
        let dependency_edges = edges
            .iter()
            .map(|edge| WorkflowDependencyEdgeProvenance {
                edge_id: edge.edge_id.clone(),
                dependency_type: edge.dependency_type.clone(),
                provenance_ref: format!("dependency-source:{}", edge.edge_id),
            })
            .collect();
        let provenance = WorkflowGraphProvenance {
            source_ref: "synthetic:test".into(),
            revision_ref: "revision:demo:1".into(),
            workflow_registry_ref: "registry:workflow:1".into(),
            operation_registry_ref: "registry:operation:1".into(),
            dependency_registry_ref: "registry:dependency:1".into(),
            checkpoint_registry_ref: "registry:checkpoint:1".into(),
            node_operations,
            dependency_edges,
            validation_input_refs: vec![
                "input:workflow".into(),
                "input:operations".into(),
                "input:dependencies".into(),
                "input:checkpoints".into(),
            ],
        };
        WorkflowGraphInput {
            workflow_id: "workflow.demo".into(),
            nodes: std::mem::take(&mut nodes),
            edges,
            graph_version: "1.0.0".into(),
            provenance,
            version_bound_evidence: BTreeMap::from([
                ("workflow_registry_digest".into(), json!(registry.workflow_digest)),
                ("operation_registry_digest".into(), json!(registry.operation_digest)),
                ("dependency_registry_digest".into(), json!(registry.dependency_digest)),
                ("checkpoint_registry_digest".into(), json!(registry.checkpoint_digest)),
                ("graph_revision_digest".into(), json!("c".repeat(64))),
                ("configuration_digest_algorithm".into(), json!(CONFIGURATION_DIGEST_ALGORITHM)),
                ("graph_validator_version".into(), json!(WORKFLOW_GRAPH_VALIDATOR_VERSION)),
            ]),
        }
    }

    #[test]
    fn accepts_complete_deterministic_topological_order() {
        let registry = registry();
        let value = input(&registry);
        let output = evaluate_workflow_graph(&value, &registry).unwrap();
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
            evaluate_workflow_graph(&first, &registry).unwrap().graph_digest,
            evaluate_workflow_graph(&second, &registry).unwrap().graph_digest
        );
        first.nodes.swap(0, 1);
        assert_eq!(
            evaluate_workflow_graph(&first, &registry).unwrap().topological_order,
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
    fn rejects_operation_substitution_and_configuration_digest_drift() {
        let registry = registry();
        let mut value = input(&registry);
        value.nodes[0].operation_ref = "operation.review".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_node_provenance_binding_mismatch".into())
        );
        let mut value = input(&registry);
        value.nodes[0].configuration_digest = "0".repeat(64);
        value.provenance.node_operations[0].configuration_digest = "0".repeat(64);
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );
    }

    #[test]
    fn rejects_unregistered_effect_class_and_dependency_semantics() {
        let mut operation_registry = registry();
        operation_registry
            .operations
            .get_mut("operation.fetch")
            .unwrap()
            .effect_class = "unregistered".into();
        let value = input(&operation_registry);
        assert_eq!(
            evaluate_workflow_graph(&value, &operation_registry)
                .unwrap()
                .validation_status,
            "invalid_reference"
        );

        let mut dependency_registry = registry();
        dependency_registry
            .dependencies
            .get_mut("required")
            .unwrap()
            .conditionality = "conditional".into();
        let value = input(&dependency_registry);
        assert_eq!(
            evaluate_workflow_graph(&value, &dependency_registry)
                .unwrap()
                .validation_status,
            "invalid_reference"
        );
    }

    #[test]
    fn rejects_missing_duplicate_self_and_unknown_dependency_references() {
        let registry = registry();
        let mut value = input(&registry);
        value.edges[0].to_node_id = "node.unknown".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );

        let mut value = input(&registry);
        value.edges[0].from_node_id = value.edges[0].to_node_id.clone();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );

        let mut value = input(&registry);
        value.edges[0].dependency_type = "unregistered".into();
        value.provenance.dependency_edges[0].dependency_type = "unregistered".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );

        let mut value = input(&registry);
        value.nodes.push(value.nodes[0].clone());
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );

        let mut value = input(&registry);
        value.edges[1].edge_id = value.edges[0].edge_id.clone();
        value.provenance.dependency_edges[1].edge_id = value.edges[0].edge_id.clone();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
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
        value.provenance.dependency_edges.push(WorkflowDependencyEdgeProvenance {
            edge_id: "edge.review-fetch".into(),
            dependency_type: "required".into(),
            provenance_ref: "dependency-source:edge.review-fetch".into(),
        });
        let output = evaluate_workflow_graph(&value, &registry).unwrap();
        assert_eq!(output.validation_status, "cycle");
        assert!(output.topological_order.is_empty());
        assert!(output.evidence.findings.contains(&"dependency_cycle_detected".into()));
    }

    #[test]
    fn requires_checkpoint_and_registered_recovery_path_for_safe_stop() {
        let mut registry = registry();
        let mut value = input(&registry);
        value.nodes[2].safe_stop = true;
        value.nodes[2].recovery_node_id = Some("node.fetch".into());
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );

        let config_digest = value.nodes[2].configuration_digest.clone();
        let checkpoint = WorkflowCheckpointBinding {
            checkpoint_ref: "checkpoint.review".into(),
            workflow_id: "workflow.demo".into(),
            graph_version: "1.0.0".into(),
            node_id: "node.review".into(),
            configuration_digest: config_digest,
            immutable: true,
        };
        registry.checkpoints.insert(checkpoint.checkpoint_ref.clone(), checkpoint);
        value.nodes[2].checkpoint_ref = Some("checkpoint.review".into());
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "valid"
        );
        value.nodes[2].checkpoint_ref = Some("checkpoint.unknown".into());
        assert_eq!(
            evaluate_workflow_graph(&value, &registry).unwrap().validation_status,
            "invalid_reference"
        );
    }

    #[test]
    fn rejects_incomplete_or_mismatched_provenance_and_unknown_evidence_keys() {
        let registry = registry();
        let mut value = input(&registry);
        value.provenance.node_operations.pop();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_provenance_coverage_incomplete".into())
        );
        let mut value = input(&registry);
        value.provenance.validation_input_refs.push("input:workflow".into());
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_validation_input_provenance_invalid".into())
        );
        let mut value = input(&registry);
        value.version_bound_evidence.insert("unexpected".into(), json!("x"));
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_graph_version_evidence_invalid".into())
        );
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
        value.provenance.revision_ref = "revision:other:2".into();
        assert_eq!(
            evaluate_workflow_graph(&value, &registry),
            Err("workflow_revision_binding_mismatch".into())
        );
    }
}
