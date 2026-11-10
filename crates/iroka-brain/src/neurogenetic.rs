//! Bounded neurogenetic contracts for IROKA INGA.
//!
//! This module defines synthetic, model-independent structures only. It does
//! not implement biological neurons, model training, durable memory, provider
//! access, agent delegation, policy decisions, or protected execution.
//! Cross-domain authority remains with the owning Genome chromosomes.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Contract version for the first neurogenetic structure family.
pub const NEUROGENETIC_CONTRACT_VERSION: &str = "1.0.0";
/// Maximum number of computational cells in one synthetic network.
pub const MAX_CELLS: usize = 100_000;
/// Maximum number of directed synapses in one synthetic network.
pub const MAX_SYNAPSES: usize = 1_000_000;
/// Fixed-point scale for synaptic weights: 1_000_000 represents 1.0.
pub const WEIGHT_SCALE: u32 = 1_000_000;

/// Computational cell roles inspired by neural and glial cell classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellKind {
    /// General-purpose computational neuron.
    Neuron,
    /// Input-encoding neuron role.
    SensoryNeuron,
    /// Internal circuit coordination role.
    Interneuron,
    /// Output-projection role; not an execution permission.
    MotorNeuron,
    /// Long-range integration role.
    PyramidalNeuron,
    /// Inhibitory or constraint-regulation role.
    InhibitoryInterneuron,
    /// Resource and local-state regulation analogy.
    AstrocyteLike,
    /// Communication-efficiency support analogy.
    OligodendrocyteLike,
    /// Integrity and anomaly-monitoring analogy.
    MicrogliaLike,
    /// Controlled module-development research role.
    NeuralProgenitorLike,
}

/// Functional computational regions; these are not anatomical claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrainRegion {
    /// Executive planning and task coordination.
    ExecutiveControl,
    /// Language and semantic processing.
    LanguageSemantic,
    /// Spatial, numerical and relational processing.
    SpatialRelational,
    /// Visual feature processing.
    VisualProcessing,
    /// Audio and speech feature processing.
    AuditoryProcessing,
    /// Memory-domain interface; G05 retains authority.
    MemoryInterface,
    /// Selective information routing.
    InformationRouting,
    /// Action proposal selection; G02/G09 retain authority.
    ActionSelection,
    /// Prediction and error-calibration support.
    PredictionCalibration,
    /// Resource and integrity-state monitoring.
    HomeostaticMonitoring,
}

/// Lifecycle status for a proposed computational cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatus {
    /// Defined but not validated for use.
    Proposed,
    /// Passed local structural validation only.
    StructurallyVerified,
    /// Isolated because validation or integrity failed.
    Quarantined,
}

/// A single computational cell descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationalCell {
    /// Stable identifier unique within its network.
    pub cell_id: String,
    /// Computational role.
    pub kind: CellKind,
    /// Functional region.
    pub region: BrainRegion,
    /// Local structural status, not runtime activation.
    pub status: CellStatus,
    /// Version of the cell contract.
    pub contract_version: String,
}

/// Plasticity policy for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasticityPolicy {
    /// Connection weights cannot be changed by this runtime.
    Frozen,
    /// Weight changes may be evaluated in isolated experiments only.
    IsolatedEvaluationOnly,
    /// A future G10-authorized learning integration is required.
    RequiresG10Authorization,
}

/// A directed connection between two computational cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Synapse {
    /// Unique identifier within the network.
    pub synapse_id: String,
    /// Source cell identifier.
    pub source_cell_id: String,
    /// Destination cell identifier.
    pub destination_cell_id: String,
    /// Weight in millionths, constrained to 0..=1_000_000.
    pub weight_micros: u32,
    /// Learning/update boundary.
    pub plasticity: PlasticityPolicy,
}

/// Neural topology organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTopology {
    /// Feed-forward directed acyclic topology.
    FeedForward,
    /// Recurrent topology; cycles are permitted but endpoints remain validated.
    Recurrent,
    /// Graph topology with explicit directed connections.
    DirectedGraph,
}

/// A bounded, synthetic neural-network descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeuralNetwork {
    /// Stable network identifier.
    pub network_id: String,
    /// Network topology declaration.
    pub topology: NetworkTopology,
    /// Computational cells.
    pub cells: Vec<ComputationalCell>,
    /// Directed synaptic connections.
    pub synapses: Vec<Synapse>,
}

impl NeuralNetwork {
    /// Validate identifiers, bounds, endpoints and fixed-point weights.
    ///
    /// This checks topology only; it does not execute a neural network.
    pub fn validate(&self) -> Result<(), NeurogeneticError> {
        if self.network_id.trim().is_empty() {
            return Err(NeurogeneticError::MissingIdentifier);
        }
        if self.cells.is_empty() || self.cells.len() > MAX_CELLS {
            return Err(NeurogeneticError::CellLimitExceeded);
        }
        if self.synapses.len() > MAX_SYNAPSES {
            return Err(NeurogeneticError::SynapseLimitExceeded);
        }

        let mut cell_ids = HashSet::with_capacity(self.cells.len());
        for cell in &self.cells {
            if cell.cell_id.trim().is_empty()
                || cell.contract_version != NEUROGENETIC_CONTRACT_VERSION
            {
                return Err(NeurogeneticError::InvalidCell);
            }
            if !cell_ids.insert(cell.cell_id.as_str()) {
                return Err(NeurogeneticError::DuplicateCell);
            }
        }

        let mut synapse_ids = HashSet::with_capacity(self.synapses.len());
        let mut edges = HashSet::with_capacity(self.synapses.len());
        for synapse in &self.synapses {
            if synapse.synapse_id.trim().is_empty()
                || synapse.source_cell_id.trim().is_empty()
                || synapse.destination_cell_id.trim().is_empty()
            {
                return Err(NeurogeneticError::InvalidSynapse);
            }
            if synapse.weight_micros > WEIGHT_SCALE {
                return Err(NeurogeneticError::InvalidWeight);
            }
            if !cell_ids.contains(synapse.source_cell_id.as_str())
                || !cell_ids.contains(synapse.destination_cell_id.as_str())
            {
                return Err(NeurogeneticError::DanglingSynapse);
            }
            if !synapse_ids.insert(synapse.synapse_id.as_str()) {
                return Err(NeurogeneticError::DuplicateSynapse);
            }
            if !edges.insert((
                synapse.source_cell_id.as_str(),
                synapse.destination_cell_id.as_str(),
            )) {
                return Err(NeurogeneticError::DuplicateEdge);
            }
        }

        if self.topology == NetworkTopology::FeedForward
            && contains_cycle(&self.cells, &self.synapses)
        {
            return Err(NeurogeneticError::CycleInFeedForwardNetwork);
        }
        Ok(())
    }
}

/// Detect a directed cycle without recursion or unbounded call-stack growth.
fn contains_cycle(cells: &[ComputationalCell], synapses: &[Synapse]) -> bool {
    let mut indegree = std::collections::HashMap::<&str, usize>::with_capacity(cells.len());
    let mut outgoing = std::collections::HashMap::<&str, Vec<&str>>::with_capacity(cells.len());
    for cell in cells {
        indegree.insert(cell.cell_id.as_str(), 0);
        outgoing.insert(cell.cell_id.as_str(), Vec::new());
    }
    for edge in synapses {
        *indegree
            .entry(edge.destination_cell_id.as_str())
            .or_default() += 1;
        outgoing
            .entry(edge.source_cell_id.as_str())
            .or_default()
            .push(edge.destination_cell_id.as_str());
    }
    let mut ready = std::collections::VecDeque::new();
    for (cell, degree) in &indegree {
        if *degree == 0 {
            ready.push_back(*cell);
        }
    }
    let mut visited = 0usize;
    while let Some(cell) = ready.pop_front() {
        visited += 1;
        if let Some(destinations) = outgoing.get(cell) {
            for destination in destinations {
                if let Some(degree) = indegree.get_mut(destination) {
                    *degree -= 1;
                    if *degree == 0 {
                        ready.push_back(destination);
                    }
                }
            }
        }
    }
    visited != cells.len()
}

/// Memory classes recognized by the G03 request interface; G05 owns memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    /// Information held during the current bounded task.
    Working,
    /// Event/experience memory, subject to G05 consent.
    Episodic,
    /// Validated concepts and facts.
    Semantic,
    /// Skill and method references.
    Procedural,
    /// Approved future-intention references.
    Prospective,
    /// Verified IROKA history references.
    Autobiographical,
    /// Quality and learning-evaluation references.
    Metacognitive,
}

/// A content-free request to a future G05 memory adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryAccessProposal {
    /// Correlation identifier.
    pub request_id: String,
    /// Requested memory class.
    pub memory_class: MemoryClass,
    /// Opaque source/query reference; no memory content is embedded.
    pub opaque_reference: String,
    /// Declared processing purpose.
    pub purpose: String,
    /// G05-issued consent/authorization receipt reference, if applicable.
    pub g05_authority_receipt_ref: Option<String>,
}

impl MemoryAccessProposal {
    /// Validate the content-free request envelope.
    pub fn validate(&self) -> Result<(), NeurogeneticError> {
        if self.request_id.trim().is_empty()
            || self.opaque_reference.trim().is_empty()
            || self.purpose.trim().is_empty()
        {
            return Err(NeurogeneticError::InvalidMemoryProposal);
        }
        Ok(())
    }
}

/// Learning approaches supported as proposal metadata, not live training.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningMode {
    /// Learning from verified labeled examples.
    Supervised,
    /// Representation learning from unlabeled data.
    SelfSupervised,
    /// Policy optimization under an approved evaluation design.
    Reinforcement,
    /// Learning across successive tasks.
    Continual,
    /// Reuse of validated representations across tasks.
    Transfer,
    /// Improving the learning procedure itself.
    MetaLearning,
    /// Selecting informative examples for review.
    Active,
    /// Learning by contrasting related examples.
    Contrastive,
    /// Progressive task-complexity scheduling.
    Curriculum,
    /// Distributed learning with privacy-preserving boundaries.
    Federated,
}

/// Lifecycle state for a learning proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Awaiting domain review.
    Proposed,
    /// Rejected by the authorized review process.
    Rejected,
    /// Accepted for isolated evaluation only.
    EvaluationAuthorized,
    /// Evaluation completed; no activation implied.
    Evaluated,
}

/// A training/evaluation proposal; it cannot train or activate a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningProposal {
    /// Stable proposal identifier.
    pub proposal_id: String,
    /// Learning approach.
    pub mode: LearningMode,
    /// Opaque target model reference.
    pub target_model_ref: String,
    /// Opaque dataset reference governed by its owning data authority.
    pub dataset_ref: String,
    /// Evidence references supporting the proposal.
    pub evidence_refs: Vec<String>,
    /// Required G10 evaluation authority reference.
    pub g10_authority_ref: Option<String>,
    /// Proposal lifecycle state.
    pub status: ProposalStatus,
    /// Must remain true until separately approved by the Owner where required.
    pub owner_approval_required: bool,
    /// Always false in this contract; activation belongs to a separate gate.
    pub activation_permitted: bool,
}

impl LearningProposal {
    /// Validate references and fail-closed activation fields.
    pub fn validate(&self) -> Result<(), NeurogeneticError> {
        if self.proposal_id.trim().is_empty()
            || self.target_model_ref.trim().is_empty()
            || self.dataset_ref.trim().is_empty()
        {
            return Err(NeurogeneticError::InvalidLearningProposal);
        }
        if !self.owner_approval_required || self.activation_permitted {
            return Err(NeurogeneticError::GovernanceBoundaryViolation);
        }
        if matches!(
            self.status,
            ProposalStatus::EvaluationAuthorized | ProposalStatus::Evaluated
        ) && self
            .g10_authority_ref
            .as_deref()
            .map_or(true, |reference| reference.trim().is_empty())
        {
            return Err(NeurogeneticError::InvalidLearningProposal);
        }
        Ok(())
    }
}

/// Adaptation categories available for proposal and evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptationKind {
    /// Select a different bounded reasoning strategy.
    CognitiveStrategy,
    /// Propose a routing adjustment.
    InformationRouting,
    /// Propose a resource-budget adjustment.
    ResourceAllocation,
    /// Propose a retrieval strategy adjustment.
    RetrievalStrategy,
    /// Propose a model-selection policy change.
    ModelSelection,
    /// Propose a structural/module change.
    StructuralVariation,
    /// Propose a stability or recovery response.
    HomeostaticResponse,
}

/// A non-executable adaptation proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptationProposal {
    /// Stable proposal identifier.
    pub proposal_id: String,
    /// Proposed adaptation category.
    pub kind: AdaptationKind,
    /// Opaque target reference.
    pub target_ref: String,
    /// Bounded rationale.
    pub rationale: String,
    /// Supporting evidence references.
    pub evidence_refs: Vec<String>,
    /// Required approval boundary.
    pub owner_approval_required: bool,
    /// Must remain false until separately authorized and verified.
    pub applied: bool,
    /// Adaptation never creates an execution grant.
    pub execution_authorized: bool,
}

impl AdaptationProposal {
    /// Validate proposal completeness and non-executable governance state.
    pub fn validate(&self) -> Result<(), NeurogeneticError> {
        if self.proposal_id.trim().is_empty()
            || self.target_ref.trim().is_empty()
            || self.rationale.trim().is_empty()
        {
            return Err(NeurogeneticError::InvalidAdaptationProposal);
        }
        if !self.owner_approval_required || self.applied || self.execution_authorized {
            return Err(NeurogeneticError::GovernanceBoundaryViolation);
        }
        Ok(())
    }
}

/// Explicit boundaries for the first synthetic neurogenetic increment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceBoundary {
    /// Durable memory writes are not permitted.
    pub memory_write_permitted: bool,
    /// Model training is not permitted.
    pub model_training_permitted: bool,
    /// Runtime neural-weight mutation is not permitted.
    pub weight_mutation_permitted: bool,
    /// Autonomous adaptation is not permitted.
    pub autonomous_adaptation_permitted: bool,
    /// Protected execution is not permitted.
    pub protected_execution_permitted: bool,
    /// Canonical genome mutation is not permitted.
    pub canonical_genome_mutation_permitted: bool,
}

impl Default for GovernanceBoundary {
    fn default() -> Self {
        Self {
            memory_write_permitted: false,
            model_training_permitted: false,
            weight_mutation_permitted: false,
            autonomous_adaptation_permitted: false,
            protected_execution_permitted: false,
            canonical_genome_mutation_permitted: false,
        }
    }
}

/// Stable validation errors for neurogenetic structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeurogeneticError {
    /// Required identifier is empty.
    MissingIdentifier,
    /// Cell count is empty or exceeds the configured bound.
    CellLimitExceeded,
    /// Synapse count exceeds the configured bound.
    SynapseLimitExceeded,
    /// A cell descriptor is malformed or has an unsupported contract version.
    InvalidCell,
    /// A cell identifier is repeated.
    DuplicateCell,
    /// A synapse descriptor is malformed.
    InvalidSynapse,
    /// A synaptic weight exceeds the fixed-point scale.
    InvalidWeight,
    /// A synapse endpoint does not exist in the network.
    DanglingSynapse,
    /// A synapse identifier is repeated.
    DuplicateSynapse,
    /// A directed edge is repeated.
    DuplicateEdge,
    /// A feed-forward network contains a directed cycle.
    CycleInFeedForwardNetwork,
    /// A memory proposal is incomplete.
    InvalidMemoryProposal,
    /// A learning proposal is incomplete.
    InvalidLearningProposal,
    /// An adaptation proposal is incomplete.
    InvalidAdaptationProposal,
    /// A proposal attempts to bypass a required authority or activation gate.
    GovernanceBoundaryViolation,
    /// Evaluation is currently defined only for feed-forward networks.
    UnsupportedEvaluationTopology,
    /// A quarantined cell cannot participate in an evaluation.
    QuarantinedCell,
    /// An input value is outside the supported signed fixed-point range.
    InputOutOfRange,
    /// An input references a cell that is not in the network.
    UnknownInputCell,
    /// Inputs may be assigned only to zero-in-degree root cells.
    InputForNonRootCell,
    /// A root cell has no caller-supplied input.
    MissingRootInput,
    /// More than one input was supplied for a cell.
    DuplicateInput,
    /// The validated graph could not be evaluated in topological order.
    EvaluationOrderViolation,
    /// A circuit descriptor is incomplete or incompatible.
    InvalidCircuit,
    /// Circuit identity references a different network.
    CircuitNetworkMismatch,
    /// A circuit input identifier is repeated.
    DuplicateCircuitInput,
    /// Circuit inputs do not exactly match the network's root cells.
    CircuitInputMismatch,
    /// A circuit output identifier is repeated.
    DuplicateCircuitOutput,
}


/// A named functional circuit composed over one validated feed-forward network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeuralCircuit {
    /// Stable circuit identifier.
    pub circuit_id: String,
    /// Contract version for this circuit descriptor.
    pub contract_version: String,
    /// Functional region primarily served by this circuit.
    pub region: BrainRegion,
    /// Network identifier to which this circuit is bound.
    pub network_id: String,
    /// All zero-in-degree cells exposed as circuit inputs.
    pub input_cell_ids: Vec<String>,
    /// Cells exposed as circuit outputs, in declared interface order.
    pub output_cell_ids: Vec<String>,
}

/// Result of evaluating a named circuit; only declared outputs are exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitEvaluation {
    /// Evaluated circuit identifier.
    pub circuit_id: String,
    /// Underlying network identifier.
    pub network_id: String,
    /// Output activations in the circuit's declared output order.
    pub outputs: Vec<CellActivation>,
}

impl NeuralCircuit {
    /// Validate circuit identity, network binding and exact root/output interfaces.
    pub fn validate(&self, network: &NeuralNetwork) -> Result<(), NeurogeneticError> {
        if self.circuit_id.trim().is_empty()
            || self.contract_version != NEUROGENETIC_CONTRACT_VERSION
            || self.input_cell_ids.is_empty()
            || self.output_cell_ids.is_empty()
        {
            return Err(NeurogeneticError::InvalidCircuit);
        }
        if self.network_id != network.network_id {
            return Err(NeurogeneticError::CircuitNetworkMismatch);
        }
        network.validate()?;

        let cell_ids: HashSet<&str> = network.cells.iter()
            .map(|cell| cell.cell_id.as_str())
            .collect();
        let mut indegree = std::collections::HashMap::<&str, usize>::with_capacity(network.cells.len());
        for cell in &network.cells {
            indegree.insert(cell.cell_id.as_str(), 0);
        }
        for synapse in &network.synapses {
            *indegree.entry(synapse.destination_cell_id.as_str()).or_default() += 1;
        }

        let mut declared_inputs = HashSet::with_capacity(self.input_cell_ids.len());
        for input in &self.input_cell_ids {
            if !declared_inputs.insert(input.as_str()) {
                return Err(NeurogeneticError::DuplicateCircuitInput);
            }
            match indegree.get(input.as_str()) {
                Some(0) => {}
                Some(_) => return Err(NeurogeneticError::CircuitInputMismatch),
                None => return Err(NeurogeneticError::InvalidCircuit),
            }
        }
        let actual_roots: HashSet<&str> = indegree.iter()
            .filter_map(|(cell_id, degree)| if *degree == 0 { Some(*cell_id) } else { None })
            .collect();
        if actual_roots != declared_inputs {
            return Err(NeurogeneticError::CircuitInputMismatch);
        }

        let mut declared_outputs = HashSet::with_capacity(self.output_cell_ids.len());
        for output in &self.output_cell_ids {
            if !declared_outputs.insert(output.as_str()) {
                return Err(NeurogeneticError::DuplicateCircuitOutput);
            }
            if !cell_ids.contains(output.as_str()) {
                return Err(NeurogeneticError::InvalidCircuit);
            }
        }
        Ok(())
    }

    /// Evaluate the bound network and expose only the circuit's declared outputs.
    pub fn evaluate(
        &self,
        network: &NeuralNetwork,
        inputs: &[CellInput],
    ) -> Result<CircuitEvaluation, NeurogeneticError> {
        self.validate(network)?;
        let evaluation = network.evaluate_feed_forward(inputs)?;
        let values: std::collections::HashMap<&str, i32> = evaluation.activations.iter()
            .map(|activation| (activation.cell_id.as_str(), activation.value_micros))
            .collect();
        let mut outputs = Vec::with_capacity(self.output_cell_ids.len());
        for cell_id in &self.output_cell_ids {
            let value_micros = *values.get(cell_id.as_str())
                .ok_or(NeurogeneticError::EvaluationOrderViolation)?;
            outputs.push(CellActivation {
                cell_id: cell_id.clone(),
                value_micros,
            });
        }
        Ok(CircuitEvaluation {
            circuit_id: self.circuit_id.clone(),
            network_id: self.network_id.clone(),
            outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(id: &str) -> ComputationalCell {
        ComputationalCell {
            cell_id: id.to_owned(),
            kind: CellKind::Neuron,
            region: BrainRegion::ExecutiveControl,
            status: CellStatus::Proposed,
            contract_version: NEUROGENETIC_CONTRACT_VERSION.to_owned(),
        }
    }

    fn edge(id: &str, source: &str, destination: &str) -> Synapse {
        Synapse {
            synapse_id: id.to_owned(),
            source_cell_id: source.to_owned(),
            destination_cell_id: destination.to_owned(),
            weight_micros: 500_000,
            plasticity: PlasticityPolicy::Frozen,
        }
    }

    #[test]
    fn validates_bounded_feed_forward_network() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::FeedForward,
            cells: vec![cell("input"), cell("hidden"), cell("output")],
            synapses: vec![
                edge("s1", "input", "hidden"),
                edge("s2", "hidden", "output"),
            ],
        };
        assert_eq!(network.validate(), Ok(()));
    }

    #[test]
    fn rejects_dangling_synapse_endpoint() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::DirectedGraph,
            cells: vec![cell("input")],
            synapses: vec![edge("s1", "input", "missing")],
        };
        assert_eq!(network.validate(), Err(NeurogeneticError::DanglingSynapse));
    }

    #[test]
    fn rejects_duplicate_cell_identity() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::DirectedGraph,
            cells: vec![cell("same"), cell("same")],
            synapses: Vec::new(),
        };
        assert_eq!(network.validate(), Err(NeurogeneticError::DuplicateCell));
    }

    #[test]
    fn rejects_out_of_range_fixed_point_weight() {
        let mut invalid = edge("s1", "a", "b");
        invalid.weight_micros = WEIGHT_SCALE + 1;
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::DirectedGraph,
            cells: vec![cell("a"), cell("b")],
            synapses: vec![invalid],
        };
        assert_eq!(network.validate(), Err(NeurogeneticError::InvalidWeight));
    }

    #[test]
    fn rejects_cycle_in_feed_forward_network() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::FeedForward,
            cells: vec![cell("a"), cell("b")],
            synapses: vec![edge("s1", "a", "b"), edge("s2", "b", "a")],
        };
        assert_eq!(
            network.validate(),
            Err(NeurogeneticError::CycleInFeedForwardNetwork)
        );
    }

    #[test]
    fn accepts_cycles_only_when_recurrent_topology_is_declared() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::Recurrent,
            cells: vec![cell("a"), cell("b")],
            synapses: vec![edge("s1", "a", "b"), edge("s2", "b", "a")],
        };
        assert_eq!(network.validate(), Ok(()));
    }

    #[test]
    fn memory_proposal_is_content_free_and_validated() {
        let proposal = MemoryAccessProposal {
            request_id: "request-1".to_owned(),
            memory_class: MemoryClass::Episodic,
            opaque_reference: "opaque-memory-ref".to_owned(),
            purpose: "bounded-task-context".to_owned(),
            g05_authority_receipt_ref: None,
        };
        assert_eq!(proposal.validate(), Ok(()));
    }

    #[test]
    fn learning_proposal_cannot_disable_owner_approval_or_activate() {
        let mut proposal = LearningProposal {
            proposal_id: "learning-1".to_owned(),
            mode: LearningMode::Continual,
            target_model_ref: "model:synthetic".to_owned(),
            dataset_ref: "dataset:synthetic".to_owned(),
            evidence_refs: vec!["evidence:1".to_owned()],
            g10_authority_ref: None,
            status: ProposalStatus::Proposed,
            owner_approval_required: true,
            activation_permitted: false,
        };
        assert_eq!(proposal.validate(), Ok(()));
        proposal.activation_permitted = true;
        assert_eq!(
            proposal.validate(),
            Err(NeurogeneticError::GovernanceBoundaryViolation)
        );
    }

    #[test]
    fn adaptation_proposal_cannot_apply_or_authorize_execution() {
        let mut proposal = AdaptationProposal {
            proposal_id: "adaptation-1".to_owned(),
            kind: AdaptationKind::CognitiveStrategy,
            target_ref: "strategy:synthetic".to_owned(),
            rationale: "synthetic evaluation only".to_owned(),
            evidence_refs: vec!["evidence:1".to_owned()],
            owner_approval_required: true,
            applied: false,
            execution_authorized: false,
        };
        assert_eq!(proposal.validate(), Ok(()));
        proposal.execution_authorized = true;
        assert_eq!(proposal.validate(), Err(NeurogeneticError::GovernanceBoundaryViolation));
    }

    #[test]
    fn default_governance_boundary_denies_all_side_effects() {
        assert_eq!(
            GovernanceBoundary::default(),
            GovernanceBoundary {
                memory_write_permitted: false,
                model_training_permitted: false,
                weight_mutation_permitted: false,
                autonomous_adaptation_permitted: false,
                protected_execution_permitted: false,
                canonical_genome_mutation_permitted: false,
            }
        );
    }
    #[test]
    fn rejects_duplicate_synapse_identity() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::DirectedGraph,
            cells: vec![cell("a"), cell("b"), cell("c")],
            synapses: vec![edge("same", "a", "b"), edge("same", "b", "c")],
        };
        assert_eq!(network.validate(), Err(NeurogeneticError::DuplicateSynapse));
    }

    #[test]
    fn rejects_duplicate_directed_edge() {
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::DirectedGraph,
            cells: vec![cell("a"), cell("b")],
            synapses: vec![edge("s1", "a", "b"), edge("s2", "a", "b")],
        };
        assert_eq!(network.validate(), Err(NeurogeneticError::DuplicateEdge));
    }

    #[test]
    fn evaluation_state_requires_g10_authority_reference() {
        let proposal = LearningProposal {
            proposal_id: "learning-2".to_owned(),
            mode: LearningMode::Supervised,
            target_model_ref: "model:synthetic".to_owned(),
            dataset_ref: "dataset:synthetic".to_owned(),
            evidence_refs: vec!["evidence:1".to_owned()],
            g10_authority_ref: None,
            status: ProposalStatus::EvaluationAuthorized,
            owner_approval_required: true,
            activation_permitted: false,
        };
        assert_eq!(
            proposal.validate(),
            Err(NeurogeneticError::InvalidLearningProposal)
        );
    }

    #[test]
    fn rejects_incomplete_memory_proposal() {
        let proposal = MemoryAccessProposal {
            request_id: "request-1".to_owned(),
            memory_class: MemoryClass::Semantic,
            opaque_reference: String::new(),
            purpose: "knowledge retrieval".to_owned(),
            g05_authority_receipt_ref: None,
        };
        assert_eq!(
            proposal.validate(),
            Err(NeurogeneticError::InvalidMemoryProposal)
        );
    }

    #[test]
    fn rejects_unsupported_cell_contract_version() {
        let mut invalid = cell("cell-1");
        invalid.contract_version = "99.0.0".to_owned();
        let network = NeuralNetwork {
            network_id: "synthetic-network".to_owned(),
            topology: NetworkTopology::DirectedGraph,
            cells: vec![invalid],
            synapses: Vec::new(),
        };
        assert_eq!(network.validate(), Err(NeurogeneticError::InvalidCell));
    }


    fn feed_forward_fixture() -> NeuralNetwork {
        NeuralNetwork {
            network_id: "fixed-point-fixture".to_owned(),
            topology: NetworkTopology::FeedForward,
            cells: vec![cell("input"), cell("hidden"), cell("output")],
            synapses: vec![
                Synapse {
                    synapse_id: "s1".to_owned(),
                    source_cell_id: "input".to_owned(),
                    destination_cell_id: "hidden".to_owned(),
                    weight_micros: 500_000,
                    plasticity: PlasticityPolicy::Frozen,
                },
                Synapse {
                    synapse_id: "s2".to_owned(),
                    source_cell_id: "hidden".to_owned(),
                    destination_cell_id: "output".to_owned(),
                    weight_micros: 1_000_000,
                    plasticity: PlasticityPolicy::Frozen,
                },
            ],
        }
    }

    #[test]
    fn feed_forward_evaluation_is_deterministic_and_fixed_point() {
        let network = feed_forward_fixture();
        let input = [CellInput {
            cell_id: "input".to_owned(),
            value_micros: 800_000,
        }];
        let first = network.evaluate_feed_forward(&input).unwrap();
        let second = network.evaluate_feed_forward(&input).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.network_id, "fixed-point-fixture");
        assert_eq!(
            first.activations,
            vec![
                CellActivation { cell_id: "hidden".to_owned(), value_micros: 400_000 },
                CellActivation { cell_id: "input".to_owned(), value_micros: 800_000 },
                CellActivation { cell_id: "output".to_owned(), value_micros: 400_000 },
            ]
        );
    }

    #[test]
    fn feed_forward_evaluation_clamps_weighted_sum_to_fixed_point_range() {
        let mut network = feed_forward_fixture();
        network.synapses[0].weight_micros = WEIGHT_SCALE;
        network.synapses[1].weight_micros = WEIGHT_SCALE;
        let result = network.evaluate_feed_forward(&[CellInput {
            cell_id: "input".to_owned(),
            value_micros: WEIGHT_SCALE as i32,
        }]).unwrap();
        assert_eq!(result.activations.iter().find(|item| item.cell_id == "output").unwrap().value_micros, WEIGHT_SCALE as i32);
    }

    #[test]
    fn feed_forward_evaluation_rejects_missing_root_input() {
        assert_eq!(
            feed_forward_fixture().evaluate_feed_forward(&[]),
            Err(NeurogeneticError::MissingRootInput)
        );
    }

    #[test]
    fn feed_forward_evaluation_rejects_unknown_and_non_root_inputs() {
        let network = feed_forward_fixture();
        assert_eq!(
            network.evaluate_feed_forward(&[CellInput { cell_id: "unknown".to_owned(), value_micros: 0 }]),
            Err(NeurogeneticError::UnknownInputCell)
        );
        assert_eq!(
            network.evaluate_feed_forward(&[
                CellInput { cell_id: "input".to_owned(), value_micros: 0 },
                CellInput { cell_id: "hidden".to_owned(), value_micros: 0 },
            ]),
            Err(NeurogeneticError::InputForNonRootCell)
        );
    }

    #[test]
    fn feed_forward_evaluation_rejects_duplicate_and_out_of_range_inputs() {
        let network = feed_forward_fixture();
        let duplicate = [
            CellInput { cell_id: "input".to_owned(), value_micros: 0 },
            CellInput { cell_id: "input".to_owned(), value_micros: 1 },
        ];
        assert_eq!(network.evaluate_feed_forward(&duplicate), Err(NeurogeneticError::DuplicateInput));
        assert_eq!(
            network.evaluate_feed_forward(&[CellInput {
                cell_id: "input".to_owned(),
                value_micros: WEIGHT_SCALE as i32 + 1,
            }]),
            Err(NeurogeneticError::InputOutOfRange)
        );
    }

    #[test]
    fn feed_forward_evaluation_rejects_recurrent_topology_and_quarantined_cells() {
        let mut recurrent = feed_forward_fixture();
        recurrent.topology = NetworkTopology::Recurrent;
        assert_eq!(
            recurrent.evaluate_feed_forward(&[CellInput { cell_id: "input".to_owned(), value_micros: 0 }]),
            Err(NeurogeneticError::UnsupportedEvaluationTopology)
        );

        let mut quarantined = feed_forward_fixture();
        quarantined.cells[1].status = CellStatus::Quarantined;
        assert_eq!(
            quarantined.evaluate_feed_forward(&[CellInput { cell_id: "input".to_owned(), value_micros: 0 }]),
            Err(NeurogeneticError::QuarantinedCell)
        );
    }

    #[test]
    fn negative_inputs_are_supported_without_floating_point_arithmetic() {
        let result = feed_forward_fixture().evaluate_feed_forward(&[CellInput {
            cell_id: "input".to_owned(),
            value_micros: -800_001,
        }]).unwrap();
        assert_eq!(
            result.activations.iter().find(|item| item.cell_id == "hidden").unwrap().value_micros,
            -400_000
        );
    }

    #[test]
    fn circuit_validates_interfaces_and_exposes_only_declared_outputs() {
        let network = feed_forward_fixture();
        let circuit = NeuralCircuit {
            circuit_id: "language-circuit".to_owned(),
            contract_version: NEUROGENETIC_CONTRACT_VERSION.to_owned(),
            region: BrainRegion::LanguageSemantic,
            network_id: network.network_id.clone(),
            input_cell_ids: vec!["input".to_owned()],
            output_cell_ids: vec!["output".to_owned()],
        };
        let result = circuit.evaluate(&network, &[CellInput {
            cell_id: "input".to_owned(),
            value_micros: 600_000,
        }]).unwrap();
        assert_eq!(result.circuit_id, "language-circuit");
        assert_eq!(result.outputs, vec![CellActivation {
            cell_id: "output".to_owned(),
            value_micros: 300_000,
        }]);
    }

    #[test]
    fn circuit_rejects_missing_root_and_duplicate_interface_ids() {
        let network = feed_forward_fixture();
        let mut circuit = NeuralCircuit {
            circuit_id: "circuit-1".to_owned(),
            contract_version: NEUROGENETIC_CONTRACT_VERSION.to_owned(),
            region: BrainRegion::ExecutiveControl,
            network_id: network.network_id.clone(),
            input_cell_ids: vec!["input".to_owned(), "hidden".to_owned()],
            output_cell_ids: vec!["output".to_owned()],
        };
        assert_eq!(circuit.validate(&network), Err(NeurogeneticError::CircuitInputMismatch));
        circuit.input_cell_ids = vec!["input".to_owned()];
        circuit.output_cell_ids = vec!["output".to_owned(), "output".to_owned()];
        assert_eq!(circuit.validate(&network), Err(NeurogeneticError::DuplicateCircuitOutput));
    }

    #[test]
    fn circuit_rejects_wrong_network_and_unknown_outputs() {
        let network = feed_forward_fixture();
        let mut circuit = NeuralCircuit {
            circuit_id: "circuit-1".to_owned(),
            contract_version: NEUROGENETIC_CONTRACT_VERSION.to_owned(),
            region: BrainRegion::ExecutiveControl,
            network_id: "different-network".to_owned(),
            input_cell_ids: vec!["input".to_owned()],
            output_cell_ids: vec!["output".to_owned()],
        };
        assert_eq!(circuit.validate(&network), Err(NeurogeneticError::CircuitNetworkMismatch));
        circuit.network_id = network.network_id.clone();
        circuit.output_cell_ids = vec!["missing".to_owned()];
        assert_eq!(circuit.validate(&network), Err(NeurogeneticError::InvalidCircuit));
    }

    #[test]
    fn circuit_rejects_unsupported_contract_and_duplicate_inputs() {
        let network = feed_forward_fixture();
        let mut circuit = NeuralCircuit {
            circuit_id: "circuit-1".to_owned(),
            contract_version: "99.0.0".to_owned(),
            region: BrainRegion::ExecutiveControl,
            network_id: network.network_id.clone(),
            input_cell_ids: vec!["input".to_owned()],
            output_cell_ids: vec!["output".to_owned()],
        };
        assert_eq!(circuit.validate(&network), Err(NeurogeneticError::InvalidCircuit));
        circuit.contract_version = NEUROGENETIC_CONTRACT_VERSION.to_owned();
        circuit.input_cell_ids = vec!["input".to_owned(), "input".to_owned()];
        assert_eq!(circuit.validate(&network), Err(NeurogeneticError::DuplicateCircuitInput));
    }

}
