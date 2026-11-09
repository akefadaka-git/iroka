//! Evidence-bound, provider-neutral engineering task planning.
//!
//! Plans are validated proposals. This module never authorizes or executes work.

use std::collections::{BTreeMap, BTreeSet};

use crate::index::RepositoryIndex;

const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannerLimits {
    pub max_steps: usize,
    pub max_evidence: usize,
    pub max_text_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for PlannerLimits {
    fn default() -> Self {
        Self {
            max_steps: 128,
            max_evidence: 256,
            max_text_bytes: 16 * 1024,
            max_total_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSnippet {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub excerpt: String,
}

#[derive(Clone, Debug)]
pub struct PlanningRequest<'a> {
    pub task_id: String,
    pub source_revision: String,
    pub description: String,
    pub repository: &'a RepositoryIndex,
    pub evidence: Vec<EvidenceSnippet>,
    pub constraints: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanAction {
    Inspect,
    Analyze,
    Edit,
    Test,
    Verify,
    RequestApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceReference {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanStep {
    pub id: String,
    pub action: PlanAction,
    pub summary: String,
    pub detail: String,
    pub depends_on: Vec<String>,
    pub target_paths: Vec<String>,
    pub evidence: Vec<EvidenceReference>,
    pub risk: RiskLevel,
    pub required_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub task_id: String,
    pub source_revision: String,
    pub objective: String,
    pub assumptions: Vec<String>,
    pub steps: Vec<PlanStep>,
    pub acceptance_criteria: Vec<String>,
    /// Must remain true for every plan containing a mutating step.
    pub requires_owner_approval: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFailure {
    pub message: String,
}

pub trait PlanningProvider: Send + Sync {
    fn propose_plan(&self, request: &PlanningRequest<'_>) -> Result<TaskPlan, ProviderFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanValidationError {
    UnsupportedSchema,
    InvalidIdentifier,
    InvalidSourceRevision,
    EmptyDescription,
    EmptyPlan,
    MissingAcceptanceCriteria,
    MissingOwnerApproval,
    LimitExceeded,
    UnsafePath,
    InvalidEvidenceRange,
    EvidenceNotInRepository,
    EvidenceNotSupplied,
    DuplicateStep,
    UnknownDependency,
    DependencyCycle,
    InvalidCapability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannerError {
    InvalidRequest(PlanValidationError),
    Provider(ProviderFailure),
    InvalidPlan(PlanValidationError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTaskPlan {
    plan: TaskPlan,
}

impl ValidatedTaskPlan {
    #[must_use]
    pub fn plan(&self) -> &TaskPlan {
        &self.plan
    }
}

pub struct TaskPlanner {
    limits: PlannerLimits,
}

impl TaskPlanner {
    #[must_use]
    pub fn new(limits: PlannerLimits) -> Self {
        Self { limits }
    }

    pub fn plan(
        &self,
        provider: &dyn PlanningProvider,
        request: &PlanningRequest<'_>,
    ) -> Result<ValidatedTaskPlan, PlannerError> {
        validate_request(request, self.limits).map_err(PlannerError::InvalidRequest)?;
        let plan = provider
            .propose_plan(request)
            .map_err(PlannerError::Provider)?;
        validate_plan(&plan, request, self.limits).map_err(PlannerError::InvalidPlan)?;
        Ok(ValidatedTaskPlan { plan })
    }
}

fn validate_request(
    request: &PlanningRequest<'_>,
    limits: PlannerLimits,
) -> Result<(), PlanValidationError> {
    if !valid_identifier(&request.task_id) {
        return Err(PlanValidationError::InvalidIdentifier);
    }
    if !valid_revision(&request.source_revision) {
        return Err(PlanValidationError::InvalidSourceRevision);
    }
    if request.description.trim().is_empty() {
        return Err(PlanValidationError::EmptyDescription);
    }
    if request.description.len() > limits.max_text_bytes
        || request.evidence.len() > limits.max_evidence
    {
        return Err(PlanValidationError::LimitExceeded);
    }
    if request.evidence.is_empty() {
        return Err(PlanValidationError::EvidenceNotSupplied);
    }
    let known_paths: BTreeSet<_> = request
        .repository
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut total_bytes = request.description.len();
    for evidence in &request.evidence {
        if !safe_relative_path(&evidence.path) {
            return Err(PlanValidationError::UnsafePath);
        }
        if evidence.start_line == 0 || evidence.end_line < evidence.start_line {
            return Err(PlanValidationError::InvalidEvidenceRange);
        }
        if !known_paths.contains(evidence.path.as_str()) {
            return Err(PlanValidationError::EvidenceNotInRepository);
        }
        if evidence.excerpt.trim().is_empty() || evidence.excerpt.len() > limits.max_text_bytes {
            return Err(PlanValidationError::LimitExceeded);
        }
        total_bytes = total_bytes.saturating_add(evidence.excerpt.len());
    }
    for constraint in &request.constraints {
        if constraint.trim().is_empty() || constraint.len() > limits.max_text_bytes {
            return Err(PlanValidationError::LimitExceeded);
        }
        total_bytes = total_bytes.saturating_add(constraint.len());
    }
    if total_bytes > limits.max_total_bytes {
        return Err(PlanValidationError::LimitExceeded);
    }
    Ok(())
}

fn validate_plan(
    plan: &TaskPlan,
    request: &PlanningRequest<'_>,
    limits: PlannerLimits,
) -> Result<(), PlanValidationError> {
    if plan.schema_version != SCHEMA_VERSION {
        return Err(PlanValidationError::UnsupportedSchema);
    }
    if !valid_identifier(&plan.plan_id)
        || plan.task_id != request.task_id
        || plan.source_revision != request.source_revision
    {
        return Err(PlanValidationError::InvalidIdentifier);
    }
    if plan.objective.trim().is_empty() {
        return Err(PlanValidationError::EmptyDescription);
    }
    if plan.steps.is_empty() {
        return Err(PlanValidationError::EmptyPlan);
    }
    if plan.steps.len() > limits.max_steps {
        return Err(PlanValidationError::LimitExceeded);
    }
    if plan.acceptance_criteria.is_empty()
        || plan
            .acceptance_criteria
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(PlanValidationError::MissingAcceptanceCriteria);
    }
    if !plan.requires_owner_approval {
        return Err(PlanValidationError::MissingOwnerApproval);
    }

    let mut total_bytes = plan.objective.len();
    let mut step_ids = BTreeSet::new();
    let mut step_map = BTreeMap::new();
    for step in &plan.steps {
        if !valid_identifier(&step.id) {
            return Err(PlanValidationError::InvalidIdentifier);
        }
        if !step_ids.insert(step.id.as_str()) {
            return Err(PlanValidationError::DuplicateStep);
        }
        total_bytes = total_bytes
            .saturating_add(step.summary.len())
            .saturating_add(step.detail.len());
        if step.summary.trim().is_empty()
            || step.detail.trim().is_empty()
            || step.summary.len() > limits.max_text_bytes
            || step.detail.len() > limits.max_text_bytes
        {
            return Err(PlanValidationError::LimitExceeded);
        }
        if step.action == PlanAction::Edit && step.target_paths.is_empty() {
            return Err(PlanValidationError::UnsafePath);
        }
        let mut targets = BTreeSet::new();
        for target in &step.target_paths {
            total_bytes = total_bytes.saturating_add(target.len());
            if !safe_relative_path(target) || !targets.insert(target.as_str()) {
                return Err(PlanValidationError::UnsafePath);
            }
        }
        for evidence in &step.evidence {
            total_bytes = total_bytes.saturating_add(evidence.path.len());
            if !safe_relative_path(&evidence.path) {
                return Err(PlanValidationError::UnsafePath);
            }
            if evidence.start_line == 0 || evidence.end_line < evidence.start_line {
                return Err(PlanValidationError::InvalidEvidenceRange);
            }
            let supplied = request.evidence.iter().any(|snippet| {
                snippet.path == evidence.path
                    && evidence.start_line >= snippet.start_line
                    && evidence.end_line <= snippet.end_line
            });
            if !supplied {
                return Err(PlanValidationError::EvidenceNotSupplied);
            }
        }
        if step
            .required_capabilities
            .iter()
            .any(|capability| capability.trim().is_empty() || capability.len() > 128)
        {
            return Err(PlanValidationError::InvalidCapability);
        }
        for capability in &step.required_capabilities {
            total_bytes = total_bytes.saturating_add(capability.len());
        }
        step_map.insert(step.id.as_str(), step);
    }

    for step in &plan.steps {
        let mut dependencies = BTreeSet::new();
        for dependency in &step.depends_on {
            if dependency == &step.id || !step_map.contains_key(dependency.as_str()) {
                return Err(PlanValidationError::UnknownDependency);
            }
            if !dependencies.insert(dependency.as_str()) {
                return Err(PlanValidationError::UnknownDependency);
            }
        }
    }
    if !plan.steps.iter().any(|step| !step.evidence.is_empty()) {
        return Err(PlanValidationError::EvidenceNotSupplied);
    }
    if has_dependency_cycle(&plan.steps) {
        return Err(PlanValidationError::DependencyCycle);
    }

    for value in plan.assumptions.iter().chain(&plan.acceptance_criteria) {
        if value.trim().is_empty() || value.len() > limits.max_text_bytes {
            return Err(PlanValidationError::LimitExceeded);
        }
        total_bytes = total_bytes.saturating_add(value.len());
    }
    if total_bytes > limits.max_total_bytes {
        return Err(PlanValidationError::LimitExceeded);
    }
    Ok(())
}

fn has_dependency_cycle(steps: &[PlanStep]) -> bool {
    let mut indegree: BTreeMap<&str, usize> =
        steps.iter().map(|step| (step.id.as_str(), 0)).collect();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for step in steps {
        for dependency in &step.depends_on {
            *indegree
                .get_mut(step.id.as_str())
                .expect("step indexed") += 1;
            children
                .entry(dependency.as_str())
                .or_default()
                .push(step.id.as_str());
        }
    }

    let mut ready: BTreeSet<&str> = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0;
    while let Some(id) = ready.iter().next().copied() {
        ready.remove(id);
        visited += 1;
        if let Some(dependents) = children.get(id) {
            for dependent in dependents {
                let count = indegree.get_mut(dependent).expect("known dependent");
                *count -= 1;
                if *count == 0 {
                    ready.insert(dependent);
                }
            }
        }
    }
    visited != steps.len()
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

pub(crate) fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && !path.bytes().any(|byte| byte.is_ascii_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{FileRecord, FileRole};

    struct FixtureProvider {
        plan: TaskPlan,
    }

    impl PlanningProvider for FixtureProvider {
        fn propose_plan(
            &self,
            _request: &PlanningRequest<'_>,
        ) -> Result<TaskPlan, ProviderFailure> {
            Ok(self.plan.clone())
        }
    }

    fn request<'a>(repository: &'a RepositoryIndex) -> PlanningRequest<'a> {
        PlanningRequest {
            task_id: "task-1".to_owned(),
            source_revision: "a".repeat(40),
            description: "Add a safe feature".to_owned(),
            repository,
            evidence: vec![EvidenceSnippet {
                path: "src/lib.rs".to_owned(),
                start_line: 1,
                end_line: 8,
                excerpt: "pub fn existing() {}".to_owned(),
            }],
            constraints: vec!["Do not execute project scripts".to_owned()],
        }
    }

    fn repository() -> RepositoryIndex {
        RepositoryIndex {
            files: vec![FileRecord {
                path: "src/lib.rs".to_owned(),
                size_bytes: 20,
                role: FileRole::Source,
                languages: Vec::new(),
            }],
            ..RepositoryIndex::default()
        }
    }

    fn plan() -> TaskPlan {
        TaskPlan {
            schema_version: SCHEMA_VERSION.to_owned(),
            plan_id: "plan-1".to_owned(),
            task_id: "task-1".to_owned(),
            source_revision: "a".repeat(40),
            objective: "Add the requested feature".to_owned(),
            assumptions: vec!["The existing module remains authoritative".to_owned()],
            steps: vec![
                PlanStep {
                    id: "inspect".to_owned(),
                    action: PlanAction::Inspect,
                    summary: "Inspect the current module".to_owned(),
                    detail: "Confirm the existing public API".to_owned(),
                    depends_on: Vec::new(),
                    target_paths: vec!["src/lib.rs".to_owned()],
                    evidence: vec![EvidenceReference {
                        path: "src/lib.rs".to_owned(),
                        start_line: 1,
                        end_line: 8,
                    }],
                    risk: RiskLevel::Low,
                    required_capabilities: vec!["repository.read".to_owned()],
                },
                PlanStep {
                    id: "edit".to_owned(),
                    action: PlanAction::Edit,
                    summary: "Propose the source change".to_owned(),
                    detail: "Return a patch for later review".to_owned(),
                    depends_on: vec!["inspect".to_owned()],
                    target_paths: vec!["src/lib.rs".to_owned()],
                    evidence: Vec::new(),
                    risk: RiskLevel::Medium,
                    required_capabilities: vec!["repository.propose_patch".to_owned()],
                },
            ],
            acceptance_criteria: vec!["The patch is testable".to_owned()],
            requires_owner_approval: true,
        }
    }

    #[test]
    fn accepts_evidence_bound_acyclic_plan_from_provider() {
        let repository = repository();
        let request = request(&repository);
        let provider = FixtureProvider { plan: plan() };
        let validated = TaskPlanner::new(PlannerLimits::default())
            .plan(&provider, &request)
            .expect("valid plan");
        assert_eq!(validated.plan().steps.len(), 2);
    }

    #[test]
    fn rejects_dependency_cycles() {
        let repository = repository();
        let request = request(&repository);
        let mut invalid = plan();
        invalid.steps[0].depends_on = vec!["edit".to_owned()];
        let provider = FixtureProvider { plan: invalid };
        assert_eq!(
            TaskPlanner::new(PlannerLimits::default()).plan(&provider, &request),
            Err(PlannerError::InvalidPlan(
                PlanValidationError::DependencyCycle
            ))
        );
    }

    #[test]
    fn rejects_missing_evidence_and_unsafe_target_paths() {
        let repository = repository();
        let request = request(&repository);
        let mut invalid = plan();
        invalid.steps[0].evidence[0].path = "../outside.rs".to_owned();
        let provider = FixtureProvider { plan: invalid };
        assert_eq!(
            TaskPlanner::new(PlannerLimits::default()).plan(&provider, &request),
            Err(PlannerError::InvalidPlan(PlanValidationError::UnsafePath))
        );
    }

    #[test]
    fn rejects_plans_that_remove_owner_approval() {
        let repository = repository();
        let request = request(&repository);
        let mut invalid = plan();
        invalid.requires_owner_approval = false;
        let provider = FixtureProvider { plan: invalid };
        assert_eq!(
            TaskPlanner::new(PlannerLimits::default()).plan(&provider, &request),
            Err(PlannerError::InvalidPlan(
                PlanValidationError::MissingOwnerApproval
            ))
        );
    }

    #[test]
    fn rejects_unpinned_or_unindexed_evidence() {
        let repository = repository();
        let mut request = request(&repository);
        request.evidence[0].path = "outside.rs".to_owned();
        let provider = FixtureProvider { plan: plan() };
        assert_eq!(
            TaskPlanner::new(PlannerLimits::default()).plan(&provider, &request),
            Err(PlannerError::InvalidRequest(
                PlanValidationError::EvidenceNotInRepository
            ))
        );
    }
}
