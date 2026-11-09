//! IROKA BRAIN G03 bounded cognitive core.
//!
//! This crate implements the offline synthetic first increment. It validates
//! versioned task envelopes, applies strict local resource bounds, produces a
//! deterministic plan, invokes only an injected model adapter, critiques the
//! result, and returns an attributable terminal envelope.
//!
//! It deliberately does not authenticate principals, resolve tenants, decide
//! policy, retrieve knowledge, access memory/perception, persist state, delegate
//! agents, invoke tools, or perform protected effects. Those authorities remain
//! with their owning Genome domains and a separately verified composition root.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const TASK_SCHEMA_ID: &str = "iroka.brain.task.v1";
pub const RESULT_SCHEMA_ID: &str = "iroka.brain.result.v1";
pub const CONTRACT_VERSION: &str = "1.0";
pub const FAKE_ADAPTER_ID: &str = "deterministic-fake";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    Answer,
    Research,
    Analysis,
    Planning,
    Engineering,
    Translation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Reasoning,
    EvidenceSynthesis,
    Planning,
    Critique,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDomain {
    User,
    G04,
    G05,
    G06,
    Ciw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputReference {
    pub reference: String,
    pub source_domain: SourceDomain,
    pub classification: Classification,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Objective {
    pub text: String,
    pub success_criteria: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locale {
    pub requested: String,
    #[serde(default)]
    pub fallbacks: Vec<String>,
    pub calendar: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    pub max_input_bytes: usize,
    pub max_output_tokens: usize,
    pub max_iterations: usize,
    pub deadline_at: Option<String>,
    pub allow_external_provider: bool,
    pub allow_persistence: bool,
    pub allow_agent_delegation: bool,
    pub allow_protected_effects: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredEvidence {
    pub citation_required: bool,
    pub minimum_source_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub schema_id: String,
    pub contract_version: String,
    pub task_id: String,
    pub correlation_id: String,
    pub created_at: String,
    pub principal_ref: Option<String>,
    pub tenant_context_ref: Option<String>,
    pub policy_context_ref: Option<String>,
    pub objective: Objective,
    pub task_class: TaskClass,
    pub requested_capabilities: Vec<Capability>,
    #[serde(default)]
    pub input_refs: Vec<InputReference>,
    pub locale: Locale,
    pub constraints: Constraints,
    pub required_evidence: RequiredEvidence,
    pub output_schema_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Completed,
    Partial,
    Abstained,
    Denied,
    Cancelled,
    TimedOut,
    BudgetExhausted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    SourceSupported,
    DeterministicCheck,
    Inference,
    Hypothesis,
    Assumption,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub text: String,
    pub epistemic_status: EpistemicStatus,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub content: String,
    pub locale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAttribution {
    pub adapter_id: String,
    pub model_id: String,
    pub model_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub input_units: usize,
    pub output_units: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Success,
    Abstention,
    PolicyDenial,
    Cancellation,
    Timeout,
    Budget,
    ProviderError,
    ValidationError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    NotVerified,
    DeterministicChecksPassed,
    RequiresIndependentReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    pub status: VerificationStatus,
    pub assurance_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEnvelope {
    pub schema_id: String,
    pub contract_version: String,
    pub task_id: String,
    pub correlation_id: String,
    pub status: ResultStatus,
    pub answer: Option<Answer>,
    pub claims: Vec<Claim>,
    pub assumptions: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub uncertainty: String,
    pub model_attribution: ModelAttribution,
    pub termination: TerminationReason,
    pub resource_usage: ResourceUsage,
    pub verification: Verification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_id: String,
    pub description: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanProposal {
    pub plan_id: String,
    pub task_id: String,
    pub objective: String,
    pub success_criteria: Vec<String>,
    pub steps: Vec<PlanStep>,
    pub assumptions: Vec<String>,
    pub approval_points: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub is_execution_grant: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticRecommendation {
    Revise,
    Abstain,
    Escalate,
    AcceptWithLimitations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticFinding {
    pub severity: String,
    pub category: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticResult {
    pub task_id: String,
    pub recommendation: CriticRecommendation,
    pub findings: Vec<CriticFinding>,
    pub coverage: Vec<String>,
    pub limitations: Vec<String>,
    pub is_independent_assurance: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedSchema,
    UnsupportedVersion,
    MissingIdentifier,
    MissingObjective,
    MissingLocale,
    MissingCapability,
    InvalidBudget,
    InputTooLarge,
    ForbiddenCapabilityFlag,
    InvalidInputReference,
    EvidenceUnavailable,
    OutputTooLarge,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ValidationError {}

impl TaskEnvelope {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_id != TASK_SCHEMA_ID || self.output_schema_id != RESULT_SCHEMA_ID {
            return Err(ValidationError::UnsupportedSchema);
        }
        if self.contract_version != CONTRACT_VERSION {
            return Err(ValidationError::UnsupportedVersion);
        }
        if self.task_id.trim().is_empty()
            || self.correlation_id.trim().is_empty()
            || self.created_at.trim().is_empty()
        {
            return Err(ValidationError::MissingIdentifier);
        }
        if self.objective.text.trim().is_empty()
            || self.objective.success_criteria.is_empty()
            || self
                .objective
                .success_criteria
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(ValidationError::MissingObjective);
        }
        if self.locale.requested.trim().is_empty() {
            return Err(ValidationError::MissingLocale);
        }
        if self.requested_capabilities.is_empty() {
            return Err(ValidationError::MissingCapability);
        }
        let limits = &self.constraints;
        if limits.max_input_bytes == 0
            || limits.max_output_tokens == 0
            || limits.max_iterations == 0
            || limits.max_iterations > 8
        {
            return Err(ValidationError::InvalidBudget);
        }
        if self.objective.text.len() > limits.max_input_bytes {
            return Err(ValidationError::InputTooLarge);
        }
        if limits.allow_external_provider
            || limits.allow_persistence
            || limits.allow_agent_delegation
            || limits.allow_protected_effects
        {
            return Err(ValidationError::ForbiddenCapabilityFlag);
        }
        if self
            .input_refs
            .iter()
            .any(|item| item.reference.trim().is_empty() || item.purpose.trim().is_empty())
        {
            return Err(ValidationError::InvalidInputReference);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelOutput {
    pub content: String,
    pub model_id: String,
    pub model_version: String,
    pub input_units: usize,
    pub output_units: usize,
}

pub trait ModelAdapter {
    fn adapter_id(&self) -> &'static str;
    fn generate(&self, task: &TaskEnvelope) -> Result<ModelOutput, AdapterError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    Unavailable,
    MalformedOutput,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AdapterError {}

/// Deterministic test adapter. It does not contact a model provider or network.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicFakeAdapter;

impl ModelAdapter for DeterministicFakeAdapter {
    fn adapter_id(&self) -> &'static str {
        FAKE_ADAPTER_ID
    }

    fn generate(&self, task: &TaskEnvelope) -> Result<ModelOutput, AdapterError> {
        let content = format!(
            "Synthetic response for task {}: {}",
            task.task_id, task.objective.text
        );
        let output_units = content.split_whitespace().count();
        Ok(ModelOutput {
            content,
            model_id: "fixture".to_owned(),
            model_version: "1".to_owned(),
            input_units: task.objective.text.len(),
            output_units,
        })
    }
}

pub struct CognitiveRuntime<A> {
    adapter: A,
}

impl<A: ModelAdapter> CognitiveRuntime<A> {
    pub fn new(adapter: A) -> Self {
        Self { adapter }
    }

    pub fn run(&self, task: &TaskEnvelope) -> ResultEnvelope {
        if let Err(error) = task.validate() {
            return self.terminal(
                task,
                ResultStatus::Denied,
                TerminationReason::ValidationError,
                error.to_string(),
            );
        }

        let plan = build_plan(task);
        if !validate_plan(&plan) {
            return self.terminal(
                task,
                ResultStatus::Failed,
                TerminationReason::ValidationError,
                "Generated plan failed structural validation".to_owned(),
            );
        }

        let generated = match self.adapter.generate(task) {
            Ok(output) => output,
            Err(_) => {
                return self.terminal(
                    task,
                    ResultStatus::Failed,
                    TerminationReason::ProviderError,
                    "Model adapter unavailable or returned malformed output".to_owned(),
                );
            }
        };

        if generated.content.trim().is_empty()
            || generated.model_id.trim().is_empty()
            || generated.model_version.trim().is_empty()
        {
            return self.terminal(
                task,
                ResultStatus::Failed,
                TerminationReason::ProviderError,
                "Model adapter returned incomplete attribution or empty output".to_owned(),
            );
        }
        if generated.output_units > task.constraints.max_output_tokens {
            return self.terminal(
                task,
                ResultStatus::BudgetExhausted,
                TerminationReason::Budget,
                "Generated output exceeded the configured output budget".to_owned(),
            );
        }

        let critic = critique(task, &generated);
        if task.required_evidence.citation_required
            || task.required_evidence.minimum_source_count > 0
        {
            return self.terminal(
                task,
                ResultStatus::Abstained,
                TerminationReason::Abstention,
                "Required evidence is unavailable in the isolated synthetic increment".to_owned(),
            );
        }

        let status = match critic.recommendation {
            CriticRecommendation::Abstain | CriticRecommendation::Escalate => {
                ResultStatus::Abstained
            }
            CriticRecommendation::Revise => ResultStatus::Partial,
            CriticRecommendation::AcceptWithLimitations => ResultStatus::Completed,
        };
        let termination = if status == ResultStatus::Completed {
            TerminationReason::Success
        } else {
            TerminationReason::Abstention
        };
        let content = if task.locale.requested == "am-ET" {
            format!("የሙከራ ምላሽ፦ {}", generated.content)
        } else {
            generated.content
        };
        let answer = if status == ResultStatus::Abstained {
            None
        } else {
            Some(Answer {
                content,
                locale: task.locale.requested.clone(),
            })
        };
        ResultEnvelope {
            schema_id: RESULT_SCHEMA_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            task_id: task.task_id.clone(),
            correlation_id: task.correlation_id.clone(),
            status,
            answer,
            claims: Vec::new(),
            assumptions: vec!["Synthetic adapter output is not externally verified".to_owned()],
            unresolved_questions: Vec::new(),
            uncertainty: "unavailable".to_owned(),
            model_attribution: ModelAttribution {
                adapter_id: self.adapter.adapter_id().to_owned(),
                model_id: generated.model_id,
                model_version: generated.model_version,
            },
            termination,
            resource_usage: ResourceUsage {
                input_units: generated.input_units,
                output_units: generated.output_units,
                elapsed_ms: 0,
            },
            verification: Verification {
                status: VerificationStatus::NotVerified,
                assurance_ref: None,
            },
        }
    }

    fn terminal(
        &self,
        task: &TaskEnvelope,
        status: ResultStatus,
        termination: TerminationReason,
        reason: String,
    ) -> ResultEnvelope {
        ResultEnvelope {
            schema_id: RESULT_SCHEMA_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            task_id: task.task_id.clone(),
            correlation_id: task.correlation_id.clone(),
            status,
            answer: None,
            claims: Vec::new(),
            assumptions: Vec::new(),
            unresolved_questions: vec![reason],
            uncertainty: "unavailable".to_owned(),
            model_attribution: ModelAttribution {
                adapter_id: self.adapter.adapter_id().to_owned(),
                model_id: "not-invoked".to_owned(),
                model_version: "not-applicable".to_owned(),
            },
            termination,
            resource_usage: ResourceUsage {
                input_units: 0,
                output_units: 0,
                elapsed_ms: 0,
            },
            verification: Verification {
                status: VerificationStatus::NotVerified,
                assurance_ref: None,
            },
        }
    }
}

pub fn build_plan(task: &TaskEnvelope) -> PlanProposal {
    PlanProposal {
        plan_id: format!("plan:{}", task.task_id),
        task_id: task.task_id.clone(),
        objective: task.objective.text.clone(),
        success_criteria: task.objective.success_criteria.clone(),
        steps: vec![PlanStep {
            step_id: "step-001".to_owned(),
            description: "Produce a bounded synthetic response; do not execute external actions"
                .to_owned(),
            depends_on: Vec::new(),
        }],
        assumptions: vec!["No external evidence or domain adapter is available".to_owned()],
        approval_points: vec![
            "Any future protected effect requires the G02/G09 governed path".to_owned(),
        ],
        stop_conditions: vec![
            "Input or output budget exceeded".to_owned(),
            "Required evidence unavailable".to_owned(),
            "Any forbidden capability requested".to_owned(),
        ],
        is_execution_grant: false,
    }
}

pub fn validate_plan(plan: &PlanProposal) -> bool {
    if plan.plan_id.trim().is_empty()
        || plan.task_id.trim().is_empty()
        || plan.objective.trim().is_empty()
        || plan.success_criteria.is_empty()
        || plan.steps.is_empty()
        || plan.is_execution_grant
    {
        return false;
    }
    let mut seen = Vec::new();
    for step in &plan.steps {
        if step.step_id.trim().is_empty()
            || step.description.trim().is_empty()
            || seen.iter().any(|id: &String| id == &step.step_id)
            || step
                .depends_on
                .iter()
                .any(|dependency| !seen.contains(dependency))
        {
            return false;
        }
        seen.push(step.step_id.clone());
    }
    true
}

pub fn critique(task: &TaskEnvelope, output: &ModelOutput) -> CriticResult {
    let mut findings = Vec::new();
    let recommendation = if output.content.trim().is_empty() {
        findings.push(CriticFinding {
            severity: "critical".to_owned(),
            category: "empty_output".to_owned(),
            message: "The adapter returned no user-facing content".to_owned(),
        });
        CriticRecommendation::Abstain
    } else if task.required_evidence.citation_required
        || task.required_evidence.minimum_source_count > 0
    {
        findings.push(CriticFinding {
            severity: "high".to_owned(),
            category: "evidence_missing".to_owned(),
            message: "The synthetic runtime cannot retrieve or validate source evidence".to_owned(),
        });
        CriticRecommendation::Abstain
    } else {
        findings.push(CriticFinding {
            severity: "low".to_owned(),
            category: "synthetic_fixture".to_owned(),
            message: "Output is synthetic and has not been independently verified".to_owned(),
        });
        CriticRecommendation::AcceptWithLimitations
    };
    CriticResult {
        task_id: task.task_id.clone(),
        recommendation,
        findings,
        coverage: vec![
            "schema".to_owned(),
            "budget".to_owned(),
            "evidence_requirement".to_owned(),
        ],
        limitations: vec![
            "Critique is an internal cognitive check, not G11 independent assurance".to_owned(),
        ],
        is_independent_assurance: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> TaskEnvelope {
        TaskEnvelope {
            schema_id: TASK_SCHEMA_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            task_id: "task-001".to_owned(),
            correlation_id: "corr-001".to_owned(),
            created_at: "2026-11-09T00:00:00Z".to_owned(),
            principal_ref: None,
            tenant_context_ref: None,
            policy_context_ref: None,
            objective: Objective {
                text: "Explain the test objective".to_owned(),
                success_criteria: vec!["Return a bounded synthetic answer".to_owned()],
            },
            task_class: TaskClass::Answer,
            requested_capabilities: vec![Capability::Reasoning],
            input_refs: Vec::new(),
            locale: Locale {
                requested: "en".to_owned(),
                fallbacks: vec!["am-ET".to_owned()],
                calendar: None,
                timezone: None,
            },
            constraints: Constraints {
                max_input_bytes: 256,
                max_output_tokens: 64,
                max_iterations: 2,
                deadline_at: None,
                allow_external_provider: false,
                allow_persistence: false,
                allow_agent_delegation: false,
                allow_protected_effects: false,
            },
            required_evidence: RequiredEvidence {
                citation_required: false,
                minimum_source_count: 0,
            },
            output_schema_id: RESULT_SCHEMA_ID.to_owned(),
        }
    }

    #[test]
    fn valid_task_runs_only_through_deterministic_fake_adapter() {
        let result = CognitiveRuntime::new(DeterministicFakeAdapter).run(&task());
        assert_eq!(result.status, ResultStatus::Completed);
        assert_eq!(result.model_attribution.adapter_id, FAKE_ADAPTER_ID);
        assert_eq!(result.model_attribution.model_id, "fixture");
        assert_eq!(result.verification.status, VerificationStatus::NotVerified);
        assert!(result.answer.is_some());
    }

    #[test]
    fn unsupported_schema_is_denied_closed() {
        let mut request = task();
        request.schema_id = "iroka.brain.task.v99".to_owned();
        let result = CognitiveRuntime::new(DeterministicFakeAdapter).run(&request);
        assert_eq!(result.status, ResultStatus::Denied);
        assert_eq!(result.termination, TerminationReason::ValidationError);
        assert!(result.answer.is_none());
    }

    #[test]
    fn unsupported_contract_version_is_rejected() {
        let mut request = task();
        request.contract_version = "2.0".to_owned();
        assert_eq!(request.validate(), Err(ValidationError::UnsupportedVersion));
    }

    #[test]
    fn zero_and_excessive_iteration_budgets_are_rejected() {
        let mut request = task();
        request.constraints.max_iterations = 0;
        assert_eq!(request.validate(), Err(ValidationError::InvalidBudget));
        request.constraints.max_iterations = 9;
        assert_eq!(request.validate(), Err(ValidationError::InvalidBudget));
    }

    #[test]
    fn untrusted_objective_is_bounded_by_bytes() {
        let mut request = task();
        request.constraints.max_input_bytes = 2;
        assert_eq!(request.validate(), Err(ValidationError::InputTooLarge));
    }

    #[test]
    fn external_provider_and_effect_flags_fail_closed() {
        let mut request = task();
        request.constraints.allow_external_provider = true;
        assert_eq!(
            request.validate(),
            Err(ValidationError::ForbiddenCapabilityFlag)
        );
        request.constraints.allow_external_provider = false;
        request.constraints.allow_protected_effects = true;
        assert_eq!(
            request.validate(),
            Err(ValidationError::ForbiddenCapabilityFlag)
        );
    }

    #[test]
    fn required_evidence_causes_abstention_not_fabricated_citations() {
        let mut request = task();
        request.required_evidence.citation_required = true;
        let result = CognitiveRuntime::new(DeterministicFakeAdapter).run(&request);
        assert_eq!(result.status, ResultStatus::Abstained);
        assert!(result.answer.is_none());
        assert!(result.claims.is_empty());
    }

    #[test]
    fn generated_output_cannot_exceed_output_budget() {
        struct Oversized;
        impl ModelAdapter for Oversized {
            fn adapter_id(&self) -> &'static str {
                "oversized-test"
            }
            fn generate(&self, _task: &TaskEnvelope) -> Result<ModelOutput, AdapterError> {
                Ok(ModelOutput {
                    content: "too many words here".to_owned(),
                    model_id: "fixture".to_owned(),
                    model_version: "1".to_owned(),
                    input_units: 1,
                    output_units: 99,
                })
            }
        }
        let result = CognitiveRuntime::new(Oversized).run(&task());
        assert_eq!(result.status, ResultStatus::BudgetExhausted);
        assert_eq!(result.termination, TerminationReason::Budget);
    }

    #[test]
    fn planner_never_grants_execution_authority() {
        let plan = build_plan(&task());
        assert!(validate_plan(&plan));
        assert!(!plan.is_execution_grant);
    }

    #[test]
    fn planner_rejects_duplicate_step_identifiers() {
        let mut plan = build_plan(&task());
        plan.steps.push(plan.steps[0].clone());
        assert!(!validate_plan(&plan));
    }

    #[test]
    fn critic_never_claims_independent_assurance() {
        let request = task();
        let output = DeterministicFakeAdapter.generate(&request).unwrap();
        let result = critique(&request, &output);
        assert!(!result.is_independent_assurance);
        assert_eq!(
            result.recommendation,
            CriticRecommendation::AcceptWithLimitations
        );
    }

    #[test]
    fn serialization_round_trips_the_contract_envelope() {
        let request = task();
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: TaskEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn amharic_locale_is_preserved_without_transliteration() {
        let mut request = task();
        request.locale.requested = "am-ET".to_owned();
        let result = CognitiveRuntime::new(DeterministicFakeAdapter).run(&request);
        assert_eq!(result.answer.unwrap().locale, "am-ET");
    }
}
