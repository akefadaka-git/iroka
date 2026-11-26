//! In-process, advisory-only bridge from IROKA services to native NCE-01 reasoning.
//!
//! This adapter returns evidence and reasoning observations only. It does not
//! authenticate principals, evaluate permissions, issue decisions, grant capabilities,
//! write audit records, or execute actions. Kernel authorization remains independent.

use iroka_cognition::{
    EngineConfig, EngineError, Literal, NativeReasoner, QueryResult, ReasoningReport, Rule,
};

const MAX_ADAPTER_INPUT_BYTES: usize = 1_048_576;
const MAX_ADAPTER_QUERIES: usize = 256;

/// Bounds for one in-process advisory reasoning call.
#[derive(Debug, Clone, Copy)]
pub struct AdvisoryCognitionConfig {
    /// NCE-01 engine limits. The engine enforces its own hard ceilings.
    pub engine: EngineConfig,
    /// Aggregate UTF-8 payload bytes accepted across facts, rules and queries.
    pub max_input_bytes: usize,
    /// Maximum number of queries returned for one reasoning call.
    pub max_queries: usize,
}

impl Default for AdvisoryCognitionConfig {
    fn default() -> Self {
        Self {
            engine: EngineConfig::default(),
            max_input_bytes: MAX_ADAPTER_INPUT_BYTES,
            max_queries: MAX_ADAPTER_QUERIES,
        }
    }
}

/// An asserted input fact and optional opaque provenance label.
///
/// The source label is metadata supplied by the caller; this adapter does not
/// authenticate it or establish the truth of the associated fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryFact {
    pub literal: Literal,
    pub source_id: Option<String>,
}

impl AdvisoryFact {
    #[must_use]
    pub fn new(literal: Literal, source_id: Option<String>) -> Self {
        Self { literal, source_id }
    }
}

/// A complete, bounded request to the native forward reasoner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisoryCognitionRequest {
    pub facts: Vec<AdvisoryFact>,
    pub rules: Vec<Rule>,
    pub queries: Vec<Literal>,
}

/// Query observations made against the resulting (possibly partial) fact state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryQueryResult {
    pub query: Literal,
    pub result: QueryResult,
}

/// Output from NCE-01. This is an advisory result, never an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryCognitionResult {
    pub report: ReasoningReport,
    pub query_results: Vec<AdvisoryQueryResult>,
}

impl AdvisoryCognitionResult {
    /// True only when NCE-01 reached a fixed point.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.report.is_complete()
    }

    /// True when a deadline or engine budget stopped reasoning early.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.report.is_partial()
    }
}

/// Input or configuration rejection from the advisory adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryCognitionError {
    InvalidAdapterConfig,
    InputTooLarge,
    TooManyFacts,
    TooManyRules,
    TooManyQueries,
    Engine(EngineError),
}

impl From<EngineError> for AdvisoryCognitionError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

/// In-process adapter for higher-level IROKA services.
///
/// The adapter is deliberately a one-call, in-memory boundary: no network, filesystem,
/// provider, background task, kernel decision, protected effect or persistent memory.
#[derive(Debug, Clone, Copy)]
pub struct AdvisoryCognitionAdapter {
    config: AdvisoryCognitionConfig,
}

impl AdvisoryCognitionAdapter {
    /// Creates an adapter after validating all engine and adapter-level limits.
    ///
    /// # Errors
    /// Returns InvalidAdapterConfig for zero or excessive adapter limits, or
    /// Engine when the NCE-01 engine configuration violates its hard ceilings.
    pub fn new(config: AdvisoryCognitionConfig) -> Result<Self, AdvisoryCognitionError> {
        if config.max_input_bytes == 0
            || config.max_input_bytes > MAX_ADAPTER_INPUT_BYTES
            || config.max_queries == 0
            || config.max_queries > MAX_ADAPTER_QUERIES
        {
            return Err(AdvisoryCognitionError::InvalidAdapterConfig);
        }
        NativeReasoner::new(config.engine)?;
        Ok(Self { config })
    }

    /// Runs bounded NCE-01 inference and returns advisory observations.
    ///
    /// The request's aggregate payload and collection counts are checked before
    /// engine-owned copies are retained. The caller has already allocated the Rust
    /// request; transport/parser allocation limits remain the responsibility of any
    /// future ingress adapter.
    ///
    /// Query observations from a partial report describe only the facts discovered so
    /// far. Callers MUST check is_complete() before treating absence as meaningful.
    ///
    /// # Errors
    /// Returns an adapter input-limit error or a wrapped NCE-01 validation/budget error.
    pub fn run(
        &self,
        request: AdvisoryCognitionRequest,
    ) -> Result<AdvisoryCognitionResult, AdvisoryCognitionError> {
        if request.facts.len() > self.config.engine.max_facts {
            return Err(AdvisoryCognitionError::TooManyFacts);
        }
        if request.rules.len() > self.config.engine.max_rules {
            return Err(AdvisoryCognitionError::TooManyRules);
        }
        if request.queries.len() > self.config.max_queries {
            return Err(AdvisoryCognitionError::TooManyQueries);
        }

        let mut input_bytes = 0usize;
        for fact in &request.facts {
            add_input_bytes(
                &mut input_bytes,
                fact.literal.atom.len(),
                self.config.max_input_bytes,
            )?;
            if let Some(source_id) = &fact.source_id {
                add_input_bytes(
                    &mut input_bytes,
                    source_id.len(),
                    self.config.max_input_bytes,
                )?;
            }
        }
        for rule in &request.rules {
            add_input_bytes(&mut input_bytes, rule.id.len(), self.config.max_input_bytes)?;
            add_input_bytes(
                &mut input_bytes,
                rule.conclusion.atom.len(),
                self.config.max_input_bytes,
            )?;
            for premise in &rule.premises {
                add_input_bytes(
                    &mut input_bytes,
                    premise.atom.len(),
                    self.config.max_input_bytes,
                )?;
            }
        }
        for query in &request.queries {
            add_input_bytes(
                &mut input_bytes,
                query.atom.len(),
                self.config.max_input_bytes,
            )?;
        }

        let mut reasoner = NativeReasoner::new(self.config.engine)?;
        for fact in request.facts {
            match fact.source_id {
                Some(source_id) => reasoner.add_fact_with_source(fact.literal, &source_id)?,
                None => reasoner.add_fact(fact.literal)?,
            }
        }
        for rule in request.rules {
            reasoner.add_rule(rule)?;
        }

        let report = reasoner.reason();
        let mut query_results = Vec::with_capacity(request.queries.len());
        for query in request.queries {
            let result = reasoner.query(&query)?;
            query_results.push(AdvisoryQueryResult { query, result });
        }

        Ok(AdvisoryCognitionResult {
            report,
            query_results,
        })
    }
}

fn add_input_bytes(
    total: &mut usize,
    bytes: usize,
    limit: usize,
) -> Result<(), AdvisoryCognitionError> {
    *total = total
        .checked_add(bytes)
        .filter(|total| *total <= limit)
        .ok_or(AdvisoryCognitionError::InputTooLarge)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evaluate, AuthorizationRequest, DecisionCode, Policy, RiskLevel};

    fn fact(atom: &str) -> AdvisoryFact {
        AdvisoryFact::new(Literal::positive(atom), None)
    }

    #[test]
    fn integrates_multi_step_reasoning_and_preserves_input_provenance() {
        let adapter = AdvisoryCognitionAdapter::new(AdvisoryCognitionConfig::default()).unwrap();
        let request = AdvisoryCognitionRequest {
            facts: vec![AdvisoryFact::new(
                Literal::positive("rain"),
                Some("weather-observation:1".into()),
            )],
            rules: vec![
                Rule {
                    id: "r1".into(),
                    premises: vec![Literal::positive("rain")],
                    conclusion: Literal::positive("road_wet"),
                },
                Rule {
                    id: "r2".into(),
                    premises: vec![Literal::positive("road_wet")],
                    conclusion: Literal::positive("traffic_slow"),
                },
            ],
            queries: vec![Literal::positive("traffic_slow")],
        };

        let result = adapter.run(request).unwrap();

        assert!(result.is_complete());
        assert_eq!(result.report.derivations.len(), 2);
        assert_eq!(
            result.report.asserted_facts[0].source_id.as_deref(),
            Some("weather-observation:1")
        );
        assert_eq!(result.query_results[0].result, QueryResult::Entailed);
    }

    #[test]
    fn reports_contradictions_without_suppressing_either_polarity() {
        let adapter = AdvisoryCognitionAdapter::new(AdvisoryCognitionConfig::default()).unwrap();
        let request = AdvisoryCognitionRequest {
            facts: vec![
                fact("door_open"),
                AdvisoryFact::new(Literal::negative("door_open"), None),
            ],
            queries: vec![Literal::positive("door_open")],
            ..AdvisoryCognitionRequest::default()
        };

        let result = adapter.run(request).unwrap();

        assert_eq!(result.report.contradictions.len(), 1);
        assert_eq!(result.query_results[0].result, QueryResult::Contradicted);
    }

    #[test]
    fn partial_reasoning_is_explicit_and_never_reported_as_complete() {
        let config = AdvisoryCognitionConfig {
            engine: EngineConfig {
                max_inference_steps: 1,
                ..EngineConfig::default()
            },
            ..AdvisoryCognitionConfig::default()
        };
        let adapter = AdvisoryCognitionAdapter::new(config).unwrap();
        let request = AdvisoryCognitionRequest {
            facts: vec![fact("a")],
            rules: vec![
                Rule {
                    id: "r1".into(),
                    premises: vec![Literal::positive("a")],
                    conclusion: Literal::positive("b"),
                },
                Rule {
                    id: "r2".into(),
                    premises: vec![Literal::positive("b")],
                    conclusion: Literal::positive("c"),
                },
            ],
            queries: vec![Literal::positive("c")],
        };

        let result = adapter.run(request).unwrap();

        assert!(result.is_partial());
        assert!(!result.is_complete());
    }

    #[test]
    fn rejects_oversized_input_before_reasoner_construction() {
        let config = AdvisoryCognitionConfig {
            max_input_bytes: 4,
            ..AdvisoryCognitionConfig::default()
        };
        let adapter = AdvisoryCognitionAdapter::new(config).unwrap();
        let request = AdvisoryCognitionRequest {
            facts: vec![fact("fiver")],
            ..AdvisoryCognitionRequest::default()
        };

        assert_eq!(
            adapter.run(request),
            Err(AdvisoryCognitionError::InputTooLarge)
        );
    }

    #[test]
    fn rejects_query_count_over_configured_limit() {
        let config = AdvisoryCognitionConfig {
            max_queries: 1,
            ..AdvisoryCognitionConfig::default()
        };
        let adapter = AdvisoryCognitionAdapter::new(config).unwrap();
        let request = AdvisoryCognitionRequest {
            queries: vec![Literal::positive("a"), Literal::positive("b")],
            ..AdvisoryCognitionRequest::default()
        };

        assert_eq!(
            adapter.run(request),
            Err(AdvisoryCognitionError::TooManyQueries)
        );
    }

    #[test]
    fn advisory_reasoning_does_not_change_kernel_authorization_policy() {
        let adapter = AdvisoryCognitionAdapter::new(AdvisoryCognitionConfig::default()).unwrap();
        let advisory = adapter
            .run(AdvisoryCognitionRequest {
                facts: vec![fact("policy:allow:records.export")],
                ..AdvisoryCognitionRequest::default()
            })
            .unwrap();
        assert!(advisory.is_complete());

        let request =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let policy = Policy::new(
            "policy-v1",
            vec!["workspace.read".into()],
            Vec::new(),
            RiskLevel::High,
        );

        let decision = evaluate(&request, &policy, false);
        assert_eq!(decision.code(), DecisionCode::Deny);
    }
}
