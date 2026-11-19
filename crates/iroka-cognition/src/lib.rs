//! IROKA native cognition: model-independent symbolic reasoning primitives.
#![forbid(unsafe_code)]

pub mod backward;

pub use backward::{
    Atom as GoalAtom, BackwardReasoner, HornClause, Proof, SearchConfig, SearchError, SearchReport,
    SearchStop, Substitution, Term,
};

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Literal {
    pub atom: String,
    pub negated: bool,
}

impl Literal {
    pub fn positive(atom: impl Into<String>) -> Self {
        Self {
            atom: atom.into(),
            negated: false,
        }
    }
    pub fn negative(atom: impl Into<String>) -> Self {
        Self {
            atom: atom.into(),
            negated: true,
        }
    }
    fn complement(&self) -> Self {
        Self {
            atom: self.atom.clone(),
            negated: !self.negated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub premises: Vec<Literal>,
    pub conclusion: Literal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    Entailed,
    Refuted,
    Unknown,
    Contradicted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    FixedPoint,
    Deadline,
    StepBudget,
    FactBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    pub fact: Literal,
    pub rule_id: String,
    pub premises: Vec<Literal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningReport {
    pub facts: Vec<Literal>,
    pub derivations: Vec<Derivation>,
    pub stop_reason: StopReason,
    pub inference_steps: usize,
    pub elapsed_micros: u128,
}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub max_inference_steps: usize,
    pub max_facts: usize,
    pub max_rules: usize,
    pub max_duration: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_inference_steps: 10_000,
            max_facts: 10_000,
            max_rules: 2_000,
            max_duration: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    EmptyAtom,
    AtomTooLong,
    EmptyRuleId,
    RuleWithoutPremises,
    DuplicateRuleId,
    RuleBudgetExceeded,
    FactBudgetExceeded,
    ZeroBudget,
}

pub struct NativeReasoner {
    config: EngineConfig,
    facts: BTreeSet<Literal>,
    rules: Vec<Rule>,
}

impl NativeReasoner {
    /// Creates a propositional reasoner with bounded facts, rules, steps, and time.
    ///
    /// # Errors
    /// Returns [`EngineError::ZeroBudget`] if any configured limit is zero.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        if config.max_inference_steps == 0
            || config.max_facts == 0
            || config.max_rules == 0
            || config.max_duration.is_zero()
        {
            return Err(EngineError::ZeroBudget);
        }
        Ok(Self {
            config,
            facts: BTreeSet::new(),
            rules: Vec::new(),
        })
    }

    /// Adds a validated fact, subject to the configured fact limit.
    ///
    /// # Errors
    /// Returns an error for malformed atoms or when the fact budget is exhausted.
    pub fn add_fact(&mut self, fact: Literal) -> Result<(), EngineError> {
        validate_literal(&fact)?;
        if !self.facts.contains(&fact) && self.facts.len() >= self.config.max_facts {
            return Err(EngineError::FactBudgetExceeded);
        }
        self.facts.insert(fact);
        Ok(())
    }

    /// Adds a validated rule, subject to the configured rule limit.
    ///
    /// # Errors
    /// Returns an error for malformed rules, duplicate IDs, or an exhausted rule budget.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), EngineError> {
        if rule.id.trim().is_empty() {
            return Err(EngineError::EmptyRuleId);
        }
        if self.rules.iter().any(|existing| existing.id == rule.id) {
            return Err(EngineError::DuplicateRuleId);
        }
        if self.rules.len() >= self.config.max_rules {
            return Err(EngineError::RuleBudgetExceeded);
        }
        if rule.premises.is_empty() {
            return Err(EngineError::RuleWithoutPremises);
        }
        for literal in rule
            .premises
            .iter()
            .chain(std::iter::once(&rule.conclusion))
        {
            validate_literal(literal)?;
        }
        self.rules.push(rule);
        self.rules.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(())
    }

    /// Queries a literal without treating unknown evidence as false.
    ///
    /// # Errors
    /// Returns an error when the queried atom is malformed.
    pub fn query(&self, query: &Literal) -> Result<QueryResult, EngineError> {
        validate_literal(query)?;
        let positive = self.facts.contains(query);
        let negative = self.facts.contains(&query.complement());
        Ok(match (positive, negative) {
            (true, true) => QueryResult::Contradicted,
            (true, false) => QueryResult::Entailed,
            (false, true) => QueryResult::Refuted,
            (false, false) => QueryResult::Unknown,
        })
    }

    pub fn reason(&mut self) -> ReasoningReport {
        let started = Instant::now();
        let deadline = started + self.config.max_duration;
        let mut derivations = Vec::new();
        let mut steps = 0usize;
        let stop_reason;
        'reasoning: loop {
            if Instant::now() >= deadline {
                stop_reason = StopReason::Deadline;
                break;
            }
            let mut changed = false;
            for rule in &self.rules {
                if Instant::now() >= deadline {
                    stop_reason = StopReason::Deadline;
                    break 'reasoning;
                }
                if steps >= self.config.max_inference_steps {
                    stop_reason = StopReason::StepBudget;
                    break 'reasoning;
                }
                steps += 1;
                if rule
                    .premises
                    .iter()
                    .all(|premise| self.facts.contains(premise))
                    && !self.facts.contains(&rule.conclusion)
                {
                    if self.facts.len() >= self.config.max_facts {
                        stop_reason = StopReason::FactBudget;
                        break 'reasoning;
                    }
                    self.facts.insert(rule.conclusion.clone());
                    derivations.push(Derivation {
                        fact: rule.conclusion.clone(),
                        rule_id: rule.id.clone(),
                        premises: rule.premises.clone(),
                    });
                    changed = true;
                }
            }
            if !changed {
                stop_reason = StopReason::FixedPoint;
                break;
            }
        }
        ReasoningReport {
            facts: self.facts.iter().cloned().collect(),
            derivations,
            stop_reason,
            inference_steps: steps,
            elapsed_micros: started.elapsed().as_micros(),
        }
    }
}

fn validate_literal(literal: &Literal) -> Result<(), EngineError> {
    if literal.atom.trim().is_empty() {
        return Err(EngineError::EmptyAtom);
    }
    if literal.atom.len() > 256 {
        return Err(EngineError::AtomTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine() -> NativeReasoner {
        NativeReasoner::new(EngineConfig::default()).unwrap()
    }

    #[test]
    fn derives_a_multi_step_conclusion_without_any_model() {
        let mut brain = engine();
        let a = Literal::positive("rain");
        let b = Literal::positive("road_wet");
        let c = Literal::positive("traffic_slow");
        brain.add_fact(a.clone()).unwrap();
        brain
            .add_rule(Rule {
                id: "r1".into(),
                premises: vec![a],
                conclusion: b.clone(),
            })
            .unwrap();
        brain
            .add_rule(Rule {
                id: "r2".into(),
                premises: vec![b],
                conclusion: c.clone(),
            })
            .unwrap();
        let report = brain.reason();
        assert_eq!(brain.query(&c).unwrap(), QueryResult::Entailed);
        assert_eq!(report.derivations.len(), 2);
        assert_eq!(report.stop_reason, StopReason::FixedPoint);
    }

    #[test]
    fn detects_conflicting_evidence_instead_of_hiding_it() {
        let mut brain = engine();
        let p = Literal::positive("door_open");
        brain.add_fact(p.clone()).unwrap();
        brain.add_fact(p.complement()).unwrap();
        assert_eq!(brain.query(&p).unwrap(), QueryResult::Contradicted);
    }

    #[test]
    fn reports_unknown_instead_of_guessing() {
        assert_eq!(
            engine().query(&Literal::positive("unknown")).unwrap(),
            QueryResult::Unknown
        );
    }

    #[test]
    fn enforces_inference_step_budget() {
        let config = EngineConfig {
            max_inference_steps: 1,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        brain.add_fact(Literal::positive("a")).unwrap();
        brain
            .add_rule(Rule {
                id: "r1".into(),
                premises: vec![Literal::positive("a")],
                conclusion: Literal::positive("b"),
            })
            .unwrap();
        brain
            .add_rule(Rule {
                id: "r2".into(),
                premises: vec![Literal::positive("b")],
                conclusion: Literal::positive("c"),
            })
            .unwrap();
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::StepBudget);
        assert_eq!(
            brain.query(&Literal::positive("c")).unwrap(),
            QueryResult::Unknown
        );
    }

    #[test]
    fn rejects_unbounded_or_malformed_rules() {
        let mut brain = engine();
        assert_eq!(
            brain.add_rule(Rule {
                id: "bad".into(),
                premises: vec![],
                conclusion: Literal::positive("x")
            }),
            Err(EngineError::RuleWithoutPremises)
        );
        assert_eq!(
            brain.add_fact(Literal::positive(" ")),
            Err(EngineError::EmptyAtom)
        );
    }
}
