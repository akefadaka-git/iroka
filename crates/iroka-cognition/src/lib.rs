//! IROKA native cognition: model-independent symbolic reasoning primitives.
#![forbid(unsafe_code)]

pub mod backward;

pub use backward::{
    Atom as GoalAtom, BackwardReasoner, HornClause, Proof, SearchConfig, SearchError, SearchReport,
    SearchStop, Substitution, Term,
};

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const MAX_ATOM_BYTES: usize = 256;
const MAX_RULE_ID_BYTES: usize = 256;
const MAX_SOURCE_ID_BYTES: usize = 256;
// Hard ceilings prevent caller-supplied configuration from disabling resource bounds.
const MAX_CONFIG: EngineConfig = EngineConfig {
    max_inference_steps: 10_000,
    max_facts: 10_000,
    max_rules: 2_000,
    max_rule_premises: 256,
    max_sources_per_fact: 32,
    max_duration: Duration::from_secs(3),
};
// Aggregate ceilings bound multiplicative state growth across individually valid entries.
const MAX_TOTAL_RULE_PREMISES: usize = 50_000;
const MAX_TOTAL_ASSERTIONS: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Literal {
    pub atom: String,
    pub negated: bool,
}

impl Literal {
    /// Constructs a literal without validating its atom; validation is deferred until submission.
    pub fn positive(atom: impl Into<String>) -> Self {
        Self {
            atom: atom.into(),
            negated: false,
        }
    }
    /// Constructs a negative literal without validating its atom.
    pub fn negative(atom: impl Into<String>) -> Self {
        Self {
            atom: atom.into(),
            negated: true,
        }
    }
    /// Constructs a positive literal after validating borrowed input before allocation.
    ///
    /// # Errors
    /// Returns [`EngineError::EmptyAtom`] for blank input or [`EngineError::AtomTooLong`] above 256 UTF-8 bytes.
    pub fn try_positive(atom: &str) -> Result<Self, EngineError> {
        validate_atom(atom)?;
        Ok(Self {
            atom: atom.to_owned(),
            negated: false,
        })
    }

    /// Constructs a negative literal after validating borrowed input before allocation.
    ///
    /// # Errors
    /// Returns [`EngineError::EmptyAtom`] for blank input or [`EngineError::AtomTooLong`] above 256 UTF-8 bytes.
    pub fn try_negative(atom: &str) -> Result<Self, EngineError> {
        validate_atom(atom)?;
        Ok(Self {
            atom: atom.to_owned(),
            negated: true,
        })
    }

    fn complement(&self) -> Self {
        Self {
            atom: self.atom.clone(),
            negated: !self.negated,
        }
    }
}

/// A rule whose premise vector is allocated by the caller before submission.
/// For streaming input, prefer `NativeReasoner::add_rule_from_iter`.
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssertedFact {
    pub fact: Literal,
    /// Opaque caller-supplied identifier. It is not authenticated or verified.
    pub source_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    pub fact: Literal,
    pub rule_id: String,
    pub premises: Vec<Literal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contradiction {
    pub positive: Literal,
    pub negative: Literal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningReport {
    pub facts: Vec<Literal>,
    pub contradictions: Vec<Contradiction>,
    /// Explicitly asserted inputs and any caller-supplied source identifiers.
    pub asserted_facts: Vec<AssertedFact>,
    /// One deterministic witness per (conclusion, rule ID), including alternate rules.
    pub derivations: Vec<Derivation>,
    pub stop_reason: StopReason,
    pub inference_steps: usize,
    pub elapsed_micros: u128,
}

impl ReasoningReport {
    /// Returns true only when reasoning reached a fixed point.
    ///
    /// A report stopped by a deadline or resource budget contains a partial
    /// knowledge state and must not be treated as a complete closure.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(&self.stop_reason, StopReason::FixedPoint)
    }

    /// Returns true when reasoning stopped before reaching a fixed point.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.is_complete()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub max_inference_steps: usize,
    pub max_facts: usize,
    pub max_rules: usize,
    /// Maximum number of premises accepted in one rule.
    pub max_rule_premises: usize,
    /// Maximum distinct source identifiers retained for one asserted fact.
    pub max_sources_per_fact: usize,
    pub max_duration: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_inference_steps: 10_000,
            max_facts: 10_000,
            max_rules: 2_000,
            max_rule_premises: 256,
            max_sources_per_fact: 32,
            max_duration: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    EmptyAtom,
    AtomTooLong,
    EmptyRuleId,
    RuleIdTooLong,
    EmptySourceId,
    SourceIdTooLong,
    FactSourceBudgetExceeded,
    RuleWithoutPremises,
    DuplicateRuleId,
    RuleBudgetExceeded,
    RulePremiseBudgetExceeded,
    FactBudgetExceeded,
    ZeroBudget,
    ConfigLimitExceeded,
    RulePremiseTotalBudgetExceeded,
    AssertionBudgetExceeded,
}

pub struct NativeReasoner {
    config: EngineConfig,
    facts: BTreeSet<Literal>,
    asserted_facts: BTreeSet<AssertedFact>,
    rules: Vec<Rule>,
    derivations: BTreeMap<String, Derivation>,
    // Resume bounded reasoning fairly across calls. A pass is complete only
    // after every rule has been visited since the last completed pass.
    next_rule_index: usize,
    pass_start_index: usize,
    pass_changed: bool,
}

impl NativeReasoner {
    /// Creates a reasoner with bounded retained state and inference work.
    /// These limits do not constrain memory already allocated by callers.
    ///
    /// # Errors
    /// Returns [`EngineError::ZeroBudget`] if any configured limit is zero, or
    /// [`EngineError::ConfigLimitExceeded`] if a limit exceeds the hard engine ceiling.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        if config.max_inference_steps == 0
            || config.max_facts == 0
            || config.max_rules == 0
            || config.max_rule_premises == 0
            || config.max_sources_per_fact == 0
            || config.max_duration.is_zero()
        {
            return Err(EngineError::ZeroBudget);
        }
        if config.max_inference_steps > MAX_CONFIG.max_inference_steps
            || config.max_facts > MAX_CONFIG.max_facts
            || config.max_rules > MAX_CONFIG.max_rules
            || config.max_rule_premises > MAX_CONFIG.max_rule_premises
            || config.max_sources_per_fact > MAX_CONFIG.max_sources_per_fact
            || config.max_duration > MAX_CONFIG.max_duration
        {
            return Err(EngineError::ConfigLimitExceeded);
        }
        Ok(Self {
            config,
            facts: BTreeSet::new(),
            asserted_facts: BTreeSet::new(),
            rules: Vec::new(),
            derivations: BTreeMap::new(),
            next_rule_index: 0,
            pass_start_index: 0,
            pass_changed: false,
        })
    }

    /// Adds a validated fact, subject to the configured fact limit.
    /// The `Literal` and its `String` atom already exist when this method is called.
    /// Use `try_positive`/`try_negative` for borrowed untrusted atom input.
    ///
    /// # Errors
    /// Returns an error for malformed atoms or when the fact budget is exhausted.
    pub fn add_fact(&mut self, fact: Literal) -> Result<(), EngineError> {
        self.add_fact_with_optional_source(fact, None)
    }

    /// Adds an asserted fact with an opaque caller-supplied source identifier.
    ///
    /// The identifier is provenance metadata only; this engine does not authenticate
    /// the source, assess its trustworthiness, or establish when the evidence arose.
    ///
    /// # Errors
    /// Returns [`EngineError::EmptySourceId`] for a blank identifier,
    /// [`EngineError::SourceIdTooLong`] above 256 UTF-8 bytes,
    /// [`EngineError::EmptyAtom`] or [`EngineError::AtomTooLong`] for an invalid fact,
    /// [`EngineError::FactBudgetExceeded`] when the fact limit is exhausted, or
    /// [`EngineError::FactSourceBudgetExceeded`] when the per-fact source limit is exhausted.
    pub fn add_fact_with_source(
        &mut self,
        fact: Literal,
        source_id: &str,
    ) -> Result<(), EngineError> {
        if source_id.len() > MAX_SOURCE_ID_BYTES {
            return Err(EngineError::SourceIdTooLong);
        }
        if source_id.trim().is_empty() {
            return Err(EngineError::EmptySourceId);
        }
        self.add_fact_with_optional_source(fact, Some(source_id.to_owned()))
    }

    fn add_fact_with_optional_source(
        &mut self,
        fact: Literal,
        source_id: Option<String>,
    ) -> Result<(), EngineError> {
        validate_literal(&fact)?;
        if !self.facts.contains(&fact) && self.facts.len() >= self.config.max_facts {
            return Err(EngineError::FactBudgetExceeded);
        }
        let assertion = AssertedFact {
            fact: fact.clone(),
            source_id,
        };
        if !self.asserted_facts.contains(&assertion)
            && self
                .asserted_facts
                .range(
                    AssertedFact {
                        fact: fact.clone(),
                        source_id: None,
                    }..,
                )
                .take_while(|existing| existing.fact == fact)
                .filter(|existing| existing.source_id.is_some())
                .count()
                >= self.config.max_sources_per_fact
        {
            return Err(EngineError::FactSourceBudgetExceeded);
        }
        if !self.asserted_facts.contains(&assertion)
            && self.asserted_facts.len() >= MAX_TOTAL_ASSERTIONS
        {
            return Err(EngineError::AssertionBudgetExceeded);
        }
        let new_fact = self.facts.insert(fact);
        self.asserted_facts.insert(assertion);
        if new_fact {
            self.next_rule_index = 0;
            self.pass_start_index = 0;
            self.pass_changed = false;
        }
        Ok(())
    }

    /// Adds a validated rule, subject to the configured rule limit.
    /// The caller has already allocated the rule ID and complete premise Vec.
    /// Use `add_rule_from_iter` with a lazy iterator to bound incremental collection.
    ///
    /// # Errors
    /// Returns an error for malformed rules, duplicate IDs, an exhausted rule budget,
    /// or [`EngineError::RulePremiseTotalBudgetExceeded`] when aggregate premises exceed 50,000.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), EngineError> {
        validate_rule_id(&rule.id)?;
        if self.rules.iter().any(|existing| existing.id == rule.id) {
            return Err(EngineError::DuplicateRuleId);
        }
        if self.rules.len() >= self.config.max_rules {
            return Err(EngineError::RuleBudgetExceeded);
        }
        if rule.premises.is_empty() {
            return Err(EngineError::RuleWithoutPremises);
        }
        if rule.premises.len() > self.config.max_rule_premises {
            return Err(EngineError::RulePremiseBudgetExceeded);
        }
        let retained_premises: usize = self
            .rules
            .iter()
            .map(|existing| existing.premises.len())
            .sum();
        if retained_premises.saturating_add(rule.premises.len()) > MAX_TOTAL_RULE_PREMISES {
            return Err(EngineError::RulePremiseTotalBudgetExceeded);
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
        // Rule indices may have shifted; restart a complete deterministic pass.
        self.next_rule_index = 0;
        self.pass_start_index = 0;
        self.pass_changed = false;
        Ok(())
    }

    /// Adds a rule while collecting no more than the configured premise limit.
    ///
    /// The iterator is consumed incrementally and stops at the first excess premise.
    /// Use a lazy iterator to avoid constructing an unbounded caller-side premise Vec.
    ///
    /// # Errors
    /// Returns an error for invalid IDs, duplicate IDs, exhausted budgets, empty rules,
    /// excessive premises, aggregate premise budget exhaustion, or malformed premise/conclusion atoms.
    pub fn add_rule_from_iter<I>(
        &mut self,
        id: &str,
        premises: I,
        conclusion: Literal,
    ) -> Result<(), EngineError>
    where
        I: IntoIterator<Item = Literal>,
    {
        validate_rule_id(id)?;
        if self.rules.iter().any(|existing| existing.id == id) {
            return Err(EngineError::DuplicateRuleId);
        }
        if self.rules.len() >= self.config.max_rules {
            return Err(EngineError::RuleBudgetExceeded);
        }
        validate_literal(&conclusion)?;

        let mut bounded_premises = Vec::new();
        for premise in premises {
            if bounded_premises.len() >= self.config.max_rule_premises {
                return Err(EngineError::RulePremiseBudgetExceeded);
            }
            validate_literal(&premise)?;
            bounded_premises.push(premise);
        }
        if bounded_premises.is_empty() {
            return Err(EngineError::RuleWithoutPremises);
        }

        self.add_rule(Rule {
            id: id.to_owned(),
            premises: bounded_premises,
            conclusion,
        })
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
        self.reason_with_elapsed(|| started.elapsed())
    }

    /// Internal clock seam keeps deadline enforcement testable without wall-clock races.
    fn reason_with_elapsed<F>(&mut self, mut elapsed: F) -> ReasoningReport
    where
        F: FnMut() -> Duration,
    {
        let mut steps = 0usize;
        let stop_reason;
        'reasoning: loop {
            if elapsed() >= self.config.max_duration {
                stop_reason = StopReason::Deadline;
                break;
            }
            if self.rules.is_empty() {
                self.next_rule_index = 0;
                self.pass_changed = false;
                stop_reason = StopReason::FixedPoint;
                break;
            }

            let call_start = self.next_rule_index % self.rules.len();
            for offset in 0..self.rules.len() {
                let rule_index = (call_start + offset) % self.rules.len();
                let rule = &self.rules[rule_index];
                if elapsed() >= self.config.max_duration {
                    self.next_rule_index = rule_index;
                    stop_reason = StopReason::Deadline;
                    break 'reasoning;
                }
                if steps >= self.config.max_inference_steps {
                    self.next_rule_index = rule_index;
                    stop_reason = StopReason::StepBudget;
                    break 'reasoning;
                }
                steps += 1;
                let mut premises_satisfied = true;
                for premise in &rule.premises {
                    if elapsed() >= self.config.max_duration {
                        self.next_rule_index = rule_index;
                        stop_reason = StopReason::Deadline;
                        break 'reasoning;
                    }
                    if !self.facts.contains(premise) {
                        premises_satisfied = false;
                        break;
                    }
                }
                if premises_satisfied {
                    if !self.facts.contains(&rule.conclusion) {
                        if self.facts.len() >= self.config.max_facts {
                            self.next_rule_index = rule_index;
                            stop_reason = StopReason::FactBudget;
                            break 'reasoning;
                        }
                        self.facts.insert(rule.conclusion.clone());
                        self.pass_changed = true;
                    }
                    self.derivations
                        .entry(rule.id.clone())
                        .or_insert_with(|| Derivation {
                            fact: rule.conclusion.clone(),
                            rule_id: rule.id.clone(),
                            premises: rule.premises.clone(),
                        });
                }

                self.next_rule_index = (rule_index + 1) % self.rules.len();
                if self.next_rule_index == self.pass_start_index {
                    if !self.pass_changed {
                        self.next_rule_index = 0;
                        self.pass_changed = false;
                        stop_reason = StopReason::FixedPoint;
                        break 'reasoning;
                    }
                    // A complete pass derived new facts; begin another pass.
                    self.pass_changed = false;
                }
            }
        }
        self.materialize_report(elapsed, stop_reason, steps)
    }

    /// Builds a bounded report under the same cooperative deadline.
    fn materialize_report<F>(
        &self,
        mut elapsed: F,
        mut stop_reason: StopReason,
        steps: usize,
    ) -> ReasoningReport
    where
        F: FnMut() -> Duration,
    {
        // Report construction is part of the cooperative deadline budget.
        // If it expires here, the returned fact/contradiction lists are partial
        // and `is_partial()` remains true.
        let mut facts = Vec::new();
        let mut asserted_facts = Vec::new();
        let mut contradictions = Vec::new();
        for fact in &self.facts {
            if elapsed() >= self.config.max_duration {
                stop_reason = StopReason::Deadline;
                break;
            }
            facts.push(fact.clone());
            asserted_facts.extend(
                self.asserted_facts
                    .range(
                        AssertedFact {
                            fact: fact.clone(),
                            source_id: None,
                        }..,
                    )
                    .take_while(|assertion| assertion.fact == *fact)
                    .cloned(),
            );
            if !fact.negated {
                let negative = fact.complement();
                if self.facts.contains(&negative) {
                    contradictions.push(Contradiction {
                        positive: fact.clone(),
                        negative,
                    });
                }
            }
        }
        // Provenance witnesses persist with the monotonic fact/rule state,
        // so a closure completed across multiple bounded calls retains all
        // witnesses discovered in earlier calls.
        let mut derivations = Vec::new();
        for derivation in self.derivations.values() {
            if elapsed() >= self.config.max_duration {
                stop_reason = StopReason::Deadline;
                break;
            }
            derivations.push(derivation.clone());
        }
        // Enforce the deadline at the final report boundary as well. In
        // particular, the last report item may consume the remaining budget.
        let final_elapsed = elapsed();
        if final_elapsed >= self.config.max_duration {
            stop_reason = StopReason::Deadline;
        }
        ReasoningReport {
            facts,
            contradictions,
            asserted_facts,
            derivations,
            stop_reason,
            inference_steps: steps,
            elapsed_micros: final_elapsed.as_micros(),
        }
    }
}

fn validate_rule_id(id: &str) -> Result<(), EngineError> {
    if id.len() > MAX_RULE_ID_BYTES {
        return Err(EngineError::RuleIdTooLong);
    }
    if id.trim().is_empty() {
        return Err(EngineError::EmptyRuleId);
    }
    Ok(())
}

fn validate_atom(atom: &str) -> Result<(), EngineError> {
    if atom.len() > MAX_ATOM_BYTES {
        return Err(EngineError::AtomTooLong);
    }
    if atom.trim().is_empty() {
        return Err(EngineError::EmptyAtom);
    }
    Ok(())
}

fn validate_literal(literal: &Literal) -> Result<(), EngineError> {
    validate_atom(&literal.atom)
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
    fn reports_derived_contradictions_with_both_sides() {
        let mut brain = engine();
        let p = Literal::positive("door_open");
        brain.add_fact(p.clone()).unwrap();
        brain
            .add_rule(Rule {
                id: "derive_negative".into(),
                premises: vec![p.clone()],
                conclusion: Literal::negative("door_open"),
            })
            .unwrap();
        let report = brain.reason();
        assert_eq!(
            report.contradictions,
            vec![Contradiction {
                positive: p.clone(),
                negative: Literal::negative("door_open"),
            }]
        );
        assert_eq!(brain.query(&p).unwrap(), QueryResult::Contradicted);
    }

    #[test]
    fn derivation_order_is_deterministic_by_rule_id() {
        let mut brain = engine();
        brain.add_fact(Literal::positive("seed")).unwrap();
        for (id, conclusion) in [("z_rule", "z"), ("a_rule", "a")] {
            brain
                .add_rule(Rule {
                    id: id.into(),
                    premises: vec![Literal::positive("seed")],
                    conclusion: Literal::positive(conclusion),
                })
                .unwrap();
        }
        let report = brain.reason();
        assert_eq!(
            report
                .derivations
                .iter()
                .map(|d| d.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a_rule", "z_rule"]
        );
        assert_eq!(report.derivations.len(), 2);
    }

    #[test]
    fn cyclic_rules_reach_a_fixed_point_without_duplicate_derivations() {
        let mut brain = engine();
        brain.add_fact(Literal::positive("a")).unwrap();
        brain
            .add_rule(Rule {
                id: "a_to_b".into(),
                premises: vec![Literal::positive("a")],
                conclusion: Literal::positive("b"),
            })
            .unwrap();
        brain
            .add_rule(Rule {
                id: "b_to_a".into(),
                premises: vec![Literal::positive("b")],
                conclusion: Literal::positive("a"),
            })
            .unwrap();
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::FixedPoint);
        assert_eq!(report.facts.len(), 2);
        assert_eq!(report.derivations.len(), 2);
        assert_eq!(
            report
                .derivations
                .iter()
                .map(|entry| entry.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a_to_b", "b_to_a"]
        );
    }

    #[test]
    fn enforces_fact_and_rule_budgets_without_partial_insertion() {
        let config = EngineConfig {
            max_facts: 1,
            max_rules: 1,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        brain.add_fact(Literal::positive("a")).unwrap();
        assert_eq!(
            brain.add_fact(Literal::positive("b")),
            Err(EngineError::FactBudgetExceeded)
        );
        let rule = Rule {
            id: "r1".into(),
            premises: vec![Literal::positive("a")],
            conclusion: Literal::positive("b"),
        };
        brain.add_rule(rule.clone()).unwrap();
        assert_eq!(
            brain.add_rule(Rule {
                id: "r2".into(),
                ..rule
            }),
            Err(EngineError::RuleBudgetExceeded)
        );
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::FactBudget);
        assert_eq!(report.facts, vec![Literal::positive("a")]);
        assert_eq!(report.derivations.len(), 0);
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let mut brain = engine();
        let rule = Rule {
            id: "same".into(),
            premises: vec![Literal::positive("a")],
            conclusion: Literal::positive("b"),
        };
        brain.add_rule(rule.clone()).unwrap();
        assert_eq!(brain.add_rule(rule), Err(EngineError::DuplicateRuleId));
    }

    #[test]
    fn maximum_supported_duration_does_not_overflow_deadline_arithmetic() {
        let config = EngineConfig {
            max_duration: Duration::from_secs(3),
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        brain.add_fact(Literal::positive("a")).unwrap();
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::FixedPoint);
    }

    #[test]
    fn rejects_rules_over_the_configured_premise_limit() {
        let config = EngineConfig {
            max_rule_premises: 2,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        assert_eq!(
            brain.add_rule(Rule {
                id: "too_many".into(),
                premises: vec![
                    Literal::positive("a"),
                    Literal::positive("b"),
                    Literal::positive("c"),
                ],
                conclusion: Literal::positive("d"),
            }),
            Err(EngineError::RulePremiseBudgetExceeded)
        );
    }

    #[test]
    fn accepts_a_rule_at_the_exact_premise_limit() {
        let config = EngineConfig {
            max_rule_premises: 2,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        brain.add_fact(Literal::positive("a")).unwrap();
        brain.add_fact(Literal::positive("b")).unwrap();
        brain
            .add_rule(Rule {
                id: "exact_limit".into(),
                premises: vec![Literal::positive("a"), Literal::positive("b")],
                conclusion: Literal::positive("c"),
            })
            .unwrap();
        let report = brain.reason();
        assert_eq!(
            brain.query(&Literal::positive("c")).unwrap(),
            QueryResult::Entailed
        );
        assert_eq!(report.derivations.len(), 1);
    }

    #[test]
    fn failed_premise_budget_check_does_not_reserve_rule_id_or_mutate_rules() {
        let config = EngineConfig {
            max_rule_premises: 1,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        assert_eq!(
            brain.add_rule(Rule {
                id: "reusable".into(),
                premises: vec![Literal::positive("a"), Literal::positive("b")],
                conclusion: Literal::positive("c"),
            }),
            Err(EngineError::RulePremiseBudgetExceeded)
        );
        brain
            .add_rule(Rule {
                id: "reusable".into(),
                premises: vec![Literal::positive("a")],
                conclusion: Literal::positive("c"),
            })
            .unwrap();
    }

    #[test]
    fn deadline_is_checked_inside_a_long_premise_scan() {
        let config = EngineConfig {
            max_duration: Duration::from_nanos(5),
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        let premises: Vec<_> = (0..256)
            .map(|index| Literal::positive(format!("premise_{index:03}")))
            .collect();
        for premise in &premises {
            brain.add_fact(premise.clone()).unwrap();
        }
        brain
            .add_rule(Rule {
                id: "maximum_premise_rule".into(),
                premises,
                conclusion: Literal::positive("derived"),
            })
            .unwrap();
        let mut clock_calls = 0usize;
        let report = brain.reason_with_elapsed(|| {
            clock_calls += 1;
            if clock_calls >= 130 {
                Duration::from_nanos(5)
            } else {
                Duration::ZERO
            }
        });
        assert_eq!(report.stop_reason, StopReason::Deadline);
        assert_eq!(report.inference_steps, 1);
        // The deadline also prevents report materialization; the internal
        // knowledge state remains intact, but no conclusion may be inserted.
        assert!(report.is_partial());
        assert_eq!(report.facts, Vec::<Literal>::new());
        assert_eq!(brain.facts.len(), 256);
        assert!(!brain.facts.contains(&Literal::positive("derived")));
        assert_eq!(report.derivations.len(), 0);
    }

    #[test]
    fn duplicate_fact_at_full_budget_is_idempotent() {
        let config = EngineConfig {
            max_facts: 1,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        let fact = Literal::positive("same");
        brain.add_fact(fact.clone()).unwrap();
        brain.add_fact(fact.clone()).unwrap();
        assert_eq!(brain.query(&fact).unwrap(), QueryResult::Entailed);
        assert_eq!(brain.facts.len(), 1);
    }

    #[test]
    fn contradiction_report_is_exhaustive_and_stably_ordered() {
        let mut brain = engine();
        for atom in ["zeta", "alpha", "middle"] {
            brain.add_fact(Literal::positive(atom)).unwrap();
            brain.add_fact(Literal::negative(atom)).unwrap();
        }
        let first = brain.reason();
        let second = brain.reason();
        let expected = ["alpha", "middle", "zeta"]
            .into_iter()
            .map(|atom| Contradiction {
                positive: Literal::positive(atom),
                negative: Literal::negative(atom),
            })
            .collect::<Vec<_>>();
        assert_eq!(first.contradictions, expected);
        assert_eq!(second.contradictions, expected);
    }

    #[test]
    fn inference_is_deterministic_across_rule_insertion_orders() {
        fn run(order: &[(&str, &str)]) -> ReasoningReport {
            let mut brain = engine();
            brain.add_fact(Literal::positive("seed")).unwrap();
            for (id, conclusion) in order {
                brain
                    .add_rule(Rule {
                        id: (*id).into(),
                        premises: vec![Literal::positive("seed")],
                        conclusion: Literal::positive(*conclusion),
                    })
                    .unwrap();
            }
            brain.reason()
        }
        let left = run(&[("r3", "c"), ("r1", "a"), ("r2", "b")]);
        let right = run(&[("r2", "b"), ("r3", "c"), ("r1", "a")]);
        assert_eq!(left.facts, right.facts);
        assert_eq!(left.contradictions, right.contradictions);
        assert_eq!(left.derivations, right.derivations);
        assert_eq!(left.stop_reason, right.stop_reason);
        assert_eq!(left.inference_steps, right.inference_steps);
    }

    #[test]
    fn exhaustively_matches_reference_reachability_for_all_three_node_graphs() {
        let edges = [(0usize, 1usize), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)];
        for mask in 0u8..(1 << edges.len()) {
            let mut brain = engine();
            brain.add_fact(Literal::positive("node_0")).unwrap();
            for (edge_index, (from, to)) in edges.iter().enumerate() {
                if mask & (1 << edge_index) != 0 {
                    brain
                        .add_rule(Rule {
                            id: format!("edge_{edge_index}"),
                            premises: vec![Literal::positive(format!("node_{from}"))],
                            conclusion: Literal::positive(format!("node_{to}")),
                        })
                        .unwrap();
                }
            }
            let report = brain.reason();

            let mut reachable = [true, false, false];
            loop {
                let mut changed = false;
                for (edge_index, (from, to)) in edges.iter().enumerate() {
                    if mask & (1 << edge_index) != 0 && reachable[*from] && !reachable[*to] {
                        reachable[*to] = true;
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            let expected: Vec<_> = reachable
                .iter()
                .enumerate()
                .filter(|(_, is_reachable)| **is_reachable)
                .map(|(index, _)| Literal::positive(format!("node_{index}")))
                .collect();
            assert_eq!(report.stop_reason, StopReason::FixedPoint, "mask={mask}");
            assert_eq!(report.facts, expected, "mask={mask}");
        }
    }

    #[test]
    fn reaches_fixed_point_for_adversarially_ordered_generated_chain() {
        const COUNT: usize = 32;
        let config = EngineConfig {
            max_inference_steps: 2_048,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        brain.add_fact(Literal::positive("node_000")).unwrap();
        for source in 0..COUNT {
            let id = format!("rule_{:04}", COUNT - source);
            brain
                .add_rule(Rule {
                    id,
                    premises: vec![Literal::positive(format!("node_{source:03}"))],
                    conclusion: Literal::positive(format!("node_{:03}", source + 1)),
                })
                .unwrap();
        }
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::FixedPoint);
        assert_eq!(report.derivations.len(), COUNT);
        assert_eq!(report.facts.len(), COUNT + 1);
        assert_eq!(report.inference_steps, COUNT * (COUNT + 1));
        assert_eq!(
            brain
                .query(&Literal::positive(format!("node_{COUNT:03}")))
                .unwrap(),
            QueryResult::Entailed
        );
    }

    #[test]
    fn handles_large_bounded_fact_and_rule_sets() {
        const COUNT: usize = 512;
        let mut brain = engine();
        for index in 0..COUNT {
            brain
                .add_fact(Literal::positive(format!("seed_{index:04}")))
                .unwrap();
        }
        for index in 0..COUNT {
            brain
                .add_rule(Rule {
                    id: format!("rule_{index:04}"),
                    premises: vec![Literal::positive(format!("seed_{index:04}"))],
                    conclusion: Literal::positive(format!("derived_{index:04}")),
                })
                .unwrap();
        }
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::FixedPoint);
        assert_eq!(report.derivations.len(), COUNT);
        assert_eq!(report.facts.len(), COUNT * 2);
        assert_eq!(report.inference_steps, COUNT * 2);
    }

    #[test]
    fn rejects_every_zero_resource_budget() {
        let configs = [
            EngineConfig {
                max_inference_steps: 0,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_facts: 0,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_rules: 0,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_rule_premises: 0,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_sources_per_fact: 0,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_duration: Duration::ZERO,
                ..EngineConfig::default()
            },
        ];
        for config in configs {
            assert!(matches!(
                NativeReasoner::new(config),
                Err(EngineError::ZeroBudget)
            ));
        }
    }

    #[test]
    fn enforces_atom_length_boundary() {
        let mut brain = engine();
        brain.add_fact(Literal::positive("x".repeat(256))).unwrap();
        assert_eq!(
            brain.add_fact(Literal::positive("x".repeat(257))),
            Err(EngineError::AtomTooLong)
        );
        assert_eq!(brain.facts.len(), 1);
    }

    #[test]
    fn contradictory_evidence_does_not_trigger_explosion() {
        let mut brain = engine();
        let p = Literal::positive("signal");
        brain.add_fact(p.clone()).unwrap();
        brain.add_fact(p.complement()).unwrap();
        brain
            .add_rule(Rule {
                id: "positive_branch".into(),
                premises: vec![p.clone()],
                conclusion: Literal::positive("positive_result"),
            })
            .unwrap();
        brain
            .add_rule(Rule {
                id: "negative_branch".into(),
                premises: vec![p.complement()],
                conclusion: Literal::positive("negative_result"),
            })
            .unwrap();
        let report = brain.reason();
        assert_eq!(report.stop_reason, StopReason::FixedPoint);
        assert_eq!(
            brain.query(&Literal::positive("positive_result")).unwrap(),
            QueryResult::Entailed
        );
        assert_eq!(
            brain.query(&Literal::positive("negative_result")).unwrap(),
            QueryResult::Entailed
        );
        assert_eq!(report.contradictions.len(), 1);
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

    #[test]
    fn only_fixed_point_reports_are_complete() {
        let report = |stop_reason| ReasoningReport {
            facts: Vec::new(),
            contradictions: Vec::new(),
            asserted_facts: Vec::new(),
            derivations: Vec::new(),
            stop_reason,
            inference_steps: 0,
            elapsed_micros: 0,
        };

        let complete = report(StopReason::FixedPoint);
        assert!(complete.is_complete());
        assert!(!complete.is_partial());

        for stop_reason in [
            StopReason::Deadline,
            StopReason::StepBudget,
            StopReason::FactBudget,
        ] {
            let partial = report(stop_reason);
            assert!(!partial.is_complete());
            assert!(partial.is_partial());
        }
    }
    #[test]
    fn deadline_is_enforced_during_report_materialization() {
        let mut brain = engine();
        brain.add_fact(Literal::positive("seed")).unwrap();
        let mut clock_calls = 0usize;
        let report = brain.reason_with_elapsed(|| {
            clock_calls += 1;
            if clock_calls >= 2 {
                Duration::from_secs(4)
            } else {
                Duration::ZERO
            }
        });

        assert_eq!(report.stop_reason, StopReason::Deadline);
        assert!(report.is_partial());
        assert_eq!(report.facts, Vec::<Literal>::new());
    }

    #[test]
    fn deadline_is_checked_after_the_final_report_item() {
        let mut brain = engine();
        brain.add_fact(Literal::positive("last_fact")).unwrap();
        let mut clock_calls = 0usize;
        let report = brain.reason_with_elapsed(|| {
            clock_calls += 1;
            if clock_calls >= 3 {
                Duration::from_secs(4)
            } else {
                Duration::ZERO
            }
        });

        assert_eq!(report.stop_reason, StopReason::Deadline);
        assert!(report.is_partial());
        assert_eq!(report.facts, vec![Literal::positive("last_fact")]);
        assert!(report.elapsed_micros >= 4_000_000);
    }

    #[test]
    fn records_multiple_assertion_sources_without_claiming_authenticity() {
        let mut brain = engine();
        let fact = Literal::positive("temperature_high");
        brain
            .add_fact_with_source(fact.clone(), "sensor:room-1")
            .unwrap();
        brain
            .add_fact_with_source(fact.clone(), "operator:inspection-7")
            .unwrap();
        brain.add_fact(fact.clone()).unwrap();

        let report = brain.reason();
        assert_eq!(report.asserted_facts.len(), 3);
        assert!(report.asserted_facts.contains(&AssertedFact {
            fact: fact.clone(),
            source_id: Some("sensor:room-1".into()),
        }));
        assert!(report.asserted_facts.contains(&AssertedFact {
            fact: fact.clone(),
            source_id: Some("operator:inspection-7".into()),
        }));
        assert!(report.asserted_facts.contains(&AssertedFact {
            fact,
            source_id: None,
        }));
    }

    #[test]
    fn bounds_distinct_sources_per_asserted_fact_atomically() {
        let config = EngineConfig {
            max_sources_per_fact: 2,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        let fact = Literal::positive("verified");
        brain
            .add_fact_with_source(fact.clone(), "source-a")
            .unwrap();
        brain
            .add_fact_with_source(fact.clone(), "source-b")
            .unwrap();
        brain
            .add_fact_with_source(fact.clone(), "source-b")
            .unwrap();
        assert_eq!(
            brain.add_fact_with_source(fact.clone(), "source-c"),
            Err(EngineError::FactSourceBudgetExceeded)
        );
        assert_eq!(brain.facts.len(), 1);
        assert_eq!(
            brain
                .asserted_facts
                .iter()
                .filter(|entry| entry.fact == fact)
                .count(),
            2
        );
    }

    #[test]
    fn rejects_empty_and_oversized_source_identifiers() {
        let mut brain = engine();
        let fact = Literal::positive("source_test");
        assert_eq!(
            brain.add_fact_with_source(fact.clone(), "  "),
            Err(EngineError::EmptySourceId)
        );
        assert_eq!(
            brain.add_fact_with_source(fact, &"x".repeat(257)),
            Err(EngineError::SourceIdTooLong)
        );
        assert!(brain.facts.is_empty());
        assert!(brain.asserted_facts.is_empty());
    }

    #[test]
    fn retains_alternative_rule_witnesses_for_the_same_conclusion() {
        let mut brain = engine();
        brain.add_fact(Literal::positive("sensor_a")).unwrap();
        brain.add_fact(Literal::positive("sensor_b")).unwrap();
        let conclusion = Literal::positive("hazard_detected");
        for (id, premise) in [("rule_a", "sensor_a"), ("rule_b", "sensor_b")] {
            brain
                .add_rule(Rule {
                    id: id.into(),
                    premises: vec![Literal::positive(premise)],
                    conclusion: conclusion.clone(),
                })
                .unwrap();
        }

        let report = brain.reason();
        let witnesses: Vec<_> = report
            .derivations
            .iter()
            .filter(|entry| entry.fact == conclusion)
            .map(|entry| entry.rule_id.as_str())
            .collect();
        assert_eq!(witnesses, vec!["rule_a", "rule_b"]);
        assert_eq!(report.derivations.len(), 2);
    }

    #[test]
    fn records_a_rule_witness_even_when_conclusion_was_already_asserted() {
        let mut brain = engine();
        let conclusion = Literal::positive("reviewed");
        brain.add_fact(conclusion.clone()).unwrap();
        brain.add_fact(Literal::positive("input")).unwrap();
        brain
            .add_rule(Rule {
                id: "independent_support".into(),
                premises: vec![Literal::positive("input")],
                conclusion: conclusion.clone(),
            })
            .unwrap();

        let report = brain.reason();
        assert_eq!(report.derivations.len(), 1);
        assert_eq!(report.derivations[0].fact, conclusion);
        assert_eq!(report.derivations[0].rule_id, "independent_support");
    }

    #[test]
    fn accepts_source_identifier_at_byte_limit_and_rejects_one_over() {
        let mut brain = engine();
        let fact = Literal::positive("bounded_source");
        brain
            .add_fact_with_source(fact.clone(), &"s".repeat(256))
            .unwrap();
        assert_eq!(
            brain.add_fact_with_source(fact.clone(), &"t".repeat(257)),
            Err(EngineError::SourceIdTooLong)
        );
        assert_eq!(
            brain
                .asserted_facts
                .iter()
                .filter(|entry| entry.fact == fact)
                .count(),
            1
        );
    }

    #[test]
    fn legacy_unknown_source_does_not_consume_source_identifier_budget() {
        let config = EngineConfig {
            max_sources_per_fact: 1,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        let fact = Literal::positive("legacy_and_identified");
        brain.add_fact(fact.clone()).unwrap();
        brain
            .add_fact_with_source(fact.clone(), "identified-source")
            .unwrap();
        assert_eq!(
            brain.add_fact_with_source(fact, "second-identified-source"),
            Err(EngineError::FactSourceBudgetExceeded)
        );
    }
    #[test]
    fn bounds_rule_identifiers_and_checks_length_before_blankness() {
        let mut brain = engine();
        brain
            .add_rule(Rule {
                id: "r".repeat(MAX_RULE_ID_BYTES),
                premises: vec![Literal::positive("seed")],
                conclusion: Literal::positive("accepted"),
            })
            .unwrap();
        assert_eq!(
            brain.add_rule(Rule {
                id: " ".repeat(MAX_RULE_ID_BYTES + 1),
                premises: vec![Literal::positive("seed")],
                conclusion: Literal::positive("rejected"),
            }),
            Err(EngineError::RuleIdTooLong)
        );
        assert_eq!(brain.rules.len(), 1);
    }

    #[test]
    fn bounded_literal_constructors_validate_before_owning_input() {
        assert_eq!(
            Literal::try_positive(&" ".repeat(MAX_ATOM_BYTES + 1)),
            Err(EngineError::AtomTooLong)
        );
        assert_eq!(Literal::try_negative("  "), Err(EngineError::EmptyAtom));
        assert_eq!(
            Literal::try_positive(&"x".repeat(MAX_ATOM_BYTES)).unwrap(),
            Literal::positive("x".repeat(MAX_ATOM_BYTES))
        );
    }

    #[test]
    fn iterator_rule_builder_stops_at_the_first_excess_premise() {
        use std::cell::Cell;

        let config = EngineConfig {
            max_rule_premises: 2,
            ..EngineConfig::default()
        };
        let mut brain = NativeReasoner::new(config).unwrap();
        let consumed = Cell::new(0usize);
        let premises = (0..100).map(|index| {
            consumed.set(consumed.get() + 1);
            Literal::positive(format!("premise_{index}"))
        });
        assert_eq!(
            brain.add_rule_from_iter("bounded", premises, Literal::positive("conclusion")),
            Err(EngineError::RulePremiseBudgetExceeded)
        );
        assert_eq!(consumed.get(), 3);
        assert_eq!(brain.rules, Vec::<Rule>::new());
    }
    #[test]
    fn rejects_caller_configurations_above_hard_resource_ceilings() {
        let invalid_configs = [
            EngineConfig {
                max_inference_steps: 10_001,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_facts: 10_001,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_rules: 2_001,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_rule_premises: 257,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_sources_per_fact: 33,
                ..EngineConfig::default()
            },
            EngineConfig {
                max_duration: Duration::from_millis(3_001),
                ..EngineConfig::default()
            },
        ];
        for config in invalid_configs {
            assert_eq!(
                NativeReasoner::new(config).err(),
                Some(EngineError::ConfigLimitExceeded)
            );
        }
    }

    #[test]
    fn aggregate_rule_premise_budget_is_atomic() {
        let mut brain = engine();
        let premises = vec![Literal::positive("p"); 256];
        for index in 0..195 {
            brain
                .add_rule(Rule {
                    id: format!("r{index}"),
                    premises: premises.clone(),
                    conclusion: Literal::positive("done"),
                })
                .unwrap();
        }
        brain
            .add_rule(Rule {
                id: "r195".into(),
                premises: vec![Literal::positive("p"); 80],
                conclusion: Literal::positive("done"),
            })
            .unwrap();
        let before = brain.rules.len();
        assert_eq!(
            brain.add_rule(Rule {
                id: "overflow".into(),
                premises: vec![Literal::positive("p")],
                conclusion: Literal::positive("done"),
            }),
            Err(EngineError::RulePremiseTotalBudgetExceeded)
        );
        assert_eq!(brain.rules.len(), before);
    }

    #[test]
    fn aggregate_assertion_budget_rejects_without_mutation() {
        let mut brain = engine();
        let mut last_fact = Literal::positive("evidence-0");
        for index in 0..MAX_TOTAL_ASSERTIONS {
            let fact_index = index / EngineConfig::default().max_sources_per_fact;
            let source_index = index % EngineConfig::default().max_sources_per_fact;
            let fact = Literal::positive(format!("evidence-{fact_index}"));
            brain
                .add_fact_with_source(fact.clone(), &format!("source-{source_index}"))
                .unwrap();
            last_fact = fact;
        }
        let before_facts = brain.facts.len();
        assert_eq!(
            brain.add_fact_with_source(last_fact, "overflow-source"),
            Err(EngineError::AssertionBudgetExceeded)
        );
        assert_eq!(brain.facts.len(), before_facts);
        assert_eq!(brain.asserted_facts.len(), MAX_TOTAL_ASSERTIONS);
    }
}
