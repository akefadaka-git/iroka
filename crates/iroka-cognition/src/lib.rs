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
pub struct Contradiction {
    pub positive: Literal,
    pub negative: Literal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningReport {
    pub facts: Vec<Literal>,
    pub contradictions: Vec<Contradiction>,
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
    pub fn is_complete(&self) -> bool {
        matches!(self.stop_reason, StopReason::FixedPoint)
    }

    /// Returns true when reasoning stopped before reaching a fixed point.
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
    pub max_duration: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_inference_steps: 10_000,
            max_facts: 10_000,
            max_rules: 2_000,
            max_rule_premises: 256,
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
    RulePremiseBudgetExceeded,
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
            || config.max_rule_premises == 0
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
        if rule.premises.len() > self.config.max_rule_premises {
            return Err(EngineError::RulePremiseBudgetExceeded);
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
        self.reason_with_elapsed(|| started.elapsed())
    }

    /// Internal clock seam keeps deadline enforcement testable without wall-clock races.
    fn reason_with_elapsed<F>(&mut self, mut elapsed: F) -> ReasoningReport
    where
        F: FnMut() -> Duration,
    {
        let mut derivations = Vec::new();
        let mut steps = 0usize;
        let stop_reason;
        'reasoning: loop {
            if elapsed() >= self.config.max_duration {
                stop_reason = StopReason::Deadline;
                break;
            }
            let mut changed = false;
            for rule in &self.rules {
                if elapsed() >= self.config.max_duration {
                    stop_reason = StopReason::Deadline;
                    break 'reasoning;
                }
                if steps >= self.config.max_inference_steps {
                    stop_reason = StopReason::StepBudget;
                    break 'reasoning;
                }
                steps += 1;
                let mut premises_satisfied = true;
                for premise in &rule.premises {
                    if elapsed() >= self.config.max_duration {
                        stop_reason = StopReason::Deadline;
                        break 'reasoning;
                    }
                    if !self.facts.contains(premise) {
                        premises_satisfied = false;
                        break;
                    }
                }
                if premises_satisfied && !self.facts.contains(&rule.conclusion) {
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
        let contradictions = self
            .facts
            .iter()
            .filter(|fact| !fact.negated)
            .filter_map(|positive| {
                let negative = positive.complement();
                self.facts.contains(&negative).then_some(Contradiction {
                    positive: positive.clone(),
                    negative,
                })
            })
            .collect();
        ReasoningReport {
            facts: self.facts.iter().cloned().collect(),
            contradictions,
            derivations,
            stop_reason,
            inference_steps: steps,
            elapsed_micros: elapsed().as_micros(),
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
        assert_eq!(report.derivations.len(), 1);
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
    fn maximum_duration_does_not_overflow_deadline_arithmetic() {
        let config = EngineConfig {
            max_duration: Duration::MAX,
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
        assert_eq!(report.facts.len(), 256);
        assert!(!report.facts.contains(&Literal::positive("derived")));
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

}
