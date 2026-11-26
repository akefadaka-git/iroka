//! In-process, advisory-only adapter for NCE-02 goal-directed reasoning.

use iroka_cognition::{
    Atom, BackwardReasoner, HornClause, SearchConfig, SearchError, SearchReport, SearchStop,
};
use std::time::Duration;

const MAX_INPUT_BYTES: usize = 1_048_576;
const MAX_GOALS: usize = 256;
const MAX_CLAUSES: usize = 10_000;
const MAX_SEARCH_STEPS: usize = 20_000;
const MAX_SEARCH_DEPTH: usize = 256;
const MAX_SEARCH_DURATION: Duration = Duration::from_secs(3);
const MAX_TOTAL_BODY_ATOMS: usize = 50_000;

/// Hard-bounded configuration for advisory backward reasoning.
#[derive(Debug, Clone, Copy)]
pub struct AdvisoryGoalConfig {
    pub search: SearchConfig,
    pub max_input_bytes: usize,
    pub max_goals: usize,
}

impl Default for AdvisoryGoalConfig {
    fn default() -> Self {
        Self {
            search: SearchConfig::default(),
            max_input_bytes: MAX_INPUT_BYTES,
            max_goals: MAX_GOALS,
        }
    }
}

/// A set of Horn clauses and goals submitted for bounded advisory proof search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdvisoryGoalRequest {
    pub clauses: Vec<HornClause>,
    pub goals: Vec<Atom>,
}

/// Result for one requested goal. Exhausted means the bounded search completed
/// without a proof; budget stops are explicitly partial and must not be read as
/// proof of impossibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryGoalResult {
    pub goal: Atom,
    pub report: SearchReport,
}

impl AdvisoryGoalResult {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.report.stop, SearchStop::Proven | SearchStop::Exhausted)
    }

    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.is_complete()
    }
}

/// All goal results from one in-process request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryGoalResponse {
    pub results: Vec<AdvisoryGoalResult>,
}

impl AdvisoryGoalResponse {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.results.iter().all(AdvisoryGoalResult::is_complete)
    }

    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.is_complete()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryGoalError {
    InvalidConfiguration,
    InputTooLarge,
    TooManyGoals,
    TooManyClauses,
    TooManyBodyAtoms,
    Search(SearchError),
}

/// Stateless adapter. It has no identity, policy, authorization, audit,
/// persistence, network, filesystem, or protected-effect capability.
#[derive(Debug, Clone, Copy)]
pub struct AdvisoryGoalAdapter {
    config: AdvisoryGoalConfig,
}

impl AdvisoryGoalAdapter {
    pub fn new(config: AdvisoryGoalConfig) -> Result<Self, AdvisoryGoalError> {
        if config.max_input_bytes == 0
            || config.max_input_bytes > MAX_INPUT_BYTES
            || config.max_goals == 0
            || config.max_goals > MAX_GOALS
            || config.search.max_steps == 0
            || config.search.max_steps > MAX_SEARCH_STEPS
            || config.search.max_depth == 0
            || config.search.max_depth > MAX_SEARCH_DEPTH
            || config.search.max_clauses == 0
            || config.search.max_clauses > MAX_CLAUSES
            || config.search.max_duration.is_zero()
            || config.search.max_duration > MAX_SEARCH_DURATION
        {
            return Err(AdvisoryGoalError::InvalidConfiguration);
        }
        Ok(Self { config })
    }

    pub fn run(
        &self,
        request: AdvisoryGoalRequest,
    ) -> Result<AdvisoryGoalResponse, AdvisoryGoalError> {
        if request.goals.len() > self.config.max_goals {
            return Err(AdvisoryGoalError::TooManyGoals);
        }
        if request.clauses.len() > self.config.search.max_clauses {
            return Err(AdvisoryGoalError::TooManyClauses);
        }

        let mut input_bytes = 0usize;
        let mut body_atoms = 0usize;
        for clause in &request.clauses {
            input_bytes = add_payload(input_bytes, clause.id.len(), self.config.max_input_bytes)?;
            input_bytes = add_payload(
                input_bytes,
                atom_bytes(&clause.head, self.config.max_input_bytes)?,
                self.config.max_input_bytes,
            )?;
            body_atoms = body_atoms.saturating_add(clause.body.len());
            if body_atoms > MAX_TOTAL_BODY_ATOMS {
                return Err(AdvisoryGoalError::TooManyBodyAtoms);
            }
            for atom in &clause.body {
                input_bytes = add_payload(
                    input_bytes,
                    atom_bytes(atom, self.config.max_input_bytes)?,
                    self.config.max_input_bytes,
                )?;
            }
        }
        for goal in &request.goals {
            input_bytes = add_payload(
                input_bytes,
                atom_bytes(goal, self.config.max_input_bytes)?,
                self.config.max_input_bytes,
            )?;
        }

        // BackwardReasoner starts a fresh deadline for each prove() call. Divide
        // the request budget across goals so a multi-goal request stays bounded.
        let mut search = self.config.search;
        if !request.goals.is_empty() {
            let per_goal_micros =
                (search.max_duration.as_micros() / request.goals.len() as u128).max(1);
            search.max_duration = Duration::from_micros(per_goal_micros as u64);
        }
        let mut reasoner = BackwardReasoner::new(search).map_err(AdvisoryGoalError::Search)?;
        for clause in request.clauses {
            reasoner
                .add_clause(clause)
                .map_err(AdvisoryGoalError::Search)?;
        }

        let mut results = Vec::with_capacity(request.goals.len());
        for goal in request.goals {
            let report = reasoner.prove(&goal).map_err(AdvisoryGoalError::Search)?;
            results.push(AdvisoryGoalResult { goal, report });
        }
        Ok(AdvisoryGoalResponse { results })
    }
}

const MAX_TERM_DEPTH: usize = 64;

fn add_payload(
    current: usize,
    additional: usize,
    limit: usize,
) -> Result<usize, AdvisoryGoalError> {
    let total = current.saturating_add(additional);
    if total > limit {
        return Err(AdvisoryGoalError::InputTooLarge);
    }
    Ok(total)
}

fn atom_bytes(atom: &Atom, limit: usize) -> Result<usize, AdvisoryGoalError> {
    let mut total = atom.predicate.len();
    if total > limit {
        return Err(AdvisoryGoalError::InputTooLarge);
    }
    for term in &atom.arguments {
        total = add_payload(total, term_bytes(term, 0, limit.saturating_sub(total))?, limit)?;
    }
    Ok(total)
}

fn term_bytes(
    term: &iroka_cognition::Term,
    depth: usize,
    limit: usize,
) -> Result<usize, AdvisoryGoalError> {
    use iroka_cognition::Term;
    if depth > MAX_TERM_DEPTH {
        return Err(AdvisoryGoalError::Search(SearchError::InvalidTerm));
    }
    match term {
        Term::Symbol(value) | Term::Variable(value) => add_payload(0, value.len(), limit),
        Term::Compound(name, args) => {
            let mut total = name.len();
            if total > limit {
                return Err(AdvisoryGoalError::InputTooLarge);
            }
            for arg in args {
                total = add_payload(
                    total,
                    term_bytes(arg, depth + 1, limit.saturating_sub(total))?,
                    limit,
                )?;
            }
            Ok(total)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroka_cognition::Term;

    fn symbol(value: &str) -> Term {
        Term::symbol(value)
    }

    fn variable(value: &str) -> Term {
        Term::variable(value)
    }

    fn atom(name: &str, args: Vec<Term>) -> Atom {
        Atom::new(name, args)
    }

    fn clause(id: &str, head: Atom, body: Vec<Atom>) -> HornClause {
        HornClause {
            id: id.into(),
            head,
            body,
        }
    }

    #[test]
    fn proves_goal_and_returns_proof_tree() {
        let adapter = AdvisoryGoalAdapter::new(AdvisoryGoalConfig::default()).unwrap();
        let response = adapter
            .run(AdvisoryGoalRequest {
                clauses: vec![
                    clause(
                        "human-socrates",
                        atom("human", vec![symbol("socrates")]),
                        vec![],
                    ),
                    clause(
                        "mortal-human",
                        atom("mortal", vec![variable("X")]),
                        vec![atom("human", vec![variable("X")])],
                    ),
                ],
                goals: vec![atom("mortal", vec![symbol("socrates")])],
            })
            .unwrap();

        assert!(response.is_complete());
        assert_eq!(response.results[0].report.stop, SearchStop::Proven);
        assert_eq!(
            response.results[0].report.proof.as_ref().unwrap().clause_id,
            "mortal-human"
        );
    }

    #[test]
    fn returns_variable_substitution_for_goal() {
        let adapter = AdvisoryGoalAdapter::new(AdvisoryGoalConfig::default()).unwrap();
        let response = adapter
            .run(AdvisoryGoalRequest {
                clauses: vec![clause(
                    "parent-fact",
                    atom("parent", vec![symbol("ana"), symbol("beka")]),
                    vec![],
                )],
                goals: vec![atom("parent", vec![variable("Who"), symbol("beka")])],
            })
            .unwrap();

        let substitution = response.results[0].report.substitution.as_ref().unwrap();
        assert_eq!(substitution.resolve(&variable("Who")), symbol("ana"));
    }

    #[test]
    fn reports_budget_stops_as_partial_not_exhausted() {
        let config = AdvisoryGoalConfig {
            search: SearchConfig {
                max_steps: 1,
                ..SearchConfig::default()
            },
            ..AdvisoryGoalConfig::default()
        };
        let adapter = AdvisoryGoalAdapter::new(config).unwrap();
        let response = adapter
            .run(AdvisoryGoalRequest {
                clauses: vec![
                    clause("a-unrelated", atom("other", vec![]), vec![]),
                    clause("z-target", atom("target", vec![]), vec![]),
                ],
                goals: vec![atom("target", vec![])],
            })
            .unwrap();

        assert!(response.is_partial());
        assert_eq!(response.results[0].report.stop, SearchStop::StepBudget);
    }

    #[test]
    fn enforces_aggregate_payload_limit() {
        let config = AdvisoryGoalConfig {
            max_input_bytes: 4,
            ..AdvisoryGoalConfig::default()
        };
        let adapter = AdvisoryGoalAdapter::new(config).unwrap();
        let result = adapter.run(AdvisoryGoalRequest {
            clauses: vec![clause("fact", atom("large", vec![]), vec![])],
            goals: vec![],
        });
        assert_eq!(result, Err(AdvisoryGoalError::InputTooLarge));
    }

    #[test]
    fn rejects_configuration_above_hard_search_ceilings() {
        let config = AdvisoryGoalConfig {
            search: SearchConfig {
                max_steps: MAX_SEARCH_STEPS + 1,
                ..SearchConfig::default()
            },
            ..AdvisoryGoalConfig::default()
        };
        assert_eq!(
            AdvisoryGoalAdapter::new(config).err(),
            Some(AdvisoryGoalError::InvalidConfiguration)
        );
    }

    #[test]
    fn enforces_goal_count_limit() {
        let config = AdvisoryGoalConfig {
            max_goals: 1,
            ..AdvisoryGoalConfig::default()
        };
        let adapter = AdvisoryGoalAdapter::new(config).unwrap();
        let result = adapter.run(AdvisoryGoalRequest {
            goals: vec![atom("a", vec![]), atom("b", vec![])],
            ..AdvisoryGoalRequest::default()
        });
        assert_eq!(result, Err(AdvisoryGoalError::TooManyGoals));
    }
}
