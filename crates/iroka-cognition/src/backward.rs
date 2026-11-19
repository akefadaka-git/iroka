//! Goal-directed Horn-clause reasoning with first-order unification.
//! Search is deterministic and bounded by time, steps and recursion depth.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Term {
    Symbol(String),
    Variable(String),
    Compound(String, Vec<Term>),
}

impl Term {
    pub fn symbol(value: impl Into<String>) -> Self {
        Self::Symbol(value.into())
    }
    pub fn variable(value: impl Into<String>) -> Self {
        Self::Variable(value.into())
    }
    pub fn compound(name: impl Into<String>, args: Vec<Term>) -> Self {
        Self::Compound(name.into(), args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Atom {
    pub predicate: String,
    pub arguments: Vec<Term>,
}

impl Atom {
    pub fn new(predicate: impl Into<String>, arguments: Vec<Term>) -> Self {
        Self {
            predicate: predicate.into(),
            arguments,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HornClause {
    pub id: String,
    pub head: Atom,
    pub body: Vec<Atom>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Substitution(BTreeMap<String, Term>);

impl Substitution {
    /// Returns the binding for a variable without exposing mutable map access.
    #[must_use]
    pub fn get(&self, variable: &str) -> Option<&Term> {
        self.0.get(variable)
    }

    /// Iterates over the variable bindings in deterministic key order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Term)> {
        self.0.iter()
    }
    #[must_use]
    pub fn resolve(&self, term: &Term) -> Term {
        match term {
            Term::Variable(name) => match self.0.get(name) {
                Some(value) if value != term => self.resolve(value),
                _ => term.clone(),
            },
            Term::Compound(name, args) => Term::Compound(
                name.clone(),
                args.iter().map(|arg| self.resolve(arg)).collect(),
            ),
            Term::Symbol(_) => term.clone(),
        }
    }

    #[must_use]
    pub fn apply(&self, atom: &Atom) -> Atom {
        Atom {
            predicate: atom.predicate.clone(),
            arguments: atom.arguments.iter().map(|arg| self.resolve(arg)).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub goal: Atom,
    pub clause_id: String,
    pub children: Vec<Proof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchStop {
    Proven,
    Exhausted,
    Deadline,
    StepBudget,
    DepthBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchReport {
    pub stop: SearchStop,
    pub substitution: Option<Substitution>,
    pub proof: Option<Proof>,
    pub steps: usize,
    pub elapsed_micros: u128,
}

#[derive(Debug, Clone, Copy)]
pub struct SearchConfig {
    pub max_steps: usize,
    pub max_depth: usize,
    pub max_clauses: usize,
    pub max_duration: Duration,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_steps: 20_000,
            max_depth: 64,
            max_clauses: 10_000,
            max_duration: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    EmptyClauseId,
    DuplicateClauseId,
    EmptyPredicate,
    InvalidTerm,
    ZeroBudget,
    ClauseBudgetExceeded,
    DepthBudgetTooLarge,
    DurationOutOfRange,
}

#[derive(Debug)]
struct SearchState {
    deadline: Instant,
    steps: usize,
    stop: Option<SearchStop>,
    fresh_id: u64,
}

pub struct BackwardReasoner {
    config: SearchConfig,
    clauses: Vec<HornClause>,
}

impl BackwardReasoner {
    /// Creates a backward reasoner with explicit execution limits.
    ///
    /// # Errors
    /// Returns [`SearchError::ZeroBudget`] if any configured limit is zero.
    pub fn new(config: SearchConfig) -> Result<Self, SearchError> {
        if config.max_steps == 0
            || config.max_depth == 0
            || config.max_clauses == 0
            || config.max_duration.is_zero()
        {
            return Err(SearchError::ZeroBudget);
        }
        if config.max_depth > MAX_SEARCH_DEPTH {
            return Err(SearchError::DepthBudgetTooLarge);
        }
        Ok(Self {
            config,
            clauses: Vec::new(),
        })
    }

    /// Adds a validated Horn clause while preserving deterministic rule order.
    ///
    /// # Errors
    /// Returns an error for an empty or duplicate clause ID, invalid atom, or invalid term.
    pub fn add_clause(&mut self, clause: HornClause) -> Result<(), SearchError> {
        if clause.id.trim().is_empty() {
            return Err(SearchError::EmptyClauseId);
        }
        if clause.body.len() > MAX_CLAUSE_BODY {
            return Err(SearchError::InvalidTerm);
        }
        if self.clauses.len() >= self.config.max_clauses {
            return Err(SearchError::ClauseBudgetExceeded);
        }
        if self.clauses.iter().any(|item| item.id == clause.id) {
            return Err(SearchError::DuplicateClauseId);
        }
        validate_atom(&clause.head)?;
        for atom in &clause.body {
            validate_atom(atom)?;
        }
        self.clauses.push(clause);
        self.clauses.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(())
    }

    /// Attempts to prove a goal and reports proof, exhaustion, or the exact budget stop.
    ///
    /// # Errors
    /// Returns [`SearchError::EmptyPredicate`] or [`SearchError::InvalidTerm`] for malformed goals.
    pub fn prove(&self, goal: &Atom) -> Result<SearchReport, SearchError> {
        validate_atom(goal)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(self.config.max_duration)
            .ok_or(SearchError::DurationOutOfRange)?;
        let mut state = SearchState {
            deadline,
            steps: 0,
            stop: None,
            fresh_id: 0,
        };
        let result = self.prove_inner(goal, &Substitution::default(), 0, &mut state);
        let stop = if result.is_some() {
            SearchStop::Proven
        } else {
            state.stop.unwrap_or(SearchStop::Exhausted)
        };
        let (substitution, proof) = match result {
            Some((substitution, proof)) => (Some(substitution), Some(proof)),
            None => (None, None),
        };
        Ok(SearchReport {
            stop,
            substitution,
            proof,
            steps: state.steps,
            elapsed_micros: started.elapsed().as_micros(),
        })
    }

    fn prove_inner(
        &self,
        goal: &Atom,
        substitution: &Substitution,
        depth: usize,
        state: &mut SearchState,
    ) -> Option<(Substitution, Proof)> {
        if state.stop.is_some() {
            return None;
        }
        if Instant::now() >= state.deadline {
            state.stop = Some(SearchStop::Deadline);
            return None;
        }
        if depth >= self.config.max_depth {
            state.stop = Some(SearchStop::DepthBudget);
            return None;
        }

        let resolved_goal = substitution.apply(goal);
        for original in &self.clauses {
            if Instant::now() >= state.deadline {
                state.stop = Some(SearchStop::Deadline);
                return None;
            }
            if state.steps >= self.config.max_steps {
                state.stop = Some(SearchStop::StepBudget);
                return None;
            }
            state.steps += 1;
            state.fresh_id += 1;
            let clause = freshen(original, state.fresh_id);
            let mut next = substitution.clone();
            if !unify_atoms(&resolved_goal, &clause.head, &mut next) {
                continue;
            }

            let mut children = Vec::new();
            let mut branch = next;
            let mut proved = true;
            for premise in &clause.body {
                if let Some((updated, proof)) = self.prove_inner(premise, &branch, depth + 1, state)
                {
                    branch = updated;
                    children.push(proof);
                } else {
                    proved = false;
                    break;
                }
            }
            if proved {
                let proof_goal = branch.apply(&resolved_goal);
                return Some((
                    branch,
                    Proof {
                        goal: proof_goal,
                        clause_id: clause.id,
                        children,
                    },
                ));
            }
            if state.stop.is_some() {
                return None;
            }
        }
        None
    }
}

fn freshen(clause: &HornClause, id: u64) -> HornClause {
    fn rename(term: &Term, id: u64) -> Term {
        match term {
            Term::Variable(name) => Term::Variable(format!("__{id}_{name}")),
            Term::Compound(name, args) => Term::Compound(
                name.clone(),
                args.iter().map(|arg| rename(arg, id)).collect(),
            ),
            Term::Symbol(_) => term.clone(),
        }
    }
    fn rename_atom(atom: &Atom, id: u64) -> Atom {
        Atom::new(
            atom.predicate.clone(),
            atom.arguments.iter().map(|t| rename(t, id)).collect(),
        )
    }
    HornClause {
        id: clause.id.clone(),
        head: rename_atom(&clause.head, id),
        body: clause.body.iter().map(|a| rename_atom(a, id)).collect(),
    }
}

fn unify_atoms(left: &Atom, right: &Atom, substitution: &mut Substitution) -> bool {
    left.predicate == right.predicate
        && left.arguments.len() == right.arguments.len()
        && left
            .arguments
            .iter()
            .zip(&right.arguments)
            .all(|(a, b)| unify_terms(a, b, substitution))
}

fn unify_terms(left: &Term, right: &Term, substitution: &mut Substitution) -> bool {
    let left = substitution.resolve(left);
    let right = substitution.resolve(right);
    if left == right {
        return true;
    }
    match (&left, &right) {
        (Term::Variable(name), value) | (value, Term::Variable(name)) => {
            bind(name, value, substitution)
        }
        (Term::Symbol(a), Term::Symbol(b)) => a == b,
        (Term::Compound(a, aa), Term::Compound(b, ba)) => {
            a == b
                && aa.len() == ba.len()
                && aa
                    .iter()
                    .zip(ba)
                    .all(|(x, y)| unify_terms(x, y, substitution))
        }
        _ => false,
    }
}

fn bind(name: &str, value: &Term, substitution: &mut Substitution) -> bool {
    if occurs(name, value, substitution) {
        return false;
    }
    substitution.0.insert(name.to_owned(), value.clone());
    true
}

fn occurs(name: &str, term: &Term, substitution: &Substitution) -> bool {
    match substitution.resolve(term) {
        Term::Variable(other) => name == other,
        Term::Compound(_, args) => args.iter().any(|arg| occurs(name, arg, substitution)),
        Term::Symbol(_) => false,
    }
}

const MAX_TERM_DEPTH: usize = 64;
const MAX_SEARCH_DEPTH: usize = 256;
const MAX_ATOM_ARITY: usize = 64;
const MAX_CLAUSE_BODY: usize = 128;

fn validate_atom(atom: &Atom) -> Result<(), SearchError> {
    if atom.predicate.trim().is_empty() || atom.predicate.len() > 128 {
        return Err(SearchError::EmptyPredicate);
    }
    if atom.arguments.len() > MAX_ATOM_ARITY {
        return Err(SearchError::InvalidTerm);
    }
    for term in &atom.arguments {
        validate_term_at_depth(term, 0)?;
    }
    Ok(())
}

fn validate_term_at_depth(term: &Term, depth: usize) -> Result<(), SearchError> {
    if depth > MAX_TERM_DEPTH {
        return Err(SearchError::InvalidTerm);
    }
    match term {
        Term::Symbol(value) | Term::Variable(value) => {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(SearchError::InvalidTerm);
            }
        }
        Term::Compound(name, args) => {
            if name.trim().is_empty() || name.len() > 128 || args.len() > MAX_ATOM_ARITY {
                return Err(SearchError::InvalidTerm);
            }
            for arg in args {
                validate_term_at_depth(arg, depth + 1)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(value: &str) -> Term {
        Term::symbol(value)
    }
    fn v(value: &str) -> Term {
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
    fn proves_socrates_is_mortal_by_backward_chaining() {
        let mut engine = BackwardReasoner::new(SearchConfig::default()).unwrap();
        engine
            .add_clause(clause(
                "human-fact",
                atom("human", vec![s("socrates")]),
                vec![],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "mortality-rule",
                atom("mortal", vec![v("X")]),
                vec![atom("human", vec![v("X")])],
            ))
            .unwrap();
        let report = engine.prove(&atom("mortal", vec![s("socrates")])).unwrap();
        assert_eq!(report.stop, SearchStop::Proven);
        assert!(report.proof.is_some());
    }

    #[test]
    fn unifies_compound_terms_and_returns_bindings() {
        let mut engine = BackwardReasoner::new(SearchConfig::default()).unwrap();
        engine
            .add_clause(clause(
                "parent",
                atom("parent", vec![s("ana"), s("beka")]),
                vec![],
            ))
            .unwrap();
        let report = engine
            .prove(&atom("parent", vec![v("Who"), s("beka")]))
            .unwrap();
        let bindings = report.substitution.unwrap();
        assert_eq!(bindings.resolve(&v("Who")), s("ana"));
    }

    #[test]
    fn proves_transitive_ancestor_through_recursive_rule() {
        let mut engine = BackwardReasoner::new(SearchConfig::default()).unwrap();
        engine
            .add_clause(clause(
                "parent-ab",
                atom("parent", vec![s("a"), s("b")]),
                vec![],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "parent-bc",
                atom("parent", vec![s("b"), s("c")]),
                vec![],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "ancestor-direct",
                atom("ancestor", vec![v("X"), v("Y")]),
                vec![atom("parent", vec![v("X"), v("Y")])],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "ancestor-recursive",
                atom("ancestor", vec![v("X"), v("Y")]),
                vec![
                    atom("parent", vec![v("X"), v("Z")]),
                    atom("ancestor", vec![v("Z"), v("Y")]),
                ],
            ))
            .unwrap();
        let report = engine
            .prove(&atom("ancestor", vec![s("a"), s("c")]))
            .unwrap();
        assert_eq!(report.stop, SearchStop::Proven);
        assert_eq!(report.proof.unwrap().children.len(), 2);
    }

    #[test]
    fn unifies_nested_compound_terms_and_returns_bindings() {
        let mut engine = BackwardReasoner::new(SearchConfig::default()).unwrap();
        engine
            .add_clause(clause(
                "nested-fact",
                atom(
                    "located",
                    vec![
                        Term::compound("pair", vec![s("ana"), s("beka")]),
                        s("confirmed"),
                    ],
                ),
                vec![],
            ))
            .unwrap();

        let report = engine
            .prove(&atom(
                "located",
                vec![
                    Term::compound("pair", vec![v("Who"), s("beka")]),
                    s("confirmed"),
                ],
            ))
            .unwrap();
        assert_eq!(report.stop, SearchStop::Proven);
        assert_eq!(report.substitution.unwrap().resolve(&v("Who")), s("ana"));
    }

    #[test]
    fn backtracks_after_an_unprovable_rule_branch() {
        let mut engine = BackwardReasoner::new(SearchConfig::default()).unwrap();
        engine
            .add_clause(clause(
                "a-dead-route",
                atom("route", vec![v("X")]),
                vec![atom("missing", vec![v("X")])],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "z-live-route",
                atom("route", vec![v("X")]),
                vec![atom("present", vec![v("X")])],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "present-ana",
                atom("present", vec![s("ana")]),
                vec![],
            ))
            .unwrap();

        let report = engine.prove(&atom("route", vec![s("ana")])).unwrap();
        assert_eq!(report.stop, SearchStop::Proven);
        assert_eq!(report.proof.unwrap().clause_id, "z-live-route");
    }

    #[test]
    fn rejects_excessively_deep_terms_before_recursive_search() {
        let mut term = s("leaf");
        for _ in 0..=MAX_TERM_DEPTH {
            term = Term::compound("nested", vec![term]);
        }
        let mut engine = BackwardReasoner::new(SearchConfig::default()).unwrap();
        assert_eq!(
            engine.add_clause(clause("too-deep", atom("deep", vec![term]), vec![])),
            Err(SearchError::InvalidTerm)
        );
    }

    #[test]
    fn fails_occurs_check_for_infinite_term() {
        let mut substitution = Substitution::default();
        let x = v("X");
        let fx = Term::compound("f", vec![x.clone()]);
        assert!(!unify_terms(&x, &fx, &mut substitution));
    }

    #[test]
    fn reports_step_budget_instead_of_claiming_no_proof() {
        let config = SearchConfig {
            max_steps: 1,
            ..SearchConfig::default()
        };
        let mut engine = BackwardReasoner::new(config).unwrap();
        engine
            .add_clause(clause("a-unrelated", atom("other", vec![s("x")]), vec![]))
            .unwrap();
        engine
            .add_clause(clause("z-target", atom("target", vec![s("x")]), vec![]))
            .unwrap();
        let report = engine.prove(&atom("target", vec![s("x")])).unwrap();
        assert_eq!(report.stop, SearchStop::StepBudget);
    }

    #[test]
    fn reports_depth_budget_instead_of_claiming_no_proof() {
        let config = SearchConfig {
            max_depth: 1,
            ..SearchConfig::default()
        };
        let mut engine = BackwardReasoner::new(config).unwrap();
        engine
            .add_clause(clause(
                "a-parent",
                atom("parent", vec![s("a"), s("b")]),
                vec![],
            ))
            .unwrap();
        engine
            .add_clause(clause(
                "z-ancestor",
                atom("ancestor", vec![v("X"), v("Y")]),
                vec![atom("parent", vec![v("X"), v("Y")])],
            ))
            .unwrap();
        let report = engine
            .prove(&atom("ancestor", vec![s("a"), s("b")]))
            .unwrap();
        assert_eq!(report.stop, SearchStop::DepthBudget);
    }

    #[test]
    fn enforces_clause_count_budget() {
        let config = SearchConfig {
            max_clauses: 1,
            ..SearchConfig::default()
        };
        let mut engine = BackwardReasoner::new(config).unwrap();
        engine
            .add_clause(clause("first", atom("first", vec![]), vec![]))
            .unwrap();
        assert_eq!(
            engine.add_clause(clause("second", atom("second", vec![]), vec![])),
            Err(SearchError::ClauseBudgetExceeded)
        );
    }

    #[test]
    fn rejects_excessive_search_depth_configuration() {
        let config = SearchConfig {
            max_depth: MAX_SEARCH_DEPTH + 1,
            ..SearchConfig::default()
        };
        assert_eq!(
            BackwardReasoner::new(config).err(),
            Some(SearchError::DepthBudgetTooLarge)
        );
    }

    #[test]
    fn rejects_duration_that_cannot_be_represented_as_a_deadline() {
        let config = SearchConfig {
            max_duration: Duration::MAX,
            ..SearchConfig::default()
        };
        let engine = BackwardReasoner::new(config).unwrap();
        assert_eq!(
            engine.prove(&atom("goal", vec![])),
            Err(SearchError::DurationOutOfRange)
        );
    }

    #[test]
    fn rejects_zero_search_budgets() {
        let config = SearchConfig {
            max_steps: 0,
            ..SearchConfig::default()
        };
        assert_eq!(
            BackwardReasoner::new(config).err(),
            Some(SearchError::ZeroBudget)
        );
    }

    #[test]
    fn rejects_recursive_unification_cycles() {
        let mut substitution = Substitution::default();
        assert!(!unify_terms(
            &v("X"),
            &Term::compound("g", vec![v("X")]),
            &mut substitution
        ));
    }
}
