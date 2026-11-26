//! Bounded finite-domain integer constraint solving for NCE-03.
//! Exact checked arithmetic, deterministic depth-first search and verified results.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const MAX_VARIABLES: usize = 128;
const MAX_CONSTRAINTS: usize = 512;
const MAX_TERMS: usize = 256;
const MAX_DOMAIN: u128 = 1_000_000;
const MAX_TOTAL_DOMAIN: u128 = 1_000_000;
const MAX_NODES: u64 = 100_000;
const MAX_PROPAGATION: u64 = 1_000_000;
const MAX_DURATION: Duration = Duration::from_secs(3);
const MAX_ID_BYTES: usize = 128;
const MAX_MODEL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntVariable { pub id: String, pub lower: i64, pub upper: i64 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearTerm { pub variable: String, pub coefficient: i64 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearExpr { pub constant: i64, pub terms: Vec<LinearTerm> }
impl LinearExpr {
    #[must_use]
    pub fn constant(value: i64) -> Self { Self { constant: value, terms: Vec::new() } }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation { Equal, NotEqual, LessOrEqual, GreaterOrEqual }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint { pub expression: LinearExpr, pub relation: Relation }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectiveDirection { Minimize, Maximize }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objective { pub expression: LinearExpr, pub direction: ObjectiveDirection }
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConstraintModel {
    pub variables: Vec<IntVariable>,
    pub constraints: Vec<Constraint>,
    pub objective: Option<Objective>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstraintSolverConfig {
    pub max_search_nodes: u64,
    pub max_propagation_ops: u64,
    pub max_duration: Duration,
}
impl Default for ConstraintSolverConfig {
    fn default() -> Self {
        Self { max_search_nodes: MAX_NODES, max_propagation_ops: MAX_PROPAGATION, max_duration: MAX_DURATION }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintError {
    EmptyVariableId, VariableIdTooLong, DuplicateVariableId, InvalidDomain,
    VariableLimitExceeded, ConstraintLimitExceeded, TooManyTerms,
    UnknownVariable, DuplicateTermVariable, ModelTooLarge, DomainTooLarge,
    ArithmeticOverflow, ZeroBudget, ConfigLimitExceeded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolveStatus { Satisfied, Infeasible, Optimal, FeasibleNotProvenOptimal, UnknownBudget }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolveStopReason { Complete, SearchNodeBudget, PropagationBudget, Deadline }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolveResult {
    pub status: SolveStatus,
    pub stop_reason: SolveStopReason,
    pub assignment: Option<Vec<(String, i64)>>,
    pub objective_value: Option<i128>,
    pub search_nodes: u64,
    pub propagation_ops: u64,
    pub elapsed_micros: u128,
    pub is_complete: bool,
    pub is_optimal: bool,
}
#[derive(Debug, Clone)]
struct Term { variable: usize, coefficient: i64 }
#[derive(Debug, Clone)]
struct Expr { constant: i64, terms: Vec<Term> }
#[derive(Debug, Clone)]
struct NormalizedConstraint { expression: Expr, relation: Relation }
#[derive(Debug, Clone)]
struct NormalizedObjective { expression: Expr, direction: ObjectiveDirection }
#[derive(Debug)]
struct State {
    domains: Vec<(i64, i64)>, nodes: u64, propagation: u64,
    started: Instant, stop: Option<SolveStopReason>,
    incumbent: Option<Vec<i64>>, incumbent_value: Option<i128>,
}

pub struct ConstraintSolver { config: ConstraintSolverConfig }
impl Default for ConstraintSolver {
    fn default() -> Self { Self { config: ConstraintSolverConfig::default() } }
}
impl ConstraintSolver {
    /// Constructs a solver; caller limits cannot exceed the frozen hard ceilings.
    pub fn new(config: ConstraintSolverConfig) -> Result<Self, ConstraintError> {
        if config.max_search_nodes == 0 || config.max_propagation_ops == 0 || config.max_duration.is_zero() {
            return Err(ConstraintError::ZeroBudget);
        }
        if config.max_search_nodes > MAX_NODES || config.max_propagation_ops > MAX_PROPAGATION || config.max_duration > MAX_DURATION {
            return Err(ConstraintError::ConfigLimitExceeded);
        }
        Ok(Self { config })
    }

    /// Solves a model. The semantic input byte cap does not bound allocations made by the caller.
    pub fn solve(&self, model: &ConstraintModel) -> Result<SolveResult, ConstraintError> {
        let (variables, constraints, objective) = normalize(model)?;
        let started = Instant::now();
        let mut state = State {
            domains: variables.iter().map(|v| (v.lower, v.upper)).collect(),
            nodes: 0, propagation: 0, started, stop: None,
            incumbent: None, incumbent_value: None,
        };
        self.search(&variables, &constraints, objective.as_ref(), &mut state);
        let complete = state.stop.is_none();
        let stop_reason = state.stop.unwrap_or(SolveStopReason::Complete);
        let assignment = state.incumbent.as_ref().map(|values| variables.iter().zip(values)
            .map(|(v, value)| (v.id.clone(), *value)).collect());
        if let Some(values) = &state.incumbent {
            verify(&variables, &constraints, objective.as_ref(), values)?;
        }
        let status = match (complete, assignment.is_some(), objective.is_some()) {
            (true, false, _) => SolveStatus::Infeasible,
            (true, true, false) => SolveStatus::Satisfied,
            (true, true, true) => SolveStatus::Optimal,
            (false, true, true) => SolveStatus::FeasibleNotProvenOptimal,
            (false, true, false) => SolveStatus::Satisfied,
            (false, false, _) => SolveStatus::UnknownBudget,
        };
        Ok(SolveResult {
            status, stop_reason, assignment, objective_value: state.incumbent_value,
            search_nodes: state.nodes, propagation_ops: state.propagation,
            elapsed_micros: started.elapsed().as_micros(), is_complete: complete,
            is_optimal: complete && objective.is_some() && state.incumbent.is_some(),
        })
    }

    fn search(&self, vars: &[IntVariable], constraints: &[NormalizedConstraint],
        objective: Option<&NormalizedObjective>, state: &mut State) {
        if self.deadline(state) { return; }
        if state.nodes >= self.config.max_search_nodes {
            state.stop = Some(SolveStopReason::SearchNodeBudget); return;
        }
        state.nodes += 1;
        if !self.propagate(constraints, state) { return; }
        let selected = state.domains.iter().enumerate()
            .filter(|(_, (lo, hi))| lo < hi)
            .min_by_key(|(i, (lo, hi))| (u128::try_from(*hi as i128 - *lo as i128 + 1).unwrap_or(u128::MAX), *i))
            .map(|(i, _)| i);
        let Some(index) = selected else {
            let values: Vec<i64> = state.domains.iter().map(|(lo, _)| *lo).collect();
            if verify(vars, constraints, objective, &values).is_err() { return; }
            let candidate = objective.map(|o| evaluate(&o.expression, &values)).transpose();
            let candidate = match candidate { Ok(v) => v, Err(_) => { state.stop = Some(SolveStopReason::Deadline); return; } };
            let replace = match (objective, state.incumbent_value, candidate) {
                (None, _, _) => state.incumbent.is_none(),
                (Some(o), Some(old), Some(new)) => match o.direction {
                    ObjectiveDirection::Minimize => new < old,
                    ObjectiveDirection::Maximize => new > old,
                },
                (Some(_), None, Some(_)) => true,
                _ => false,
            };
            if replace { state.incumbent = Some(values); state.incumbent_value = candidate; }
            return;
        };
        let (lo, hi) = state.domains[index];
        let mut value = lo;
        loop {
            if self.deadline(state) { break; }
            state.domains[index] = (value, value);
            self.search(vars, constraints, objective, state);
            if state.stop.is_some() || value == hi { break; }
            value = match value.checked_add(1) {
                Some(v) => v, None => { state.stop = Some(SolveStopReason::Deadline); break; }
            };
        }
        state.domains[index] = (lo, hi);
    }

    // Each constraint interval evaluation counts as one propagation operation.
    // It prunes impossible nodes; it never narrows a domain unsafely.
    fn propagate(&self, constraints: &[NormalizedConstraint], state: &mut State) -> bool {
        for c in constraints {
            if self.deadline(state) { return false; }
            if state.propagation >= self.config.max_propagation_ops {
                state.stop = Some(SolveStopReason::PropagationBudget); return false;
            }
            state.propagation += 1;
            let (min, max) = match bounds(&c.expression, &state.domains) {
                Ok(v) => v, Err(_) => { state.stop = Some(SolveStopReason::Deadline); return false; }
            };
            let possible = match c.relation {
                Relation::Equal => min <= 0 && max >= 0,
                Relation::NotEqual => min > 0 || max < 0,
                Relation::LessOrEqual => min <= 0,
                Relation::GreaterOrEqual => max >= 0,
            };
            if !possible { return false; }
        }
        true
    }
    fn deadline(&self, state: &mut State) -> bool {
        if state.started.elapsed() >= self.config.max_duration {
            state.stop = Some(SolveStopReason::Deadline); true
        } else { false }
    }
}

fn normalize(model: &ConstraintModel) -> Result<(Vec<IntVariable>, Vec<NormalizedConstraint>, Option<NormalizedObjective>), ConstraintError> {
    if model.variables.len() > MAX_VARIABLES { return Err(ConstraintError::VariableLimitExceeded); }
    if model.constraints.len() > MAX_CONSTRAINTS { return Err(ConstraintError::ConstraintLimitExceeded); }
    let mut bytes = 0usize;
    let mut ids = BTreeSet::new();
    let mut total = 0u128;
    for v in &model.variables {
        if v.id.trim().is_empty() { return Err(ConstraintError::EmptyVariableId); }
        if v.id.len() > MAX_ID_BYTES { return Err(ConstraintError::VariableIdTooLong); }
        if !ids.insert(v.id.as_str()) { return Err(ConstraintError::DuplicateVariableId); }
        if v.lower > v.upper { return Err(ConstraintError::InvalidDomain); }
        let size = u128::try_from(v.upper as i128 - v.lower as i128 + 1).map_err(|_| ConstraintError::DomainTooLarge)?;
        if size > MAX_DOMAIN { return Err(ConstraintError::DomainTooLarge); }
        total = total.checked_add(size).ok_or(ConstraintError::DomainTooLarge)?;
        bytes = bytes.checked_add(v.id.len() + 16).ok_or(ConstraintError::ModelTooLarge)?;
    }
    if total > MAX_TOTAL_DOMAIN { return Err(ConstraintError::DomainTooLarge); }
    let mut cs = Vec::with_capacity(model.constraints.len());
    for c in &model.constraints {
        cs.push(NormalizedConstraint { expression: normalize_expr(&c.expression, model, &mut bytes)?, relation: c.relation });
        bytes = bytes.checked_add(1).ok_or(ConstraintError::ModelTooLarge)?;
    }
    let full_domains: Vec<(i64, i64)> = model.variables.iter().map(|v| (v.lower, v.upper)).collect();
    for constraint in &cs { let _ = bounds(&constraint.expression, &full_domains)?; }
    let objective = model.objective.as_ref().map(|o| normalize_expr(&o.expression, model, &mut bytes)
        .map(|expression| NormalizedObjective { expression, direction: o.direction })).transpose()?;
    if let Some(item) = &objective { let _ = bounds(&item.expression, &full_domains)?; }
    if bytes > MAX_MODEL_BYTES { return Err(ConstraintError::ModelTooLarge); }
    Ok((model.variables.clone(), cs, objective))
}
fn normalize_expr(expr: &LinearExpr, model: &ConstraintModel, bytes: &mut usize) -> Result<Expr, ConstraintError> {
    if expr.terms.len() > MAX_TERMS { return Err(ConstraintError::TooManyTerms); }
    *bytes = bytes.checked_add(8 + expr.terms.len().checked_mul(16).ok_or(ConstraintError::ModelTooLarge)?)
        .ok_or(ConstraintError::ModelTooLarge)?;
    if *bytes > MAX_MODEL_BYTES { return Err(ConstraintError::ModelTooLarge); }
    let mut seen = BTreeSet::new();
    let mut terms = Vec::with_capacity(expr.terms.len());
    for term in &expr.terms {
        let index = model.variables.iter().position(|v| v.id == term.variable).ok_or(ConstraintError::UnknownVariable)?;
        if !seen.insert(index) { return Err(ConstraintError::DuplicateTermVariable); }
        terms.push(Term { variable: index, coefficient: term.coefficient });
    }
    terms.sort_by_key(|t| t.variable);
    Ok(Expr { constant: expr.constant, terms })
}
fn bounds(expr: &Expr, domains: &[(i64, i64)]) -> Result<(i128, i128), ConstraintError> {
    let (mut min, mut max) = (i128::from(expr.constant), i128::from(expr.constant));
    for t in &expr.terms {
        let (lo, hi) = domains[t.variable];
        let c = i128::from(t.coefficient);
        let (a, b) = if c >= 0 { (i128::from(lo), i128::from(hi)) } else { (i128::from(hi), i128::from(lo)) };
        min = min.checked_add(c.checked_mul(a).ok_or(ConstraintError::ArithmeticOverflow)?).ok_or(ConstraintError::ArithmeticOverflow)?;
        max = max.checked_add(c.checked_mul(b).ok_or(ConstraintError::ArithmeticOverflow)?).ok_or(ConstraintError::ArithmeticOverflow)?;
    }
    Ok((min, max))
}
fn evaluate(expr: &Expr, values: &[i64]) -> Result<i128, ConstraintError> {
    let mut total = i128::from(expr.constant);
    for t in &expr.terms {
        total = total.checked_add(i128::from(t.coefficient).checked_mul(i128::from(values[t.variable]))
            .ok_or(ConstraintError::ArithmeticOverflow)?).ok_or(ConstraintError::ArithmeticOverflow)?;
    }
    Ok(total)
}
fn verify(vars: &[IntVariable], cs: &[NormalizedConstraint], objective: Option<&NormalizedObjective>, values: &[i64]) -> Result<(), ConstraintError> {
    if values.len() != vars.len() { return Err(ConstraintError::InvalidDomain); }
    for (v, value) in vars.iter().zip(values) {
        if *value < v.lower || *value > v.upper { return Err(ConstraintError::InvalidDomain); }
    }
    for c in cs {
        let n = evaluate(&c.expression, values)?;
        let ok = match c.relation {
            Relation::Equal => n == 0, Relation::NotEqual => n != 0,
            Relation::LessOrEqual => n <= 0, Relation::GreaterOrEqual => n >= 0,
        };
        if !ok { return Err(ConstraintError::InvalidDomain); }
    }
    if let Some(o) = objective { let _ = evaluate(&o.expression, values)?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(id: &str, lo: i64, hi: i64) -> IntVariable { IntVariable { id: id.into(), lower: lo, upper: hi } }
    fn e(k: i64, terms: &[(&str, i64)]) -> LinearExpr {
        LinearExpr { constant: k, terms: terms.iter().map(|(variable, coefficient)| LinearTerm { variable: (*variable).into(), coefficient: *coefficient }).collect() }
    }
    #[test]
    fn solves_exact_integer_equality() {
        let m = ConstraintModel { variables: vec![v("x", -3, 3)], constraints: vec![Constraint { expression: e(-2, &[("x", 1)]), relation: Relation::Equal }], objective: None };
        let r = ConstraintSolver::default().solve(&m).unwrap();
        assert_eq!(r.status, SolveStatus::Satisfied);
        assert_eq!(r.assignment, Some(vec![("x".into(), 2)]));
    }
    #[test]
    fn proves_infeasibility_only_after_exhaustion() {
        let m = ConstraintModel { variables: vec![v("x", 0, 2)], constraints: vec![Constraint { expression: e(-4, &[("x", 1)]), relation: Relation::Equal }], objective: None };
        let r = ConstraintSolver::default().solve(&m).unwrap();
        assert_eq!(r.status, SolveStatus::Infeasible);
        assert!(r.is_complete);
    }
    #[test]
    fn minimizes_and_maximizes() {
        let min = ConstraintModel { variables: vec![v("x", -5, 5)], constraints: vec![Constraint { expression: e(-2, &[("x", 1)]), relation: Relation::GreaterOrEqual }], objective: Some(Objective { expression: e(0, &[("x", 1)]), direction: ObjectiveDirection::Minimize }) };
        let r = ConstraintSolver::default().solve(&min).unwrap();
        assert_eq!(r.status, SolveStatus::Optimal);
        assert_eq!(r.objective_value, Some(2));
        let max = ConstraintModel { variables: vec![v("x", -2, 3)], objective: Some(Objective { expression: e(0, &[("x", -2)]), direction: ObjectiveDirection::Maximize }), ..ConstraintModel::default() };
        assert_eq!(ConstraintSolver::default().solve(&max).unwrap().objective_value, Some(4));
    }
    #[test]
    fn rejects_duplicate_and_unknown_terms() {
        let duplicate = ConstraintModel { variables: vec![v("x", 0, 1)], constraints: vec![Constraint { expression: e(0, &[("x", 1), ("x", 2)]), relation: Relation::Equal }], objective: None };
        assert_eq!(ConstraintSolver::default().solve(&duplicate), Err(ConstraintError::DuplicateTermVariable));
        let unknown = ConstraintModel { variables: vec![v("x", 0, 1)], constraints: vec![Constraint { expression: e(0, &[("y", 1)]), relation: Relation::Equal }], objective: None };
        assert_eq!(ConstraintSolver::default().solve(&unknown), Err(ConstraintError::UnknownVariable));
    }
    #[test]
    fn budget_stop_never_claims_optimality() {
        let config = ConstraintSolverConfig { max_search_nodes: 2, ..ConstraintSolverConfig::default() };
        let m = ConstraintModel { variables: vec![v("x", 0, 5)], objective: Some(Objective { expression: e(0, &[("x", 1)]), direction: ObjectiveDirection::Maximize }), ..ConstraintModel::default() };
        let r = ConstraintSolver::new(config).unwrap().solve(&m).unwrap();
        assert_eq!(r.status, SolveStatus::FeasibleNotProvenOptimal);
        assert!(!r.is_optimal);
    }
    #[test]
    fn validates_all_four_relations() {
        for relation in [Relation::Equal, Relation::NotEqual, Relation::LessOrEqual, Relation::GreaterOrEqual] {
            let m = ConstraintModel { variables: vec![v("x", 0, 2)], constraints: vec![Constraint { expression: e(0, &[("x", 1)]), relation }], objective: None };
            assert!(ConstraintSolver::default().solve(&m).unwrap().assignment.is_some());
        }
    }
    #[test]
    fn rejects_domain_over_hard_ceiling() {
        let m = ConstraintModel { variables: vec![v("x", 0, 1_000_000)], ..ConstraintModel::default() };
        assert_eq!(ConstraintSolver::default().solve(&m), Err(ConstraintError::DomainTooLarge));
    }
    #[test]
    fn reports_unknown_budget_without_incumbent() {
        let config = ConstraintSolverConfig { max_search_nodes: 1, ..ConstraintSolverConfig::default() };
        let m = ConstraintModel {
            variables: vec![v("x", 0, 3)],
            constraints: vec![Constraint { expression: e(-3, &[("x", 1)]), relation: Relation::Equal }],
            objective: None,
        };
        let r = ConstraintSolver::new(config).unwrap().solve(&m).unwrap();
        assert_eq!(r.status, SolveStatus::UnknownBudget);
        assert!(!r.is_complete);
    }

    #[test]
    fn reports_checked_i128_overflow_as_model_error() {
        let m = ConstraintModel {
            variables: vec![v("x", i64::MAX - 1, i64::MAX), v("y", i64::MAX - 1, i64::MAX)],
            constraints: vec![Constraint {
                expression: e(0, &[("x", i64::MAX), ("y", i64::MAX)]),
                relation: Relation::Equal,
            }],
            objective: None,
        };
        assert_eq!(ConstraintSolver::default().solve(&m), Err(ConstraintError::ArithmeticOverflow));
    }

    #[test]
    fn disequality_prunes_only_when_zero_is_outside_interval() {
        let m = ConstraintModel {
            variables: vec![v("x", 0, 2)],
            constraints: vec![Constraint { expression: e(0, &[("x", 1)]), relation: Relation::NotEqual }],
            objective: None,
        };
        let r = ConstraintSolver::default().solve(&m).unwrap();
        assert_eq!(r.assignment, Some(vec![("x".into(), 1)]));
    }

}
