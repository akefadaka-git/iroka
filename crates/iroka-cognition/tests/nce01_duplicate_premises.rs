//! NCE-01 duplicate-premise contract tests.
//!
//! Duplicate premises are accepted and retained in caller order. Logically, a
//! conjunction is idempotent: requiring the same literal twice does not require
//! two separate copies of that fact. For resource accounting, however, every
//! supplied occurrence is retained and charged against per-rule and aggregate
//! premise budgets. Derivation witnesses preserve the accepted rule verbatim.

use iroka_cognition::{
    EngineConfig, EngineError, Literal, NativeReasoner, QueryResult, Rule, StopReason,
};

#[test]
fn duplicate_premises_are_logically_idempotent_and_preserved_in_witness() {
    let mut engine = NativeReasoner::new(EngineConfig::default()).unwrap();
    let premise = Literal::positive("evidence");
    engine.add_fact(premise.clone()).unwrap();
    engine
        .add_rule(Rule {
            id: "duplicate-premise-rule".into(),
            premises: vec![premise.clone(), premise.clone()],
            conclusion: Literal::positive("conclusion"),
        })
        .unwrap();

    let report = engine.reason();

    assert_eq!(report.stop_reason, StopReason::FixedPoint);
    assert_eq!(
        engine.query(&Literal::positive("conclusion")).unwrap(),
        QueryResult::Entailed
    );
    assert_eq!(report.derivations.len(), 1);
    assert_eq!(
        report.derivations[0].premises,
        vec![premise.clone(), premise]
    );
}

#[test]
fn duplicate_premises_do_not_create_evidence_when_the_literal_is_absent() {
    let mut engine = NativeReasoner::new(EngineConfig::default()).unwrap();
    let premise = Literal::positive("missing-evidence");
    let conclusion = Literal::positive("must-not-derive");
    engine
        .add_rule(Rule {
            id: "requires-the-same-evidence-twice".into(),
            premises: vec![premise.clone(), premise],
            conclusion: conclusion.clone(),
        })
        .unwrap();

    let report = engine.reason();

    assert_eq!(report.stop_reason, StopReason::FixedPoint);
    assert_eq!(engine.query(&conclusion).unwrap(), QueryResult::Unknown);
    assert!(report.derivations.is_empty());
}

#[test]
fn duplicate_occurrences_count_toward_aggregate_premise_budget() {
    let mut engine = NativeReasoner::new(EngineConfig::default()).unwrap();
    let repeated = Literal::positive("same-premise");

    // 195 * 256 = 49,920 retained premise occurrences.
    for index in 0..195 {
        engine
            .add_rule(Rule {
                id: format!("bulk-{index:03}"),
                premises: vec![repeated.clone(); 256],
                conclusion: Literal::positive(format!("bulk-conclusion-{index:03}")),
            })
            .unwrap();
    }

    // Reach the exact aggregate limit: 49,920 + 80 = 50,000.
    engine
        .add_rule(Rule {
            id: "aggregate-exact-limit".into(),
            premises: vec![repeated.clone(); 80],
            conclusion: Literal::positive("aggregate-exact-conclusion"),
        })
        .unwrap();

    // The next duplicate occurrence must be rejected; it is not deduplicated
    // merely because the literal value equals an existing premise.
    assert_eq!(
        engine.add_rule(Rule {
            id: "aggregate-one-over".into(),
            premises: vec![repeated],
            conclusion: Literal::positive("aggregate-over-conclusion"),
        }),
        Err(EngineError::RulePremiseTotalBudgetExceeded)
    );
}
