//! NCE-01 negative-literal query semantics.
//!
//! Query polarity is symmetric: querying a negative literal treats explicit
//! negative evidence as positive evidence for that query and the positive
//! literal as its complement. Absence is never interpreted as evidence.

use iroka_cognition::{EngineConfig, Literal, NativeReasoner, QueryResult, Rule};

fn engine_with_facts(facts: &[Literal]) -> NativeReasoner {
    let mut engine = NativeReasoner::new(EngineConfig::default()).unwrap();
    for fact in facts {
        engine.add_fact(fact.clone()).unwrap();
    }
    engine
}

#[test]
fn negative_query_is_entailed_by_explicit_negative_evidence() {
    let query = Literal::negative("door_open");
    let engine = engine_with_facts(std::slice::from_ref(&query));
    assert_eq!(engine.query(&query).unwrap(), QueryResult::Entailed);
}

#[test]
fn negative_query_is_refuted_by_positive_complement_only() {
    let query = Literal::negative("door_open");
    let engine = engine_with_facts(&[Literal::positive("door_open")]);
    assert_eq!(engine.query(&query).unwrap(), QueryResult::Refuted);
}

#[test]
fn negative_query_is_contradicted_when_both_polarities_are_present() {
    let query = Literal::negative("door_open");
    let engine = engine_with_facts(&[
        Literal::negative("door_open"),
        Literal::positive("door_open"),
    ]);
    assert_eq!(engine.query(&query).unwrap(), QueryResult::Contradicted);
}

#[test]
fn negative_query_is_unknown_when_neither_polarity_is_present() {
    let query = Literal::negative("door_open");
    let engine = engine_with_facts(&[]);
    assert_eq!(engine.query(&query).unwrap(), QueryResult::Unknown);
}

#[test]
fn negative_query_can_be_entailed_by_a_rule_derived_negative_literal() {
    let mut engine = engine_with_facts(&[Literal::positive("sensor_fault")]);
    engine
        .add_rule(Rule {
            id: "fault_implies_door_sensor_unreliable".into(),
            premises: vec![Literal::positive("sensor_fault")],
            conclusion: Literal::negative("door_open"),
        })
        .unwrap();
    let report = engine.reason();
    assert!(report.is_complete());
    assert_eq!(
        engine.query(&Literal::negative("door_open")).unwrap(),
        QueryResult::Entailed
    );
}
