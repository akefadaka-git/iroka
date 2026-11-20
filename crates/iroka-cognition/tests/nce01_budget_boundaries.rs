//! NCE-01 inclusive resource-boundary regression tests.

use std::time::Duration;

use iroka_cognition::{EngineConfig, EngineError, Literal, NativeReasoner, StopReason};

#[test]
fn accepts_configuration_at_every_hard_resource_ceiling() {
    let config = EngineConfig {
        max_inference_steps: 10_000,
        max_facts: 10_000,
        max_rules: 2_000,
        max_rule_premises: 256,
        max_duration: Duration::from_secs(3),
        max_sources_per_fact: 32,
    };

    assert!(NativeReasoner::new(config).is_ok());
}

#[test]
fn source_budget_accepts_exact_limit_and_rejects_one_over_atomically() {
    let config = EngineConfig {
        max_sources_per_fact: 2,
        ..EngineConfig::default()
    };
    let mut engine = NativeReasoner::new(config).unwrap();
    let fact = Literal::positive("bounded-source-fact");

    engine
        .add_fact_with_source(fact.clone(), "source-a")
        .unwrap();
    engine
        .add_fact_with_source(fact.clone(), "source-b")
        .unwrap();

    // Replaying an existing source is idempotent at capacity.
    engine
        .add_fact_with_source(fact.clone(), "source-b")
        .unwrap();

    assert_eq!(
        engine.add_fact_with_source(fact.clone(), "source-c"),
        Err(EngineError::FactSourceBudgetExceeded)
    );

    let report = engine.reason();
    assert_eq!(report.stop_reason, StopReason::FixedPoint);
    assert_eq!(report.asserted_facts.len(), 2);
    assert!(report
        .asserted_facts
        .iter()
        .all(|assertion| assertion.fact == fact));
    assert_eq!(
        report
            .asserted_facts
            .iter()
            .filter_map(|assertion| assertion.source_id.as_deref())
            .collect::<Vec<_>>(),
        vec!["source-a", "source-b"]
    );
}
