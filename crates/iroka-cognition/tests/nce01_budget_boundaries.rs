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

#[test]
fn fact_budget_exhaustion_stays_partial_and_never_emits_a_false_witness() {
    let config = EngineConfig {
        max_facts: 1,
        ..EngineConfig::default()
    };
    let mut engine = NativeReasoner::new(config).unwrap();
    let seed = Literal::positive("single-slot-seed");
    let blocked = Literal::positive("must-not-be-inserted");
    engine.add_fact(seed.clone()).unwrap();
    engine
        .add_rule(iroka_cognition::Rule {
            id: "blocked-derivation".into(),
            premises: vec![seed.clone()],
            conclusion: blocked.clone(),
        })
        .unwrap();

    for _ in 0..3 {
        let report = engine.reason();
        assert_eq!(report.stop_reason, StopReason::FactBudget);
        assert!(report.is_partial());
        assert!(!report.is_complete());
        assert_eq!(report.facts, vec![seed.clone()]);
        assert!(!report.facts.contains(&blocked));
        assert!(report.derivations.is_empty());
    }
}

#[test]
fn malformed_late_iterator_item_rejects_rule_atomically() {
    use std::cell::Cell;

    let mut engine = NativeReasoner::new(EngineConfig::default()).unwrap();
    let consumed = Cell::new(0usize);
    let premises = [
        Literal::positive("valid-prefix"),
        Literal::positive(" "),
        Literal::positive("must-not-be-consumed"),
    ]
    .into_iter()
    .inspect(|_| consumed.set(consumed.get() + 1));

    assert_eq!(
        engine.add_rule_from_iter(
            "reusable-after-invalid-input",
            premises,
            Literal::positive("conclusion")
        ),
        Err(EngineError::EmptyAtom)
    );
    assert_eq!(consumed.get(), 2);

    // The rejected prefix was never retained and the ID was not reserved.
    engine
        .add_rule_from_iter(
            "reusable-after-invalid-input",
            [Literal::positive("valid-premise")],
            Literal::positive("conclusion"),
        )
        .unwrap();
}
