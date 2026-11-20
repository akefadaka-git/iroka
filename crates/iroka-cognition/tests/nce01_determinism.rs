//! NCE-01 deterministic report behavior under insertion-order variation.

use iroka_cognition::{EngineConfig, Literal, NativeReasoner, Rule};

fn fixture(reverse: bool) -> NativeReasoner {
    fixture_with_config(reverse, EngineConfig::default())
}

fn fixture_with_config(reverse: bool, config: EngineConfig) -> NativeReasoner {
    let mut engine = NativeReasoner::new(config).unwrap();
    let facts = [Literal::positive("seed_a"), Literal::positive("seed_b")];
    let rules = [
        Rule {
            id: "r-a".into(),
            premises: vec![Literal::positive("seed_a")],
            conclusion: Literal::positive("middle"),
        },
        Rule {
            id: "r-b".into(),
            premises: vec![Literal::positive("seed_b")],
            conclusion: Literal::positive("middle"),
        },
        Rule {
            id: "r-c".into(),
            premises: vec![Literal::positive("middle")],
            conclusion: Literal::negative("safe"),
        },
        Rule {
            id: "r-d".into(),
            premises: vec![Literal::positive("seed_a")],
            conclusion: Literal::positive("safe"),
        },
        Rule {
            id: "r-e".into(),
            premises: vec![Literal::negative("safe")],
            conclusion: Literal::positive("alert"),
        },
    ];

    if reverse {
        for fact in facts.into_iter().rev() {
            engine.add_fact(fact).unwrap();
        }
        for rule in rules.into_iter().rev() {
            engine.add_rule(rule).unwrap();
        }
    } else {
        for fact in facts {
            engine.add_fact(fact).unwrap();
        }
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
    }
    engine
}

#[test]
fn facts_contradictions_and_derivation_witnesses_are_insertion_order_invariant() {
    let mut forward = fixture(false);
    let mut reverse = fixture(true);

    let left = forward.reason();
    let right = reverse.reason();

    assert!(left.is_complete());
    assert!(right.is_complete());
    assert_eq!(left.facts, right.facts);
    assert_eq!(left.contradictions, right.contradictions);
    assert_eq!(left.asserted_facts, right.asserted_facts);
    assert_eq!(left.derivations, right.derivations);
    assert_eq!(left.inference_steps, right.inference_steps);
    assert_eq!(left.stop_reason, right.stop_reason);
}

#[test]
fn repeated_step_bounded_calls_resume_fairly_until_fixed_point() {
    let config = EngineConfig {
        max_inference_steps: 1,
        ..EngineConfig::default()
    };
    let mut engine = NativeReasoner::new(config).unwrap();
    let a = Literal::positive("a");
    let b = Literal::positive("b");
    let c = Literal::positive("c");
    engine.add_fact(a.clone()).unwrap();
    engine
        .add_rule(Rule {
            id: "a-first".into(),
            premises: vec![a],
            conclusion: b.clone(),
        })
        .unwrap();
    engine
        .add_rule(Rule {
            id: "b-second".into(),
            premises: vec![b.clone()],
            conclusion: c.clone(),
        })
        .unwrap();

    let first = engine.reason();
    assert_eq!(first.stop_reason, iroka_cognition::StopReason::StepBudget);
    assert!(first.is_partial());
    assert!(first.facts.contains(&b));
    assert!(!first.facts.contains(&c));

    let second = engine.reason();
    assert_eq!(second.stop_reason, iroka_cognition::StopReason::StepBudget);
    assert!(second.is_partial());
    assert!(second.facts.contains(&c));

    let third = engine.reason();
    assert_eq!(third.stop_reason, iroka_cognition::StopReason::StepBudget);
    assert!(third.is_partial());

    let fourth = engine.reason();
    assert_eq!(fourth.stop_reason, iroka_cognition::StopReason::FixedPoint);
    assert!(fourth.is_complete());
    assert!(fourth.facts.contains(&c));
    assert_eq!(fourth.derivations.len(), 2);
    assert_eq!(
        fourth
            .derivations
            .iter()
            .map(|witness| witness.rule_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-first", "b-second"]
    );
}

#[test]
fn bounded_resumption_is_insertion_order_invariant() {
    let config = EngineConfig {
        max_inference_steps: 1,
        ..EngineConfig::default()
    };
    let mut forward = fixture_with_config(false, config);
    let mut reverse = fixture_with_config(true, config);

    let mut forward_report = None;
    let mut reverse_report = None;
    for _ in 0..64 {
        if forward_report.is_none() {
            let report = forward.reason();
            assert!(
                report.is_complete() || report.is_partial(),
                "reasoning report must explicitly describe completion"
            );
            if report.is_complete() {
                forward_report = Some(report);
            } else {
                assert_eq!(report.stop_reason, iroka_cognition::StopReason::StepBudget);
            }
        }
        if reverse_report.is_none() {
            let report = reverse.reason();
            assert!(
                report.is_complete() || report.is_partial(),
                "reasoning report must explicitly describe completion"
            );
            if report.is_complete() {
                reverse_report = Some(report);
            } else {
                assert_eq!(report.stop_reason, iroka_cognition::StopReason::StepBudget);
            }
        }
        if forward_report.is_some() && reverse_report.is_some() {
            break;
        }
    }

    let left = forward_report.expect("forward insertion order must reach fixed point");
    let right = reverse_report.expect("reverse insertion order must reach fixed point");
    assert_eq!(left.stop_reason, iroka_cognition::StopReason::FixedPoint);
    assert_eq!(right.stop_reason, iroka_cognition::StopReason::FixedPoint);
    assert_eq!(left.facts, right.facts);
    assert_eq!(left.contradictions, right.contradictions);
    assert_eq!(left.asserted_facts, right.asserted_facts);
    assert_eq!(left.derivations, right.derivations);
}

#[test]
fn adding_new_fact_after_partial_stop_restarts_scan_and_preserves_witnesses() {
    let config = EngineConfig {
        max_inference_steps: 1,
        ..EngineConfig::default()
    };
    let mut engine = NativeReasoner::new(config).unwrap();
    let a = Literal::positive("a");
    let b = Literal::positive("b");
    let c = Literal::positive("c");
    let d = Literal::positive("d");

    engine.add_fact(a.clone()).unwrap();
    engine
        .add_rule(Rule {
            id: "a-first".into(),
            premises: vec![a],
            conclusion: b.clone(),
        })
        .unwrap();
    engine
        .add_rule(Rule {
            id: "b-later".into(),
            premises: vec![c.clone()],
            conclusion: d.clone(),
        })
        .unwrap();

    let partial = engine.reason();
    assert_eq!(partial.stop_reason, iroka_cognition::StopReason::StepBudget);
    assert!(partial.is_partial());
    assert!(partial.facts.contains(&b));
    assert_eq!(partial.derivations.len(), 1);

    // A newly asserted fact invalidates the old pass cursor. The engine must
    // restart deterministically while retaining the earlier rule witness.
    engine.add_fact(c).unwrap();

    let mut complete = None;
    for _ in 0..16 {
        let report = engine.reason();
        if report.is_complete() {
            complete = Some(report);
            break;
        }
        assert_eq!(report.stop_reason, iroka_cognition::StopReason::StepBudget);
    }

    let report = complete.expect("updated knowledge base must reach fixed point");
    assert_eq!(report.stop_reason, iroka_cognition::StopReason::FixedPoint);
    assert!(report.facts.contains(&b));
    assert!(report.facts.contains(&d));
    assert_eq!(
        report
            .derivations
            .iter()
            .map(|witness| witness.rule_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-first", "b-later"]
    );
}


#[test]
fn adding_rule_after_partial_stop_restarts_scan_and_preserves_witnesses() {
    let config = EngineConfig {
        max_inference_steps: 1,
        ..EngineConfig::default()
    };
    let mut engine = NativeReasoner::new(config).unwrap();
    let a = Literal::positive("seed-a");
    let b = Literal::positive("derived-b");
    let c = Literal::positive("seed-c");
    let d = Literal::positive("derived-d");
    let e = Literal::positive("derived-e");

    engine.add_fact(a.clone()).unwrap();
    engine.add_fact(c.clone()).unwrap();
    engine
        .add_rule(Rule {
            id: "z-first".into(),
            premises: vec![a],
            conclusion: b.clone(),
        })
        .unwrap();
    engine
        .add_rule(Rule {
            id: "y-second".into(),
            premises: vec![c.clone()],
            conclusion: d.clone(),
        })
        .unwrap();

    let partial = engine.reason();
    assert_eq!(partial.stop_reason, iroka_cognition::StopReason::StepBudget);
    assert!(partial.is_partial());
    assert!(partial.facts.contains(&b));
    assert_eq!(partial.derivations.len(), 1);

    // Inserting a lexicographically earlier rule changes sorted rule indices.
    // The engine must restart its pass and preserve the already-recorded witness.
    engine
        .add_rule(Rule {
            id: "a-new-earliest".into(),
            premises: vec![c],
            conclusion: e.clone(),
        })
        .unwrap();

    let mut complete = None;
    for _ in 0..32 {
        let report = engine.reason();
        if report.is_complete() {
            complete = Some(report);
            break;
        }
        assert_eq!(report.stop_reason, iroka_cognition::StopReason::StepBudget);
    }

    let report = complete.expect("rule-updated knowledge base must reach fixed point");
    assert_eq!(report.stop_reason, iroka_cognition::StopReason::FixedPoint);
    assert!(report.facts.contains(&b));
    assert!(report.facts.contains(&d));
    assert!(report.facts.contains(&e));
    assert_eq!(
        report
            .derivations
            .iter()
            .map(|witness| witness.rule_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a-new-earliest", "y-second", "z-first"]
    );
}
