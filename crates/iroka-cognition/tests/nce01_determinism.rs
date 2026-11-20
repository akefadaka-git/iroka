//! NCE-01 deterministic report behavior under insertion-order variation.

use iroka_cognition::{EngineConfig, Literal, NativeReasoner, Rule};

fn fixture(reverse: bool) -> NativeReasoner {
    let mut engine = NativeReasoner::new(EngineConfig::default()).unwrap();
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
}
