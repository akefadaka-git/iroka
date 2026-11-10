use iroka_kernel::{
    ChangeInterpretation, DisclosureDecision, FlourishingDomain, FlourishingMetricError,
    MetricComparison, MetricDefinition, MetricDirection, MetricUnit, SmallCellSuppressionPolicy,
    SyntheticAggregateObservation,
};

fn definition(direction: MetricDirection, unit: MetricUnit, adverse: bool) -> MetricDefinition {
    MetricDefinition::new(
        "education:completion-rate",
        FlourishingDomain::Education,
        unit,
        direction,
        "learners completing programme",
        if unit == MetricUnit::BasisPoints {
            Some("learners enrolled".into())
        } else {
            None
        },
        adverse,
    )
    .unwrap()
}

fn observation(value: u64, cohort: u64) -> SyntheticAggregateObservation {
    SyntheticAggregateObservation::new(
        "education:completion-rate",
        MetricUnit::BasisPoints,
        value,
        cohort,
    )
    .unwrap()
}

#[test]
fn metric_definition_retains_domain_unit_direction_and_adverse_flag() {
    let metric = definition(
        MetricDirection::HigherIsBetter,
        MetricUnit::BasisPoints,
        false,
    );
    assert_eq!(metric.domain(), FlourishingDomain::Education);
    assert_eq!(metric.unit(), MetricUnit::BasisPoints);
    assert_eq!(metric.direction(), MetricDirection::HigherIsBetter);
    assert!(!metric.is_adverse_outcome_indicator());
    assert_eq!(metric.denominator_label(), Some("learners enrolled"));
}

#[test]
fn metric_definition_rejects_blank_identifier_and_numerator() {
    assert_eq!(
        MetricDefinition::new(
            " ",
            FlourishingDomain::Education,
            MetricUnit::Count,
            MetricDirection::MonitorOnly,
            "learners",
            None,
            false,
        ),
        Err(FlourishingMetricError::EmptyMetricId)
    );
    assert_eq!(
        MetricDefinition::new(
            "metric:1",
            FlourishingDomain::Education,
            MetricUnit::Count,
            MetricDirection::MonitorOnly,
            " ",
            None,
            false,
        ),
        Err(FlourishingMetricError::EmptyNumeratorLabel)
    );
}

#[test]
fn rate_metric_requires_denominator_label() {
    assert_eq!(
        MetricDefinition::new(
            "rate:1",
            FlourishingDomain::HealthAccess,
            MetricUnit::BasisPoints,
            MetricDirection::HigherIsBetter,
            "people reached",
            None,
            false,
        ),
        Err(FlourishingMetricError::DenominatorRequired)
    );
}

#[test]
fn rate_metric_rejects_blank_denominator_label() {
    assert_eq!(
        MetricDefinition::new(
            "rate:1",
            FlourishingDomain::HealthAccess,
            MetricUnit::BasisPoints,
            MetricDirection::HigherIsBetter,
            "people reached",
            Some(" ".into()),
            false,
        ),
        Err(FlourishingMetricError::EmptyDenominatorLabel)
    );
}

#[test]
fn synthetic_observation_rejects_zero_cohort() {
    assert_eq!(
        SyntheticAggregateObservation::new("metric:1", MetricUnit::Count, 10, 0,),
        Err(FlourishingMetricError::EmptyCohort)
    );
}

#[test]
fn synthetic_rate_is_bounded_to_one_hundred_percent() {
    assert_eq!(
        SyntheticAggregateObservation::new("rate:1", MetricUnit::BasisPoints, 10_001, 100,),
        Err(FlourishingMetricError::RateOutOfRange)
    );
    assert!(
        SyntheticAggregateObservation::new("rate:1", MetricUnit::BasisPoints, 10_000, 100,).is_ok()
    );
}

#[test]
fn small_cell_suppression_requires_a_nontrivial_threshold() {
    assert_eq!(
        SmallCellSuppressionPolicy::new(1),
        Err(FlourishingMetricError::UnsafeSuppressionThreshold)
    );
}

#[test]
fn small_cells_are_suppressed_and_larger_synthetic_cohorts_may_be_disclosed() {
    let policy = SmallCellSuppressionPolicy::new(5).unwrap();
    assert_eq!(
        policy.disclosure_for(&observation(7000, 4)),
        DisclosureDecision::SuppressSmallCell
    );
    assert_eq!(
        policy.disclosure_for(&observation(7000, 5)),
        DisclosureDecision::MayDiscloseSyntheticAggregate
    );
}

#[test]
fn higher_is_better_metric_marks_increase_as_improvement() {
    let metric = definition(
        MetricDirection::HigherIsBetter,
        MetricUnit::BasisPoints,
        false,
    );
    let result =
        MetricComparison::evaluate(&metric, &observation(6000, 20), &observation(7200, 22))
            .unwrap();
    assert_eq!(result.change(), 1200);
    assert_eq!(result.interpretation(), ChangeInterpretation::Improvement);
}

#[test]
fn lower_is_better_adverse_metric_marks_increase_as_deterioration() {
    let metric = MetricDefinition::new(
        "water:illness-incidence",
        FlourishingDomain::WaterAccess,
        MetricUnit::Count,
        MetricDirection::LowerIsBetter,
        "reported adverse incidents",
        None,
        true,
    )
    .unwrap();
    let baseline =
        SyntheticAggregateObservation::new(metric.id(), MetricUnit::Count, 4, 30).unwrap();
    let follow_up =
        SyntheticAggregateObservation::new(metric.id(), MetricUnit::Count, 8, 32).unwrap();
    let result = MetricComparison::evaluate(&metric, &baseline, &follow_up).unwrap();
    assert!(metric.is_adverse_outcome_indicator());
    assert_eq!(result.interpretation(), ChangeInterpretation::Deterioration);
}

#[test]
fn lower_is_better_metric_marks_decrease_as_improvement() {
    let metric = MetricDefinition::new(
        "livelihood:days-unemployed",
        FlourishingDomain::Livelihood,
        MetricUnit::Days,
        MetricDirection::LowerIsBetter,
        "days without work",
        None,
        false,
    )
    .unwrap();
    let baseline =
        SyntheticAggregateObservation::new(metric.id(), MetricUnit::Days, 20, 12).unwrap();
    let follow_up =
        SyntheticAggregateObservation::new(metric.id(), MetricUnit::Days, 12, 14).unwrap();
    let result = MetricComparison::evaluate(&metric, &baseline, &follow_up).unwrap();
    assert_eq!(result.interpretation(), ChangeInterpretation::Improvement);
}

#[test]
fn monitor_only_metric_does_not_claim_improvement_or_deterioration() {
    let metric = definition(
        MetricDirection::MonitorOnly,
        MetricUnit::BasisPoints,
        false,
    );
    let result =
        MetricComparison::evaluate(&metric, &observation(6000, 20), &observation(7200, 22))
            .unwrap();
    assert_eq!(result.interpretation(), ChangeInterpretation::MonitorOnly);
}

#[test]
fn comparison_rejects_metric_identifier_and_unit_mismatch() {
    let metric = definition(MetricDirection::HigherIsBetter, MetricUnit::BasisPoints, false);
    let wrong_id =
        SyntheticAggregateObservation::new("different:metric", MetricUnit::BasisPoints, 7000, 10)
            .unwrap();
    assert_eq!(
        MetricComparison::evaluate(&metric, &observation(6000, 10), &wrong_id),
        Err(FlourishingMetricError::MetricIdMismatch)
    );
    let wrong_unit =
        SyntheticAggregateObservation::new("education:completion-rate", MetricUnit::Count, 7, 10)
            .unwrap();
    assert_eq!(
        MetricComparison::evaluate(&metric, &observation(6000, 10), &wrong_unit),
        Err(FlourishingMetricError::UnitMismatch)
    );
}

#[test]
fn comparison_never_claims_causal_attribution() {
    let metric = definition(
        MetricDirection::HigherIsBetter,
        MetricUnit::BasisPoints,
        false,
    );
    let result = MetricComparison::evaluate(&metric, &observation(6000, 20), &observation(7200, 22))
        .unwrap();
    assert!(!result.causal_attribution_established());
}

#[test]
fn no_change_is_reported_without_overclaiming() {
    let metric = definition(
        MetricDirection::HigherIsBetter,
        MetricUnit::BasisPoints,
        false,
    );
    let result = MetricComparison::evaluate(&metric, &observation(6000, 20), &observation(6000, 22))
        .unwrap();
    assert_eq!(result.change(), 0);
    assert_eq!(result.interpretation(), ChangeInterpretation::NoChange);
}
