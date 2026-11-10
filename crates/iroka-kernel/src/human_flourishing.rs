//! Candidate human-flourishing metrics and synthetic-only impact comparisons.
//!
//! These contracts define measurement vocabulary; they do not collect or store
//! real-world data, establish causal impact, rank human worth, or authorize
//! interventions. Real data collection remains gated by Owner decisions and
//! privacy/consent governance. Small-cell suppression is a disclosure guard,
//! not a differential-privacy guarantee.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlourishingDomain {
    Education,
    Livelihood,
    HealthAccess,
    FoodSecurity,
    WaterAccess,
    DignityAndFairness,
    CommunityWellbeing,
    EnvironmentalStewardship,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricUnit {
    Count,
    BasisPoints,
    Days,
    IndexPoints,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricDirection {
    HigherIsBetter,
    LowerIsBetter,
    MonitorOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricDefinition {
    id: String,
    domain: FlourishingDomain,
    unit: MetricUnit,
    direction: MetricDirection,
    numerator_label: String,
    denominator_label: Option<String>,
    adverse_outcome_indicator: bool,
}

impl MetricDefinition {
    pub fn new(
        id: impl Into<String>,
        domain: FlourishingDomain,
        unit: MetricUnit,
        direction: MetricDirection,
        numerator_label: impl Into<String>,
        denominator_label: Option<String>,
        adverse_outcome_indicator: bool,
    ) -> Result<Self, FlourishingMetricError> {
        let definition = Self {
            id: id.into(),
            domain,
            unit,
            direction,
            numerator_label: numerator_label.into(),
            denominator_label,
            adverse_outcome_indicator,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), FlourishingMetricError> {
        if self.id.trim().is_empty() {
            return Err(FlourishingMetricError::EmptyMetricId);
        }
        if self.numerator_label.trim().is_empty() {
            return Err(FlourishingMetricError::EmptyNumeratorLabel);
        }
        match (self.unit, self.denominator_label.as_deref()) {
            (MetricUnit::BasisPoints, None) => {
                return Err(FlourishingMetricError::DenominatorRequired);
            }
            (_, Some(label)) if label.trim().is_empty() => {
                return Err(FlourishingMetricError::EmptyDenominatorLabel);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn domain(&self) -> FlourishingDomain {
        self.domain
    }

    pub fn unit(&self) -> MetricUnit {
        self.unit
    }

    pub fn direction(&self) -> MetricDirection {
        self.direction
    }

    pub fn numerator_label(&self) -> &str {
        &self.numerator_label
    }

    pub fn denominator_label(&self) -> Option<&str> {
        self.denominator_label.as_deref()
    }

    pub fn is_adverse_outcome_indicator(&self) -> bool {
        self.adverse_outcome_indicator
    }
}

/// Synthetic aggregate only; this type cannot represent person-level records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticAggregateObservation {
    metric_id: String,
    unit: MetricUnit,
    value: u64,
    cohort_size: u64,
}

impl SyntheticAggregateObservation {
    pub fn new(
        metric_id: impl Into<String>,
        unit: MetricUnit,
        value: u64,
        cohort_size: u64,
    ) -> Result<Self, FlourishingMetricError> {
        let observation = Self {
            metric_id: metric_id.into(),
            unit,
            value,
            cohort_size,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> Result<(), FlourishingMetricError> {
        if self.metric_id.trim().is_empty() {
            return Err(FlourishingMetricError::EmptyMetricId);
        }
        if self.cohort_size == 0 {
            return Err(FlourishingMetricError::EmptyCohort);
        }
        if self.unit == MetricUnit::BasisPoints && self.value > 10_000 {
            return Err(FlourishingMetricError::RateOutOfRange);
        }
        Ok(())
    }

    pub fn metric_id(&self) -> &str {
        &self.metric_id
    }

    pub fn unit(&self) -> MetricUnit {
        self.unit
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn cohort_size(&self) -> u64 {
        self.cohort_size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmallCellSuppressionPolicy {
    minimum_group_size: u64,
}

impl SmallCellSuppressionPolicy {
    pub fn new(minimum_group_size: u64) -> Result<Self, FlourishingMetricError> {
        if minimum_group_size < 2 {
            return Err(FlourishingMetricError::UnsafeSuppressionThreshold);
        }
        Ok(Self { minimum_group_size })
    }

    pub fn minimum_group_size(&self) -> u64 {
        self.minimum_group_size
    }

    pub fn disclosure_for(
        &self,
        observation: &SyntheticAggregateObservation,
    ) -> DisclosureDecision {
        if observation.cohort_size() < self.minimum_group_size {
            DisclosureDecision::SuppressSmallCell
        } else {
            DisclosureDecision::MayDiscloseSyntheticAggregate
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureDecision {
    SuppressSmallCell,
    MayDiscloseSyntheticAggregate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeInterpretation {
    Improvement,
    Deterioration,
    NoChange,
    MonitorOnly,
}

/// Descriptive comparison only. Attribution is permanently not established
/// by this primitive; temporal association is not causal evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricComparison {
    metric_id: String,
    unit: MetricUnit,
    baseline: u64,
    follow_up: u64,
    change: i128,
    interpretation: ChangeInterpretation,
}

impl MetricComparison {
    pub fn evaluate(
        definition: &MetricDefinition,
        baseline: &SyntheticAggregateObservation,
        follow_up: &SyntheticAggregateObservation,
    ) -> Result<Self, FlourishingMetricError> {
        definition.validate()?;
        baseline.validate()?;
        follow_up.validate()?;
        if baseline.metric_id() != definition.id()
            || follow_up.metric_id() != definition.id()
        {
            return Err(FlourishingMetricError::MetricIdMismatch);
        }
        if baseline.unit() != definition.unit() || follow_up.unit() != definition.unit() {
            return Err(FlourishingMetricError::UnitMismatch);
        }

        let change = i128::from(follow_up.value()) - i128::from(baseline.value());
        let interpretation = match (definition.direction(), change.signum()) {
            (_, 0) => ChangeInterpretation::NoChange,
            (MetricDirection::HigherIsBetter, 1)
            | (MetricDirection::LowerIsBetter, -1) => ChangeInterpretation::Improvement,
            (MetricDirection::HigherIsBetter, -1)
            | (MetricDirection::LowerIsBetter, 1) => ChangeInterpretation::Deterioration,
            (MetricDirection::MonitorOnly, _) => ChangeInterpretation::MonitorOnly,
            _ => ChangeInterpretation::MonitorOnly,
        };

        Ok(Self {
            metric_id: definition.id().to_owned(),
            unit: definition.unit(),
            baseline: baseline.value(),
            follow_up: follow_up.value(),
            change,
            interpretation,
        })
    }

    pub fn metric_id(&self) -> &str {
        &self.metric_id
    }

    pub fn unit(&self) -> MetricUnit {
        self.unit
    }

    pub fn baseline(&self) -> u64 {
        self.baseline
    }

    pub fn follow_up(&self) -> u64 {
        self.follow_up
    }

    pub fn change(&self) -> i128 {
        self.change
    }

    pub fn interpretation(&self) -> ChangeInterpretation {
        self.interpretation
    }

    pub fn causal_attribution_established(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlourishingMetricError {
    EmptyMetricId,
    EmptyNumeratorLabel,
    DenominatorRequired,
    EmptyDenominatorLabel,
    EmptyCohort,
    RateOutOfRange,
    UnsafeSuppressionThreshold,
    MetricIdMismatch,
    UnitMismatch,
}
