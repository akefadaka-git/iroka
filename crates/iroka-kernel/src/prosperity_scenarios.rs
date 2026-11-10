//! Deterministic, synthetic-only business scenario arithmetic.
//!
//! Inputs are assumptions supplied by a caller, not market facts or forecasts.
//! This module performs no data collection, investment recommendation,
//! guarantee, financial transaction, tax calculation or external execution.

/// The named case in a three-scenario comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScenarioCase {
    Downside,
    Base,
    Upside,
}

/// Explicit, caller-supplied operating assumptions for one scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusinessScenario {
    id: String,
    case: ScenarioCase,
    currency_code: String,
    units: u64,
    unit_price_minor: u64,
    variable_cost_per_unit_minor: u64,
    fixed_cost_minor: u64,
}

impl BusinessScenario {
    pub fn new(
        id: impl Into<String>,
        case: ScenarioCase,
        currency_code: impl Into<String>,
        units: u64,
        unit_price_minor: u64,
        variable_cost_per_unit_minor: u64,
        fixed_cost_minor: u64,
    ) -> Result<Self, ScenarioError> {
        let scenario = Self {
            id: id.into(),
            case,
            currency_code: currency_code.into(),
            units,
            unit_price_minor,
            variable_cost_per_unit_minor,
            fixed_cost_minor,
        };
        scenario.validate()?;
        Ok(scenario)
    }

    pub fn validate(&self) -> Result<(), ScenarioError> {
        if self.id.trim().is_empty() {
            return Err(ScenarioError::EmptyScenarioId);
        }
        if self.currency_code.len() != 3
            || !self
                .currency_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ScenarioError::InvalidCurrencyCode);
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn case(&self) -> ScenarioCase {
        self.case
    }

    pub fn currency_code(&self) -> &str {
        &self.currency_code
    }

    pub fn calculate(&self) -> Result<ScenarioResult, ScenarioError> {
        self.validate()?;
        let revenue_minor = self
            .units
            .checked_mul(self.unit_price_minor)
            .ok_or(ScenarioError::ArithmeticOverflow)?;
        let variable_cost_minor = self
            .units
            .checked_mul(self.variable_cost_per_unit_minor)
            .ok_or(ScenarioError::ArithmeticOverflow)?;
        let total_cost_minor = variable_cost_minor
            .checked_add(self.fixed_cost_minor)
            .ok_or(ScenarioError::ArithmeticOverflow)?;
        let operating_profit_minor =
            i128::from(revenue_minor) - i128::from(total_cost_minor);

        Ok(ScenarioResult {
            case: self.case,
            currency_code: self.currency_code.clone(),
            revenue_minor,
            variable_cost_minor,
            total_cost_minor,
            operating_profit_minor,
        })
    }
}

/// Arithmetic output. Amounts remain in the input currency's minor unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioResult {
    case: ScenarioCase,
    currency_code: String,
    revenue_minor: u64,
    variable_cost_minor: u64,
    total_cost_minor: u64,
    operating_profit_minor: i128,
}

impl ScenarioResult {
    pub fn case(&self) -> ScenarioCase {
        self.case
    }

    pub fn currency_code(&self) -> &str {
        &self.currency_code
    }

    pub fn revenue_minor(&self) -> u64 {
        self.revenue_minor
    }

    pub fn variable_cost_minor(&self) -> u64 {
        self.variable_cost_minor
    }

    pub fn total_cost_minor(&self) -> u64 {
        self.total_cost_minor
    }

    pub fn operating_profit_minor(&self) -> i128 {
        self.operating_profit_minor
    }
}

/// Three explicitly labelled scenarios sharing one currency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioComparison {
    downside: BusinessScenario,
    base: BusinessScenario,
    upside: BusinessScenario,
}

impl ScenarioComparison {
    pub fn new(
        downside: BusinessScenario,
        base: BusinessScenario,
        upside: BusinessScenario,
    ) -> Result<Self, ScenarioError> {
        let comparison = Self {
            downside,
            base,
            upside,
        };
        comparison.validate()?;
        Ok(comparison)
    }

    pub fn validate(&self) -> Result<(), ScenarioError> {
        self.downside.validate()?;
        self.base.validate()?;
        self.upside.validate()?;
        if self.downside.case() != ScenarioCase::Downside
            || self.base.case() != ScenarioCase::Base
            || self.upside.case() != ScenarioCase::Upside
        {
            return Err(ScenarioError::ScenarioCaseMismatch);
        }
        if self.downside.currency_code() != self.base.currency_code()
            || self.base.currency_code() != self.upside.currency_code()
        {
            return Err(ScenarioError::CurrencyMismatch);
        }
        Ok(())
    }

    pub fn evaluate(&self) -> Result<ScenarioComparisonResult, ScenarioError> {
        self.validate()?;
        Ok(ScenarioComparisonResult {
            downside: self.downside.calculate()?,
            base: self.base.calculate()?,
            upside: self.upside.calculate()?,
        })
    }
}

/// Calculated outputs for a downside, base and upside scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioComparisonResult {
    downside: ScenarioResult,
    base: ScenarioResult,
    upside: ScenarioResult,
}

impl ScenarioComparisonResult {
    pub fn downside(&self) -> &ScenarioResult {
        &self.downside
    }

    pub fn base(&self) -> &ScenarioResult {
        &self.base
    }

    pub fn upside(&self) -> &ScenarioResult {
        &self.upside
    }
}

/// Validation and arithmetic failures for synthetic scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioError {
    EmptyScenarioId,
    InvalidCurrencyCode,
    ScenarioCaseMismatch,
    CurrencyMismatch,
    ArithmeticOverflow,
}
