use iroka_kernel::{BusinessScenario, ScenarioCase, ScenarioComparison, ScenarioError};

fn scenario(
    id: &str,
    case: ScenarioCase,
    units: u64,
    price: u64,
    variable_cost: u64,
    fixed_cost: u64,
) -> BusinessScenario {
    BusinessScenario::new(id, case, "ETB", units, price, variable_cost, fixed_cost).unwrap()
}

#[test]
fn scenario_calculates_revenue_costs_and_operating_result() {
    let result = scenario("base:1", ScenarioCase::Base, 10, 500, 200, 1_000)
        .calculate()
        .unwrap();
    assert_eq!(result.revenue_minor(), 5_000);
    assert_eq!(result.variable_cost_minor(), 2_000);
    assert_eq!(result.total_cost_minor(), 3_000);
    assert_eq!(result.operating_profit_minor(), 2_000);
    assert_eq!(result.currency_code(), "ETB");
}

#[test]
fn scenario_preserves_operating_loss_as_negative_result() {
    let result = scenario("loss:1", ScenarioCase::Base, 2, 100, 150, 200)
        .calculate()
        .unwrap();
    assert_eq!(result.operating_profit_minor(), -300);
}

#[test]
fn scenario_rejects_revenue_overflow() {
    let result = BusinessScenario::new("overflow:1", ScenarioCase::Base, "ETB", u64::MAX, 2, 0, 0)
        .unwrap()
        .calculate();
    assert_eq!(result, Err(ScenarioError::ArithmeticOverflow));
}

#[test]
fn scenario_rejects_total_cost_overflow() {
    let result = BusinessScenario::new("overflow:2", ScenarioCase::Base, "ETB", 1, 1, u64::MAX, 1)
        .unwrap()
        .calculate();
    assert_eq!(result, Err(ScenarioError::ArithmeticOverflow));
}

#[test]
fn scenario_rejects_non_iso_style_currency_code() {
    let result = BusinessScenario::new("currency:1", ScenarioCase::Base, "etb", 1, 1, 0, 0);
    assert_eq!(result, Err(ScenarioError::InvalidCurrencyCode));
}

#[test]
fn comparison_rejects_mislabelled_cases() {
    let result = ScenarioComparison::new(
        scenario("down:1", ScenarioCase::Base, 1, 100, 20, 10),
        scenario("base:1", ScenarioCase::Base, 2, 100, 20, 10),
        scenario("up:1", ScenarioCase::Upside, 3, 100, 20, 10),
    );
    assert_eq!(result, Err(ScenarioError::ScenarioCaseMismatch));
}

#[test]
fn comparison_rejects_mixed_currencies() {
    let downside =
        BusinessScenario::new("down:1", ScenarioCase::Downside, "ETB", 1, 100, 20, 10).unwrap();
    let base = BusinessScenario::new("base:1", ScenarioCase::Base, "USD", 2, 100, 20, 10).unwrap();
    let upside =
        BusinessScenario::new("up:1", ScenarioCase::Upside, "USD", 3, 100, 20, 10).unwrap();
    assert_eq!(
        ScenarioComparison::new(downside, base, upside),
        Err(ScenarioError::CurrencyMismatch)
    );
}

#[test]
fn comparison_evaluates_all_three_assumption_sets() {
    let comparison = ScenarioComparison::new(
        scenario("down:1", ScenarioCase::Downside, 5, 400, 250, 1_000),
        scenario("base:1", ScenarioCase::Base, 10, 500, 200, 1_000),
        scenario("up:1", ScenarioCase::Upside, 15, 600, 180, 1_000),
    )
    .unwrap();
    let result = comparison.evaluate().unwrap();
    assert_eq!(result.downside().operating_profit_minor(), -250);
    assert_eq!(result.base().operating_profit_minor(), 2_000);
    assert_eq!(result.upside().operating_profit_minor(), 5_300);
}
