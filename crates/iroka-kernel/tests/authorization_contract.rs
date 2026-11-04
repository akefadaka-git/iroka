use iroka_kernel::{evaluate, AuthorizationRequest, DecisionCode, Policy, RiskLevel};

#[test]
fn unknown_capabilities_never_authorize() {
    let policy = Policy::new("v1", vec![], vec![], RiskLevel::Critical);
    let request = AuthorizationRequest::new(
        "agent:untrusted", "filesystem.write", "filesystem:/", RiskLevel::Low,
    );
    assert_eq!(evaluate(&request, &policy, false).code(), DecisionCode::Deny);
}

#[test]
fn approval_required_never_becomes_allow_without_approval_workflow() {
    let policy = Policy::new(
        "v1",
        vec!["payment.release".into()],
        vec!["payment.release".into()],
        RiskLevel::High,
    );
    let request = AuthorizationRequest::new(
        "principal:operator", "payment.release", "payment:123", RiskLevel::High,
    );
    assert_eq!(evaluate(&request, &policy, false).code(), DecisionCode::RequireApproval);
}
