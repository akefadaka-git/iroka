//! IROKA ZERO trusted-kernel foundation.
//! This crate evaluates authorization proposals deterministically. It does not
//! execute tools, call models, verify credentials, or persist audit records.

mod decision;
mod policy;
mod request;

pub use decision::{Decision, DecisionCode, DecisionReason};
pub use policy::{Policy, RiskLevel};
pub use request::AuthorizationRequest;

/// Evaluate a proposed operation against an explicit policy.
/// Missing or invalid evidence must never be interpreted as permission.
pub fn evaluate(
    request: &AuthorizationRequest,
    policy: &Policy,
    emergency_stop_active: bool,
) -> Decision {
    if emergency_stop_active {
        return Decision::new(DecisionCode::Escalate, DecisionReason::EmergencyStopActive, policy.version());
    }
    if !request.is_well_formed() {
        return Decision::new(DecisionCode::Deny, DecisionReason::MalformedRequest, policy.version());
    }
    if !policy.allows_capability(request.capability()) {
        return Decision::new(DecisionCode::Deny, DecisionReason::CapabilityNotGranted, policy.version());
    }
    if request.risk() > policy.maximum_risk() {
        return Decision::new(DecisionCode::Escalate, DecisionReason::RiskExceedsPolicy, policy.version());
    }
    if policy.requires_approval(request.capability()) {
        return Decision::new(DecisionCode::RequireApproval, DecisionReason::HumanApprovalRequired, policy.version());
    }
    Decision::new(DecisionCode::Allow, DecisionReason::PolicySatisfied, policy.version())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(capability: &str, risk: RiskLevel) -> AuthorizationRequest {
        AuthorizationRequest::new("principal:operator-1", capability, "resource:workspace-1", risk)
    }

    fn policy() -> Policy {
        Policy::new(
            "policy-v1",
            vec!["workspace.read".into(), "records.export".into()],
            vec!["records.export".into()],
            RiskLevel::High,
        )
    }

    #[test]
    fn allows_registered_capability_within_policy() {
        let d = evaluate(&request("workspace.read", RiskLevel::Low), &policy(), false);
        assert_eq!(d.code(), DecisionCode::Allow);
    }

    #[test]
    fn denies_unregistered_capability() {
        let d = evaluate(&request("system.modify", RiskLevel::Low), &policy(), false);
        assert_eq!(d.code(), DecisionCode::Deny);
        assert_eq!(d.reason(), DecisionReason::CapabilityNotGranted);
    }

    #[test]
    fn requires_approval_for_designated_capability() {
        let d = evaluate(&request("records.export", RiskLevel::Low), &policy(), false);
        assert_eq!(d.code(), DecisionCode::RequireApproval);
    }

    #[test]
    fn escalates_excessive_risk() {
        let d = evaluate(&request("workspace.read", RiskLevel::Critical), &policy(), false);
        assert_eq!(d.code(), DecisionCode::Escalate);
    }

    #[test]
    fn emergency_stop_precedes_policy_checks() {
        let d = evaluate(&request("workspace.read", RiskLevel::Low), &policy(), true);
        assert_eq!(d.reason(), DecisionReason::EmergencyStopActive);
    }

    #[test]
    fn denies_malformed_request() {
        let r = AuthorizationRequest::new("", "workspace.read", "resource:1", RiskLevel::Low);
        let d = evaluate(&r, &policy(), false);
        assert_eq!(d.code(), DecisionCode::Deny);
    }
}
