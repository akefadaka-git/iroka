//! IROKA ZERO trusted-kernel foundation.
//! This crate provides deterministic policy evaluation and explicit contracts
//! for identity, governance approval evidence and assurance audit records.
//! Production adapters remain a separate, independently reviewed trust boundary.

mod assurance;
mod decision;
mod governance;
mod identity;
mod policy;
mod request;

pub use assurance::{record_decision, AuditError, AuditEvent, AuditSink};
pub use decision::{Decision, DecisionCode, DecisionReason};
pub use governance::{validate_approval_scope, ApprovalError, ApprovalEvidence, ApprovalVerifier};
pub use identity::{
    authenticate, bind_principal, IdentityAssertion, IdentityError, IdentityVerifier,
    VerifiedPrincipal,
};
pub use policy::{Policy, RiskLevel};
pub use request::AuthorizationRequest;

/// Low-level deterministic policy primitive. This does not authenticate the
/// subject, validate approval evidence or persist an audit record.
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

    struct TestCredentialVerifier;
    impl IdentityVerifier for TestCredentialVerifier {
        fn verify_credential(&self, _assertion: &IdentityAssertion, _now: u64) -> Result<(), IdentityError> {
            Ok(())
        }
    }

    #[test]
    fn identity_rejects_expired_assertions() {
        let a = IdentityAssertion::new("issuer", "principal:1", "iroka", 10, "credential:1");
        assert_eq!(authenticate(&TestCredentialVerifier, &a, "iroka", 10), Err(IdentityError::Expired));
    }

    #[test]
    fn identity_rejects_wrong_audience() {
        let a = IdentityAssertion::new("issuer", "principal:1", "other", 100, "credential:1");
        assert_eq!(authenticate(&TestCredentialVerifier, &a, "iroka", 1), Err(IdentityError::VerificationFailed));
    }

    #[test]
    fn identity_returns_principal_only_after_verifier_accepts() {
        let a = IdentityAssertion::new("issuer", "principal:1", "iroka", 100, "credential:1");
        let p = authenticate(&TestCredentialVerifier, &a, "iroka", 1).expect("test assertion accepted");
        assert_eq!(p.subject(), "principal:1");
    }

    #[test]
    fn approval_is_bound_to_exact_request_and_policy() {
        let q = AuthorizationRequest::new("principal:1", "records.export", "resource:9", RiskLevel::Low);
        let a = IdentityAssertion::new("issuer", "owner:1", "iroka", 100, "owner-credential");
        let e = ApprovalEvidence::new("approval:1", a, "records.export", "resource:9", "principal:1", "policy-v1", 100);
        assert_eq!(validate_approval_scope(&e, &q, "policy-v1", 1), Ok(()));
        assert_eq!(validate_approval_scope(&e, &q, "policy-v2", 1), Err(ApprovalError::ScopeMismatch));
    }

    struct FailingAudit;
    impl AuditSink for FailingAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> { Err(AuditError::Unavailable) }
    }

    #[test]
    fn audit_failure_escalates_positive_decision() {
        let event = AuditEvent::new("event:1", "trace:1", "principal:1", "workspace.read", "workspace:1", "policy-v1", DecisionCode::Allow, 1);
        let allow = Decision::new(DecisionCode::Allow, DecisionReason::PolicySatisfied, "policy-v1");
        let result = record_decision(&FailingAudit, &event, allow);
        assert_eq!(result.code(), DecisionCode::Escalate);
        assert_eq!(result.reason(), DecisionReason::AuditUnavailable);
    }
}
