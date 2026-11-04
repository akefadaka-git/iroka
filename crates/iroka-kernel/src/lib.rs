//! IROKA ZERO trusted-kernel foundation.
//! Deterministic policy evaluation plus explicit identity, governance and
//! assurance contracts. Concrete production adapters remain independently
//! reviewed trust-boundary components.

mod assurance;
mod decision;
mod governance;
mod identity;
mod identity_crypto;
mod owner_approval;
mod security_store;
mod trust_lifecycle;
mod policy;
mod request;
mod service;

pub use assurance::{record_decision, AuditError, AuditEvent, AuditSink};
pub use decision::{Decision, DecisionCode, DecisionReason};
pub(crate) use governance::{validate_approval_scope, ApprovalError, ApprovalEvidence, ApprovalVerifier};
pub(crate) use identity::{
    authenticate, bind_principal, IdentityAssertion, IdentityError, IdentityVerifier,
};
pub use identity::VerifiedPrincipal;
pub use identity_crypto::{
    CredentialError, Ed25519CredentialVerifier, RevocationChecker, TrustConfigError,
    TrustStore, TrustedKey,
};
#[cfg(any(test, feature = "dev-no-revocations"))]
pub use identity_crypto::NoRevocations;
pub use owner_approval::{OwnerApprovalError, OwnerApprovalPayload, OwnerApprovalVerifier, SignedOwnerApproval, TrustedOwnerKey};
pub use security_store::{SecurityStoreError, SqliteSecurityStore};
pub use trust_lifecycle::{verify_and_install_trust_bundle, SignedTrustBundle, TrustBundleError, TrustBundlePayload, TrustRoot};
pub use policy::{Policy, RiskLevel};
pub use request::AuthorizationRequest;
pub(crate) use service::{authorize, authorize_authenticated};
pub use service::authorize_authenticated_with_owner_approval;

/// Low-level deterministic policy primitive. It does not authenticate subjects,
/// validate approval evidence or persist audit events. Prefer authorize().
pub fn evaluate(
    request: &AuthorizationRequest,
    policy: &Policy,
    emergency_stop_active: bool,
) -> Decision {
    if emergency_stop_active {
        return Decision::new(
            DecisionCode::Escalate,
            DecisionReason::EmergencyStopActive,
            policy.version(),
        );
    }
    if !request.is_well_formed() {
        return Decision::new(
            DecisionCode::Deny,
            DecisionReason::MalformedRequest,
            policy.version(),
        );
    }
    if !policy.allows_capability(request.capability()) {
        return Decision::new(
            DecisionCode::Deny,
            DecisionReason::CapabilityNotGranted,
            policy.version(),
        );
    }
    if request.risk() > policy.maximum_risk() {
        return Decision::new(
            DecisionCode::Escalate,
            DecisionReason::RiskExceedsPolicy,
            policy.version(),
        );
    }
    if policy.requires_approval(request.capability()) {
        return Decision::new(
            DecisionCode::RequireApproval,
            DecisionReason::HumanApprovalRequired,
            policy.version(),
        );
    }
    Decision::new(
        DecisionCode::Allow,
        DecisionReason::PolicySatisfied,
        policy.version(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIdentity;
    impl IdentityVerifier for TestIdentity {
        fn verify_credential(
            &self,
            _a: &IdentityAssertion,
            _now: u64,
        ) -> Result<(), IdentityError> {
            Ok(())
        }
    }

    struct TestApproval;
    impl ApprovalVerifier for TestApproval {
        fn verify_approval(
            &self,
            _e: &ApprovalEvidence,
            _p: &VerifiedPrincipal,
            _r: &AuthorizationRequest,
            _v: &str,
            _now: u64,
        ) -> Result<(), ApprovalError> {
            Ok(())
        }
    }

    struct TestAudit;
    impl AuditSink for TestAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }

    struct FailedAudit;
    impl AuditSink for FailedAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::Unavailable)
        }
    }

    fn policy() -> Policy {
        Policy::new(
            "policy-v1",
            vec!["workspace.read".into(), "records.export".into()],
            vec!["records.export".into()],
            RiskLevel::High,
        )
    }

    fn assertion(subject: &str) -> IdentityAssertion {
        IdentityAssertion::new("test-issuer", subject, "iroka", 100, "test-credential")
    }

    #[test]
    fn identity_rejects_expired_assertions() {
        assert_eq!(
            authenticate(&TestIdentity, &assertion("principal:1"), "iroka", 100),
            Err(IdentityError::Expired)
        );
    }

    #[test]
    fn identity_rejects_wrong_audience() {
        let a = IdentityAssertion::new("issuer", "principal:1", "other", 100, "credential");
        assert_eq!(
            authenticate(&TestIdentity, &a, "iroka", 1),
            Err(IdentityError::VerificationFailed)
        );
    }

    #[test]
    fn authorization_binds_verified_subject_to_request() {
        let q = AuthorizationRequest::new(
            "principal:other",
            "workspace.read",
            "workspace:1",
            RiskLevel::Low,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            None,
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.reason(), DecisionReason::IdentitySubjectMismatch);
        assert_eq!(d.code(), DecisionCode::Deny);
    }

    #[test]
    fn authenticated_principal_flows_into_governed_authorization() {
        let q = AuthorizationRequest::new(
            "principal:1",
            "workspace.read",
            "workspace:1",
            RiskLevel::Low,
        );
        let principal = VerifiedPrincipal::from_verified_credential(
            "principal:1".into(),
            "issuer:test".into(),
            "credential:1".into(),
        );
        let d = authorize_authenticated(
            &q,
            &principal,
            None,
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:authenticated",
            "trace:authenticated",
        );
        assert_eq!(d.code(), DecisionCode::Allow);
    }

    #[test]
    fn missing_approval_remains_require_approval() {
        let q =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let d = authorize(
            &q,
            &assertion("principal:1"),
            None,
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::RequireApproval);
    }

    #[test]
    fn verified_approval_is_required_before_approval_capability_allows() {
        let q =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let evidence = ApprovalEvidence::new(
            "approval:1",
            assertion("owner:1"),
            "records.export",
            "records:1",
            "principal:1",
            "policy-v1",
            90,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            Some(&evidence),
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::Allow);
        assert_eq!(d.reason(), DecisionReason::ApprovalVerified);
    }

    #[test]
    fn approval_scope_mismatch_escalates() {
        let q =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let evidence = ApprovalEvidence::new(
            "approval:1",
            assertion("owner:1"),
            "records.export",
            "records:other",
            "principal:1",
            "policy-v1",
            90,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            Some(&evidence),
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::Escalate);
        assert_eq!(d.reason(), DecisionReason::ApprovalScopeMismatch);
    }

    #[test]
    fn audit_failure_prevents_positive_authorization() {
        let q = AuthorizationRequest::new(
            "principal:1",
            "workspace.read",
            "workspace:1",
            RiskLevel::Low,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            None,
            &TestIdentity,
            &TestApproval,
            &FailedAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::Escalate);
        assert_eq!(d.reason(), DecisionReason::AuditUnavailable);
    }
}
