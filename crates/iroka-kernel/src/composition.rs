//! End-to-end G01 → tenant → G02 → Owner approval → G11 composition.
//!
//! This module produces a decision only. G09 must independently revalidate
//! tenant membership and policy state before any protected effect.

use crate::{
    record_decision, AuditEvent, AuditSink, AuthorizationRequest, CredentialError, Decision,
    DecisionCode, DecisionReason, Ed25519CredentialVerifier, OwnerApprovalVerifier,
    RevocationChecker, SignedOwnerApproval, VerifiedGenesis,
};

struct TenantBoundAuditSink<'a, S> {
    inner: &'a S,
    tenant_id: &'a str,
    membership_version: u64,
    correlation_id: &'a str,
}

impl<S: AuditSink> AuditSink for TenantBoundAuditSink<'_, S> {
    fn append(&self, event: &AuditEvent) -> Result<(), crate::AuditError> {
        let correlation = format!(
            "tenant:{}:membership-version:{}:{}:{}",
            self.tenant_id, self.membership_version, self.correlation_id, event.correlation_id()
        );
        let bound = AuditEvent::new(
            event.event_id(),
            correlation,
            event.subject(),
            event.capability(),
            event.resource(),
            event.policy_version(),
            event.decision(),
            event.occurred_at(),
        );
        self.inner.append(&bound)
    }
}

fn audit_unresolved<S: AuditSink>(
    sink: &S,
    request: &AuthorizationRequest,
    policy_version: &str,
    decision: Decision,
    now: u64,
    event_id: &str,
    correlation_id: &str,
) -> Decision {
    let event = AuditEvent::new(
        event_id,
        format!("tenant:unresolved:{correlation_id}"),
        request.subject(),
        request.capability(),
        request.resource(),
        policy_version,
        decision.code(),
        now,
    );
    record_decision(sink, &event, decision)
}

/// Authenticate a compact G01 credential, resolve its tenant using IROKA's
/// Owner-governed membership authority, load the current Owner-signed global
/// G02 policy, validate any one-time Owner approval, and append the final G11
/// decision event. The requested tenant is a selector only.
///
/// The active policy in this increment is explicitly global to this Kernel
/// store; this function does not claim tenant-specific policy partitioning.
/// An ALLOW is a decision, never a G09 execution grant. Because the membership
/// lookup and decision are not one cross-domain database transaction, G09 must
/// revalidate the membership version and active policy immediately before an
/// effect. No caller-provided tenant context or policy is accepted.
#[allow(clippy::too_many_arguments)]
pub fn authorize_compact_in_tenant<R: RevocationChecker, S: AuditSink>(
    compact_credential: &str,
    expected_audience: &str,
    requested_tenant_id: &str,
    request: &AuthorizationRequest,
    genesis: &VerifiedGenesis,
    approval: Option<&SignedOwnerApproval>,
    credential_verifier: &Ed25519CredentialVerifier<R>,
    owner_verifier: &OwnerApprovalVerifier,
    audit_sink: &S,
    now: u64,
    max_membership_age_secs: u64,
    event_id: &str,
    correlation_id: &str,
) -> Decision {
    let principal = match credential_verifier.authenticate(
        compact_credential,
        expected_audience,
        now,
    ) {
        Ok(principal) => principal,
        Err(error) => {
            let reason = match error {
                CredentialError::Expired | CredentialError::NotYetValid
                | CredentialError::IssuedInFuture => DecisionReason::IdentityExpired,
                CredentialError::Malformed => DecisionReason::MalformedRequest,
                _ => DecisionReason::IdentityVerificationFailed,
            };
            let decision = Decision::new(DecisionCode::Deny, reason, "unavailable");
            return audit_unresolved(
                audit_sink,
                request,
                "unavailable",
                decision,
                now,
                event_id,
                correlation_id,
            );
        }
    };

    if principal.subject() != request.subject() {
        let decision = Decision::new(
            DecisionCode::Deny,
            DecisionReason::IdentitySubjectMismatch,
            "unavailable",
        );
        return audit_unresolved(audit_sink, request, "unavailable", decision, now, event_id, correlation_id);
    }

    let resolver = owner_verifier.tenant_membership_resolver();
    let tenant = match resolver.resolve(&principal, requested_tenant_id, now, max_membership_age_secs) {
        Ok(context) => context,
        Err(error) => {
            let (code, reason) = match error {
                crate::TenantResolutionError::Malformed => {
                    (DecisionCode::Deny, DecisionReason::TenantSelectorMalformed)
                }
                crate::TenantResolutionError::MembershipMissing => {
                    (DecisionCode::Deny, DecisionReason::TenantMembershipMissing)
                }
                crate::TenantResolutionError::MembershipInactive => {
                    (DecisionCode::Deny, DecisionReason::TenantMembershipInactive)
                }
                crate::TenantResolutionError::MembershipStale => {
                    (DecisionCode::Deny, DecisionReason::TenantMembershipStale)
                }
                crate::TenantResolutionError::StoreUnavailable => (
                    DecisionCode::Escalate,
                    DecisionReason::TenantAuthorityUnavailable,
                ),
            };
            let decision = Decision::new(code, reason, "unavailable");
            return audit_unresolved(audit_sink, request, "unavailable", decision, now, event_id, correlation_id);
        }
    };

    let policy = match crate::PolicyActivationCoordinator::load_active(owner_verifier, now) {
        Ok(context) => context,
        Err(_) => {
            let decision = Decision::new(
                DecisionCode::Escalate,
                DecisionReason::PolicyUnavailable,
                "unavailable",
            );
            let bound_sink = TenantBoundAuditSink {
                inner: audit_sink,
                tenant_id: tenant.tenant_id(),
                membership_version: tenant.membership_version(),
                correlation_id,
            };
            let event = AuditEvent::new(
                event_id,
                correlation_id,
                request.subject(),
                request.capability(),
                request.resource(),
                "unavailable",
                decision.code(),
                now,
            );
            return record_decision(&bound_sink, &event, decision);
        }
    };

    let bound_sink = TenantBoundAuditSink {
        inner: audit_sink,
        tenant_id: tenant.tenant_id(),
        membership_version: tenant.membership_version(),
        correlation_id,
    };
    crate::authorize_authenticated_with_owner_approval(
        request,
        &principal,
        genesis,
        approval,
        owner_verifier,
        &bound_sink,
        policy.policy(),
        now,
        policy.emergency_stop_active(),
        event_id,
        correlation_id,
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CaptureAudit(Mutex<Option<AuditEvent>>);

    impl AuditSink for CaptureAudit {
        fn append(&self, event: &AuditEvent) -> Result<(), crate::AuditError> {
            *self.0.lock().unwrap() = Some(event.clone());
            Ok(())
        }
    }

    struct RejectAudit;
    impl AuditSink for RejectAudit {
        fn append(&self, _: &AuditEvent) -> Result<(), crate::AuditError> {
            Err(crate::AuditError::Unavailable)
        }
    }

    #[test]
    fn tenant_decision_audit_binds_tenant_and_membership_version() {
        let capture = CaptureAudit::default();
        let sink = TenantBoundAuditSink {
            inner: &capture,
            tenant_id: "tenant:alpha",
            membership_version: 7,
            correlation_id: "trace:request-1",
        };
        let event = AuditEvent::new(
            "event:1",
            "trace:inner",
            "principal:alice",
            "workspace.read",
            "workspace:1",
            "policy-global-v1",
            DecisionCode::Allow,
            1_800,
        );
        sink.append(&event).unwrap();
        let stored = capture.0.lock().unwrap().clone().unwrap();
        assert_eq!(
            stored.correlation_id(),
            "tenant:tenant:alpha:membership-version:7:trace:request-1:trace:inner"
        );
        assert_eq!(stored.resource(), "workspace:1");
        assert_eq!(stored.policy_version(), "policy-global-v1");
    }

    #[test]
    fn unresolved_tenant_audit_failure_escalates() {
        let request = AuthorizationRequest::new(
            "principal:alice",
            "workspace.read",
            "workspace:1",
            crate::RiskLevel::Low,
        );
        let decision = Decision::new(
            DecisionCode::Deny,
            DecisionReason::TenantMembershipMissing,
            "unavailable",
        );
        let result = audit_unresolved(
            &RejectAudit,
            &request,
            "unavailable",
            decision,
            1_800,
            "event:missing-tenant",
            "trace:missing-tenant",
        );
        assert_eq!(result.code(), DecisionCode::Escalate);
        assert_eq!(result.reason(), DecisionReason::AuditUnavailable);
    }
}
