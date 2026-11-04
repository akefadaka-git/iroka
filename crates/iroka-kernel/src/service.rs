//! Governed authorization pipeline. This module decides; it never executes.

use crate::{
    authenticate, evaluate, record_decision, validate_approval_scope, ApprovalError,
    ApprovalEvidence, ApprovalVerifier, AuditEvent, AuditSink, AuthorizationRequest, Decision,
    DecisionCode, DecisionReason, IdentityAssertion, IdentityError, IdentityVerifier,
    OwnerApprovalError, OwnerApprovalVerifier, Policy, SignedOwnerApproval, VerifiedPrincipal,
};

fn identity_failure(error: IdentityError, policy: &Policy) -> Decision {
    let reason = match error {
        IdentityError::Malformed => DecisionReason::MalformedRequest,
        IdentityError::Expired => DecisionReason::IdentityExpired,
        IdentityError::VerificationFailed => DecisionReason::IdentityVerificationFailed,
    };
    Decision::new(DecisionCode::Deny, reason, policy.version())
}

fn approval_failure(error: ApprovalError, policy: &Policy) -> Decision {
    let reason = match error {
        ApprovalError::Malformed => DecisionReason::ApprovalMalformed,
        ApprovalError::Expired => DecisionReason::ApprovalExpired,
        ApprovalError::ScopeMismatch => DecisionReason::ApprovalScopeMismatch,
        ApprovalError::UnauthorizedApprover => DecisionReason::ApprovalUnauthorized,
        ApprovalError::RevokedOrUnknown => DecisionReason::ApprovalRevokedOrUnknown,
        ApprovalError::VerificationFailed => DecisionReason::ApprovalVerificationFailed,
    };
    Decision::new(DecisionCode::Escalate, reason, policy.version())
}

/// Evaluate an operation through identity, policy, optional approval and audit.
///
/// The returned ALLOW is a decision only. It is not an execution grant and must
/// not be used to perform a protected side effect. G09 must later exchange
/// independently verified decision evidence for a short-lived execution grant.
#[allow(clippy::too_many_arguments)] // Keeps the authorization trust dependencies explicit.
pub(crate) fn authorize<I, A, S>(
    request: &AuthorizationRequest,
    subject_assertion: &IdentityAssertion,
    approval: Option<&ApprovalEvidence>,
    identity_verifier: &I,
    approval_verifier: &A,
    audit_sink: &S,
    policy: &Policy,
    expected_audience: &str,
    now: u64,
    emergency_stop_active: bool,
    event_id: &str,
    correlation_id: &str,
) -> Decision
where
    I: IdentityVerifier,
    A: ApprovalVerifier,
    S: AuditSink,
{
    let decision = match authenticate(identity_verifier, subject_assertion, expected_audience, now)
    {
        Err(error) => identity_failure(error, policy),
        Ok(principal) if principal.subject() != request.subject() => Decision::new(
            DecisionCode::Deny,
            DecisionReason::IdentitySubjectMismatch,
            policy.version(),
        ),
        Ok(_principal) => {
            let initial = evaluate(request, policy, emergency_stop_active);
            if initial.code() != DecisionCode::RequireApproval {
                initial
            } else if let Some(evidence) = approval {
                match validate_approval_scope(evidence, request, policy.version(), now) {
                    Err(error) => approval_failure(error, policy),
                    Ok(()) => match authenticate(
                        identity_verifier,
                        evidence.approver_assertion(),
                        expected_audience,
                        now,
                    ) {
                        Err(error) => identity_failure(error, policy),
                        Ok(approver) => match approval_verifier.verify_approval(
                            evidence,
                            &approver,
                            request,
                            policy.version(),
                            now,
                        ) {
                            Ok(()) => Decision::new(
                                DecisionCode::Allow,
                                DecisionReason::ApprovalVerified,
                                policy.version(),
                            ),
                            Err(error) => approval_failure(error, policy),
                        },
                    },
                }
            } else {
                initial
            }
        }
    };

    let event = AuditEvent::new(
        event_id,
        correlation_id,
        request.subject(),
        request.capability(),
        request.resource(),
        policy.version(),
        decision.code(),
        now,
    );
    record_decision(audit_sink, &event, decision)
}

/// Continue authorization using a principal produced by a concrete credential
/// verifier. This is the production integration point for G01 compact credentials.
/// The principal cannot be constructed by downstream callers.
#[allow(clippy::too_many_arguments)] // Keeps the authorization trust dependencies explicit.
pub(crate) fn authorize_authenticated<I, A, S>(
    request: &AuthorizationRequest,
    principal: &VerifiedPrincipal,
    approval: Option<&ApprovalEvidence>,
    approver_identity_verifier: &I,
    approval_verifier: &A,
    audit_sink: &S,
    policy: &Policy,
    expected_audience: &str,
    now: u64,
    emergency_stop_active: bool,
    event_id: &str,
    correlation_id: &str,
) -> Decision
where
    I: IdentityVerifier,
    A: ApprovalVerifier,
    S: AuditSink,
{
    let decision = if principal.subject() != request.subject() {
        Decision::new(
            DecisionCode::Deny,
            DecisionReason::IdentitySubjectMismatch,
            policy.version(),
        )
    } else {
        let initial = evaluate(request, policy, emergency_stop_active);
        if initial.code() != DecisionCode::RequireApproval {
            initial
        } else if let Some(evidence) = approval {
            match validate_approval_scope(evidence, request, policy.version(), now) {
                Err(error) => approval_failure(error, policy),
                Ok(()) => match authenticate(
                    approver_identity_verifier,
                    evidence.approver_assertion(),
                    expected_audience,
                    now,
                ) {
                    Err(error) => identity_failure(error, policy),
                    Ok(approver) => match approval_verifier.verify_approval(
                        evidence,
                        &approver,
                        request,
                        policy.version(),
                        now,
                    ) {
                        Ok(()) => Decision::new(
                            DecisionCode::Allow,
                            DecisionReason::ApprovalVerified,
                            policy.version(),
                        ),
                        Err(error) => approval_failure(error, policy),
                    },
                },
            }
        } else {
            initial
        }
    };

    let event = AuditEvent::new(
        event_id,
        correlation_id,
        request.subject(),
        request.capability(),
        request.resource(),
        policy.version(),
        decision.code(),
        now,
    );
    record_decision(audit_sink, &event, decision)
}

/// Production Owner-approval path. Unlike the legacy assertion-based adapter,
/// this verifies a cryptographic Owner signature against explicitly provisioned
/// Owner public keys and atomically consumes the approval ID before returning ALLOW.
#[allow(clippy::too_many_arguments)]
pub fn authorize_authenticated_with_owner_approval<S: AuditSink>(
    request: &AuthorizationRequest,
    principal: &VerifiedPrincipal,
    approval: Option<&SignedOwnerApproval>,
    owner_approval_verifier: &OwnerApprovalVerifier,
    audit_sink: &S,
    policy: &Policy,
    now: u64,
    emergency_stop_active: bool,
    event_id: &str,
    correlation_id: &str,
) -> Decision {
    let decision = if principal.subject() != request.subject() {
        Decision::new(
            DecisionCode::Deny,
            DecisionReason::IdentitySubjectMismatch,
            policy.version(),
        )
    } else {
        let initial = evaluate(request, policy, emergency_stop_active);
        if initial.code() != DecisionCode::RequireApproval {
            initial
        } else if let Some(evidence) = approval {
            match owner_approval_verifier.verify_and_consume(
                evidence,
                request,
                policy.version(),
                now,
            ) {
                Ok(()) => Decision::new(
                    DecisionCode::Allow,
                    DecisionReason::ApprovalVerified,
                    policy.version(),
                ),
                Err(error) => {
                    let reason = match error {
                        OwnerApprovalError::Malformed => DecisionReason::ApprovalMalformed,
                        OwnerApprovalError::Expired
                        | OwnerApprovalError::NotYetValid
                        | OwnerApprovalError::OwnerKeyOutsideValidity => {
                            DecisionReason::ApprovalExpired
                        }
                        OwnerApprovalError::ScopeMismatch => DecisionReason::ApprovalScopeMismatch,
                        OwnerApprovalError::UnknownOwnerKey => DecisionReason::ApprovalUnauthorized,
                        OwnerApprovalError::Revoked | OwnerApprovalError::Replay => {
                            DecisionReason::ApprovalRevokedOrUnknown
                        }
                        OwnerApprovalError::InvalidSignature
                        | OwnerApprovalError::StoreUnavailable => {
                            DecisionReason::ApprovalVerificationFailed
                        }
                    };
                    Decision::new(DecisionCode::Escalate, reason, policy.version())
                }
            }
        } else {
            initial
        }
    };

    let event = AuditEvent::new(
        event_id,
        correlation_id,
        request.subject(),
        request.capability(),
        request.resource(),
        policy.version(),
        decision.code(),
        now,
    );
    record_decision(audit_sink, &event, decision)
}
