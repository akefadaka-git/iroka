//! G02 governance and approval-evidence contract.

use crate::{AuthorizationRequest, IdentityAssertion, VerifiedPrincipal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalEvidence {
    approval_id: String,
    approver: IdentityAssertion,
    capability: String,
    resource: String,
    request_subject: String,
    policy_version: String,
    expires_at: u64,
}

impl ApprovalEvidence {
    pub fn new(
        approval_id: impl Into<String>,
        approver: IdentityAssertion,
        capability: impl Into<String>,
        resource: impl Into<String>,
        request_subject: impl Into<String>,
        policy_version: impl Into<String>,
        expires_at: u64,
    ) -> Self {
        Self {
            approval_id: approval_id.into(),
            approver,
            capability: capability.into(),
            resource: resource.into(),
            request_subject: request_subject.into(),
            policy_version: policy_version.into(),
            expires_at,
        }
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }
    pub fn approver_assertion(&self) -> &IdentityAssertion {
        &self.approver
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Verifies Owner/delegate authority, approval authenticity, separation of duties,
/// approval status and revocation against the authoritative governance store.
/// A positive result is meaningful only when the implementation is trusted.
pub trait ApprovalVerifier {
    fn verify_approval(
        &self,
        evidence: &ApprovalEvidence,
        approver: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        policy_version: &str,
        now: u64,
    ) -> Result<(), ApprovalError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    Malformed,
    Expired,
    ScopeMismatch,
    UnauthorizedApprover,
    RevokedOrUnknown,
    VerificationFailed,
}

pub fn validate_approval_scope(
    evidence: &ApprovalEvidence,
    request: &AuthorizationRequest,
    policy_version: &str,
    now: u64,
) -> Result<(), ApprovalError> {
    if evidence.approval_id.trim().is_empty()
        || evidence.capability.trim().is_empty()
        || evidence.resource.trim().is_empty()
        || evidence.request_subject.trim().is_empty()
        || evidence.policy_version.trim().is_empty()
    {
        return Err(ApprovalError::Malformed);
    }
    if evidence.expires_at <= now {
        return Err(ApprovalError::Expired);
    }
    if evidence.capability != request.capability()
        || evidence.resource != request.resource()
        || evidence.request_subject != request.subject()
        || evidence.policy_version != policy_version
    {
        return Err(ApprovalError::ScopeMismatch);
    }
    Ok(())
}
