#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionCode {
    Allow,
    Deny,
    RequireApproval,
    Escalate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    PolicySatisfied,
    MalformedRequest,
    CapabilityNotGranted,
    RiskExceedsPolicy,
    HumanApprovalRequired,
    EmergencyStopActive,
    IdentitySubjectMismatch,
    IdentityExpired,
    IdentityVerificationFailed,
    ApprovalVerified,
    ApprovalMalformed,
    ApprovalExpired,
    ApprovalScopeMismatch,
    ApprovalUnauthorized,
    ApprovalRevokedOrUnknown,
    ApprovalVerificationFailed,
    AuditUnavailable,
    ConstitutionalValidationFailed,
    TenantSelectorMalformed,
    TenantMembershipMissing,
    TenantMembershipInactive,
    TenantMembershipStale,
    TenantAuthorityUnavailable,
    PolicyUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    code: DecisionCode,
    reason: DecisionReason,
    policy_version: String,
}

impl Decision {
    pub(crate) fn new(code: DecisionCode, reason: DecisionReason, policy_version: &str) -> Self {
        Self {
            code,
            reason,
            policy_version: policy_version.to_owned(),
        }
    }
    pub fn code(&self) -> DecisionCode {
        self.code
    }
    pub fn reason(&self) -> DecisionReason {
        self.reason
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
}
