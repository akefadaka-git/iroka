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

/// Opaque evidence that the kernel completed an authenticated, Owner-approved
/// authorization decision and durably recorded its audit event. Only the kernel
/// authorization service can construct this value; a Decision alone is not enough.
#[derive(Debug, PartialEq, Eq)]
pub struct GovernedDecisionEvidence {
    decision_id: String,
    correlation_id: String,
    subject: String,
    capability: String,
    resource: String,
    policy_version: String,
    risk: crate::RiskLevel,
    reason: DecisionReason,
    genesis_digest: String,
    issued_at: u64,
}

impl GovernedDecisionEvidence {
    pub(crate) fn from_approved_decision(
        request: &crate::AuthorizationRequest,
        decision: &Decision,
        genesis_digest: &str,
        issued_at: u64,
        decision_id: &str,
        correlation_id: &str,
    ) -> Option<Self> {
        if decision.code() != DecisionCode::Allow
            || decision.reason() != DecisionReason::ApprovalVerified
            || !request.is_well_formed()
            || genesis_digest.len() != 64
            || !genesis_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || issued_at == 0
            || decision_id.trim().is_empty()
            || correlation_id.trim().is_empty()
        {
            return None;
        }
        Some(Self {
            decision_id: decision_id.to_owned(),
            correlation_id: correlation_id.to_owned(),
            subject: request.subject().to_owned(),
            capability: request.capability().to_owned(),
            resource: request.resource().to_owned(),
            policy_version: decision.policy_version().to_owned(),
            risk: request.risk(),
            reason: decision.reason(),
            genesis_digest: genesis_digest.to_ascii_lowercase(),
            issued_at,
        })
    }

    #[must_use]
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    #[must_use]
    pub fn risk(&self) -> crate::RiskLevel {
        self.risk
    }

    #[must_use]
    pub fn reason(&self) -> DecisionReason {
        self.reason
    }

    #[must_use]
    pub fn genesis_digest(&self) -> &str {
        &self.genesis_digest
    }

    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
}
