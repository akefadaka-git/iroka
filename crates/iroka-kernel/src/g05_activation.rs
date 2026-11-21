//! G02 canonical decision boundary for G05 durable-memory activation.
//!
//! This module binds organization authority to the complete immutable G05
//! activation tuple. It returns an opaque decision only after current G02
//! designation (and, when supplied, delegation) resolution succeeds. It does
//! not inspect memory content or replace G01 proof verification.
use crate::{
    OrganizationAuthorityError, OrganizationAuthorityResolver, TenantContext, VerifiedPrincipal,
};

const MAX_REF_BYTES: usize = 512;
const G05_ACTIVATE_CAPABILITY: &str = "g05.memory.durable.activate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct G05ActivationTuple {
    pub tenant_id: String,
    pub organization_id: String,
    pub reviewer_subject: String,
    pub designation_id: String,
    pub designation_version: u64,
    pub delegation_id: Option<String>,
    pub delegation_version: Option<u64>,
    pub action: String,
    pub memory_id: String,
    pub record_version: u64,
    pub content_sha256: String,
    pub purpose: String,
    pub classification: String,
    pub policy_version: String,
}

impl G05ActivationTuple {
    pub fn validate(&self) -> Result<(), G05ActivationDecisionError> {
        let refs = [
            self.tenant_id.as_str(),
            self.organization_id.as_str(),
            self.reviewer_subject.as_str(),
            self.designation_id.as_str(),
            self.action.as_str(),
            self.memory_id.as_str(),
            self.content_sha256.as_str(),
            self.purpose.as_str(),
            self.classification.as_str(),
            self.policy_version.as_str(),
        ];
        if refs
            .iter()
            .any(|v| v.trim().is_empty() || v.len() > MAX_REF_BYTES)
            || self.designation_version == 0
            || self.record_version == 0
            || self.content_sha256.len() != 64
            || !self.content_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || self.action != G05_ACTIVATE_CAPABILITY
            || self
                .delegation_id
                .as_ref()
                .is_some_and(|v| v.trim().is_empty() || v.len() > MAX_REF_BYTES)
            || self.delegation_version.is_some_and(|v| v == 0)
            || self.delegation_id.is_some() != self.delegation_version.is_some()
        {
            return Err(G05ActivationDecisionError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G05ActivationDecisionError {
    Malformed,
    PrincipalMismatch,
    TenantMismatch,
    OrganizationAuthorityDenied,
    DesignationMismatch,
    DelegationMismatch,
}

impl From<OrganizationAuthorityError> for G05ActivationDecisionError {
    fn from(_: OrganizationAuthorityError) -> Self {
        Self::OrganizationAuthorityDenied
    }
}

/// Opaque, request-scoped result. Construction is private; consumers can only
/// inspect the exact tuple and the resolution timestamp after G02 allowed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct G05ActivationDecision {
    tuple: G05ActivationTuple,
    resolved_at: u64,
}
impl G05ActivationDecision {
    pub fn tuple(&self) -> &G05ActivationTuple {
        &self.tuple
    }
    pub fn resolved_at(&self) -> u64 {
        self.resolved_at
    }
}

impl OrganizationAuthorityResolver {
    /// Revalidates the current reviewer designation and optional delegation
    /// against G02 canonical state for this exact G05 activation tuple.
    /// Missing, stale, revoked, mismatched or unavailable authority fails closed.
    pub fn resolve_g05_activation(
        &self,
        reviewer: &VerifiedPrincipal,
        tenant: &TenantContext,
        tuple: &G05ActivationTuple,
        now: u64,
        max_age_secs: u64,
    ) -> Result<G05ActivationDecision, G05ActivationDecisionError> {
        tuple.validate()?;
        if reviewer.subject() != tuple.reviewer_subject
            || tenant.subject() != reviewer.subject()
            || tenant.tenant_id() != tuple.tenant_id
        {
            return Err(G05ActivationDecisionError::PrincipalMismatch);
        }
        if let (Some(id), Some(version)) = (&tuple.delegation_id, tuple.delegation_version) {
            // Delegated reviewers are authorized through the live delegation
            // and the delegator's current designation; they need not hold a
            // separate direct designation of their own.
            let delegation = self.resolve_delegation(
                reviewer,
                tenant,
                &tuple.organization_id,
                id,
                G05_ACTIVATE_CAPABILITY,
                now,
                max_age_secs,
            )?;
            if delegation.version() != version
                || delegation.designation_id() != tuple.designation_id
                || delegation.designation_version() != tuple.designation_version
                || delegation.tenant_id() != tuple.tenant_id
                || delegation.organization_id() != tuple.organization_id
                || delegation.delegate() != reviewer.subject()
            {
                return Err(G05ActivationDecisionError::DelegationMismatch);
            }
        } else {
            let designation = self.resolve(
                reviewer,
                tenant,
                &tuple.organization_id,
                G05_ACTIVATE_CAPABILITY,
                now,
                max_age_secs,
            )?;
            if designation.designation_id() != tuple.designation_id
                || designation.designation_version() != tuple.designation_version
                || designation.tenant_id() != tuple.tenant_id
                || designation.organization_id() != tuple.organization_id
            {
                return Err(G05ActivationDecisionError::DesignationMismatch);
            }
        }
        Ok(G05ActivationDecision {
            tuple: tuple.clone(),
            resolved_at: now,
        })
    }
}
