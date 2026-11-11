//! G02 Owner-governed organization authority.
//! This module consumes G01 verified principals and tenant contexts; it does not
//! create identities, tenant memberships, or caller-asserted roles.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{SecurityStoreError, SqliteSecurityStore, TenantContext, VerifiedPrincipal};

const MAX_AUTHORITY_AGE_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationAuthorityError {
    Malformed,
    OrganizationMissing,
    OrganizationInactive,
    TenantMismatch,
    DesignationMissing,
    DesignationInactive,
    CapabilityDenied,
    Stale,
    StoreUnavailable,
}

impl From<SecurityStoreError> for OrganizationAuthorityError {
    fn from(_: SecurityStoreError) -> Self { Self::StoreUnavailable }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrganizationAuthorityAction {
    CreateOrganization,
    SetDesignation,
    RevokeDesignation,
    SetOrganizationActive { active: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrganizationAuthorityPayload {
    pub command_id: String,
    pub owner_subject: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub organization_id: String,
    pub tenant_id: String,
    pub principal: Option<String>,
    pub designation_id: Option<String>,
    pub action: OrganizationAuthorityAction,
    pub version: u64,
    pub capabilities: Vec<String>,
    pub reason: String,
}

impl OrganizationAuthorityPayload {
    /// Dedicated G02 domain; the payload cannot be replayed as a generic G02
    /// security command or an approval payload.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, OrganizationAuthorityError> {
        let body = serde_jcs::to_vec(self).map_err(|_| OrganizationAuthorityError::Malformed)?;
        let mut bytes = b"IROKA:G02:ORGANIZATION_AUTHORITY:V1\0".to_vec();
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), OrganizationAuthorityError> {
        if self.command_id.trim().is_empty() || self.owner_subject.trim().is_empty()
            || self.key_id.trim().is_empty() || self.organization_id.trim().is_empty()
            || self.tenant_id.trim().is_empty() || self.reason.trim().is_empty()
            || self.version == 0 || self.issued_at >= self.expires_at
            || self.command_id.len() > 256 || self.organization_id.len() > 256
            || self.tenant_id.len() > 256 || self.reason.len() > 1024
            || self.expires_at - self.issued_at > 900
        { return Err(OrganizationAuthorityError::Malformed); }

        let mut previous: Option<&str> = None;
        for capability in &self.capabilities {
            if capability.trim().is_empty() || capability.len() > 128
                || previous.is_some_and(|p| p >= capability.as_str())
            { return Err(OrganizationAuthorityError::Malformed); }
            previous = Some(capability);
        }
        match self.action {
            OrganizationAuthorityAction::CreateOrganization => {
                if self.principal.is_some() || self.designation_id.is_some() || !self.capabilities.is_empty() {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
            OrganizationAuthorityAction::SetDesignation => {
                if self.principal.as_deref().is_none_or(str::is_empty)
                    || self.designation_id.as_deref().is_none_or(str::is_empty)
                    || self.capabilities.is_empty()
                { return Err(OrganizationAuthorityError::Malformed); }
            }
            OrganizationAuthorityAction::RevokeDesignation => {
                if self.principal.as_deref().is_none_or(str::is_empty)
                    || self.designation_id.as_deref().is_none_or(str::is_empty)
                    || !self.capabilities.is_empty()
                { return Err(OrganizationAuthorityError::Malformed); }
            }
            OrganizationAuthorityAction::SetOrganizationActive { .. } => {
                if self.principal.is_some() || self.designation_id.is_some() || !self.capabilities.is_empty() {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOrganizationAuthorityCommand {
    pub payload: OrganizationAuthorityPayload,
    pub signature: Vec<u8>,
}

impl SignedOrganizationAuthorityCommand {
    pub fn from_signature(payload: OrganizationAuthorityPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationContext {
    subject: String,
    tenant_id: String,
    organization_id: String,
    designation_id: String,
    designation_version: u64,
    capability: String,
    resolved_at: u64,
}

impl OrganizationContext {
    pub fn subject(&self) -> &str { &self.subject }
    pub fn tenant_id(&self) -> &str { &self.tenant_id }
    pub fn organization_id(&self) -> &str { &self.organization_id }
    pub fn designation_id(&self) -> &str { &self.designation_id }
    pub fn designation_version(&self) -> u64 { self.designation_version }
    pub fn capability(&self) -> &str { &self.capability }
    pub fn resolved_at(&self) -> u64 { self.resolved_at }
}

/// Reads canonical G02 state on every privileged decision. SQLite is a
/// single-node adapter; production/multi-node use requires a separately
/// reviewed shared transactional implementation.
pub struct OrganizationAuthorityResolver {
    store: Arc<SqliteSecurityStore>,
}

impl OrganizationAuthorityResolver {
    pub fn new(store: Arc<SqliteSecurityStore>) -> Self { Self { store } }

    pub fn resolve(
        &self,
        principal: &VerifiedPrincipal,
        tenant: &TenantContext,
        organization_id: &str,
        capability: &str,
        now: u64,
        max_age_secs: u64,
    ) -> Result<OrganizationContext, OrganizationAuthorityError> {
        if principal.subject().trim().is_empty() || tenant.subject() != principal.subject()
            || organization_id.trim().is_empty() || capability.trim().is_empty()
            || max_age_secs == 0 || max_age_secs > MAX_AUTHORITY_AGE_SECS
        { return Err(OrganizationAuthorityError::Malformed); }

        let (bound_tenant, org_active, _org_version, org_updated) =
            self.store.organization_state(organization_id)?
                .ok_or(OrganizationAuthorityError::OrganizationMissing)?;
        if !org_active { return Err(OrganizationAuthorityError::OrganizationInactive); }
        if bound_tenant != tenant.tenant_id() { return Err(OrganizationAuthorityError::TenantMismatch); }
        if org_updated > now || now.saturating_sub(org_updated) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let (designation_id, active, capabilities_json, version, updated) =
            self.store.organization_designation(organization_id, principal.subject())?
                .ok_or(OrganizationAuthorityError::DesignationMissing)?;
        if !active { return Err(OrganizationAuthorityError::DesignationInactive); }
        if updated > now || now.saturating_sub(updated) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let capabilities: Vec<String> = serde_json::from_str(&capabilities_json)
            .map_err(|_| OrganizationAuthorityError::StoreUnavailable)?;
        if !capabilities.iter().any(|c| c == capability) {
            return Err(OrganizationAuthorityError::CapabilityDenied);
        }
        Ok(OrganizationContext {
            subject: principal.subject().to_owned(),
            tenant_id: tenant.tenant_id().to_owned(),
            organization_id: organization_id.to_owned(),
            designation_id,
            designation_version: version,
            capability: capability.to_owned(),
            resolved_at: now,
        })
    }
}
