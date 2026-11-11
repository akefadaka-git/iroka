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
    DelegationMissing,
    DelegationInactive,
    CapabilityDenied,
    Stale,
    StoreUnavailable,
}

impl From<SecurityStoreError> for OrganizationAuthorityError {
    fn from(_: SecurityStoreError) -> Self {
        Self::StoreUnavailable
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrganizationAuthorityAction {
    CreateOrganization,
    SetDesignation,
    RevokeDesignation,
    SetDelegation,
    RevokeDelegation,
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
    pub delegate: Option<String>,
    pub delegation_expires_at: Option<u64>,
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
        if self.command_id.trim().is_empty()
            || self.owner_subject.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.organization_id.trim().is_empty()
            || self.tenant_id.trim().is_empty()
            || self.reason.trim().is_empty()
            || self.version == 0
            || self.issued_at >= self.expires_at
            || self.command_id.len() > 256
            || self.organization_id.len() > 256
            || self.tenant_id.len() > 256
            || self.reason.len() > 1024
            || self.expires_at - self.issued_at > 900
        {
            return Err(OrganizationAuthorityError::Malformed);
        }

        let mut previous: Option<&str> = None;
        for capability in &self.capabilities {
            if capability.trim().is_empty()
                || capability.len() > 128
                || previous.is_some_and(|p| p >= capability.as_str())
            {
                return Err(OrganizationAuthorityError::Malformed);
            }
            previous = Some(capability);
        }
        match &self.action {
            OrganizationAuthorityAction::CreateOrganization => {
                if self.principal.is_some()
                    || self.designation_id.is_some()
                    || self.delegate.is_some()
                    || self.delegation_expires_at.is_some()
                    || !self.capabilities.is_empty()
                {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
            OrganizationAuthorityAction::SetDesignation => {
                if self.principal.as_deref().map_or(true, str::is_empty)
                    || self.designation_id.as_deref().map_or(true, str::is_empty)
                    || self.capabilities.is_empty()
                    || self.delegate.is_some()
                    || self.delegation_expires_at.is_some()
                {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
            OrganizationAuthorityAction::RevokeDesignation => {
                if self.principal.as_deref().map_or(true, str::is_empty)
                    || self.designation_id.as_deref().map_or(true, str::is_empty)
                    || !self.capabilities.is_empty()
                    || self.delegate.is_some()
                    || self.delegation_expires_at.is_some()
                {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
            OrganizationAuthorityAction::SetDelegation => {
                let delegate = self.delegate.as_deref().unwrap_or_default();
                let valid_until = self.delegation_expires_at.unwrap_or_default();
                if self.principal.as_deref().map_or(true, str::is_empty)
                    || self.designation_id.as_deref().map_or(true, str::is_empty)
                    || delegate.trim().is_empty()
                    || delegate.len() > 256
                    || self.capabilities.is_empty()
                    || valid_until <= self.issued_at
                    || valid_until > self.expires_at
                {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
            OrganizationAuthorityAction::RevokeDelegation => {
                if self.principal.as_deref().map_or(true, str::is_empty)
                    || self.designation_id.as_deref().map_or(true, str::is_empty)
                    || self.delegate.as_deref().map_or(true, str::is_empty)
                    || self.delegation_expires_at.is_some()
                    || !self.capabilities.is_empty()
                {
                    return Err(OrganizationAuthorityError::Malformed);
                }
            }
            OrganizationAuthorityAction::SetOrganizationActive { .. } => {
                if self.principal.is_some()
                    || self.designation_id.is_some()
                    || self.delegate.is_some()
                    || self.delegation_expires_at.is_some()
                    || !self.capabilities.is_empty()
                {
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
pub struct DelegationContext {
    delegation_id: String,
    delegator: String,
    delegate: String,
    tenant_id: String,
    organization_id: String,
    version: u64,
    capability: String,
    resolved_at: u64,
}

impl DelegationContext {
    pub fn delegation_id(&self) -> &str { &self.delegation_id }
    pub fn delegator(&self) -> &str { &self.delegator }
    pub fn delegate(&self) -> &str { &self.delegate }
    pub fn tenant_id(&self) -> &str { &self.tenant_id }
    pub fn organization_id(&self) -> &str { &self.organization_id }
    pub fn version(&self) -> u64 { self.version }
    pub fn capability(&self) -> &str { &self.capability }
    pub fn resolved_at(&self) -> u64 { self.resolved_at }
}

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
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
    pub fn designation_id(&self) -> &str {
        &self.designation_id
    }
    pub fn designation_version(&self) -> u64 {
        self.designation_version
    }
    pub fn capability(&self) -> &str {
        &self.capability
    }
    pub fn resolved_at(&self) -> u64 {
        self.resolved_at
    }
}

/// Reads canonical G02 state on every privileged decision. SQLite is a
/// single-node adapter; production/multi-node use requires a separately
/// reviewed shared transactional implementation.
pub struct OrganizationAuthorityResolver {
    store: Arc<SqliteSecurityStore>,
}

impl OrganizationAuthorityResolver {
    pub fn new(store: Arc<SqliteSecurityStore>) -> Self {
        Self { store }
    }

    /// Resolve a current Owner-signed delegation grant. This verifies the
    /// exact delegate, tenant, organization, capability and live delegator
    /// designation; it does not itself execute a delegated mutation.
    pub fn resolve_delegation(
        &self,
        delegate: &VerifiedPrincipal,
        tenant: &TenantContext,
        organization_id: &str,
        delegation_id: &str,
        capability: &str,
        now: u64,
        max_age_secs: u64,
    ) -> Result<DelegationContext, OrganizationAuthorityError> {
        if delegate.subject().trim().is_empty()
            || tenant.subject() != delegate.subject()
            || organization_id.trim().is_empty()
            || delegation_id.trim().is_empty()
            || capability.trim().is_empty()
            || max_age_secs == 0
            || max_age_secs > MAX_AUTHORITY_AGE_SECS
        {
            return Err(OrganizationAuthorityError::Malformed);
        }
        if tenant.resolved_at() > now || now.saturating_sub(tenant.resolved_at()) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let membership = self.store.tenant_membership(delegate.subject(), tenant.tenant_id())?
            .ok_or(OrganizationAuthorityError::TenantMismatch)?;
        if !membership.0 || membership.1 != tenant.membership_version() {
            return Err(OrganizationAuthorityError::TenantMismatch);
        }
        if membership.2 > now || now.saturating_sub(membership.2) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let (bound_tenant, org_active, _, org_updated) = self.store.organization_state(organization_id)?
            .ok_or(OrganizationAuthorityError::OrganizationMissing)?;
        if bound_tenant != tenant.tenant_id() { return Err(OrganizationAuthorityError::TenantMismatch); }
        if !org_active { return Err(OrganizationAuthorityError::OrganizationInactive); }
        if org_updated > now || now.saturating_sub(org_updated) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let (delegator, stored_delegate, stored_tenant, stored_org, active, caps_json, version, valid_until, updated) = self.store.organization_delegation(delegation_id)?
            .ok_or(OrganizationAuthorityError::DelegationMissing)?;
        if !active || valid_until <= now { return Err(OrganizationAuthorityError::DelegationInactive); }
        if updated > now || now.saturating_sub(updated) > max_age_secs { return Err(OrganizationAuthorityError::Stale); }
        let delegation_caps: Vec<String> = serde_json::from_str(&caps_json)
            .map_err(|_| OrganizationAuthorityError::StoreUnavailable)?;
        if !delegation_caps.iter().any(|item| item == capability) {
            return Err(OrganizationAuthorityError::CapabilityDenied);
        }
        let (designation_id, designation_active, designation_caps_json, _, designation_updated) = self.store.organization_designation(organization_id, &delegator)?
            .ok_or(OrganizationAuthorityError::DesignationMissing)?;
        if !designation_active { return Err(OrganizationAuthorityError::DesignationInactive); }
        if designation_updated > now || now.saturating_sub(designation_updated) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let designation_caps: Vec<String> = serde_json::from_str(&designation_caps_json)
            .map_err(|_| OrganizationAuthorityError::StoreUnavailable)?;
        if !designation_caps.iter().any(|item| item == "organization.designation.delegate") {
            return Err(OrganizationAuthorityError::CapabilityDenied);
        }
        if stored_delegate != delegate.subject() || stored_tenant != tenant.tenant_id() || stored_org != organization_id {
            return Err(OrganizationAuthorityError::TenantMismatch);
        }
        Ok(DelegationContext {
            delegation_id: delegation_id.to_owned(), delegator, delegate: delegate.subject().to_owned(),
            tenant_id: tenant.tenant_id().to_owned(), organization_id: organization_id.to_owned(),
            version, capability: capability.to_owned(), resolved_at: now,
        })
    }

    pub fn resolve(
        &self,
        principal: &VerifiedPrincipal,
        tenant: &TenantContext,
        organization_id: &str,
        capability: &str,
        now: u64,
        max_age_secs: u64,
    ) -> Result<OrganizationContext, OrganizationAuthorityError> {
        if principal.subject().trim().is_empty()
            || tenant.subject() != principal.subject()
            || organization_id.trim().is_empty()
            || capability.trim().is_empty()
            || max_age_secs == 0
            || max_age_secs > MAX_AUTHORITY_AGE_SECS
        {
            return Err(OrganizationAuthorityError::Malformed);
        }
        if tenant.resolved_at() > now || now.saturating_sub(tenant.resolved_at()) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let current_membership = self
            .store
            .tenant_membership(principal.subject(), tenant.tenant_id())?
            .ok_or(OrganizationAuthorityError::TenantMismatch)?;
        if !current_membership.0 || current_membership.1 != tenant.membership_version() {
            return Err(OrganizationAuthorityError::TenantMismatch);
        }
        if current_membership.2 > now || now.saturating_sub(current_membership.2) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }

        let (bound_tenant, org_active, _org_version, org_updated) = self
            .store
            .organization_state(organization_id)?
            .ok_or(OrganizationAuthorityError::OrganizationMissing)?;
        if !org_active {
            return Err(OrganizationAuthorityError::OrganizationInactive);
        }
        if bound_tenant != tenant.tenant_id() {
            return Err(OrganizationAuthorityError::TenantMismatch);
        }
        if org_updated > now || now.saturating_sub(org_updated) > max_age_secs {
            return Err(OrganizationAuthorityError::Stale);
        }
        let (designation_id, active, capabilities_json, version, updated) = self
            .store
            .organization_designation(organization_id, principal.subject())?
            .ok_or(OrganizationAuthorityError::DesignationMissing)?;
        if !active {
            return Err(OrganizationAuthorityError::DesignationInactive);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OwnerApprovalVerifier, OwnerSecurityAction, OwnerSecurityCommandPayload,
        SignedOwnerSecurityCommand, TrustedOwnerKey,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (
        SigningKey,
        OwnerApprovalVerifier,
        Arc<SqliteSecurityStore>,
        VerifiedPrincipal,
    ) {
        let signer = SigningKey::from_bytes(&[81u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let owner = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:test".into(),
                key_id: "owner-key".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5000,
            }],
            store.clone(),
        )
        .unwrap();
        let principal = VerifiedPrincipal::from_verified_credential(
            "principal:alice".into(),
            "issuer:test".into(),
            "credential:1".into(),
        );
        (signer, owner, store, principal)
    }

    fn signed_org(
        signer: &SigningKey,
        command_id: &str,
        action: OrganizationAuthorityAction,
        principal: Option<&str>,
        designation_id: Option<&str>,
        capabilities: Vec<&str>,
        version: u64,
    ) -> SignedOrganizationAuthorityCommand {
        let payload = OrganizationAuthorityPayload {
            command_id: command_id.into(),
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            issued_at: 1100,
            expires_at: 1400,
            organization_id: "org:alpha".into(),
            tenant_id: "tenant:alpha".into(),
            principal: principal.map(str::to_owned),
            designation_id: designation_id.map(str::to_owned),
            delegate: None,
            delegation_expires_at: None,
            action,
            version,
            capabilities: capabilities.into_iter().map(str::to_owned).collect(),
            reason: "Owner-authorized test command".into(),
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedOrganizationAuthorityCommand::from_signature(payload, signature)
    }

    fn tenant_context(
        signer: &SigningKey,
        owner: &OwnerApprovalVerifier,
        principal: &VerifiedPrincipal,
        store: Arc<SqliteSecurityStore>,
    ) -> TenantContext {
        let payload = OwnerSecurityCommandPayload {
            command_id: format!("membership:{}", principal.subject()),
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            issued_at: 1100,
            expires_at: 1400,
            action: OwnerSecurityAction::SetTenantMembership {
                subject: principal.subject().into(),
                tenant_id: "tenant:alpha".into(),
                active: true,
                version: 1,
                reason: "fixture".into(),
            },
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        owner
            .apply_security_command(
                &SignedOwnerSecurityCommand::from_signature(payload, signature),
                1200,
            )
            .unwrap();
        crate::TenantMembershipResolver::new(store)
            .resolve(principal, "tenant:alpha", 1200, 600)
            .unwrap()
    }

    #[test]
    fn g02_domain_is_distinct_and_capability_order_is_canonical() {
        let (signer, _, _, _) = fixture();
        let command = signed_org(
            &signer,
            "org:create",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        let bytes = command.payload.signing_bytes().unwrap();
        assert!(bytes.starts_with(b"IROKA:G02:ORGANIZATION_AUTHORITY:V1\0"));
        let mut malformed = command.payload.clone();
        malformed.capabilities = vec!["z".into(), "a".into()];
        assert_eq!(
            malformed.validate(),
            Err(OrganizationAuthorityError::Malformed)
        );
    }

    #[test]
    fn owner_command_creates_org_and_scoped_designation_resolves_exact_capability() {
        let (signer, owner, store, principal) = fixture();
        let tenant = tenant_context(&signer, &owner, &principal, store.clone());
        let create = signed_org(
            &signer,
            "org:create",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        owner.apply_organization_command(&create, 1200).unwrap();
        let designate = signed_org(
            &signer,
            "org:designate",
            OrganizationAuthorityAction::SetDesignation,
            Some(principal.subject()),
            Some("designation:alice"),
            vec!["records.read", "workspace.read"],
            1,
        );
        owner.apply_organization_command(&designate, 1200).unwrap();

        let resolver = OrganizationAuthorityResolver::new(store);
        let context = resolver
            .resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600)
            .unwrap();
        assert_eq!(context.subject(), "principal:alice");
        assert_eq!(context.tenant_id(), "tenant:alpha");
        assert_eq!(context.designation_id(), "designation:alice");
        assert_eq!(context.capability(), "records.read");
        assert_eq!(
            resolver.resolve(
                &principal,
                &tenant,
                "org:alpha",
                "records.delete",
                1200,
                600
            ),
            Err(OrganizationAuthorityError::CapabilityDenied)
        );
    }

    #[test]
    fn tenant_binding_is_immutable_and_designation_revocation_takes_effect() {
        let (signer, owner, store, principal) = fixture();
        let tenant = tenant_context(&signer, &owner, &principal, store.clone());
        owner
            .apply_organization_command(
                &signed_org(
                    &signer,
                    "org:create",
                    OrganizationAuthorityAction::CreateOrganization,
                    None,
                    None,
                    vec![],
                    1,
                ),
                1200,
            )
            .unwrap();
        owner
            .apply_organization_command(
                &signed_org(
                    &signer,
                    "org:designate",
                    OrganizationAuthorityAction::SetDesignation,
                    Some(principal.subject()),
                    Some("designation:alice"),
                    vec!["records.read"],
                    1,
                ),
                1200,
            )
            .unwrap();

        let wrong_tenant = OrganizationAuthorityPayload {
            command_id: "org:wrong-tenant".into(),
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            issued_at: 1100,
            expires_at: 1400,
            organization_id: "org:alpha".into(),
            tenant_id: "tenant:other".into(),
            principal: None,
            designation_id: None,
            delegate: None,
            delegation_expires_at: None,
            action: OrganizationAuthorityAction::SetOrganizationActive { active: true },
            version: 2,
            capabilities: vec![],
            reason: "attempted tenant rebind".into(),
        };
        let sig = signer
            .sign(&wrong_tenant.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            owner.apply_organization_command(
                &SignedOrganizationAuthorityCommand::from_signature(wrong_tenant, sig),
                1200
            ),
            Err(crate::OwnerApprovalError::Malformed)
        );

        let resolver = OrganizationAuthorityResolver::new(store.clone());
        assert!(resolver
            .resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600)
            .is_ok());
        let revoke = signed_org(
            &signer,
            "org:revoke",
            OrganizationAuthorityAction::RevokeDesignation,
            Some(principal.subject()),
            Some("designation:alice"),
            vec![],
            2,
        );
        owner.apply_organization_command(&revoke, 1200).unwrap();
        assert_eq!(
            resolver.resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600),
            Err(OrganizationAuthorityError::DesignationInactive)
        );
    }

    #[test]
    fn forged_signature_and_replay_are_rejected() {
        let (signer, owner, _, _) = fixture();
        let mut command = signed_org(
            &signer,
            "org:create",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        command.signature[0] ^= 0x80;
        assert_eq!(
            owner.apply_organization_command(&command, 1200),
            Err(crate::OwnerApprovalError::InvalidSignature)
        );
        let valid = signed_org(
            &signer,
            "org:create-valid",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        owner.apply_organization_command(&valid, 1200).unwrap();
        assert_eq!(
            owner.apply_organization_command(&valid, 1200),
            Err(crate::OwnerApprovalError::Replay)
        );
    }

    #[test]
    fn organization_suspension_and_reactivation_are_versioned_and_enforced() {
        let (signer, owner, store, principal) = fixture();
        let tenant = tenant_context(&signer, &owner, &principal, store.clone());
        owner
            .apply_organization_command(
                &signed_org(
                    &signer,
                    "org:create",
                    OrganizationAuthorityAction::CreateOrganization,
                    None,
                    None,
                    vec![],
                    1,
                ),
                1200,
            )
            .unwrap();
        owner
            .apply_organization_command(
                &signed_org(
                    &signer,
                    "org:designate",
                    OrganizationAuthorityAction::SetDesignation,
                    Some(principal.subject()),
                    Some("designation:alice"),
                    vec!["records.read"],
                    1,
                ),
                1200,
            )
            .unwrap();
        let resolver = OrganizationAuthorityResolver::new(store);
        assert!(resolver
            .resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600)
            .is_ok());

        let suspend = signed_org(
            &signer,
            "org:suspend",
            OrganizationAuthorityAction::SetOrganizationActive { active: false },
            None,
            None,
            vec![],
            2,
        );
        owner.apply_organization_command(&suspend, 1200).unwrap();
        assert_eq!(
            resolver.resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600),
            Err(OrganizationAuthorityError::OrganizationInactive)
        );

        let reactivate = signed_org(
            &signer,
            "org:reactivate",
            OrganizationAuthorityAction::SetOrganizationActive { active: true },
            None,
            None,
            vec![],
            3,
        );
        owner.apply_organization_command(&reactivate, 1200).unwrap();
        assert!(resolver
            .resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600)
            .is_ok());
    }

    #[test]
    fn designation_revocation_requires_exact_designation_id() {
        let (signer, owner, store, principal) = fixture();
        let tenant = tenant_context(&signer, &owner, &principal, store.clone());
        owner
            .apply_organization_command(
                &signed_org(
                    &signer,
                    "org:create",
                    OrganizationAuthorityAction::CreateOrganization,
                    None,
                    None,
                    vec![],
                    1,
                ),
                1200,
            )
            .unwrap();
        owner
            .apply_organization_command(
                &signed_org(
                    &signer,
                    "org:designate",
                    OrganizationAuthorityAction::SetDesignation,
                    Some(principal.subject()),
                    Some("designation:alice"),
                    vec!["records.read"],
                    1,
                ),
                1200,
            )
            .unwrap();
        let forged_target = signed_org(
            &signer,
            "org:revoke-wrong-id",
            OrganizationAuthorityAction::RevokeDesignation,
            Some(principal.subject()),
            Some("designation:other"),
            vec![],
            2,
        );
        assert_eq!(
            owner.apply_organization_command(&forged_target, 1200),
            Err(crate::OwnerApprovalError::Malformed)
        );
        let resolver = OrganizationAuthorityResolver::new(store);
        assert!(resolver
            .resolve(&principal, &tenant, "org:alpha", "records.read", 1200, 600)
            .is_ok());
    }

    #[test]
    fn owner_command_rejects_expired_future_and_revoked_signer() {
        let (signer, owner, store, _) = fixture();

        let mut expired = signed_org(
            &signer,
            "org:expired",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        expired.payload.expires_at = 1_199;
        expired.signature = signer
            .sign(&expired.payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            owner.apply_organization_command(&expired, 1_200),
            Err(crate::OwnerApprovalError::Expired)
        );

        let mut future = signed_org(
            &signer,
            "org:future",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        future.payload.issued_at = 1_231;
        future.signature = signer
            .sign(&future.payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            owner.apply_organization_command(&future, 1_200),
            Err(crate::OwnerApprovalError::NotYetValid)
        );

        store
            .revoke_key(
                "iroka:owner-authority",
                "owner-key",
                1_150,
                "test key compromise",
            )
            .unwrap();
        let revoked = signed_org(
            &signer,
            "org:revoked-key",
            OrganizationAuthorityAction::CreateOrganization,
            None,
            None,
            vec![],
            1,
        );
        assert_eq!(
            owner.apply_organization_command(&revoked, 1_200),
            Err(crate::OwnerApprovalError::Revoked)
        );
    }
    fn signed_delegation(
        signer: &SigningKey,
        command_id: &str,
        action: OrganizationAuthorityAction,
        delegation_id: &str,
        delegator: &str,
        delegate: &str,
        capabilities: Vec<&str>,
        version: u64,
        valid_until: Option<u64>,
    ) -> SignedOrganizationAuthorityCommand {
        let payload = OrganizationAuthorityPayload {
            command_id: command_id.into(), owner_subject: "owner:test".into(), key_id: "owner-key".into(),
            issued_at: 1100, expires_at: 1400, organization_id: "org:alpha".into(), tenant_id: "tenant:alpha".into(),
            principal: Some(delegator.into()), designation_id: Some(delegation_id.into()),
            delegate: Some(delegate.into()), delegation_expires_at: valid_until, action, version,
            capabilities: capabilities.into_iter().map(str::to_owned).collect(),
            reason: "Owner-authorized exact-scope delegation".into(),
        };
        let signature = signer.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
        SignedOrganizationAuthorityCommand::from_signature(payload, signature)
    }

    #[test]
    fn owner_delegation_is_exact_scope_versioned_and_revocable() {
        let (signer, owner, store, alice) = fixture();
        let alice_tenant = tenant_context(&signer, &owner, &alice, store.clone());
        let bob = VerifiedPrincipal::from_verified_credential(
            "principal:bob".into(), "issuer:test".into(), "credential:bob".into(),
        );
        let bob_tenant = tenant_context(&signer, &owner, &bob, store.clone());
        owner.apply_organization_command(
            &signed_org(&signer,"org:create",OrganizationAuthorityAction::CreateOrganization,None,None,vec![],1), 1200,
        ).unwrap();
        owner.apply_organization_command(
            &signed_org(&signer,"org:designate-alice",OrganizationAuthorityAction::SetDesignation,
                Some(alice.subject()),Some("designation:alice"),vec!["organization.designation.delegate"],1),1200,
        ).unwrap();
        let grant = signed_delegation(&signer,"delegation:grant",OrganizationAuthorityAction::SetDelegation,
            "delegation:alice-bob",alice.subject(),bob.subject(),vec!["records.review"],1,Some(1300));
        owner.apply_organization_command(&grant,1200).unwrap();
        let resolver = OrganizationAuthorityResolver::new(store);
        let context = resolver.resolve_delegation(&bob,&bob_tenant,"org:alpha","delegation:alice-bob","records.review",1200,600).unwrap();
        assert_eq!(context.delegator(),alice.subject());
        assert_eq!(context.delegate(),bob.subject());
        assert_eq!(context.capability(),"records.review");
        assert_eq!(resolver.resolve_delegation(&bob,&bob_tenant,"org:alpha","delegation:alice-bob","records.delete",1200,600),Err(OrganizationAuthorityError::CapabilityDenied));
        let revoke = signed_delegation(&signer,"delegation:revoke",OrganizationAuthorityAction::RevokeDelegation,
            "delegation:alice-bob",alice.subject(),bob.subject(),vec![],2,None);
        owner.apply_organization_command(&revoke,1200).unwrap();
        assert_eq!(resolver.resolve_delegation(&bob,&bob_tenant,"org:alpha","delegation:alice-bob","records.review",1200,600),Err(OrganizationAuthorityError::DelegationInactive));
        assert_eq!(alice_tenant.tenant_id(),"tenant:alpha");
    }

}
