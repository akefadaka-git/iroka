//! G01 server-side tenant membership resolution.
//!
//! Tenant IDs supplied by a request are selectors only. Authority comes from
//! the Owner-signed membership ledger in the Kernel security store.

use std::sync::Arc;

use crate::{SecurityStoreError, SqliteSecurityStore, VerifiedPrincipal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantResolutionError {
    Malformed,
    MembershipMissing,
    MembershipInactive,
    MembershipStale,
    StoreUnavailable,
}

impl From<SecurityStoreError> for TenantResolutionError {
    fn from(_: SecurityStoreError) -> Self {
        Self::StoreUnavailable
    }
}

/// Immutable tenant binding derived from a verified principal and an active,
/// fresh server-side membership record. Callers cannot construct this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    subject: String,
    tenant_id: String,
    membership_version: u64,
    resolved_at: u64,
}

impl TenantContext {
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn membership_version(&self) -> u64 {
        self.membership_version
    }

    pub fn resolved_at(&self) -> u64 {
        self.resolved_at
    }
}

/// Resolves a tenant selector against the Kernel-owned membership authority.
/// This SQLite adapter is single-node only; a multi-node deployment requires
/// a shared transactional adapter with equivalent consistency guarantees.
pub struct TenantMembershipResolver {
    store: Arc<SqliteSecurityStore>,
}

impl TenantMembershipResolver {
    pub fn new(store: Arc<SqliteSecurityStore>) -> Self {
        Self { store }
    }

    /// Resolve the requested tenant for an already verified principal.
    ///
    /// `max_age_secs` is an explicit freshness bound selected by the trusted
    /// server integration, never by a request parameter. A zero bound fails closed.
    pub fn resolve(
        &self,
        principal: &VerifiedPrincipal,
        requested_tenant_id: &str,
        now: u64,
        max_age_secs: u64,
    ) -> Result<TenantContext, TenantResolutionError> {
        let subject = principal.subject();
        if subject.trim().is_empty()
            || subject.len() > 256
            || requested_tenant_id.trim().is_empty()
            || requested_tenant_id.len() > 256
            || max_age_secs == 0
        {
            return Err(TenantResolutionError::Malformed);
        }

        let (active, version, updated_at) = self
            .store
            .tenant_membership(subject, requested_tenant_id)?
            .ok_or(TenantResolutionError::MembershipMissing)?;

        if !active {
            return Err(TenantResolutionError::MembershipInactive);
        }
        if updated_at > now || now.saturating_sub(updated_at) > max_age_secs {
            return Err(TenantResolutionError::MembershipStale);
        }

        Ok(TenantContext {
            subject: subject.to_owned(),
            tenant_id: requested_tenant_id.to_owned(),
            membership_version: version,
            resolved_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OwnerApprovalVerifier, OwnerSecurityAction, OwnerSecurityCommandPayload,
        SignedOwnerSecurityCommand, SqliteSecurityStore, TrustedOwnerKey,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (
        SigningKey,
        OwnerApprovalVerifier,
        TenantMembershipResolver,
        VerifiedPrincipal,
    ) {
        let signer = SigningKey::from_bytes(&[73u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:test".into(),
                key_id: "owner-key".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 10_000,
            }],
            store.clone(),
        )
        .unwrap();
        let resolver = TenantMembershipResolver::new(store);
        let principal = VerifiedPrincipal::from_verified_credential(
            "principal:alice".into(),
            "issuer:test".into(),
            "credential:1".into(),
        );
        (signer, verifier, resolver, principal)
    }

    fn command_for(
        signer: &SigningKey,
        command_id: &str,
        subject: &str,
        tenant_id: &str,
        active: bool,
        version: u64,
        issued_at: u64,
    ) -> SignedOwnerSecurityCommand {
        let payload = OwnerSecurityCommandPayload {
            command_id: command_id.into(),
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            issued_at,
            expires_at: issued_at + 300,
            action: OwnerSecurityAction::SetTenantMembership {
                subject: subject.into(),
                tenant_id: tenant_id.into(),
                active,
                version,
                reason: "owner-authorized test fixture".into(),
            },
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedOwnerSecurityCommand::from_signature(payload, signature)
    }

    fn command(
        signer: &SigningKey,
        command_id: &str,
        active: bool,
        version: u64,
        issued_at: u64,
    ) -> SignedOwnerSecurityCommand {
        command_for(
            signer,
            command_id,
            "principal:alice",
            "tenant:alpha",
            active,
            version,
            issued_at,
        )
    }

    #[test]
    fn resolves_only_owner_provisioned_active_membership() {
        let (signer, owner, resolver, principal) = fixture();
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_200, 600),
            Err(TenantResolutionError::MembershipMissing)
        );
        owner
            .apply_security_command(&command(&signer, "membership-1", true, 1, 1_100), 1_200)
            .unwrap();
        let context = resolver
            .resolve(&principal, "tenant:alpha", 1_200, 600)
            .unwrap();
        assert_eq!(context.subject(), "principal:alice");
        assert_eq!(context.tenant_id(), "tenant:alpha");
        assert_eq!(context.membership_version(), 1);
    }

    #[test]
    fn client_tenant_selector_cannot_grant_membership() {
        let (_signer, _owner, resolver, principal) = fixture();
        assert_eq!(
            resolver.resolve(&principal, "tenant:forged", 1_200, 600),
            Err(TenantResolutionError::MembershipMissing)
        );
    }

    #[test]
    fn inactive_membership_is_denied() {
        let (signer, owner, resolver, principal) = fixture();
        owner
            .apply_security_command(&command(&signer, "membership-1", false, 1, 1_100), 1_200)
            .unwrap();
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_200, 600),
            Err(TenantResolutionError::MembershipInactive)
        );
    }

    #[test]
    fn stale_or_future_membership_is_denied() {
        let (signer, owner, resolver, principal) = fixture();
        owner
            .apply_security_command(&command(&signer, "membership-1", true, 1, 1_100), 1_200)
            .unwrap();
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_801, 600),
            Err(TenantResolutionError::MembershipStale)
        );
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_000, 600),
            Err(TenantResolutionError::MembershipStale)
        );
    }

    #[test]
    fn owner_membership_versions_cannot_roll_back() {
        let (signer, owner, resolver, principal) = fixture();
        owner
            .apply_security_command(&command(&signer, "membership-2", true, 2, 1_100), 1_200)
            .unwrap();
        assert!(owner
            .apply_security_command(&command(&signer, "membership-1", false, 1, 1_100), 1_200)
            .is_err());
        let context = resolver
            .resolve(&principal, "tenant:alpha", 1_200, 600)
            .unwrap();
        assert_eq!(context.membership_version(), 2);
    }

    #[test]
    fn revoked_owner_key_cannot_change_tenant_membership() {
        let (signer, owner, resolver, principal) = fixture();
        let payload = OwnerSecurityCommandPayload {
            command_id: "revoke-owner-key".into(),
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            issued_at: 1_100,
            expires_at: 1_400,
            action: OwnerSecurityAction::RevokeSigningKey {
                issuer: "iroka:owner-authority".into(),
                key_id: "owner-key".into(),
                reason: "test revocation".into(),
            },
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let revocation = SignedOwnerSecurityCommand::from_signature(payload, signature);
        owner.apply_security_command(&revocation, 1_200).unwrap();

        assert_eq!(
            owner.apply_security_command(
                &command(&signer, "membership-after-revocation", true, 1, 1_100),
                1_200,
            ),
            Err(crate::OwnerApprovalError::Revoked)
        );
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_200, 600),
            Err(TenantResolutionError::MembershipMissing)
        );
    }

    #[test]
    fn membership_commands_are_replay_protected() {
        let (signer, owner, _resolver, _principal) = fixture();
        let signed = command(&signer, "membership-1", true, 1, 1_100);
        owner.apply_security_command(&signed, 1_200).unwrap();
        assert!(owner.apply_security_command(&signed, 1_200).is_err());
    }

    #[test]
    fn membership_isolation_prevents_cross_tenant_and_cross_principal_resolution() {
        let (signer, owner, resolver, alice) = fixture();
        let bob = VerifiedPrincipal::from_verified_credential(
            "principal:bob".into(),
            "issuer:test".into(),
            "credential:2".into(),
        );
        owner
            .apply_security_command(
                &command_for(
                    &signer,
                    "alice-alpha",
                    "principal:alice",
                    "tenant:alpha",
                    true,
                    1,
                    1_100,
                ),
                1_200,
            )
            .unwrap();
        owner
            .apply_security_command(
                &command_for(
                    &signer,
                    "bob-beta",
                    "principal:bob",
                    "tenant:beta",
                    true,
                    1,
                    1_100,
                ),
                1_200,
            )
            .unwrap();

        let alice_context = resolver
            .resolve(&alice, "tenant:alpha", 1_200, 600)
            .unwrap();
        let bob_context = resolver.resolve(&bob, "tenant:beta", 1_200, 600).unwrap();
        assert_eq!(alice_context.subject(), "principal:alice");
        assert_eq!(alice_context.tenant_id(), "tenant:alpha");
        assert_eq!(bob_context.subject(), "principal:bob");
        assert_eq!(bob_context.tenant_id(), "tenant:beta");
        assert_eq!(
            resolver.resolve(&alice, "tenant:beta", 1_200, 600),
            Err(TenantResolutionError::MembershipMissing)
        );
        assert_eq!(
            resolver.resolve(&bob, "tenant:alpha", 1_200, 600),
            Err(TenantResolutionError::MembershipMissing)
        );
    }

    #[test]
    fn membership_freshness_accepts_exact_age_boundary_and_rejects_older_or_future_records() {
        let (signer, owner, resolver, principal) = fixture();
        owner
            .apply_security_command(&command(&signer, "fresh-boundary", true, 1, 1_100), 1_200)
            .unwrap();

        assert!(resolver
            .resolve(&principal, "tenant:alpha", 1_800, 600)
            .is_ok());
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_801, 600),
            Err(TenantResolutionError::MembershipStale)
        );
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_199, 600),
            Err(TenantResolutionError::MembershipStale)
        );
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_200, 0),
            Err(TenantResolutionError::Malformed)
        );
    }

    #[test]
    fn newer_owner_revocation_immediately_invalidates_previous_active_membership() {
        let (signer, owner, resolver, principal) = fixture();
        owner
            .apply_security_command(
                &command(&signer, "membership-active", true, 1, 1_100),
                1_200,
            )
            .unwrap();
        assert!(resolver
            .resolve(&principal, "tenant:alpha", 1_200, 600)
            .is_ok());

        owner
            .apply_security_command(
                &command(&signer, "membership-revoked", false, 2, 1_201),
                1_201,
            )
            .unwrap();
        assert_eq!(
            resolver.resolve(&principal, "tenant:alpha", 1_201, 600),
            Err(TenantResolutionError::MembershipInactive)
        );
    }
}
