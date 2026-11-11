//! G02 concrete Owner authority and one-time signed approvals.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::organization_authority::{
    OrganizationAuthorityAction, SignedOrganizationAuthorityCommand,
};
use crate::security_store::{
    ApprovalConsumptionError, ApprovalReceipt, OrganizationMutation, RevocationTarget,
    SecurityCommandReceipt,
};
use crate::RevocationChecker;
use crate::{AuthorizationRequest, SecurityStoreError, SqliteSecurityStore};

const MAX_APPROVAL_TTL_SECS: u64 = 900;
const CLOCK_SKEW_SECS: u64 = 30;
const OWNER_ISSUER: &str = "iroka:owner-authority";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerApprovalPayload {
    pub approval_id: String,
    pub owner_subject: String,
    pub key_id: String,
    pub request_subject: String,
    pub capability: String,
    pub resource: String,
    pub policy_version: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl OwnerApprovalPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval_id: impl Into<String>,
        owner_subject: impl Into<String>,
        key_id: impl Into<String>,
        request_subject: impl Into<String>,
        capability: impl Into<String>,
        resource: impl Into<String>,
        policy_version: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            approval_id: approval_id.into(),
            owner_subject: owner_subject.into(),
            key_id: key_id.into(),
            request_subject: request_subject.into(),
            capability: capability.into(),
            resource: resource.into(),
            policy_version: policy_version.into(),
            issued_at,
            expires_at,
        }
    }

    /// Deterministic struct-field-order JSON used as the Ed25519 signing input.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, OwnerApprovalError> {
        serde_json::to_vec(self).map_err(|_| OwnerApprovalError::Malformed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerApproval {
    pub payload: OwnerApprovalPayload,
    pub signature: Vec<u8>,
}

impl SignedOwnerApproval {
    /// Construct an approval from a signature produced by an offline signer or KMS.
    /// The kernel never receives or stores the Owner private key.
    pub fn from_signature(payload: OwnerApprovalPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

#[derive(Debug, Clone)]
pub struct TrustedOwnerKey {
    pub owner_subject: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerApprovalError {
    Malformed,
    UnknownOwnerKey,
    OwnerKeyOutsideValidity,
    InvalidSignature,
    Expired,
    NotYetValid,
    ScopeMismatch,
    Revoked,
    Replay,
    StoreUnavailable,
}

impl From<SecurityStoreError> for OwnerApprovalError {
    fn from(error: SecurityStoreError) -> Self {
        match error {
            SecurityStoreError::InvalidVersion => Self::Malformed,
            SecurityStoreError::Revoked => Self::Revoked,
            _ => Self::StoreUnavailable,
        }
    }
}

#[derive(Debug, Clone)]
struct OwnerKeyRecord {
    owner_subject: String,
    verifying_key: VerifyingKey,
    not_before: u64,
    not_after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerSecurityAction {
    RevokeCredential {
        issuer: String,
        credential_id: String,
        reason: String,
    },
    RevokeSigningKey {
        issuer: String,
        key_id: String,
        reason: String,
    },
    RevokeApproval {
        approval_id: String,
        reason: String,
    },
    SetTenantMembership {
        subject: String,
        tenant_id: String,
        active: bool,
        version: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerSecurityCommandPayload {
    pub command_id: String,
    pub owner_subject: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub action: OwnerSecurityAction,
}

impl OwnerSecurityCommandPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, OwnerApprovalError> {
        serde_json::to_vec(self).map_err(|_| OwnerApprovalError::Malformed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerSecurityCommand {
    pub payload: OwnerSecurityCommandPayload,
    pub signature: Vec<u8>,
}

impl SignedOwnerSecurityCommand {
    pub fn from_signature(payload: OwnerSecurityCommandPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

/// Owner authority is established only by explicitly provisioned public keys.
/// There is no default Owner, self-registration, model-issued authority or
/// automatic privilege inheritance. Private keys remain in an offline signer/HSM.
pub struct OwnerApprovalVerifier {
    keys: HashMap<String, OwnerKeyRecord>,
    store: Arc<SqliteSecurityStore>,
}

impl OwnerApprovalVerifier {
    pub fn new(
        keys: Vec<TrustedOwnerKey>,
        store: Arc<SqliteSecurityStore>,
    ) -> Result<Self, OwnerApprovalError> {
        if keys.is_empty() {
            return Err(OwnerApprovalError::UnknownOwnerKey);
        }
        let mut records = HashMap::new();
        for key in keys {
            if key.owner_subject.trim().is_empty()
                || key.key_id.trim().is_empty()
                || key.not_before >= key.not_after
            {
                return Err(OwnerApprovalError::Malformed);
            }
            let verifying_key = VerifyingKey::from_bytes(&key.public_key)
                .map_err(|_| OwnerApprovalError::Malformed)?;
            let id = key.key_id.clone();
            if records
                .insert(
                    id,
                    OwnerKeyRecord {
                        owner_subject: key.owner_subject,
                        verifying_key,
                        not_before: key.not_before,
                        not_after: key.not_after,
                    },
                )
                .is_some()
            {
                return Err(OwnerApprovalError::Malformed);
            }
        }
        Ok(Self {
            keys: records,
            store,
        })
    }

    pub fn verify_and_consume(
        &self,
        approval: &SignedOwnerApproval,
        request: &AuthorizationRequest,
        policy_version: &str,
        now: u64,
    ) -> Result<(), OwnerApprovalError> {
        let p = &approval.payload;
        if p.approval_id.trim().is_empty()
            || p.owner_subject.trim().is_empty()
            || p.key_id.trim().is_empty()
            || p.request_subject.trim().is_empty()
            || p.capability.trim().is_empty()
            || p.resource.trim().is_empty()
            || p.policy_version.trim().is_empty()
            || p.issued_at >= p.expires_at
        {
            return Err(OwnerApprovalError::Malformed);
        }
        if p.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(OwnerApprovalError::NotYetValid);
        }
        if p.expires_at <= now {
            return Err(OwnerApprovalError::Expired);
        }
        if p.expires_at - p.issued_at > MAX_APPROVAL_TTL_SECS {
            return Err(OwnerApprovalError::Malformed);
        }
        if p.request_subject != request.subject()
            || p.capability != request.capability()
            || p.resource != request.resource()
            || p.policy_version != policy_version
        {
            return Err(OwnerApprovalError::ScopeMismatch);
        }
        let owner_key = self
            .keys
            .get(&p.key_id)
            .ok_or(OwnerApprovalError::UnknownOwnerKey)?;
        if p.owner_subject != owner_key.owner_subject {
            return Err(OwnerApprovalError::ScopeMismatch);
        }
        if now < owner_key.not_before
            || now >= owner_key.not_after
            || p.issued_at < owner_key.not_before
            || p.issued_at >= owner_key.not_after
        {
            return Err(OwnerApprovalError::OwnerKeyOutsideValidity);
        }
        if self
            .store
            .key_revoked(OWNER_ISSUER, &p.key_id)
            .map_err(|_| OwnerApprovalError::StoreUnavailable)?
        {
            return Err(OwnerApprovalError::Revoked);
        }
        if self.store.approval_is_revoked(&p.approval_id)? {
            return Err(OwnerApprovalError::Revoked);
        }
        let signing_bytes = p.signing_bytes()?;
        let signature = Signature::from_slice(&approval.signature)
            .map_err(|_| OwnerApprovalError::Malformed)?;
        owner_key
            .verifying_key
            .verify(&signing_bytes, &signature)
            .map_err(|_| OwnerApprovalError::InvalidSignature)?;

        let digest = Sha256::digest(&signing_bytes);
        let consumed = self
            .store
            .consume_approval(ApprovalReceipt {
                approval_id: &p.approval_id,
                payload_digest: digest.as_slice(),
                owner_subject: &p.owner_subject,
                signer_issuer: OWNER_ISSUER,
                signer_key_id: &p.key_id,
                request_subject: &p.request_subject,
                capability: &p.capability,
                resource: &p.resource,
                policy_version: &p.policy_version,
                issued_at: p.issued_at,
                expires_at: p.expires_at,
                consumed_at: now,
            })
            .map_err(|error| match error {
                ApprovalConsumptionError::SigningKeyRevoked
                | ApprovalConsumptionError::ApprovalRevoked => OwnerApprovalError::Revoked,
                ApprovalConsumptionError::Store(store_error) => store_error.into(),
            })?;
        if !consumed {
            return Err(OwnerApprovalError::Replay);
        }
        Ok(())
    }

    /// Apply an Owner-signed, replay-protected revocation command. The command
    /// record and revocation effect commit in one SQLite transaction.
    pub fn apply_security_command(
        &self,
        command: &SignedOwnerSecurityCommand,
        now: u64,
    ) -> Result<(), OwnerApprovalError> {
        let p = &command.payload;
        if p.command_id.trim().is_empty()
            || p.owner_subject.trim().is_empty()
            || p.key_id.trim().is_empty()
            || p.issued_at >= p.expires_at
        {
            return Err(OwnerApprovalError::Malformed);
        }
        if p.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(OwnerApprovalError::NotYetValid);
        }
        if p.expires_at <= now {
            return Err(OwnerApprovalError::Expired);
        }
        if p.expires_at - p.issued_at > MAX_APPROVAL_TTL_SECS {
            return Err(OwnerApprovalError::Malformed);
        }
        let owner_key = self
            .keys
            .get(&p.key_id)
            .ok_or(OwnerApprovalError::UnknownOwnerKey)?;
        if p.owner_subject != owner_key.owner_subject {
            return Err(OwnerApprovalError::ScopeMismatch);
        }
        if now < owner_key.not_before
            || now >= owner_key.not_after
            || p.issued_at < owner_key.not_before
            || p.issued_at >= owner_key.not_after
        {
            return Err(OwnerApprovalError::OwnerKeyOutsideValidity);
        }
        if self
            .store
            .key_revoked(OWNER_ISSUER, &p.key_id)
            .map_err(|_| OwnerApprovalError::StoreUnavailable)?
        {
            return Err(OwnerApprovalError::Revoked);
        }
        let signing_bytes = p.signing_bytes()?;
        let signature =
            Signature::from_slice(&command.signature).map_err(|_| OwnerApprovalError::Malformed)?;
        owner_key
            .verifying_key
            .verify(&signing_bytes, &signature)
            .map_err(|_| OwnerApprovalError::InvalidSignature)?;
        let digest = Sha256::digest(&signing_bytes);
        let target = match &p.action {
            OwnerSecurityAction::RevokeCredential {
                issuer,
                credential_id,
                reason,
            } => {
                if issuer.trim().is_empty()
                    || credential_id.trim().is_empty()
                    || reason.trim().is_empty()
                {
                    return Err(OwnerApprovalError::Malformed);
                }
                RevocationTarget::Credential {
                    issuer: issuer.clone(),
                    credential_id: credential_id.clone(),
                    reason: reason.clone(),
                }
            }
            OwnerSecurityAction::RevokeSigningKey {
                issuer,
                key_id,
                reason,
            } => {
                if issuer.trim().is_empty() || key_id.trim().is_empty() || reason.trim().is_empty()
                {
                    return Err(OwnerApprovalError::Malformed);
                }
                RevocationTarget::Key {
                    issuer: issuer.clone(),
                    key_id: key_id.clone(),
                    reason: reason.clone(),
                }
            }
            OwnerSecurityAction::RevokeApproval {
                approval_id,
                reason,
            } => {
                if approval_id.trim().is_empty() || reason.trim().is_empty() {
                    return Err(OwnerApprovalError::Malformed);
                }
                RevocationTarget::Approval {
                    approval_id: approval_id.clone(),
                    reason: reason.clone(),
                }
            }
            OwnerSecurityAction::SetTenantMembership {
                subject,
                tenant_id,
                active,
                version,
                reason,
            } => {
                if subject.trim().is_empty()
                    || tenant_id.trim().is_empty()
                    || reason.trim().is_empty()
                    || *version == 0
                    || subject.len() > 256
                    || tenant_id.len() > 256
                    || reason.len() > 1024
                {
                    return Err(OwnerApprovalError::Malformed);
                }
                RevocationTarget::TenantMembership {
                    subject: subject.clone(),
                    tenant_id: tenant_id.clone(),
                    active: *active,
                    version: *version,
                    reason: reason.clone(),
                }
            }
        };
        let applied = self.store.apply_signed_revocation(
            SecurityCommandReceipt {
                command_id: &p.command_id,
                owner_subject: &p.owner_subject,
                signer_issuer: OWNER_ISSUER,
                signer_key_id: &p.key_id,
                digest: digest.as_slice(),
                at: now,
            },
            target,
        )?;
        if applied {
            Ok(())
        } else {
            Err(OwnerApprovalError::Replay)
        }
    }

    /// Verify and atomically apply a G02-domain-separated Owner organization command.
    pub fn apply_organization_command(
        &self,
        command: &SignedOrganizationAuthorityCommand,
        now: u64,
    ) -> Result<(), OwnerApprovalError> {
        let p = &command.payload;
        p.validate().map_err(|_| OwnerApprovalError::Malformed)?;
        if p.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(OwnerApprovalError::NotYetValid);
        }
        if p.expires_at <= now {
            return Err(OwnerApprovalError::Expired);
        }
        let owner_key = self
            .keys
            .get(&p.key_id)
            .ok_or(OwnerApprovalError::UnknownOwnerKey)?;
        if p.owner_subject != owner_key.owner_subject {
            return Err(OwnerApprovalError::ScopeMismatch);
        }
        if now < owner_key.not_before
            || now >= owner_key.not_after
            || p.issued_at < owner_key.not_before
            || p.issued_at >= owner_key.not_after
        {
            return Err(OwnerApprovalError::OwnerKeyOutsideValidity);
        }
        if self
            .store
            .key_revoked(OWNER_ISSUER, &p.key_id)
            .map_err(|_| OwnerApprovalError::StoreUnavailable)?
        {
            return Err(OwnerApprovalError::Revoked);
        }

        let bytes = p
            .signing_bytes()
            .map_err(|_| OwnerApprovalError::Malformed)?;
        let signature =
            Signature::from_slice(&command.signature).map_err(|_| OwnerApprovalError::Malformed)?;
        owner_key
            .verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| OwnerApprovalError::InvalidSignature)?;
        let digest = Sha256::digest(&bytes);
        let reason = p.reason.clone();
        let mutation = match &p.action {
            OrganizationAuthorityAction::CreateOrganization => {
                OrganizationMutation::CreateOrganization {
                    organization_id: p.organization_id.clone(),
                    tenant_id: p.tenant_id.clone(),
                    version: p.version,
                    reason,
                }
            }
            OrganizationAuthorityAction::SetOrganizationActive { active } => {
                OrganizationMutation::SetOrganizationActive {
                    organization_id: p.organization_id.clone(),
                    tenant_id: p.tenant_id.clone(),
                    active: *active,
                    version: p.version,
                    reason,
                }
            }
            OrganizationAuthorityAction::SetDesignation => OrganizationMutation::SetDesignation {
                organization_id: p.organization_id.clone(),
                tenant_id: p.tenant_id.clone(),
                principal: p.principal.clone().ok_or(OwnerApprovalError::Malformed)?,
                designation_id: p
                    .designation_id
                    .clone()
                    .ok_or(OwnerApprovalError::Malformed)?,
                active: true,
                capabilities_json: serde_json::to_string(&p.capabilities)
                    .map_err(|_| OwnerApprovalError::Malformed)?,
                version: p.version,
                reason,
            },
            OrganizationAuthorityAction::RevokeDesignation => {
                OrganizationMutation::SetDesignation {
                    organization_id: p.organization_id.clone(),
                    tenant_id: p.tenant_id.clone(),
                    principal: p.principal.clone().ok_or(OwnerApprovalError::Malformed)?,
                    designation_id: p
                        .designation_id
                        .clone()
                        .ok_or(OwnerApprovalError::Malformed)?,
                    active: false,
                    capabilities_json: "[]".to_owned(),
                    version: p.version,
                    reason,
                }
            }
        };
        let applied = self
            .store
            .apply_organization_mutation(
                SecurityCommandReceipt {
                    command_id: &p.command_id,
                    owner_subject: &p.owner_subject,
                    signer_issuer: OWNER_ISSUER,
                    signer_key_id: &p.key_id,
                    digest: digest.as_slice(),
                    at: now,
                },
                mutation,
            )
            .map_err(|error| match error {
                SecurityStoreError::Revoked => OwnerApprovalError::Revoked,
                SecurityStoreError::InvalidVersion
                | SecurityStoreError::Rollback
                | SecurityStoreError::ConflictingVersion => OwnerApprovalError::Malformed,
                _ => OwnerApprovalError::StoreUnavailable,
            })?;
        if applied {
            Ok(())
        } else {
            Err(OwnerApprovalError::Replay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RiskLevel;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (SigningKey, OwnerApprovalVerifier, AuthorizationRequest) {
        let signer = SigningKey::from_bytes(&[51u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:akefa".into(),
                key_id: "owner-key-01".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5_000,
            }],
            store,
        )
        .unwrap();
        let request = AuthorizationRequest::new(
            "principal:requester",
            "finance.approve",
            "ledger:2026-001",
            RiskLevel::High,
        );
        (signer, verifier, request)
    }

    fn signed(signer: &SigningKey, expires_at: u64) -> SignedOwnerApproval {
        let payload = OwnerApprovalPayload::new(
            "approval:one-use",
            "owner:akefa",
            "owner-key-01",
            "principal:requester",
            "finance.approve",
            "ledger:2026-001",
            "policy-v1",
            1_100,
            expires_at,
        );
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedOwnerApproval::from_signature(payload, signature)
    }

    #[test]
    fn verifies_owner_signature_and_consumes_approval_once() {
        let (signer, verifier, request) = fixture();
        let approval = signed(&signer, 1_500);
        assert_eq!(
            verifier.verify_and_consume(&approval, &request, "policy-v1", 1_200),
            Ok(())
        );
        assert_eq!(
            verifier.verify_and_consume(&approval, &request, "policy-v1", 1_201),
            Err(OwnerApprovalError::Replay)
        );
        assert_eq!(verifier.store.approval_receipt_count(), Ok(1));
    }

    #[test]
    fn rejects_tampering_wrong_scope_and_unknown_key() {
        let (signer, verifier, request) = fixture();
        let mut tampered = signed(&signer, 1_500);
        tampered.payload.resource = "ledger:other".into();
        assert_eq!(
            verifier.verify_and_consume(&tampered, &request, "policy-v1", 1_200),
            Err(OwnerApprovalError::ScopeMismatch)
        );

        let mut wrong_signature = signed(&signer, 1_500);
        wrong_signature.signature[0] ^= 0x80;
        assert_eq!(
            verifier.verify_and_consume(&wrong_signature, &request, "policy-v1", 1_200),
            Err(OwnerApprovalError::InvalidSignature)
        );

        let mut unknown = signed(&signer, 1_500);
        unknown.payload.key_id = "unknown".into();
        assert_eq!(
            verifier.verify_and_consume(&unknown, &request, "policy-v1", 1_200),
            Err(OwnerApprovalError::UnknownOwnerKey)
        );
    }

    #[test]
    fn rejects_expired_and_overlong_approvals() {
        let (signer, verifier, request) = fixture();
        assert_eq!(
            verifier.verify_and_consume(&signed(&signer, 1_150), &request, "policy-v1", 1_200),
            Err(OwnerApprovalError::Expired)
        );
        assert_eq!(
            verifier.verify_and_consume(&signed(&signer, 3_000), &request, "policy-v1", 1_200),
            Err(OwnerApprovalError::Malformed)
        );
    }

    #[test]
    fn rejects_revoked_owner_key_and_approval() {
        let (signer, verifier, request) = fixture();
        verifier
            .store
            .revoke_key(OWNER_ISSUER, "owner-key-01", 1_150, "key compromise")
            .unwrap();
        assert_eq!(
            verifier.verify_and_consume(&signed(&signer, 1_500), &request, "policy-v1", 1_200),
            Err(OwnerApprovalError::Revoked)
        );
    }
    #[test]
    fn owner_signed_revocation_is_atomic_and_replay_protected() {
        let (signer, verifier, _request) = fixture();
        let payload = OwnerSecurityCommandPayload {
            command_id: "command:revoke-credential-1".into(),
            owner_subject: "owner:akefa".into(),
            key_id: "owner-key-01".into(),
            issued_at: 1_100,
            expires_at: 1_500,
            action: OwnerSecurityAction::RevokeCredential {
                issuer: "issuer:service".into(),
                credential_id: "credential:compromised".into(),
                reason: "credential compromise".into(),
            },
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let command = SignedOwnerSecurityCommand::from_signature(payload, signature);
        assert_eq!(verifier.apply_security_command(&command, 1_200), Ok(()));
        assert_eq!(
            verifier
                .store
                .credential_revoked("issuer:service", "credential:compromised"),
            Ok(true)
        );
        assert_eq!(
            verifier.apply_security_command(&command, 1_201),
            Err(OwnerApprovalError::Replay)
        );
        assert_eq!(verifier.store.security_command_count(), Ok(1));
    }
}
