//! G02 Owner-signed immutable policy snapshots and fail-closed activation.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AuditEvent, DecisionCode, OwnerApprovalError, OwnerApprovalVerifier, Policy, RiskLevel,
    SqliteAuditSink, SqliteSecurityStore,
};

const DOMAIN: &[u8] = b"IROKA:G02:POLICY-SNAPSHOT:V1\0";
const MAX_POLICY_TTL_SECS: u64 = 86_400;
const CLOCK_SKEW_SECS: u64 = 30;
const MAX_CAPABILITIES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotPayload {
    pub schema_id: String,
    pub contract_version: String,
    pub owner_subject: String,
    pub key_id: String,
    pub policy_epoch: u64,
    pub policy_version: String,
    pub allowed_capabilities: Vec<String>,
    pub approval_required: Vec<String>,
    pub maximum_risk: RiskLevel,
    pub emergency_stop_active: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl PolicySnapshotPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PolicyLifecycleError> {
        let canonical = serde_jcs::to_vec(self).map_err(|_| PolicyLifecycleError::Malformed)?;
        let mut bytes = Vec::with_capacity(DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub(crate) fn validate(&self, now: u64) -> Result<(), PolicyLifecycleError> {
        if self.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(PolicyLifecycleError::NotYetValid);
        }
        if self.expires_at <= now {
            return Err(PolicyLifecycleError::Expired);
        }
        if self.schema_id != "iroka.g02.policy-snapshot"
            || self.contract_version != "1.0"
            || self.owner_subject.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.policy_epoch == 0
            || self.policy_version.trim().is_empty()
            || self.policy_version.len() > 128
            || self.issued_at >= self.expires_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_POLICY_TTL_SECS
            || self.allowed_capabilities.len() > MAX_CAPABILITIES
            || self.approval_required.len() > MAX_CAPABILITIES
        {
            return Err(PolicyLifecycleError::Malformed);
        }
        if !strictly_sorted_unique(&self.allowed_capabilities)
            || !strictly_sorted_unique(&self.approval_required)
            || self
                .approval_required
                .iter()
                .any(|v| !self.allowed_capabilities.contains(v))
            || self
                .allowed_capabilities
                .iter()
                .any(|v| v.trim().is_empty() || v.len() > 256)
            || self
                .approval_required
                .iter()
                .any(|v| v.trim().is_empty() || v.len() > 256)
        {
            return Err(PolicyLifecycleError::Malformed);
        }
        Ok(())
    }
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|w| w[0] < w[1])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicySnapshot {
    pub payload: PolicySnapshotPayload,
    pub signature: Vec<u8>,
}

impl SignedPolicySnapshot {
    pub fn from_signature(payload: PolicySnapshotPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLifecycleError {
    Malformed,
    UnknownOwnerKey,
    OwnerKeyOutsideValidity,
    InvalidSignature,
    Expired,
    NotYetValid,
    Revoked,
    Rollback,
    ConflictingEpoch,
    StoreUnavailable,
    AuditUnavailable,
    Inactive,
}

impl From<OwnerApprovalError> for PolicyLifecycleError {
    fn from(value: OwnerApprovalError) -> Self {
        match value {
            OwnerApprovalError::UnknownOwnerKey => Self::UnknownOwnerKey,
            OwnerApprovalError::OwnerKeyOutsideValidity => Self::OwnerKeyOutsideValidity,
            OwnerApprovalError::InvalidSignature => Self::InvalidSignature,
            OwnerApprovalError::Expired => Self::Expired,
            OwnerApprovalError::NotYetValid => Self::NotYetValid,
            OwnerApprovalError::Revoked => Self::Revoked,
            OwnerApprovalError::Malformed | OwnerApprovalError::ScopeMismatch => Self::Malformed,
            OwnerApprovalError::Replay => Self::ConflictingEpoch,
            OwnerApprovalError::StoreUnavailable => Self::StoreUnavailable,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedPolicySnapshot {
    pub(crate) payload: PolicySnapshotPayload,
    pub(crate) signature: Vec<u8>,
    pub(crate) canonical_payload: Vec<u8>,
    pub(crate) digest: [u8; 32],
}

impl VerifiedPolicySnapshot {
    pub fn epoch(&self) -> u64 {
        self.payload.policy_epoch
    }
    pub fn version(&self) -> &str {
        &self.payload.policy_version
    }
    pub fn emergency_stop_active(&self) -> bool {
        self.payload.emergency_stop_active()
    }
    pub fn policy(&self) -> Policy {
        Policy::new(
            self.payload.policy_version.clone(),
            self.payload.allowed_capabilities.clone(),
            self.payload.approval_required.clone(),
            self.payload.maximum_risk,
        )
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedPolicyContext {
    epoch: u64,
    digest: [u8; 32],
    policy: Policy,
    emergency_stop_active: bool,
}

impl VerifiedPolicyContext {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn emergency_stop_active(&self) -> bool {
        self.emergency_stop_active
    }
}

pub struct PolicyActivationCoordinator;

impl PolicyActivationCoordinator {
    pub fn activate(
        verifier: &OwnerApprovalVerifier,
        audit: &SqliteAuditSink,
        signed: &SignedPolicySnapshot,
        now: u64,
    ) -> Result<VerifiedPolicyContext, PolicyLifecycleError> {
        let verified = verifier.verify_policy_snapshot(signed, now)?;
        let store = verifier.security_store();
        let previous_epoch = store
            .stage_policy_snapshot(
                verified.epoch(),
                &verified.digest,
                &verified.canonical_payload,
                &verified.signature,
                &verified.payload.owner_subject,
                &verified.payload.key_id,
                verified.version(),
                verified.payload.issued_at,
                verified.payload.expires_at,
                verified.payload.emergency_stop_active,
            )
            .map_err(map_store_error)?;

        let digest_hex = verified
            .digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let event_id = format!("g02-policy-activate:{}:{digest_hex}", verified.epoch());
        let event = AuditEvent::new(
            event_id.clone(),
            event_id,
            &verified.payload.owner_subject,
            "g02.policy.activate",
            format!(
                "policy-epoch:{}:digest:{}:key:{}:previous:{}",
                verified.epoch(),
                digest_hex,
                verified.payload.key_id,
                previous_epoch.map_or_else(|| "none".to_owned(), |value| value.to_string())
            ),
            verified.version(),
            DecisionCode::Allow,
            verified.payload.issued_at,
        );
        audit
            .append_event_idempotent(&event)
            .map_err(|_| PolicyLifecycleError::AuditUnavailable)?;
        store
            .activate_policy_snapshot(verified.epoch(), &verified.digest, now)
            .map_err(map_store_error)?;
        Ok(VerifiedPolicyContext {
            epoch: verified.epoch(),
            digest: verified.digest,
            policy: verified.policy(),
            emergency_stop_active: verified.emergency_stop_active(),
        })
    }

    pub fn load_active(
        verifier: &OwnerApprovalVerifier,
        now: u64,
    ) -> Result<VerifiedPolicyContext, PolicyLifecycleError> {
        let (epoch, signed) = verifier
            .security_store()
            .active_policy_snapshot()
            .map_err(map_store_error)?
            .ok_or(PolicyLifecycleError::Inactive)?;
        let verified = verifier.verify_policy_snapshot(&signed, now)?;
        if verified.epoch() != epoch {
            return Err(PolicyLifecycleError::Rollback);
        }
        Ok(VerifiedPolicyContext {
            epoch,
            digest: verified.digest,
            policy: verified.policy(),
            emergency_stop_active: verified.emergency_stop_active(),
        })
    }
}

fn map_store_error(error: crate::SecurityStoreError) -> PolicyLifecycleError {
    match error {
        crate::SecurityStoreError::Rollback => PolicyLifecycleError::Rollback,
        crate::SecurityStoreError::ConflictingVersion => PolicyLifecycleError::ConflictingEpoch,
        crate::SecurityStoreError::Revoked => PolicyLifecycleError::Revoked,
        _ => PolicyLifecycleError::StoreUnavailable,
    }
}

pub(crate) fn canonical_payload_and_digest(
    payload: &PolicySnapshotPayload,
) -> Result<(Vec<u8>, [u8; 32]), PolicyLifecycleError> {
    let bytes = serde_jcs::to_vec(payload).map_err(|_| PolicyLifecycleError::Malformed)?;
    let digest = Sha256::digest(&bytes).into();
    Ok((bytes, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OwnerApprovalError, TrustedOwnerKey};
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;

    fn fixture() -> (
        SigningKey,
        OwnerApprovalVerifier,
        Arc<SqliteSecurityStore>,
        SqliteAuditSink,
    ) {
        let signer = SigningKey::from_bytes(&[83u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:akefa".into(),
                key_id: "owner-key-policy".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 10_000,
            }],
            Arc::clone(&store),
        )
        .unwrap();
        let audit = SqliteAuditSink::open_in_memory().unwrap();
        (signer, verifier, store, audit)
    }

    fn payload(epoch: u64, emergency_stop_active: bool) -> PolicySnapshotPayload {
        PolicySnapshotPayload {
            schema_id: "iroka.g02.policy-snapshot".into(),
            contract_version: "1.0".into(),
            owner_subject: "owner:akefa".into(),
            key_id: "owner-key-policy".into(),
            policy_epoch: epoch,
            policy_version: format!("policy-{epoch}"),
            allowed_capabilities: vec!["finance.read".into(), "workspace.read".into()],
            approval_required: vec!["finance.read".into()],
            maximum_risk: RiskLevel::High,
            emergency_stop_active,
            issued_at: 1_100 + epoch,
            expires_at: 2_000 + epoch,
        }
    }

    fn signed(signer: &SigningKey, epoch: u64, emergency: bool) -> SignedPolicySnapshot {
        let payload = payload(epoch, emergency);
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedPolicySnapshot::from_signature(payload, signature)
    }

    #[test]
    fn policy_signatures_use_jcs_and_domain_separation() {
        let p = payload(1, false);
        let canonical = serde_jcs::to_vec(&p).unwrap();
        let signing = p.signing_bytes().unwrap();
        assert!(signing.starts_with(DOMAIN));
        assert_eq!(&signing[DOMAIN.len()..], canonical.as_slice());
        assert_ne!(signing, serde_json::to_vec(&p).unwrap());
    }

    #[test]
    fn owner_signed_policy_is_audited_before_activation_and_loads_verified() {
        let (signer, verifier, store, audit) = fixture();
        let signed = signed(&signer, 1, true);
        let active =
            PolicyActivationCoordinator::activate(&verifier, &audit, &signed, 1_200).unwrap();
        assert_eq!(active.epoch(), 1);
        assert!(active.emergency_stop_active());
        assert!(active.policy().allows_capability("workspace.read"));
        assert_eq!(audit.head().unwrap().0, 1);
        let loaded = PolicyActivationCoordinator::load_active(&verifier, 1_201).unwrap();
        assert_eq!(loaded.epoch(), 1);
        assert!(loaded.emergency_stop_active());
        assert_eq!(loaded.digest(), active.digest());
    }

    #[test]
    fn identical_activation_retry_is_idempotent() {
        let (signer, verifier, store, audit) = fixture();
        let signed = signed(&signer, 1, false);
        PolicyActivationCoordinator::activate(&verifier, &audit, &signed, 1_200).unwrap();
        PolicyActivationCoordinator::activate(&verifier, &audit, &signed, 1_250).unwrap();
        assert_eq!(audit.head().unwrap().0, 1);
    }

    #[test]
    fn pending_snapshot_is_not_active_before_g11_confirmation() {
        let (signer, verifier, store, _audit) = fixture();
        let signed = signed(&signer, 1, false);
        let verified = verifier.verify_policy_snapshot(&signed, 1_200).unwrap();
        assert_eq!(
            store
                .stage_policy_snapshot(
                    verified.epoch(),
                    &verified.digest,
                    &verified.canonical_payload,
                    &verified.signature,
                    "owner:akefa",
                    "owner-key-policy",
                    "policy-1",
                    1_101,
                    2_001,
                    false,
                )
                .unwrap(),
            None
        );
        assert_eq!(
            PolicyActivationCoordinator::load_active(&verifier, 1_201).unwrap_err(),
            PolicyLifecycleError::Inactive
        );
    }

    #[test]
    fn g11_failure_keeps_policy_pending_and_retry_recovers_idempotently() {
        let (signer, verifier, store, audit) = fixture();
        let signed = signed(&signer, 1, false);
        audit.force_append_failure(true).unwrap();
        assert_eq!(
            PolicyActivationCoordinator::activate(&verifier, &audit, &signed, 1_200).unwrap_err(),
            PolicyLifecycleError::AuditUnavailable
        );
        assert_eq!(
            PolicyActivationCoordinator::load_active(&verifier, 1_201).unwrap_err(),
            PolicyLifecycleError::Inactive
        );
        audit.force_append_failure(false).unwrap();
        PolicyActivationCoordinator::activate(&verifier, &audit, &signed, 1_202).unwrap();
        assert_eq!(audit.head().unwrap().0, 1);
    }

    #[test]
    fn pending_owner_policy_revocation_blocks_policy_use_until_g11_recovers() {
        let (signer, verifier, store, audit) = fixture();
        let signed = signed(&signer, 1, false);
        PolicyActivationCoordinator::activate(&verifier, &store, &audit, &signed, 1_200).unwrap();
        store
            .stage_policy_revocation(
                1,
                "pending-revoke",
                &[7u8; 32],
                "owner:akefa",
                "owner-key-policy",
                "test pending revocation",
                1_300,
            )
            .unwrap();
        assert_eq!(
            PolicyActivationCoordinator::load_active(&verifier, 1_301).unwrap_err(),
            PolicyLifecycleError::Inactive
        );
    }

    #[test]
    fn policy_epochs_are_monotonic_and_same_epoch_conflicts_fail() {
        let (signer, verifier, store, audit) = fixture();
        let first = signed(&signer, 1, false);
        PolicyActivationCoordinator::activate(&verifier, &audit, &first, 1_200).unwrap();
        let second = signed(&signer, 2, true);
        PolicyActivationCoordinator::activate(&verifier, &audit, &second, 1_300).unwrap();
        assert_eq!(
            PolicyActivationCoordinator::activate(&verifier, &audit, &first, 1_301).unwrap_err(),
            PolicyLifecycleError::Rollback
        );
        let conflict_payload = payload(2, false);
        let conflict_signature = signer
            .sign(&conflict_payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let conflict = SignedPolicySnapshot::from_signature(conflict_payload, conflict_signature);
        assert_eq!(
            PolicyActivationCoordinator::activate(&verifier, &audit, &conflict, 1_302).unwrap_err(),
            PolicyLifecycleError::ConflictingEpoch
        );
    }

    #[test]
    fn invalid_signature_expiry_and_revoked_owner_key_fail_closed() {
        let (signer, verifier, store, audit) = fixture();
        let mut bad = signed(&signer, 1, false);
        bad.signature[0] ^= 0x80;
        assert_eq!(
            verifier.verify_policy_snapshot(&bad, 1_200).unwrap_err(),
            OwnerApprovalError::InvalidSignature
        );
        let expired = signed(&signer, 2, false);
        assert_eq!(
            verifier
                .verify_policy_snapshot(&expired, 3_000)
                .unwrap_err(),
            OwnerApprovalError::Expired
        );
        store
            .revoke_key(
                "iroka:owner-authority",
                "owner-key-policy",
                1_250,
                "test revocation",
            )
            .unwrap();
        let valid = signed(&signer, 3, false);
        assert_eq!(
            PolicyActivationCoordinator::activate(&verifier, &audit, &valid, 1_300).unwrap_err(),
            PolicyLifecycleError::Revoked
        );
    }

    #[test]
    fn owner_signed_revocation_is_audited_before_policy_is_disabled() {
        let (signer, verifier, store, audit) = fixture();
        let active = signed(&signer, 1, false);
        PolicyActivationCoordinator::activate(&verifier, &audit, &active, 1_200).unwrap();
        let payload = crate::OwnerSecurityCommandPayload {
            command_id: "policy-revoke-1".into(),
            owner_subject: "owner:akefa".into(),
            key_id: "owner-key-policy".into(),
            issued_at: 1_300,
            expires_at: 1_600,
            action: crate::OwnerSecurityAction::RevokePolicy {
                policy_epoch: 1,
                reason: "policy superseded by incident response".into(),
            },
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let command = crate::SignedOwnerSecurityCommand::from_signature(payload, signature);
        verifier
            .revoke_policy_snapshot(&command, &audit, 1_350)
            .unwrap();
        assert_eq!(
            PolicyActivationCoordinator::load_active(&verifier, 1_351).unwrap_err(),
            PolicyLifecycleError::Inactive
        );
        verifier
            .revoke_policy_snapshot(&command, &audit, 1_352)
            .unwrap();
        assert_eq!(audit.head().unwrap().0, 2);
    }

    #[test]
    fn emergency_stop_can_only_be_cleared_by_a_new_owner_signed_epoch() {
        let (signer, verifier, store, audit) = fixture();
        let stopped = signed(&signer, 1, true);
        assert!(
            PolicyActivationCoordinator::activate(&verifier, &audit, &stopped, 1_200)
                .unwrap()
                .emergency_stop_active
        );
        let cleared = signed(&signer, 2, false);
        assert!(
            !PolicyActivationCoordinator::activate(&verifier, &audit, &cleared, 1_300)
                .unwrap()
                .emergency_stop_active
        );
        assert_eq!(audit.head().unwrap().0, 2);
    }

    #[test]
    fn malformed_capability_order_and_unknown_schema_are_rejected() {
        let (_signer, verifier, _store, _audit) = fixture();
        let mut p = payload(1, false);
        p.allowed_capabilities.swap(0, 1);
        assert_eq!(p.validate(1_200), Err(PolicyLifecycleError::Malformed));
        let mut p = payload(1, false);
        p.schema_id = "unknown.schema".into();
        assert_eq!(p.validate(1_200), Err(PolicyLifecycleError::Malformed));
        let _ = verifier;
    }
}
