//! G02 Owner-signed immutable policy snapshots and fail-closed activation.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuditEvent, DecisionCode, OwnerApprovalError, OwnerApprovalVerifier, Policy, RiskLevel, SqliteAuditSink, SqliteSecurityStore};

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

    fn validate(&self, now: u64) -> Result<(), PolicyLifecycleError> {
        if self.schema_id != "iroka.g02.policy-snapshot"
            || self.contract_version != "1.0"
            || self.owner_subject.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.policy_epoch == 0
            || self.policy_version.trim().is_empty()
            || self.policy_version.len() > 128
            || self.issued_at >= self.expires_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_POLICY_TTL_SECS
            || self.issued_at > now.saturating_add(CLOCK_SKEW_SECS)
            || self.expires_at <= now
            || self.allowed_capabilities.is_empty()
            || self.allowed_capabilities.len() > MAX_CAPABILITIES
            || self.approval_required.len() > MAX_CAPABILITIES
        {
            return Err(PolicyLifecycleError::Malformed);
        }
        if !strictly_sorted_unique(&self.allowed_capabilities)
            || !strictly_sorted_unique(&self.approval_required)
            || self.approval_required.iter().any(|v| !self.allowed_capabilities.contains(v))
            || self.allowed_capabilities.iter().any(|v| v.trim().is_empty() || v.len() > 256)
            || self.approval_required.iter().any(|v| v.trim().is_empty() || v.len() > 256)
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
    pub fn epoch(&self) -> u64 { self.payload.policy_epoch }
    pub fn version(&self) -> &str { &self.payload.policy_version }
    pub fn emergency_stop_active(&self) -> bool { self.payload.emergency_stop_active }
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
    pub epoch: u64,
    pub digest: [u8; 32],
    pub policy: Policy,
    pub emergency_stop_active: bool,
}

pub struct PolicyActivationCoordinator;

impl PolicyActivationCoordinator {
    pub fn activate(
        verifier: &OwnerApprovalVerifier,
        store: &SqliteSecurityStore,
        audit: &SqliteAuditSink,
        signed: &SignedPolicySnapshot,
        now: u64,
    ) -> Result<VerifiedPolicyContext, PolicyLifecycleError> {
        let verified = verifier.verify_policy_snapshot(signed, now)?;
        store.stage_policy_snapshot(
            verified.epoch(),
            &verified.digest,
            &verified.canonical_payload,
            &verified.signature,
            &verified.payload.owner_subject,
            &verified.payload.key_id,
            verified.version(),
            verified.payload.issued_at,
            verified.payload.expires_at,
            now,
        ).map_err(map_store_error)?;

        let digest_hex = verified.digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let event_id = format!("g02-policy-activate:{}:{digest_hex}", verified.epoch());
        let event = AuditEvent::new(
            event_id.clone(),
            event_id,
            &verified.payload.owner_subject,
            "g02.policy.activate",
            format!("policy-epoch:{}", verified.epoch()),
            verified.version(),
            DecisionCode::Allow,
            now,
        );
        audit.append_event_idempotent(&event).map_err(|_| PolicyLifecycleError::AuditUnavailable)?;
        store.activate_policy_snapshot(verified.epoch(), &verified.digest, now).map_err(map_store_error)?;
        Ok(VerifiedPolicyContext {
            epoch: verified.epoch(),
            digest: verified.digest,
            policy: verified.policy(),
            emergency_stop_active: verified.emergency_stop_active(),
        })
    }

    pub fn load_active(
        verifier: &OwnerApprovalVerifier,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<VerifiedPolicyContext, PolicyLifecycleError> {
        let (epoch, signed) = store.active_policy_snapshot().map_err(map_store_error)?
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
