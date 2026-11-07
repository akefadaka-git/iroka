//! Two-person K-04 recovery authorization bound to an independently read witness high-water mark.
//! This module defines the verification boundary; production approver keys and the external
//! high-water adapter must be provisioned outside the application and repository.

use std::{collections::BTreeMap, sync::Arc};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuditHead, RevocationChecker, SecurityStoreError, SqliteSecurityStore};

const RECOVERY_DOMAIN: &[u8] = b"IROKA:G11:K04:RECOVERY-APPROVAL:V1\0";
const RECOVERY_ISSUER: &str = "iroka:k04:recovery-authority";
const MAX_APPROVAL_TTL_SECS: u64 = 900;
const CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApprovalPayload {
    pub approval_id: String,
    pub recovery_id: String,
    pub approver_subject: String,
    pub key_id: String,
    pub stream_id: String,
    pub expected_checkpoint_number: u64,
    pub expected_checkpoint_digest: [u8; 32],
    pub local_sequence: u64,
    pub local_head_hash: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl RecoveryApprovalPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        let encoded = serde_json::to_vec(self).map_err(|_| RecoveryError::Malformed)?;
        let mut bytes = Vec::with_capacity(RECOVERY_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(RECOVERY_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRecoveryApproval {
    pub payload: RecoveryApprovalPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TrustedRecoveryApprover {
    pub subject: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryHighWater {
    pub checkpoint_number: u64,
    pub checkpoint_digest: [u8; 32],
    pub last_sequence: u64,
    pub head_event_hash: [u8; 32],
}

/// Must read the high-water value from an independently administered witness/anchor domain.
pub trait ExternalWitnessHighWater: Send + Sync {
    fn high_water(&self, stream_id: &str) -> Result<Option<RecoveryHighWater>, RecoveryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAuthorization {
    pub recovery_id: String,
    pub stream_id: String,
    pub witnessed_checkpoint_number: u64,
    pub local_head_sequence: u64,
    pub local_ahead_of_witnessed_head: bool,
    pub approved_by: [String; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    Malformed,
    UnknownApprover,
    ApproverOutsideValidity,
    InvalidSignature,
    Expired,
    NotYetValid,
    ScopeMismatch,
    Revoked,
    HighWaterUnavailable,
    HighWaterMismatch,
    LocalRollbackOrTampering,
    DuplicateApprover,
    Replay,
    StoreUnavailable,
}

impl From<SecurityStoreError> for RecoveryError {
    fn from(error: SecurityStoreError) -> Self {
        match error {
            SecurityStoreError::InvalidVersion => Self::Malformed,
            SecurityStoreError::Revoked => Self::Revoked,
            _ => Self::StoreUnavailable,
        }
    }
}

#[derive(Debug, Clone)]
struct ApproverKey {
    subject: String,
    verifying_key: VerifyingKey,
    not_before: u64,
    not_after: u64,
}

pub struct RecoveryApprovalVerifier {
    keys: BTreeMap<String, ApproverKey>,
    store: Arc<SqliteSecurityStore>,
}

impl RecoveryApprovalVerifier {
    pub fn new(
        approvers: Vec<TrustedRecoveryApprover>,
        store: Arc<SqliteSecurityStore>,
    ) -> Result<Self, RecoveryError> {
        if approvers.len() < 2 {
            return Err(RecoveryError::UnknownApprover);
        }
        let mut keys = BTreeMap::new();
        let mut subjects = std::collections::BTreeSet::new();
        for approver in approvers {
            if approver.subject.trim().is_empty()
                || approver.key_id.trim().is_empty()
                || approver.not_before >= approver.not_after
                || !subjects.insert(approver.subject.clone())
            {
                return Err(RecoveryError::Malformed);
            }
            let verifying_key = VerifyingKey::from_bytes(&approver.public_key)
                .map_err(|_| RecoveryError::Malformed)?;
            if keys
                .insert(
                    approver.key_id,
                    ApproverKey {
                        subject: approver.subject,
                        verifying_key,
                        not_before: approver.not_before,
                        not_after: approver.not_after,
                    },
                )
                .is_some()
            {
                return Err(RecoveryError::Malformed);
            }
        }
        Ok(Self { keys, store })
    }

    /// Verify two distinct, one-time approvals and compare the restored local head with
    /// an independently fetched witness high-water mark before authorizing recovery.
    pub fn authorize_recovery(
        &self,
        approvals: &[SignedRecoveryApproval],
        local: &AuditHead,
        external: &dyn ExternalWitnessHighWater,
        now: u64,
    ) -> Result<RecoveryAuthorization, RecoveryError> {
        if approvals.len() != 2 {
            return Err(RecoveryError::DuplicateApprover);
        }
        let first = &approvals[0].payload;
        let second = &approvals[1].payload;
        if first.approval_id.trim().is_empty()
            || second.approval_id.trim().is_empty()
            || first.recovery_id.trim().is_empty()
            || first.stream_id.trim().is_empty()
            || first.expected_checkpoint_number == 0
            || first.expected_checkpoint_digest == [0; 32]
            || first.local_head_hash == [0; 32]
            || first.issued_at >= first.expires_at
            || first.approval_id == second.approval_id
        {
            return Err(RecoveryError::Malformed);
        }
        if first.approver_subject == second.approver_subject {
            return Err(RecoveryError::DuplicateApprover);
        }
        if first.recovery_id != second.recovery_id
            || first.stream_id != second.stream_id
            || first.expected_checkpoint_number != second.expected_checkpoint_number
            || first.expected_checkpoint_digest != second.expected_checkpoint_digest
            || first.local_sequence != second.local_sequence
            || first.local_head_hash != second.local_head_hash
            || first.issued_at != second.issued_at
            || first.expires_at != second.expires_at
        {
            return Err(RecoveryError::ScopeMismatch);
        }
        if first.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(RecoveryError::NotYetValid);
        }
        if first.expires_at <= now {
            return Err(RecoveryError::Expired);
        }
        if first.expires_at - first.issued_at > MAX_APPROVAL_TTL_SECS {
            return Err(RecoveryError::Malformed);
        }
        if local.last_sequence != first.local_sequence
            || local.head_event_hash != first.local_head_hash
        {
            return Err(RecoveryError::ScopeMismatch);
        }

        let mut approval_digests = Vec::with_capacity(2);
        for approval in approvals {
            let payload = &approval.payload;
            let key = self
                .keys
                .get(&payload.key_id)
                .ok_or(RecoveryError::UnknownApprover)?;
            if key.subject != payload.approver_subject {
                return Err(RecoveryError::ScopeMismatch);
            }
            if now < key.not_before
                || now >= key.not_after
                || payload.issued_at < key.not_before
                || payload.issued_at >= key.not_after
            {
                return Err(RecoveryError::ApproverOutsideValidity);
            }
            if self
                .store
                .key_revoked(RECOVERY_ISSUER, &payload.key_id)
                .map_err(|_| RecoveryError::StoreUnavailable)?
            {
                return Err(RecoveryError::Revoked);
            }
            let signing_bytes = payload.signing_bytes()?;
            let signature = Signature::from_slice(&approval.signature)
                .map_err(|_| RecoveryError::Malformed)?;
            key.verifying_key
                .verify(&signing_bytes, &signature)
                .map_err(|_| RecoveryError::InvalidSignature)?;
            approval_digests.push(Sha256::digest(&signing_bytes).to_vec());
        }

        let high_water = external
            .high_water(&first.stream_id)?
            .ok_or(RecoveryError::HighWaterUnavailable)?;
        if high_water.checkpoint_number != first.expected_checkpoint_number
            || high_water.checkpoint_digest != first.expected_checkpoint_digest
        {
            return Err(RecoveryError::HighWaterMismatch);
        }
        if local.last_sequence < high_water.last_sequence
            || (local.last_sequence == high_water.last_sequence
                && local.head_event_hash != high_water.head_event_hash)
        {
            return Err(RecoveryError::LocalRollbackOrTampering);
        }

        let mut pair = Vec::new();
        pair.extend_from_slice(b"IROKA:G11:K04:RECOVERY-PAIR:V1\0");
        let mut ordered = approvals.iter().collect::<Vec<_>>();
        ordered.sort_by(|a, b| a.payload.approver_subject.cmp(&b.payload.approver_subject));
        for approval in ordered {
            let bytes = approval.payload.signing_bytes()?;
            pair.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            pair.extend_from_slice(&bytes);
            pair.extend_from_slice(&(approval.signature.len() as u64).to_be_bytes());
            pair.extend_from_slice(&approval.signature);
        }
        let pair_digest = Sha256::digest(pair);
        let approval_ids = [&first.approval_id[..], &second.approval_id[..]];
        if !self.store.consume_recovery_approval_pair(
            &first.recovery_id,
            approval_ids,
            pair_digest.as_slice(),
            now,
        )? {
            return Err(RecoveryError::Replay);
        }

        let mut approved_by = [
            first.approver_subject.clone(),
            second.approver_subject.clone(),
        ];
        approved_by.sort();
        Ok(RecoveryAuthorization {
            recovery_id: first.recovery_id.clone(),
            stream_id: first.stream_id.clone(),
            witnessed_checkpoint_number: high_water.checkpoint_number,
            local_head_sequence: local.last_sequence,
            local_ahead_of_witnessed_head: local.last_sequence > high_water.last_sequence,
            approved_by,
        })
    }
}
