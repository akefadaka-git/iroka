//! IGACMS A4-03-E external checkpoint quorum protocol.
//!
//! This module enforces the frozen 2-of-3 independently administered witness
//! rule and two independently administered immutable-retention domains. It
//! defines provider ports and offline verification; production endpoints and
//! operator/key custody are deployment configuration, never test defaults.
use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::SignedCheckpoint;

const WITNESS_DOMAIN: &[u8] = b"IROKA:G11:WITNESS-RECEIPT:V1\0";
const RETENTION_DOMAIN: &[u8] = b"IROKA:G11:RETENTION-RECEIPT:V1\0";
const MANIFEST_DOMAIN: &[u8] = b"IROKA:G11:SEGMENT-MANIFEST:V1\0";
const MAX_CLOCK_SKEW_SECS: u64 = 30;
const MAX_RECEIPT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointQuorumError {
    InvalidPolicy,
    Malformed,
    InvalidSigner,
    InvalidSignature,
    InvalidWitnessReceipt,
    InsufficientWitnessQuorum,
    InvalidRetentionReceipt,
    InsufficientRetentionDomains,
    RetentionNotImmutable,
    StreamMismatch,
    SequenceMismatch,
    PreviousCheckpointMismatch,
    ProviderUnavailable,
}

#[derive(Debug, Clone)]
pub struct CheckpointSignerTrust {
    pub operator_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
pub struct WitnessTrust {
    pub witness_id: String,
    pub operator_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
pub struct RetentionDomainTrust {
    pub domain_id: String,
    pub operator_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
pub struct CheckpointQuorumPolicy {
    signer: CheckpointSignerTrust,
    witnesses: HashMap<String, WitnessTrust>,
    retention_domains: HashMap<String, RetentionDomainTrust>,
    minimum_retention_secs: u64,
}

impl CheckpointQuorumPolicy {
    pub fn new(
        signer: CheckpointSignerTrust,
        witnesses: Vec<WitnessTrust>,
        retention_domains: Vec<RetentionDomainTrust>,
        minimum_retention_secs: u64,
    ) -> Result<Self, CheckpointQuorumError> {
        if minimum_retention_secs == 0 || witnesses.len() != 3 || retention_domains.len() != 2 {
            return Err(CheckpointQuorumError::InvalidPolicy);
        }
        validate_key(&signer.public_key, &signer.key_id, signer.not_before, signer.not_after)?;
        let mut operators = HashSet::new();
        if signer.operator_id.trim().is_empty() || !operators.insert(signer.operator_id.clone()) {
            return Err(CheckpointQuorumError::InvalidPolicy);
        }
        let mut witness_map = HashMap::new();
        let mut all_key_ids = HashSet::from([signer.key_id.clone()]);
        let mut all_public_keys = HashSet::from([signer.public_key]);
        for witness in witnesses {
            validate_key(&witness.public_key, &witness.key_id, witness.not_before, witness.not_after)?;
            if witness.witness_id.trim().is_empty()
                || witness.witness_id.len() > 256
                || witness.operator_id.trim().is_empty()
                || witness.operator_id.len() > 256
                || !operators.insert(witness.operator_id.clone())
                || !all_key_ids.insert(witness.key_id.clone())
                || !all_public_keys.insert(witness.public_key)
                || witness_map.insert(witness.witness_id.clone(), witness).is_some()
            {
                return Err(CheckpointQuorumError::InvalidPolicy);
            }
        }
        let mut retention_map = HashMap::new();
        for domain in retention_domains {
            validate_key(&domain.public_key, &domain.key_id, domain.not_before, domain.not_after)?;
            if domain.domain_id.trim().is_empty()
                || domain.domain_id.len() > 256
                || domain.operator_id.trim().is_empty()
                || domain.operator_id.len() > 256
                || !operators.insert(domain.operator_id.clone())
                || !all_key_ids.insert(domain.key_id.clone())
                || !all_public_keys.insert(domain.public_key)
                || retention_map.insert(domain.domain_id.clone(), domain).is_some()
            {
                return Err(CheckpointQuorumError::InvalidPolicy);
            }
        }
        Ok(Self {
            signer,
            witnesses: witness_map,
            retention_domains: retention_map,
            minimum_retention_secs,
        })
    }
}

fn validate_key(
    public_key: &[u8; 32],
    key_id: &str,
    not_before: u64,
    not_after: u64,
) -> Result<(), CheckpointQuorumError> {
    if key_id.trim().is_empty()
        || not_before >= not_after
        || VerifyingKey::from_bytes(public_key).is_err()
    {
        return Err(CheckpointQuorumError::InvalidPolicy);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSegmentManifest {
    pub schema_id: String,
    pub stream_id: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
    pub audit_head_digest: String,
    pub entries_merkle_root: String,
    pub entry_count: u64,
    pub issued_at: u64,
}

impl CheckpointSegmentManifest {
    pub fn digest(&self) -> Result<String, CheckpointQuorumError> {
        self.validate_shape()?;
        let canonical = serde_jcs::to_vec(self).map_err(|_| CheckpointQuorumError::Malformed)?;
        let mut bytes = MANIFEST_DOMAIN.to_vec();
        bytes.extend_from_slice(&canonical);
        Ok(sha256_hex(&bytes))
    }

    fn validate_shape(&self) -> Result<(), CheckpointQuorumError> {
        if self.schema_id != "iroka.g11.checkpoint-segment.v1"
            || self.stream_id.trim().is_empty()
            || self.stream_id.len() > 256
            || self.first_sequence == 0
            || self.last_sequence < self.first_sequence
            || self.last_sequence.checked_sub(self.first_sequence).and_then(|v| v.checked_add(1)) != Some(self.entry_count)
            || !valid_digest(&self.audit_head_digest)
            || !valid_digest(&self.entries_merkle_root)
            || self.previous_checkpoint_digest.as_deref().is_some_and(|d| !valid_digest(d))
        {
            return Err(CheckpointQuorumError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CheckpointChainPosition<'a> {
    pub stream_id: &'a str,
    pub sequence: u64,
    pub previous_digest: Option<&'a str>,
    pub previous_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPackage {
    pub checkpoint: SignedCheckpoint,
    pub manifest: CheckpointSegmentManifest,
}

impl CheckpointPackage {
    pub fn validate(
        &self,
        position: &CheckpointChainPosition<'_>,
    ) -> Result<(), CheckpointQuorumError> {
        self.manifest.validate_shape()?;
        self.checkpoint.payload.validate().map_err(|_| CheckpointQuorumError::Malformed)?;
        if self.checkpoint.payload.stream_id != position.stream_id
            || self.manifest.stream_id != position.stream_id
        {
            return Err(CheckpointQuorumError::StreamMismatch);
        }
        if self.checkpoint.payload.sequence != position.sequence
            || self.manifest.last_sequence != position.sequence
            || self.manifest.first_sequence != position.previous_sequence.saturating_add(1)
            || self.manifest.entry_count != position.sequence.saturating_sub(position.previous_sequence)
        {
            return Err(CheckpointQuorumError::SequenceMismatch);
        }
        if self.checkpoint.payload.previous_checkpoint_digest.as_deref() != position.previous_digest
            || self.manifest.previous_checkpoint_digest.as_deref() != position.previous_digest
        {
            return Err(CheckpointQuorumError::PreviousCheckpointMismatch);
        }
        if self.checkpoint.payload.audit_head_digest != self.manifest.audit_head_digest
            || self.manifest.issued_at < self.checkpoint.payload.issued_at
        {
            return Err(CheckpointQuorumError::Malformed);
        }
        Ok(())
    }

    pub fn checkpoint_digest(&self) -> Result<String, CheckpointQuorumError> {
        self.checkpoint.digest().map_err(|_| CheckpointQuorumError::Malformed)
    }

    pub fn manifest_digest(&self) -> Result<String, CheckpointQuorumError> {
        self.manifest.digest()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceipt {
    pub schema_id: String,
    pub witness_id: String,
    pub operator_id: String,
    pub key_id: String,
    pub checkpoint_digest: String,
    pub manifest_digest: String,
    pub sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
    pub verified_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct WitnessReceiptUnsigned<'a> {
    schema_id: &'a str,
    witness_id: &'a str,
    operator_id: &'a str,
    key_id: &'a str,
    checkpoint_digest: &'a str,
    manifest_digest: &'a str,
    sequence: u64,
    previous_checkpoint_digest: &'a Option<String>,
    verified_at: u64,
}

impl WitnessReceipt {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CheckpointQuorumError> {
        let unsigned = WitnessReceiptUnsigned {
            schema_id: &self.schema_id,
            witness_id: &self.witness_id,
            operator_id: &self.operator_id,
            key_id: &self.key_id,
            checkpoint_digest: &self.checkpoint_digest,
            manifest_digest: &self.manifest_digest,
            sequence: self.sequence,
            previous_checkpoint_digest: &self.previous_checkpoint_digest,
            verified_at: self.verified_at,
        };
        let canonical = serde_jcs::to_vec(&unsigned).map_err(|_| CheckpointQuorumError::Malformed)?;
        let mut bytes = WITNESS_DOMAIN.to_vec();
        bytes.extend_from_slice(&canonical);
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(CheckpointQuorumError::Malformed);
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImmutableRetentionMode {
    ComplianceWorm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionReceipt {
    pub schema_id: String,
    pub domain_id: String,
    pub operator_id: String,
    pub key_id: String,
    pub checkpoint_digest: String,
    pub manifest_digest: String,
    pub witness_receipts_digest: String,
    pub object_ref: String,
    pub retained_at: u64,
    pub retain_until: u64,
    pub mode: ImmutableRetentionMode,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct RetentionReceiptUnsigned<'a> {
    schema_id: &'a str,
    domain_id: &'a str,
    operator_id: &'a str,
    key_id: &'a str,
    checkpoint_digest: &'a str,
    manifest_digest: &'a str,
    witness_receipts_digest: &'a str,
    object_ref: &'a str,
    retained_at: u64,
    retain_until: u64,
    mode: ImmutableRetentionMode,
}

impl RetentionReceipt {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CheckpointQuorumError> {
        let unsigned = RetentionReceiptUnsigned {
            schema_id: &self.schema_id,
            domain_id: &self.domain_id,
            operator_id: &self.operator_id,
            key_id: &self.key_id,
            checkpoint_digest: &self.checkpoint_digest,
            manifest_digest: &self.manifest_digest,
            witness_receipts_digest: &self.witness_receipts_digest,
            object_ref: &self.object_ref,
            retained_at: self.retained_at,
            retain_until: self.retain_until,
            mode: self.mode,
        };
        let canonical = serde_jcs::to_vec(&unsigned).map_err(|_| CheckpointQuorumError::Malformed)?;
        let mut bytes = RETENTION_DOMAIN.to_vec();
        bytes.extend_from_slice(&canonical);
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(CheckpointQuorumError::Malformed);
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternallyAnchoredCheckpoint {
    pub package: CheckpointPackage,
    pub witness_receipts: Vec<WitnessReceipt>,
    pub retention_receipts: Vec<RetentionReceipt>,
}

pub trait CheckpointWitnessProvider: Send + Sync {
    fn attest(&self, package: &CheckpointPackage) -> Result<WitnessReceipt, CheckpointQuorumError>;
}

pub trait ImmutableRetentionProvider: Send + Sync {
    fn retain(
        &self,
        package: &CheckpointPackage,
        witness_receipts: &[WitnessReceipt],
    ) -> Result<RetentionReceipt, CheckpointQuorumError>;
}

/// Publish to all three configured witnesses, require a cryptographically
/// verified 2-of-3 quorum, then retain the package and receipts in both
/// independent immutable-retention domains.
pub fn publish_checkpoint_package(
    package: CheckpointPackage,
    witness_providers: &[&dyn CheckpointWitnessProvider],
    retention_providers: &[&dyn ImmutableRetentionProvider],
    policy: &CheckpointQuorumPolicy,
    position: &CheckpointChainPosition<'_>,
    now: u64,
) -> Result<ExternallyAnchoredCheckpoint, CheckpointQuorumError> {
    package.validate(position)?;
    verify_checkpoint_signer(&package.checkpoint, policy, now)?;
    if witness_providers.len() != 3 || retention_providers.len() != 2 {
        return Err(CheckpointQuorumError::InvalidPolicy);
    }
    let mut witness_receipts = Vec::new();
    for provider in witness_providers {
        if let Ok(receipt) = provider.attest(&package) {
            witness_receipts.push(receipt);
        }
    }
    verify_witness_quorum(&package, &witness_receipts, policy, now)?;
    let mut retention_receipts = Vec::new();
    for provider in retention_providers {
        retention_receipts.push(
            provider.retain(&package, &witness_receipts)
                .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?,
        );
    }
    let anchored = ExternallyAnchoredCheckpoint {
        package,
        witness_receipts,
        retention_receipts,
    };
    verify_externally_anchored_checkpoint(
        &anchored,
        policy,
        position,
        now,
    )?;
    Ok(anchored)
}

/// Offline verification. No database row, network lookup or provider response
/// is trusted; only the signed package and separately pinned trust policy count.
pub fn verify_externally_anchored_checkpoint(
    anchored: &ExternallyAnchoredCheckpoint,
    policy: &CheckpointQuorumPolicy,
    position: &CheckpointChainPosition<'_>,
    now: u64,
) -> Result<(), CheckpointQuorumError> {
    anchored.package.validate(position)?;
    verify_checkpoint_signer(&anchored.package.checkpoint, policy, now)?;
    verify_witness_quorum(&anchored.package, &anchored.witness_receipts, policy, now)?;
    verify_retention_quorum(
        &anchored.package,
        &anchored.witness_receipts,
        &anchored.retention_receipts,
        policy,
        now,
    )
}

fn verify_checkpoint_signer(
    checkpoint: &SignedCheckpoint,
    policy: &CheckpointQuorumPolicy,
    now: u64,
) -> Result<(), CheckpointQuorumError> {
    let signer = &policy.signer;
    if checkpoint.payload.signer_key_id != signer.key_id
        || checkpoint.payload.issued_at < signer.not_before
        || checkpoint.payload.issued_at >= signer.not_after
        || checkpoint.payload.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
    {
        return Err(CheckpointQuorumError::InvalidSigner);
    }
    let key = VerifyingKey::from_bytes(&signer.public_key)
        .map_err(|_| CheckpointQuorumError::InvalidSigner)?;
    let message = checkpoint.payload.signing_bytes()
        .map_err(|_| CheckpointQuorumError::Malformed)?;
    let signature = Signature::from_slice(&checkpoint.signature)
        .map_err(|_| CheckpointQuorumError::InvalidSignature)?;
    key.verify(&message, &signature)
        .map_err(|_| CheckpointQuorumError::InvalidSignature)
}

fn verify_witness_quorum(
    package: &CheckpointPackage,
    receipts: &[WitnessReceipt],
    policy: &CheckpointQuorumPolicy,
    now: u64,
) -> Result<(), CheckpointQuorumError> {
    if receipts.len() < 2 || receipts.len() > 3 {
        return Err(CheckpointQuorumError::InsufficientWitnessQuorum);
    }
    let checkpoint_digest = package.checkpoint_digest()?;
    let manifest_digest = package.manifest_digest()?;
    let mut witness_ids = HashSet::new();
    let mut operators = HashSet::new();
    for receipt in receipts {
        if receipt.schema_id != "iroka.g11.witness-receipt.v1"
            || receipt.checkpoint_digest != checkpoint_digest
            || receipt.manifest_digest != manifest_digest
            || receipt.sequence != package.checkpoint.payload.sequence
            || receipt.previous_checkpoint_digest != package.checkpoint.payload.previous_checkpoint_digest
            || receipt.verified_at < package.checkpoint.payload.issued_at
            || receipt.verified_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
            || !witness_ids.insert(receipt.witness_id.clone())
        {
            return Err(CheckpointQuorumError::InvalidWitnessReceipt);
        }
        let trust = policy.witnesses.get(&receipt.witness_id)
            .ok_or(CheckpointQuorumError::InvalidWitnessReceipt)?;
        if trust.operator_id != receipt.operator_id
            || trust.key_id != receipt.key_id
            || !operators.insert(trust.operator_id.clone())
            || receipt.verified_at < trust.not_before
            || receipt.verified_at >= trust.not_after
        {
            return Err(CheckpointQuorumError::InvalidWitnessReceipt);
        }
        let key = VerifyingKey::from_bytes(&trust.public_key)
            .map_err(|_| CheckpointQuorumError::InvalidWitnessReceipt)?;
        let message = receipt.signing_bytes()?;
        let signature = Signature::from_slice(&receipt.signature)
            .map_err(|_| CheckpointQuorumError::InvalidWitnessReceipt)?;
        key.verify(&message, &signature)
            .map_err(|_| CheckpointQuorumError::InvalidWitnessReceipt)?;
    }
    Ok(())
}

fn verify_retention_quorum(
    package: &CheckpointPackage,
    witness_receipts: &[WitnessReceipt],
    receipts: &[RetentionReceipt],
    policy: &CheckpointQuorumPolicy,
    now: u64,
) -> Result<(), CheckpointQuorumError> {
    if receipts.len() != 2 {
        return Err(CheckpointQuorumError::InsufficientRetentionDomains);
    }
    let checkpoint_digest = package.checkpoint_digest()?;
    let manifest_digest = package.manifest_digest()?;
    let witness_digest = witness_receipts_digest(witness_receipts)?;
    let minimum_until = now.saturating_add(policy.minimum_retention_secs);
    let mut domain_ids = HashSet::new();
    let mut operators = HashSet::new();
    for receipt in receipts {
        if receipt.schema_id != "iroka.g11.immutable-retention-receipt.v1"
            || receipt.checkpoint_digest != checkpoint_digest
            || receipt.manifest_digest != manifest_digest
            || receipt.witness_receipts_digest != witness_digest
            || receipt.object_ref.trim().is_empty()
            || receipt.object_ref.len() > 2_048
            || receipt.retained_at < package.checkpoint.payload.issued_at
            || receipt.retained_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
            || receipt.retain_until < minimum_until
            || receipt.mode != ImmutableRetentionMode::ComplianceWorm
            || !domain_ids.insert(receipt.domain_id.clone())
        {
            return Err(CheckpointQuorumError::InvalidRetentionReceipt);
        }
        let trust = policy.retention_domains.get(&receipt.domain_id)
            .ok_or(CheckpointQuorumError::InvalidRetentionReceipt)?;
        if trust.operator_id != receipt.operator_id
            || trust.key_id != receipt.key_id
            || !operators.insert(trust.operator_id.clone())
            || receipt.retained_at < trust.not_before
            || receipt.retained_at >= trust.not_after
        {
            return Err(CheckpointQuorumError::InvalidRetentionReceipt);
        }
        let key = VerifyingKey::from_bytes(&trust.public_key)
            .map_err(|_| CheckpointQuorumError::InvalidRetentionReceipt)?;
        let message = receipt.signing_bytes()?;
        let signature = Signature::from_slice(&receipt.signature)
            .map_err(|_| CheckpointQuorumError::InvalidRetentionReceipt)?;
        key.verify(&message, &signature)
            .map_err(|_| CheckpointQuorumError::InvalidRetentionReceipt)?;
    }
    Ok(())
}

fn witness_receipts_digest(receipts: &[WitnessReceipt]) -> Result<String, CheckpointQuorumError> {
    let mut sorted = receipts.to_vec();
    sorted.sort_by(|a, b| a.witness_id.cmp(&b.witness_id));
    let canonical = serde_jcs::to_vec(&sorted).map_err(|_| CheckpointQuorumError::Malformed)?;
    let mut domain_separated = b"IROKA:G11:WITNESS-RECEIPT-SET:V1\0".to_vec();
    domain_separated.extend_from_slice(&canonical);
    Ok(sha256_hex(&domain_separated))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckpointPayload;
    use ed25519_dalek::{Signer, SigningKey};

    struct LocalWitness {
        trust: WitnessTrust,
        signer: SigningKey,
    }
    impl CheckpointWitnessProvider for LocalWitness {
        fn attest(&self, package: &CheckpointPackage) -> Result<WitnessReceipt, CheckpointQuorumError> {
            let mut receipt = WitnessReceipt {
                schema_id: "iroka.g11.witness-receipt.v1".into(),
                witness_id: self.trust.witness_id.clone(),
                operator_id: self.trust.operator_id.clone(),
                key_id: self.trust.key_id.clone(),
                checkpoint_digest: package.checkpoint_digest()?,
                manifest_digest: package.manifest_digest()?,
                sequence: package.checkpoint.payload.sequence,
                previous_checkpoint_digest: package.checkpoint.payload.previous_checkpoint_digest.clone(),
                verified_at: 1_801,
                signature: Vec::new(),
            };
            receipt.signature = self.signer.sign(&receipt.signing_bytes()?).to_bytes().to_vec();
            Ok(receipt)
        }
    }

    struct FailingWitness;
    impl CheckpointWitnessProvider for FailingWitness {
        fn attest(&self, _: &CheckpointPackage) -> Result<WitnessReceipt, CheckpointQuorumError> {
            Err(CheckpointQuorumError::ProviderUnavailable)
        }
    }

    struct LocalRetention {
        trust: RetentionDomainTrust,
        signer: SigningKey,
    }
    impl ImmutableRetentionProvider for LocalRetention {
        fn retain(
            &self,
            package: &CheckpointPackage,
            witness_receipts: &[WitnessReceipt],
        ) -> Result<RetentionReceipt, CheckpointQuorumError> {
            let mut receipt = RetentionReceipt {
                schema_id: "iroka.g11.immutable-retention-receipt.v1".into(),
                domain_id: self.trust.domain_id.clone(),
                operator_id: self.trust.operator_id.clone(),
                key_id: self.trust.key_id.clone(),
                checkpoint_digest: package.checkpoint_digest()?,
                manifest_digest: package.manifest_digest()?,
                witness_receipts_digest: witness_receipts_digest(witness_receipts)?,
                object_ref: format!("immutable://{}/checkpoint/7", self.trust.domain_id),
                retained_at: 1_802,
                retain_until: 10_000,
                mode: ImmutableRetentionMode::ComplianceWorm,
                signature: Vec::new(),
            };
            receipt.signature = self.signer.sign(&receipt.signing_bytes()?).to_bytes().to_vec();
            Ok(receipt)
        }
    }

    fn fixture() -> (
        CheckpointPackage,
        CheckpointQuorumPolicy,
        Vec<LocalWitness>,
        Vec<LocalRetention>,
        SigningKey,
    ) {
        let checkpoint_signer = SigningKey::from_bytes(&[7u8; 32]);
        let signer_trust = CheckpointSignerTrust {
            operator_id: "operator:signer".into(),
            key_id: "checkpoint-key".into(),
            public_key: checkpoint_signer.verifying_key().to_bytes(),
            not_before: 1_000,
            not_after: 20_000,
        };
        let mut witness_providers = Vec::new();
        let mut witness_trusts = Vec::new();
        for i in 0..3u8 {
            let signer = SigningKey::from_bytes(&[10 + i; 32]);
            let trust = WitnessTrust {
                witness_id: format!("witness-{i}"),
                operator_id: format!("operator:witness-{i}"),
                key_id: format!("witness-key-{i}"),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 20_000,
            };
            witness_trusts.push(trust.clone());
            witness_providers.push(LocalWitness { trust, signer });
        }
        let mut retention_providers = Vec::new();
        let mut retention_trusts = Vec::new();
        for i in 0..2u8 {
            let signer = SigningKey::from_bytes(&[20 + i; 32]);
            let trust = RetentionDomainTrust {
                domain_id: format!("retention-{i}"),
                operator_id: format!("operator:retention-{i}"),
                key_id: format!("retention-key-{i}"),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 20_000,
            };
            retention_trusts.push(trust.clone());
            retention_providers.push(LocalRetention { trust, signer });
        }
        let policy = CheckpointQuorumPolicy::new(
            signer_trust,
            witness_trusts,
            retention_trusts,
            5_000,
        ).unwrap();
        let payload = CheckpointPayload {
            schema_id: crate::G11_CHECKPOINT_SCHEMA_ID.into(),
            stream_id: "g11:memory".into(),
            sequence: 7,
            previous_checkpoint_digest: Some("a".repeat(64)),
            audit_head_digest: "b".repeat(64),
            issued_at: 1_800,
            signer_key_id: "checkpoint-key".into(),
        };
        let checkpoint = SignedCheckpoint {
            signature: checkpoint_signer.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec(),
            payload,
        };
        let manifest = CheckpointSegmentManifest {
            schema_id: "iroka.g11.checkpoint-segment.v1".into(),
            stream_id: "g11:memory".into(),
            first_sequence: 6,
            last_sequence: 7,
            previous_checkpoint_digest: Some("a".repeat(64)),
            audit_head_digest: "b".repeat(64),
            entries_merkle_root: "c".repeat(64),
            entry_count: 2,
            issued_at: 1_800,
        };
        (
            CheckpointPackage { checkpoint, manifest },
            policy,
            witness_providers,
            retention_providers,
            checkpoint_signer,
        )
    }

    #[test]
    fn enforces_two_of_three_witnesses_and_both_immutable_domains() {
        let (package, policy, witnesses, retention, _) = fixture();
        let previous_digest = "a".repeat(64);
        let position = CheckpointChainPosition {
            stream_id: "g11:memory",
            sequence: 7,
            previous_digest: Some(&previous_digest),
            previous_sequence: 5,
        };
        let failing = FailingWitness;
        let witness_refs: Vec<&dyn CheckpointWitnessProvider> = vec![
            &witnesses[0],
            &witnesses[1],
            &failing,
        ];
        let retention_refs: Vec<&dyn ImmutableRetentionProvider> =
            retention.iter().map(|p| p as &dyn ImmutableRetentionProvider).collect();
        let anchored = publish_checkpoint_package(
            package,
            &witness_refs,
            &retention_refs,
            &policy,
            &position,
            1_803,
        );
        let anchored = anchored.unwrap();
        verify_externally_anchored_checkpoint(
            &anchored,
            &policy,
            &position,
            1_803,
        ).unwrap();
    }

    #[test]
    fn policy_rejects_shared_operator_domains() {
        let (package, policy, _, _, _) = fixture();
        let _ = (package, policy);
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let witness = SigningKey::from_bytes(&[8u8; 32]);
        let retention = SigningKey::from_bytes(&[9u8; 32]);
        let signer_trust = CheckpointSignerTrust {
            operator_id: "same".into(), key_id: "s".into(),
            public_key: signer.verifying_key().to_bytes(), not_before: 1, not_after: 10,
        };
        let witnesses = (0..3).map(|i| WitnessTrust {
            witness_id: format!("w{i}"), operator_id: format!("wop{i}"),
            key_id: format!("wk{i}"), public_key: witness.verifying_key().to_bytes(),
            not_before: 1, not_after: 10,
        }).collect();
        let retentions = (0..2).map(|i| RetentionDomainTrust {
            domain_id: format!("r{i}"), operator_id: "same".into(),
            key_id: format!("rk{i}"), public_key: retention.verifying_key().to_bytes(),
            not_before: 1, not_after: 10,
        }).collect();
        assert!(matches!(
            CheckpointQuorumPolicy::new(signer_trust, witnesses, retentions, 5),
            Err(CheckpointQuorumError::InvalidPolicy)
        ));
    }
}
