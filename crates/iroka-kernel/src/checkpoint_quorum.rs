//! Frozen IGACMS A4-03 witness quorum and dual immutable-retention verifier.
//! This module verifies portable, signed evidence; it does not appoint operators,
//! provision production keys, or claim that a provider is independent without
//! an externally approved trust roster and administrative-domain attestations.
use std::collections::{HashMap, HashSet};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const WITNESS_DOMAIN: &[u8] = b"IGACMS-AUDIT-WITNESS-RECEIPT-v1\0";
const RETENTION_DOMAIN: &[u8] = b"IGACMS-AUDIT-RETENTION-RECEIPT-v1\0";
pub const REQUIRED_WITNESS_QUORUM: usize = 2;
pub const CONFIGURED_WITNESS_COUNT: usize = 3;
pub const REQUIRED_RETENTION_DOMAINS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumError {
    Malformed,
    InvalidRoster,
    UnknownWitness,
    UnknownRetentionDomain,
    InvalidSignature,
    EvidenceMismatch,
    DuplicateIdentity,
    InsufficientWitnessQuorum,
    InsufficientRetentionDomains,
    RetentionNotImmutable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceiptPayload {
    pub schema: String,
    pub checkpoint_digest: String,
    pub segment_manifest_digest: String,
    pub sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
    pub witness_id: String,
    pub witness_key_id: String,
    pub witness_policy_version: String,
    pub verifier_build_id: String,
    pub independently_verified_segment: bool,
    pub witness_retained_evidence: bool,
    pub issued_at: u64,
}

impl WitnessReceiptPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, QuorumError> {
        self.validate()?;
        let mut bytes = WITNESS_DOMAIN.to_vec();
        bytes.extend_from_slice(&serde_jcs::to_vec(self).map_err(|_| QuorumError::Malformed)?);
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), QuorumError> {
        if self.schema != "igacms.audit-witness-receipt.v1"
            || !digest(&self.checkpoint_digest)
            || !digest(&self.segment_manifest_digest)
            || self.sequence == 0
            || self.previous_checkpoint_digest.as_deref().is_some_and(|d| !digest(d))
            || self.witness_id.trim().is_empty()
            || self.witness_key_id.trim().is_empty()
            || self.witness_policy_version.trim().is_empty()
            || self.verifier_build_id.trim().is_empty()
            || !self.independently_verified_segment
            || !self.witness_retained_evidence
        { return Err(QuorumError::Malformed); }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessReceipt {
    pub payload: WitnessReceiptPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionReceiptPayload {
    pub schema: String,
    pub checkpoint_digest: String,
    pub segment_manifest_digest: String,
    pub witness_receipts_digest: String,
    pub package_digest: String,
    pub retention_domain_id: String,
    pub attestor_key_id: String,
    pub object_id: String,
    pub object_version_id: String,
    pub retain_until: u64,
    pub immutable_lock_enabled: bool,
    pub readback_verified: bool,
    pub issued_at: u64,
}

impl RetentionReceiptPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, QuorumError> {
        self.validate()?;
        let mut bytes = RETENTION_DOMAIN.to_vec();
        bytes.extend_from_slice(&serde_jcs::to_vec(self).map_err(|_| QuorumError::Malformed)?);
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), QuorumError> {
        if self.schema != "igacms.audit-retention-receipt.v1"
            || !digest(&self.checkpoint_digest)
            || !digest(&self.segment_manifest_digest)
            || !digest(&self.witness_receipts_digest)
            || !digest(&self.package_digest)
            || self.retention_domain_id.trim().is_empty()
            || self.attestor_key_id.trim().is_empty()
            || self.object_id.trim().is_empty()
            || self.object_version_id.trim().is_empty()
            || self.retain_until <= self.issued_at
        { return Err(QuorumError::Malformed); }
        if !self.immutable_lock_enabled || !self.readback_verified {
            return Err(QuorumError::RetentionNotImmutable);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRetentionReceipt {
    pub payload: RetentionReceiptPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WitnessTrust {
    pub witness_id: String,
    pub administrative_domain: String,
    pub key_id: String,
    pub key: VerifyingKey,
}

#[derive(Debug, Clone)]
pub struct RetentionTrust {
    pub domain_id: String,
    pub administrative_domain: String,
    pub attestor_key_id: String,
    pub key: VerifyingKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpointQuorum {
    pub checkpoint_digest: String,
    pub witness_ids: Vec<String>,
    pub retention_domains: Vec<String>,
    pub package_digest: String,
}

/// Immutable checkpoint tuple all independent receipts must bind to.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointExpectation<'a> {
    pub checkpoint_digest: &'a str,
    pub segment_manifest_digest: &'a str,
    pub sequence: u64,
    pub previous_checkpoint_digest: Option<&'a str>,
    pub package_digest: &'a str,
}

/// Verify exactly the frozen 2-of-3 witness and two-domain retention rule.
/// The trust roster must be provisioned from an Owner-approved, independently
/// governed source. Distinct labels alone are not proof of real-world independence.
pub fn verify_checkpoint_quorum(
    expectation: &CheckpointExpectation<'_>,
    witness_roster: &[WitnessTrust],
    witness_receipts: &[SignedWitnessReceipt],
    retention_roster: &[RetentionTrust],
    retention_receipts: &[SignedRetentionReceipt],
    now: u64,
) -> Result<VerifiedCheckpointQuorum, QuorumError> {
    if !digest(expectation.checkpoint_digest) || !digest(expectation.segment_manifest_digest)
        || !digest(expectation.package_digest) || expectation.sequence == 0
        || expectation.previous_checkpoint_digest.is_some_and(|d| !digest(d)) {
        return Err(QuorumError::Malformed);
    }
    if witness_roster.len() != CONFIGURED_WITNESS_COUNT
        || retention_roster.len() != REQUIRED_RETENTION_DOMAINS {
        return Err(QuorumError::InvalidRoster);
    }
    let mut witness_keys = HashSet::new();
    let mut witness_domains = HashSet::new();
    let mut witness_ids = HashSet::new();
    let mut witness_by_id = HashMap::new();
    for item in witness_roster {
        if item.witness_id.trim().is_empty() || item.key_id.trim().is_empty()
            || item.administrative_domain.trim().is_empty()
            || !witness_ids.insert(item.witness_id.clone())
            || !witness_keys.insert(item.key_id.clone())
            || !witness_domains.insert(item.administrative_domain.clone()) {
            return Err(QuorumError::InvalidRoster);
        }
        witness_by_id.insert(item.witness_id.as_str(), item);
    }
    let mut retention_ids = HashSet::new();
    let mut retention_domains = HashSet::new();
    let mut retention_keys = HashSet::new();
    let mut retention_by_id = HashMap::new();
    for item in retention_roster {
        if item.domain_id.trim().is_empty() || item.attestor_key_id.trim().is_empty()
            || item.administrative_domain.trim().is_empty()
            || !retention_ids.insert(item.domain_id.clone())
            || !retention_keys.insert(item.attestor_key_id.clone())
            || !retention_domains.insert(item.administrative_domain.clone()) {
            return Err(QuorumError::InvalidRoster);
        }
        retention_by_id.insert(item.domain_id.as_str(), item);
    }
    if witness_domains.iter().any(|domain| retention_domains.contains(domain)) {
        return Err(QuorumError::InvalidRoster);
    }

    let mut accepted_witnesses = HashSet::new();
    for receipt in witness_receipts {
        let p = &receipt.payload;
        p.validate()?;
        let trusted = witness_by_id.get(p.witness_id.as_str()).ok_or(QuorumError::UnknownWitness)?;
        if p.witness_key_id != trusted.key_id || p.expectation.checkpoint_digest != expectation.checkpoint_digest
            || p.expectation.segment_manifest_digest != expectation.segment_manifest_digest || p.expectation.sequence != expectation.sequence
            || p.expectation.previous_checkpoint_digest.as_deref() != expectation.previous_checkpoint_digest
            || p.issued_at > now {
            return Err(QuorumError::EvidenceMismatch);
        }
        let sig = Signature::from_slice(&receipt.signature).map_err(|_| QuorumError::InvalidSignature)?;
        trusted.key.verify(&p.signing_bytes()?, &sig).map_err(|_| QuorumError::InvalidSignature)?;
        if !accepted_witnesses.insert(p.witness_id.clone()) {
            return Err(QuorumError::DuplicateIdentity);
        }
    }
    if accepted_witnesses.len() < REQUIRED_WITNESS_QUORUM {
        return Err(QuorumError::InsufficientWitnessQuorum);
    }

    let receipts_digest = receipt_bundle_digest(witness_receipts)?;
    let mut accepted_retention = HashSet::new();
    for receipt in retention_receipts {
        let p = &receipt.payload;
        p.validate()?;
        let trusted = retention_by_id.get(p.retention_domain_id.as_str())
            .ok_or(QuorumError::UnknownRetentionDomain)?;
        if p.attestor_key_id != trusted.attestor_key_id
            || p.expectation.checkpoint_digest != expectation.checkpoint_digest
            || p.expectation.segment_manifest_digest != expectation.segment_manifest_digest
            || p.witness_receipts_digest != receipts_digest
            || p.expectation.package_digest != expectation.package_digest || p.issued_at > now {
            return Err(QuorumError::EvidenceMismatch);
        }
        let sig = Signature::from_slice(&receipt.signature).map_err(|_| QuorumError::InvalidSignature)?;
        trusted.key.verify(&p.signing_bytes()?, &sig).map_err(|_| QuorumError::InvalidSignature)?;
        if !accepted_retention.insert(p.retention_domain_id.clone()) {
            return Err(QuorumError::DuplicateIdentity);
        }
    }
    if accepted_retention.len() != REQUIRED_RETENTION_DOMAINS {
        return Err(QuorumError::InsufficientRetentionDomains);
    }
    let mut witness_ids: Vec<_> = accepted_witnesses.into_iter().collect();
    witness_ids.sort();
    let mut retention_domains: Vec<_> = accepted_retention.into_iter().collect();
    retention_domains.sort();
    Ok(VerifiedCheckpointQuorum {
        expectation.checkpoint_digest: expectation.checkpoint_digest.into(),
        witness_ids,
        retention_domains,
        expectation.package_digest: expectation.package_digest.into(),
    })
}

/// Stable digest for the exact set of signed witness receipts included in a bundle.
pub fn receipt_bundle_digest(receipts: &[SignedWitnessReceipt]) -> Result<String, QuorumError> {
    let mut normalized = receipts.to_vec();
    normalized.sort_by(|a,b| a.payload.witness_id.cmp(&b.payload.witness_id));
    let bytes = serde_jcs::to_vec(&normalized).map_err(|_| QuorumError::Malformed)?;
    Ok(hex(&sha256(&bytes)))
}

fn digest(s: &str) -> bool { s.len()==64 && s.bytes().all(|b| b.is_ascii_hexdigit()) }
fn sha256(b: &[u8]) -> [u8;32] {
    use sha2::{Digest,Sha256};
    Sha256::digest(b).into()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_witness(key: &SigningKey, id: &str, key_id: &str) -> SignedWitnessReceipt {
        let payload = WitnessReceiptPayload {
            schema: "igacms.audit-witness-receipt.v1".into(),
            checkpoint_digest: "a".repeat(64),
            segment_manifest_digest: "b".repeat(64),
            sequence: 7,
            previous_checkpoint_digest: Some("c".repeat(64)),
            witness_id: id.into(),
            witness_key_id: key_id.into(),
            witness_policy_version: "witness-policy-v1".into(),
            verifier_build_id: format!("independent-verifier-{id}"),
            independently_verified_segment: true,
            witness_retained_evidence: true,
            issued_at: 100,
        };
        let signature = key.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
        SignedWitnessReceipt { payload, signature }
    }

    fn sign_retention(
        key: &SigningKey, domain: &str, key_id: &str, receipts_digest: &str,
    ) -> SignedRetentionReceipt {
        let payload = RetentionReceiptPayload {
            schema: "igacms.audit-retention-receipt.v1".into(),
            checkpoint_digest: "a".repeat(64),
            segment_manifest_digest: "b".repeat(64),
            witness_receipts_digest: receipts_digest.into(),
            package_digest: "d".repeat(64),
            retention_domain_id: domain.into(),
            attestor_key_id: key_id.into(),
            object_id: format!("object-{domain}"),
            object_version_id: format!("version-{domain}"),
            retain_until: 10_000,
            immutable_lock_enabled: true,
            readback_verified: true,
            issued_at: 110,
        };
        let signature = key.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
        SignedRetentionReceipt { payload, signature }
    }

    #[test]
    fn frozen_two_of_three_and_both_retention_domains_verify() {
        let wk: Vec<_> = (1..=3).map(|n| SigningKey::from_bytes(&[n; 32])).collect();
        let roster: Vec<_> = wk.iter().enumerate().map(|(i,k)| WitnessTrust {
            witness_id: format!("w{}", i+1),
            administrative_domain: format!("operator-{}", i+1),
            key_id: format!("witness-key-{}", i+1),
            key: k.verifying_key(),
        }).collect();
        let witness_receipts = vec![
            sign_witness(&wk[0], "w1", "witness-key-1"),
            sign_witness(&wk[2], "w3", "witness-key-3"),
        ];
        let receipts_digest = receipt_bundle_digest(&witness_receipts).unwrap();
        let rk1 = SigningKey::from_bytes(&[11; 32]);
        let rk2 = SigningKey::from_bytes(&[12; 32]);
        let retention_roster = vec![
            RetentionTrust { domain_id: "r1".into(), administrative_domain: "storage-operator-1".into(),
                attestor_key_id: "retention-key-1".into(), key: rk1.verifying_key() },
            RetentionTrust { domain_id: "r2".into(), administrative_domain: "storage-operator-2".into(),
                attestor_key_id: "retention-key-2".into(), key: rk2.verifying_key() },
        ];
        let retention_receipts = vec![
            sign_retention(&rk1, "r1", "retention-key-1", &receipts_digest),
            sign_retention(&rk2, "r2", "retention-key-2", &receipts_digest),
        ];
        let verified = verify_checkpoint_quorum(
            &CheckpointExpectation {
                checkpoint_digest: &"a".repeat(64),
                segment_manifest_digest: &"b".repeat(64),
                sequence: 7,
                previous_checkpoint_digest: Some(&"c".repeat(64)),
                package_digest: &"d".repeat(64),
            },
            &roster, &witness_receipts, &retention_roster, &retention_receipts, 120,
        ).unwrap();
        assert_eq!(verified.witness_ids, vec!["w1", "w3"]);
        assert_eq!(verified.retention_domains, vec!["r1", "r2"]);
    }

    #[test]
    fn quorum_rejects_two_receipts_from_same_witness_and_unlocked_retention() {
        let wk1 = SigningKey::from_bytes(&[21; 32]);
        let wk2 = SigningKey::from_bytes(&[22; 32]);
        let wk3 = SigningKey::from_bytes(&[23; 32]);
        let roster = vec![
            WitnessTrust { witness_id:"w1".into(), administrative_domain:"o1".into(), key_id:"k1".into(), key:wk1.verifying_key() },
            WitnessTrust { witness_id:"w2".into(), administrative_domain:"o2".into(), key_id:"k2".into(), key:wk2.verifying_key() },
            WitnessTrust { witness_id:"w3".into(), administrative_domain:"o3".into(), key_id:"k3".into(), key:wk3.verifying_key() },
        ];
        let duplicate = sign_witness(&wk1, "w1", "k1");
        let duplicate2 = duplicate.clone();
        let receipts = vec![duplicate, duplicate2];
        let rk1 = SigningKey::from_bytes(&[31; 32]);
        let rk2 = SigningKey::from_bytes(&[32; 32]);
        let rr = vec![
            RetentionTrust { domain_id:"r1".into(), administrative_domain:"s1".into(), attestor_key_id:"rk1".into(), key:rk1.verifying_key() },
            RetentionTrust { domain_id:"r2".into(), administrative_domain:"s2".into(), attestor_key_id:"rk2".into(), key:rk2.verifying_key() },
        ];
        let empty = Vec::new();
        assert_eq!(
            verify_checkpoint_quorum(&CheckpointExpectation {
                checkpoint_digest: &"a".repeat(64),
                segment_manifest_digest: &"b".repeat(64),
                sequence: 7,
                previous_checkpoint_digest: Some(&"c".repeat(64)),
                package_digest: &"d".repeat(64),
            },
                &roster, &receipts, &rr, &empty, 120),
            Err(QuorumError::DuplicateIdentity)
        );
        let mut unlocked = sign_retention(&rk1, "r1", "rk1", &"e".repeat(64));
        unlocked.payload.immutable_lock_enabled = false;
        assert_eq!(unlocked.payload.signing_bytes(), Err(QuorumError::RetentionNotImmutable));
        let _ = wk2; let _ = wk3;
    }
}
