//! A3 G01 canonical identity-root descriptor evaluator.

use std::collections::BTreeMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{CredentialError, Ed25519CredentialVerifier, RevocationChecker};

pub const IDENTITY_ROOT_ALGORITHM_POLICY_VERSION: &str = "IROKA-G01-EDDSA-ONLY-1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootInput {
    pub root_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub key_fingerprint: String,
    pub public_key_base64url: String,
    pub algorithm: String,
    pub algorithm_policy_version: String,
    pub activation_epoch: u64,
    pub status: IdentityRootStatus,
    pub provenance: BTreeMap<String, serde_json::Value>,
    pub version_bound_evidence: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRootStatus { Active, Suspended, Revoked }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRootPolicy { current_epoch: u64 }

impl IdentityRootPolicy {
    pub fn new(current_epoch: u64) -> Result<Self, IdentityRootError> {
        Ok(Self { current_epoch })
    }
    pub fn version(&self) -> &'static str { IDENTITY_ROOT_ALGORITHM_POLICY_VERSION }
    pub fn current_epoch(&self) -> u64 { self.current_epoch }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTrustDecision { Trusted, Untrusted, Revoked }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootDecisionEvidence {
    pub provenance: BTreeMap<String, serde_json::Value>,
    pub issuer_trust_verified: bool,
    pub key_fingerprint_match: bool,
    pub algorithm_policy_version: String,
    pub key_revocation_checked: bool,
    pub decision_reason: String,
    pub root_status: IdentityRootStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootOutput {
    pub root_id: String,
    pub verified: bool,
    pub trust_decision: IdentityTrustDecision,
    pub evaluated_epoch: u64,
    pub evidence: IdentityRootDecisionEvidence,
    pub version_bound_evidence: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRootError { InvalidPolicy }

/// Canonical root_id is issuer_id + "::" + key_id. Only EdDSA/Ed25519 is
/// accepted. The verifier must have been constructed from a signed trust bundle.
pub fn evaluate_identity_root<R: RevocationChecker>(
    input: &IdentityRootInput,
    policy: &IdentityRootPolicy,
    verifier: &Ed25519CredentialVerifier<R>,
    now_unix_secs: u64,
) -> IdentityRootOutput {
    let mut issuer_trust_verified = false;
    let mut fingerprint_match = false;
    let mut revocation_checked = false;
    let mut reason = "untrusted".to_owned();
    let mut decision = IdentityTrustDecision::Untrusted;
    let canonical_id = format!("{}::{}", input.issuer_id, input.key_id);

    if input.root_id.trim().is_empty() || input.issuer_id.trim().is_empty()
        || input.key_id.trim().is_empty() || input.root_id != canonical_id
        || input.provenance.is_empty() || input.version_bound_evidence.is_empty() {
        reason = "invalid_or_noncanonical_identity_descriptor".into();
    } else if input.algorithm != "EdDSA" {
        reason = "unsupported_algorithm".into();
    } else if input.algorithm_policy_version != policy.version() {
        reason = "algorithm_policy_version_mismatch".into();
    } else if input.activation_epoch > policy.current_epoch {
        reason = "root_not_yet_active".into();
    } else if input.status == IdentityRootStatus::Revoked {
        decision = IdentityTrustDecision::Revoked;
        reason = "root_revoked".into();
    } else if input.status == IdentityRootStatus::Suspended {
        reason = "root_suspended".into();
    } else {
        match URL_SAFE_NO_PAD.decode(&input.public_key_base64url) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&bytes);
                if VerifyingKey::from_bytes(&public_key).is_err() {
                    reason = "invalid_ed25519_public_key".into();
                } else {
                    fingerprint_match = hex_sha256(&public_key) == input.key_fingerprint;
                    if !fingerprint_match {
                        reason = "key_fingerprint_mismatch".into();
                    } else {
                        match verifier.verify_root_descriptor(&input.issuer_id, &input.key_id, &public_key, now_unix_secs) {
                            Ok(()) => {
                                issuer_trust_verified = true;
                                revocation_checked = true;
                                decision = IdentityTrustDecision::Trusted;
                                reason = "trusted_root_verified".into();
                            }
                            Err(CredentialError::RevokedKey) => {
                                revocation_checked = true;
                                decision = IdentityTrustDecision::Revoked;
                                reason = "key_revoked".into();
                            }
                            Err(CredentialError::RevocationUnavailable) => reason = "revocation_state_unavailable".into(),
                            Err(CredentialError::UntrustedIssuer) => reason = "issuer_untrusted".into(),
                            Err(CredentialError::UnknownKey) => reason = "key_not_in_signed_trust_snapshot".into(),
                            Err(CredentialError::KeyOutsideValidity) => reason = "key_outside_validity_window".into(),
                            Err(_) => reason = "trusted_key_descriptor_mismatch".into(),
                        }
                    }
                }
            }
            _ => reason = "invalid_public_key_encoding".into(),
        }
    }

    IdentityRootOutput {
        root_id: input.root_id.clone(),
        verified: decision == IdentityTrustDecision::Trusted,
        trust_decision: decision,
        evaluated_epoch: policy.current_epoch,
        evidence: IdentityRootDecisionEvidence {
            provenance: input.provenance.clone(),
            issuer_trust_verified,
            key_fingerprint_match: fingerprint_match,
            algorithm_policy_version: policy.version().to_owned(),
            key_revocation_checked: revocation_checked,
            decision_reason: reason,
            root_status: input.status,
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NoRevocations, TrustStore, TrustedKey};
    use ed25519_dalek::SigningKey;

    fn fixture() -> (Ed25519CredentialVerifier<NoRevocations>, IdentityRootInput, IdentityRootPolicy) {
        let signer = SigningKey::from_bytes(&[41u8; 32]);
        let public_key = signer.verifying_key().to_bytes();
        let issuer = "issuer:iroka-test";
        let key_id = "root-key-1";
        let trust = TrustStore::new([issuer], vec![TrustedKey {
            issuer: issuer.into(), key_id: key_id.into(), public_key,
            not_before: 1_000, not_after: 10_000,
        }]).expect("valid trust");
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        let input = IdentityRootInput {
            root_id: format!("{issuer}::{key_id}"), issuer_id: issuer.into(), key_id: key_id.into(),
            key_fingerprint: hex_sha256(&public_key),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            algorithm: "EdDSA".into(), algorithm_policy_version: IDENTITY_ROOT_ALGORITHM_POLICY_VERSION.into(),
            activation_epoch: 2, status: IdentityRootStatus::Active,
            provenance: BTreeMap::from([("source".into(), serde_json::json!("signed-root-bundle"))]),
            version_bound_evidence: BTreeMap::from([("genome_digest".into(), serde_json::json!("a".repeat(64)))]),
        };
        (verifier, input, IdentityRootPolicy::new(3).unwrap())
    }

    #[test]
    fn accepts_canonical_active_root_from_signed_snapshot() {
        let (verifier, input, policy) = fixture();
        let out = evaluate_identity_root(&input, &policy, &verifier, 1_200);
        assert!(out.verified);
        assert_eq!(out.trust_decision, IdentityTrustDecision::Trusted);
        assert!(out.evidence.issuer_trust_verified && out.evidence.key_fingerprint_match && out.evidence.key_revocation_checked);
    }

    #[test]
    fn rejects_fingerprint_and_algorithm_substitution() {
        let (verifier, mut input, policy) = fixture();
        input.key_fingerprint = "0".repeat(64);
        let out = evaluate_identity_root(&input, &policy, &verifier, 1_200);
        assert!(!out.verified);
        assert_eq!(out.evidence.decision_reason, "key_fingerprint_mismatch");
        input.key_fingerprint = hex_sha256(&URL_SAFE_NO_PAD.decode(&input.public_key_base64url).unwrap());
        input.algorithm = "RSA-PSS".into();
        let out = evaluate_identity_root(&input, &policy, &verifier, 1_200);
        assert!(!out.verified);
        assert_eq!(out.evidence.decision_reason, "unsupported_algorithm");
        input.algorithm = "EdDSA".into();
        input.algorithm_policy_version = "unapproved-policy".into();
        let out = evaluate_identity_root(&input, &policy, &verifier, 1_200);
        assert!(!out.verified);
        assert_eq!(out.evidence.decision_reason, "algorithm_policy_version_mismatch");
    }

    #[test]
    fn rejects_revoked_suspended_future_and_noncanonical_roots() {
        let (verifier, mut input, policy) = fixture();
        input.status = IdentityRootStatus::Revoked;
        let out = evaluate_identity_root(&input, &policy, &verifier, 1_200);
        assert!(!out.verified);
        assert_eq!(out.trust_decision, IdentityTrustDecision::Revoked);
        input.status = IdentityRootStatus::Suspended;
        assert!(!evaluate_identity_root(&input, &policy, &verifier, 1_200).verified);
        input.status = IdentityRootStatus::Active;
        input.activation_epoch = 4;
        assert!(!evaluate_identity_root(&input, &policy, &verifier, 1_200).verified);
        input.activation_epoch = 2;
        input.root_id = "alias".into();
        assert!(!evaluate_identity_root(&input, &policy, &verifier, 1_200).verified);
    }
}
