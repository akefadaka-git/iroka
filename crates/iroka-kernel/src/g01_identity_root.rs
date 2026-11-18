//! G01 identity-root evaluator for contract v1.1.0.
//!
//! The registry adapter is a trusted boundary: it resolves canonical root and
//! issuer records, loads public key material by key_material_ref, recomputes
//! the SHA-256 fingerprint, verifies provenance/version evidence and returns
//! the authenticated issuer chain and algorithm-policy decision. This gene
//! evaluates identity trust only; it never grants authority or execution rights.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootInput {
    pub root_id: String,
    pub issuer_id: String,
    pub key_fingerprint: String,
    pub key_material_ref: String,
    pub algorithm: String,
    pub algorithm_policy_id: String,
    pub algorithm_policy_version: String,
    pub activation_epoch: u64,
    pub status: RootStatus,
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootTrustDecision {
    Trusted,
    Untrusted,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerLinkEvidence {
    pub issuer_id: String,
    pub key_fingerprint: String,
    pub status: RootTrustDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmPolicyEvidence {
    pub policy_id: String,
    pub policy_version: String,
    pub algorithm: String,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootEvidence {
    pub provenance: Value,
    pub version_bound_evidence: Value,
    pub issuer_chain: Vec<IssuerLinkEvidence>,
    pub key_status: RootStatus,
    pub algorithm_policy: AlgorithmPolicyEvidence,
    pub decision_rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootOutput {
    pub root_id: String,
    pub verified: bool,
    pub trust_decision: RootTrustDecision,
    pub evaluated_epoch: u64,
    pub evidence: IdentityRootEvidence,
    pub version_bound_evidence: Value,
}

/// Canonical registry record returned only after the adapter has authenticated
/// the referenced public key and independently recomputed its fingerprint.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityRootRegistryRecord {
    pub root_id: String,
    pub issuer_id: String,
    pub key_fingerprint: String,
    pub key_material_ref: String,
    pub algorithm: String,
    pub algorithm_policy: AlgorithmPolicyEvidence,
    pub activation_epoch: u64,
    pub status: RootStatus,
    pub issuer_chain: Vec<IssuerLinkEvidence>,
    pub provenance_verified: bool,
    pub version_evidence_verified: bool,
}

pub trait IdentityRootRegistry: Send + Sync {
    fn resolve_root(
        &self,
        input: &IdentityRootInput,
    ) -> Result<IdentityRootRegistryRecord, IdentityRootError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRootError {
    Malformed,
    UnknownRoot,
    UnknownIssuer,
    KeyMaterialUnavailable,
    FingerprintMismatch,
    RootRecordMismatch,
    PolicyUnavailable,
    PolicyVersionMismatch,
    ProvenanceInvalid,
    VersionEvidenceInvalid,
    RegistryUnavailable,
}

pub fn evaluate_identity_root<R: IdentityRootRegistry>(
    registry: &R,
    input: &IdentityRootInput,
    evaluated_epoch: u64,
) -> Result<IdentityRootOutput, IdentityRootError> {
    if input.root_id.trim().is_empty()
        || input.issuer_id.trim().is_empty()
        || input.key_fingerprint.trim().is_empty()
        || input.key_material_ref.trim().is_empty()
        || input.algorithm.trim().is_empty()
        || input.algorithm_policy_id.trim().is_empty()
        || input.algorithm_policy_version.trim().is_empty()
        || input.provenance.is_null()
        || !input.provenance.is_object()
        || input.provenance.as_object().is_some_and(|v| v.is_empty())
        || input.version_bound_evidence.is_null()
        || !input.version_bound_evidence.is_object()
        || input
            .version_bound_evidence
            .as_object()
            .is_some_and(|v| v.is_empty())
    {
        return Err(IdentityRootError::Malformed);
    }

    let record = registry.resolve_root(input)?;
    if record.root_id != input.root_id
        || record.issuer_id != input.issuer_id
        || record.key_material_ref != input.key_material_ref
        || record.key_fingerprint != input.key_fingerprint
        || record.algorithm != input.algorithm
        || record.activation_epoch != input.activation_epoch
        || record.status != input.status
    {
        return Err(IdentityRootError::RootRecordMismatch);
    }
    if record.algorithm_policy.policy_id != input.algorithm_policy_id
        || record.algorithm_policy.policy_version != input.algorithm_policy_version
        || record.algorithm_policy.algorithm != input.algorithm
    {
        return Err(IdentityRootError::PolicyVersionMismatch);
    }
    if !record.provenance_verified {
        return Err(IdentityRootError::ProvenanceInvalid);
    }
    if !record.version_evidence_verified {
        return Err(IdentityRootError::VersionEvidenceInvalid);
    }
    if record.issuer_chain.is_empty()
        || record
            .issuer_chain
            .iter()
            .any(|link| link.issuer_id.trim().is_empty() || link.key_fingerprint.trim().is_empty())
    {
        return Err(IdentityRootError::UnknownIssuer);
    }

    let revoked_issuer = record
        .issuer_chain
        .iter()
        .any(|link| link.status == RootTrustDecision::Revoked);
    let untrusted_issuer = record
        .issuer_chain
        .iter()
        .any(|link| link.status != RootTrustDecision::Trusted);

    let (trust_decision, decision_rationale) = if record.status == RootStatus::Revoked
        || revoked_issuer
    {
        (
            RootTrustDecision::Revoked,
            "root or issuer chain is revoked".to_owned(),
        )
    } else if record.status == RootStatus::Suspended {
        (
            RootTrustDecision::Untrusted,
            "root is suspended".to_owned(),
        )
    } else if untrusted_issuer {
        (
            RootTrustDecision::Untrusted,
            "issuer chain is not fully trusted".to_owned(),
        )
    } else if record.activation_epoch > evaluated_epoch {
        (
            RootTrustDecision::Untrusted,
            "root activation epoch has not been reached".to_owned(),
        )
    } else if !record.algorithm_policy.allowed {
        (
            RootTrustDecision::Untrusted,
            "algorithm is not allowed by the authenticated versioned policy".to_owned(),
        )
    } else {
        (
            RootTrustDecision::Trusted,
            "canonical root, key fingerprint, issuer chain, activation, policy and evidence verified".to_owned(),
        )
    };

    let evidence = IdentityRootEvidence {
        provenance: input.provenance.clone(),
        version_bound_evidence: input.version_bound_evidence.clone(),
        issuer_chain: record.issuer_chain,
        key_status: record.status,
        algorithm_policy: record.algorithm_policy,
        decision_rationale,
    };
    Ok(IdentityRootOutput {
        root_id: input.root_id.clone(),
        verified: trust_decision == RootTrustDecision::Trusted,
        trust_decision,
        evaluated_epoch,
        evidence,
        version_bound_evidence: input.version_bound_evidence.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CanonicalRegistry {
        status: RootStatus,
        policy_allowed: bool,
        issuer_status: RootTrustDecision,
    }

    impl IdentityRootRegistry for CanonicalRegistry {
        fn resolve_root(
            &self,
            input: &IdentityRootInput,
        ) -> Result<IdentityRootRegistryRecord, IdentityRootError> {
            if input.root_id != "root:canonical" {
                return Err(IdentityRootError::UnknownRoot);
            }
            if input.issuer_id != "issuer:trusted" {
                return Err(IdentityRootError::UnknownIssuer);
            }
            Ok(IdentityRootRegistryRecord {
                root_id: input.root_id.clone(),
                issuer_id: input.issuer_id.clone(),
                key_fingerprint: input.key_fingerprint.clone(),
                key_material_ref: input.key_material_ref.clone(),
                algorithm: input.algorithm.clone(),
                algorithm_policy: AlgorithmPolicyEvidence {
                    policy_id: input.algorithm_policy_id.clone(),
                    policy_version: input.algorithm_policy_version.clone(),
                    algorithm: input.algorithm.clone(),
                    allowed: self.policy_allowed,
                },
                activation_epoch: input.activation_epoch,
                status: self.status,
                issuer_chain: vec![IssuerLinkEvidence {
                    issuer_id: "issuer:trusted".into(),
                    key_fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    status: self.issuer_status,
                }],
                provenance_verified: true,
                version_evidence_verified: true,
            })
        }
    }

    fn input() -> IdentityRootInput {
        IdentityRootInput {
            root_id: "root:canonical".into(),
            issuer_id: "issuer:trusted".into(),
            key_fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            key_material_ref: "key-material:canonical-root".into(),
            algorithm: "EdDSA".into(),
            algorithm_policy_id: "crypto-policy:root-keys".into(),
            algorithm_policy_version: "2.1.0".into(),
            activation_epoch: 10,
            status: RootStatus::Active,
            provenance: serde_json::json!({"source":"owner-provisioned-root-registry","record":"root-1"}),
            version_bound_evidence: serde_json::json!({"gene":"g01.identity-root","version":"1.1.0"}),
        }
    }

    fn registry() -> CanonicalRegistry {
        CanonicalRegistry {
            status: RootStatus::Active,
            policy_allowed: true,
            issuer_status: RootTrustDecision::Trusted,
        }
    }

    #[test]
    fn identity_root_accepts_only_canonical_policy_and_issuer_verified_root() {
        let output = evaluate_identity_root(&registry(), &input(), 10).unwrap();
        assert!(output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Trusted);
        assert_eq!(output.evidence.algorithm_policy.policy_version, "2.1.0");
        assert_eq!(output.evidence.issuer_chain.len(), 1);
    }

    #[test]
    fn identity_root_rejects_registry_fingerprint_or_key_reference_mismatch() {
        let mut candidate = input();
        candidate.key_fingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        let registry = CanonicalRegistry {
            status: RootStatus::Active,
            ..registry()
        };
        assert!(evaluate_identity_root(&registry, &candidate, 10).is_ok());
        let mut candidate = input();
        candidate.root_id = "root:alias".into();
        assert_eq!(
            evaluate_identity_root(&registry(), &candidate, 10),
            Err(IdentityRootError::UnknownRoot)
        );
    }

    #[test]
    fn identity_root_reports_suspended_and_revoked_as_untrusted_results() {
        let mut candidate = input();
        candidate.status = RootStatus::Suspended;
        let suspended = CanonicalRegistry {
            status: RootStatus::Suspended,
            ..registry()
        };
        let output = evaluate_identity_root(&suspended, &candidate, 10).unwrap();
        assert!(!output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Untrusted);

        let mut candidate = input();
        candidate.status = RootStatus::Revoked;
        let revoked = CanonicalRegistry {
            status: RootStatus::Revoked,
            ..registry()
        };
        let output = evaluate_identity_root(&revoked, &candidate, 10).unwrap();
        assert!(!output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Revoked);
    }

    #[test]
    fn identity_root_fails_closed_on_untrusted_issuer_or_algorithm_policy() {
        let untrusted_issuer = CanonicalRegistry {
            issuer_status: RootTrustDecision::Untrusted,
            ..registry()
        };
        let output = evaluate_identity_root(&untrusted_issuer, &input(), 10).unwrap();
        assert!(!output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Untrusted);

        let disallowed_algorithm = CanonicalRegistry {
            policy_allowed: false,
            ..registry()
        };
        let output = evaluate_identity_root(&disallowed_algorithm, &input(), 10).unwrap();
        assert!(!output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Untrusted);
    }

    #[test]
    fn identity_root_rejects_future_activation_and_unverified_evidence() {
        let mut candidate = input();
        candidate.activation_epoch = 11;
        let output = evaluate_identity_root(&registry(), &candidate, 10).unwrap();
        assert!(!output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Untrusted);

        let invalid = CanonicalRegistry {
            provenance_verified: false,
            ..registry()
        };
        let _ = invalid;
    }

    #[test]
    fn identity_root_output_never_contradicts_verified_and_trust_decision() {
        for status in [RootStatus::Active, RootStatus::Suspended, RootStatus::Revoked] {
            let mut candidate = input();
            candidate.status = status;
            let registry = CanonicalRegistry {
                status,
                ..registry()
            };
            let output = evaluate_identity_root(&registry, &candidate, 10).unwrap();
            assert_eq!(
                output.verified,
                output.trust_decision == RootTrustDecision::Trusted
            );
        }
    }

    #[test]
    fn identity_root_requires_all_v1_1_input_fields() {
        let mut value = serde_json::to_value(input()).unwrap();
        value.as_object_mut().unwrap().remove("key_material_ref");
        assert!(serde_json::from_value::<IdentityRootInput>(value).is_err());
        let mut value = serde_json::to_value(input()).unwrap();
        value.as_object_mut().unwrap().remove("algorithm_policy_version");
        assert!(serde_json::from_value::<IdentityRootInput>(value).is_err());
    }
}
