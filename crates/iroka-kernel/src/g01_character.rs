//! G01 character-gene evaluators.
//!
//! These evaluators constrain identity claims; they do not grant authority or
//! execution permission. External registries/verifiers are explicit trusted
//! boundaries. Missing or contradictory evidence is rejected.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootInput {
    pub root_id: String,
    pub issuer_id: String,
    pub key_fingerprint: String,
    pub algorithm: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootOutput {
    pub root_id: String,
    pub verified: bool,
    pub trust_decision: RootTrustDecision,
    pub evaluated_epoch: u64,
    pub evidence: RootEvidence,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RootEvidence {
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

/// Canonical trust registry boundary. Implementations must resolve exact IDs,
/// independently verify issuer trust, key material/fingerprint and algorithm
/// policy, and bind the returned record to the supplied evidence.
pub trait IdentityRootRegistry: Send + Sync {
    fn verify_root(
        &self,
        input: &IdentityRootInput,
        evaluated_epoch: u64,
    ) -> Result<(), IdentityRootError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRootError {
    Malformed,
    UnsupportedAlgorithm,
    NotYetActive,
    Suspended,
    Revoked,
    UnknownRoot,
    UnknownIssuer,
    FingerprintMismatch,
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
        || input.algorithm.trim().is_empty()
        || input.provenance.is_null()
        || !input.provenance.is_object()
        || input.provenance.as_object().is_some_and(|v| v.is_empty())
        || input.version_bound_evidence.is_null()
        || !input.version_bound_evidence.is_object()
        || input.version_bound_evidence.as_object().is_some_and(|v| v.is_empty())
    {
        return Err(IdentityRootError::Malformed);
    }
    if input.algorithm != "EdDSA" {
        return Err(IdentityRootError::UnsupportedAlgorithm);
    }
    if input.activation_epoch > evaluated_epoch {
        return Err(IdentityRootError::NotYetActive);
    }
    match input.status {
        RootStatus::Suspended => return Err(IdentityRootError::Suspended),
        RootStatus::Revoked => return Err(IdentityRootError::Revoked),
        RootStatus::Active => {}
    }

    // The registry is responsible for canonical resolution and independent
    // verification; caller-supplied fields are never treated as proof.
    registry.verify_root(input, evaluated_epoch)?;

    let evidence = RootEvidence {
        provenance: input.provenance.clone(),
        version_bound_evidence: input.version_bound_evidence.clone(),
    };
    Ok(IdentityRootOutput {
        root_id: input.root_id.clone(),
        verified: true,
        trust_decision: RootTrustDecision::Trusted,
        evaluated_epoch,
        version_bound_evidence: input.version_bound_evidence.clone(),
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptRegistry;
    impl IdentityRootRegistry for AcceptRegistry {
        fn verify_root(
            &self,
            input: &IdentityRootInput,
            _: u64,
        ) -> Result<(), IdentityRootError> {
            if input.root_id != "root:canonical" {
                return Err(IdentityRootError::UnknownRoot);
            }
            if input.issuer_id != "issuer:trusted" {
                return Err(IdentityRootError::UnknownIssuer);
            }
            if input.key_fingerprint != "sha256:verified-key-fingerprint" {
                return Err(IdentityRootError::FingerprintMismatch);
            }
            Ok(())
        }
    }

    fn input() -> IdentityRootInput {
        IdentityRootInput {
            root_id: "root:canonical".into(),
            issuer_id: "issuer:trusted".into(),
            key_fingerprint: "sha256:verified-key-fingerprint".into(),
            algorithm: "EdDSA".into(),
            activation_epoch: 10,
            status: RootStatus::Active,
            provenance: serde_json::json!({"source":"trusted-registry","record":"root-1"}),
            version_bound_evidence: serde_json::json!({"gene":"g01.identity-root","version":"1.0.0"}),
        }
    }

    #[test]
    fn identity_root_accepts_only_registry_verified_active_root() {
        let output = evaluate_identity_root(&AcceptRegistry, &input(), 10).unwrap();
        assert!(output.verified);
        assert_eq!(output.trust_decision, RootTrustDecision::Trusted);
        assert_eq!(output.root_id, "root:canonical");
        assert_eq!(output.evaluated_epoch, 10);
    }

    #[test]
    fn identity_root_rejects_unknown_algorithm() {
        let mut candidate = input();
        candidate.algorithm = "none".into();
        assert_eq!(
            evaluate_identity_root(&AcceptRegistry, &candidate, 10),
            Err(IdentityRootError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn identity_root_rejects_not_yet_active_root() {
        let mut candidate = input();
        candidate.activation_epoch = 11;
        assert_eq!(
            evaluate_identity_root(&AcceptRegistry, &candidate, 10),
            Err(IdentityRootError::NotYetActive)
        );
    }

    #[test]
    fn identity_root_rejects_suspended_and_revoked_roots() {
        for (status, expected) in [
            (RootStatus::Suspended, IdentityRootError::Suspended),
            (RootStatus::Revoked, IdentityRootError::Revoked),
        ] {
            let mut candidate = input();
            candidate.status = status;
            assert_eq!(
                evaluate_identity_root(&AcceptRegistry, &candidate, 10),
                Err(expected)
            );
        }
    }

    #[test]
    fn identity_root_rejects_registry_identity_or_fingerprint_mismatch() {
        let mut candidate = input();
        candidate.root_id = "root:alias".into();
        assert_eq!(
            evaluate_identity_root(&AcceptRegistry, &candidate, 10),
            Err(IdentityRootError::UnknownRoot)
        );
        let mut candidate = input();
        candidate.key_fingerprint = "sha256:caller-claim".into();
        assert_eq!(
            evaluate_identity_root(&AcceptRegistry, &candidate, 10),
            Err(IdentityRootError::FingerprintMismatch)
        );
    }

    #[test]
    fn identity_root_rejects_missing_provenance_or_version_evidence() {
        let mut candidate = input();
        candidate.provenance = Value::Null;
        assert_eq!(
            evaluate_identity_root(&AcceptRegistry, &candidate, 10),
            Err(IdentityRootError::Malformed)
        );
        let mut candidate = input();
        candidate.version_bound_evidence = serde_json::json!({});
        assert_eq!(
            evaluate_identity_root(&AcceptRegistry, &candidate, 10),
            Err(IdentityRootError::Malformed)
        );
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LineageInput {
    pub subject_id: String,
    pub predecessor_id: String,
    pub relationship: LineageRelationship,
    pub proof_digest: String,
    pub epoch: u64,
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LineageRelationship {
    Derived,
    Successor,
    Merged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LineageOutput {
    pub subject_id: String,
    pub lineage_valid: bool,
    pub chain_digest: String,
    pub verified_depth: u64,
    pub evidence: RootEvidence,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageError {
    Malformed,
    SelfReference,
    UnsupportedMergedRelationship,
    ProofUnavailable,
    ProofInvalid,
    UnknownIdentity,
    CycleDetected,
    ConflictingAncestry,
    EpochNotMonotonic,
    ProvenanceInvalid,
    VersionEvidenceInvalid,
    RegistryUnavailable,
}

/// Trusted lineage resolver. It must resolve canonical identities, retrieve
/// and authenticate proof material matching proof_digest, validate the full
/// ancestry graph (including cycles/conflicts), and check authoritative epoch
/// ordering plus provenance/version evidence. A single predecessor is the
/// only representable parent shape in the frozen v1.0.0 input schema.
pub trait LineageResolver: Send + Sync {
    fn verify_lineage(
        &self,
        input: &LineageInput,
    ) -> Result<(String, u64), LineageError>;
}

pub fn evaluate_lineage<R: LineageResolver>(
    resolver: &R,
    input: &LineageInput,
) -> Result<LineageOutput, LineageError> {
    if input.subject_id.trim().is_empty()
        || input.predecessor_id.trim().is_empty()
        || input.proof_digest.trim().is_empty()
        || input.provenance.is_null()
        || !input.provenance.is_object()
        || input.provenance.as_object().is_some_and(|v| v.is_empty())
        || input.version_bound_evidence.is_null()
        || !input.version_bound_evidence.is_object()
        || input.version_bound_evidence.as_object().is_some_and(|v| v.is_empty())
    {
        return Err(LineageError::Malformed);
    }
    if input.subject_id == input.predecessor_id {
        return Err(LineageError::SelfReference);
    }
    if input.relationship == LineageRelationship::Merged {
        // The frozen contract has exactly one predecessor_id. Treating a
        // single parent as a merge would fabricate or omit ancestry.
        return Err(LineageError::UnsupportedMergedRelationship);
    }

    let (chain_digest, verified_depth) = resolver.verify_lineage(input)?;
    if chain_digest.trim().is_empty() || verified_depth < 2 {
        return Err(LineageError::ProofInvalid);
    }
    let evidence = RootEvidence {
        provenance: input.provenance.clone(),
        version_bound_evidence: input.version_bound_evidence.clone(),
    };
    Ok(LineageOutput {
        subject_id: input.subject_id.clone(),
        lineage_valid: true,
        chain_digest,
        verified_depth,
        version_bound_evidence: input.version_bound_evidence.clone(),
        evidence,
    })
}

#[cfg(test)]
mod lineage_tests {
    use super::*;

    struct ValidLineage;
    impl LineageResolver for ValidLineage {
        fn verify_lineage(
            &self,
            input: &LineageInput,
        ) -> Result<(String, u64), LineageError> {
            if input.subject_id != "subject:current"
                || input.predecessor_id != "subject:previous"
            {
                return Err(LineageError::UnknownIdentity);
            }
            if input.proof_digest != "sha256:succession-proof" {
                return Err(LineageError::ProofInvalid);
            }
            Ok(("sha256:verified-chain".into(), 2))
        }
    }

    fn input() -> LineageInput {
        LineageInput {
            subject_id: "subject:current".into(),
            predecessor_id: "subject:previous".into(),
            relationship: LineageRelationship::Successor,
            proof_digest: "sha256:succession-proof".into(),
            epoch: 22,
            provenance: serde_json::json!({"registry":"canonical-lineage"}),
            version_bound_evidence: serde_json::json!({"gene":"g01.lineage","version":"1.0.0"}),
        }
    }

    #[test]
    fn lineage_accepts_resolver_verified_acyclic_chain() {
        let output = evaluate_lineage(&ValidLineage, &input()).unwrap();
        assert!(output.lineage_valid);
        assert_eq!(output.chain_digest, "sha256:verified-chain");
        assert_eq!(output.verified_depth, 2);
    }

    #[test]
    fn lineage_rejects_self_reference_and_unrepresentable_merge() {
        let mut candidate = input();
        candidate.predecessor_id = candidate.subject_id.clone();
        assert_eq!(
            evaluate_lineage(&ValidLineage, &candidate),
            Err(LineageError::SelfReference)
        );
        let mut candidate = input();
        candidate.relationship = LineageRelationship::Merged;
        assert_eq!(
            evaluate_lineage(&ValidLineage, &candidate),
            Err(LineageError::UnsupportedMergedRelationship)
        );
    }

    #[test]
    fn lineage_rejects_missing_proof_and_incomplete_resolver_result() {
        let mut candidate = input();
        candidate.proof_digest.clear();
        assert_eq!(
            evaluate_lineage(&ValidLineage, &candidate),
            Err(LineageError::Malformed)
        );
        struct Shallow;
        impl LineageResolver for Shallow {
            fn verify_lineage(&self, _: &LineageInput) -> Result<(String, u64), LineageError> {
                Ok(("sha256:chain".into(), 1))
            }
        }
        assert_eq!(
            evaluate_lineage(&Shallow, &input()),
            Err(LineageError::ProofInvalid)
        );
    }
}
