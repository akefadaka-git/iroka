//! G01 lineage gene evaluator. No authority is granted by a lineage result.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
pub struct LineageEvidence {
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LineageOutput {
    pub subject_id: String,
    pub lineage_valid: bool,
    pub chain_digest: String,
    pub verified_depth: u64,
    pub evidence: LineageEvidence,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageError {
    Malformed,
    SelfReference,
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
/// ordering plus provenance/version evidence. For merged relationships,
/// predecessor_id is the canonical anchor; the authenticated proof graph must
/// establish and validate every additional parent edge.
pub trait LineageResolver: Send + Sync {
    fn verify_lineage(&self, input: &LineageInput) -> Result<(String, u64), LineageError>;
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
        || input
            .version_bound_evidence
            .as_object()
            .is_some_and(|v| v.is_empty())
    {
        return Err(LineageError::Malformed);
    }
    if input.subject_id == input.predecessor_id {
        return Err(LineageError::SelfReference);
    }
    let (chain_digest, verified_depth) = resolver.verify_lineage(input)?;
    if chain_digest.trim().is_empty() || verified_depth < 2 {
        return Err(LineageError::ProofInvalid);
    }
    let evidence = LineageEvidence {
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
        fn verify_lineage(&self, input: &LineageInput) -> Result<(String, u64), LineageError> {
            if input.subject_id != "subject:current" || input.predecessor_id != "subject:previous" {
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
    fn lineage_rejects_self_reference_and_accepts_resolver_verified_merge() {
        let mut candidate = input();
        candidate.predecessor_id = candidate.subject_id.clone();
        assert_eq!(
            evaluate_lineage(&ValidLineage, &candidate),
            Err(LineageError::SelfReference)
        );
        let mut candidate = input();
        candidate.relationship = LineageRelationship::Merged;
        assert!(
            evaluate_lineage(&ValidLineage, &candidate)
                .unwrap()
                .lineage_valid
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
