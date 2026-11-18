//! G01 lineage evaluator for contract v1.1.0.
//!
//! The resolver is a trusted boundary: it retrieves and authenticates the
//! succession proof, resolves canonical parents, traverses the complete graph,
//! detects cycles/conflicts and verifies authoritative epoch ordering. This
//! gene reports ancestry only; it never grants authority or execution rights.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LineageInput {
    pub subject_id: String,
    pub predecessor_id: String,
    pub relationship: LineageRelationship,
    pub proof_digest: String,
    pub proof_ref: String,
    pub proof_issuer_id: String,
    pub proof_signature_ref: String,
    pub proof_policy_id: String,
    pub proof_policy_version: String,
    pub epoch: u64,
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LineageRelationship {
    Derived,
    Successor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProofVerificationEvidence {
    pub verified: bool,
    pub proof_digest: String,
    pub issuer_id: String,
    pub policy_id: String,
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GraphIntegrityEvidence {
    pub cycle_free: bool,
    pub conflict_free: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ParentResolutionEvidence {
    pub subject_id: String,
    pub predecessor_id: String,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EpochValidationEvidence {
    pub predecessor_epoch: u64,
    pub subject_epoch: u64,
    pub monotonic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LineageEvidence {
    pub provenance: Value,
    pub version_bound_evidence: Value,
    pub proof_verification: ProofVerificationEvidence,
    pub graph_integrity: GraphIntegrityEvidence,
    pub parent_resolution: ParentResolutionEvidence,
    pub epoch_validation: EpochValidationEvidence,
    pub decision_rationale: String,
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

#[derive(Debug, Clone, PartialEq)]
pub struct LineageVerificationRecord {
    pub subject_id: String,
    pub predecessor_id: String,
    pub proof_digest: String,
    pub proof_issuer_id: String,
    pub proof_policy_id: String,
    pub proof_policy_version: String,
    pub chain_digest: String,
    pub verified_depth: u64,
    pub proof_verified: bool,
    pub cycle_free: bool,
    pub conflict_free: bool,
    pub graph_complete: bool,
    pub parent_resolved: bool,
    pub predecessor_epoch: u64,
    pub epoch_monotonic: bool,
    pub provenance_verified: bool,
    pub version_evidence_verified: bool,
}

/// Must retrieve proof_ref/signature_ref, verify proof_digest and signature
/// under proof_policy_id/version, resolve exact subject and predecessor,
/// traverse every parent link, detect cycles/conflicts, and validate epochs.
pub trait LineageResolver: Send + Sync {
    fn verify_lineage(
        &self,
        input: &LineageInput,
    ) -> Result<LineageVerificationRecord, LineageError>;
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
    IncompleteGraph,
    EpochNotMonotonic,
    ProvenanceInvalid,
    VersionEvidenceInvalid,
    RegistryUnavailable,
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub fn evaluate_lineage<R: LineageResolver>(
    resolver: &R,
    input: &LineageInput,
) -> Result<LineageOutput, LineageError> {
    if input.subject_id.trim().is_empty()
        || input.predecessor_id.trim().is_empty()
        || !valid_sha256(&input.proof_digest)
        || input.proof_ref.trim().is_empty()
        || input.proof_issuer_id.trim().is_empty()
        || input.proof_signature_ref.trim().is_empty()
        || input.proof_policy_id.trim().is_empty()
        || input.proof_policy_version.trim().is_empty()
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

    let record = resolver.verify_lineage(input)?;
    if record.subject_id != input.subject_id
        || record.predecessor_id != input.predecessor_id
        || record.proof_digest != input.proof_digest
        || record.proof_issuer_id != input.proof_issuer_id
        || record.proof_policy_id != input.proof_policy_id
        || record.proof_policy_version != input.proof_policy_version
        || !valid_sha256(&record.chain_digest)
        || record.verified_depth < 2
    {
        return Err(LineageError::ProofInvalid);
    }
    if !record.proof_verified {
        return Err(LineageError::ProofInvalid);
    }
    if !record.parent_resolved {
        return Err(LineageError::UnknownIdentity);
    }
    if !record.cycle_free {
        return Err(LineageError::CycleDetected);
    }
    if !record.conflict_free {
        return Err(LineageError::ConflictingAncestry);
    }
    if !record.graph_complete {
        return Err(LineageError::IncompleteGraph);
    }
    if !record.epoch_monotonic || record.predecessor_epoch >= input.epoch {
        return Err(LineageError::EpochNotMonotonic);
    }
    if !record.provenance_verified {
        return Err(LineageError::ProvenanceInvalid);
    }
    if !record.version_evidence_verified {
        return Err(LineageError::VersionEvidenceInvalid);
    }

    let proof_verification = ProofVerificationEvidence {
        verified: true,
        proof_digest: record.proof_digest,
        issuer_id: record.proof_issuer_id,
        policy_id: record.proof_policy_id,
        policy_version: record.proof_policy_version,
    };
    let graph_integrity = GraphIntegrityEvidence {
        cycle_free: true,
        conflict_free: true,
        complete: true,
    };
    let parent_resolution = ParentResolutionEvidence {
        subject_id: input.subject_id.clone(),
        predecessor_id: input.predecessor_id.clone(),
        resolved: true,
    };
    let epoch_validation = EpochValidationEvidence {
        predecessor_epoch: record.predecessor_epoch,
        subject_epoch: input.epoch,
        monotonic: true,
    };
    let evidence = LineageEvidence {
        provenance: input.provenance.clone(),
        version_bound_evidence: input.version_bound_evidence.clone(),
        proof_verification,
        graph_integrity,
        parent_resolution,
        epoch_validation,
        decision_rationale:
            "authenticated succession proof and complete acyclic ancestry verified".into(),
    };
    Ok(LineageOutput {
        subject_id: input.subject_id.clone(),
        lineage_valid: true,
        chain_digest: record.chain_digest,
        verified_depth: record.verified_depth,
        evidence,
        version_bound_evidence: input.version_bound_evidence.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestResolver {
        record: LineageVerificationRecord,
    }

    impl LineageResolver for TestResolver {
        fn verify_lineage(
            &self,
            _: &LineageInput,
        ) -> Result<LineageVerificationRecord, LineageError> {
            Ok(self.record.clone())
        }
    }

    fn input() -> LineageInput {
        LineageInput {
            subject_id: "subject:current".into(),
            predecessor_id: "subject:previous".into(),
            relationship: LineageRelationship::Successor,
            proof_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            proof_ref: "proof:succession:current".into(),
            proof_issuer_id: "issuer:succession".into(),
            proof_signature_ref: "signature:succession:current".into(),
            proof_policy_id: "policy:succession".into(),
            proof_policy_version: "1.2.0".into(),
            epoch: 22,
            provenance: serde_json::json!({"registry":"canonical-lineage"}),
            version_bound_evidence: serde_json::json!({"gene":"g01.lineage","version":"1.1.0"}),
        }
    }

    fn record() -> LineageVerificationRecord {
        LineageVerificationRecord {
            subject_id: "subject:current".into(),
            predecessor_id: "subject:previous".into(),
            proof_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            proof_issuer_id: "issuer:succession".into(),
            proof_policy_id: "policy:succession".into(),
            proof_policy_version: "1.2.0".into(),
            chain_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            verified_depth: 2,
            proof_verified: true,
            cycle_free: true,
            conflict_free: true,
            graph_complete: true,
            parent_resolved: true,
            predecessor_epoch: 21,
            epoch_monotonic: true,
            provenance_verified: true,
            version_evidence_verified: true,
        }
    }

    #[test]
    fn lineage_accepts_only_fully_verified_acyclic_monotonic_chain() {
        let output = evaluate_lineage(&TestResolver { record: record() }, &input()).unwrap();
        assert!(output.lineage_valid);
        assert_eq!(output.verified_depth, 2);
        assert!(output.evidence.proof_verification.verified);
        assert!(output.evidence.graph_integrity.cycle_free);
        assert!(output.evidence.graph_integrity.conflict_free);
        assert!(output.evidence.graph_integrity.complete);
        assert!(output.evidence.epoch_validation.monotonic);
    }

    #[test]
    fn lineage_rejects_missing_proof_reference_and_self_reference() {
        let resolver = TestResolver { record: record() };
        let mut candidate = input();
        candidate.proof_signature_ref.clear();
        assert_eq!(
            evaluate_lineage(&resolver, &candidate),
            Err(LineageError::Malformed)
        );
        let mut candidate = input();
        candidate.predecessor_id = candidate.subject_id.clone();
        assert_eq!(
            evaluate_lineage(&resolver, &candidate),
            Err(LineageError::SelfReference)
        );
    }

    #[test]
    fn lineage_rejects_merged_relationship_in_v1_1_contract() {
        let mut value = serde_json::to_value(input()).unwrap();
        value["relationship"] = Value::String("merged".into());
        assert!(serde_json::from_value::<LineageInput>(value).is_err());
    }

    #[test]
    fn lineage_rejects_unverified_proof_and_unknown_parent() {
        let mut proof = record();
        proof.proof_verified = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: proof }, &input()),
            Err(LineageError::ProofInvalid)
        );
        let mut parent = record();
        parent.parent_resolved = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: parent }, &input()),
            Err(LineageError::UnknownIdentity)
        );
    }

    #[test]
    fn lineage_rejects_cycles_conflicts_and_incomplete_graphs() {
        let mut cycle = record();
        cycle.cycle_free = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: cycle }, &input()),
            Err(LineageError::CycleDetected)
        );
        let mut conflict = record();
        conflict.conflict_free = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: conflict }, &input()),
            Err(LineageError::ConflictingAncestry)
        );
        let mut incomplete = record();
        incomplete.graph_complete = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: incomplete }, &input()),
            Err(LineageError::IncompleteGraph)
        );
    }

    #[test]
    fn lineage_rejects_non_monotonic_epoch_and_unverified_evidence() {
        let mut epoch = record();
        epoch.epoch_monotonic = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: epoch }, &input()),
            Err(LineageError::EpochNotMonotonic)
        );
        let mut provenance = record();
        provenance.provenance_verified = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: provenance }, &input()),
            Err(LineageError::ProvenanceInvalid)
        );
        let mut version = record();
        version.version_evidence_verified = false;
        assert_eq!(
            evaluate_lineage(&TestResolver { record: version }, &input()),
            Err(LineageError::VersionEvidenceInvalid)
        );
    }

    #[test]
    fn lineage_rejects_unbound_proof_policy_or_chain_digest() {
        let mut policy = record();
        policy.proof_policy_version = "9.9.9".into();
        assert_eq!(
            evaluate_lineage(&TestResolver { record: policy }, &input()),
            Err(LineageError::ProofInvalid)
        );
        let mut digest = record();
        digest.chain_digest = "not-a-digest".into();
        assert_eq!(
            evaluate_lineage(&TestResolver { record: digest }, &input()),
            Err(LineageError::ProofInvalid)
        );
    }
}
