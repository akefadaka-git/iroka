//! A3 G12 version-lineage evaluator. Registry access and evidence verification
//! are injected; this gene is read-only and never grants execution authority.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{canonical_json, EvidenceBinding, RollbackEvidenceReceipt, RollbackEvidenceVerifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageDenialCode {
    None,
    InvalidInput,
    RegistryUnavailable,
    UnknownVersion,
    DigestMismatch,
    ParentMismatch,
    MutationInvalid,
    AncestryInvalid,
    EpochNonMonotonic,
    EvidenceInvalid,
    VersionEvidenceInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageRegistryError {
    UnknownVersion,
    AmbiguousVersion,
    Unavailable,
    IntegrityFailure,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RegisteredLineageArtifact {
    pub gene_id: String,
    pub version: String,
    pub artifact_digest: String,
    pub artifact: Value,
    pub parent_version: Option<String>,
    pub parent_digest: Option<String>,
    pub mutation_id: Option<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RegisteredMutationRecord {
    pub mutation_ref: String,
    pub mutation_id: String,
    pub source_version: Option<String>,
    pub source_digest: Option<String>,
    pub target_version: String,
    pub target_digest: String,
    pub approved: bool,
    pub gates_passed: bool,
    pub approval_commitment: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VersionLineageRecord {
    /// Exactly one ordered path from the immutable root to the candidate.
    pub ancestry: Vec<RegisteredLineageArtifact>,
    /// None only for the canonical GENESIS root.
    pub mutation: Option<RegisteredMutationRecord>,
    pub registry_revision: u64,
}

/// Production implementations must resolve one authoritative, immutable registry
/// snapshot and must never mutate registry state during lineage evaluation.
pub trait VersionLineageRegistry: Send + Sync {
    fn resolve_lineage(
        &self,
        candidate_version: &str,
        candidate_digest: &str,
    ) -> Result<VersionLineageRecord, LineageRegistryError>;
}

pub struct VersionLineageInput<'a> {
    pub artifact: &'a Value,
    pub artifact_digest: String,
    pub version: String,
    pub parent_version: Option<String>,
    pub parent_digest: Option<String>,
    pub mutation_ref: String,
    pub epoch: u64,
    pub provenance: &'a [RollbackEvidenceReceipt],
    pub version_bound_evidence: &'a [RollbackEvidenceReceipt],
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LineageEvidenceSummary {
    pub status: String,
    pub verified_subjects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LineageAncestryOutput {
    pub gene_id: String,
    pub version: String,
    pub artifact_digest: String,
    pub parent_version: Option<String>,
    pub parent_digest: Option<String>,
    pub mutation_id: Option<String>,
    pub epoch: u64,
    pub evidence_commitments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VersionLineageResult {
    pub decision: String,
    pub lineage_digest: Option<String>,
    pub linked: bool,
    pub epoch_monotonic: bool,
    pub ancestry: Vec<LineageAncestryOutput>,
    pub evidence: LineageEvidenceSummary,
    pub version_bound_evidence: Vec<RollbackEvidenceReceipt>,
    pub denial_code: LineageDenialCode,
    pub denial_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionLineageError {
    Canonicalization,
    Commitment,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_value(value: &Value) -> Result<String, VersionLineageError> {
    canonical_json(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| VersionLineageError::Canonicalization)
}

fn parse_semver(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    fn number(part: &str) -> Option<u64> {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        part.parse().ok()
    }
    Some((number(major)?, number(minor)?, number(patch)?))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn deny(
    input: &VersionLineageInput<'_>,
    code: LineageDenialCode,
    reason: &str,
) -> VersionLineageResult {
    VersionLineageResult {
        decision: "deny".into(),
        lineage_digest: None,
        linked: false,
        epoch_monotonic: false,
        ancestry: Vec::new(),
        evidence: LineageEvidenceSummary {
            status: "invalid".into(),
            verified_subjects: Vec::new(),
        },
        version_bound_evidence: input.version_bound_evidence.to_vec(),
        denial_code: code,
        denial_reason: Some(reason.into()),
    }
}

fn verify_lineage_evidence(
    receipts: &[RollbackEvidenceReceipt],
    expected: &[EvidenceBinding],
    verifier: &dyn RollbackEvidenceVerifier,
    now: u64,
) -> bool {
    if receipts.len() != expected.len() {
        return false;
    }
    let mut subjects = std::collections::BTreeSet::new();
    let mut nonces = std::collections::BTreeSet::new();
    for receipt in receipts {
        if !subjects.insert(receipt.subject.as_str()) || !nonces.insert(receipt.nonce.as_str()) {
            return false;
        }
        let Some(binding) = expected
            .iter()
            .find(|binding| binding.subject == receipt.subject)
        else {
            return false;
        };
        if verifier.verify(receipt, binding, now).is_err() {
            return false;
        }
    }
    subjects.len() == expected.len()
        && expected
            .iter()
            .all(|binding| subjects.contains(binding.subject.as_str()))
}

fn receipt_for<'a>(
    receipts: &'a [RollbackEvidenceReceipt],
    subject: &str,
) -> Option<&'a RollbackEvidenceReceipt> {
    receipts.iter().find(|receipt| receipt.subject == subject)
}

/// Verify candidate bytes, canonical versions, immutable mutation record,
/// exact ancestry links, acyclicity, monotonic epochs and evidence for every node.
pub fn evaluate_version_lineage(
    input: &VersionLineageInput<'_>,
    registry: &dyn VersionLineageRegistry,
    evidence_verifier: &dyn RollbackEvidenceVerifier,
    now: u64,
) -> Result<VersionLineageResult, VersionLineageError> {
    if !valid_digest(&input.artifact_digest)
        || parse_semver(&input.version).is_none()
        || input.mutation_ref.trim().is_empty()
    {
        return Ok(deny(
            input,
            LineageDenialCode::InvalidInput,
            "candidate digest, SemVer, mutation reference or epoch is invalid",
        ));
    }

    let root = input.parent_version.is_none() && input.parent_digest.is_none();
    if input.parent_version.is_some() != input.parent_digest.is_some()
        || (root && (input.mutation_ref != "GENESIS" || input.epoch != 0))
        || (!root && input.mutation_ref == "GENESIS")
        || input
            .parent_version
            .as_deref()
            .is_some_and(|version| parse_semver(version).is_none())
        || input
            .parent_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
    {
        return Ok(deny(
            input,
            LineageDenialCode::ParentMismatch,
            "root and non-root parent representation is ambiguous or invalid",
        ));
    }

    let candidate_digest = digest_value(input.artifact)?;
    if candidate_digest != input.artifact_digest {
        return Ok(deny(
            input,
            LineageDenialCode::DigestMismatch,
            "candidate artifact digest does not match canonical SHA-256/JCS bytes",
        ));
    }

    let record = match registry.resolve_lineage(&input.version, &input.artifact_digest) {
        Ok(record) => record,
        Err(LineageRegistryError::UnknownVersion) => {
            return Ok(deny(
                input,
                LineageDenialCode::UnknownVersion,
                "candidate version is not registered",
            ));
        }
        Err(LineageRegistryError::Unavailable) => {
            return Ok(deny(
                input,
                LineageDenialCode::RegistryUnavailable,
                "authoritative version registry is unavailable",
            ));
        }
        Err(LineageRegistryError::AmbiguousVersion | LineageRegistryError::IntegrityFailure) => {
            return Ok(deny(
                input,
                LineageDenialCode::AncestryInvalid,
                "version registry returned ambiguous or inconsistent lineage",
            ));
        }
    };

    if record.ancestry.is_empty() || record.ancestry.len() > 128 {
        return Ok(deny(
            input,
            LineageDenialCode::AncestryInvalid,
            "ancestry must contain between one and 128 entries",
        ));
    }

    let mut seen_digests = std::collections::BTreeSet::new();
    let mut seen_identities = std::collections::BTreeSet::new();
    for (index, entry) in record.ancestry.iter().enumerate() {
        if entry.gene_id.trim().is_empty()
            || parse_semver(&entry.version).is_none()
            || !valid_digest(&entry.artifact_digest)
            || !seen_digests.insert(entry.artifact_digest.as_str())
            || !seen_identities.insert((
                entry.gene_id.as_str(),
                entry.version.as_str(),
                entry.artifact_digest.as_str(),
            ))
        {
            return Ok(deny(
                input,
                LineageDenialCode::AncestryInvalid,
                "ancestry contains malformed or duplicate immutable identity",
            ));
        }
        if digest_value(&entry.artifact)? != entry.artifact_digest {
            return Ok(deny(
                input,
                LineageDenialCode::DigestMismatch,
                "an ancestor artifact digest does not match its immutable bytes",
            ));
        }
        if index == 0 {
            if entry.parent_version.is_some()
                || entry.parent_digest.is_some()
                || entry.mutation_id.is_some()
                || entry.epoch != 0
            {
                return Ok(deny(
                    input,
                    LineageDenialCode::ParentMismatch,
                    "oldest ancestry entry is not the canonical root",
                ));
            }
        } else {
            let parent = &record.ancestry[index - 1];
            if entry.parent_version.as_deref() != Some(parent.version.as_str())
                || entry.parent_digest.as_deref() != Some(parent.artifact_digest.as_str())
                || entry.mutation_id.as_deref().map_or(true, str::is_empty)
            {
                return Ok(deny(
                    input,
                    LineageDenialCode::ParentMismatch,
                    "ancestry parent pair does not resolve to the immediately preceding node",
                ));
            }
            let previous_version =
                parse_semver(&parent.version).ok_or(VersionLineageError::Commitment)?;
            let current_version =
                parse_semver(&entry.version).ok_or(VersionLineageError::Commitment)?;
            if current_version <= previous_version || entry.epoch <= parent.epoch {
                return Ok(deny(
                    input,
                    LineageDenialCode::EpochNonMonotonic,
                    "version and authoritative epoch must strictly increase along ancestry",
                ));
            }
        }
    }

    let candidate = record
        .ancestry
        .last()
        .ok_or(VersionLineageError::Commitment)?;
    if candidate.version != input.version
        || candidate.artifact_digest != input.artifact_digest
        || candidate.epoch != input.epoch
        || candidate.parent_version != input.parent_version
        || candidate.parent_digest != input.parent_digest
        || candidate.artifact != *input.artifact
    {
        return Ok(deny(
            input,
            LineageDenialCode::ParentMismatch,
            "registered final ancestry node does not exactly match the candidate input",
        ));
    }

    if root {
        if record.ancestry.len() != 1 || record.mutation.is_some() {
            return Ok(deny(
                input,
                LineageDenialCode::MutationInvalid,
                "GENESIS must be a single root node without a mutation record",
            ));
        }
    } else {
        let Some(mutation) = record.mutation.as_ref() else {
            return Ok(deny(
                input,
                LineageDenialCode::MutationInvalid,
                "non-root candidate has no immutable mutation record",
            ));
        };
        let parent = &record.ancestry[record.ancestry.len() - 2];
        if mutation.mutation_ref != input.mutation_ref
            || !mutation.approved
            || !mutation.gates_passed
            || mutation.target_version != candidate.version
            || mutation.target_digest != candidate.artifact_digest
            || mutation.source_version.as_deref() != Some(parent.version.as_str())
            || mutation.source_digest.as_deref() != Some(parent.artifact_digest.as_str())
            || candidate.mutation_id.as_deref() != Some(mutation.mutation_id.as_str())
            || !valid_digest(&mutation.approval_commitment)
        {
            return Ok(deny(
                input,
                LineageDenialCode::MutationInvalid,
                "mutation record is unapproved, ungated or not bound to exact source and target",
            ));
        }
    }

    let registry_value =
        serde_json::to_value(&record).map_err(|_| VersionLineageError::Commitment)?;
    let registry_digest = digest_value(&registry_value)?;
    let mut expected = Vec::new();
    for entry in &record.ancestry {
        expected.push(EvidenceBinding {
            subject: format!("lineage:artifact:{}", entry.artifact_digest),
            digest: digest_value(&json!({
                "version": entry.version,
                "artifact_digest": entry.artifact_digest,
                "epoch": entry.epoch
            }))?,
            epoch: entry.epoch,
            revision: record.registry_revision,
        });
    }
    if let Some(mutation) = record.mutation.as_ref() {
        expected.push(EvidenceBinding {
            subject: format!("lineage:mutation:{}", mutation.mutation_ref),
            digest: digest_value(
                &serde_json::to_value(mutation).map_err(|_| VersionLineageError::Commitment)?,
            )?,
            epoch: candidate.epoch,
            revision: record.registry_revision,
        });
    }
    expected.push(EvidenceBinding {
        subject: "lineage:registry".into(),
        digest: registry_digest.clone(),
        epoch: candidate.epoch,
        revision: record.registry_revision,
    });

    if !verify_lineage_evidence(input.provenance, &expected, evidence_verifier, now) {
        return Ok(deny(
            input,
            LineageDenialCode::EvidenceInvalid,
            "provenance evidence is missing, stale, replayed, forged or mismatched",
        ));
    }
    if !verify_lineage_evidence(
        input.version_bound_evidence,
        &expected,
        evidence_verifier,
        now,
    ) {
        return Ok(deny(
            input,
            LineageDenialCode::VersionEvidenceInvalid,
            "version-bound evidence is missing, stale, replayed or not bound to every lineage node",
        ));
    }

    let mut output_ancestry = Vec::new();
    let mut evidence_subjects = Vec::new();
    for entry in &record.ancestry {
        let subject = format!("lineage:artifact:{}", entry.artifact_digest);
        let provenance =
            receipt_for(input.provenance, &subject).ok_or(VersionLineageError::Commitment)?;
        let version_bound = receipt_for(input.version_bound_evidence, &subject)
            .ok_or(VersionLineageError::Commitment)?;
        output_ancestry.push(LineageAncestryOutput {
            gene_id: entry.gene_id.clone(),
            version: entry.version.clone(),
            artifact_digest: entry.artifact_digest.clone(),
            parent_version: entry.parent_version.clone(),
            parent_digest: entry.parent_digest.clone(),
            mutation_id: entry.mutation_id.clone(),
            epoch: entry.epoch,
            evidence_commitments: vec![
                digest_value(
                    &serde_json::to_value(provenance)
                        .map_err(|_| VersionLineageError::Commitment)?,
                )?,
                digest_value(
                    &serde_json::to_value(version_bound)
                        .map_err(|_| VersionLineageError::Commitment)?,
                )?,
            ],
        });
        evidence_subjects.push(subject);
    }
    if let Some(mutation) = record.mutation.as_ref() {
        evidence_subjects.push(format!("lineage:mutation:{}", mutation.mutation_ref));
    }
    evidence_subjects.push("lineage:registry".into());

    let evidence_commitment = digest_value(&json!({
        "provenance": input.provenance,
        "version_bound_evidence": input.version_bound_evidence
    }))?;
    let envelope = json!({
        "envelope_version": "1.1.0",
        "hash_algorithm": "SHA-256",
        "canonicalization": "RFC8785-JCS",
        "candidate_version": candidate.version,
        "candidate_digest": candidate.artifact_digest,
        "registry_revision": record.registry_revision,
        "ancestry": output_ancestry,
        "mutation": record.mutation,
        "registry_digest": registry_digest,
        "evidence_commitment": evidence_commitment
    });
    let lineage_digest = digest_value(&envelope)?;

    Ok(VersionLineageResult {
        decision: "allow".into(),
        lineage_digest: Some(lineage_digest),
        linked: true,
        epoch_monotonic: true,
        ancestry: output_ancestry,
        evidence: LineageEvidenceSummary {
            status: "verified".into(),
            verified_subjects: evidence_subjects,
        },
        version_bound_evidence: input.version_bound_evidence.to_vec(),
        denial_code: LineageDenialCode::None,
        denial_reason: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceVerificationError, RollbackEvidenceReceipt};

    struct TestEvidence;
    impl RollbackEvidenceVerifier for TestEvidence {
        fn verify(
            &self,
            receipt: &RollbackEvidenceReceipt,
            expected: &EvidenceBinding,
            now: u64,
        ) -> Result<(), EvidenceVerificationError> {
            if receipt.subject != expected.subject
                || receipt.subject_digest != expected.digest
                || receipt.subject_epoch != expected.epoch
                || receipt.revision != expected.revision
                || receipt.issued_at > now
                || receipt.expires_at <= now
                || receipt.signature.len() != 64
            {
                return Err(EvidenceVerificationError::ScopeMismatch);
            }
            Ok(())
        }
    }

    struct StaticRegistry(Result<VersionLineageRecord, LineageRegistryError>);
    impl VersionLineageRegistry for StaticRegistry {
        fn resolve_lineage(
            &self,
            _candidate_version: &str,
            _candidate_digest: &str,
        ) -> Result<VersionLineageRecord, LineageRegistryError> {
            self.0.clone()
        }
    }

    fn artifact(version: u64) -> Value {
        json!({"gene":"g12.version-lineage","payload_version":version})
    }

    fn entry(
        version: &str,
        value: Value,
        parent: Option<&RegisteredLineageArtifact>,
        mutation_id: Option<&str>,
        epoch: u64,
    ) -> RegisteredLineageArtifact {
        RegisteredLineageArtifact {
            gene_id: "g12.version-lineage".into(),
            version: version.into(),
            artifact_digest: digest_value(&value).unwrap(),
            artifact: value,
            parent_version: parent.map(|entry| entry.version.clone()),
            parent_digest: parent.map(|entry| entry.artifact_digest.clone()),
            mutation_id: mutation_id.map(str::to_owned),
            epoch,
        }
    }

    fn root_record() -> VersionLineageRecord {
        let root = entry("1.0.0", artifact(1), None, None, 0);
        VersionLineageRecord {
            ancestry: vec![root],
            mutation: None,
            registry_revision: 1,
        }
    }

    fn linear_record() -> VersionLineageRecord {
        let root = entry("1.0.0", artifact(1), None, None, 0);
        let middle = entry("1.1.0", artifact(2), Some(&root), Some("mutation-1"), 1);
        let candidate = entry("1.2.0", artifact(3), Some(&middle), Some("mutation-2"), 2);
        let mutation = RegisteredMutationRecord {
            mutation_ref: "mutation-ref-2".into(),
            mutation_id: "mutation-2".into(),
            source_version: Some(middle.version.clone()),
            source_digest: Some(middle.artifact_digest.clone()),
            target_version: candidate.version.clone(),
            target_digest: candidate.artifact_digest.clone(),
            approved: true,
            gates_passed: true,
            approval_commitment: "a".repeat(64),
        };
        VersionLineageRecord {
            ancestry: vec![root, middle, candidate],
            mutation: Some(mutation),
            registry_revision: 42,
        }
    }

    fn expected(record: &VersionLineageRecord) -> Vec<EvidenceBinding> {
        let mut bindings = Vec::new();
        for entry in &record.ancestry {
            bindings.push(EvidenceBinding {
                subject: format!("lineage:artifact:{}", entry.artifact_digest),
                digest: digest_value(&json!({
                    "version": entry.version,
                    "artifact_digest": entry.artifact_digest,
                    "epoch": entry.epoch
                }))
                .unwrap(),
                epoch: entry.epoch,
                revision: record.registry_revision,
            });
        }
        let candidate = record.ancestry.last().unwrap();
        if let Some(mutation) = &record.mutation {
            bindings.push(EvidenceBinding {
                subject: format!("lineage:mutation:{}", mutation.mutation_ref),
                digest: digest_value(&serde_json::to_value(mutation).unwrap()).unwrap(),
                epoch: candidate.epoch,
                revision: record.registry_revision,
            });
        }
        bindings.push(EvidenceBinding {
            subject: "lineage:registry".into(),
            digest: digest_value(&serde_json::to_value(record).unwrap()).unwrap(),
            epoch: candidate.epoch,
            revision: record.registry_revision,
        });
        bindings
    }

    fn evidence(record: &VersionLineageRecord, suffix: &str) -> Vec<RollbackEvidenceReceipt> {
        expected(record)
            .iter()
            .enumerate()
            .map(|(index, binding)| RollbackEvidenceReceipt {
                subject: binding.subject.clone(),
                subject_digest: binding.digest.clone(),
                subject_epoch: binding.epoch,
                revision: binding.revision,
                issuer: "issuer:lineage-test".into(),
                key_id: "lineage-test-key".into(),
                issued_at: 1_000,
                expires_at: 2_000,
                nonce: format!("lineage-nonce-{suffix}-{index:03}-unique"),
                signature: vec![9; 64],
            })
            .collect()
    }

    fn evaluate_record(
        record: &VersionLineageRecord,
        artifact: &Value,
        mutation_ref: &str,
        provenance: &[RollbackEvidenceReceipt],
        version_bound: &[RollbackEvidenceReceipt],
    ) -> VersionLineageResult {
        let candidate = record.ancestry.last().unwrap();
        let input = VersionLineageInput {
            artifact,
            artifact_digest: candidate.artifact_digest.clone(),
            version: candidate.version.clone(),
            parent_version: candidate.parent_version.clone(),
            parent_digest: candidate.parent_digest.clone(),
            mutation_ref: mutation_ref.into(),
            epoch: candidate.epoch,
            provenance,
            version_bound_evidence: version_bound,
        };
        evaluate_version_lineage(
            &input,
            &StaticRegistry(Ok(record.clone())),
            &TestEvidence,
            1_100,
        )
        .unwrap()
    }

    #[test]
    fn registered_genesis_root_is_accepted() {
        let record = root_record();
        let root_artifact = record.ancestry[0].artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &root_artifact,
            "GENESIS",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.decision, "allow");
        assert_eq!(result.ancestry.len(), 1);
        assert!(result.linked && result.epoch_monotonic);
        assert!(result.lineage_digest.is_some());
    }

    #[test]
    fn complete_three_node_ancestry_is_accepted() {
        let record = linear_record();
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.decision, "allow");
        assert_eq!(result.ancestry.len(), 3);
        assert_eq!(
            result.ancestry[2].parent_digest,
            Some(record.ancestry[1].artifact_digest.clone())
        );
        assert!(result.linked && result.epoch_monotonic);
    }

    #[test]
    fn candidate_artifact_digest_substitution_is_denied() {
        let record = linear_record();
        let substituted = json!({"gene":"g12.version-lineage","payload_version":999});
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &substituted,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.denial_code, LineageDenialCode::DigestMismatch);
        assert!(!result.linked && !result.epoch_monotonic);
    }

    #[test]
    fn unknown_version_registry_entry_fails_closed() {
        let record = linear_record();
        let candidate = record.ancestry.last().unwrap();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let input = VersionLineageInput {
            artifact: &candidate.artifact,
            artifact_digest: candidate.artifact_digest.clone(),
            version: candidate.version.clone(),
            parent_version: candidate.parent_version.clone(),
            parent_digest: candidate.parent_digest.clone(),
            mutation_ref: "mutation-ref-2".into(),
            epoch: candidate.epoch,
            provenance: &provenance,
            version_bound_evidence: &version_bound,
        };
        let result = evaluate_version_lineage(
            &input,
            &StaticRegistry(Err(LineageRegistryError::UnknownVersion)),
            &TestEvidence,
            1_100,
        )
        .unwrap();
        assert_eq!(result.denial_code, LineageDenialCode::UnknownVersion);
    }

    #[test]
    fn ambiguous_genesis_parent_pair_is_denied() {
        let record = root_record();
        let candidate = &record.ancestry[0];
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let input = VersionLineageInput {
            artifact: &candidate.artifact,
            artifact_digest: candidate.artifact_digest.clone(),
            version: candidate.version.clone(),
            parent_version: Some("1.0.0".into()),
            parent_digest: None,
            mutation_ref: "GENESIS".into(),
            epoch: 0,
            provenance: &provenance,
            version_bound_evidence: &version_bound,
        };
        let result = evaluate_version_lineage(
            &input,
            &StaticRegistry(Ok(record.clone())),
            &TestEvidence,
            1_100,
        )
        .unwrap();
        assert_eq!(result.denial_code, LineageDenialCode::ParentMismatch);
    }

    #[test]
    fn unapproved_or_ungated_mutation_is_denied() {
        let mut record = linear_record();
        record.mutation.as_mut().unwrap().approved = false;
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.denial_code, LineageDenialCode::MutationInvalid);
    }

    #[test]
    fn missing_ancestor_evidence_is_denied() {
        let record = linear_record();
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(&record, &candidate, "mutation-ref-2", &[], &version_bound);
        assert_eq!(result.denial_code, LineageDenialCode::EvidenceInvalid);
    }

    #[test]
    fn duplicate_or_cyclic_ancestry_is_denied() {
        let mut record = linear_record();
        record.ancestry[1].artifact_digest = record.ancestry[0].artifact_digest.clone();
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.denial_code, LineageDenialCode::AncestryInvalid);
    }

    #[test]
    fn broken_parent_digest_link_is_denied() {
        let mut record = linear_record();
        record.ancestry[2].parent_digest = Some("f".repeat(64));
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.denial_code, LineageDenialCode::ParentMismatch);
    }

    #[test]
    fn non_monotonic_epoch_is_denied() {
        let mut record = linear_record();
        record.ancestry[1].epoch = 0;
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let result = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert_eq!(result.denial_code, LineageDenialCode::EpochNonMonotonic);
    }

    #[test]
    fn lineage_flags_are_derived_and_digest_is_reproducible() {
        let record = linear_record();
        let candidate = record.ancestry.last().unwrap().artifact.clone();
        let provenance = evidence(&record, "p");
        let version_bound = evidence(&record, "v");
        let first = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        let second = evaluate_record(
            &record,
            &candidate,
            "mutation-ref-2",
            &provenance,
            &version_bound,
        );
        assert!(first.linked && first.epoch_monotonic);
        assert_eq!(first.lineage_digest, second.lineage_digest);
        assert_eq!(first.decision, "allow");
    }
}
