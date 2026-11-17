//! G05 memory classification and restrictive handling controls.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryClassificationInput {
    pub memory_id: String,
    pub content_digest: String,
    pub labels: Vec<String>,
    pub purpose: String,
    pub owner_id: String,
    pub data_class: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryHandlingControl {
    pub control_id: String,
    pub action: String,
    pub scope: String,
    pub rationale: String,
    pub mandatory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryClassificationPolicy {
    pub classification_by_data_class: BTreeMap<String, String>,
    pub classification_rank: BTreeMap<String, u32>,
    pub classification_by_label: BTreeMap<String, String>,
    pub controls_by_classification: BTreeMap<String, Vec<MemoryHandlingControl>>,
    pub maximum_labels: usize,
    pub maximum_controls: usize,
}

impl MemoryClassificationPolicy {
    pub fn new(
        classification_by_data_class: BTreeMap<String, String>,
        classification_rank: BTreeMap<String, u32>,
        classification_by_label: BTreeMap<String, String>,
        controls_by_classification: BTreeMap<String, Vec<MemoryHandlingControl>>,
        maximum_labels: usize,
        maximum_controls: usize,
    ) -> Self {
        Self {
            classification_by_data_class,
            classification_rank,
            classification_by_label,
            controls_by_classification,
            maximum_labels,
            maximum_controls,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryClassificationEvidence {
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryClassificationOutput {
    pub memory_id: String,
    pub classification: String,
    pub handling_controls: Vec<MemoryHandlingControl>,
    pub classification_rationale: String,
    pub evidence: MemoryClassificationEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

fn canonical<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).ok()?).ok()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'_' | b'-' | b'.' | b':')
        })
}

fn policy_digest(policy: &MemoryClassificationPolicy) -> Option<String> {
    canonical(policy).map(|bytes| digest(&bytes))
}

fn fail(
    input: &MemoryClassificationInput,
    reason: &str,
) -> Result<MemoryClassificationOutput, String> {
    let _ = input;
    Err(reason.to_owned())
}

/// Classify memory using explicit Owner-governed mappings. Controls only restrict handling;
/// this evaluator never grants disclosure, access, or execution authority.
pub fn evaluate_memory_classification(
    input: &MemoryClassificationInput,
    policy: &MemoryClassificationPolicy,
) -> Result<MemoryClassificationOutput, String> {
    if !valid_identifier(&input.memory_id)
        || !valid_identifier(&input.owner_id)
        || input.purpose.trim().is_empty()
        || input.purpose.len() > 512
    {
        return fail(input, "memory_identity_owner_or_purpose_invalid");
    }
    if !valid_digest(&input.content_digest) {
        return fail(input, "content_digest_invalid");
    }
    if input.labels.is_empty() || input.labels.len() > policy.maximum_labels {
        return fail(input, "label_count_outside_policy");
    }
    if input.provenance.is_empty() || input.version_bound_evidence.is_empty() {
        return fail(input, "provenance_or_version_evidence_missing");
    }
    let Some(base_classification) = policy
        .classification_by_data_class
        .get(&input.data_class)
    else {
        return fail(input, "data_class_not_approved");
    };
    let mut classifications = vec![base_classification.as_str()];
    let mut seen_labels = BTreeSet::new();
    for label in &input.labels {
        if label.is_empty() || label.trim() != label || !seen_labels.insert(label.as_str()) {
            return fail(input, "labels_must_be_unique_opaque_policy_identifiers");
        }
        let Some(classification) = policy.classification_by_label.get(label) else {
            return fail(input, "label_not_approved");
        };
        classifications.push(classification);
    }
    let mut selected: Option<(&str, u32)> = None;
    for classification in classifications {
        let Some(rank) = policy.classification_rank.get(classification) else {
            return fail(input, "classification_rank_missing");
        };
        if selected.map_or(true, |(_, current_rank)| *rank > current_rank) {
            selected = Some((classification, *rank));
        }
    }
    let Some((classification, _)) = selected else {
        return fail(input, "classification_not_resolved");
    };
    let Some(controls) = policy.controls_by_classification.get(classification) else {
        return fail(input, "handling_controls_missing");
    };
    if controls.is_empty() || controls.len() > policy.maximum_controls {
        return fail(input, "handling_controls_outside_policy");
    }
    let mut control_ids = BTreeSet::new();
    for control in controls {
        if !valid_identifier(&control.control_id)
            || control.action.trim().is_empty()
            || control.scope.trim().is_empty()
            || control.rationale.trim().is_empty()
            || !control_ids.insert(control.control_id.as_str())
        {
            return fail(input, "handling_control_malformed_or_duplicate");
        }
    }
    if policy_digest(policy).is_none() || canonical(&input.labels).is_none() {
        return fail(input, "policy_or_label_canonicalization_failed");
    }
    Ok(MemoryClassificationOutput {
        memory_id: input.memory_id.clone(),
        classification: classification.to_owned(),
        handling_controls: controls.clone(),
        classification_rationale: format!(
            "highest approved classification across data class and exact opaque labels; owner={}",
            input.owner_id
        ),
        evidence: MemoryClassificationEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence: input.version_bound_evidence.clone(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> MemoryClassificationPolicy {
        let control = |id: &str, action: &str| MemoryHandlingControl {
            control_id: id.into(),
            action: action.into(),
            scope: "memory:all".into(),
            rationale: "enforce classification handling boundary".into(),
            mandatory: true,
        };
        MemoryClassificationPolicy::new(
            BTreeMap::from([
                ("public".into(), "public".into()),
                ("internal".into(), "internal".into()),
                ("restricted".into(), "restricted".into()),
            ]),
            BTreeMap::from([
                ("public".into(), 0),
                ("internal".into(), 1),
                ("confidential".into(), 2),
                ("restricted".into(), 3),
            ]),
            BTreeMap::from([
                ("pii".into(), "confidential".into()),
                ("legal_hold".into(), "restricted".into()),
                ("team_only".into(), "internal".into()),
            ]),
            BTreeMap::from([
                ("public".into(), vec![control("public-retain", "retain")]),
                ("internal".into(), vec![control("internal-limit", "limit_internal")]),
                ("confidential".into(), vec![control("confidential-encrypt", "encrypt_at_rest")]),
                ("restricted".into(), vec![
                    control("restricted-encrypt", "encrypt_at_rest"),
                    control("restricted-no-export", "deny_export"),
                ]),
            ]),
            16,
            8,
        )
    }

    fn input() -> MemoryClassificationInput {
        MemoryClassificationInput {
            memory_id: "memory-001".into(),
            content_digest: "a".repeat(64),
            labels: vec!["team_only".into()],
            purpose: "user-requested continuity".into(),
            owner_id: "owner-001".into(),
            data_class: "public".into(),
            provenance: BTreeMap::from([("source".into(), json!("synthetic"))]),
            version_bound_evidence: BTreeMap::from([("genome_digest".into(), json!("b".repeat(64)))]),
        }
    }

    #[test]
    fn applies_highest_classification_without_label_normalization() {
        let result = evaluate_memory_classification(&input(), &policy()).unwrap();
        assert_eq!(result.classification, "internal");
        assert_eq!(result.handling_controls.len(), 1);
        assert!(!result.evidence.provenance.is_empty());
    }

    #[test]
    fn sensitive_label_cannot_be_downgraded_by_public_data_class() {
        let mut value = input();
        value.labels = vec!["pii".into()];
        let result = evaluate_memory_classification(&value, &policy()).unwrap();
        assert_eq!(result.classification, "confidential");
    }

    #[test]
    fn restricted_label_applies_restrictive_controls() {
        let mut value = input();
        value.labels = vec!["legal_hold".into()];
        let result = evaluate_memory_classification(&value, &policy()).unwrap();
        assert_eq!(result.classification, "restricted");
        assert!(result.handling_controls.iter().any(|control| control.action == "deny_export"));
    }

    #[test]
    fn rejects_unknown_or_normalized_labels_and_duplicate_labels() {
        let mut value = input();
        value.labels = vec!["PII".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("label_not_approved".into()));
        value.labels = vec!["pii ".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("labels_must_be_unique_opaque_policy_identifiers".into()));
        value.labels = vec!["pii".into(), "pii".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("labels_must_be_unique_opaque_policy_identifiers".into()));
    }

    #[test]
    fn rejects_bad_digest_missing_controls_and_missing_provenance() {
        let mut value = input();
        value.content_digest = "not-a-digest".into();
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("content_digest_invalid".into()));
        let mut p = policy();
        p.controls_by_classification.remove("internal");
        assert_eq!(evaluate_memory_classification(&input(), &p), Err("handling_controls_missing".into()));
        let mut value = input();
        value.provenance.clear();
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("provenance_or_version_evidence_missing".into()));
    }
}
