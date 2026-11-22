//! G05 memory classification with explicit policy mappings and restrictive controls.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const POLICY_DIGEST_KEY: &str = "g05_classification_policy_sha256";

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
#[serde(deny_unknown_fields)]
pub struct MemoryClassificationPolicy {
    pub classification_by_data_class: BTreeMap<String, String>,
    pub classification_rank: BTreeMap<String, u32>,
    pub classification_by_label: BTreeMap<String, String>,
    pub controls_by_classification: BTreeMap<String, Vec<MemoryHandlingControl>>,
    pub approved_purposes: BTreeSet<String>,
    pub maximum_labels: usize,
    pub maximum_controls: usize,
}

impl MemoryClassificationPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        classification_by_data_class: BTreeMap<String, String>,
        classification_rank: BTreeMap<String, u32>,
        classification_by_label: BTreeMap<String, String>,
        controls_by_classification: BTreeMap<String, Vec<MemoryHandlingControl>>,
        approved_purposes: BTreeSet<String>,
        maximum_labels: usize,
        maximum_controls: usize,
    ) -> Self {
        Self {
            classification_by_data_class,
            classification_rank,
            classification_by_label,
            controls_by_classification,
            approved_purposes,
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

/// Matches the closed G05 output schema: version-bound evidence appears once,
/// nested within the evidence object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryClassificationOutput {
    pub memory_id: String,
    pub classification: String,
    pub handling_controls: Vec<MemoryHandlingControl>,
    pub classification_rationale: String,
    pub evidence: MemoryClassificationEvidence,
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

fn valid_purpose(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_uppercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_'
        })
}

fn valid_restrictive_action(value: &str) -> bool {
    valid_identifier(value)
        && [
            "deny_",
            "restrict_",
            "require_",
            "encrypt_",
            "quarantine_",
            "limit_",
            "redact_",
            "mask_",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn validate_policy(policy: &MemoryClassificationPolicy) -> Result<(), &'static str> {
    if policy.classification_rank.is_empty()
        || policy.classification_by_data_class.is_empty()
        || policy.classification_by_label.is_empty()
        || policy.approved_purposes.is_empty()
        || policy.maximum_labels == 0
        || policy.maximum_labels > 64
        || policy.maximum_controls == 0
        || policy.maximum_controls > 64
    {
        return Err("classification_policy_incomplete_or_unbounded");
    }

    let mut ranks = BTreeSet::new();
    for (classification, rank) in &policy.classification_rank {
        if !valid_identifier(classification) || !ranks.insert(*rank) {
            return Err("classification_rank_malformed_or_ambiguous");
        }
    }

    for (data_class, classification) in &policy.classification_by_data_class {
        if !valid_identifier(data_class) || !policy.classification_rank.contains_key(classification) {
            return Err("data_class_mapping_invalid");
        }
    }

    for (label, classification) in &policy.classification_by_label {
        if !valid_identifier(label) || !policy.classification_rank.contains_key(classification) {
            return Err("label_mapping_invalid");
        }
    }

    for purpose in &policy.approved_purposes {
        if !valid_purpose(purpose) {
            return Err("approved_purpose_malformed");
        }
    }

    for classification in policy.classification_rank.keys() {
        let controls = policy
            .controls_by_classification
            .get(classification)
            .ok_or("handling_controls_missing_for_classification")?;
        if controls.is_empty() || controls.len() > policy.maximum_controls {
            return Err("handling_controls_outside_policy");
        }
        let mut control_ids = BTreeSet::new();
        for control in controls {
            if !valid_identifier(&control.control_id)
                || !valid_restrictive_action(&control.action)
                || !valid_identifier(&control.scope)
                || control.rationale.trim().is_empty()
                || control.rationale.len() > 512
                || control.rationale.trim() != control.rationale
                || !control_ids.insert(control.control_id.as_str())
            {
                return Err("handling_control_malformed_non_restrictive_or_duplicate");
            }
        }
    }

    if policy
        .controls_by_classification
        .keys()
        .any(|classification| !policy.classification_rank.contains_key(classification))
    {
        return Err("handling_controls_reference_unknown_classification");
    }

    Ok(())
}

/// Classify memory using explicit policy mappings. A greater rank is more
/// restrictive. Controls only restrict handling; this evaluator never grants
/// disclosure, access, sharing, or execution authority.
pub fn evaluate_memory_classification(
    input: &MemoryClassificationInput,
    policy: &MemoryClassificationPolicy,
) -> Result<MemoryClassificationOutput, String> {
    if !valid_identifier(&input.memory_id) || !valid_identifier(&input.owner_id) {
        return Err("memory_identity_or_owner_invalid".into());
    }
    if !valid_digest(&input.content_digest) {
        return Err("content_digest_invalid".into());
    }
    if !policy.approved_purposes.contains(&input.purpose) {
        return Err("purpose_not_approved".into());
    }
    if input.provenance.is_empty()
        || input.version_bound_evidence.is_empty()
        || input.version_bound_evidence.contains_key(POLICY_DIGEST_KEY)
    {
        return Err("provenance_or_version_evidence_missing_or_reserved".into());
    }
    if input.labels.is_empty() || input.labels.len() > policy.maximum_labels {
        return Err("label_count_outside_policy".into());
    }
    validate_policy(policy).map_err(str::to_owned)?;

    let base_classification = policy
        .classification_by_data_class
        .get(&input.data_class)
        .ok_or_else(|| "data_class_not_approved".to_owned())?;

    let mut classifications = vec![base_classification.as_str()];
    let mut seen_labels = BTreeSet::new();
    for label in &input.labels {
        if !valid_identifier(label) || !seen_labels.insert(label.as_str()) {
            return Err("labels_must_be_unique_exact_policy_identifiers".into());
        }
        let classification = policy
            .classification_by_label
            .get(label)
            .ok_or_else(|| "label_not_approved".to_owned())?;
        classifications.push(classification);
    }

    let mut selected: Option<(&str, u32)> = None;
    for classification in classifications {
        let rank = *policy
            .classification_rank
            .get(classification)
            .ok_or_else(|| "classification_rank_missing".to_owned())?;
        if selected.map_or(true, |(_, current_rank)| rank > current_rank) {
            selected = Some((classification, rank));
        }
    }
    let (classification, _) =
        selected.ok_or_else(|| "classification_not_resolved".to_owned())?;

    let controls = policy
        .controls_by_classification
        .get(classification)
        .ok_or_else(|| "handling_controls_missing".to_owned())?;
    if controls.is_empty() || controls.len() > policy.maximum_controls {
        return Err("handling_controls_outside_policy".into());
    }

    let policy_bytes = canonical(policy)
        .ok_or_else(|| "classification_policy_canonicalization_failed".to_owned())?;
    let policy_digest = digest(&policy_bytes);
    let mut version_bound_evidence = input.version_bound_evidence.clone();
    version_bound_evidence.insert(
        POLICY_DIGEST_KEY.to_owned(),
        Value::String(policy_digest.clone()),
    );

    Ok(MemoryClassificationOutput {
        memory_id: input.memory_id.clone(),
        classification: classification.to_owned(),
        handling_controls: controls.clone(),
        classification_rationale: format!(
            "highest explicit classification rank selected from approved data-class and exact-label mappings; policy_sha256={policy_digest}"
        ),
        evidence: MemoryClassificationEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn control(id: &str, action: &str) -> MemoryHandlingControl {
        MemoryHandlingControl {
            control_id: id.into(),
            action: action.into(),
            scope: "memory:all".into(),
            rationale: "enforce the approved classification handling boundary".into(),
            mandatory: true,
        }
    }

    fn policy() -> MemoryClassificationPolicy {
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
                ("public".into(), vec![control("public-restrict-retention", "restrict_retention")]),
                ("internal".into(), vec![control("internal-restrict-export", "restrict_export")]),
                ("confidential".into(), vec![control("confidential-require-encryption", "require_encryption_at_rest")]),
                (
                    "restricted".into(),
                    vec![
                        control("restricted-require-encryption", "require_encryption_at_rest"),
                        control("restricted-deny-export", "deny_export"),
                    ],
                ),
            ]),
            BTreeSet::from([
                "TASK_CONTINUITY".into(),
                "USER_PREFERENCE".into(),
                "PROJECT_CONTEXT".into(),
                "ORGANIZATIONAL_CONTEXT".into(),
                "OPERATIONAL_HISTORY".into(),
                "AUTHORIZED_SYSTEM_ASSURANCE".into(),
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
            purpose: "TASK_CONTINUITY".into(),
            owner_id: "owner-001".into(),
            data_class: "public".into(),
            provenance: BTreeMap::from([("source".into(), json!("synthetic"))]),
            version_bound_evidence: BTreeMap::from([("genome_digest".into(), json!("b".repeat(64)))]),
        }
    }

    #[test]
    fn selects_highest_explicit_classification_rank() {
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
    fn restricted_label_applies_only_restrictive_controls() {
        let mut value = input();
        value.labels = vec!["legal_hold".into()];
        let result = evaluate_memory_classification(&value, &policy()).unwrap();
        assert_eq!(result.classification, "restricted");
        assert!(result.handling_controls.iter().any(|item| item.action == "deny_export"));
        assert!(result.handling_controls.iter().all(|item| valid_restrictive_action(&item.action)));
    }

    #[test]
    fn rejects_unknown_normalized_duplicate_and_malformed_labels() {
        let mut value = input();
        value.labels = vec!["PII".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("labels_must_be_unique_exact_policy_identifiers".into()));
        value.labels = vec!["pii ".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("labels_must_be_unique_exact_policy_identifiers".into()));
        value.labels = vec!["unknown".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("label_not_approved".into()));
        value.labels = vec!["pii".into(), "pii".into()];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("labels_must_be_unique_exact_policy_identifiers".into()));
    }

    #[test]
    fn rejects_unapproved_purpose_data_class_and_bad_digest() {
        let mut value = input();
        value.purpose = "TASK_CONTINUITY ".into();
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("purpose_not_approved".into()));
        value = input();
        value.data_class = "unknown".into();
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("data_class_not_approved".into()));
        value = input();
        value.content_digest = "not-a-digest".into();
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("content_digest_invalid".into()));
    }

    #[test]
    fn rejects_missing_evidence_and_reserved_policy_digest_key() {
        let mut value = input();
        value.provenance.clear();
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("provenance_or_version_evidence_missing_or_reserved".into()));
        value = input();
        value.version_bound_evidence.insert(POLICY_DIGEST_KEY.into(), json!("caller-controlled"));
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("provenance_or_version_evidence_missing_or_reserved".into()));
    }

    #[test]
    fn rejects_ambiguous_policy_rank_and_non_restrictive_controls() {
        let mut value = policy();
        value.classification_rank.insert("restricted".into(), 1);
        assert_eq!(validate_policy(&value), Err("classification_rank_malformed_or_ambiguous"));
        value = policy();
        value.controls_by_classification.get_mut("internal").unwrap()[0].action = "grant_access".into();
        assert_eq!(validate_policy(&value), Err("handling_control_malformed_non_restrictive_or_duplicate"));
    }

    #[test]
    fn binds_policy_digest_and_matches_closed_output_contract() {
        let result = evaluate_memory_classification(&input(), &policy()).unwrap();
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(
            value.as_object().unwrap().keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "memory_id".into(),
                "classification".into(),
                "handling_controls".into(),
                "classification_rationale".into(),
                "evidence".into(),
            ])
        );
        let evidence = value.get("evidence").unwrap();
        assert!(evidence.get("provenance").is_some());
        let bound = evidence.get("version_bound_evidence").unwrap();
        assert_eq!(bound.get(POLICY_DIGEST_KEY).and_then(Value::as_str).unwrap().len(), 64);
        assert!(value.get("version_bound_evidence").is_none());
    }

    #[test]
    fn enforces_policy_label_and_control_bounds() {
        let mut value = input();
        value.labels = vec!["team_only".into(); 17];
        assert_eq!(evaluate_memory_classification(&value, &policy()), Err("label_count_outside_policy".into()));
        let mut p = policy();
        p.maximum_controls = 1;
        assert_eq!(validate_policy(&p), Err("handling_controls_outside_policy"));
    }
}
