//! G06 perception-transform registry and provenance validation.
//! This module validates registered transform metadata and receipts; it never executes transforms.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerceptionTransformInput {
    pub envelope_id: String,
    pub transform_id: String,
    pub transform_version: String,
    pub modality: String,
    pub output_type: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerceptionLossAnnotation {
    pub annotation_id: String,
    pub loss_type: String,
    pub source_segment: String,
    pub description: String,
    pub impact: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerceptionTransformRegistration {
    pub transform_id: String,
    pub transform_version: String,
    pub modality: String,
    pub allowed_output_types: BTreeSet<String>,
    pub transform_digest: String,
    pub loss_annotations: Vec<PerceptionLossAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerceptionTransformPolicy {
    pub registrations: BTreeMap<String, PerceptionTransformRegistration>,
    pub maximum_loss_annotations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerceptionTransformEvidence {
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerceptionTransformOutput {
    pub transform_id: String,
    pub output_digest: String,
    pub output_type: String,
    pub source_envelope_digest: String,
    pub loss_annotations: Vec<PerceptionLossAnnotation>,
    pub transform_status: String,
    pub evidence: PerceptionTransformEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

fn canonical<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    crate::canonical_json(&serde_json::to_value(value).ok()?).ok()
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

fn valid_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

/// Validate transform identity, exact version, modality, output type and receipt digests.
/// The returned status is degraded whenever the registered transform declares information loss.
pub fn evaluate_perception_transform(
    input: &PerceptionTransformInput,
    policy: &PerceptionTransformPolicy,
) -> Result<PerceptionTransformOutput, String> {
    if !valid_identifier(&input.envelope_id)
        || !valid_identifier(&input.transform_id)
        || !valid_version(&input.transform_version)
        || input.modality.trim().is_empty()
        || input.output_type.trim().is_empty()
    {
        return Err("transform_identity_or_type_invalid".into());
    }
    if input.provenance.is_empty() || input.version_bound_evidence.is_empty() {
        return Err("provenance_or_version_evidence_missing".into());
    }
    let Some(registration) = policy.registrations.get(&input.transform_id) else {
        return Err("transform_not_registered".into());
    };
    if registration.transform_id != input.transform_id
        || registration.transform_version != input.transform_version
    {
        return Err("transform_registration_version_mismatch".into());
    }
    if registration.modality != input.modality {
        return Err("transform_modality_mismatch".into());
    }
    if !registration.allowed_output_types.contains(&input.output_type) {
        return Err("transform_output_type_not_approved".into());
    }
    if !valid_digest(&registration.transform_digest) {
        return Err("registered_transform_digest_invalid".into());
    }
    if registration.loss_annotations.len() > policy.maximum_loss_annotations {
        return Err("loss_annotation_count_exceeds_policy".into());
    }
    let Some(source_digest) = input
        .version_bound_evidence
        .get("source_envelope_digest")
        .and_then(Value::as_str)
    else {
        return Err("source_envelope_digest_missing".into());
    };
    let Some(output_digest) = input
        .version_bound_evidence
        .get("output_digest")
        .and_then(Value::as_str)
    else {
        return Err("output_digest_missing".into());
    };
    let Some(registered_digest) = input
        .version_bound_evidence
        .get("transform_digest")
        .and_then(Value::as_str)
    else {
        return Err("transform_digest_evidence_missing".into());
    };
    if !valid_digest(source_digest) || !valid_digest(output_digest) {
        return Err("source_or_output_digest_invalid".into());
    }
    if registered_digest != registration.transform_digest {
        return Err("transform_digest_evidence_mismatch".into());
    }
    let mut annotation_ids = BTreeSet::new();
    for annotation in &registration.loss_annotations {
        if !valid_identifier(&annotation.annotation_id)
            || annotation.loss_type.trim().is_empty()
            || annotation.source_segment.trim().is_empty()
            || annotation.description.trim().is_empty()
            || annotation.impact.trim().is_empty()
            || annotation.severity.trim().is_empty()
            || !annotation_ids.insert(annotation.annotation_id.as_str())
        {
            return Err("loss_annotation_malformed_or_duplicate".into());
        }
    }
    if canonical(&input.provenance).is_none()
        || canonical(&input.version_bound_evidence).is_none()
        || canonical(policy).is_none()
    {
        return Err("transform_evidence_canonicalization_failed".into());
    }
    Ok(PerceptionTransformOutput {
        transform_id: input.transform_id.clone(),
        output_digest: output_digest.to_owned(),
        output_type: input.output_type.clone(),
        source_envelope_digest: source_digest.to_owned(),
        loss_annotations: registration.loss_annotations.clone(),
        transform_status: if registration.loss_annotations.is_empty() {
            "success".into()
        } else {
            "degraded".into()
        },
        evidence: PerceptionTransformEvidence {
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

    fn annotation() -> PerceptionLossAnnotation {
        PerceptionLossAnnotation {
            annotation_id: "loss-001".into(),
            loss_type: "resolution_reduction".into(),
            source_segment: "frame:0".into(),
            description: "Downsampled source frame".into(),
            impact: "Fine detail may be unavailable".into(),
            severity: "moderate".into(),
        }
    }

    fn policy(lossy: bool) -> PerceptionTransformPolicy {
        PerceptionTransformPolicy {
            registrations: BTreeMap::from([(
                "image-resize".into(),
                PerceptionTransformRegistration {
                    transform_id: "image-resize".into(),
                    transform_version: "1.0.0".into(),
                    modality: "image".into(),
                    allowed_output_types: ["image/webp".into()].into_iter().collect(),
                    transform_digest: "c".repeat(64),
                    loss_annotations: if lossy { vec![annotation()] } else { Vec::new() },
                },
            )]),
            maximum_loss_annotations: 8,
        }
    }

    fn input() -> PerceptionTransformInput {
        PerceptionTransformInput {
            envelope_id: "envelope-001".into(),
            transform_id: "image-resize".into(),
            transform_version: "1.0.0".into(),
            modality: "image".into(),
            output_type: "image/webp".into(),
            provenance: BTreeMap::from([("source".into(), json!("synthetic"))]),
            version_bound_evidence: BTreeMap::from([
                ("source_envelope_digest".into(), json!("a".repeat(64))),
                ("output_digest".into(), json!("b".repeat(64))),
                ("transform_digest".into(), json!("c".repeat(64))),
            ]),
        }
    }

    #[test]
    fn validates_registered_transform_receipt() {
        let result = evaluate_perception_transform(&input(), &policy(false)).unwrap();
        assert_eq!(result.transform_status, "success");
        assert!(result.loss_annotations.is_empty());
    }

    #[test]
    fn marks_lossy_transform_as_degraded_and_discloses_loss() {
        let result = evaluate_perception_transform(&input(), &policy(true)).unwrap();
        assert_eq!(result.transform_status, "degraded");
        assert_eq!(result.loss_annotations.len(), 1);
    }

    #[test]
    fn rejects_unregistered_or_substituted_transform_metadata() {
        let mut value = input();
        value.transform_id = "unknown-transform".into();
        assert_eq!(evaluate_perception_transform(&value, &policy(false)), Err("transform_not_registered".into()));
        let mut value = input();
        value.modality = "audio".into();
        assert_eq!(evaluate_perception_transform(&value, &policy(false)), Err("transform_modality_mismatch".into()));
        let mut value = input();
        value.version_bound_evidence.insert("transform_digest".into(), json!("d".repeat(64)));
        assert_eq!(evaluate_perception_transform(&value, &policy(false)), Err("transform_digest_evidence_mismatch".into()));
    }

    #[test]
    fn rejects_missing_or_invalid_receipt_digests() {
        let mut value = input();
        value.version_bound_evidence.remove("output_digest");
        assert_eq!(evaluate_perception_transform(&value, &policy(false)), Err("output_digest_missing".into()));
        let mut value = input();
        value.version_bound_evidence.insert("output_digest".into(), json!("bad"));
        assert_eq!(evaluate_perception_transform(&value, &policy(false)), Err("source_or_output_digest_invalid".into()));
    }
}
