//! G03 uncertainty calculus with explicit calibration and evidence disposition.
use crate::canonical_json;
use crate::EpistemicStatus;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDirection {
    Supports,
    Refutes,
    Neutral,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationStatus {
    Validated,
    Unvalidated,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyMethod {
    WeightedLogOddsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WeightedEvidence {
    pub evidence_id: String,
    pub direction: EvidenceDirection,
    pub weight: f64,
    pub reliability: f64,
    pub epistemic_status: EpistemicStatus,
    pub source_digest: String,
    pub provenance_ref: String,
    pub observed_at: String,
    pub valid_until: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyHypothesis {
    pub hypothesis_id: String,
    pub statement: String,
    pub prior_probability: f64,
    pub evidence: Vec<WeightedEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CalibrationProfile {
    pub profile_id: String,
    pub profile_version: String,
    pub status: CalibrationStatus,
    pub dataset_digest: String,
    pub support_likelihood_ratio: f64,
    pub refute_likelihood_ratio: f64,
    pub probability_floor: f64,
    pub probability_ceiling: f64,
    pub validated_at: String,
    pub valid_until: String,
    pub calibrator_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyInput {
    pub inference_id: String,
    pub premise_set_digest: String,
    pub context_id: String,
    pub calculation_method: UncertaintyMethod,
    pub method_version: String,
    pub calibration_profile: CalibrationProfile,
    pub hypotheses: Vec<UncertaintyHypothesis>,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncertaintyPolicy {
    method_version: String,
    calibration_profile_id: String,
    calibration_profile_digest: String,
    maximum_hypotheses: usize,
    maximum_evidence_per_hypothesis: usize,
}
impl UncertaintyPolicy {
    pub fn new(
        method_version: String,
        calibration_profile_id: String,
        calibration_profile_digest: String,
        maximum_hypotheses: usize,
        maximum_evidence_per_hypothesis: usize,
    ) -> Self {
        Self {
            method_version,
            calibration_profile_id,
            calibration_profile_digest,
            maximum_hypotheses,
            maximum_evidence_per_hypothesis,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HypothesisEstimate {
    pub hypothesis_id: String,
    pub statement: String,
    pub prior_probability: Option<f64>,
    pub posterior_probability: Option<f64>,
    pub normalized_entropy: Option<f64>,
    pub supporting_evidence_count: u64,
    pub refuting_evidence_count: u64,
    pub evidence_conflict: bool,
    pub used_evidence_ids: Vec<String>,
    pub uncertainty_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedEvidence {
    pub hypothesis_id: String,
    pub evidence_id: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyEvidence {
    pub method_version: String,
    pub calibration_profile_id: String,
    pub calibration_profile_digest: String,
    pub calibration_dataset_digest: String,
    pub inference_id: String,
    pub premise_set_digest: String,
    pub input_hypothesis_count: u64,
    pub total_evidence_count: u64,
    pub used_evidence_count: u64,
    pub unresolved_evidence_count: u64,
    pub complete_disposition: bool,
    pub probability_semantics: String,
    pub normalization_scope: String,
    pub calculation_digest: String,
    pub decision_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyOutput {
    pub calculation_valid: bool,
    pub hypothesis_estimates: Vec<HypothesisEstimate>,
    pub unresolved_evidence: Vec<UnresolvedEvidence>,
    pub evidence: UncertaintyEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
fn canonical<T: Serialize>(v: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(v).ok()?).ok()
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn parse_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let p = |a: usize, z: usize| -> Option<i64> {
        let v = std::str::from_utf8(&b[a..z]).ok()?;
        if !v.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    };
    let y = p(0, 4)?;
    let m = p(5, 7)?;
    let d = p(8, 10)?;
    let h = p(11, 13)?;
    let mi = p(14, 16)?;
    let se = p(17, 19)?;
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&mi)
        || !(0..=59).contains(&se)
    {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let md = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d < 1 || d > md[(m - 1) as usize] {
        return None;
    }
    let yy = y - if m <= 2 { 1 } else { 0 };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from((era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + se).ok()
}
fn entropy(p: f64) -> f64 {
    -(p * p.ln() + (1.0 - p) * (1.0 - p).ln()) / std::f64::consts::LN_2
}
fn profile_digest(profile: &CalibrationProfile) -> Option<String> {
    let mut bytes = b"IROKA-CALIBRATION-PROFILE-V1\0".to_vec();
    bytes.extend(canonical(profile)?);
    Some(digest(&bytes))
}
#[allow(clippy::too_many_arguments)]
fn base_evidence(
    input: &UncertaintyInput,
    profile_hash: String,
    used: u64,
    unresolved: u64,
    total: u64,
    complete: bool,
    valid: bool,
    reason: &str,
) -> UncertaintyEvidence {
    let calc = canonical(&serde_json::json!({
        "inference_id":input.inference_id,"premise_set_digest":input.premise_set_digest,
        "method_version":input.method_version,"profile_digest":profile_hash,
        "hypothesis_estimates":input.hypotheses,"provenance":input.provenance,
        "version_bound_evidence":input.version_bound_evidence
    }))
    .map(|b| digest(&b))
    .unwrap_or_default();
    UncertaintyEvidence {
        method_version: input.method_version.clone(),
        calibration_profile_id: input.calibration_profile.profile_id.clone(),
        calibration_profile_digest: profile_hash,
        calibration_dataset_digest: input.calibration_profile.dataset_digest.clone(),
        inference_id: input.inference_id.clone(),
        premise_set_digest: input.premise_set_digest.clone(),
        input_hypothesis_count: input.hypotheses.len() as u64,
        total_evidence_count: total,
        used_evidence_count: used,
        unresolved_evidence_count: unresolved,
        complete_disposition: complete,
        probability_semantics: if valid {
            "calibrated_posterior_under_registered_profile".into()
        } else {
            "no_calibrated_probability".into()
        },
        normalization_scope: "independent_per_hypothesis".into(),
        calculation_digest: calc,
        decision_reason: reason.into(),
    }
}
fn empty_estimates(input: &UncertaintyInput, reason: &str) -> Vec<HypothesisEstimate> {
    input
        .hypotheses
        .iter()
        .map(|h| HypothesisEstimate {
            hypothesis_id: h.hypothesis_id.clone(),
            statement: h.statement.clone(),
            prior_probability: if h.prior_probability.is_finite()
                && h.prior_probability > 0.0
                && h.prior_probability < 1.0
            {
                Some(h.prior_probability)
            } else {
                None
            },
            posterior_probability: None,
            normalized_entropy: None,
            supporting_evidence_count: 0,
            refuting_evidence_count: 0,
            evidence_conflict: false,
            used_evidence_ids: vec![],
            uncertainty_reason: Some(reason.into()),
        })
        .collect()
}

/// Apply a registered calibration profile to source-backed fact evidence.
/// Estimates are independent per hypothesis, not a normalized distribution across hypotheses.
pub fn evaluate_uncertainty(
    input: &UncertaintyInput,
    policy: &UncertaintyPolicy,
    now: u64,
) -> UncertaintyOutput {
    let profile = &input.calibration_profile;
    let profile_hash = profile_digest(profile).unwrap_or_default();
    let version_ok = input.method_version == policy.method_version
        && input.calculation_method == UncertaintyMethod::WeightedLogOddsV1
        && profile.profile_id == policy.calibration_profile_id
        && profile_hash == policy.calibration_profile_digest
        && input
            .version_bound_evidence
            .get("calibration_profile_digest")
            .and_then(Value::as_str)
            == Some(profile_hash.as_str())
        && input
            .version_bound_evidence
            .get("method_version")
            .and_then(Value::as_str)
            == Some(input.method_version.as_str())
        && input
            .version_bound_evidence
            .get("calculation_method")
            .and_then(Value::as_str)
            == Some("weighted_log_odds_v1")
        && input
            .version_bound_evidence
            .get("inference_id")
            .and_then(Value::as_str)
            == Some(input.inference_id.as_str())
        && input
            .version_bound_evidence
            .get("premise_set_digest")
            .and_then(Value::as_str)
            == Some(input.premise_set_digest.as_str())
        && valid_digest(&input.premise_set_digest)
        && !input.inference_id.trim().is_empty()
        && !input.context_id.trim().is_empty()
        && !input.provenance.is_empty();
    let validated_at = parse_utc(&profile.validated_at);
    let profile_until = parse_utc(&profile.valid_until);
    let profile_ok = profile.status == CalibrationStatus::Validated
        && valid_digest(&profile.dataset_digest)
        && profile.support_likelihood_ratio.is_finite()
        && profile.support_likelihood_ratio > 1.0
        && profile.refute_likelihood_ratio.is_finite()
        && profile.refute_likelihood_ratio > 1.0
        && profile.probability_floor.is_finite()
        && profile.probability_ceiling.is_finite()
        && profile.probability_floor > 0.0
        && profile.probability_floor < 0.5
        && profile.probability_ceiling > 0.5
        && profile.probability_ceiling < 1.0
        && profile.calibrator_id.trim() != ""
        && validated_at.is_some_and(|v| v <= now)
        && profile_until.is_some_and(|v| v > now);
    let mut ids = BTreeSet::new();
    let unique = input
        .hypotheses
        .iter()
        .all(|h| !h.hypothesis_id.trim().is_empty() && ids.insert(h.hypothesis_id.as_str()));
    let valid = version_ok
        && profile_ok
        && unique
        && !input.hypotheses.is_empty()
        && input.hypotheses.len() <= policy.maximum_hypotheses
        && input.hypotheses.iter().all(|h| {
            !h.statement.trim().is_empty()
                && h.prior_probability.is_finite()
                && h.prior_probability > 0.0
                && h.prior_probability < 1.0
                && h.evidence.len() <= policy.maximum_evidence_per_hypothesis
        });
    let mut estimates = Vec::new();
    let mut unresolved_items = Vec::new();
    let mut used_total = 0u64;
    let mut total = 0u64;
    if !valid {
        for h in &input.hypotheses {
            for e in &h.evidence {
                total += 1;
                unresolved_items.push(UnresolvedEvidence {
                    hypothesis_id: h.hypothesis_id.clone(),
                    evidence_id: e.evidence_id.clone(),
                    reason: "calibration_or_input_policy_invalid".into(),
                });
            }
        }
        let complete = unresolved_items.len() as u64 == total;
        let ev = base_evidence(
            input,
            profile_hash,
            0,
            total,
            total,
            complete,
            false,
            "calibration_or_input_policy_invalid",
        );
        return UncertaintyOutput {
            calculation_valid: false,
            hypothesis_estimates: empty_estimates(input, "calibration_or_input_policy_invalid"),
            unresolved_evidence: unresolved_items,
            evidence: ev,
            version_bound_evidence: input.version_bound_evidence.clone(),
        };
    }
    for h in &input.hypotheses {
        let mut evidence_ids = BTreeSet::new();
        let mut used = Vec::new();
        let mut support_count = 0u64;
        let mut refute_count = 0u64;
        let mut log_odds = (h.prior_probability / (1.0 - h.prior_probability)).ln();
        for e in &h.evidence {
            total += 1;
            let reason = if e.evidence_id.trim().is_empty()
                || !evidence_ids.insert(e.evidence_id.as_str())
            {
                "duplicate_or_empty_evidence_id"
            } else if !e.weight.is_finite()
                || !(0.0..=1.0).contains(&e.weight)
                || !e.reliability.is_finite()
                || !(0.0..=1.0).contains(&e.reliability)
            {
                "invalid_weight_or_reliability"
            } else if e.epistemic_status != EpistemicStatus::Fact {
                "non_fact_evidence_not_admissible"
            } else if !valid_digest(&e.source_digest) || e.provenance_ref.trim().is_empty() {
                "source_provenance_invalid"
            } else if parse_utc(&e.observed_at).is_none_or(|t| t > now) {
                "observation_time_invalid_or_future"
            } else if e.valid_until.as_ref().is_some_and(|v| {
                parse_utc(v).is_none_or(|t| {
                    t <= now || parse_utc(&e.observed_at).is_none_or(|observed| t <= observed)
                })
            }) {
                "evidence_expired_or_invalid"
            } else {
                ""
            };
            if !reason.is_empty() {
                unresolved_items.push(UnresolvedEvidence {
                    hypothesis_id: h.hypothesis_id.clone(),
                    evidence_id: e.evidence_id.clone(),
                    reason: reason.into(),
                });
                continue;
            }
            used.push(e.evidence_id.clone());
            used_total += 1;
            let effect = e.weight * e.reliability;
            if effect > 0.0 {
                match e.direction {
                    EvidenceDirection::Supports => {
                        support_count += 1;
                        log_odds += effect * profile.support_likelihood_ratio.ln();
                    }
                    EvidenceDirection::Refutes => {
                        refute_count += 1;
                        log_odds -= effect * profile.refute_likelihood_ratio.ln();
                    }
                    EvidenceDirection::Neutral => {}
                }
            }
        }
        used.sort();
        let informative = support_count + refute_count > 0;
        let posterior = if informative {
            let raw = 1.0 / (1.0 + (-log_odds.clamp(-700.0, 700.0)).exp());
            Some(raw.clamp(profile.probability_floor, profile.probability_ceiling))
        } else {
            None
        };
        let normalized_entropy = posterior.map(entropy);
        estimates.push(HypothesisEstimate {
            hypothesis_id: h.hypothesis_id.clone(),
            statement: h.statement.clone(),
            prior_probability: Some(h.prior_probability),
            posterior_probability: posterior,
            normalized_entropy,
            supporting_evidence_count: support_count,
            refuting_evidence_count: refute_count,
            evidence_conflict: support_count > 0 && refute_count > 0,
            used_evidence_ids: used,
            uncertainty_reason: if informative {
                None
            } else {
                Some("no_informative_valid_fact_evidence".into())
            },
        });
    }
    estimates.sort_by(|a, b| a.hypothesis_id.cmp(&b.hypothesis_id));
    unresolved_items.sort_by(|a, b| {
        (&a.hypothesis_id, &a.evidence_id).cmp(&(&b.hypothesis_id, &b.evidence_id))
    });
    let complete = used_total + unresolved_items.len() as u64 == total;
    let ev = base_evidence(
        input,
        profile_hash,
        used_total,
        unresolved_items.len() as u64,
        total,
        complete,
        true,
        "calibrated_independent_hypothesis_estimates",
    );
    UncertaintyOutput {
        calculation_valid: true,
        hypothesis_estimates: estimates,
        unresolved_evidence: unresolved_items,
        evidence: ev,
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (UncertaintyInput, UncertaintyPolicy) {
        let profile = CalibrationProfile {
            profile_id: "calibration:profile-1".into(),
            profile_version: "1.0.0".into(),
            status: CalibrationStatus::Validated,
            dataset_digest: "a".repeat(64),
            support_likelihood_ratio: 3.0,
            refute_likelihood_ratio: 3.0,
            probability_floor: 0.01,
            probability_ceiling: 0.99,
            validated_at: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            calibrator_id: "assessor:cal-1".into(),
        };
        let ph = profile_digest(&profile).unwrap();
        let hypothesis = UncertaintyHypothesis {
            hypothesis_id: "h-1".into(),
            statement: "Hypothesis A".into(),
            prior_probability: 0.5,
            evidence: vec![
                WeightedEvidence {
                    evidence_id: "e-1".into(),
                    direction: EvidenceDirection::Supports,
                    weight: 0.8,
                    reliability: 0.9,
                    epistemic_status: EpistemicStatus::Fact,
                    source_digest: "b".repeat(64),
                    provenance_ref: "source:e-1".into(),
                    observed_at: "2026-01-01T00:00:00Z".into(),
                    valid_until: None,
                },
                WeightedEvidence {
                    evidence_id: "e-2".into(),
                    direction: EvidenceDirection::Refutes,
                    weight: 0.2,
                    reliability: 0.8,
                    epistemic_status: EpistemicStatus::Fact,
                    source_digest: "c".repeat(64),
                    provenance_ref: "source:e-2".into(),
                    observed_at: "2026-01-01T00:00:00Z".into(),
                    valid_until: None,
                },
                WeightedEvidence {
                    evidence_id: "e-3".into(),
                    direction: EvidenceDirection::Supports,
                    weight: 0.9,
                    reliability: 0.9,
                    epistemic_status: EpistemicStatus::Hypothesis,
                    source_digest: "d".repeat(64),
                    provenance_ref: "source:e-3".into(),
                    observed_at: "2026-01-01T00:00:00Z".into(),
                    valid_until: None,
                },
            ],
        };
        let input = UncertaintyInput {
            inference_id: "inference:123".into(),
            premise_set_digest: "e".repeat(64),
            context_id: "ctx-1".into(),
            calculation_method: UncertaintyMethod::WeightedLogOddsV1,
            method_version: "uncertainty-1.1.0".into(),
            calibration_profile: profile,
            hypotheses: vec![hypothesis],
            provenance: BTreeMap::from([("inference".into(), serde_json::json!("synthetic"))]),
            version_bound_evidence: BTreeMap::from([
                ("inference_id".into(), serde_json::json!("inference:123")),
                (
                    "premise_set_digest".into(),
                    serde_json::json!("e".repeat(64)),
                ),
                ("calibration_profile_digest".into(), serde_json::json!(ph)),
                (
                    "method_version".into(),
                    serde_json::json!("uncertainty-1.1.0"),
                ),
                (
                    "calculation_method".into(),
                    serde_json::json!("weighted_log_odds_v1"),
                ),
            ]),
        };
        let policy = UncertaintyPolicy::new(
            "uncertainty-1.1.0".into(),
            "calibration:profile-1".into(),
            ph,
            32,
            128,
        );
        (input, policy)
    }
    #[test]
    fn computes_bounded_posterior_and_entropy_with_conflict() {
        let (i, p) = fixture();
        let o = evaluate_uncertainty(&i, &p, 1_767_225_600);
        assert!(o.calculation_valid);
        let h = &o.hypothesis_estimates[0];
        assert!(h.posterior_probability.is_some());
        assert!(h.evidence_conflict);
        assert_eq!(o.evidence.used_evidence_count, 2);
        assert_eq!(o.evidence.unresolved_evidence_count, 1);
    }
    #[test]
    fn rejects_unvalidated_or_substituted_calibration() {
        let (i, mut p) = fixture();
        let mut bad = i.clone();
        bad.calibration_profile.status = CalibrationStatus::Unvalidated;
        let o = evaluate_uncertainty(&bad, &p, 1_767_225_600);
        assert!(!o.calculation_valid);
        p.calibration_profile_digest = "f".repeat(64);
        let o = evaluate_uncertainty(&i, &p, 1_767_225_600);
        assert!(!o.calculation_valid);
    }
    #[test]
    fn refuses_future_observation_and_does_not_invent_prior_posterior() {
        let (i, p) = fixture();
        let mut future = i.clone();
        future.hypotheses[0].evidence[0].observed_at = "2027-01-01T00:00:00Z".into();
        let o = evaluate_uncertainty(&future, &p, 1_767_225_600);
        assert_eq!(o.evidence.used_evidence_count, 1);
        let mut neutral = i;
        neutral.hypotheses[0].evidence[0].direction = EvidenceDirection::Neutral;
        neutral.hypotheses[0].evidence[1].direction = EvidenceDirection::Neutral;
        let o = evaluate_uncertainty(&neutral, &p, 1_767_225_600);
        assert!(o.hypothesis_estimates[0].posterior_probability.is_none());
    }
    #[test]
    fn refuses_non_fact_evidence_and_expired_sources() {
        let (i, p) = fixture();
        let mut bad = i.clone();
        bad.hypotheses[0].evidence[0].epistemic_status = EpistemicStatus::Assumption;
        let o = evaluate_uncertainty(&bad, &p, 1_767_312_000);
        assert_eq!(o.evidence.used_evidence_count, 1);
        let mut bad = i;
        bad.hypotheses[0].evidence[0].valid_until = Some("2026-01-01T00:00:01Z".into());
        let o = evaluate_uncertainty(&bad, &p, 1_767_312_000);
        assert_eq!(o.evidence.used_evidence_count, 1);
    }
}
