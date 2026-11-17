//! A3 G02 authority-source resolver. Validation only; it never grants execution authority.
use crate::{canonical_json, Ed25519CredentialVerifier, RevocationChecker};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySourceType {
    Owner,
    Delegated,
    Statutory,
    System,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Active,
    Suspended,
    Revoked,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityDecision {
    Valid,
    Invalid,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPrincipalRegistration {
    pub authority_id: String,
    pub source_type: AuthoritySourceType,
    pub issuer_id: String,
    pub key_id: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub status: AuthorityStatus,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityMandate {
    pub mandate_ref: String,
    pub authority_id: String,
    pub source_type: AuthoritySourceType,
    pub issuer_id: String,
    pub key_id: String,
    pub scope: Vec<String>,
    pub delegation_chain: Vec<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub allow_unbounded: bool,
    pub status: AuthorityStatus,
    pub provenance_digest: String,
    pub version_bound_evidence_digest: String,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySourceInput {
    pub authority_id: String,
    pub source_type: AuthoritySourceType,
    pub mandate_ref: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub principal_registration: SignedPrincipalRegistration,
    pub mandate: SignedAuthorityMandate,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySourcePolicy {
    allowed_source_types: BTreeSet<AuthoritySourceType>,
    unbounded_source_types: BTreeSet<AuthoritySourceType>,
}
impl AuthoritySourcePolicy {
    pub fn new(
        allowed_source_types: BTreeSet<AuthoritySourceType>,
        unbounded_source_types: BTreeSet<AuthoritySourceType>,
    ) -> Self {
        Self {
            allowed_source_types,
            unbounded_source_types,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySourceEvidence {
    pub principal_registration_verified: bool,
    pub source_class_verified: bool,
    pub mandate_signature_verified: bool,
    pub mandate_scope_verified: bool,
    pub temporal_validity_verified: bool,
    pub revocation_checked: bool,
    pub delegation_chain_verified: bool,
    pub evaluated_at: String,
    pub provenance: BTreeMap<String, Value>,
    pub decision_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySourceOutput {
    pub authority_id: String,
    pub source_valid: bool,
    pub scope: Vec<String>,
    pub decision: AuthorityDecision,
    pub evidence: AuthoritySourceEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct RegistrationPayload<'a> {
    authority_id: &'a str,
    source_type: AuthoritySourceType,
    issuer_id: &'a str,
    key_id: &'a str,
    valid_from: &'a str,
    valid_until: &'a Option<String>,
    status: AuthorityStatus,
}
#[derive(Serialize)]
struct MandatePayload<'a> {
    mandate_ref: &'a str,
    authority_id: &'a str,
    source_type: AuthoritySourceType,
    issuer_id: &'a str,
    key_id: &'a str,
    scope: &'a [String],
    delegation_chain: &'a [String],
    valid_from: &'a str,
    valid_until: &'a Option<String>,
    allow_unbounded: bool,
    status: AuthorityStatus,
    provenance_digest: &'a str,
    version_bound_evidence_digest: &'a str,
}
fn canonical<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).ok()?).ok()
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn map_digest(value: &BTreeMap<String, Value>) -> Option<String> {
    Some(digest(&canonical(value)?))
}
fn parse_utc(value: &str) -> Option<u64> {
    let b = value.as_bytes();
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
    let part = |a: usize, z: usize| -> Option<i64> {
        let s = std::str::from_utf8(&b[a..z]).ok()?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let y = part(0, 4)?;
    let m = part(5, 7)?;
    let d = part(8, 10)?;
    let h = part(11, 13)?;
    let min = part(14, 16)?;
    let sec = part(17, 19)?;
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&min)
        || !(0..=59).contains(&sec)
    {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_month = [
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
    if d < 1 || d > days_in_month[(m - 1) as usize] {
        return None;
    }
    let yy = y - if m <= 2 { 1 } else { 0 };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    u64::try_from(days * 86_400 + h * 3_600 + min * 60 + sec).ok()
}
fn decision(
    input: &AuthoritySourceInput,
    now: u64,
    reason: &str,
    expired: bool,
    principal_ok: bool,
    class_ok: bool,
    mandate_ok: bool,
    scope_ok: bool,
    temporal_ok: bool,
    revocation_ok: bool,
    delegation_ok: bool,
) -> AuthoritySourceOutput {
    AuthoritySourceOutput {
        authority_id: input.authority_id.clone(),
        source_valid: false,
        scope: Vec::new(),
        decision: if expired {
            AuthorityDecision::Expired
        } else {
            AuthorityDecision::Invalid
        },
        evidence: AuthoritySourceEvidence {
            principal_registration_verified: principal_ok,
            source_class_verified: class_ok,
            mandate_signature_verified: mandate_ok,
            mandate_scope_verified: scope_ok,
            temporal_validity_verified: temporal_ok,
            revocation_checked: revocation_ok,
            delegation_chain_verified: delegation_ok,
            evaluated_at: format_utc(now),
            provenance: input.provenance.clone(),
            decision_reason: reason.into(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}
fn format_utc(seconds: u64) -> String {
    // Evaluated-at is recorded as Unix seconds to avoid local-time ambiguity.
    format!("unix:{seconds}")
}

/// Validate a principal registration and signed mandate. The returned scope is
/// informational evidence only: it does not authorize an operation or create authority.
pub fn evaluate_authority_source<R: RevocationChecker>(
    input: &AuthoritySourceInput,
    policy: &AuthoritySourcePolicy,
    verifier: &Ed25519CredentialVerifier<R>,
    now: u64,
) -> AuthoritySourceOutput {
    if input.authority_id.trim().is_empty()
        || input.mandate_ref.trim().is_empty()
        || input.provenance.is_empty()
        || input.version_bound_evidence.is_empty()
    {
        return decision(
            input,
            now,
            "required_input_missing",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    let registration = &input.principal_registration;
    let mandate = &input.mandate;
    if registration.authority_id != input.authority_id
        || mandate.authority_id != input.authority_id
        || mandate.mandate_ref != input.mandate_ref
        || mandate.source_type != input.source_type
        || registration.source_type != input.source_type
        || mandate.valid_from != input.valid_from
        || mandate.valid_until != input.valid_until
    {
        return decision(
            input,
            now,
            "principal_or_mandate_binding_mismatch",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    if !policy.allowed_source_types.contains(&input.source_type) {
        return decision(
            input,
            now,
            "source_class_not_permitted_by_policy",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    let Some(reg_from) = parse_utc(&registration.valid_from) else {
        return decision(
            input,
            now,
            "registration_timestamp_noncanonical",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    };
    let reg_until = match &registration.valid_until {
        Some(v) => match parse_utc(v) {
            Some(t) => Some(t),
            None => {
                return decision(
                    input,
                    now,
                    "registration_expiry_noncanonical",
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                )
            }
        },
        None => None,
    };
    let Some(mandate_from) = parse_utc(&mandate.valid_from) else {
        return decision(
            input,
            now,
            "mandate_timestamp_noncanonical",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    };
    let mandate_until = match &mandate.valid_until {
        Some(v) => match parse_utc(v) {
            Some(t) => Some(t),
            None => {
                return decision(
                    input,
                    now,
                    "mandate_expiry_noncanonical",
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                )
            }
        },
        None => None,
    };
    if reg_until.is_some_and(|v| v <= reg_from) || mandate_until.is_some_and(|v| v <= mandate_from)
    {
        return decision(
            input,
            now,
            "validity_interval_not_increasing",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    let unbounded_allowed =
        policy.unbounded_source_types.contains(&input.source_type) && mandate.allow_unbounded;
    if (reg_until.is_none() || mandate_until.is_none()) && !unbounded_allowed {
        return decision(
            input,
            now,
            "unbounded_expiry_not_permitted",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    let principal_payload = RegistrationPayload {
        authority_id: &registration.authority_id,
        source_type: registration.source_type,
        issuer_id: &registration.issuer_id,
        key_id: &registration.key_id,
        valid_from: &registration.valid_from,
        valid_until: &registration.valid_until,
        status: registration.status,
    };
    let mandate_payload = MandatePayload {
        mandate_ref: &mandate.mandate_ref,
        authority_id: &mandate.authority_id,
        source_type: mandate.source_type,
        issuer_id: &mandate.issuer_id,
        key_id: &mandate.key_id,
        scope: &mandate.scope,
        delegation_chain: &mandate.delegation_chain,
        valid_from: &mandate.valid_from,
        valid_until: &mandate.valid_until,
        allow_unbounded: mandate.allow_unbounded,
        status: mandate.status,
        provenance_digest: &mandate.provenance_digest,
        version_bound_evidence_digest: &mandate.version_bound_evidence_digest,
    };
    let Some(principal_bytes) = canonical(&principal_payload) else {
        return decision(
            input,
            now,
            "registration_canonicalization_failed",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    };
    let Some(mandate_bytes) = canonical(&mandate_payload) else {
        return decision(
            input,
            now,
            "mandate_canonicalization_failed",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    };
    let principal_ok = verifier
        .verify_detached_payload(
            &registration.issuer_id,
            &registration.key_id,
            &principal_bytes,
            &registration.signature,
            now,
        )
        .is_ok();
    if !principal_ok {
        return decision(
            input,
            now,
            "principal_registration_signature_or_trust_invalid",
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    let mandate_ok = verifier
        .verify_detached_payload(
            &mandate.issuer_id,
            &mandate.key_id,
            &mandate_bytes,
            &mandate.signature,
            now,
        )
        .is_ok();
    if !mandate_ok {
        return decision(
            input,
            now,
            "mandate_signature_or_trust_invalid",
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
        );
    }
    if registration.status != AuthorityStatus::Active || mandate.status != AuthorityStatus::Active {
        return decision(
            input,
            now,
            "principal_or_mandate_not_active",
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
        );
    }
    if mandate.scope.is_empty()
        || mandate.scope.iter().any(|s| s.trim().is_empty())
        || mandate.scope.iter().collect::<BTreeSet<_>>().len() != mandate.scope.len()
    {
        return decision(
            input,
            now,
            "mandate_scope_empty_or_ambiguous",
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
        );
    }
    let delegation_ok = if input.source_type == AuthoritySourceType::Delegated {
        !mandate.delegation_chain.is_empty()
            && mandate
                .delegation_chain
                .last()
                .is_some_and(|v| v == &input.authority_id)
            && mandate
                .delegation_chain
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == mandate.delegation_chain.len()
    } else {
        mandate.delegation_chain.is_empty()
    };
    if !delegation_ok {
        return decision(
            input,
            now,
            "delegation_chain_invalid",
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            false,
        );
    }
    if map_digest(&input.provenance).as_deref() != Some(mandate.provenance_digest.as_str())
        || map_digest(&input.version_bound_evidence).as_deref()
            != Some(mandate.version_bound_evidence_digest.as_str())
    {
        return decision(
            input,
            now,
            "provenance_or_version_evidence_commitment_mismatch",
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            delegation_ok,
        );
    }
    let temporal = (now >= reg_from && reg_until.is_none_or(|v| now < v))
        && (now >= mandate_from && mandate_until.is_none_or(|v| now < v));
    if !temporal {
        let expired =
            reg_until.is_some_and(|v| now >= v) || mandate_until.is_some_and(|v| now >= v);
        return decision(
            input,
            now,
            "principal_or_mandate_outside_validity_window",
            expired,
            true,
            true,
            true,
            true,
            false,
            true,
            delegation_ok,
        );
    }
    AuthoritySourceOutput {
        authority_id: input.authority_id.clone(),
        source_valid: true,
        scope: mandate.scope.clone(),
        decision: AuthorityDecision::Valid,
        evidence: AuthoritySourceEvidence {
            principal_registration_verified: true,
            source_class_verified: true,
            mandate_signature_verified: true,
            mandate_scope_verified: true,
            temporal_validity_verified: true,
            revocation_checked: true,
            delegation_chain_verified: true,
            evaluated_at: format_utc(now),
            provenance: input.provenance.clone(),
            decision_reason: "authority_source_verified".into(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NoRevocations, TrustStore, TrustedKey};
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (
        Ed25519CredentialVerifier<NoRevocations>,
        AuthoritySourceInput,
        AuthoritySourcePolicy,
    ) {
        let signer = SigningKey::from_bytes(&[62u8; 32]);
        let issuer = "registry:iroka";
        let kid = "registry-key";
        let trust = TrustStore::new(
            [issuer],
            vec![TrustedKey {
                issuer: issuer.into(),
                key_id: kid.into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 1_700_000_000,
                not_after: 2_000_000_000,
            }],
        )
        .unwrap();
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        let provenance = BTreeMap::from([("source".into(), serde_json::json!("signed-registry"))]);
        let version = BTreeMap::from([("genome_digest".into(), serde_json::json!("b".repeat(64)))]);
        let pd = digest(&canonical(&provenance).unwrap());
        let vd = digest(&canonical(&version).unwrap());
        let mut registration = SignedPrincipalRegistration {
            authority_id: "principal:owner-1".into(),
            source_type: AuthoritySourceType::Owner,
            issuer_id: issuer.into(),
            key_id: kid.into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: Some("2027-01-01T00:00:00Z".into()),
            status: AuthorityStatus::Active,
            signature: vec![],
        };
        let rp = RegistrationPayload {
            authority_id: &registration.authority_id,
            source_type: registration.source_type,
            issuer_id: &registration.issuer_id,
            key_id: &registration.key_id,
            valid_from: &registration.valid_from,
            valid_until: &registration.valid_until,
            status: registration.status,
        };
        registration.signature = signer.sign(&canonical(&rp).unwrap()).to_bytes().to_vec();
        let mut mandate = SignedAuthorityMandate {
            mandate_ref: "mandate:owner-1".into(),
            authority_id: registration.authority_id.clone(),
            source_type: AuthoritySourceType::Owner,
            issuer_id: issuer.into(),
            key_id: kid.into(),
            scope: vec!["governance.decide".into()],
            delegation_chain: vec![],
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: Some("2027-01-01T00:00:00Z".into()),
            allow_unbounded: false,
            status: AuthorityStatus::Active,
            provenance_digest: pd,
            version_bound_evidence_digest: vd,
            signature: vec![],
        };
        let mp = MandatePayload {
            mandate_ref: &mandate.mandate_ref,
            authority_id: &mandate.authority_id,
            source_type: mandate.source_type,
            issuer_id: &mandate.issuer_id,
            key_id: &mandate.key_id,
            scope: &mandate.scope,
            delegation_chain: &mandate.delegation_chain,
            valid_from: &mandate.valid_from,
            valid_until: &mandate.valid_until,
            allow_unbounded: mandate.allow_unbounded,
            status: mandate.status,
            provenance_digest: &mandate.provenance_digest,
            version_bound_evidence_digest: &mandate.version_bound_evidence_digest,
        };
        mandate.signature = signer.sign(&canonical(&mp).unwrap()).to_bytes().to_vec();
        let input = AuthoritySourceInput {
            authority_id: registration.authority_id.clone(),
            source_type: AuthoritySourceType::Owner,
            mandate_ref: mandate.mandate_ref.clone(),
            valid_from: mandate.valid_from.clone(),
            valid_until: mandate.valid_until.clone(),
            principal_registration: registration,
            mandate,
            provenance,
            version_bound_evidence: version,
        };
        (
            verifier,
            input,
            AuthoritySourcePolicy::new(
                [AuthoritySourceType::Owner].into_iter().collect(),
                BTreeSet::new(),
            ),
        )
    }
    #[test]
    fn accepts_signed_registered_owner_mandate() {
        let (v, i, p) = fixture();
        let o = evaluate_authority_source(&i, &p, &v, 1_767_225_600);
        assert!(o.source_valid);
        assert_eq!(o.scope, vec!["governance.decide"]);
    }
    #[test]
    fn rejects_source_class_and_scope_substitution() {
        let (v, mut i, p) = fixture();
        i.source_type = AuthoritySourceType::System;
        assert!(!evaluate_authority_source(&i, &p, &v, 1_767_225_600).source_valid);
        let (v, mut i, p) = fixture();
        i.mandate.scope.push("system.execute".into());
        assert!(!evaluate_authority_source(&i, &p, &v, 1_767_225_600).source_valid);
    }
    #[test]
    fn rejects_noncanonical_or_expired_time() {
        let (v, mut i, p) = fixture();
        i.valid_from = "2026-01-01 00:00:00".into();
        assert!(!evaluate_authority_source(&i, &p, &v, 1_767_225_600).source_valid);
        let (v, mut i, p) = fixture();
        assert_eq!(
            evaluate_authority_source(&i, &p, &v, 1_900_000_000).decision,
            AuthorityDecision::Expired
        );
    }
}
