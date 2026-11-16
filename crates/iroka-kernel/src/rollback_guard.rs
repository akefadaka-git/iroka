//! A3 G12 rollback guard. This evaluator is side-effect free except for the
//! explicitly one-time consumption of a valid Owner approval for an allowed rollback.
//! Evidence authenticity/revocation/replay checks are delegated to a fail-closed verifier.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    canonical_json, AuthorizationRequest, OwnerApprovalVerifier, RiskLevel, SignedOwnerApproval,
};

const ROLLBACK_SUBJECT: &str = "iroka:rollback-guard";
const ROLLBACK_CAPABILITY: &str = "system.rollback";
const CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackDenialCode {
    None,
    EvidenceInvalid,
    VersionEvidenceInvalid,
    DigestMismatch,
    RevocationFloor,
    StaleEpoch,
    EpochConflict,
    AuthorizationInvalid,
}

impl RollbackDenialCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::EvidenceInvalid => "EVIDENCE_INVALID",
            Self::VersionEvidenceInvalid => "VERSION_EVIDENCE_INVALID",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::RevocationFloor => "REVOCATION_FLOOR",
            Self::StaleEpoch => "STALE_EPOCH",
            Self::EpochConflict => "EPOCH_CONFLICT",
            Self::AuthorizationInvalid => "AUTHORIZATION_INVALID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveState {
    Candidate,
    Current,
    Unresolved,
}

impl EffectiveState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Current => "current",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RollbackEvidenceReceipt {
    pub subject: String,
    pub subject_digest: String,
    pub subject_epoch: u64,
    pub revision: u64,
    pub issuer: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBinding {
    pub subject: String,
    pub digest: String,
    pub epoch: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceVerificationError {
    Malformed,
    UnknownIssuer,
    InvalidSignature,
    Expired,
    Revoked,
    Replay,
    ScopeMismatch,
    StoreUnavailable,
}

/// Production implementations MUST verify the signature, trusted issuer/key,
/// revocation, validity, exact binding and durable replay protection.
pub trait RollbackEvidenceVerifier: Send + Sync {
    fn verify(
        &self,
        receipt: &RollbackEvidenceReceipt,
        expected: &EvidenceBinding,
        now: u64,
    ) -> Result<(), EvidenceVerificationError>;
}

pub struct RollbackGuardInput<'a> {
    pub current_epoch: u64,
    pub current_digest: String,
    pub current_artifact: &'a Value,
    pub candidate_epoch: u64,
    pub candidate_digest: String,
    pub candidate_artifact: &'a Value,
    pub revocation_floor: u64,
    pub revocation_floor_revision: u64,
    pub policy_version: &'a str,
    pub rollback_reason: &'a str,
    pub rollback_authorization: Option<&'a SignedOwnerApproval>,
    pub provenance: &'a [RollbackEvidenceReceipt],
    pub version_bound_evidence: &'a [RollbackEvidenceReceipt],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackGuardDecision {
    pub allowed: bool,
    pub effective_state: EffectiveState,
    pub effective_epoch: Option<u64>,
    pub effective_digest: Option<String>,
    pub denial_code: RollbackDenialCode,
    pub denial_reason: Option<String>,
    pub guard_digest: String,
    pub decision_envelope: Value,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_value(value: &Value) -> Result<String, ()> {
    canonical_json(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| ())
}

fn expected_bindings(input: &RollbackGuardInput<'_>) -> Result<Vec<EvidenceBinding>, ()> {
    let floor = json!({
        "revocation_floor": input.revocation_floor,
        "revision": input.revocation_floor_revision
    });
    let policy = json!({ "policy_version": input.policy_version });
    Ok(vec![
        EvidenceBinding {
            subject: "current_state".into(),
            digest: input.current_digest.clone(),
            epoch: input.current_epoch,
            revision: input.current_epoch,
        },
        EvidenceBinding {
            subject: "candidate_state".into(),
            digest: input.candidate_digest.clone(),
            epoch: input.candidate_epoch,
            revision: input.candidate_epoch,
        },
        EvidenceBinding {
            subject: "revocation_floor".into(),
            digest: digest_value(&floor)?,
            epoch: input.revocation_floor,
            revision: input.revocation_floor_revision,
        },
        EvidenceBinding {
            subject: "policy_version".into(),
            digest: digest_value(&policy)?,
            epoch: 0,
            revision: 0,
        },
    ])
}

fn verify_evidence_set(
    receipts: &[RollbackEvidenceReceipt],
    expected: &[EvidenceBinding],
    verifier: &dyn RollbackEvidenceVerifier,
    now: u64,
) -> Result<(), EvidenceVerificationError> {
    if receipts.len() != expected.len() {
        return Err(EvidenceVerificationError::Malformed);
    }
    let mut seen_subjects = std::collections::BTreeSet::new();
    let mut seen_nonces = std::collections::BTreeSet::new();
    for receipt in receipts {
        if receipt.subject.trim().is_empty()
            || receipt.issuer.trim().is_empty()
            || receipt.key_id.trim().is_empty()
            || receipt.nonce.trim().len() < 16
            || receipt.signature.is_empty()
            || receipt.issued_at >= receipt.expires_at
            || receipt.issued_at > now.saturating_add(CLOCK_SKEW_SECS)
            || receipt.expires_at <= now
            || !seen_subjects.insert(receipt.subject.as_str())
            || !seen_nonces.insert(receipt.nonce.as_str())
        {
            return Err(EvidenceVerificationError::Malformed);
        }
        let binding = expected
            .iter()
            .find(|binding| binding.subject == receipt.subject)
            .ok_or(EvidenceVerificationError::ScopeMismatch)?;
        verifier.verify(receipt, binding, now)?;
    }
    if expected
        .iter()
        .any(|binding| !seen_subjects.contains(binding.subject.as_str()))
    {
        return Err(EvidenceVerificationError::Malformed);
    }
    Ok(())
}

fn transition_resource(input: &RollbackGuardInput<'_>) -> Result<String, ()> {
    let payload = json!({
        "current_epoch": input.current_epoch,
        "current_digest": input.current_digest,
        "candidate_epoch": input.candidate_epoch,
        "candidate_digest": input.candidate_digest,
        "revocation_floor": input.revocation_floor,
        "revocation_floor_revision": input.revocation_floor_revision,
        "policy_version": input.policy_version,
        "rollback_reason": input.rollback_reason
    });
    Ok(format!("rollback-transition:{}", digest_value(&payload)?))
}

fn input_commitment(input: &RollbackGuardInput<'_>) -> Result<String, ()> {
    let approval = input.rollback_authorization.map(|signed| {
        json!({
            "approval_id": signed.payload.approval_id,
            "owner_subject": signed.payload.owner_subject,
            "key_id": signed.payload.key_id,
            "issued_at": signed.payload.issued_at,
            "expires_at": signed.payload.expires_at,
            "signature": sha256(&signed.signature)
        })
    });
    digest_value(&json!({
        "current_epoch": input.current_epoch,
        "current_digest": input.current_digest,
        "candidate_epoch": input.candidate_epoch,
        "candidate_digest": input.candidate_digest,
        "revocation_floor": input.revocation_floor,
        "revocation_floor_revision": input.revocation_floor_revision,
        "policy_version": input.policy_version,
        "rollback_reason": input.rollback_reason,
        "rollback_authorization": approval
    }))
}

fn evidence_commitment(
    provenance: &[RollbackEvidenceReceipt],
    version_bound: &[RollbackEvidenceReceipt],
) -> Result<String, ()> {
    let p = serde_json::to_value(provenance).map_err(|_| ())?;
    let v = serde_json::to_value(version_bound).map_err(|_| ())?;
    digest_value(&json!({ "provenance": p, "version_bound_evidence": v }))
}

fn finish(
    input: &RollbackGuardInput<'_>,
    allowed: bool,
    current_verified: bool,
    code: RollbackDenialCode,
    reason: Option<&str>,
    input_digest: &str,
    evidence_digest: &str,
) -> Result<RollbackGuardDecision, ()> {
    let (effective_state, effective_epoch, effective_digest) = if allowed {
        (
            EffectiveState::Candidate,
            Some(input.candidate_epoch),
            Some(input.candidate_digest.clone()),
        )
    } else if current_verified && input.current_epoch >= input.revocation_floor {
        (
            EffectiveState::Current,
            Some(input.current_epoch),
            Some(input.current_digest.clone()),
        )
    } else {
        (EffectiveState::Unresolved, None, None)
    };
    let envelope = json!({
        "envelope_version": "1.1.0",
        "hash_algorithm": "SHA-256",
        "canonicalization": "RFC8785-JCS",
        "input_digest": input_digest,
        "policy_version": input.policy_version,
        "decision": if allowed { "allow" } else { "deny" },
        "effective_state": effective_state.as_str(),
        "effective_epoch": effective_epoch,
        "effective_digest": effective_digest,
        "denial_code": code.as_str(),
        "evidence_commitment": evidence_digest
    });
    let guard_digest = digest_value(&envelope)?;
    Ok(RollbackGuardDecision {
        allowed,
        effective_state,
        effective_epoch,
        effective_digest,
        denial_code: code,
        denial_reason: reason.map(str::to_owned),
        guard_digest,
        decision_envelope: envelope,
    })
}

/// Evaluate one rollback candidate. A candidate below the verified floor is
/// denied before Owner approval verification/consumption. A permitted rollback
/// requires the existing replay-protected Owner approval verifier.
pub fn evaluate_rollback_guard(
    input: &RollbackGuardInput<'_>,
    evidence_verifier: &dyn RollbackEvidenceVerifier,
    owner_verifier: &OwnerApprovalVerifier,
    now: u64,
) -> Result<RollbackGuardDecision, ()> {
    if input.policy_version.trim().is_empty()
        || input.rollback_reason.trim().is_empty()
        || input.current_digest.len() != 64
        || input.candidate_digest.len() != 64
        || !input
            .current_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || !input
            .candidate_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(());
    }
    let input_digest = input_commitment(input)?;
    let evidence_digest = evidence_commitment(input.provenance, input.version_bound_evidence)?;
    let expected = expected_bindings(input)?;

    let provenance_ok =
        verify_evidence_set(input.provenance, &expected, evidence_verifier, now).is_ok();
    let version_ok = verify_evidence_set(
        input.version_bound_evidence,
        &expected,
        evidence_verifier,
        now,
    )
    .is_ok();
    if !provenance_ok {
        return finish(
            input,
            false,
            false,
            RollbackDenialCode::EvidenceInvalid,
            Some("provenance evidence is missing, stale, replayed, untrusted or mismatched"),
            &input_digest,
            &evidence_digest,
        );
    }
    if !version_ok {
        return finish(
            input,
            false,
            false,
            RollbackDenialCode::VersionEvidenceInvalid,
            Some("version-bound evidence is missing, stale, replayed, untrusted or mismatched"),
            &input_digest,
            &evidence_digest,
        );
    }

    let current_digest = digest_value(input.current_artifact)?;
    let candidate_digest = digest_value(input.candidate_artifact)?;
    if current_digest != input.current_digest || candidate_digest != input.candidate_digest {
        return finish(
            input,
            false,
            current_digest == input.current_digest,
            RollbackDenialCode::DigestMismatch,
            Some(
                "current or candidate artifact digest does not match canonical SHA-256/JCS content",
            ),
            &input_digest,
            &evidence_digest,
        );
    }

    // Absolute floor: no authorization is consulted or consumed below this line.
    if input.candidate_epoch < input.revocation_floor {
        return finish(
            input,
            false,
            true,
            RollbackDenialCode::RevocationFloor,
            Some("candidate epoch is below the authoritative revocation floor"),
            &input_digest,
            &evidence_digest,
        );
    }
    if input.candidate_epoch == input.current_epoch
        && input.candidate_digest != input.current_digest
    {
        return finish(
            input,
            false,
            true,
            RollbackDenialCode::EpochConflict,
            Some("same epoch cannot identify two different immutable artifacts"),
            &input_digest,
            &evidence_digest,
        );
    }

    if input.candidate_epoch < input.current_epoch {
        let Some(approval) = input.rollback_authorization else {
            return finish(
                input,
                false,
                true,
                RollbackDenialCode::AuthorizationInvalid,
                Some("rollback requires a scoped, signed, unexpired and unused Owner approval"),
                &input_digest,
                &evidence_digest,
            );
        };
        let resource = transition_resource(input)?;
        let request = AuthorizationRequest::new(
            ROLLBACK_SUBJECT,
            ROLLBACK_CAPABILITY,
            resource,
            RiskLevel::High,
        );
        if owner_verifier
            .verify_and_consume(approval, &request, input.policy_version, now)
            .is_err()
        {
            return finish(
                input,
                false,
                true,
                RollbackDenialCode::AuthorizationInvalid,
                Some("Owner rollback approval is invalid, out of scope, expired, revoked or replayed"),
                &input_digest,
                &evidence_digest,
            );
        }
    }

    finish(
        input,
        true,
        true,
        RollbackDenialCode::None,
        None,
        &input_digest,
        &evidence_digest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OwnerApprovalPayload, SqliteSecurityStore, TrustedOwnerKey};
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;

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

    fn owner() -> (SigningKey, OwnerApprovalVerifier) {
        let signer = SigningKey::from_bytes(&[71u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:akefa".into(),
                key_id: "owner-key-test".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5_000,
            }],
            store,
        )
        .unwrap();
        (signer, verifier)
    }

    fn make_receipts(
        input: &RollbackGuardInput<'_>,
    ) -> (Vec<RollbackEvidenceReceipt>, Vec<RollbackEvidenceReceipt>) {
        let expected = expected_bindings(input).unwrap();
        let make = |subject: &str, suffix: &str| {
            let binding = expected.iter().find(|x| x.subject == subject).unwrap();
            RollbackEvidenceReceipt {
                subject: binding.subject.clone(),
                subject_digest: binding.digest.clone(),
                subject_epoch: binding.epoch,
                revision: binding.revision,
                issuer: "issuer:trusted-test".into(),
                key_id: "evidence-key-1".into(),
                issued_at: 1_000,
                expires_at: 2_000,
                nonce: format!("nonce-unique-{suffix}-{subject}-0001"),
                signature: vec![7u8; 64],
            }
        };
        let names = [
            "current_state",
            "candidate_state",
            "revocation_floor",
            "policy_version",
        ];
        (
            names.iter().map(|n| make(n, "p")).collect(),
            names.iter().map(|n| make(n, "v")).collect(),
        )
    }

    fn fixture<'a>(
        current_epoch: u64,
        candidate_epoch: u64,
        floor: u64,
        current: &'a Value,
        candidate: &'a Value,
        auth: Option<&'a SignedOwnerApproval>,
        provenance: &'a [RollbackEvidenceReceipt],
        version_bound: &'a [RollbackEvidenceReceipt],
    ) -> RollbackGuardInput<'a> {
        RollbackGuardInput {
            current_epoch,
            current_digest: digest_value(current).unwrap(),
            current_artifact: current,
            candidate_epoch,
            candidate_digest: digest_value(candidate).unwrap(),
            candidate_artifact: candidate,
            revocation_floor: floor,
            revocation_floor_revision: 5,
            policy_version: "policy-v1",
            rollback_reason: "Owner-approved recovery test",
            rollback_authorization: auth,
            provenance,
            version_bound_evidence: version_bound,
        }
    }

    fn signed_approval(
        signer: &SigningKey,
        input: &RollbackGuardInput<'_>,
        now: u64,
    ) -> SignedOwnerApproval {
        let resource = transition_resource(input).unwrap();
        let payload = OwnerApprovalPayload::new(
            "approval:rollback-1",
            "owner:akefa",
            "owner-key-test",
            ROLLBACK_SUBJECT,
            ROLLBACK_CAPABILITY,
            resource,
            "policy-v1",
            now - 10,
            now + 100,
        );
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedOwnerApproval::from_signature(payload, signature)
    }

    #[test]
    fn forward_transition_requires_verified_evidence_and_recomputes_digests() {
        let current = json!({"version":"1.0.0","state":"current"});
        let candidate = json!({"version":"1.1.0","state":"candidate"});
        let empty = Vec::new();
        let mut input = fixture(10, 11, 8, &current, &candidate, None, &empty, &empty);
        let (p, v) = make_receipts(&input);
        input.provenance = &p;
        input.version_bound_evidence = &v;
        let (_, owner_verifier) = owner();
        let result =
            evaluate_rollback_guard(&input, &TestEvidence, &owner_verifier, 1_100).unwrap();
        assert!(result.allowed);
        assert_eq!(result.effective_state, EffectiveState::Candidate);
        assert_eq!(result.denial_code, RollbackDenialCode::None);
        assert_eq!(result.guard_digest.len(), 64);
    }

    #[test]
    fn revocation_floor_is_absolute_even_with_signed_owner_approval() {
        let current = json!({"version":"2.0.0","state":"current"});
        let candidate = json!({"version":"1.0.0","state":"candidate"});
        let empty = Vec::new();
        let mut input = fixture(20, 5, 10, &current, &candidate, None, &empty, &empty);
        let (p, v) = make_receipts(&input);
        input.provenance = &p;
        input.version_bound_evidence = &v;
        let (signer, owner_verifier) = owner();
        let approval = signed_approval(&signer, &input, 1_100);
        input.rollback_authorization = Some(&approval);
        let result =
            evaluate_rollback_guard(&input, &TestEvidence, &owner_verifier, 1_100).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.denial_code, RollbackDenialCode::RevocationFloor);
        assert_eq!(result.effective_state, EffectiveState::Current);
    }

    #[test]
    fn rollback_requires_exact_one_time_owner_approval() {
        let current = json!({"version":"2.0.0","state":"current"});
        let candidate = json!({"version":"1.5.0","state":"candidate"});
        let empty = Vec::new();
        let mut input = fixture(20, 15, 10, &current, &candidate, None, &empty, &empty);
        let (p, v) = make_receipts(&input);
        input.provenance = &p;
        input.version_bound_evidence = &v;
        let (signer, owner_verifier) = owner();
        let approval = signed_approval(&signer, &input, 1_100);
        input.rollback_authorization = Some(&approval);
        let first = evaluate_rollback_guard(&input, &TestEvidence, &owner_verifier, 1_100).unwrap();
        assert!(first.allowed);
        let replay =
            evaluate_rollback_guard(&input, &TestEvidence, &owner_verifier, 1_101).unwrap();
        assert!(!replay.allowed);
        assert_eq!(replay.denial_code, RollbackDenialCode::AuthorizationInvalid);
    }

    #[test]
    fn digest_substitution_and_same_epoch_conflict_fail_closed() {
        let current = json!({"version":"2.0.0","state":"current"});
        let candidate = json!({"version":"2.0.0","state":"different"});
        let empty = Vec::new();
        let mut input = fixture(20, 20, 10, &current, &candidate, None, &empty, &empty);
        let (p, v) = make_receipts(&input);
        input.provenance = &p;
        input.version_bound_evidence = &v;
        let (_, owner_verifier) = owner();
        let conflict =
            evaluate_rollback_guard(&input, &TestEvidence, &owner_verifier, 1_100).unwrap();
        assert_eq!(conflict.denial_code, RollbackDenialCode::EpochConflict);
        let mut substituted = fixture(20, 21, 10, &current, &candidate, None, &p, &v);
        let substituted_artifact = json!({"version":"2.1.0","state":"substituted"});
        substituted.candidate_artifact = &substituted_artifact;
        let mismatch =
            evaluate_rollback_guard(&substituted, &TestEvidence, &owner_verifier, 1_100).unwrap();
        assert_eq!(mismatch.denial_code, RollbackDenialCode::DigestMismatch);
    }

    #[test]
    fn missing_evidence_is_denied_and_current_below_floor_is_unresolved() {
        let current = json!({"version":"1.0.0"});
        let candidate = json!({"version":"1.1.0"});
        let empty = Vec::new();
        let input = fixture(2, 3, 4, &current, &candidate, None, &empty, &empty);
        let (_, owner_verifier) = owner();
        let result =
            evaluate_rollback_guard(&input, &TestEvidence, &owner_verifier, 1_100).unwrap();
        assert_eq!(result.denial_code, RollbackDenialCode::EvidenceInvalid);
        assert_eq!(result.effective_state, EffectiveState::Unresolved);
        assert_eq!(result.effective_epoch, None);
        assert_eq!(result.effective_digest, None);
    }
}
