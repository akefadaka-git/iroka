//! G01 cryptographic reviewer-proof boundary.
//!
//! A verified login is not reviewer evidence. This module requires a current,
//! authoritative identity-to-reviewer-key binding, a signature over the exact
//! approval scope, freshness and revocation checks, and one-time proof use.
//! The binding adapter is part of the trusted computing base and must read the
//! issuer's authoritative current key-binding/revocation state.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{SecurityStoreError, SqliteSecurityStore, VerifiedPrincipal};

const DOMAIN: &[u8] = b"IROKA:G01:REVIEWER_PROOF:V1\0";
const MAX_PROOF_TTL_SECS: u64 = 300;
const CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewerProofPayload {
    pub proof_id: String,
    pub issuer: String,
    pub subject: String,
    pub credential_id: String,
    pub reviewer_id: String,
    pub designation_id: String,
    pub designation_version: u64,
    pub key_id: String,
    pub approval_id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub memory_id: String,
    pub record_version: u64,
    pub content_sha256: String,
    pub purpose: String,
    pub classification: String,
    pub capability: String,
    pub resource: String,
    pub policy_version: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ReviewerProofPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ReviewerProofError> {
        let body = serde_jcs::to_vec(self).map_err(|_| ReviewerProofError::Malformed)?;
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedReviewerProof {
    pub payload: ReviewerProofPayload,
    pub signature: Vec<u8>,
}

impl SignedReviewerProof {
    pub fn from_signature(payload: ReviewerProofPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

/// Returned only after signature, binding, scope, freshness, revocation and
/// replay checks succeed. Fields are private to prevent caller fabrication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReviewerProof {
    reviewer_id: String,
    subject: String,
    issuer: String,
    approval_id: String,
    designation_id: String,
    designation_version: u64,
    tenant_id: String,
    organization_id: String,
    memory_id: String,
    record_version: u64,
    content_sha256: String,
    purpose: String,
    classification: String,
    capability: String,
    resource: String,
    policy_version: String,
    proof_id: String,
    verified_at: u64,
}

#[rustfmt::skip]
impl VerifiedReviewerProof {
    pub fn reviewer_id(&self) -> &str { &self.reviewer_id }
    pub fn subject(&self) -> &str { &self.subject }
    pub fn issuer(&self) -> &str { &self.issuer }
    pub fn approval_id(&self) -> &str { &self.approval_id }
    pub fn designation_id(&self) -> &str { &self.designation_id }
    pub fn designation_version(&self) -> u64 { self.designation_version }
    pub fn tenant_id(&self) -> &str { &self.tenant_id }
    pub fn organization_id(&self) -> &str { &self.organization_id }
    pub fn memory_id(&self) -> &str { &self.memory_id }
    pub fn record_version(&self) -> u64 { self.record_version }
    pub fn content_sha256(&self) -> &str { &self.content_sha256 }
    pub fn purpose(&self) -> &str { &self.purpose }
    pub fn classification(&self) -> &str { &self.classification }
    pub fn capability(&self) -> &str { &self.capability }
    pub fn resource(&self) -> &str { &self.resource }
    pub fn policy_version(&self) -> &str { &self.policy_version }
    pub fn proof_id(&self) -> &str { &self.proof_id }
    pub fn verified_at(&self) -> u64 { self.verified_at }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewerProofError {
    Malformed,
    PrincipalMismatch,
    BindingMissing,
    BindingInactive,
    KeyOutsideValidity,
    InvalidSignature,
    ScopeMismatch,
    NotYetValid,
    Expired,
    Revoked,
    Replay,
    StoreUnavailable,
    IssuerTrustUnavailable,
    IssuerKeyRevoked,
    InvalidBindingSignature,
}

#[rustfmt::skip]
impl From<SecurityStoreError> for ReviewerProofError {
    fn from(_: SecurityStoreError) -> Self { Self::StoreUnavailable }
}

/// Current issuer-signed reviewer identity-to-key binding.
pub trait ReviewerKeyBindingResolver: Send + Sync {
    fn resolve_current_binding(
        &self,
        issuer: &str,
        subject: &str,
        credential_id: &str,
        key_id: &str,
        now: u64,
    ) -> Result<Option<SignedReviewerKeyBinding>, ReviewerProofError>;
}

const BINDING_DOMAIN: &[u8] = b"IROKA:G01:REVIEWER_KEY_BINDING:V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewerKeyBinding {
    pub issuer: String,
    pub subject: String,
    pub credential_id: String,
    pub reviewer_id: String,
    pub key_id: String,
    pub binding_id: String,
    pub binding_version: u64,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub status: ReviewerKeyBindingStatus,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer_key_id: String,
}
impl ReviewerKeyBinding {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ReviewerProofError> {
        let body = serde_jcs::to_vec(self).map_err(|_| ReviewerProofError::Malformed)?;
        let mut bytes = BINDING_DOMAIN.to_vec();
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerKeyBindingStatus {
    Active,
    Revoked,
    Suspended,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedReviewerKeyBinding {
    pub binding: ReviewerKeyBinding,
    pub issuer_signature: Vec<u8>,
}

/// Resolves issuer signing keys from G01's root-signed trust snapshot and
/// current revocation source. Caller-supplied keys are never trusted.
#[derive(Debug, Clone)]
pub struct ReviewerIssuerTrustKey {
    pub issuer: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
    pub trust_version: u64,
    pub resolved_at: u64,
}
pub trait ReviewerIssuerTrustProvider: Send + Sync {
    fn resolve_current_issuer_key(
        &self,
        issuer: &str,
        key_id: &str,
        now: u64,
    ) -> Result<Option<ReviewerIssuerTrustKey>, ReviewerProofError>;
}

pub struct ReviewerProofVerifier<R, I> {
    bindings: R,
    issuer_trust: I,
    store: std::sync::Arc<SqliteSecurityStore>,
}
#[rustfmt::skip]
impl<R: ReviewerKeyBindingResolver, I: ReviewerIssuerTrustProvider> ReviewerProofVerifier<R, I> {
    pub fn new(bindings: R, issuer_trust: I, store: std::sync::Arc<SqliteSecurityStore>) -> Self {
        Self { bindings, issuer_trust, store }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_consume(
        &self, proof: &SignedReviewerProof, principal: &VerifiedPrincipal,
        expected_reviewer_id: &str, expected_approval_id: &str, expected_tenant_id: &str,
        expected_organization_id: &str, expected_designation_id: &str,
        expected_designation_version: u64, expected_memory_id: &str,
        expected_record_version: u64, expected_content_sha256: &str,
        expected_purpose: &str, expected_classification: &str,
        expected_capability: &str, expected_resource: &str,
        expected_policy_version: &str, now: u64,
    ) -> Result<VerifiedReviewerProof, ReviewerProofError> {
        let p = &proof.payload;
        for value in [p.proof_id.as_str(), p.issuer.as_str(), p.subject.as_str(),
            p.credential_id.as_str(), p.reviewer_id.as_str(), p.designation_id.as_str(), p.key_id.as_str(),
            p.approval_id.as_str(), p.tenant_id.as_str(), p.organization_id.as_str(),
            p.memory_id.as_str(), p.content_sha256.as_str(), p.purpose.as_str(), p.classification.as_str(),
            p.capability.as_str(), p.resource.as_str(), p.policy_version.as_str(),
            expected_reviewer_id, expected_approval_id, expected_tenant_id,
            expected_organization_id, expected_designation_id, expected_memory_id,
            expected_content_sha256, expected_purpose, expected_classification, expected_capability,
            expected_resource, expected_policy_version] {
            if value.trim().is_empty() || value.len() > 512 { return Err(ReviewerProofError::Malformed); }
        }
        if p.designation_version == 0 || p.record_version == 0 || p.content_sha256.len() != 64
            || !p.content_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ReviewerProofError::Malformed);
        }
        if p.issued_at >= p.expires_at || p.expires_at - p.issued_at > MAX_PROOF_TTL_SECS {
            return Err(ReviewerProofError::Malformed);
        }
        if p.issued_at > now.saturating_add(CLOCK_SKEW_SECS) { return Err(ReviewerProofError::NotYetValid); }
        if p.expires_at <= now { return Err(ReviewerProofError::Expired); }
        if p.issuer != principal.issuer() || p.subject != principal.subject()
            || p.credential_id != principal.credential_id() { return Err(ReviewerProofError::PrincipalMismatch); }
        if p.reviewer_id != expected_reviewer_id || p.approval_id != expected_approval_id
            || p.tenant_id != expected_tenant_id || p.organization_id != expected_organization_id
            || p.designation_id != expected_designation_id || p.designation_version != expected_designation_version
            || p.memory_id != expected_memory_id || p.record_version != expected_record_version
            || p.content_sha256 != expected_content_sha256 || p.purpose != expected_purpose
            || p.classification != expected_classification || p.capability != expected_capability
            || p.resource != expected_resource || p.policy_version != expected_policy_version {
            return Err(ReviewerProofError::ScopeMismatch);
        }
        let signed = self.bindings.resolve_current_binding(&p.issuer, &p.subject, &p.credential_id, &p.key_id, now)?
            .ok_or(ReviewerProofError::BindingMissing)?;
        let binding = &signed.binding;
        if binding.issuer != p.issuer || binding.subject != p.subject
            || binding.credential_id != p.credential_id || binding.reviewer_id != p.reviewer_id
            || binding.key_id != p.key_id || binding.binding_id.trim().is_empty()
            || binding.binding_version == 0 || binding.issuer_key_id.trim().is_empty()
            || binding.not_before >= binding.not_after || binding.issued_at >= binding.expires_at
            || binding.expires_at - binding.issued_at > MAX_PROOF_TTL_SECS
            || binding.issued_at > now.saturating_add(CLOCK_SKEW_SECS) || binding.expires_at <= now {
            return Err(ReviewerProofError::BindingMissing);
        }
        if binding.status != ReviewerKeyBindingStatus::Active { return Err(ReviewerProofError::Revoked); }
        if now < binding.not_before || now >= binding.not_after
            || binding.issued_at < binding.not_before || binding.issued_at >= binding.not_after
            || p.issued_at < binding.not_before || p.issued_at >= binding.not_after {
            return Err(ReviewerProofError::KeyOutsideValidity);
        }
        let issuer_key = self.issuer_trust.resolve_current_issuer_key(&p.issuer, &binding.issuer_key_id, now)?
            .ok_or(ReviewerProofError::IssuerTrustUnavailable)?;
        if issuer_key.issuer != p.issuer || issuer_key.key_id != binding.issuer_key_id
            || issuer_key.revoked || issuer_key.trust_version == 0 {
            return Err(ReviewerProofError::IssuerKeyRevoked);
        }
        if issuer_key.resolved_at > now || now.saturating_sub(issuer_key.resolved_at) > 30
            || now < issuer_key.not_before || now >= issuer_key.not_after
            || binding.issued_at < issuer_key.not_before || binding.issued_at >= issuer_key.not_after {
            return Err(ReviewerProofError::IssuerTrustUnavailable);
        }
        let issuer_vk = VerifyingKey::from_bytes(&issuer_key.public_key)
            .map_err(|_| ReviewerProofError::IssuerTrustUnavailable)?;
        let issuer_sig = Signature::from_slice(&signed.issuer_signature).map_err(|_| ReviewerProofError::Malformed)?;
        issuer_vk.verify(&binding.signing_bytes()?, &issuer_sig)
            .map_err(|_| ReviewerProofError::InvalidBindingSignature)?;
        if binding.public_key == [0u8; 32] { return Err(ReviewerProofError::BindingMissing); }
        let key = VerifyingKey::from_bytes(&binding.public_key).map_err(|_| ReviewerProofError::BindingMissing)?;
        let bytes = p.signing_bytes()?;
        let signature = Signature::from_slice(&proof.signature).map_err(|_| ReviewerProofError::Malformed)?;
        key.verify(&bytes, &signature).map_err(|_| ReviewerProofError::InvalidSignature)?;
        let digest = Sha256::digest(&bytes);
        self.store.consume_reviewer_proof(&p.issuer, &p.credential_id, &p.proof_id, digest.as_slice(), now)
            .map_err(|error| match error {
                SecurityStoreError::ConflictingVersion => ReviewerProofError::Replay,
                other => ReviewerProofError::from(other),
            })?;
        Ok(VerifiedReviewerProof {
            reviewer_id: p.reviewer_id.clone(), subject: p.subject.clone(), issuer: p.issuer.clone(),
            approval_id: p.approval_id.clone(), designation_id: p.designation_id.clone(),
            designation_version: p.designation_version, tenant_id: p.tenant_id.clone(),
            organization_id: p.organization_id.clone(), memory_id: p.memory_id.clone(),
            record_version: p.record_version, content_sha256: p.content_sha256.clone(),
            purpose: p.purpose.clone(), classification: p.classification.clone(), capability: p.capability.clone(),
            resource: p.resource.clone(), policy_version: p.policy_version.clone(),
            proof_id: p.proof_id.clone(), verified_at: now,
        })
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    struct Bindings { signed: SignedReviewerKeyBinding }
    impl ReviewerKeyBindingResolver for Bindings {
        fn resolve_current_binding(&self, _: &str, _: &str, _: &str, _: &str, _: u64)
            -> Result<Option<SignedReviewerKeyBinding>, ReviewerProofError> { Ok(Some(self.signed.clone())) }
    }
    struct IssuerTrust { key: [u8;32], revoked: bool }
    impl ReviewerIssuerTrustProvider for IssuerTrust {
        fn resolve_current_issuer_key(&self, issuer: &str, key_id: &str, now: u64)
            -> Result<Option<ReviewerIssuerTrustKey>, ReviewerProofError> {
            Ok(Some(ReviewerIssuerTrustKey { issuer:issuer.into(), key_id:key_id.into(),
                public_key:self.key, not_before:100, not_after:2000, revoked:self.revoked,
                trust_version:4, resolved_at:now }))
        }
    }
    fn fixture(revoked: bool) -> (SigningKey, ReviewerProofVerifier<Bindings,IssuerTrust>, VerifiedPrincipal) {
        let key=SigningKey::from_bytes(&[91u8;32]);
        let issuer=SigningKey::from_bytes(&[92u8;32]);
        let binding=ReviewerKeyBinding { issuer:"issuer:community".into(), subject:"reviewer:alice".into(),
            credential_id:"credential:42".into(), reviewer_id:"reviewer:maale-01".into(),
            key_id:"reviewer-key-01".into(), binding_id:"binding:1".into(), binding_version:3,
            public_key:key.verifying_key().to_bytes(), not_before:100, not_after:2000,
            status:if revoked {ReviewerKeyBindingStatus::Revoked} else {ReviewerKeyBindingStatus::Active},
            issued_at:1100, expires_at:1250, issuer_key_id:"issuer-key-01".into() };
        let issuer_signature=issuer.sign(&binding.signing_bytes().unwrap()).to_bytes().to_vec();
        let verifier=ReviewerProofVerifier::new(Bindings {signed:SignedReviewerKeyBinding {binding,issuer_signature}},
            IssuerTrust {key:issuer.verifying_key().to_bytes(),revoked:false},
            Arc::new(SqliteSecurityStore::open_in_memory().unwrap()));
        let principal=VerifiedPrincipal::from_verified_credential("reviewer:alice".into(),"issuer:community".into(),"credential:42".into());
        (key,verifier,principal)
    }
    fn signed(key:&SigningKey,id:&str)->SignedReviewerProof {
        let payload=ReviewerProofPayload { proof_id:id.into(),issuer:"issuer:community".into(),
            subject:"reviewer:alice".into(),credential_id:"credential:42".into(),reviewer_id:"reviewer:maale-01".into(),
            designation_id:"designation:1".into(),designation_version:3,key_id:"reviewer-key-01".into(),
            approval_id:"approval:17".into(),tenant_id:"tenant:alpha".into(),organization_id:"org:alpha".into(),
            memory_id:"memory:1".into(),record_version:4,content_sha256:"a".repeat(64),
            purpose:"ORGANIZATIONAL_CONTEXT".into(),classification:"CONFIDENTIAL".into(),
            capability:"content.review".into(),resource:"translation:chapter-1".into(),policy_version:"policy:v1".into(),
            issued_at:1100,expires_at:1300 };
        let signature=key.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
        SignedReviewerProof::from_signature(payload,signature)
    }
    fn verify(v:&ReviewerProofVerifier<Bindings,IssuerTrust>,p:&SignedReviewerProof,principal:&VerifiedPrincipal)
        -> Result<VerifiedReviewerProof,ReviewerProofError> {
        v.verify_and_consume(p,principal,"reviewer:maale-01","approval:17","tenant:alpha","org:alpha",
            "designation:1",3,"memory:1",4,&"a".repeat(64),"ORGANIZATIONAL_CONTEXT","CONFIDENTIAL",
            "content.review","translation:chapter-1","policy:v1",1200)
    }
    #[test] fn verifies_issuer_signed_binding_and_consumes_once() {
        let (key,v,principal)=fixture(false); let proof=signed(&key,"proof:once");
        assert_eq!(verify(&v,&proof,&principal).unwrap().reviewer_id(),"reviewer:maale-01");
        assert_eq!(verify(&v,&proof,&principal),Err(ReviewerProofError::Replay));
    }
    #[test] fn rejects_wrong_scope_and_principal() {
        let (key,v,principal)=fixture(false); let mut proof=signed(&key,"proof:scope");
        proof.payload.resource="translation:chapter-2".into();
        proof.signature=key.sign(&proof.payload.signing_bytes().unwrap()).to_bytes().to_vec();
        assert_eq!(verify(&v,&proof,&principal),Err(ReviewerProofError::ScopeMismatch));
        let other=VerifiedPrincipal::from_verified_credential("reviewer:bob".into(),"issuer:community".into(),"credential:43".into());
        assert_eq!(verify(&v,&signed(&key,"proof:principal"),&other),Err(ReviewerProofError::PrincipalMismatch));
    }
    #[test] fn rejects_revoked_binding_and_tampered_proof() {
        let (key,v,principal)=fixture(true);
        assert_eq!(verify(&v,&signed(&key,"proof:revoked"),&principal),Err(ReviewerProofError::Revoked));
        let (_,v2,p2)=fixture(false); let mut tampered=signed(&key,"proof:tampered"); tampered.signature[0]^=1;
        assert_eq!(verify(&v2,&tampered,&p2),Err(ReviewerProofError::InvalidSignature));
    }
    #[test] fn rejects_expired_and_future_proofs() {
        let (key,v,principal)=fixture(false); let mut expired=signed(&key,"proof:expired");
        expired.payload.expires_at=1199;
        assert_eq!(verify(&v,&expired,&principal),Err(ReviewerProofError::Expired));
        let mut future=signed(&key,"proof:future"); future.payload.issued_at=1300; future.payload.expires_at=1400;
        assert_eq!(verify(&v,&future,&principal),Err(ReviewerProofError::NotYetValid));
    }
}
