//! Concrete G01 compact-JWS credential verification.
//! Only Ed25519 (EdDSA) is accepted. Trust and revocation state are explicit inputs.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::identity::{IdentityError, VerifiedPrincipal};

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub issuer: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    /// Inclusive Unix timestamp at which this key becomes trusted.
    pub not_before: u64,
    /// Exclusive Unix timestamp at which this key stops being trusted.
    pub not_after: u64,
}

#[derive(Debug, Clone)]
struct KeyRecord {
    issuer: String,
    key: VerifyingKey,
    not_before: u64,
    not_after: u64,
}

/// Immutable trust snapshot. Rotation is performed by publishing a new snapshot
/// containing overlapping old/new key validity windows; removal/revocation of
/// a compromised key is immediate by omitting it from the replacement snapshot.
#[derive(Debug, Clone)]
pub struct TrustStore {
    issuers: HashSet<String>,
    keys: HashMap<(String, String), KeyRecord>,
}

impl TrustStore {
    pub fn new<I, S>(trusted_issuers: I, keys: Vec<TrustedKey>) -> Result<Self, TrustConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let issuers: HashSet<String> = trusted_issuers.into_iter().map(Into::into).collect();
        if issuers.is_empty() || issuers.iter().any(|s| s.trim().is_empty()) {
            return Err(TrustConfigError::EmptyIssuerSet);
        }
        let mut records = HashMap::new();
        for item in keys {
            if !issuers.contains(&item.issuer) || item.key_id.trim().is_empty()
                || item.not_before >= item.not_after {
                return Err(TrustConfigError::InvalidKeyMetadata);
            }
            let key = VerifyingKey::from_bytes(&item.public_key)
                .map_err(|_| TrustConfigError::InvalidPublicKey)?;
            let index = (item.issuer.clone(), item.key_id.clone());
            if records.insert(index, KeyRecord {
                issuer: item.issuer, key, not_before: item.not_before, not_after: item.not_after,
            }).is_some() {
                return Err(TrustConfigError::DuplicateKeyId);
            }
        }
        if records.is_empty() {
            return Err(TrustConfigError::NoTrustedKeys);
        }
        Ok(Self { issuers, keys: records })
    }

    fn key(&self, issuer: &str, kid: &str, now: u64) -> Result<&KeyRecord, CredentialError> {
        if !self.issuers.contains(issuer) {
            return Err(CredentialError::UntrustedIssuer);
        }
        let record = self.keys.get(&(issuer.to_owned(), kid.to_owned()))
            .ok_or(CredentialError::UnknownKey)?;
        if now < record.not_before || now >= record.not_after {
            return Err(CredentialError::KeyOutsideValidity);
        }
        Ok(record)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustConfigError {
    EmptyIssuerSet,
    InvalidKeyMetadata,
    InvalidPublicKey,
    DuplicateKeyId,
    NoTrustedKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    Malformed,
    UnsupportedAlgorithm,
    UntrustedIssuer,
    UnknownKey,
    KeyOutsideValidity,
    InvalidSignature,
    Expired,
    NotYetValid,
    IssuedInFuture,
    AudienceMismatch,
    RevokedCredential,
    RevokedKey,
    RevocationUnavailable,
}

/// Implementations must read authoritative, current revocation state.
/// A cache must have an explicit maximum staleness and fail closed when exceeded.
pub trait RevocationChecker: Send + Sync {
    fn credential_revoked(&self, issuer: &str, credential_id: &str) -> Result<bool, ()>;
    fn key_revoked(&self, issuer: &str, key_id: &str) -> Result<bool, ()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocations;
impl RevocationChecker for NoRevocations {
    fn credential_revoked(&self, _: &str, _: &str) -> Result<bool, ()> { Ok(false) }
    fn key_revoked(&self, _: &str, _: &str) -> Result<bool, ()> { Ok(false) }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwsHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: String,
}

/// Concrete verifier for compact JWS credentials signed by trusted Ed25519 keys.
pub struct Ed25519CredentialVerifier<R> {
    trust: TrustStore,
    revocations: R,
    max_clock_skew_secs: u64,
}

impl<R: RevocationChecker> Ed25519CredentialVerifier<R> {
    pub fn new(trust: TrustStore, revocations: R) -> Self {
        Self { trust, revocations, max_clock_skew_secs: MAX_CLOCK_SKEW_SECS }
    }

    /// Verifies signature, issuer/key trust, time claims, exact audience and
    /// revocation before creating the opaque principal. Token format is
    /// base64url(header).base64url(claims).base64url(signature).
    pub fn authenticate(
        &self,
        compact_token: &str,
        expected_audience: &str,
        now: u64,
    ) -> Result<VerifiedPrincipal, CredentialError> {
        if compact_token.len() > MAX_TOKEN_BYTES || expected_audience.trim().is_empty() {
            return Err(CredentialError::Malformed);
        }
        let mut parts = compact_token.split('.');
        let (Some(header_part), Some(claims_part), Some(signature_part), None) =
            (parts.next(), parts.next(), parts.next(), parts.next()) else {
                return Err(CredentialError::Malformed);
            };
        let header_bytes = URL_SAFE_NO_PAD.decode(header_part).map_err(|_| CredentialError::Malformed)?;
        let claims_bytes = URL_SAFE_NO_PAD.decode(claims_part).map_err(|_| CredentialError::Malformed)?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_part).map_err(|_| CredentialError::Malformed)?;
        if signature_bytes.len() != 64 { return Err(CredentialError::Malformed); }
        let header: JwsHeader = serde_json::from_slice(&header_bytes).map_err(|_| CredentialError::Malformed)?;
        if header.alg != "EdDSA" || header.typ != "IROKA-CREDENTIAL" {
            return Err(CredentialError::UnsupportedAlgorithm);
        }
        if header.kid.trim().is_empty() { return Err(CredentialError::Malformed); }
        let claims: Claims = serde_json::from_slice(&claims_bytes).map_err(|_| CredentialError::Malformed)?;
        if claims.iss.trim().is_empty() || claims.sub.trim().is_empty() || claims.jti.trim().is_empty() {
            return Err(CredentialError::Malformed);
        }
        if claims.aud != expected_audience { return Err(CredentialError::AudienceMismatch); }
        let skew = self.max_clock_skew_secs;
        if claims.exp <= now.saturating_sub(skew) { return Err(CredentialError::Expired); }
        if claims.nbf.is_some_and(|v| v > now.saturating_add(skew)) {
            return Err(CredentialError::NotYetValid);
        }
        if claims.iat.is_some_and(|v| v > now.saturating_add(skew)) {
            return Err(CredentialError::IssuedInFuture);
        }
        let key = self.trust.key(&claims.iss, &header.kid, now)
            .map_err(|e| e)?;
        if key.issuer != claims.iss { return Err(CredentialError::UntrustedIssuer); }
        if self.revocations.key_revoked(&claims.iss, &header.kid)
            .map_err(|_| CredentialError::RevocationUnavailable)? {
            return Err(CredentialError::RevokedKey);
        }
        if self.revocations.credential_revoked(&claims.iss, &claims.jti)
            .map_err(|_| CredentialError::RevocationUnavailable)? {
            return Err(CredentialError::RevokedCredential);
        }
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| CredentialError::Malformed)?;
        let signing_input = format!("{header_part}.{claims_part}");
        key.key.verify(signing_input.as_bytes(), &signature)
            .map_err(|_| CredentialError::InvalidSignature)?;

        Ok(VerifiedPrincipal::from_verified_credential(
            claims.sub, claims.iss, claims.jti,
        ))
    }
}
