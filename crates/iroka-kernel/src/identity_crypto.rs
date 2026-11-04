//! Concrete G01 compact-JWS credential verification.
//! Only Ed25519 (EdDSA) is accepted. Trust and revocation state are explicit inputs.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::identity::{IdentityError, VerifiedPrincipal};

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CLOCK_SKEW_SECS: u64 = 30;
const MAX_CREDENTIAL_TTL_SECS: u64 = 3_600;

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
        let issued_at = claims.iat.ok_or(CredentialError::Malformed)?;
        if issued_at > now.saturating_add(skew) {
            return Err(CredentialError::IssuedInFuture);
        }
        if claims.exp <= issued_at || claims.exp - issued_at > MAX_CREDENTIAL_TTL_SECS
            || claims.nbf.is_some_and(|v| v > claims.exp) {
            return Err(CredentialError::Malformed);
        }
        let key = self.trust.key(&claims.iss, &header.kid, now)
            .map_err(|e| e)?;
        if key.issuer != claims.iss { return Err(CredentialError::UntrustedIssuer); }
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| CredentialError::Malformed)?;
        let signing_input = format!("{header_part}.{claims_part}");
        key.key.verify(signing_input.as_bytes(), &signature)
            .map_err(|_| CredentialError::InvalidSignature)?;
        if self.revocations.key_revoked(&claims.iss, &header.kid)
            .map_err(|_| CredentialError::RevocationUnavailable)? {
            return Err(CredentialError::RevokedKey);
        }
        if self.revocations.credential_revoked(&claims.iss, &claims.jti)
            .map_err(|_| CredentialError::RevocationUnavailable)? {
            return Err(CredentialError::RevokedCredential);
        }

        Ok(VerifiedPrincipal::from_verified_credential(
            claims.sub, claims.iss, claims.jti,
        ))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Clone, Copy)]
    struct Revoked;
    impl RevocationChecker for Revoked {
        fn credential_revoked(&self, _: &str, _: &str) -> Result<bool, ()> { Ok(true) }
        fn key_revoked(&self, _: &str, _: &str) -> Result<bool, ()> { Ok(false) }
    }

    fn fixture() -> (SigningKey, TrustStore) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let trust = TrustStore::new(
            ["issuer:iroka-test"],
            vec![TrustedKey {
                issuer: "issuer:iroka-test".into(),
                key_id: "key-2026-a".into(),
                public_key: signing.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 10_000,
            }],
        ).expect("valid trust configuration");
        (signing, trust)
    }

    fn token(signing: &SigningKey, kid: &str, exp: u64) -> String {
        let header_json = format!(r#"{{"alg":"EdDSA","typ":"IROKA-CREDENTIAL","kid":"{kid}"}}"#);
        let header = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims_json = format!(r#"{{"iss":"issuer:iroka-test","sub":"principal:42","aud":"iroka-kernel","exp":{exp},"nbf":1100,"iat":1100,"jti":"cred-001"}}"#);
        let claims = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let input = format!("{header}.{claims}");
        let signature = signing.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn verifies_a_trusted_ed25519_credential() {
        let (signing, trust) = fixture();
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        let principal = verifier.authenticate(&token(&signing, "key-2026-a", 4700), "iroka-kernel", 1200)
            .expect("credential should verify");
        assert_eq!(principal.subject(), "principal:42");
        assert_eq!(principal.issuer(), "issuer:iroka-test");
        assert_eq!(principal.credential_id(), "cred-001");
    }

    #[test]
    fn rejects_modified_signature_input() {
        let (signing, trust) = fixture();
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        let signed = token(&signing, "key-2026-a", 4700);
        // The replacement is inside base64url, so alter the signed payload segment.
        let mut parts = signed.split('.').map(str::to_owned).collect::<Vec<_>>();
        let payload = URL_SAFE_NO_PAD.decode(&parts[1]).expect("payload");
        let changed = String::from_utf8(payload).expect("utf8").replace("principal:42", "principal:43");
        parts[1] = URL_SAFE_NO_PAD.encode(changed.as_bytes());
        let tampered = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        assert_eq!(verifier.authenticate(&tampered, "iroka-kernel", 1200), Err(CredentialError::InvalidSignature));
    }

    #[test]
    fn fails_closed_when_revocation_store_marks_credential_revoked() {
        let (signing, trust) = fixture();
        let verifier = Ed25519CredentialVerifier::new(trust, Revoked);
        assert_eq!(verifier.authenticate(&token(&signing, "key-2026-a", 4700), "iroka-kernel", 1200),
            Err(CredentialError::RevokedCredential));
    }

    #[test]
    fn accepts_both_keys_during_an_explicit_rotation_overlap() {
        let old = SigningKey::from_bytes(&[7u8; 32]);
        let new = SigningKey::from_bytes(&[9u8; 32]);
        let trust = TrustStore::new(
            ["issuer:iroka-test"],
            vec![
                TrustedKey { issuer: "issuer:iroka-test".into(), key_id: "key-old".into(),
                    public_key: old.verifying_key().to_bytes(), not_before: 1_000, not_after: 2_000 },
                TrustedKey { issuer: "issuer:iroka-test".into(), key_id: "key-new".into(),
                    public_key: new.verifying_key().to_bytes(), not_before: 1_500, not_after: 3_000 },
            ],
        ).expect("overlapping rotation keys are valid");
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        assert_eq!(verifier.authenticate(&token(&old, "key-old", 4700), "iroka-kernel", 1600)
            .expect("old key remains trusted during overlap").subject(), "principal:42");
        assert_eq!(verifier.authenticate(&token(&new, "key-new", 4700), "iroka-kernel", 1600)
            .expect("new key is trusted during overlap").subject(), "principal:42");
    }

    #[test]
    fn rejects_wrong_audience_and_expired_credentials() {
        let (signing, trust) = fixture();
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        assert_eq!(verifier.authenticate(&token(&signing, "key-2026-a", 4700), "other-service", 1200),
            Err(CredentialError::AudienceMismatch));
        assert_eq!(verifier.authenticate(&token(&signing, "key-2026-a", 1150), "iroka-kernel", 1200),
            Err(CredentialError::Expired));
    }

    #[test]
    fn rejects_unknown_key_id_even_when_signature_is_valid() {
        let (signing, trust) = fixture();
        let verifier = Ed25519CredentialVerifier::new(trust, NoRevocations);
        assert_eq!(verifier.authenticate(&token(&signing, "untrusted-key", 4700), "iroka-kernel", 1200),
            Err(CredentialError::UnknownKey));
    }
}
