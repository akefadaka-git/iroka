//! G01 identity boundary.
//!
//! Cryptographic token verification is supplied by a trusted verifier adapter.
//! This module binds the resulting verified principal to authorization input.

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityAssertion {
    issuer: String,
    subject: String,
    audience: String,
    expires_at: u64,
    credential_id: String,
}

#[cfg(test)]
impl IdentityAssertion {
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
        expires_at: u64,
        credential_id: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.into(),
            audience: audience.into(),
            expires_at,
            credential_id: credential_id.into(),
        }
    }
}

/// Trusted adapter contract. Implementations must verify credential integrity,
/// issuer trust, audience, subject binding, revocation and required assurance.
/// The adapter itself is part of the trusted computing base.
#[cfg(test)]
pub(crate) trait IdentityVerifier {
    fn verify_credential(
        &self,
        assertion: &IdentityAssertion,
        now: u64,
    ) -> Result<(), IdentityError>;
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityError {
    Malformed,
    Expired,
    VerificationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrincipal {
    subject: String,
    issuer: String,
    credential_id: String,
    key_id: String,
    revocation_version: u64,
    issued_at: u64,
    expires_at: u64,
}

impl VerifiedPrincipal {
    pub(crate) fn from_verified_credential(
        subject: String,
        issuer: String,
        credential_id: String,
        key_id: String,
        revocation_version: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            subject,
            issuer,
            credential_id,
            key_id,
            revocation_version,
            issued_at,
            expires_at,
        }
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn revocation_version(&self) -> u64 {
        self.revocation_version
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Verify an assertion before producing the opaque principal used by the service.
#[cfg(test)]
pub(crate) fn authenticate<V: IdentityVerifier>(
    verifier: &V,
    assertion: &IdentityAssertion,
    expected_audience: &str,
    now: u64,
) -> Result<VerifiedPrincipal, IdentityError> {
    if assertion.issuer.trim().is_empty()
        || assertion.subject.trim().is_empty()
        || assertion.audience.trim().is_empty()
        || assertion.credential_id.trim().is_empty()
        || expected_audience.trim().is_empty()
    {
        return Err(IdentityError::Malformed);
    }
    if assertion.expires_at <= now {
        return Err(IdentityError::Expired);
    }
    if assertion.audience != expected_audience {
        return Err(IdentityError::VerificationFailed);
    }
    verifier.verify_credential(assertion, now)?;
    Ok(VerifiedPrincipal {
        subject: assertion.subject.clone(),
        issuer: assertion.issuer.clone(),
        credential_id: assertion.credential_id.clone(),
        key_id: "test-key".into(),
        revocation_version: 1,
        issued_at: 0,
        expires_at: assertion.expires_at,
    })
}
