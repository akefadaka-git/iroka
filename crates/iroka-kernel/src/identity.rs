//! G01 identity boundary.
//!
//! Cryptographic token verification is supplied by a trusted verifier adapter.
//! This module binds the resulting verified principal to authorization input.

use crate::{AuthorizationRequest, Decision, DecisionCode, DecisionReason, Policy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAssertion {
    issuer: String,
    subject: String,
    audience: String,
    expires_at: u64,
    credential_id: String,
}

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

    pub fn issuer(&self) -> &str { &self.issuer }
    pub fn subject(&self) -> &str { &self.subject }
    pub fn audience(&self) -> &str { &self.audience }
    pub fn expires_at(&self) -> u64 { self.expires_at }
    pub fn credential_id(&self) -> &str { &self.credential_id }
}

/// Trusted adapter contract. Implementations must verify credential integrity,
/// issuer trust, audience, subject binding, revocation and required assurance.
/// The adapter itself is part of the trusted computing base.
pub trait IdentityVerifier {
    fn verify_credential(&self, assertion: &IdentityAssertion, now: u64) -> Result<(), IdentityError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    Malformed,
    Expired,
    VerificationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrincipal {
    subject: String,
    issuer: String,
    credential_id: String,
}

impl VerifiedPrincipal {
    pub(crate) fn from_verified_credential(
        subject: String,
        issuer: String,
        credential_id: String,
    ) -> Self {
        Self { subject, issuer, credential_id }
    }

    pub fn subject(&self) -> &str { &self.subject }
    pub fn issuer(&self) -> &str { &self.issuer }
    pub fn credential_id(&self) -> &str { &self.credential_id }
}

/// Verify an assertion before producing the opaque principal used by the service.
pub fn authenticate<V: IdentityVerifier>(
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
    })
}

/// Ensure the request subject is the exact verified principal.
pub fn bind_principal(
    principal: &VerifiedPrincipal,
    request: &AuthorizationRequest,
    policy: &Policy,
) -> Decision {
    if principal.subject != request.subject() {
        return Decision::new(
            DecisionCode::Deny,
            DecisionReason::IdentitySubjectMismatch,
            policy.version(),
        );
    }
    crate::evaluate(request, policy, false)
}
