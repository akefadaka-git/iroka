//! Typed G03↔G04 retrieval contract and fail-closed evidence adapter.
//!
//! This crate does not implement a source registry, index, retrieval engine or
//! persistent knowledge store. A provider remains the G04 authority for source
//! lifecycle, permissions, provenance, freshness and revocation. It MUST resolve
//! the opaque G01/G02 references before accessing or ranking source content.
//! This adapter validates the provider's response; it does not authenticate
//! request references or upgrade evidence states.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const REQUEST_SCHEMA_ID: &str = "iroka.g04.retrieval-request";
pub const BUNDLE_SCHEMA_ID: &str = "iroka.g04.evidence-bundle";
pub const CONTRACT_VERSION: &str = "1.0";
pub const MAX_QUERY_BYTES: usize = 4_096;
pub const MAX_RESULTS: usize = 50;
pub const MAX_BUNDLE_BYTES: usize = 1_048_576;
pub const MAX_REFERENCE_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum G04Error {
    MalformedRequest,
    ProviderUnavailable,
    MalformedBundle,
    CorrelationMismatch,
    ResultLimitExceeded,
    ByteBudgetExceeded,
    DuplicateEvidenceReference,
    DigestMismatch,
    UnpermittedContentExposed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    VerifiedCurrent,
    VerifiedStale,
    Unverified,
    Revoked,
    Superseded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceState {
    Verified,
    Incomplete,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    Permitted,
    NotPermitted,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalRequest {
    pub schema_id: String,
    pub contract_version: String,
    pub request_id: String,
    pub correlation_id: String,
    pub principal_ref: String,
    pub tenant_context_ref: String,
    pub policy_context_ref: String,
    pub query: String,
    pub source_selectors: Vec<String>,
    pub max_results: u16,
    pub max_bytes: u32,
    pub accepted_formats: Vec<String>,
    pub max_source_age_secs: Option<u64>,
    pub purpose_ref: String,
    pub classification_ceiling: String,
}

impl RetrievalRequest {
    pub fn validate(&self) -> Result<(), G04Error> {
        if self.schema_id != REQUEST_SCHEMA_ID
            || self.contract_version != CONTRACT_VERSION
            || !valid_ref(&self.request_id)
            || !valid_ref(&self.correlation_id)
            || !valid_ref(&self.principal_ref)
            || !valid_ref(&self.tenant_context_ref)
            || !valid_ref(&self.policy_context_ref)
            || !valid_ref(&self.purpose_ref)
            || !valid_ref(&self.classification_ceiling)
            || self.query.trim().is_empty()
            || self.query.len() > MAX_QUERY_BYTES
            || self.max_results == 0
            || usize::from(self.max_results) > MAX_RESULTS
            || self.max_bytes == 0
            || usize::try_from(self.max_bytes).unwrap_or(usize::MAX) > MAX_BUNDLE_BYTES
            || self.accepted_formats.is_empty()
            || self.accepted_formats.len() > 16
            || self.accepted_formats.iter().any(|v| !valid_ref(v))
            || self.source_selectors.len() > MAX_RESULTS
            || self.source_selectors.iter().any(|v| !valid_ref(v))
        {
            return Err(G04Error::MalformedRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_ref: String,
    pub source_ref: String,
    pub source_version: String,
    /// SHA-256 of the immutable source revision, not of the excerpt.
    pub source_sha256: String,
    /// SHA-256 of the exact UTF-8 excerpt returned in this item.
    pub excerpt_sha256: String,
    pub locator: String,
    pub excerpt: String,
    pub media_type: String,
    pub source_updated_at: Option<u64>,
    pub retrieved_at: u64,
    pub freshness_state: EvidenceState,
    pub provenance_state: ProvenanceState,
    pub license_state: LicenseState,
    pub license_ref: Option<String>,
    pub attribution_required: bool,
    pub tenant_context_ref: String,
    pub classification: String,
}

impl EvidenceItem {
    fn validate(&self, request: &RetrievalRequest) -> Result<usize, G04Error> {
        if !valid_ref(&self.evidence_ref)
            || !valid_ref(&self.source_ref)
            || !valid_ref(&self.source_version)
            || !valid_ref(&self.locator)
            || !valid_ref(&self.media_type)
            || !valid_ref(&self.classification)
            || self.tenant_context_ref != request.tenant_context_ref
            || self.excerpt.len() > MAX_BUNDLE_BYTES
            || !is_sha256(&self.source_sha256)
            || !is_sha256(&self.excerpt_sha256)
            || self.license_ref.as_ref().is_some_and(|v| !valid_ref(v))
        {
            return Err(G04Error::MalformedBundle);
        }
        if sha256_hex(self.excerpt.as_bytes()) != self.excerpt_sha256 {
            return Err(G04Error::DigestMismatch);
        }
        if self.license_state != LicenseState::Permitted && !self.excerpt.is_empty() {
            return Err(G04Error::UnpermittedContentExposed);
        }
        if self.license_state == LicenseState::Permitted
            && self.license_ref.as_deref().map_or(true, |v| v.is_empty())
        {
            return Err(G04Error::MalformedBundle);
        }
        if self.freshness_state == EvidenceState::VerifiedCurrent
            && (self.provenance_state != ProvenanceState::Verified
                || self.source_updated_at.is_none())
        {
            return Err(G04Error::MalformedBundle);
        }
        if self.freshness_state == EvidenceState::Revoked && !self.excerpt.is_empty() {
            return Err(G04Error::UnpermittedContentExposed);
        }
        if !request.accepted_formats.iter().any(|f| f == &self.media_type) {
            return Err(G04Error::MalformedBundle);
        }
        Ok(self.excerpt.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_id: String,
    pub contract_version: String,
    pub request_id: String,
    pub correlation_id: String,
    pub retrieved_at: u64,
    pub items: Vec<EvidenceItem>,
}

impl EvidenceBundle {
    pub fn validate_for(&self, request: &RetrievalRequest) -> Result<(), G04Error> {
        if self.schema_id != BUNDLE_SCHEMA_ID || self.contract_version != CONTRACT_VERSION {
            return Err(G04Error::MalformedBundle);
        }
        if self.request_id != request.request_id || self.correlation_id != request.correlation_id {
            return Err(G04Error::CorrelationMismatch);
        }
        if self.items.len() > usize::from(request.max_results) {
            return Err(G04Error::ResultLimitExceeded);
        }
        let mut refs = HashSet::with_capacity(self.items.len());
        let mut total_bytes = 0usize;
        for item in &self.items {
            if !refs.insert(item.evidence_ref.as_str()) {
                return Err(G04Error::DuplicateEvidenceReference);
            }
            if !request.source_selectors.is_empty()
                && !request.source_selectors.iter().any(|s| s == &item.source_ref)
            {
                return Err(G04Error::MalformedBundle);
            }
            total_bytes = total_bytes
                .checked_add(item.validate(request)?)
                .ok_or(G04Error::ByteBudgetExceeded)?;
            if total_bytes > usize::try_from(request.max_bytes).unwrap_or(usize::MAX) {
                return Err(G04Error::ByteBudgetExceeded);
            }
        }
        Ok(())
    }
}

/// G04 owns source permissions, lifecycle, retrieval, provenance, freshness
/// and revocation. Implementations must enforce G01/G02 context before ranking.
pub trait G04Provider: Send + Sync {
    fn retrieve(&self, request: &RetrievalRequest) -> Result<EvidenceBundle, G04Error>;
}

/// Validates the G04 response without promoting stale, unverified, revoked or
/// superseded evidence. This is a client adapter, not an authorization engine.
pub struct G04Adapter<P> {
    provider: P,
}

impl<P: G04Provider> G04Adapter<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub fn retrieve(&self, request: &RetrievalRequest) -> Result<EvidenceBundle, G04Error> {
        request.validate()?;
        let bundle = self.provider.retrieve(request)?;
        bundle.validate_for(request)?;
        Ok(bundle)
    }
}

fn valid_ref(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_REFERENCE_BYTES
        && !value.chars().any(char::is_control)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureProvider {
        bundle: EvidenceBundle,
    }

    impl G04Provider for FixtureProvider {
        fn retrieve(&self, _request: &RetrievalRequest) -> Result<EvidenceBundle, G04Error> {
            Ok(self.bundle.clone())
        }
    }

    fn request() -> RetrievalRequest {
        RetrievalRequest {
            schema_id: REQUEST_SCHEMA_ID.into(),
            contract_version: CONTRACT_VERSION.into(),
            request_id: "request:1".into(),
            correlation_id: "trace:1".into(),
            principal_ref: "g01:principal:1".into(),
            tenant_context_ref: "g01:tenant-context:1".into(),
            policy_context_ref: "g02:policy-context:1".into(),
            query: "የማኣሌ ታሪክ".into(),
            source_selectors: vec!["source:approved".into()],
            max_results: 4,
            max_bytes: 4096,
            accepted_formats: vec!["text/plain".into()],
            max_source_age_secs: Some(86_400),
            purpose_ref: "purpose:research".into(),
            classification_ceiling: "public".into(),
        }
    }

    fn item() -> EvidenceItem {
        let excerpt = "ማሌ".to_owned();
        EvidenceItem {
            evidence_ref: "evidence:1".into(),
            source_ref: "source:approved".into(),
            source_version: "v1".into(),
            source_sha256: "a".repeat(64),
            excerpt_sha256: sha256_hex(excerpt.as_bytes()),
            locator: "page:1/paragraph:2".into(),
            excerpt,
            media_type: "text/plain".into(),
            source_updated_at: Some(1_700_000_000),
            retrieved_at: 1_700_000_100,
            freshness_state: EvidenceState::VerifiedCurrent,
            provenance_state: ProvenanceState::Verified,
            license_state: LicenseState::Permitted,
            license_ref: Some("license:fixture".into()),
            attribution_required: true,
            tenant_context_ref: "g01:tenant-context:1".into(),
            classification: "public".into(),
        }
    }

    fn bundle(item: EvidenceItem) -> EvidenceBundle {
        EvidenceBundle {
            schema_id: BUNDLE_SCHEMA_ID.into(),
            contract_version: CONTRACT_VERSION.into(),
            request_id: "request:1".into(),
            correlation_id: "trace:1".into(),
            retrieved_at: 1_700_000_100,
            items: vec![item],
        }
    }

    #[test]
    fn accepts_well_formed_synthetic_evidence_without_upgrading_it() {
        let req = request();
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(item()) });
        let result = adapter.retrieve(&req).unwrap();
        assert_eq!(result.items[0].freshness_state, EvidenceState::VerifiedCurrent);
        assert_eq!(result.items[0].tenant_context_ref, req.tenant_context_ref);
    }

    #[test]
    fn rejects_correlation_mismatch() {
        let req = request();
        let mut response = bundle(item());
        response.correlation_id = "trace:other".into();
        let adapter = G04Adapter::new(FixtureProvider { bundle: response });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::CorrelationMismatch));
    }

    #[test]
    fn rejects_cross_tenant_evidence() {
        let req = request();
        let mut evidence = item();
        evidence.tenant_context_ref = "g01:tenant-context:other".into();
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(evidence) });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::MalformedBundle));
    }

    #[test]
    fn rejects_tampered_excerpt_digest() {
        let req = request();
        let mut evidence = item();
        evidence.excerpt.push('!');
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(evidence) });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::DigestMismatch));
    }

    #[test]
    fn rejects_revoked_content_exposure() {
        let req = request();
        let mut evidence = item();
        evidence.freshness_state = EvidenceState::Revoked;
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(evidence) });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::UnpermittedContentExposed));
    }

    #[test]
    fn rejects_unlicensed_content_exposure() {
        let req = request();
        let mut evidence = item();
        evidence.license_state = LicenseState::Unknown;
        evidence.license_ref = None;
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(evidence) });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::UnpermittedContentExposed));
    }

    #[test]
    fn accepts_explicit_unverified_metadata_only() {
        let req = request();
        let mut evidence = item();
        evidence.excerpt.clear();
        evidence.excerpt_sha256 = sha256_hex(b"");
        evidence.freshness_state = EvidenceState::Unverified;
        evidence.provenance_state = ProvenanceState::Unverified;
        evidence.license_state = LicenseState::Unknown;
        evidence.license_ref = None;
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(evidence) });
        let result = adapter.retrieve(&req).unwrap();
        assert_eq!(result.items[0].freshness_state, EvidenceState::Unverified);
    }

    #[test]
    fn rejects_duplicate_evidence_refs_and_unselected_sources() {
        let req = request();
        let first = item();
        let mut second = item();
        second.source_ref = "source:other".into();
        let mut duplicate = bundle(first.clone());
        duplicate.items.push(first);
        let adapter = G04Adapter::new(FixtureProvider { bundle: duplicate });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::DuplicateEvidenceReference));

        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(second) });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::MalformedBundle));
    }

    #[test]
    fn rejects_result_and_byte_budget_overruns() {
        let mut req = request();
        req.max_results = 1;
        let mut response = bundle(item());
        let mut extra = item();
        extra.evidence_ref = "evidence:2".into();
        response.items.push(extra);
        let adapter = G04Adapter::new(FixtureProvider { bundle: response });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::ResultLimitExceeded));

        let mut req = request();
        req.max_bytes = 1;
        let adapter = G04Adapter::new(FixtureProvider { bundle: bundle(item()) });
        assert_eq!(adapter.retrieve(&req), Err(G04Error::ByteBudgetExceeded));
    }

    #[test]
    fn rejects_unknown_schema_and_invalid_budgets() {
        let mut req = request();
        req.schema_id = "unknown".into();
        assert_eq!(req.validate(), Err(G04Error::MalformedRequest));
        let mut req = request();
        req.max_results = 0;
        assert_eq!(req.validate(), Err(G04Error::MalformedRequest));
    }
}
