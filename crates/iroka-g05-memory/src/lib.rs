//! IROKA G05 governed memory domain primitives.
//!
//! This crate defines the memory-owned data model, policy validation and
//! integration ports. It deliberately does not authenticate principals,
//! resolve tenants, authorize access, verify human approvals, persist content,
//! or implement audit storage. Those duties remain with G01, IROKA tenant
//! authority, G02, the approved human-review authority, a G05 repository
//! adapter, and G11 respectively.
//!
//! Implementations MUST invoke the ports in the documented order. In
//! particular, authorization precedes content access; durable activation
//! requires a record-bound approval; episodic capture requires opt-in; and
//! audit completion must be coordinated transactionally through a G11-backed
//! outbox before a lifecycle mutation is reported complete.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CONTRACT_ID: &str = "IROKA-G05-MEM-001";
pub const CONTRACT_VERSION: &str = "1.0.0";
pub const RECORD_SCHEMA_ID: &str = "iroka.g05.memory-record";
pub const MAX_MEMORY_ID_BYTES: usize = 256;
pub const MAX_CONTENT_BYTES: usize = 32_768;
pub const MAX_SOURCE_REFS: usize = 32;
pub const MAX_REF_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    Working,
    Episodic,
    Durable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Purpose {
    TaskContinuity,
    UserPreference,
    ProjectContext,
    OrganizationalContext,
    OperationalHistory,
    AuthorizedSystemAssurance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    UserExplicit,
    OwnerApproved,
    SystemObserved,
    G04EvidenceReference,
    AuthorizedWorkflow,
    HumanReviewed,
    ModelProposed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Proposed,
    PendingReview,
    Active,
    Rejected,
    Restricted,
    CorrectionPending,
    DeletionPending,
    Expired,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Propose,
    CreateWorking,
    CreateEpisodic,
    ActivateDurable,
    Retrieve,
    InspectMetadata,
    Correct,
    Restrict,
    RequestDeletion,
    VerifyDeletion,
    Share,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum G05Error {
    MalformedRecord,
    InvalidReference,
    ContentTooLarge,
    TooManySources,
    DigestMismatch,
    ExpiryRequired,
    ExpiryInvalid,
    RestrictedWorkingMemory,
    EpisodicOptInRequired,
    DurableApprovalRequired,
    ApprovalBindingMismatch,
    ApprovalExpired,
    ReviewerNotAuthorized,
    AuthorizationDenied,
    TenantScopeMismatch,
    SubjectScopeMismatch,
    SharingNotAuthorized,
    InvalidLifecycleTransition,
    RecordNotActive,
    VersionConflict,
    DuplicateRecord,
    RecordNotFound,
    RepositoryUnavailable,
    AuditUnavailable,
    UnsupportedOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub kind: ProvenanceKind,
    pub source_refs: Vec<String>,
    pub source_revision_refs: Vec<String>,
    pub derived_from: Vec<String>,
    pub recorded_by_ref: String,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCandidate {
    pub schema_id: String,
    pub contract_version: String,
    pub memory_id: String,
    pub tenant_ref: String,
    pub subject_ref: String,
    pub actor_ref: String,
    pub memory_class: MemoryClass,
    pub content: String,
    pub content_sha256: String,
    pub purpose: Purpose,
    pub classification: Classification,
    pub provenance: Provenance,
    pub confidence_milli: Option<u16>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub retention_policy_ref: String,
    pub episodic_opt_in_ref: Option<String>,
    pub record_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub candidate: MemoryCandidate,
    pub lifecycle_state: LifecycleState,
    pub approval_ref: Option<String>,
    pub approved_by_ref: Option<String>,
    pub approved_at: Option<u64>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableApprovalReceipt {
    pub approval_ref: String,
    pub memory_id: String,
    pub tenant_ref: String,
    pub subject_ref: String,
    pub content_sha256: String,
    pub reviewer_ref: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Opaque signature or approval proof. G05 does not interpret its format.
    pub proof_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessContext {
    pub principal_ref: String,
    pub tenant_ref: String,
    pub subject_ref: String,
    pub correlation_ref: String,
    pub purpose: Purpose,
    pub requested_classification: Classification,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub operation: Operation,
    pub principal_ref: String,
    pub tenant_ref: String,
    pub subject_ref: String,
    pub purpose: Purpose,
    pub classification: Classification,
    pub memory_id: Option<String>,
    pub recipient_refs: Vec<String>,
    pub correlation_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub memory_id: String,
    pub tenant_ref: String,
    pub actor_ref: String,
    pub purpose: Purpose,
    pub record_version: u64,
    pub outcome: String,
    pub correlation_ref: String,
    pub occurred_at: u64,
    /// Deliberately excludes content and excerpts.
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationPolicy {
    pub max_working_ttl_secs: u64,
    pub max_episodic_ttl_secs: u64,
    pub allowed_purposes: BTreeSet<Purpose>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            // Bounded defaults; deployments may tighten these through policy.
            max_working_ttl_secs: 24 * 60 * 60,
            max_episodic_ttl_secs: 365 * 24 * 60 * 60,
            allowed_purposes: [
                Purpose::TaskContinuity,
                Purpose::UserPreference,
                Purpose::ProjectContext,
                Purpose::OrganizationalContext,
                Purpose::OperationalHistory,
                Purpose::AuthorizedSystemAssurance,
            ]
            .into_iter()
            .collect(),
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn valid_ref(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_REF_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate candidate shape and contract-level policy before any write.
/// This function does not establish consent, identity, tenant membership,
/// authorization, reviewer designation, or source truth; those require ports.
pub fn validate_candidate(
    candidate: &MemoryCandidate,
    now: u64,
    policy: &ValidationPolicy,
) -> Result<(), G05Error> {
    if candidate.schema_id != RECORD_SCHEMA_ID
        || candidate.contract_version != CONTRACT_VERSION
        || !valid_ref(&candidate.memory_id)
        || candidate.memory_id.len() > MAX_MEMORY_ID_BYTES
        || !valid_ref(&candidate.tenant_ref)
        || !valid_ref(&candidate.subject_ref)
        || !valid_ref(&candidate.actor_ref)
        || !valid_ref(&candidate.retention_policy_ref)
        || candidate.record_version == 0
        || candidate.created_at > now
        || candidate.provenance.recorded_at > now
        || !valid_ref(&candidate.provenance.recorded_by_ref)
    {
        return Err(G05Error::MalformedRecord);
    }
    if candidate.content.len() > MAX_CONTENT_BYTES {
        return Err(G05Error::ContentTooLarge);
    }
    if !valid_digest(&candidate.content_sha256)
        || sha256_hex(candidate.content.as_bytes()) != candidate.content_sha256
    {
        return Err(G05Error::DigestMismatch);
    }
    if candidate.provenance.source_refs.len() > MAX_SOURCE_REFS
        || candidate.provenance.source_revision_refs.len() > MAX_SOURCE_REFS
        || candidate.provenance.derived_from.len() > MAX_SOURCE_REFS
    {
        return Err(G05Error::TooManySources);
    }
    if candidate
        .provenance
        .source_refs
        .iter()
        .chain(candidate.provenance.source_revision_refs.iter())
        .chain(candidate.provenance.derived_from.iter())
        .any(|reference| !valid_ref(reference))
    {
        return Err(G05Error::InvalidReference);
    }
    if candidate
        .confidence_milli
        .is_some_and(|confidence| confidence > 1_000)
    {
        return Err(G05Error::MalformedRecord);
    }
    if !policy.allowed_purposes.contains(&candidate.purpose) {
        return Err(G05Error::UnsupportedOperation);
    }

    match candidate.memory_class {
        MemoryClass::Working => {
            if candidate.classification == Classification::Restricted {
                return Err(G05Error::RestrictedWorkingMemory);
            }
            let expiry = candidate.expires_at.ok_or(G05Error::ExpiryRequired)?;
            if expiry <= now || expiry <= candidate.created_at {
                return Err(G05Error::ExpiryInvalid);
            }
            if expiry.saturating_sub(now) > policy.max_working_ttl_secs {
                return Err(G05Error::ExpiryInvalid);
            }
            if candidate.episodic_opt_in_ref.is_some() {
                return Err(G05Error::MalformedRecord);
            }
        }
        MemoryClass::Episodic => {
            let expiry = candidate.expires_at.ok_or(G05Error::ExpiryRequired)?;
            if expiry <= now
                || expiry <= candidate.created_at
                || expiry.saturating_sub(now) > policy.max_episodic_ttl_secs
            {
                return Err(G05Error::ExpiryInvalid);
            }
            if candidate
                .episodic_opt_in_ref
                .as_deref()
                .map_or(true, |reference| !valid_ref(reference))
            {
                return Err(G05Error::EpisodicOptInRequired);
            }
        }
        MemoryClass::Durable => {
            // Durable candidates are proposals only. Approval is checked at
            // activation, never inferred from provenance or confidence.
            if candidate.expires_at.is_some() && candidate.expires_at <= Some(now) {
                return Err(G05Error::ExpiryInvalid);
            }
        }
    }
    Ok(())
}

/// Validate a record-bound durable approval receipt before delegating
/// cryptographic and reviewer-authority verification to the trusted port.
pub fn validate_approval_binding(
    record: &MemoryRecord,
    receipt: &DurableApprovalReceipt,
    now: u64,
) -> Result<(), G05Error> {
    if record.candidate.memory_class != MemoryClass::Durable {
        return Err(G05Error::UnsupportedOperation);
    }
    if record.lifecycle_state != LifecycleState::Proposed
        && record.lifecycle_state != LifecycleState::PendingReview
    {
        return Err(G05Error::InvalidLifecycleTransition);
    }
    if !valid_ref(&receipt.approval_ref)
        || !valid_ref(&receipt.reviewer_ref)
        || !valid_ref(&receipt.proof_ref)
    {
        return Err(G05Error::InvalidReference);
    }
    if receipt.memory_id != record.candidate.memory_id
        || receipt.tenant_ref != record.candidate.tenant_ref
        || receipt.subject_ref != record.candidate.subject_ref
        || receipt.content_sha256 != record.candidate.content_sha256
    {
        return Err(G05Error::ApprovalBindingMismatch);
    }
    if receipt.issued_at < record.candidate.created_at
        || receipt.issued_at > now
        || receipt.expires_at <= now
        || receipt.expires_at <= receipt.issued_at
    {
        return Err(G05Error::ApprovalExpired);
    }
    Ok(())
}

/// Lifecycle transition matrix. No transition can implicitly activate durable
/// memory; callers must first validate a bound approval receipt.
pub fn transition_allowed(from: LifecycleState, to: LifecycleState) -> bool {
    use LifecycleState as S;
    matches!(
        (from, to),
        (S::Proposed, S::PendingReview)
            | (S::Proposed, S::Rejected)
            | (S::PendingReview, S::Rejected)
            | (S::Active, S::Restricted)
            | (S::Active, S::CorrectionPending)
            | (S::Active, S::DeletionPending)
            | (S::Active, S::Expired)
            | (S::Restricted, S::DeletionPending)
            | (S::Restricted, S::Expired)
            | (S::CorrectionPending, S::Active)
            | (S::CorrectionPending, S::Rejected)
            | (S::DeletionPending, S::Deleted)
            | (S::DeletionPending, S::Restricted)
    )
}


/// Activation is a privileged lifecycle transition. It is allowed only when
/// the receipt is bound to this exact record and the trusted governance port
/// has independently verified its signature and reviewer designation.
pub fn validate_durable_activation(
    record: &MemoryRecord,
    receipt: &DurableApprovalReceipt,
    now: u64,
) -> Result<(), G05Error> {
    validate_approval_binding(record, receipt, now)?;
    if record.lifecycle_state != LifecycleState::PendingReview {
        return Err(G05Error::InvalidLifecycleTransition);
    }
    Ok(())
}

/// Sharing requires an explicit G02 policy authorization. Tenant membership
/// or possession of a memory identifier is not sufficient.
pub fn validate_sharing_scope(
    source_tenant: &str,
    requested_tenant: &str,
    recipient_refs: &[String],
    explicit_policy_authorized: bool,
) -> Result<(), G05Error> {
    if source_tenant != requested_tenant {
        return Err(G05Error::TenantScopeMismatch);
    }
    if recipient_refs.is_empty() || recipient_refs.iter().any(|r| !valid_ref(r)) {
        return Err(G05Error::InvalidReference);
    }
    if !explicit_policy_authorized {
        return Err(G05Error::SharingNotAuthorized);
    }
    Ok(())
}

/// Ports required by a concrete G05 service adapter. Implementations MUST
/// resolve G01 identity and tenant authority server-side, call G02 for every
/// operation, verify opt-in and signed human approvals, and emit G11 events.
/// The trait deliberately exposes no caller-controlled authorization result.
pub trait GovernancePort {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), G05Error>;

    fn verify_episodic_opt_in(
        &self,
        opt_in_ref: &str,
        tenant_ref: &str,
        subject_ref: &str,
        purpose: Purpose,
        now: u64,
    ) -> Result<(), G05Error>;

    fn verify_durable_approval(
        &self,
        receipt: &DurableApprovalReceipt,
        organizational: bool,
        now: u64,
    ) -> Result<(), G05Error>;

    /// G11 adapter. Must append a content-free event through an atomic outbox
    /// or equivalent transaction coordinated with the repository mutation.
    fn append_audit(&self, event: &AuditEvent) -> Result<(), G05Error>;
}

/// Repository contract for a G05-owned persistence adapter. Implementations
/// MUST provide tenant-aware constraints, optimistic version checks, atomic
/// state changes, idempotency, and deletion/resurrection controls. Content
/// reads MUST only be invoked after GovernancePort::authorize succeeds.
pub trait MemoryRepository {
    fn insert(&mut self, record: MemoryRecord) -> Result<(), G05Error>;
    fn get_metadata(&self, memory_id: &str) -> Result<Option<MemoryRecord>, G05Error>;
    fn get_content(&self, memory_id: &str) -> Result<Option<MemoryRecord>, G05Error>;
    fn replace(&mut self, record: MemoryRecord, expected_version: u64) -> Result<(), G05Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(class: MemoryClass, classification: Classification) -> MemoryCandidate {
        let content = "synthetic memory".to_owned();
        MemoryCandidate {
            schema_id: RECORD_SCHEMA_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            memory_id: "memory:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            actor_ref: "principal:1".to_owned(),
            memory_class: class,
            content_sha256: sha256_hex(content.as_bytes()),
            content,
            purpose: Purpose::TaskContinuity,
            classification,
            provenance: Provenance {
                kind: ProvenanceKind::UserExplicit,
                source_refs: vec!["source:1".to_owned()],
                source_revision_refs: vec!["revision:1".to_owned()],
                derived_from: vec![],
                recorded_by_ref: "principal:1".to_owned(),
                recorded_at: 100,
            },
            confidence_milli: Some(900),
            created_at: 100,
            expires_at: match class {
                MemoryClass::Working => Some(200),
                MemoryClass::Episodic => Some(200),
                MemoryClass::Durable => None,
            },
            retention_policy_ref: "retention:v1".to_owned(),
            episodic_opt_in_ref: if class == MemoryClass::Episodic {
                Some("opt-in:1".to_owned())
            } else {
                None
            },
            record_version: 1,
        }
    }

    fn policy() -> ValidationPolicy {
        ValidationPolicy::default()
    }

    #[test]
    fn working_memory_requires_bounded_expiry() {
        let mut item = candidate(MemoryClass::Working, Classification::Internal);
        assert_eq!(validate_candidate(&item, 100, &policy()), Ok(()));
        item.expires_at = None;
        assert_eq!(validate_candidate(&item, 100, &policy()), Err(G05Error::ExpiryRequired));
        item.expires_at = Some(100 + 24 * 60 * 60 + 1);
        assert_eq!(validate_candidate(&item, 100, &policy()), Err(G05Error::ExpiryInvalid));
    }

    #[test]
    fn restricted_content_is_rejected_from_working_memory() {
        let item = candidate(MemoryClass::Working, Classification::Restricted);
        assert_eq!(
            validate_candidate(&item, 100, &policy()),
            Err(G05Error::RestrictedWorkingMemory)
        );
    }

    #[test]
    fn episodic_memory_requires_explicit_opt_in_reference() {
        let mut item = candidate(MemoryClass::Episodic, Classification::Internal);
        assert_eq!(validate_candidate(&item, 100, &policy()), Ok(()));
        item.episodic_opt_in_ref = None;
        assert_eq!(
            validate_candidate(&item, 100, &policy()),
            Err(G05Error::EpisodicOptInRequired)
        );
    }

    #[test]
    fn durable_candidate_does_not_activate_by_default() {
        let item = candidate(MemoryClass::Durable, Classification::Confidential);
        assert_eq!(validate_candidate(&item, 100, &policy()), Ok(()));
        assert!(!transition_allowed(LifecycleState::Proposed, LifecycleState::Active));
        assert!(!transition_allowed(LifecycleState::PendingReview, LifecycleState::Active));
        assert!(transition_allowed(LifecycleState::Proposed, LifecycleState::PendingReview));
    }

    #[test]
    fn approval_is_bound_to_exact_record_and_content_digest() {
        let item = candidate(MemoryClass::Durable, Classification::Internal);
        let record = MemoryRecord {
            candidate: item,
            lifecycle_state: LifecycleState::PendingReview,
            approval_ref: None,
            approved_by_ref: None,
            approved_at: None,
            updated_at: 100,
        };
        let receipt = DurableApprovalReceipt {
            approval_ref: "approval:1".to_owned(),
            memory_id: "memory:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            content_sha256: record.candidate.content_sha256.clone(),
            reviewer_ref: "reviewer:1".to_owned(),
            issued_at: 101,
            expires_at: 200,
            proof_ref: "proof:1".to_owned(),
        };
        assert_eq!(validate_approval_binding(&record, &receipt, 110), Ok(()));
        assert_eq!(validate_durable_activation(&record, &receipt, 110), Ok(()));
        let mut tampered = receipt.clone();
        tampered.content_sha256 = "0".repeat(64);
        assert_eq!(
            validate_approval_binding(&record, &tampered, 110),
            Err(G05Error::ApprovalBindingMismatch)
        );
    }

    #[test]
    fn approval_expiry_is_enforced() {
        let item = candidate(MemoryClass::Durable, Classification::Internal);
        let record = MemoryRecord {
            candidate: item,
            lifecycle_state: LifecycleState::Proposed,
            approval_ref: None,
            approved_by_ref: None,
            approved_at: None,
            updated_at: 100,
        };
        let receipt = DurableApprovalReceipt {
            approval_ref: "approval:1".to_owned(),
            memory_id: "memory:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            content_sha256: record.candidate.content_sha256.clone(),
            reviewer_ref: "reviewer:1".to_owned(),
            issued_at: 90,
            expires_at: 100,
            proof_ref: "proof:1".to_owned(),
        };
        assert_eq!(
            validate_approval_binding(&record, &receipt, 100),
            Err(G05Error::ApprovalExpired)
        );
    }

    #[test]
    fn cross_tenant_sharing_is_denied_even_with_policy_flag() {
        assert_eq!(
            validate_sharing_scope("tenant:1", "tenant:2", &["principal:2".to_owned()], true),
            Err(G05Error::TenantScopeMismatch)
        );
    }

    #[test]
    fn cross_principal_sharing_defaults_to_denied() {
        assert_eq!(
            validate_sharing_scope("tenant:1", "tenant:1", &["principal:2".to_owned()], false),
            Err(G05Error::SharingNotAuthorized)
        );
        assert_eq!(
            validate_sharing_scope("tenant:1", "tenant:1", &["principal:2".to_owned()], true),
            Ok(())
        );
    }

    #[test]
    fn digest_mismatch_is_rejected() {
        let mut item = candidate(MemoryClass::Working, Classification::Internal);
        item.content_sha256 = "f".repeat(64);
        assert_eq!(validate_candidate(&item, 100, &policy()), Err(G05Error::DigestMismatch));
    }

    #[test]
    fn model_proposal_is_not_a_verified_fact() {
        let mut item = candidate(MemoryClass::Durable, Classification::Internal);
        item.provenance.kind = ProvenanceKind::ModelProposed;
        assert_eq!(validate_candidate(&item, 100, &policy()), Ok(()));
        assert!(!transition_allowed(LifecycleState::PendingReview, LifecycleState::Active));
    }

    #[test]
    fn deleted_record_cannot_be_reactivated() {
        assert!(!transition_allowed(LifecycleState::Deleted, LifecycleState::Active));
    }

    #[test]
    fn audit_event_has_no_content_field() {
        let event = AuditEvent {
            event_type: "memory.created".to_owned(),
            memory_id: "memory:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            actor_ref: "principal:1".to_owned(),
            purpose: Purpose::TaskContinuity,
            record_version: 1,
            outcome: "accepted".to_owned(),
            correlation_ref: "trace:1".to_owned(),
            occurred_at: 100,
            content_sha256: "a".repeat(64),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("synthetic memory"));
        assert!(!json.contains("\"content\""));
    }
}
