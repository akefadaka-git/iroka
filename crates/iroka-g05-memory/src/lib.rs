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

mod registry;
pub use registry::{
    G01ReviewerProofAuthority, KernelG02AuthorizationAdapter, RegistryDesignatedReviewerAuthority,
    ReviewerDesignation, SqliteG05AuthorityRegistry,
};

mod authority;
pub use authority::{
    DesignatedReviewerAuthority, EpisodicConsentAuthority, G02AuthorizationAuthority,
    G11MemoryAuditAuthority, KernelG11MemoryAuditAdapter, TrustedGovernanceAdapter,
};

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
    GrantEpisodicConsent,
    WithdrawEpisodicConsent,
    DesignateReviewer,
    RevokeReviewerDesignation,
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
    ConsentScopeMismatch,
    ApprovalReplay,
    AuthorityUnavailable,
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

/// Metadata-only view returned before content access. It intentionally
/// excludes the content field and any excerpt or derived text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryMetadata {
    pub memory_id: String,
    pub tenant_ref: String,
    pub subject_ref: String,
    pub memory_class: MemoryClass,
    pub content_sha256: String,
    pub purpose: Purpose,
    pub classification: Classification,
    pub lifecycle_state: LifecycleState,
    pub expires_at: Option<u64>,
    pub record_version: u64,
    pub retention_policy_ref: String,
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
    /// Stable outbox identifier; G11 sinks must deduplicate on this value.
    pub event_id: String,
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
    !value.trim().is_empty() && value.len() <= MAX_REF_BYTES && !value.chars().any(char::is_control)
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

/// Prepare a new record after policy validation, G02 authorization and (for
/// episodic capture) trusted opt-in verification. Durable records always enter
/// review; working and episodic records become active only after their gates.
pub fn prepare_candidate_record<G: GovernancePort>(
    candidate: MemoryCandidate,
    request: &AuthorizationRequest,
    policy: &ValidationPolicy,
    governance: &G,
    now: u64,
) -> Result<MemoryRecord, G05Error> {
    validate_candidate(&candidate, now, policy)?;
    let expected_operation = match candidate.memory_class {
        MemoryClass::Working => Operation::CreateWorking,
        MemoryClass::Episodic => Operation::CreateEpisodic,
        MemoryClass::Durable => Operation::Propose,
    };
    if request.operation != expected_operation
        || request.memory_id.as_deref() != Some(candidate.memory_id.as_str())
        || request.tenant_ref != candidate.tenant_ref
        || request.subject_ref != candidate.subject_ref
        || request.principal_ref != candidate.actor_ref
        || request.purpose != candidate.purpose
        || request.classification != candidate.classification
        || !valid_ref(&request.correlation_ref)
    {
        return Err(G05Error::MalformedRecord);
    }
    governance.authorize(request)?;
    if candidate.memory_class == MemoryClass::Episodic {
        let opt_in_ref = candidate
            .episodic_opt_in_ref
            .as_deref()
            .ok_or(G05Error::EpisodicOptInRequired)?;
        governance.verify_episodic_opt_in(
            opt_in_ref,
            &candidate.tenant_ref,
            &candidate.subject_ref,
            candidate.purpose,
            now,
        )?;
    }
    let lifecycle_state = match candidate.memory_class {
        MemoryClass::Working | MemoryClass::Episodic => LifecycleState::Active,
        MemoryClass::Durable => LifecycleState::PendingReview,
    };
    Ok(MemoryRecord {
        candidate,
        lifecycle_state,
        approval_ref: None,
        approved_by_ref: None,
        approved_at: None,
        updated_at: now,
    })
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
pub fn validate_durable_activation_binding(
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

/// First retrieval authorization. A caller MUST invoke this before even
/// looking up record metadata; the record ID is only a selector.
pub fn authorize_retrieval_request<G: GovernancePort>(
    request: &AuthorizationRequest,
    governance: &G,
) -> Result<(), G05Error> {
    if request.operation != Operation::Retrieve
        || request
            .memory_id
            .as_deref()
            .map_or(true, |id| !valid_ref(id))
        || !valid_ref(&request.principal_ref)
        || !valid_ref(&request.tenant_ref)
        || !valid_ref(&request.subject_ref)
        || !valid_ref(&request.correlation_ref)
    {
        return Err(G05Error::MalformedRecord);
    }
    governance.authorize(request)
}

/// Second retrieval authorization, after metadata-only lookup and before
/// content access. This binds the G02 decision to the stored record's actual
/// tenant, subject, purpose, classification, state and expiry.
pub fn authorize_retrieval_metadata<G: GovernancePort>(
    metadata: &MemoryMetadata,
    request: &AuthorizationRequest,
    governance: &G,
    now: u64,
) -> Result<(), G05Error> {
    if request.operation != Operation::Retrieve
        || request.memory_id.as_deref() != Some(metadata.memory_id.as_str())
        || request.tenant_ref != metadata.tenant_ref
        || request.subject_ref != metadata.subject_ref
        || request.purpose != metadata.purpose
        || request.classification != metadata.classification
    {
        return Err(G05Error::TenantScopeMismatch);
    }
    if metadata.lifecycle_state != LifecycleState::Active
        || metadata.expires_at.is_some_and(|expiry| expiry <= now)
    {
        return Err(G05Error::RecordNotActive);
    }
    governance.authorize(request)
}

/// Complete durable activation preflight. This function enforces operation
/// scope, G02 authorization, record-bound receipt integrity, and delegated
/// cryptographic/designated-reviewer verification. Persistence and G11
/// transactional outbox completion remain the repository adapter's duty.
pub fn authorize_durable_activation<G: GovernancePort>(
    record: &MemoryRecord,
    receipt: &DurableApprovalReceipt,
    principal: &iroka_kernel::VerifiedPrincipal,
    request: &AuthorizationRequest,
    governance: &G,
    now: u64,
) -> Result<(), G05Error> {
    if request.operation != Operation::ActivateDurable
        || request.memory_id.as_deref() != Some(record.candidate.memory_id.as_str())
        || request.tenant_ref != record.candidate.tenant_ref
        || request.subject_ref != record.candidate.subject_ref
        || request.purpose != record.candidate.purpose
        || request.classification != record.candidate.classification
        || request.principal_ref != principal.subject()
        || principal.subject() != receipt.reviewer_ref
        || !valid_ref(&request.correlation_ref)
    {
        return Err(G05Error::ApprovalBindingMismatch);
    }
    validate_durable_activation_binding(record, receipt, now)?;
    governance.authorize(request)?;
    governance.verify_durable_approval(principal, record, receipt, now)?;
    Ok(())
}

/// Prepare an approved durable record transition. The returned value is not
/// persisted; the caller MUST commit it with the G11 outbox using the G05
/// repository transaction port. A replayed or stale version fails closed.
pub fn prepare_durable_activation<G: GovernancePort>(
    record: &MemoryRecord,
    receipt: &DurableApprovalReceipt,
    principal: &iroka_kernel::VerifiedPrincipal,
    request: &AuthorizationRequest,
    governance: &G,
    now: u64,
) -> Result<MemoryRecord, G05Error> {
    authorize_durable_activation(record, receipt, principal, request, governance, now)?;
    let mut activated = record.clone();
    activated.candidate.record_version = record
        .candidate
        .record_version
        .checked_add(1)
        .ok_or(G05Error::VersionConflict)?;
    activated.lifecycle_state = LifecycleState::Active;
    activated.approval_ref = Some(receipt.approval_ref.clone());
    activated.approved_by_ref = Some(receipt.reviewer_ref.clone());
    activated.approved_at = Some(now);
    activated.updated_at = now;
    Ok(activated)
}

/// Verify opt-in through the authoritative consent/governance adapter before
/// episodic capture. A reference's presence alone is not proof of consent.
pub fn authorize_episodic_capture<G: GovernancePort>(
    candidate: &MemoryCandidate,
    request: &AuthorizationRequest,
    governance: &G,
    now: u64,
) -> Result<(), G05Error> {
    if candidate.memory_class != MemoryClass::Episodic
        || request.operation != Operation::CreateEpisodic
        || request.tenant_ref != candidate.tenant_ref
        || request.subject_ref != candidate.subject_ref
        || request.principal_ref != candidate.actor_ref
        || request.memory_id.as_deref() != Some(candidate.memory_id.as_str())
        || request.purpose != candidate.purpose
        || request.classification != candidate.classification
    {
        return Err(G05Error::MalformedRecord);
    }
    let opt_in_ref = candidate
        .episodic_opt_in_ref
        .as_deref()
        .ok_or(G05Error::EpisodicOptInRequired)?;
    governance.authorize(request)?;
    governance.verify_episodic_opt_in(
        opt_in_ref,
        &candidate.tenant_ref,
        &candidate.subject_ref,
        candidate.purpose,
        now,
    )?;
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
        principal: &iroka_kernel::VerifiedPrincipal,
        record: &MemoryRecord,
        receipt: &DurableApprovalReceipt,
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
    /// Atomically persist the record and enqueue its content-free G11 event.
    fn insert_with_audit(
        &mut self,
        record: MemoryRecord,
        event: AuditEvent,
    ) -> Result<(), G05Error>;

    /// Metadata reads MUST NOT materialize or return the memory content.
    fn get_metadata(&self, memory_id: &str) -> Result<Option<MemoryMetadata>, G05Error>;

    /// Call only after G01/tenant/G02 authorization has succeeded against
    /// metadata and classification.
    fn get_content(&self, memory_id: &str) -> Result<Option<MemoryRecord>, G05Error>;

    /// Atomically compare the expected version, replace the record, and
    /// enqueue its G11 event. A conflict MUST NOT partially commit.
    fn replace_with_audit(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AllowGovernance;
    impl GovernancePort for AllowGovernance {
        fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), G05Error> {
            Ok(())
        }
        fn verify_episodic_opt_in(
            &self,
            _opt_in_ref: &str,
            _tenant_ref: &str,
            _subject_ref: &str,
            _purpose: Purpose,
            _now: u64,
        ) -> Result<(), G05Error> {
            Ok(())
        }
        fn verify_durable_approval(
            &self,
            _receipt: &DurableApprovalReceipt,
            _now: u64,
        ) -> Result<(), G05Error> {
            Ok(())
        }
        fn append_audit(&self, _event: &AuditEvent) -> Result<(), G05Error> {
            Ok(())
        }
    }

    struct DenyGovernance;
    impl GovernancePort for DenyGovernance {
        fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), G05Error> {
            Err(G05Error::AuthorizationDenied)
        }
        fn verify_episodic_opt_in(
            &self,
            _opt_in_ref: &str,
            _tenant_ref: &str,
            _subject_ref: &str,
            _purpose: Purpose,
            _now: u64,
        ) -> Result<(), G05Error> {
            Ok(())
        }
        fn verify_durable_approval(
            &self,
            _receipt: &DurableApprovalReceipt,
            _now: u64,
        ) -> Result<(), G05Error> {
            Ok(())
        }
        fn append_audit(&self, _event: &AuditEvent) -> Result<(), G05Error> {
            Ok(())
        }
    }

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
        ValidationPolicy {
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

    #[test]
    fn durable_candidate_creation_enters_review_not_active() {
        let item = candidate(MemoryClass::Durable, Classification::Internal);
        let request = AuthorizationRequest {
            operation: Operation::Propose,
            principal_ref: "principal:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            memory_id: Some("memory:1".to_owned()),
            recipient_refs: vec![],
            correlation_ref: "trace:1".to_owned(),
        };
        let record =
            prepare_candidate_record(item, &request, &policy(), &AllowGovernance, 110).unwrap();
        assert_eq!(record.lifecycle_state, LifecycleState::PendingReview);
        assert_eq!(record.approval_ref, None);
    }

    #[test]
    fn working_candidate_creation_requires_g02_authorization() {
        let item = candidate(MemoryClass::Working, Classification::Internal);
        let request = AuthorizationRequest {
            operation: Operation::CreateWorking,
            principal_ref: "principal:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            memory_id: Some("memory:1".to_owned()),
            recipient_refs: vec![],
            correlation_ref: "trace:1".to_owned(),
        };
        assert_eq!(
            prepare_candidate_record(item.clone(), &request, &policy(), &AllowGovernance, 110)
                .unwrap()
                .lifecycle_state,
            LifecycleState::Active
        );
        assert_eq!(
            prepare_candidate_record(item, &request, &policy(), &DenyGovernance, 110),
            Err(G05Error::AuthorizationDenied)
        );
    }

    #[test]
    fn working_memory_requires_bounded_expiry() {
        let mut item = candidate(MemoryClass::Working, Classification::Internal);
        assert_eq!(validate_candidate(&item, 100, &policy()), Ok(()));
        item.expires_at = None;
        assert_eq!(
            validate_candidate(&item, 100, &policy()),
            Err(G05Error::ExpiryRequired)
        );
        item.expires_at = Some(100 + 24 * 60 * 60 + 1);
        assert_eq!(
            validate_candidate(&item, 100, &policy()),
            Err(G05Error::ExpiryInvalid)
        );
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
        let request = AuthorizationRequest {
            operation: Operation::CreateEpisodic,
            principal_ref: "principal:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            memory_id: Some("memory:1".to_owned()),
            recipient_refs: vec![],
            correlation_ref: "trace:1".to_owned(),
        };
        assert_eq!(
            authorize_episodic_capture(&item, &request, &AllowGovernance, 110),
            Ok(())
        );
        assert_eq!(
            authorize_episodic_capture(&item, &request, &DenyGovernance, 110),
            Err(G05Error::AuthorizationDenied)
        );
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
        assert!(!transition_allowed(
            LifecycleState::Proposed,
            LifecycleState::Active
        ));
        assert!(!transition_allowed(
            LifecycleState::PendingReview,
            LifecycleState::Active
        ));
        assert!(transition_allowed(
            LifecycleState::Proposed,
            LifecycleState::PendingReview
        ));
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
        let request = AuthorizationRequest {
            operation: Operation::ActivateDurable,
            principal_ref: "reviewer:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            memory_id: Some("memory:1".to_owned()),
            recipient_refs: vec![],
            correlation_ref: "trace:1".to_owned(),
        };
        assert_eq!(
            authorize_durable_activation(&record, &receipt, &request, &AllowGovernance, 110),
            Ok(())
        );
        assert_eq!(
            authorize_durable_activation(&record, &receipt, &request, &DenyGovernance, 110),
            Err(G05Error::AuthorizationDenied)
        );
        let activated =
            prepare_durable_activation(&record, &receipt, &request, &AllowGovernance, 110).unwrap();
        assert_eq!(activated.lifecycle_state, LifecycleState::Active);
        assert_eq!(activated.approved_by_ref.as_deref(), Some("reviewer:1"));
        assert_eq!(activated.candidate.record_version, 2);

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
        assert_eq!(
            validate_candidate(&item, 100, &policy()),
            Err(G05Error::DigestMismatch)
        );
    }

    #[test]
    fn model_proposal_is_not_a_verified_fact() {
        let mut item = candidate(MemoryClass::Durable, Classification::Internal);
        item.provenance.kind = ProvenanceKind::ModelProposed;
        assert_eq!(validate_candidate(&item, 100, &policy()), Ok(()));
        assert!(!transition_allowed(
            LifecycleState::PendingReview,
            LifecycleState::Active
        ));
    }

    #[test]
    fn deleted_record_cannot_be_reactivated() {
        assert!(!transition_allowed(
            LifecycleState::Deleted,
            LifecycleState::Active
        ));
    }

    #[test]
    fn retrieval_requires_preflight_and_stored_scope_authorization() {
        let request = AuthorizationRequest {
            operation: Operation::Retrieve,
            principal_ref: "principal:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            memory_id: Some("memory:1".to_owned()),
            recipient_refs: vec![],
            correlation_ref: "trace:1".to_owned(),
        };
        let metadata = MemoryMetadata {
            memory_id: "memory:1".to_owned(),
            tenant_ref: "tenant:1".to_owned(),
            subject_ref: "principal:1".to_owned(),
            memory_class: MemoryClass::Working,
            content_sha256: "a".repeat(64),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            lifecycle_state: LifecycleState::Active,
            expires_at: Some(200),
            record_version: 1,
            retention_policy_ref: "retention:v1".to_owned(),
        };
        assert_eq!(
            authorize_retrieval_request(&request, &AllowGovernance),
            Ok(())
        );
        assert_eq!(
            authorize_retrieval_metadata(&metadata, &request, &AllowGovernance, 150),
            Ok(())
        );
        assert_eq!(
            authorize_retrieval_request(&request, &DenyGovernance),
            Err(G05Error::AuthorizationDenied)
        );
        let mut cross_tenant = request.clone();
        cross_tenant.tenant_ref = "tenant:2".to_owned();
        assert_eq!(
            authorize_retrieval_metadata(&metadata, &cross_tenant, &AllowGovernance, 150),
            Err(G05Error::TenantScopeMismatch)
        );
        let mut expired = metadata;
        expired.expires_at = Some(150);
        assert_eq!(
            authorize_retrieval_metadata(&expired, &request, &AllowGovernance, 150),
            Err(G05Error::RecordNotActive)
        );
    }

    #[test]
    fn audit_event_has_no_content_field() {
        let event = AuditEvent {
            event_id: "event:memory-created:1".to_owned(),
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
