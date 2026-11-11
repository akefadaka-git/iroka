//! Trusted G05 authority composition boundaries.
//!
//! No local consent registry, reviewer directory, trust roots, signing keys,
//! or authorization policy are created here. Those are owned by authoritative
//! services; an absent or failing provider fails closed.
//!
//! G02 owns authorization; the consent authority owns episodic opt-in and
//! revocation; the reviewer authority owns organizational reviewer designation
//! and approval proof verification; G11 owns memory lifecycle audit events.

use crate::{
    AuditEvent, AuthorizationRequest, DurableApprovalReceipt, G05Error, GovernancePort, Purpose,
};

/// Delegates to the canonical G01 -> tenant -> G02 authorization composition.
/// Must not accept caller-asserted principal or tenant authority.
pub trait G02AuthorizationAuthority: Send + Sync {
    fn authorize_g05(&self, request: &AuthorizationRequest) -> Result<(), G05Error>;

    /// Global G02 capability permission is not sufficient to manage a
    /// particular organization's reviewers. Implementations must additionally
    /// resolve the actor's current organization-scoped governance delegation.
    /// Default denial prevents a global capability from becoming an org role.
    fn authorize_organization_scope(
        &self,
        _request: &AuthorizationRequest,
        _organization_ref: &str,
    ) -> Result<(), G05Error> {
        Err(G05Error::ReviewerNotAuthorized)
    }
}

/// Loads authoritative consent state and verifies exact tenant, subject,
/// purpose, opt-in state, effective interval, revocation and record integrity.
/// The reference is a selector, never proof. Consent is purpose-specific.
pub trait EpisodicConsentAuthority: Send + Sync {
    fn verify_active_opt_in(
        &self,
        consent_ref: &str,
        tenant_ref: &str,
        subject_ref: &str,
        purpose: Purpose,
        now: u64,
    ) -> Result<(), G05Error>;
}

/// Re-resolves the current reviewer designation for the organization, validates
/// the approval proof against a separately provisioned trust root, and checks
/// exact organization/reviewer/memory/tenant/subject/digest scope, validity,
/// revocation and replay. Owner approval alone is not reviewer designation.
pub trait DesignatedReviewerAuthority: Send + Sync {
    fn verify_designated_reviewer(
        &self,
        receipt: &DurableApprovalReceipt,
        proof: &iroka_kernel::VerifiedReviewerProof,
        record: &crate::MemoryRecord,
        organization_ref: &str,
        now: u64,
    ) -> Result<(), G05Error>;
}

/// G11-owned versioned, content-free lifecycle event sink. The receiver MUST
/// deduplicate by event ID because the durable G05 outbox retries after crashes.
/// Atomicity with a G05 authority mutation is supplied by the local outbox
/// transaction, not by this cross-domain delivery call.
pub trait G11MemoryAuditAuthority: Send + Sync {
    fn append_memory_event(&self, event: &AuditEvent) -> Result<(), G05Error>;
}

/// Composition only: no authority is minted locally. All four domain owners
/// are required; providers must be authenticated server-side implementations.
pub struct TrustedGovernanceAdapter<G, C, R, A> {
    g02: G,
    consent: C,
    reviewers: R,
    g11: A,
}
impl<G, C, R, A> TrustedGovernanceAdapter<G, C, R, A> {
    pub fn new(g02: G, consent: C, reviewers: R, g11: A) -> Self {
        Self {
            g02,
            consent,
            reviewers,
            g11,
        }
    }
    pub fn into_parts(self) -> (G, C, R, A) {
        (self.g02, self.consent, self.reviewers, self.g11)
    }
}
impl<G, C, R, A> GovernancePort for TrustedGovernanceAdapter<G, C, R, A>
where
    G: G02AuthorizationAuthority,
    C: EpisodicConsentAuthority,
    R: DesignatedReviewerAuthority,
    A: G11MemoryAuditAuthority,
{
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), G05Error> {
        self.g02.authorize_g05(request)
    }
    fn verify_episodic_opt_in(
        &self,
        reference: &str,
        tenant: &str,
        subject: &str,
        purpose: Purpose,
        now: u64,
    ) -> Result<(), G05Error> {
        self.consent
            .verify_active_opt_in(reference, tenant, subject, purpose, now)
    }
    fn verify_durable_approval(
        &self,
        receipt: &DurableApprovalReceipt,
        proof: &iroka_kernel::VerifiedReviewerProof,
        record: &crate::MemoryRecord,
        now: u64,
    ) -> Result<(), G05Error> {
        self.reviewers
            .verify_designated_reviewer(receipt, proof, record, &receipt.subject_ref, now)
    }
    fn append_audit(&self, event: &AuditEvent) -> Result<(), G05Error> {
        self.g11.append_memory_event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record_and_proof(receipt: &DurableApprovalReceipt) -> (crate::MemoryRecord, iroka_kernel::VerifiedReviewerProof) {
        let record = crate::MemoryRecord {
            candidate: crate::MemoryCandidate {
                schema_id: crate::RECORD_SCHEMA_ID.into(),
                contract_version: crate::CONTRACT_VERSION.into(),
                memory_id: receipt.memory_id.clone(),
                tenant_ref: receipt.tenant_ref.clone(),
                subject_ref: receipt.subject_ref.clone(),
                actor_ref: "actor:owner".into(),
                memory_class: crate::MemoryClass::Durable,
                content: "test".into(),
                content_sha256: receipt.content_sha256.clone(),
                purpose: Purpose::OrganizationalContext,
                classification: Classification::Confidential,
                provenance: crate::Provenance { kind: crate::ProvenanceKind::OwnerApproved,
                    source_refs: vec![], source_revision_refs: vec![], derived_from: vec![],
                    recorded_by_ref: "actor:owner".into(), recorded_at: 100 },
                confidence_milli: None, created_at: 100, expires_at: None,
                retention_policy_ref: "retention:v1".into(), episodic_opt_in_ref: None, record_version: 1,
            },
            lifecycle_state: crate::LifecycleState::PendingReview,
            approval_ref: None, approved_by_ref: None, approved_at: None, updated_at: 100,
        };
        let resource = format!("g05:durable-approval:{}:{}:{}:v{}:{}",
            record.candidate.tenant_ref, record.candidate.subject_ref, record.candidate.memory_id,
            record.candidate.record_version, record.candidate.content_sha256);
        let payload = iroka_kernel::ReviewerProofPayload {
            proof_id: receipt.proof_ref.clone(), issuer: "issuer:test".into(), subject: "reviewer:test".into(),
            credential_id: "credential:test".into(), reviewer_id: receipt.reviewer_ref.clone(),
            designation_id: "designation:1".into(), designation_version: 1, key_id: "key:1".into(),
            approval_id: receipt.approval_ref.clone(), tenant_id: record.candidate.tenant_ref.clone(),
            organization_id: record.candidate.subject_ref.clone(), memory_id: record.candidate.memory_id.clone(),
            record_version: 1, content_sha256: record.candidate.content_sha256.clone(),
            purpose: "ORGANIZATIONAL_CONTEXT".into(), classification: "CONFIDENTIAL".into(),
            capability: "g05.memory.durable.approve".into(), resource,
            policy_version: crate::CONTRACT_VERSION.into(), issued_at: receipt.issued_at, expires_at: receipt.expires_at,
        };
        (record, iroka_kernel::VerifiedReviewerProof::for_test(&payload, 150))
    }
    struct AllowG02;
    impl G02AuthorizationAuthority for AllowG02 {
        fn authorize_g05(&self, _: &AuthorizationRequest) -> Result<(), G05Error> {
            Ok(())
        }
        fn authorize_organization_scope(
            &self,
            _: &AuthorizationRequest,
            _: &str,
        ) -> Result<(), G05Error> {
            Ok(())
        }
    }
    struct DenyConsent;
    impl EpisodicConsentAuthority for DenyConsent {
        fn verify_active_opt_in(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Purpose,
            _: u64,
        ) -> Result<(), G05Error> {
            Err(G05Error::EpisodicOptInRequired)
        }
    }
    struct DenyReviewer;
    impl DesignatedReviewerAuthority for DenyReviewer {
        fn verify_designated_reviewer(
            &self,
            _: &DurableApprovalReceipt,
            _: &iroka_kernel::VerifiedReviewerProof,
            _: &crate::MemoryRecord,
            _: &str,
            _: u64,
        ) -> Result<(), G05Error> {
            Err(G05Error::ReviewerNotAuthorized)
        }
    }
    struct AllowAudit;
    impl G11MemoryAuditAuthority for AllowAudit {
        fn append_memory_event(&self, _: &AuditEvent) -> Result<(), G05Error> {
            Ok(())
        }
    }
    #[test]
    fn missing_or_revoked_consent_fails_closed() {
        let adapter =
            TrustedGovernanceAdapter::new(AllowG02, DenyConsent, DenyReviewer, AllowAudit);
        assert_eq!(
            adapter.verify_episodic_opt_in(
                "consent:selector",
                "tenant:1",
                "principal:1",
                Purpose::TaskContinuity,
                100
            ),
            Err(G05Error::EpisodicOptInRequired)
        );
    }
    #[test]
    fn undesignated_reviewer_fails_closed() {
        let adapter =
            TrustedGovernanceAdapter::new(AllowG02, DenyConsent, DenyReviewer, AllowAudit);
        let receipt = DurableApprovalReceipt {
            approval_ref: "approval:1".into(),
            memory_id: "memory:1".into(),
            tenant_ref: "tenant:1".into(),
            subject_ref: "organization:1".into(),
            content_sha256: "a".repeat(64),
            reviewer_ref: "principal:unlisted".into(),
            issued_at: 100,
            expires_at: 200,
            proof_ref: "proof:1".into(),
        };
        let (record, proof) = test_record_and_proof(&receipt);
        assert_eq!(
            adapter.verify_durable_approval(&receipt, &proof, &record, 150),
            Err(G05Error::ReviewerNotAuthorized)
        );
    }
    #[test]
    fn global_g02_capability_does_not_grant_organization_reviewer_authority() {
        struct CapabilityOnly;
        impl G02AuthorizationAuthority for CapabilityOnly {
            fn authorize_g05(&self, _: &AuthorizationRequest) -> Result<(), G05Error> {
                Ok(())
            }
        }
        let request = AuthorizationRequest {
            operation: crate::Operation::DesignateReviewer,
            principal_ref: "principal:actor".into(),
            tenant_ref: "tenant:one".into(),
            subject_ref: "org:one".into(),
            purpose: Purpose::OrganizationalContext,
            classification: crate::Classification::Confidential,
            memory_id: None,
            recipient_refs: vec!["principal:reviewer".into()],
            correlation_ref: "designation:one".into(),
        };
        assert_eq!(
            CapabilityOnly.authorize_organization_scope(&request, "org:one"),
            Err(G05Error::ReviewerNotAuthorized)
        );
    }
}

/// Concrete bridge from G05's transactional outbox payload to the G11-owned
/// versioned memory lifecycle stream. The adapter deliberately drops the
/// content digest: it is not needed for lifecycle assurance and can enable
/// dictionary attacks against low-entropy memory content.
pub struct KernelG11MemoryAuditAdapter<'a> {
    sink: &'a iroka_kernel::SqliteMemoryLifecycleAuditStore,
}

impl<'a> KernelG11MemoryAuditAdapter<'a> {
    pub fn new(sink: &'a iroka_kernel::SqliteMemoryLifecycleAuditStore) -> Self {
        Self { sink }
    }
}

impl G11MemoryAuditAuthority for KernelG11MemoryAuditAdapter<'_> {
    fn append_memory_event(&self, event: &AuditEvent) -> Result<(), G05Error> {
        use iroka_kernel::MemoryLifecycleAuditSink;
        let purpose = match event.purpose {
            Purpose::TaskContinuity => "TASK_CONTINUITY",
            Purpose::UserPreference => "USER_PREFERENCE",
            Purpose::ProjectContext => "PROJECT_CONTEXT",
            Purpose::OrganizationalContext => "ORGANIZATIONAL_CONTEXT",
            Purpose::OperationalHistory => "OPERATIONAL_HISTORY",
            Purpose::AuthorizedSystemAssurance => "AUTHORIZED_SYSTEM_ASSURANCE",
        };
        let versioned = iroka_kernel::MemoryLifecycleEvent::new(
            event.event_id.clone(),
            event.event_type.clone(),
            event.memory_id.clone(),
            event.tenant_ref.clone(),
            event.actor_ref.clone(),
            purpose,
            event.record_version,
            event.outcome.clone(),
            event.correlation_ref.clone(),
            event.occurred_at,
        );
        self.sink
            .append_memory_event(&versioned)
            .map_err(|_| G05Error::AuditUnavailable)
    }
}

#[cfg(test)]
mod kernel_g11_adapter_tests {
    use super::*;

    #[test]
    fn kernel_g11_adapter_emits_versioned_content_free_events_idempotently() {
        let sink = iroka_kernel::SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let adapter = KernelG11MemoryAuditAdapter::new(&sink);
        let event = AuditEvent {
            event_id: "event:consent:1".into(),
            event_type: "memory.consent.granted".into(),
            memory_id: "consent:opaque-1".into(),
            tenant_ref: "tenant:opaque-1".into(),
            actor_ref: "principal:opaque-1".into(),
            purpose: Purpose::TaskContinuity,
            record_version: 1,
            outcome: "granted".into(),
            correlation_ref: "trace:opaque-1".into(),
            occurred_at: 100,
            content_sha256: "a".repeat(64),
        };
        adapter.append_memory_event(&event).unwrap();
        adapter.append_memory_event(&event).unwrap();
        sink.verify_integrity().unwrap();
    }

    #[test]
    fn kernel_g11_adapter_rejects_invalid_event_and_fails_closed() {
        let sink = iroka_kernel::SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let adapter = KernelG11MemoryAuditAdapter::new(&sink);
        let mut event = AuditEvent {
            event_id: "event:1".into(),
            event_type: "decision.allow".into(),
            memory_id: "aggregate:1".into(),
            tenant_ref: "tenant:1".into(),
            actor_ref: "principal:1".into(),
            purpose: Purpose::TaskContinuity,
            record_version: 1,
            outcome: "accepted".into(),
            correlation_ref: "trace:1".into(),
            occurred_at: 100,
            content_sha256: "b".repeat(64),
        };
        assert_eq!(
            adapter.append_memory_event(&event),
            Err(G05Error::AuditUnavailable)
        );
        event.event_type = "memory.created".into();
        event.actor_ref.clear();
        assert_eq!(
            adapter.append_memory_event(&event),
            Err(G05Error::AuditUnavailable)
        );
    }
}
