//! Cross-domain G05 authority composition.
//!
//! G01 verifies signed reviewer proof and current key binding. G02 alone
//! resolves organization designation/delegation for the complete activation
//! tuple. G05 owns episodic consent and memory lifecycle only. G11 owns audit
//! acceptance. No reviewer designation authority is persisted in G05.
use std::sync::Arc;

use iroka_kernel::{
    G05ActivationDecision, G05ActivationTuple, OrganizationAuthorityResolver,
    ReviewerKeyBindingResolver, ReviewerProofVerifier, SignedReviewerProof,
    SqliteSecurityStore, TenantContext, VerifiedPrincipal, VerifiedReviewerProof,
};

use crate::{
    AuditEvent, AuthorizationRequest, DurableApprovalReceipt, EpisodicConsentAuthority,
    G05Error, GovernancePort, G11MemoryAuditAuthority, MemoryRecord, Purpose,
};

pub trait G02AuthorizationAuthority: Send + Sync {
    fn authorize_g05(&self, request: &AuthorizationRequest) -> Result<(), G05Error>;

    fn resolve_g05_activation(
        &self,
        verified_proof: &VerifiedReviewerProof,
        receipt: &DurableApprovalReceipt,
        record: &MemoryRecord,
        reviewer: &VerifiedPrincipal,
        now: u64,
    ) -> Result<G05ActivationDecision, G05Error>;
}

pub trait G01ReviewerProofAuthority: Send + Sync {
    fn verify_approval_proof(
        &self,
        proof: &SignedReviewerProof,
        principal: &VerifiedPrincipal,
        receipt: &DurableApprovalReceipt,
        record: &MemoryRecord,
        now: u64,
    ) -> Result<VerifiedReviewerProof, G05Error>;
}

pub trait G11MemoryAuditAuthority: Send + Sync {
    fn append_memory_event(&self, event: &AuditEvent) -> Result<crate::G11Acknowledgment, G05Error>;
}

pub trait TenantContextResolver: Send + Sync {
    fn resolve_current_tenant(
        &self,
        principal: &VerifiedPrincipal,
        tenant_id: &str,
    ) -> Result<TenantContext, G05Error>;
}

/// Concrete G01 adapter: the proof signature covers designation/delegation,
/// memory tuple, purpose, classification, policy, and identity-key binding.
pub struct KernelG01ReviewerProofAdapter<R: ReviewerKeyBindingResolver> {
    verifier: ReviewerProofVerifier<R>,
}
impl<R: ReviewerKeyBindingResolver> KernelG01ReviewerProofAdapter<R> {
    pub fn new(bindings: R, store: Arc<SqliteSecurityStore>) -> Self {
        Self { verifier: ReviewerProofVerifier::new(bindings, store) }
    }
}
impl<R: ReviewerKeyBindingResolver> G01ReviewerProofAuthority for KernelG01ReviewerProofAdapter<R> {
    fn verify_approval_proof(
        &self,
        proof: &SignedReviewerProof,
        principal: &VerifiedPrincipal,
        receipt: &DurableApprovalReceipt,
        record: &MemoryRecord,
        now: u64,
    ) -> Result<VerifiedReviewerProof, G05Error> {
        let p = &proof.payload;
        let resource = format!(
            "g05:durable.activate:{}:{}",
            record.candidate.memory_id, record.candidate.record_version
        );
        if receipt.issued_at != p.issued_at
            || receipt.expires_at != p.expires_at
            || receipt.proof_ref != p.proof_id
            || receipt.reviewer_ref != p.reviewer_id
            || p.tenant_id != record.candidate.tenant_ref
            || p.memory_id != record.candidate.memory_id
            || p.record_version != record.candidate.record_version
            || p.content_sha256 != record.candidate.content_sha256
            || p.purpose != purpose_key(record.candidate.purpose)
            || p.classification != classification_key(record.candidate.classification)
            || p.capability != "g05.memory.durable.activate"
            || p.resource != resource
            || p.policy_version != "g05-memory-v1"
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        let verified = self.verifier.verify_and_consume(
            proof,
            principal,
            &receipt.reviewer_ref,
            &receipt.approval_ref,
            &record.candidate.tenant_ref,
            &p.organization_id,
            &p.designation_id,
            p.designation_version,
            p.delegation_id.as_deref(),
            p.delegation_version,
            &record.candidate.memory_id,
            record.candidate.record_version,
            &record.candidate.content_sha256,
            purpose_key(record.candidate.purpose),
            classification_key(record.candidate.classification),
            "g05.memory.durable.activate",
            &resource,
            "g05-memory-v1",
            now,
        ).map_err(|_| G05Error::ReviewerNotAuthorized)?;
        Ok(verified)
    }
}

/// Concrete G02 adapter. General G05 operation authorization is supplied by
/// the authenticated service pipeline; activation authority is always
/// re-resolved from the canonical G02 store on this request.
pub struct KernelG02ActivationAdapter<A, T> {
    resolver: OrganizationAuthorityResolver,
    request_authorizer: A,
    tenants: T,
    max_authority_age_secs: u64,
}
impl<A, T> KernelG02ActivationAdapter<A, T> {
    pub fn new(
        resolver: OrganizationAuthorityResolver,
        request_authorizer: A,
        tenants: T,
        max_authority_age_secs: u64,
    ) -> Self {
        Self { resolver, request_authorizer, tenants, max_authority_age_secs }
    }
}
pub trait G02RequestAuthorizer: Send + Sync {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), G05Error>;
}
impl<A: G02RequestAuthorizer, T: TenantContextResolver> G02AuthorizationAuthority
    for KernelG02ActivationAdapter<A, T>
{
    fn authorize_g05(&self, request: &AuthorizationRequest) -> Result<(), G05Error> {
        self.request_authorizer.authorize(request)
    }

    fn resolve_g05_activation(
        &self,
        proof: &VerifiedReviewerProof,
        receipt: &DurableApprovalReceipt,
        record: &MemoryRecord,
        reviewer: &VerifiedPrincipal,
        now: u64,
    ) -> Result<G05ActivationDecision, G05Error> {
        let tuple = G05ActivationTuple {
            tenant_id: proof.tenant_id().to_owned(),
            organization_id: proof.organization_id().to_owned(),
            reviewer_subject: proof.subject().to_owned(),
            designation_id: proof.designation_id().to_owned(),
            designation_version: proof.designation_version(),
            delegation_id: proof.delegation_id().map(str::to_owned),
            delegation_version: proof.delegation_version(),
            action: proof.capability().to_owned(),
            memory_id: proof.memory_id().to_owned(),
            record_version: proof.record_version(),
            content_sha256: proof.content_sha256().to_owned(),
            purpose: proof.purpose().to_owned(),
            classification: proof.classification().to_owned(),
            policy_version: proof.policy_version().to_owned(),
        };
        if proof.subject() != reviewer.subject()
            || proof.tenant_id() != receipt.tenant_ref
            || proof.organization_id() != receipt.subject_ref
            || proof.reviewer_id() != receipt.reviewer_ref
            || proof.approval_id() != receipt.approval_ref
            || proof.memory_id() != record.candidate.memory_id
            || proof.record_version() != record.candidate.record_version
            || proof.content_sha256() != record.candidate.content_sha256
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        let tenant = self.tenants.resolve_current_tenant(reviewer, &tuple.tenant_id)?;
        self.resolver
            .resolve_g05_activation(
                reviewer,
                &tenant,
                &tuple,
                now,
                self.max_authority_age_secs,
            )
            .map_err(|_| G05Error::ReviewerNotAuthorized)
    }
}

pub struct TrustedGovernanceAdapter<G, C, P, A> {
    g02: G,
    consent: C,
    g01: P,
    g11: A,
}
impl<G, C, P, A> TrustedGovernanceAdapter<G, C, P, A> {
    pub fn new(g02: G, consent: C, g01: P, g11: A) -> Self {
        Self { g02, consent, g01, g11 }
    }
}
impl<G, C, P, A> GovernancePort for TrustedGovernanceAdapter<G, C, P, A>
where
    G: G02AuthorizationAuthority,
    C: EpisodicConsentAuthority,
    P: G01ReviewerProofAuthority,
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
        self.consent.verify_active_opt_in(reference, tenant, subject, purpose, now)
    }
    fn verify_durable_approval(
        &self,
        receipt: &DurableApprovalReceipt,
        record: &MemoryRecord,
        reviewer: &VerifiedPrincipal,
        now: u64,
    ) -> Result<(), G05Error> {
        let verified = self.g01.verify_approval_proof(
            &receipt.signed_proof, reviewer, receipt, record, now,
        )?;
        self.g02.resolve_g05_activation(&verified, receipt, record, reviewer, now)?;
        Ok(())
    }
    fn append_audit(&self, event: &AuditEvent) -> Result<crate::G11Acknowledgment, G05Error> {
        self.g11.append_memory_event(event)
    }
}

fn purpose_key(p: Purpose) -> &'static str {
    match p {
        Purpose::TaskContinuity => "TASK_CONTINUITY",
        Purpose::UserPreference => "USER_PREFERENCE",
        Purpose::ProjectContext => "PROJECT_CONTEXT",
        Purpose::OrganizationalContext => "ORGANIZATIONAL_CONTEXT",
        Purpose::OperationalHistory => "OPERATIONAL_HISTORY",
        Purpose::AuthorizedSystemAssurance => "AUTHORIZED_SYSTEM_ASSURANCE",
    }
}
fn classification_key(value: crate::Classification) -> &'static str {
    match value {
        crate::Classification::Public => "PUBLIC",
        crate::Classification::Internal => "INTERNAL",
        crate::Classification::Confidential => "CONFIDENTIAL",
        crate::Classification::Restricted => "RESTRICTED",
    }
}
