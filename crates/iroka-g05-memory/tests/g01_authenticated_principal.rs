use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use iroka_kernel::{
    CredentialError, Ed25519CredentialVerifier, RevocationChecker, RevocationError,
    SignedTrustBundle, SqliteSecurityStore, TrustBundlePayload, TrustRoot, TrustedKey,
    OwnerApprovalVerifier, OwnerSecurityAction, OwnerSecurityCommandPayload,
    SignedOwnerSecurityCommand, TrustedOwnerKey, OrganizationAuthorityAction,
    OrganizationAuthorityPayload, SignedOrganizationAuthorityCommand,
    OrganizationAuthorityResolver, TenantMembershipResolver,
    ReviewerKeyBinding, ReviewerKeyBindingResolver, ReviewerProofError,
    ReviewerProofPayload, ReviewerProofVerifier, SignedReviewerProof,
};
use std::sync::Arc;

struct AllowRevocations;

impl RevocationChecker for AllowRevocations {
    fn credential_revoked(&self, _: &str, _: &str) -> Result<bool, RevocationError> {
        Ok(false)
    }

    fn key_revoked(&self, _: &str, _: &str) -> Result<bool, RevocationError> {
        Ok(false)
    }
}

fn signed_bundle(
    root_signer: &SigningKey,
    issuer_signer: &SigningKey,
) -> (SignedTrustBundle, TrustRoot) {
    let root = TrustRoot {
        key_id: "iroka-test-root".into(),
        public_key: root_signer.verifying_key().to_bytes(),
        not_before: 900,
        not_after: 3_000,
        provenance_ref: "test:offline-root-ceremony".into(),
    };
    let payload = TrustBundlePayload {
        version: 1,
        issued_at: 1_000,
        expires_at: 2_000,
        trusted_issuers: vec!["issuer:iroka-integration".into()],
        keys: vec![TrustedKey {
            issuer: "issuer:iroka-integration".into(),
            key_id: "credential-key-1".into(),
            public_key: issuer_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 2_500,
        }],
    };
    let bytes =
        SignedTrustBundle::signing_bytes_for("iroka-test-root", &payload).unwrap();
    let signature = root_signer.sign(&bytes).to_bytes().to_vec();
    (
        SignedTrustBundle::from_signature("iroka-test-root", payload, signature),
        root,
    )
}

fn signed_credential(issuer_signer: &SigningKey, subject: &str, credential_id: &str) -> String {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "IROKA-CREDENTIAL",
        "kid": "credential-key-1"
    });
    let claims = serde_json::json!({
        "iss": "issuer:iroka-integration",
        "sub": subject,
        "aud": "iroka",
        "exp": 1_500,
        "nbf": 1_100,
        "iat": 1_100,
        "jti": credential_id
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{claims}");
    let signature = issuer_signer
        .sign(signing_input.as_bytes())
        .to_bytes();
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[test]
fn g01_principal_is_created_only_after_root_signed_trust_and_credential_verification() {
    let root_signer = SigningKey::from_bytes(&[31_u8; 32]);
    let issuer_signer = SigningKey::from_bytes(&[32_u8; 32]);
    let store = SqliteSecurityStore::open_in_memory().unwrap();
    let (bundle, root) = signed_bundle(&root_signer, &issuer_signer);
    let verifier = Ed25519CredentialVerifier::from_signed_bundle(
        &bundle,
        &root,
        &store,
        AllowRevocations,
        1_200,
    )
    .unwrap();

    let principal = verifier
        .authenticate(&signed_credential(&issuer_signer, "reviewer:integration", "credential:integration-1"), "iroka", 1_200)
        .unwrap();

    assert_eq!(principal.subject(), "reviewer:integration");
    assert_eq!(principal.issuer(), "issuer:iroka-integration");
    assert_eq!(principal.credential_id(), "credential:integration-1");
}

#[test]
fn g01_rejects_a_credential_with_a_forged_signature_before_principal_creation() {
    let root_signer = SigningKey::from_bytes(&[41_u8; 32]);
    let issuer_signer = SigningKey::from_bytes(&[42_u8; 32]);
    let store = SqliteSecurityStore::open_in_memory().unwrap();
    let (bundle, root) = signed_bundle(&root_signer, &issuer_signer);
    let verifier = Ed25519CredentialVerifier::from_signed_bundle(
        &bundle,
        &root,
        &store,
        AllowRevocations,
        1_200,
    )
    .unwrap();

    let mut token = signed_credential(&issuer_signer, "reviewer:integration", "credential:integration-1");
    let signature_start = token.rfind('.').unwrap() + 1;
    let replacement = if token.as_bytes()[signature_start] == b'A' {
        'B'
    } else {
        'A'
    };
    token.replace_range(signature_start..signature_start + 1, &replacement.to_string());

    assert_eq!(
        verifier.authenticate(&token, "iroka", 1_200),
        Err(CredentialError::InvalidSignature)
    );
}


fn authenticated_principal(
    issuer_signer: &SigningKey,
    subject: &str,
    credential_id: &str,
) -> iroka_kernel::VerifiedPrincipal {
    let root_signer = SigningKey::from_bytes(&[31_u8; 32]);
    let store = SqliteSecurityStore::open_in_memory().unwrap();
    let (bundle, root) = signed_bundle(&root_signer, issuer_signer);
    let verifier = Ed25519CredentialVerifier::from_signed_bundle(
        &bundle, &root, &store, AllowRevocations, 1_200,
    ).unwrap();
    verifier.authenticate(
        &signed_credential(issuer_signer, subject, credential_id), "iroka", 1_200,
    ).unwrap()
}

fn signed_membership(
    signer: &SigningKey,
    subject: &str,
    command_id: &str,
) -> SignedOwnerSecurityCommand {
    let payload = OwnerSecurityCommandPayload {
        command_id: command_id.into(),
        owner_subject: "owner:test".into(),
        key_id: "owner-key".into(),
        issued_at: 1_100,
        expires_at: 1_400,
        action: OwnerSecurityAction::SetTenantMembership {
            subject: subject.into(),
            tenant_id: "tenant:alpha".into(),
            active: true,
            version: 1,
            reason: "integration fixture membership".into(),
        },
    };
    let signature = signer.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
    SignedOwnerSecurityCommand::from_signature(payload, signature)
}

fn signed_organization_command(
    signer: &SigningKey,
    command_id: &str,
    action: OrganizationAuthorityAction,
    principal: Option<&str>,
    designation_id: Option<&str>,
    delegate: Option<&str>,
    delegation_expires_at: Option<u64>,
    version: u64,
    capabilities: Vec<&str>,
) -> SignedOrganizationAuthorityCommand {
    let payload = OrganizationAuthorityPayload {
        command_id: command_id.into(),
        owner_subject: "owner:test".into(),
        key_id: "owner-key".into(),
        issued_at: 1_100,
        expires_at: 1_400,
        organization_id: "org:alpha".into(),
        tenant_id: "tenant:alpha".into(),
        principal: principal.map(str::to_owned),
        designation_id: designation_id.map(str::to_owned),
        delegate: delegate.map(str::to_owned),
        delegation_expires_at,
        action,
        version,
        capabilities: capabilities.into_iter().map(str::to_owned).collect(),
        reason: "Owner-signed integration fixture".into(),
    };
    let signature = signer.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
    SignedOrganizationAuthorityCommand::from_signature(payload, signature)
}

#[test]
fn g02_owner_signed_membership_designation_and_delegation_resolve_for_authenticated_principals() {
    let owner_signer = SigningKey::from_bytes(&[51_u8; 32]);
    let issuer_signer = SigningKey::from_bytes(&[52_u8; 32]);
    let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
    let owner = OwnerApprovalVerifier::new(
        vec![TrustedOwnerKey {
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            public_key: owner_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 5_000,
        }],
        store.clone(),
    ).unwrap();

    let delegator = authenticated_principal(
        &issuer_signer, "reviewer:integration", "credential:integration-1",
    );
    let delegate = authenticated_principal(
        &issuer_signer, "delegate:integration", "credential:delegate-1",
    );

    for (subject, id) in [
        (delegator.subject(), "membership:reviewer"),
        (delegate.subject(), "membership:delegate"),
    ] {
        owner.apply_security_command(
            &signed_membership(&owner_signer, subject, id), 1_200,
        ).unwrap();
    }

    owner.apply_organization_command(
        &signed_organization_command(
            &owner_signer, "organization:create",
            OrganizationAuthorityAction::CreateOrganization,
            None, None, None, None, 1, vec![],
        ), 1_200,
    ).unwrap();

    owner.apply_organization_command(
        &signed_organization_command(
            &owner_signer, "designation:reviewer",
            OrganizationAuthorityAction::SetDesignation,
            Some(delegator.subject()), Some("designation:reviewer"),
            None, None, 1, vec![
                "g05.memory.durable.activate",
                "organization.designation.delegate",
            ],
        ), 1_200,
    ).unwrap();

    let tenant_resolver = TenantMembershipResolver::new(store.clone());
    let delegate_tenant = tenant_resolver.resolve(&delegate, "tenant:alpha", 1_200, 600).unwrap();
    let delegation_id = "delegation:reviewer-to-delegate";
    owner.apply_organization_command(
        &signed_organization_command(
            &owner_signer, delegation_id,
            OrganizationAuthorityAction::SetDelegation,
            Some(delegator.subject()), Some(delegation_id),
            Some(delegate.subject()), Some(1_350), 1,
            vec!["g05.memory.durable.activate"],
        ), 1_200,
    ).unwrap();

    let resolver = OrganizationAuthorityResolver::new(store);
    let resolved = resolver.resolve_delegation(
        &delegate, &delegate_tenant, "org:alpha", delegation_id,
        "g05.memory.durable.activate", 1_200, 600,
    ).unwrap();

    assert_eq!(resolved.delegator(), delegator.subject());
    assert_eq!(resolved.delegate(), delegate.subject());
    assert_eq!(resolved.designation_id(), "designation:reviewer");
    assert_eq!(resolved.designation_version(), 1);
    assert_eq!(resolved.version(), 1);
}


struct StaticReviewerBinding {
    public_key: [u8; 32],
    subject: String,
    credential_id: String,
}

impl ReviewerKeyBindingResolver for StaticReviewerBinding {
    fn resolve_current_binding(
        &self,
        issuer: &str,
        subject: &str,
        credential_id: &str,
        key_id: &str,
        now: u64,
    ) -> Result<Option<ReviewerKeyBinding>, ReviewerProofError> {
        if issuer != "issuer:iroka-integration"
            || subject != self.subject
            || credential_id != self.credential_id
            || key_id != "credential-key-1"
        {
            return Ok(None);
        }
        Ok(Some(ReviewerKeyBinding {
            binding_id: "binding:reviewer-integration".into(),
            binding_version: 3,
            public_key: self.public_key,
            not_before: 900,
            not_after: 2_000,
            revoked: false,
            credential_revoked: false,
            resolved_at: now,
        }))
    }
}

#[test]
fn g01_signed_reviewer_proof_is_bound_to_authenticated_principal_and_consumed_once() {
    let issuer_signer = SigningKey::from_bytes(&[62_u8; 32]);
    let principal = authenticated_principal(
        &issuer_signer, "reviewer:integration", "credential:integration-1",
    );
    let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
    let payload = ReviewerProofPayload {
        proof_id: "proof:durable-activation-1".into(),
        issuer: principal.issuer().into(),
        subject: principal.subject().into(),
        credential_id: principal.credential_id().into(),
        reviewer_id: "reviewer:integration".into(),
        binding_id: "binding:reviewer-integration".into(),
        binding_version: 3,
        designation_id: "designation:reviewer".into(),
        designation_version: 1,
        delegation_id: Some("delegation:reviewer-to-delegate".into()),
        delegation_version: Some(1),
        key_id: "credential-key-1".into(),
        approval_id: "approval:durable-activation-1".into(),
        tenant_id: "tenant:alpha".into(),
        organization_id: "org:alpha".into(),
        memory_id: "memory:integration-1".into(),
        record_version: 7,
        content_sha256: "a".repeat(64),
        purpose: "ORGANIZATIONAL_CONTEXT".into(),
        classification: "CONFIDENTIAL".into(),
        capability: "g05.memory.durable.activate".into(),
        resource: "memory:integration-1".into(),
        policy_version: "g05-memory-v1".into(),
        issued_at: 1_150,
        expires_at: 1_350,
    };
    let signature = issuer_signer.sign(&payload.signing_bytes().unwrap()).to_bytes().to_vec();
    let proof = SignedReviewerProof::from_signature(payload, signature);
    let verifier = ReviewerProofVerifier::new(
        StaticReviewerBinding {
            public_key: issuer_signer.verifying_key().to_bytes(),
            subject: "reviewer:integration".into(),
            credential_id: "credential:integration-1".into(),
        },
        store,
    );

    let verified = verifier.verify_and_consume(
        &proof, &principal, "reviewer:integration", "approval:durable-activation-1",
        "tenant:alpha", "org:alpha", "designation:reviewer", 1,
        Some("delegation:reviewer-to-delegate"), Some(1),
        "memory:integration-1", 7, &"a".repeat(64),
        "ORGANIZATIONAL_CONTEXT", "CONFIDENTIAL",
        "g05.memory.durable.activate", "memory:integration-1", "g05-memory-v1", 1_200,
    ).unwrap();

    assert_eq!(verified.subject(), principal.subject());
    assert_eq!(verified.designation_version(), 1);
    assert_eq!(verified.delegation_version(), Some(1));
    assert_eq!(
        verifier.verify_and_consume(
            &proof, &principal, "reviewer:integration", "approval:durable-activation-1",
            "tenant:alpha", "org:alpha", "designation:reviewer", 1,
            Some("delegation:reviewer-to-delegate"), Some(1),
            "memory:integration-1", 7, &"a".repeat(64),
            "ORGANIZATIONAL_CONTEXT", "CONFIDENTIAL",
            "g05.memory.durable.activate", "memory:integration-1", "g05-memory-v1", 1_200,
        ),
        Err(ReviewerProofError::Replay)
    );
}


struct ExactG05RequestAuthorizer {
    reviewer: String,
}
impl iroka_g05_memory::G02RequestAuthorizer for ExactG05RequestAuthorizer {
    fn authorize(
        &self,
        request: &iroka_g05_memory::AuthorizationRequest,
    ) -> Result<(), iroka_g05_memory::G05Error> {
        if request.operation == iroka_g05_memory::Operation::ActivateDurable
            && request.principal_ref == self.reviewer
            && request.tenant_ref == "tenant:alpha"
            && request.memory_id.as_deref() == Some("memory:integrated")
        {
            Ok(())
        } else {
            Err(iroka_g05_memory::G05Error::AuthorizationDenied)
        }
    }
}

struct KernelTenantResolver(TenantMembershipResolver);
impl iroka_g05_memory::TenantContextResolver for KernelTenantResolver {
    fn resolve_current_tenant(
        &self,
        principal: &iroka_kernel::VerifiedPrincipal,
        tenant_id: &str,
    ) -> Result<iroka_kernel::TenantContext, iroka_g05_memory::G05Error> {
        self.0.resolve(principal, tenant_id, 1_200, 600)
            .map_err(|_| iroka_g05_memory::G05Error::ReviewerNotAuthorized)
    }
}

struct NoConsent;
impl iroka_g05_memory::EpisodicConsentAuthority for NoConsent {
    fn verify_active_opt_in(
        &self, _: &str, _: &str, _: &str,
        _: iroka_g05_memory::Purpose, _: u64,
    ) -> Result<(), iroka_g05_memory::G05Error> {
        Err(iroka_g05_memory::G05Error::AuthorizationDenied)
    }
}

struct UnavailableG11;
impl iroka_g05_memory::G11MemoryAuditAuthority for UnavailableG11 {
    fn append_memory_event(
        &self,
        _: &iroka_g05_memory::AuditEvent,
    ) -> Result<iroka_g05_memory::G11Acknowledgment, iroka_g05_memory::G05Error> {
        Err(iroka_g05_memory::G05Error::AuditUnavailable)
    }
}

#[test]
fn g01_g02_g05_g11_durable_activation_requires_receipt_then_final_repository_cas() {
    use iroka_g05_memory::{
        commit_durable_activation, dispatch_g11_outbox, durable_activation_audit_event,
        prepare_durable_activation, AuditEvent, Classification, DurableApprovalReceipt,
        G11MemoryAuditAuthority, G11OutboxRepository, KernelG01ReviewerProofAdapter,
        KernelG02ActivationAdapter, KernelSqliteG11MemoryAdapter, LifecycleState,
        MemoryCandidate, MemoryClass,
        MemoryRecord, MemoryRepository, Operation, Provenance, ProvenanceKind, Purpose,
        SqliteMemoryRepository, TrustedGovernanceAdapter,
    };
    use iroka_kernel::{OrganizationAuthorityResolver, SqliteAuditSink};

    let owner_signer = SigningKey::from_bytes(&[71_u8; 32]);
    let issuer_signer = SigningKey::from_bytes(&[72_u8; 32]);
    let security_store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
    let owner = OwnerApprovalVerifier::new(
        vec![TrustedOwnerKey {
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            public_key: owner_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 5_000,
        }],
        security_store.clone(),
    ).unwrap();
    let delegator = authenticated_principal(
        &issuer_signer, "reviewer:delegator", "credential:delegator",
    );
    let reviewer = authenticated_principal(
        &issuer_signer, "reviewer:delegate", "credential:delegate",
    );

    for subject in [delegator.subject(), reviewer.subject()] {
        owner.apply_security_command(
            &signed_membership(&owner_signer, subject, &format!("membership:{subject}")),
            1_200,
        ).unwrap();
    }
    owner.apply_organization_command(
        &signed_organization_command(
            &owner_signer, "organization:create:integration",
            OrganizationAuthorityAction::CreateOrganization,
            None, None, None, None, 1, vec![],
        ), 1_200,
    ).unwrap();
    owner.apply_organization_command(
        &signed_organization_command(
            &owner_signer, "designation:delegator",
            OrganizationAuthorityAction::SetDesignation,
            Some(delegator.subject()), Some("designation:delegator"),
            None, None, 1,
            vec!["g05.memory.durable.activate", "organization.designation.delegate"],
        ), 1_200,
    ).unwrap();
    let delegation_id = "delegation:integrated";
    owner.apply_organization_command(
        &signed_organization_command(
            &owner_signer, delegation_id,
            OrganizationAuthorityAction::SetDelegation,
            Some(delegator.subject()), Some(delegation_id),
            Some(reviewer.subject()), Some(1_350), 1,
            vec!["g05.memory.durable.activate"],
        ), 1_200,
    ).unwrap();

    let tenant_resolver = TenantMembershipResolver::new(security_store.clone());
    let g02 = KernelG02ActivationAdapter::new(
        OrganizationAuthorityResolver::new(security_store.clone()),
        ExactG05RequestAuthorizer { reviewer: reviewer.subject().into() },
        KernelTenantResolver(tenant_resolver),
        600,
    );
    let g01 = KernelG01ReviewerProofAdapter::new(
        StaticReviewerBinding {
            public_key: issuer_signer.verifying_key().to_bytes(),
            subject: reviewer.subject().into(),
            credential_id: reviewer.credential_id().into(),
        },
        security_store.clone(),
    );
    let g11_sink = Arc::new(SqliteAuditSink::open_in_memory().unwrap());
    let g11 = KernelSqliteG11MemoryAdapter::new(g11_sink.clone());
    let governance = TrustedGovernanceAdapter::new(g02, NoConsent, g01, g11);
    let g11_dispatch = KernelSqliteG11MemoryAdapter::new(g11_sink.clone());

    let content = "synthetic durable memory for integration verification";
    let digest = iroka_g05_memory::sha256_hex(content.as_bytes());
    let candidate = MemoryCandidate {
        schema_id: iroka_g05_memory::RECORD_SCHEMA_ID.into(),
        contract_version: iroka_g05_memory::CONTRACT_VERSION.into(),
        memory_id: "memory:integrated".into(),
        tenant_ref: "tenant:alpha".into(),
        subject_ref: delegator.subject().into(),
        actor_ref: reviewer.subject().into(),
        memory_class: MemoryClass::Durable,
        content: content.into(),
        content_sha256: digest.clone(),
        purpose: Purpose::OrganizationalContext,
        classification: Classification::Confidential,
        provenance: Provenance {
            kind: ProvenanceKind::HumanReviewed,
            source_refs: vec!["source:integration".into()],
            source_revision_refs: vec!["revision:1".into()],
            derived_from: vec![],
            recorded_by_ref: reviewer.subject().into(),
            recorded_at: 1_150,
        },
        confidence_milli: Some(1_000),
        created_at: 1_100,
        expires_at: None,
        retention_policy_ref: "retention:durable-v1".into(),
        episodic_opt_in_ref: None,
        record_version: 1,
    };
    let record = MemoryRecord {
        candidate,
        lifecycle_state: LifecycleState::PendingReview,
        approval_ref: None,
        approved_by_ref: None,
        approved_at: None,
        updated_at: 1_150,
    };

    let proof_payload = ReviewerProofPayload {
        proof_id: "proof:integrated".into(),
        issuer: reviewer.issuer().into(),
        subject: reviewer.subject().into(),
        credential_id: reviewer.credential_id().into(),
        reviewer_id: reviewer.subject().into(),
        binding_id: "binding:reviewer-integration".into(),
        binding_version: 3,
        designation_id: "designation:delegator".into(),
        designation_version: 1,
        delegation_id: Some(delegation_id.into()),
        delegation_version: Some(1),
        key_id: "credential-key-1".into(),
        approval_id: "approval:integrated".into(),
        tenant_id: "tenant:alpha".into(),
        organization_id: "org:alpha".into(),
        memory_id: "memory:integrated".into(),
        record_version: 1,
        content_sha256: digest.clone(),
        purpose: "ORGANIZATIONAL_CONTEXT".into(),
        classification: "CONFIDENTIAL".into(),
        capability: "g05.memory.durable.activate".into(),
        resource: "g05:durable.activate:memory:integrated:1".into(),
        policy_version: "g05-memory-v1".into(),
        issued_at: 1_150,
        expires_at: 1_350,
    };
    let proof_signature = issuer_signer.sign(&proof_payload.signing_bytes().unwrap()).to_bytes().to_vec();
    let signed_proof = SignedReviewerProof::from_signature(proof_payload, proof_signature);
    let receipt = DurableApprovalReceipt {
        approval_ref: "approval:integrated".into(),
        memory_id: "memory:integrated".into(),
        tenant_ref: "tenant:alpha".into(),
        subject_ref: delegator.subject().into(),
        content_sha256: digest.clone(),
        reviewer_ref: reviewer.subject().into(),
        issued_at: 1_150,
        expires_at: 1_350,
        proof_ref: "proof:integrated".into(),
        signed_proof,
    };
    let request = iroka_g05_memory::AuthorizationRequest {
        operation: Operation::ActivateDurable,
        principal_ref: reviewer.subject().into(),
        tenant_ref: "tenant:alpha".into(),
        subject_ref: delegator.subject().into(),
        purpose: Purpose::OrganizationalContext,
        classification: Classification::Confidential,
        memory_id: Some("memory:integrated".into()),
        recipient_refs: vec![],
        correlation_ref: "correlation:integrated".into(),
    };

    let mut repository = SqliteMemoryRepository::open_in_memory().unwrap();
    let created_event = AuditEvent {
        event_id: "g05:memory:integrated:created".into(),
        event_type: "memory.durable.proposed".into(),
        memory_id: "memory:integrated".into(),
        tenant_ref: "tenant:alpha".into(),
        actor_ref: reviewer.subject().into(),
        purpose: Purpose::OrganizationalContext,
        record_version: 1,
        outcome: "pending_review".into(),
        correlation_ref: "correlation:integrated".into(),
        occurred_at: 1_150,
        content_sha256: digest.clone(),
    };
    repository.insert_with_audit(record.clone(), created_event).unwrap();

    let pending = prepare_durable_activation(
        &record, &receipt, &reviewer, &request, &governance, 1_200,
    ).unwrap();
    let pending_event = durable_activation_audit_event(&pending).unwrap();
    repository.replace_with_audit(pending.clone(), 1, pending_event.clone()).unwrap();
    assert_eq!(
        repository.get_metadata("memory:integrated").unwrap().unwrap().lifecycle_state,
        LifecycleState::PendingAudit
    );

    assert_eq!(
        dispatch_g11_outbox(&repository, &UnavailableG11, 10),
        Err(iroka_g05_memory::G05Error::AuditUnavailable)
    );
    assert_eq!(
        repository.get_metadata("memory:integrated").unwrap().unwrap().lifecycle_state,
        LifecycleState::PendingAudit
    );

    let acknowledgments = dispatch_g11_outbox(&repository, &g11_dispatch, 10).unwrap();
    assert_eq!(g11_sink.verify_integrity(), Ok(()));
    let pending_ack = acknowledgments.into_iter()
        .find(|ack| ack.event_id() == pending_event.event_id)
        .unwrap();

    assert_eq!(
        commit_durable_activation(&mut repository, &pending, &pending_ack, 1, 1_210),
        Err(iroka_g05_memory::G05Error::VersionConflict)
    );
    assert_eq!(
        repository.get_metadata("memory:integrated").unwrap().unwrap().lifecycle_state,
        LifecycleState::PendingAudit
    );
    commit_durable_activation(&mut repository, &pending, &pending_ack, 2, 1_210).unwrap();
    assert_eq!(
        repository.get_metadata("memory:integrated").unwrap().unwrap().lifecycle_state,
        LifecycleState::Active
    );
    assert_eq!(g11_sink.verify_integrity(), Ok(()));
}
