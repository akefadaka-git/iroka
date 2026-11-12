use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use iroka_kernel::{
    CredentialError, Ed25519CredentialVerifier, RevocationChecker, RevocationError,
    SignedTrustBundle, SqliteSecurityStore, TrustBundlePayload, TrustRoot, TrustedKey,
    OwnerApprovalVerifier, OwnerSecurityAction, OwnerSecurityCommandPayload,
    SignedOwnerSecurityCommand, TrustedOwnerKey, OrganizationAuthorityAction,
    OrganizationAuthorityPayload, SignedOrganizationAuthorityCommand,
    OrganizationAuthorityResolver, TenantMembershipResolver,
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
