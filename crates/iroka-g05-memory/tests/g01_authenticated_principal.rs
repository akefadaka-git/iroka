use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use iroka_kernel::{
    CredentialError, Ed25519CredentialVerifier, RevocationChecker, RevocationError,
    SignedTrustBundle, SqliteSecurityStore, TrustBundlePayload, TrustRoot, TrustedKey,
};

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

fn signed_credential(issuer_signer: &SigningKey) -> String {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "IROKA-CREDENTIAL",
        "kid": "credential-key-1"
    });
    let claims = serde_json::json!({
        "iss": "issuer:iroka-integration",
        "sub": "reviewer:integration",
        "aud": "iroka",
        "exp": 1_500,
        "nbf": 1_100,
        "iat": 1_100,
        "jti": "credential:integration-1"
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
        .authenticate(&signed_credential(&issuer_signer), "iroka", 1_200)
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

    let mut token = signed_credential(&issuer_signer);
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
