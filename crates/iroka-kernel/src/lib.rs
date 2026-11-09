//! IROKA ZERO trusted-kernel foundation.
//! Deterministic policy evaluation plus explicit identity, governance and
//! assurance contracts. Concrete production adapters remain independently
//! reviewed trust-boundary components.

mod assurance;
mod audit_store;
mod decision;
#[cfg(test)]
mod governance;
mod identity;
mod identity_crypto;
mod igacms;
mod owner_approval;
mod policy;
mod request;
mod security_store;
mod service;
mod trust_lifecycle;

pub use assurance::{record_decision, AuditError, AuditEvent, AuditSink};
pub use audit_store::{AuditStoreError, SqliteAuditSink};
pub use decision::{Decision, DecisionCode, DecisionReason};
#[cfg(test)]
pub(crate) use governance::{
    validate_approval_scope, ApprovalError, ApprovalEvidence, ApprovalVerifier,
};
pub use identity::VerifiedPrincipal;
#[cfg(test)]
pub(crate) use identity::{authenticate, IdentityAssertion, IdentityError, IdentityVerifier};
#[cfg(any(test, feature = "dev-no-revocations"))]
pub use identity_crypto::NoRevocations;
pub use identity_crypto::{
    CredentialError, Ed25519CredentialVerifier, RevocationChecker, TrustConfigError, TrustStore,
    TrustedKey,
};
pub use igacms::{
    authorize_mutation, canonical_json, cross_chromosome_invariants, preserve_historical,
    sign_fingerprint, sign_genesis, sign_marker_assertion, validate_embedded_baseline,
    validate_genome, validate_marker_assertion, validate_marker_transition,
    verify_attestation_with_trust_roots, verify_attested_marker_assertion, verify_epoch_transition,
    verify_genesis_with_trust_roots, Attestation, Fingerprint, Genesis, HistoricalArtifact,
    IgacmsError, MarkerAssertion, MigrationEvidence, MutationClass, MutationEvidence,
    ValidatedGenome, VerifiedGenesis,
};
pub use owner_approval::{
    OwnerApprovalError, OwnerApprovalPayload, OwnerApprovalVerifier, OwnerSecurityAction,
    OwnerSecurityCommandPayload, SignedOwnerApproval, SignedOwnerSecurityCommand, TrustedOwnerKey,
};
pub use policy::{Policy, RiskLevel};
pub use request::AuthorizationRequest;
pub use security_store::{SecurityStoreError, SqliteSecurityStore};
pub use service::authorize_authenticated_with_owner_approval;
#[cfg(test)]
pub(crate) use service::{authorize, authorize_authenticated};
pub use trust_lifecycle::{
    verify_and_install_trust_bundle, verify_and_install_trust_bundle_with_roots, SignedTrustBundle,
    TrustBundleError, TrustBundlePayload, TrustRoot, TrustRootSet, TrustSnapshotManager,
};

/// Low-level deterministic policy primitive. It does not authenticate subjects,
/// validate approval evidence or persist audit events. Prefer authorize().
pub fn evaluate(
    request: &AuthorizationRequest,
    policy: &Policy,
    emergency_stop_active: bool,
) -> Decision {
    if emergency_stop_active {
        return Decision::new(
            DecisionCode::Escalate,
            DecisionReason::EmergencyStopActive,
            policy.version(),
        );
    }
    if !request.is_well_formed() {
        return Decision::new(
            DecisionCode::Deny,
            DecisionReason::MalformedRequest,
            policy.version(),
        );
    }
    if !policy.allows_capability(request.capability()) {
        return Decision::new(
            DecisionCode::Deny,
            DecisionReason::CapabilityNotGranted,
            policy.version(),
        );
    }
    if request.risk() > policy.maximum_risk() {
        return Decision::new(
            DecisionCode::Escalate,
            DecisionReason::RiskExceedsPolicy,
            policy.version(),
        );
    }
    if policy.requires_approval(request.capability()) {
        return Decision::new(
            DecisionCode::RequireApproval,
            DecisionReason::HumanApprovalRequired,
            policy.version(),
        );
    }
    Decision::new(
        DecisionCode::Allow,
        DecisionReason::PolicySatisfied,
        policy.version(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIdentity;
    impl IdentityVerifier for TestIdentity {
        fn verify_credential(
            &self,
            _a: &IdentityAssertion,
            _now: u64,
        ) -> Result<(), IdentityError> {
            Ok(())
        }
    }

    struct TestApproval;
    impl ApprovalVerifier for TestApproval {
        fn verify_approval(
            &self,
            _e: &ApprovalEvidence,
            _p: &VerifiedPrincipal,
            _r: &AuthorizationRequest,
            _v: &str,
            _now: u64,
        ) -> Result<(), ApprovalError> {
            Ok(())
        }
    }

    struct TestAudit;
    impl AuditSink for TestAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }

    struct FailedAudit;
    impl AuditSink for FailedAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::Unavailable)
        }
    }

    fn policy() -> Policy {
        Policy::new(
            "policy-v1",
            vec!["workspace.read".into(), "records.export".into()],
            vec!["records.export".into()],
            RiskLevel::High,
        )
    }

    fn assertion(subject: &str) -> IdentityAssertion {
        IdentityAssertion::new("test-issuer", subject, "iroka", 100, "test-credential")
    }

    #[test]
    fn identity_rejects_expired_assertions() {
        assert_eq!(
            authenticate(&TestIdentity, &assertion("principal:1"), "iroka", 100),
            Err(IdentityError::Expired)
        );
    }

    #[test]
    fn identity_rejects_wrong_audience() {
        let a = IdentityAssertion::new("issuer", "principal:1", "other", 100, "credential");
        assert_eq!(
            authenticate(&TestIdentity, &a, "iroka", 1),
            Err(IdentityError::VerificationFailed)
        );
    }

    #[test]
    fn authorization_binds_verified_subject_to_request() {
        let q = AuthorizationRequest::new(
            "principal:other",
            "workspace.read",
            "workspace:1",
            RiskLevel::Low,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            None,
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.reason(), DecisionReason::IdentitySubjectMismatch);
        assert_eq!(d.code(), DecisionCode::Deny);
    }

    #[test]
    fn authenticated_principal_flows_into_governed_authorization() {
        let q = AuthorizationRequest::new(
            "principal:1",
            "workspace.read",
            "workspace:1",
            RiskLevel::Low,
        );
        let principal = VerifiedPrincipal::from_verified_credential(
            "principal:1".into(),
            "issuer:test".into(),
            "credential:1".into(),
        );
        let d = authorize_authenticated(
            &q,
            &principal,
            None,
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:authenticated",
            "trace:authenticated",
        );
        assert_eq!(d.code(), DecisionCode::Allow);
    }

    #[test]
    fn missing_approval_remains_require_approval() {
        let q =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let d = authorize(
            &q,
            &assertion("principal:1"),
            None,
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::RequireApproval);
    }

    #[test]
    fn verified_approval_is_required_before_approval_capability_allows() {
        let q =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let evidence = ApprovalEvidence::new(
            "approval:1",
            assertion("owner:1"),
            "records.export",
            "records:1",
            "principal:1",
            "policy-v1",
            90,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            Some(&evidence),
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::Allow);
        assert_eq!(d.reason(), DecisionReason::ApprovalVerified);
    }

    #[test]
    fn approval_scope_mismatch_escalates() {
        let q =
            AuthorizationRequest::new("principal:1", "records.export", "records:1", RiskLevel::Low);
        let evidence = ApprovalEvidence::new(
            "approval:1",
            assertion("owner:1"),
            "records.export",
            "records:other",
            "principal:1",
            "policy-v1",
            90,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            Some(&evidence),
            &TestIdentity,
            &TestApproval,
            &TestAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::Escalate);
        assert_eq!(d.reason(), DecisionReason::ApprovalScopeMismatch);
    }

    #[test]
    fn audit_failure_prevents_positive_authorization() {
        let q = AuthorizationRequest::new(
            "principal:1",
            "workspace.read",
            "workspace:1",
            RiskLevel::Low,
        );
        let d = authorize(
            &q,
            &assertion("principal:1"),
            None,
            &TestIdentity,
            &TestApproval,
            &FailedAudit,
            &policy(),
            "iroka",
            1,
            false,
            "event:1",
            "trace:1",
        );
        assert_eq!(d.code(), DecisionCode::Escalate);
        assert_eq!(d.reason(), DecisionReason::AuditUnavailable);
    }
    #[test]
    fn production_pipeline_requires_and_consumes_signed_owner_approval() {
        use ed25519_dalek::{Signer, SigningKey};
        use std::sync::Arc;

        let signer = SigningKey::from_bytes(&[71u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let owner = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:akefa".into(),
                key_id: "owner-key-test".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5_000,
            }],
            store,
        )
        .unwrap();
        let request = AuthorizationRequest::new(
            "principal:requester",
            "records.export",
            "records:2026-01",
            RiskLevel::Low,
        );
        let principal = VerifiedPrincipal::from_verified_credential(
            "principal:requester".into(),
            "issuer:test".into(),
            "credential:requester".into(),
        );
        let payload = OwnerApprovalPayload::new(
            "approval:service-test",
            "owner:akefa",
            "owner-key-test",
            "principal:requester",
            "records.export",
            "records:2026-01",
            "policy-v1",
            1_100,
            1_500,
        );
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let signed = SignedOwnerApproval::from_signature(payload, signature);
        let fingerprint = validate_embedded_baseline().unwrap();
        let genesis_signer = SigningKey::from_bytes(&[72u8; 32]);
        let genesis_root = TrustRoot {
            key_id: "genesis-test-key".into(),
            public_key: genesis_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 5_000,
            provenance_ref: "test-root-record".into(),
        };
        let mut genesis = Genesis {
            dna_id: "iroka.dna".into(),
            dna_version: "1.0.0".into(),
            genome_id: "IROKA_ZERO_GENOME".into(),
            genome_version: "1.0.0".into(),
            digest: fingerprint.digest_hex.clone(),
            canonicalization: "RFC8785-JCS".into(),
            hash_algorithm: "SHA-256".into(),
            epoch: 0,
            parent: None,
            owner_approval_ref: "owner-approval:test-genesis".into(),
            trust_root_key_ids: vec!["genesis-test-key".into()],
            trust_root_provenance_refs: vec!["test-root-record".into()],
            attestation: Attestation {
                envelope_type: "iroka.igacms.attestation".into(),
                version: "1.0.0".into(),
                digest: String::new(),
                epoch: 0,
                key_id: "genesis-test-key".into(),
                signature: Vec::new(),
            },
            audit_refs: vec!["audit:test-genesis".into()],
        };
        genesis.attestation = sign_genesis(&genesis, "genesis-test-key", &genesis_signer).unwrap();
        let roots = TrustRootSet::new(vec![genesis_root]).unwrap();
        let verified_genesis =
            verify_genesis_with_trust_roots(&genesis, &fingerprint, &roots, 1_200).unwrap();
        let first = authorize_authenticated_with_owner_approval(
            &request,
            &principal,
            &verified_genesis,
            Some(&signed),
            &owner,
            &TestAudit,
            &policy(),
            1_200,
            false,
            "event:owner-approval",
            "trace:owner-approval",
        );
        assert_eq!(first.code(), DecisionCode::Allow);
        let replay = authorize_authenticated_with_owner_approval(
            &request,
            &principal,
            &verified_genesis,
            Some(&signed),
            &owner,
            &TestAudit,
            &policy(),
            1_201,
            false,
            "event:owner-approval-replay",
            "trace:owner-approval-replay",
        );
        assert_eq!(replay.code(), DecisionCode::Escalate);
        assert_eq!(replay.reason(), DecisionReason::ApprovalRevokedOrUnknown);
    }
}
