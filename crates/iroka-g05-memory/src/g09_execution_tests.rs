use super::*;
use crate::{G02AuthorizationAuthority, G11Acknowledgment};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use iroka_kernel::{
    Ed25519CredentialVerifier, G05ActivationDecision, OwnerApprovalVerifier, OwnerSecurityAction,
    OwnerSecurityCommandPayload, RevocationChecker, RevocationError, SignedOwnerSecurityCommand,
    SignedTrustBundle, SqliteSecurityStore, TenantContext, TenantMembershipResolver,
    TrustBundlePayload, TrustRoot, TrustedKey, TrustedOwnerKey, VerifiedPrincipal,
    VerifiedReviewerProof,
};
use std::sync::mpsc::{self, Sender};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;

#[derive(Clone, Copy)]
struct NoRevocations;
impl RevocationChecker for NoRevocations {
    fn credential_revoked(&self, _: &str, _: &str) -> Result<bool, RevocationError> {
        Ok(false)
    }
    fn key_revoked(&self, _: &str, _: &str) -> Result<bool, RevocationError> {
        Ok(false)
    }
}
struct TestClock(Arc<AtomicU64>);
impl TrustedClock for TestClock {
    fn now_unix_seconds(&self) -> Result<u64, G05Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct TestG02;
impl G02AuthorizationAuthority for TestG02 {
    fn authorize_g05(&self, _: &AuthorizationRequest) -> Result<(), G05Error> {
        Ok(())
    }
    fn resolve_g05_activation(
        &self,
        _: &VerifiedReviewerProof,
        _: &DurableApprovalReceipt,
        _: &MemoryRecord,
        _: &VerifiedPrincipal,
        _: u64,
    ) -> Result<G05ActivationDecision, G05Error> {
        Err(G05Error::ReviewerNotAuthorized)
    }
}
#[derive(Default)]
struct AuthorityState {
    membership_version: u64,
    policy_revoked: bool,
    owner_key_revoked: bool,
    unavailable: bool,
    emergency_stop: bool,
}
struct TestG09 {
    state: Arc<Mutex<AuthorityState>>,
    guard_acquired: Option<Sender<()>>,
}
impl G09ExecutionRevalidator for TestG09 {
    fn revalidate(
        &self,
        _: &VerifiedPrincipal,
        _: &AuthorizationRequest,
        _: u64,
    ) -> Result<(), G05Error> {
        Ok(())
    }
    fn with_current_authority<T>(
        &self,
        _: &VerifiedPrincipal,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        now: u64,
        effect: impl FnOnce(&G02PolicySnapshot) -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        let state = self
            .state
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        if state.unavailable {
            return Err(G05Error::AuthorityUnavailable);
        }
        if tenant.subject() != request.principal_ref
            || tenant.tenant_id() != request.tenant_ref
            || tenant.membership_version() != state.membership_version
            || tenant.resolved_at() > now
            || now.saturating_sub(tenant.resolved_at()) > 600
        {
            return Err(G05Error::TenantScopeMismatch);
        }
        if state.policy_revoked || state.owner_key_revoked || state.emergency_stop {
            return Err(G05Error::AuthorizationDenied);
        }
        if let Some(tx) = &self.guard_acquired {
            let _ = tx.send(());
        }
        let snapshot = G02PolicySnapshot {
            policy_id: "test-policy".into(),
            epoch: 1,
            policy_version: "policy-v1".into(),
            owner_subject: "owner:test".into(),
            signer_issuer: "issuer:owner".into(),
            signer_key_id: "owner-key".into(),
            issued_at: 1_000,
            expires_at: 8_000,
            canonical_payload: b"test-policy".to_vec(),
            payload_sha256: "a".repeat(64),
            signature: vec![7; 64],
        };
        effect(&snapshot)
    }
}
#[derive(Default)]
struct TestG11 {
    events: Mutex<Vec<AuditEvent>>,
    fail_next: AtomicBool,
}
impl G11MemoryAuditAuthority for TestG11 {
    fn append_memory_event(&self, event: &AuditEvent) -> Result<G11Acknowledgment, G05Error> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(G05Error::AuditUnavailable);
        }
        let mut events = self.events.lock().map_err(|_| G05Error::AuditUnavailable)?;
        let digest = audit_event_sha256(event);
        if let Some(existing) = events
            .iter()
            .find(|existing| existing.event_id == event.event_id)
        {
            if audit_event_sha256(existing) != digest {
                return Err(G05Error::AuditUnavailable);
            }
            return Ok(G11Acknowledgment {
                event_id: event.event_id.clone(),
                payload_sha256: digest,
                accepted_at: existing.occurred_at,
            });
        }
        events.push(event.clone());
        Ok(G11Acknowledgment {
            event_id: event.event_id.clone(),
            payload_sha256: digest,
            accepted_at: event.occurred_at,
        })
    }
}
type TestService = G05IngressService<NoRevocations, TestG02, TestClock, TestG09>;
struct Fixture {
    service: TestService,
    token: String,
    tenant: TenantContext,
    request: AuthorizationRequest,
    now: Arc<AtomicU64>,
    authority: Arc<Mutex<AuthorityState>>,
}
fn fixture(state: AuthorityState, guard_acquired: Option<Sender<()>>) -> Fixture {
    let now = 1_200;
    let credential_signer = SigningKey::from_bytes(&[31u8; 32]);
    let root_signer = SigningKey::from_bytes(&[32u8; 32]);
    let root = TrustRoot {
        key_id: "root:test".into(),
        public_key: root_signer.verifying_key().to_bytes(),
        not_before: 900,
        not_after: 9_000,
        provenance_ref: "test-root-provenance".into(),
    };
    let payload = TrustBundlePayload {
        version: 1,
        issued_at: 1_000,
        expires_at: 8_000,
        trusted_issuers: vec!["issuer:test".into()],
        keys: vec![TrustedKey {
            issuer: "issuer:test".into(),
            key_id: "credential-key".into(),
            public_key: credential_signer.verifying_key().to_bytes(),
            not_before: 1_000,
            not_after: 7_000,
        }],
    };
    let mut bundle = SignedTrustBundle::from_signature(root.key_id.clone(), payload, Vec::new());
    bundle.signature = root_signer
        .sign(&bundle.signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
    let credentials =
        Ed25519CredentialVerifier::from_signed_bundle(&bundle, &root, &store, NoRevocations, now)
            .unwrap();
    let header = URL_SAFE_NO_PAD
        .encode(br#"{"alg":"EdDSA","typ":"IROKA-CREDENTIAL","kid":"credential-key"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        br#"{"iss":"issuer:test","sub":"principal:alice","aud":"iroka","exp":4700,"nbf":1100,"iat":1100,"jti":"credential:alice"}"#
    );
    let input = format!("{header}.{claims}");
    let token = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(credential_signer.sign(input.as_bytes()).to_bytes())
    );
    let principal = credentials.authenticate(&token, "iroka", now).unwrap();

    let owner_signer = SigningKey::from_bytes(&[41u8; 32]);
    let owner = OwnerApprovalVerifier::new(
        vec![TrustedOwnerKey {
            owner_subject: "owner:test".into(),
            key_id: "owner-key".into(),
            public_key: owner_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 9_000,
        }],
        store.clone(),
    )
    .unwrap();
    let membership = OwnerSecurityCommandPayload {
        command_id: "g01-membership-test".into(),
        owner_subject: "owner:test".into(),
        key_id: "owner-key".into(),
        issued_at: 1_100,
        expires_at: 1_500,
        action: OwnerSecurityAction::SetTenantMembership {
            subject: "principal:alice".into(),
            tenant_id: "tenant:alpha".into(),
            active: true,
            version: 1,
            reason: "G09 execution-boundary regression fixture".into(),
        },
    };
    let signature = owner_signer
        .sign(&membership.signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    owner
        .apply_security_command(
            &SignedOwnerSecurityCommand::from_signature(membership, signature),
            now,
        )
        .unwrap();
    let tenant = TenantMembershipResolver::new(store)
        .resolve(&principal, "tenant:alpha", now, 600)
        .unwrap();

    let authority = Arc::new(Mutex::new(state));
    let g09 = TestG09 {
        state: authority.clone(),
        guard_acquired,
    };
    let now_ref = Arc::new(AtomicU64::new(now));
    let service = G05IngressService::new(
        credentials,
        TestG02,
        TestClock(now_ref.clone()),
        g09,
        "iroka",
    )
    .unwrap();
    let request = AuthorizationRequest {
        operation: Operation::Retrieve,
        principal_ref: "principal:alice".into(),
        tenant_ref: "tenant:alpha".into(),
        subject_ref: "principal:alice".into(),
        purpose: Purpose::ProjectContext,
        classification: Classification::Internal,
        memory_id: Some("memory:one".into()),
        recipient_refs: Vec::new(),
        correlation_ref: "correlation:g09-test".into(),
    };
    Fixture {
        service,
        token,
        tenant,
        request,
        now: now_ref,
        authority,
    }
}
fn initial_state() -> AuthorityState {
    AuthorityState {
        membership_version: 1,
        ..AuthorityState::default()
    }
}
fn authorize(f: &Fixture) -> AuthenticatedG05Request {
    f.service.authorize(&f.token, f.request.clone()).unwrap()
}

#[test]
fn membership_version_change_after_kernel_allow_is_denied() {
    let f = fixture(initial_state(), None);
    let context = authorize(&f);
    f.authority.lock().unwrap().membership_version = 2;
    let ran = AtomicBool::new(false);
    let result = f.service.execute_external_with_context(
        &context,
        &f.tenant,
        &f.token,
        &TestG11::default(),
        || {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result, Err(G05Error::TenantScopeMismatch));
    assert!(!ran.load(Ordering::SeqCst));
}
#[test]
fn policy_revocation_after_kernel_allow_is_denied() {
    let f = fixture(initial_state(), None);
    let context = authorize(&f);
    f.authority.lock().unwrap().policy_revoked = true;
    let ran = AtomicBool::new(false);
    let result = f.service.execute_external_with_context(
        &context,
        &f.tenant,
        &f.token,
        &TestG11::default(),
        || {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result, Err(G05Error::AuthorizationDenied));
    assert!(!ran.load(Ordering::SeqCst));
}
#[test]
fn owner_key_revocation_after_kernel_allow_is_denied() {
    let f = fixture(initial_state(), None);
    let context = authorize(&f);
    f.authority.lock().unwrap().owner_key_revoked = true;
    let ran = AtomicBool::new(false);
    let result = f.service.execute_external_with_context(
        &context,
        &f.tenant,
        &f.token,
        &TestG11::default(),
        || {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result, Err(G05Error::AuthorizationDenied));
    assert!(!ran.load(Ordering::SeqCst));
}
#[test]
fn unavailable_authority_fails_closed() {
    let f = fixture(
        AuthorityState {
            unavailable: true,
            ..initial_state()
        },
        None,
    );
    let context = authorize(&f);
    let ran = AtomicBool::new(false);
    let result = f.service.execute_external_with_context(
        &context,
        &f.tenant,
        &f.token,
        &TestG11::default(),
        || {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result, Err(G05Error::AuthorityUnavailable));
    assert!(!ran.load(Ordering::SeqCst));
}
#[test]
fn stale_g01_tenant_context_fails_closed() {
    let f = fixture(initial_state(), None);
    let context = authorize(&f);
    f.now.store(1_901, Ordering::SeqCst);
    let ran = AtomicBool::new(false);
    let result = f.service.execute_external_with_context(
        &context,
        &f.tenant,
        &f.token,
        &TestG11::default(),
        || {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result, Err(G05Error::AuthorizationDenied));
    assert!(!ran.load(Ordering::SeqCst));
}
#[test]
fn g11_intent_receipt_failure_prevents_the_effect() {
    let f = fixture(initial_state(), None);
    let context = authorize(&f);
    let g11 = TestG11::default();
    g11.fail_next.store(true, Ordering::SeqCst);
    let ran = AtomicBool::new(false);
    let result =
        f.service
            .execute_external_with_context(&context, &f.tenant, &f.token, &g11, || {
                ran.store(true, Ordering::SeqCst);
                Ok(())
            });
    assert_eq!(result, Err(G05Error::AuditUnavailable));
    assert!(!ran.load(Ordering::SeqCst));
    assert!(g11.events.lock().unwrap().is_empty());
}
#[test]
fn execution_context_is_one_shot_and_g11_records_both_phases() {
    let f = fixture(initial_state(), None);
    let context = authorize(&f);
    let g11 = TestG11::default();
    f.service
        .execute_external_with_context(&context, &f.tenant, &f.token, &g11, || Ok(()))
        .unwrap();
    assert_eq!(g11.events.lock().unwrap().len(), 2);
    let replay = f.service.execute_external_with_context(
        &context,
        &f.tenant,
        &f.token,
        &g11,
        || -> Result<(), G05Error> { panic!("replayed effect must not run") },
    );
    assert_eq!(replay, Err(G05Error::ExecutionReplay));
}
#[test]
fn correlation_replay_across_fresh_ingress_contexts_is_rejected_by_g11() {
    let f = fixture(initial_state(), None);
    let first = authorize(&f);
    let g11 = TestG11::default();
    f.service
        .execute_external_with_context(&first, &f.tenant, &f.token, &g11, || Ok(()))
        .unwrap();

    let second = authorize(&f);
    let ran = AtomicBool::new(false);
    let replay =
        f.service
            .execute_external_with_context(&second, &f.tenant, &f.token, &g11, || {
                ran.store(true, Ordering::SeqCst);
                Ok(())
            });
    assert_eq!(replay, Err(G05Error::AuditUnavailable));
    assert!(!ran.load(Ordering::SeqCst));
    assert_eq!(g11.events.lock().unwrap().len(), 2);
}

#[test]
fn revocation_racing_execution_waits_until_guarded_effect_and_receipts_finish() {
    let (guard_tx, guard_rx) = mpsc::channel();
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let f = fixture(initial_state(), Some(guard_tx));
    let context = authorize(&f);
    let state = f.authority.clone();
    let revoker = thread::spawn(move || {
        guard_rx.recv().unwrap();
        attempt_tx.send(()).unwrap();
        state.lock().unwrap().policy_revoked = true;
    });
    let g11 = TestG11::default();
    let ran = AtomicBool::new(false);
    f.service
        .execute_external_with_context(&context, &f.tenant, &f.token, &g11, || {
            attempt_rx.recv().unwrap();
            ran.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    revoker.join().unwrap();
    assert!(ran.load(Ordering::SeqCst));
    assert!(f.authority.lock().unwrap().policy_revoked);
    assert_eq!(g11.events.lock().unwrap().len(), 2);
}
