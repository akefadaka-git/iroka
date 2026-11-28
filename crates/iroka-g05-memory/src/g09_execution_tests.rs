use super::*;
use crate::{G02AuthorizationAuthority, G11Acknowledgment};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use iroka_kernel::{
    Ed25519CredentialVerifier, G05ActivationDecision, OwnerApprovalVerifier, OwnerSecurityAction,
    OwnerSecurityCommandPayload, Policy, RevocationChecker, RevocationError, RiskLevel,
    SignedOwnerSecurityCommand, SignedTrustBundle, SqliteSecurityStore, TenantContext,
    TenantMembershipResolver, TrustBundlePayload, TrustRoot, TrustedKey, TrustedOwnerKey,
    VerifiedPrincipal, VerifiedReviewerProof,
};
use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
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
    principal: VerifiedPrincipal,
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
        principal,
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
fn postgres_g09_guard_serializes_policy_and_owner_key_revocations_after_effect() {
    let Ok(database_url) = std::env::var("IROKA_TEST_DATABASE_URL") else {
        return;
    };
    let f = fixture(initial_state(), None);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database_name = format!("iroka_g09_{}_{}", std::process::id(), nonce % 1_000_000_000);
    let base_url = database_url.split('?').next().unwrap();
    let authority = base_url.rsplit_once('/').unwrap().0;
    let admin_url = format!("{authority}/postgres?sslmode=disable");
    let test_url = format!("{authority}/{database_name}?sslmode=disable");
    let mut admin = Client::connect(&admin_url, NoTls).unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database_name}"))
        .unwrap();

    let policy_id = format!("policy:g09:{nonce}");
    let command_id = format!("g09-test-command-{nonce}");
    let owner_subject = format!("owner:g09:{nonce}");
    let signer_issuer = format!("issuer:g09:{nonce}");
    let signer_key_id = format!("key:g09:{nonce}");
    let tenant_id = f.tenant.tenant_id().to_owned();
    let subject = f.principal.subject().to_owned();
    let canonical_payload = b"test-policy-payload".to_vec();
    let payload_sha256 = Sha256::digest(&canonical_payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    {
        let mut setup = Client::connect(&test_url, NoTls).unwrap();
        setup
            .batch_execute(include_str!(
                "../migrations/postgres/0001_shared_g05_g11.sql"
            ))
            .unwrap();
        setup
            .batch_execute(include_str!(
                "../migrations/postgres/0002_g02_authority.sql"
            ))
            .unwrap();
        setup
            .batch_execute(include_str!(
                "../migrations/postgres/0003_g02_owner_key_registry.sql"
            ))
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_owner_commands(command_id,owner_subject,signer_issuer,signer_key_id,issued_at,expires_at,payload_canonical,payload_sha256,signature,command_kind)
                 VALUES($1,$2,$3,$4,1000,5000,$5,$6,$7,'test.fixture')",
                &[&command_id, &owner_subject, &signer_issuer, &signer_key_id,
                  &b"test-command".as_slice(), &"a".repeat(64), &vec![1u8; 64]],
            )
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_owner_key_registry_versions(version,root_key_id,issued_at,expires_at,payload_sha256)
                 VALUES(1,'root:test',900,8000,$1)",
                &[&"b".repeat(64)],
            )
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_owner_keys(registry_version,owner_subject,issuer,key_id,public_key,not_before,not_after)
                 VALUES(1,$1,$2,$3,$4,900,7000)",
                &[&owner_subject, &signer_issuer, &signer_key_id, &&vec![7u8; 32][..]],
            )
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_policy_snapshots(policy_id,epoch,policy_version,owner_subject,signer_issuer,signer_key_id,issued_at,expires_at,canonical_payload,payload_sha256,signature)
                 VALUES($1,1,'policy-v1',$2,$3,$4,1000,7000,$5,$6,$7)",
                &[&policy_id, &owner_subject, &signer_issuer, &signer_key_id,
                  &canonical_payload, &payload_sha256, &vec![9u8; 64]],
            )
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_policy_heads(policy_id,current_epoch,current_payload_sha256)
                 VALUES($1,1,$2)",
                &[&policy_id, &payload_sha256],
            )
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_tenant_memberships(subject_ref,tenant_ref,active,version,updated_at,command_id)
                 VALUES($1,$2,TRUE,1,1200,$3)",
                &[&subject, &tenant_id, &command_id],
            )
            .unwrap();
        setup
            .execute(
                "INSERT INTO g02_emergency_stop(singleton,active,version,reason_code,changed_by_command_id,changed_at)
                 VALUES(TRUE,FALSE,1,'test.fixture',$1,1200)",
                &[&command_id],
            )
            .unwrap();
    }

    struct AllowVerifiedPolicy;
    impl G02PolicySnapshotVerifier for AllowVerifiedPolicy {
        fn verify_snapshot(
            &self,
            snapshot: &G02PolicySnapshot,
            _: u64,
        ) -> Result<Policy, G05Error> {
            Ok(Policy::new(
                snapshot.policy_version.clone(),
                vec![crate::ingress::capability_for(Operation::Retrieve).to_string()],
                Vec::new(),
                RiskLevel::Critical,
            ))
        }
    }

    let resolver = PostgresG09PolicyResolver::connect_for_test(
        &test_url,
        policy_id.clone(),
        Arc::new(AllowVerifiedPolicy),
    )
    .unwrap();
    resolver.verify_schema().unwrap();

    let (guard_tx, guard_rx) = mpsc::channel();
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let revoker_url = test_url.clone();
    let revoker_policy_id = policy_id.clone();
    let revoker_command_id = command_id.clone();
    let revoker_issuer = signer_issuer.clone();
    let revoker_key_id = signer_key_id.clone();
    let revoker = thread::spawn(move || {
        guard_rx.recv().unwrap();
        attempt_tx.send(()).unwrap();
        let mut client = Client::connect(&revoker_url, NoTls).unwrap();
        client
            .execute(
                "INSERT INTO g02_policy_revocations(policy_id,epoch,reason_code,revoked_by_command_id,revoked_at)
                 VALUES($1,1,'race.test',$2,1201)",
                &[&revoker_policy_id, &revoker_command_id],
            )
            .unwrap();
        client
            .execute(
                "INSERT INTO g02_owner_key_revocations(issuer,key_id,revoked_at,reason_code,revoked_by_command_id)
                 VALUES($1,$2,1201,'race.test',$3)",
                &[&revoker_issuer, &revoker_key_id, &revoker_command_id],
            )
            .unwrap();
    });

    let effect_ran = AtomicBool::new(false);
    let result =
        resolver.with_execution_authority(&f.principal, &f.tenant, &f.request, 1_200, |snapshot| {
            assert_eq!(snapshot.policy_version, "policy-v1");
            guard_tx.send(()).unwrap();
            attempt_rx.recv().unwrap();
            effect_ran.store(true, Ordering::SeqCst);
            Ok(())
        });
    assert!(result.is_ok());
    revoker.join().unwrap();
    assert!(effect_ran.load(Ordering::SeqCst));

    let mut verify = Client::connect(&test_url, NoTls).unwrap();
    let policy_revoked: bool = verify
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_policy_revocations WHERE policy_id=$1 AND epoch=1)",
            &[&policy_id],
        )
        .unwrap()
        .get(0);
    let key_revoked: bool = verify
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_owner_key_revocations WHERE issuer=$1 AND key_id=$2)",
            &[&signer_issuer, &signer_key_id],
        )
        .unwrap()
        .get(0);
    assert!(policy_revoked);
    assert!(key_revoked);
    drop(verify);
    drop(resolver);
    admin
        .batch_execute(&format!("DROP DATABASE {database_name}"))
        .unwrap();
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

fn service_validation_policy() -> ValidationPolicy {
    ValidationPolicy {
        max_working_ttl_secs: 5_000,
        max_episodic_ttl_secs: 5_000,
        allowed_purposes: [Purpose::ProjectContext].into_iter().collect(),
    }
}

fn service_record_and_event(correlation: &str) -> (MemoryRecord, AuditEvent) {
    let content = "guarded G05 test content".to_owned();
    let digest = sha256_hex(content.as_bytes());
    let record = MemoryRecord {
        candidate: MemoryCandidate {
            schema_id: RECORD_SCHEMA_ID.into(),
            contract_version: CONTRACT_VERSION.into(),
            memory_id: "memory:service-test".into(),
            tenant_ref: "tenant:alpha".into(),
            subject_ref: "principal:alice".into(),
            actor_ref: "principal:alice".into(),
            memory_class: MemoryClass::Working,
            content,
            content_sha256: digest.clone(),
            purpose: Purpose::ProjectContext,
            classification: Classification::Internal,
            provenance: Provenance {
                kind: ProvenanceKind::UserExplicit,
                source_refs: vec![],
                source_revision_refs: vec![],
                derived_from: vec![],
                recorded_by_ref: "principal:alice".into(),
                recorded_at: 1_200,
            },
            confidence_milli: None,
            created_at: 1_200,
            expires_at: Some(4_000),
            retention_policy_ref: "retention:working".into(),
            episodic_opt_in_ref: None,
            record_version: 1,
        },
        lifecycle_state: LifecycleState::Active,
        approval_ref: None,
        approved_by_ref: None,
        approved_at: None,
        updated_at: 1_200,
    };
    let event = AuditEvent {
        event_id: format!("g05:service:create:{correlation}"),
        event_type: "g05.memory.working.created".into(),
        memory_id: record.candidate.memory_id.clone(),
        tenant_ref: record.candidate.tenant_ref.clone(),
        actor_ref: record.candidate.actor_ref.clone(),
        purpose: record.candidate.purpose,
        record_version: record.candidate.record_version,
        outcome: "created".into(),
        correlation_ref: correlation.into(),
        occurred_at: 1_200,
        content_sha256: digest,
    };
    (record, event)
}

#[test]
fn mandatory_service_routes_sqlite_insert_metadata_and_content_reads() {
    let f = fixture(initial_state(), None);
    let repository = SqliteMemoryRepository::open_in_memory().unwrap();
    let service = G05ExecutionService::new_sqlite(
        f.service,
        repository,
        TestG11::default(),
        service_validation_policy(),
        SqliteG05AuthorityRegistry::open_in_memory().unwrap(),
    );
    let (record, event) = service_record_and_event("correlation:service-insert");
    let mut create = f.request.clone();
    create.operation = Operation::CreateWorking;
    create.memory_id = Some("memory:service-test".into());
    create.correlation_ref = "correlation:service-insert".into();
    service.insert_record(&f.token, &f.tenant, create, record, event).unwrap();

    let mut metadata_request = f.request.clone();
    metadata_request.operation = Operation::InspectMetadata;
    metadata_request.memory_id = Some("memory:service-test".into());
    metadata_request.correlation_ref = "correlation:service-metadata".into();
    let metadata = service.read_metadata(&f.token, &f.tenant, metadata_request).unwrap().unwrap();
    assert_eq!(metadata.memory_id, "memory:service-test");
    assert_eq!(metadata.record_version, 1);

    let mut read_request = f.request.clone();
    read_request.memory_id = Some("memory:service-test".into());
    read_request.correlation_ref = "correlation:service-read".into();
    let record = service.read_content(&f.token, &f.tenant, read_request).unwrap().unwrap();
    assert_eq!(record.candidate.content, "guarded G05 test content");
}

#[test]
fn mandatory_service_rejects_unauthorized_scope_before_repository_mutation() {
    let f = fixture(initial_state(), None);
    let repository = SqliteMemoryRepository::open_in_memory().unwrap();
    let inspect = repository.clone();
    let service = G05ExecutionService::new_sqlite(
        f.service,
        repository,
        TestG11::default(),
        SqliteG05AuthorityRegistry::open_in_memory().unwrap(),
    );
    let (record, event) = service_record_and_event("correlation:service-denied");
    let mut request = f.request.clone();
    request.operation = Operation::CreateWorking;
    request.correlation_ref = "correlation:service-denied".into();
    request.subject_ref = "principal:mallory".into();
    assert_eq!(
        service.insert_record(&f.token, &f.tenant, request, record, event),
        Err(G05Error::ApprovalBindingMismatch)
    );
    assert!(MemoryRepository::get_metadata(&inspect, "memory:service-test").unwrap().is_none());
}


#[test]
fn mandatory_service_does_not_mutate_when_g11_intent_is_unavailable() {
    let f = fixture(initial_state(), None);
    let repository = SqliteMemoryRepository::open_in_memory().unwrap();
    let inspect = repository.clone();
    let g11 = TestG11::default();
    g11.fail_next.store(true, Ordering::SeqCst);
    let service = G05ExecutionService::new_sqlite(
        f.service,
        repository,
        g11,
        service_validation_policy(),
        SqliteG05AuthorityRegistry::open_in_memory().unwrap(),
    );
    let (record, event) = service_record_and_event("correlation:service-audit-fail");
    let mut request = f.request.clone();
    request.operation = Operation::CreateWorking;
    request.memory_id = Some("memory:service-test".into());
    request.correlation_ref = "correlation:service-audit-fail".into();
    assert_eq!(
        service.insert_record(&f.token, &f.tenant, request, record, event),
        Err(G05Error::AuditUnavailable)
    );
    assert!(MemoryRepository::get_metadata(&inspect, "memory:service-test").unwrap().is_none());
}

