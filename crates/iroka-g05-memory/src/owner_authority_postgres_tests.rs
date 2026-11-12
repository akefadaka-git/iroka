use super::*;
use crate::owner_authority_postgres::{
    G02SecurityAction, G02SecurityCommandPayload, G02TrustedOwnerKey,
    PostgresOwnerSignatureVerifier, SignedG02SecurityCommand,
};
use crate::{AuthorizationRequest, Classification, Operation, Purpose, G09PolicyResolver};
use ed25519_dalek::{Signer, SigningKey};
use postgres::{Client, NoTls};
use std::sync::{Arc, Barrier, Mutex};

static PG_TEST_LOCK: Mutex<()> = Mutex::new(());
use std::thread;

fn test_url() -> Option<String> {
    std::env::var("IROKA_TEST_DATABASE_URL").ok()
}
fn admin(url: &str) -> Client {
    let mut c=Client::connect(url,NoTls).expect("postgres test connection");
    c.batch_execute(include_str!("../migrations/postgres/0001_shared_g05_g11.sql")).unwrap();
    c.batch_execute(include_str!("../migrations/postgres/0002_g02_authority.sql")).unwrap();
    c.batch_execute(include_str!("../migrations/postgres/0003_g02_revocation_projections.sql")).unwrap();
    c.batch_execute(include_str!("../migrations/postgres/0004_g02_authority_outbox_delivery.sql")).unwrap();
    c
}
fn trusted(signer: &SigningKey, key_id: &str) -> G02TrustedOwnerKey {
    G02TrustedOwnerKey { owner_subject:"owner:iroka".into(), key_id:key_id.into(),
        public_key:signer.verifying_key().to_bytes(), not_before:100, not_after:10_000 }
}
fn verifier(url:&str, signer:&SigningKey, key_id:&str)->PostgresOwnerSignatureVerifier {
    PostgresOwnerSignatureVerifier::from_client_for_test(
        Client::connect(url,NoTls).unwrap(),vec![trusted(signer,key_id)]
    ).unwrap()
}
fn command(signer:&SigningKey,key_id:&str,id:&str,action:G02SecurityAction)->SignedG02SecurityCommand {
    let payload=G02SecurityCommandPayload { command_id:id.into(), owner_subject:"owner:iroka".into(),
        key_id:key_id.into(), issued_at:1_100, expires_at:1_500, action };
    let signature=signer.sign(&serde_json::to_vec(&payload).unwrap()).to_bytes().to_vec();
    SignedG02SecurityCommand { payload, signature }
}
fn policy_snapshot(signer:&SigningKey,key_id:&str,policy_id:&str)->(G02PolicySnapshot,Vec<u8>) {
    let payload=PostgresPolicySnapshotPayload {
        schema_id:"iroka.g02.policy-snapshot".into(),contract_version:"1.0".into(),
        owner_subject:"owner:iroka".into(),key_id:key_id.into(),policy_epoch:1,
        policy_version:"policy-v1".into(),allowed_capabilities:vec!["g05.memory.retrieve".into()],
        approval_required:vec![],maximum_risk:crate::owner_authority_postgres::PolicyRiskLevel::High,
        emergency_stop_active:false,issued_at:1_100,expires_at:2_000,
    };
    let canonical=serde_jcs::to_vec(&payload).unwrap();
    let mut signing=b"IROKA:G02:POLICY-SNAPSHOT:V1\0".to_vec();
    signing.extend_from_slice(&canonical);
    let signature=signer.sign(&signing).to_bytes().to_vec();
    let digest=crate::sha256_hex(&canonical);
    (G02PolicySnapshot { policy_id:policy_id.into(),epoch:1,policy_version:"policy-v1".into(),
        owner_subject:"owner:iroka".into(),signer_issuer:"iroka:owner-authority".into(),
        signer_key_id:key_id.into(),issued_at:1_100,expires_at:2_000,
        canonical_payload:canonical,payload_sha256:digest,signature:signature.clone() },signature)
}
fn install_snapshot(client:&mut Client,row:&G02PolicySnapshot,signature:&[u8],policy_id:&str) {
    client.execute("INSERT INTO g02_policy_snapshots(policy_id,epoch,policy_version,owner_subject,signer_issuer,signer_key_id,issued_at,expires_at,canonical_payload,payload_sha256,signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[&policy_id,&(row.epoch as i64),&row.policy_version,&row.owner_subject,&row.signer_issuer,
          &row.signer_key_id,&(row.issued_at as i64),&(row.expires_at as i64),&row.canonical_payload,
          &row.payload_sha256, &signature]).unwrap();
    client.execute("INSERT INTO g02_policy_heads(policy_id,current_epoch,current_payload_sha256) VALUES($1,1,$2)",
        &[&policy_id,&row.payload_sha256]).unwrap();
}
fn unique(prefix:&str)->String {
    format!("{prefix}-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
}


fn verified_principal(
    auth: &PostgresOwnerSignatureVerifier,
    subject: &str,
) -> iroka_kernel::VerifiedPrincipal {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let identity_signer = SigningKey::from_bytes(&[91u8; 32]);
    let root_signer = SigningKey::from_bytes(&[92u8; 32]);
    let trust_payload = iroka_kernel::TrustBundlePayload {
        version: 1,
        issued_at: 1_000,
        expires_at: 5_000,
        trusted_issuers: vec!["issuer:g01-test".into()],
        keys: vec![iroka_kernel::TrustedKey {
            issuer: "issuer:g01-test".into(),
            key_id: "g01-key".into(),
            public_key: identity_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 5_000,
        }],
    };
    let root = iroka_kernel::TrustRoot {
        key_id: "g01-root".into(),
        public_key: root_signer.verifying_key().to_bytes(),
        not_before: 900,
        not_after: 5_000,
        provenance_ref: "test-only-root-ceremony".into(),
    };
    let trust_bytes =
        iroka_kernel::SignedTrustBundle::signing_bytes_for("g01-root", &trust_payload).unwrap();
    let trust_signature = root_signer.sign(&trust_bytes).to_bytes().to_vec();
    let bundle = iroka_kernel::SignedTrustBundle::from_signature(
        "g01-root",
        trust_payload,
        trust_signature,
    );
    let local_anti_rollback =
        std::sync::Arc::new(iroka_kernel::SqliteSecurityStore::open_in_memory().unwrap());
    let credential_verifier = iroka_kernel::Ed25519CredentialVerifier::from_signed_bundle(
        &bundle,
        &root,
        &local_anti_rollback,
        auth.clone(),
        1_200,
    )
    .unwrap();
    let header =
        URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"IROKA-CREDENTIAL","kid":"g01-key"}"#);
    let claims_json = serde_json::json!({
        "iss": "issuer:g01-test",
        "sub": subject,
        "aud": "iroka-g05",
        "exp": 1_500,
        "nbf": 1_100,
        "iat": 1_100,
        "jti": unique("credential"),
    });
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_json).unwrap());
    let signing_input = format!("{header}.{claims}");
    let signature = identity_signer.sign(signing_input.as_bytes()).to_bytes();
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    credential_verifier
        .authenticate(&token, "iroka-g05", 1_200)
        .unwrap()
}

#[test]
fn postgres_g02_migrations_command_replay_monotonicity_and_rollback_are_live() {
    let Some(url)=test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let mut db=admin(&url);
    let signer=SigningKey::from_bytes(&[81u8;32]);
    let auth=verifier(&url,&signer,"owner-key");
    auth.verify_schema().unwrap();
    let tenant=unique("tenant");
    let subject=unique("subject");
    let first=command(&signer,"owner-key",&unique("membership"),G02SecurityAction::SetTenantMembership{
        subject:subject.clone(),tenant_id:tenant.clone(),active:true,version:1,reason:"grant".into()
    });
    auth.apply_security_command(&first,1_200).unwrap();
    assert_eq!(auth.apply_security_command(&first,1_201),Err(G02CommandError::Replay));

    let stale=command(&signer,"owner-key",&unique("stale"),G02SecurityAction::SetTenantMembership{
        subject:subject.clone(),tenant_id:tenant.clone(),active:false,version:1,reason:"stale".into()
    });
    assert_eq!(auth.apply_security_command(&stale,1_202),Err(G02CommandError::Rollback));
    let exists:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM g02_owner_commands WHERE command_id=$1)",
        &[&stale.payload.command_id]).unwrap().get(0);
    assert!(!exists,"failed monotonic update must roll back its command row and outbox");

    let current:i64=db.query_one("SELECT version FROM g02_tenant_memberships WHERE subject_ref=$1 AND tenant_ref=$2",
        &[&subject,&tenant]).unwrap().get(0);
    assert_eq!(current,1);
}

#[test]
fn postgres_g02_duplicate_concurrent_command_has_one_commit_and_one_replay() {
    let Some(url)=test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let _db=admin(&url);
    let signer=SigningKey::from_bytes(&[82u8;32]);
    let payload=command(&signer,"owner-key",&unique("concurrent"),G02SecurityAction::SetTenantMembership{
        subject:unique("concurrent-subject"),tenant_id:unique("concurrent-tenant"),
        active:true,version:1,reason:"concurrent replay test".into()
    });
    let barrier=Arc::new(Barrier::new(2));
    let mut handles=Vec::new();
    for _ in 0..2 {
        let url=url.clone();let barrier=barrier.clone();let signed=payload.clone();let signer=signer.clone();
        handles.push(thread::spawn(move||{
            let auth=verifier(&url,&signer,"owner-key");
            barrier.wait();
            auth.apply_security_command(&signed,1_200)
        }));
    }
    let results:Vec<_>=handles.into_iter().map(|h|h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r|r.is_ok()).count(),1,"results: {results:?}");
    assert_eq!(results.iter().filter(|r|**r==Err(G02CommandError::Replay)).count(),1,"results: {results:?}");
}

#[test]
fn postgres_g09_resolver_verifies_signed_policy_membership_and_emergency_stop() {
    let Some(url)=test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let mut db=admin(&url);
    let signer=SigningKey::from_bytes(&[83u8;32]);
    let policy_id=unique("policy");
    let auth=Arc::new(verifier(&url,&signer,"owner-key"));
    let baseline=command(&signer,"owner-key",&unique("stop-baseline"),G02SecurityAction::SetEmergencyStop{
        active:false,version:1,reason:"initial safe state".into()
    });
    auth.apply_security_command(&baseline,1_200).unwrap();
    let stop = command(&signer,"owner-key",&unique("stop-active"),G02SecurityAction::SetEmergencyStop{
        active:true,version:2,reason:"security incident".into()
    });
    auth.apply_security_command(&stop,1_201).unwrap();
    let stale_stop = command(&signer,"owner-key",&unique("stop-stale"),G02SecurityAction::SetEmergencyStop{
        active:false,version:1,reason:"stale clear attempt".into()
    });
    assert_eq!(auth.apply_security_command(&stale_stop,1_202),Err(G02CommandError::Rollback));
    let (snapshot,signature)=policy_snapshot(&signer,"owner-key",&policy_id);
    install_snapshot(&mut db,&snapshot,&signature,&policy_id);
    let subject=unique("subject");
    let tenant=unique("tenant");
    let membership=command(&signer,"owner-key",&unique("membership"),G02SecurityAction::SetTenantMembership{
        subject:subject.clone(),tenant_id:tenant.clone(),active:true,version:1,reason:"grant".into()
    });
    auth.apply_security_command(&membership,1_200).unwrap();
    let resolver=PostgresG09PolicyResolver::from_client_for_test(
        Client::connect(&url,NoTls).unwrap(),policy_id,Arc::clone(&auth)
    );
    resolver.verify_schema().unwrap();
    let (policy,stopped)=resolver.current_policy(1_200).unwrap();
    assert_eq!(policy.version(),"policy-v1");
    assert!(stopped);
    let principal = verified_principal(&auth, &subject);
    let request=AuthorizationRequest { operation:Operation::Retrieve,principal_ref:subject,
        tenant_ref:tenant,subject_ref:"subject:resource".into(),purpose:Purpose::TaskContinuity,
        classification:Classification::Internal,memory_id:None,recipient_refs:vec![],
        correlation_ref:"trace:g09-test".into() };
    resolver.authorize_resource_scope(&principal,&request,1_200).unwrap();
}

#[test]
fn postgres_g02_revoked_owner_key_is_rejected_for_new_policy_verification() {
    let Some(url)=test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let mut db=admin(&url);
    let policy_signer=SigningKey::from_bytes(&[84u8;32]);
    let revoker=SigningKey::from_bytes(&[85u8;32]);
    let policy_id=unique("revoked-policy");
    let revocation=command(&revoker,"revoker-key",&unique("revoke-key"),G02SecurityAction::RevokeSigningKey{
        issuer:"iroka:owner-authority".into(),key_id:"policy-key".into(),reason:"compromise".into()
    });
    // Trust both independently provisioned public roots in the same authority instance.
    let auth=PostgresOwnerSignatureVerifier::from_client_for_test(
        Client::connect(&url,NoTls).unwrap(),
        vec![trusted(&policy_signer,"policy-key"),trusted(&revoker,"revoker-key")]
    ).unwrap();
    auth.apply_security_command(&revocation,1_200).unwrap();
    let (snapshot,signature)=policy_snapshot(&policy_signer,"policy-key",&policy_id);
    install_snapshot(&mut db,&snapshot,&signature,&policy_id);
    let resolver=PostgresG09PolicyResolver::from_client_for_test(
        Client::connect(&url,NoTls).unwrap(),policy_id,Arc::new(auth)
    );
    assert_eq!(resolver.current_policy(1_200),Err(G05Error::AuthorizationDenied));
}


#[test]
fn postgres_g02_outbox_claim_and_ack_are_lease_bound() {
    let Some(url) = test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let _db = admin(&url);
    let mut cleanup = Client::connect(&url, NoTls).unwrap();
    cleanup.batch_execute("TRUNCATE TABLE g02_authority_outbox").unwrap();
    let signer = SigningKey::from_bytes(&[86u8; 32]);
    let auth = verifier(&url, &signer, "owner-key");
    let signed = command(
        &signer,
        "owner-key",
        &unique("outbox-ack"),
        G02SecurityAction::SetTenantMembership {
            subject: unique("outbox-subject"),
            tenant_id: unique("outbox-tenant"),
            active: true,
            version: 1,
            reason: "outbox ack test".into(),
        },
    );
    auth.apply_security_command(&signed, 1_200).unwrap();
    let worker = PostgresG02AuthorityOutboxWorker::from_client_for_test(
        Client::connect(&url, NoTls).unwrap(),
    );
    let token = "11111111-1111-4111-8111-111111111111";
    let events = worker.claim_batch("worker-test", token, 1, 30).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].command_id, signed.payload.command_id);
    assert_eq!(events[0].attempt_count, 1);
    let ack = "d".repeat(64);
    worker.acknowledge(&events[0].event_id, token, &ack).unwrap();
    assert_eq!(
        worker.acknowledge(&events[0].event_id, token, &ack),
        Err(G02OutboxError::LeaseLost)
    );
    let mut db = Client::connect(&url, NoTls).unwrap();
    let row = db.query_one(
        "SELECT delivered_at IS NOT NULL,acknowledgment_sha256
         FROM g02_authority_outbox WHERE event_id=$1",
        &[&events[0].event_id],
    ).unwrap();
    assert!(row.get::<_, bool>(0));
    let stored: String = row.get(1);
    assert_eq!(stored.trim(), ack);
    assert!(db.execute(
        "UPDATE g02_authority_outbox SET payload_json='{}'::jsonb WHERE event_id=$1",
        &[&events[0].event_id],
    ).is_err());
    assert!(db.execute(
        "DELETE FROM g02_authority_outbox WHERE event_id=$1",
        &[&events[0].event_id],
    ).is_err());
}

#[test]
fn postgres_g02_outbox_workers_claim_distinct_rows_with_skip_locked() {
    let Some(url) = test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let _db = admin(&url);
    let mut cleanup = Client::connect(&url, NoTls).unwrap();
    cleanup.execute("DELETE FROM g02_authority_outbox WHERE delivered_at IS NULL", &[]).unwrap();
    let signer = SigningKey::from_bytes(&[87u8; 32]);
    let auth = verifier(&url, &signer, "owner-key");
    for _ in 0..2 {
        let signed = command(
            &signer,
            "owner-key",
            &unique("outbox-skip-locked"),
            G02SecurityAction::SetTenantMembership {
                subject: unique("outbox-subject"),
                tenant_id: unique("outbox-tenant"),
                active: true,
                version: 1,
                reason: "skip locked test".into(),
            },
        );
        auth.apply_security_command(&signed, 1_200).unwrap();
    }
    let first = PostgresG02AuthorityOutboxWorker::from_client_for_test(
        Client::connect(&url, NoTls).unwrap(),
    );
    let second = PostgresG02AuthorityOutboxWorker::from_client_for_test(
        Client::connect(&url, NoTls).unwrap(),
    );
    let a = first.claim_batch(
        "worker-a",
        "22222222-2222-4222-8222-222222222222",
        1,
        30,
    ).unwrap();
    let b = second.claim_batch(
        "worker-b",
        "33333333-3333-4333-8333-333333333333",
        1,
        30,
    ).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_ne!(a[0].event_id, b[0].event_id);
}


#[test]
fn postgres_g02_outbox_dispatch_acknowledges_durable_sink_receipt() {
    struct AckSink;
    impl G02AuthorityEventSink for AckSink {
        fn deliver(&self, _event: &G02AuthorityOutboxEvent) -> Result<String, G02OutboxError> {
            Ok("e".repeat(64))
        }
    }
    let Some(url) = test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let _db = admin(&url);
    let mut cleanup = Client::connect(&url, NoTls).unwrap();
    cleanup.execute("DELETE FROM g02_authority_outbox WHERE delivered_at IS NULL", &[]).unwrap();
    let signer = SigningKey::from_bytes(&[88u8; 32]);
    let auth = verifier(&url, &signer, "owner-key");
    let signed = command(
        &signer,
        "owner-key",
        &unique("outbox-dispatch"),
        G02SecurityAction::SetTenantMembership {
            subject: unique("dispatch-subject"),
            tenant_id: unique("dispatch-tenant"),
            active: true,
            version: 1,
            reason: "dispatch test".into(),
        },
    );
    auth.apply_security_command(&signed, 1_200).unwrap();
    let worker = PostgresG02AuthorityOutboxWorker::from_client_for_test(
        Client::connect(&url, NoTls).unwrap(),
    );
    worker.verify_schema().unwrap();
    let stats = worker.dispatch_once(
        "dispatch-worker",
        "44444444-4444-4444-8444-444444444444",
        1,
        30,
        10,
        &AckSink,
    ).unwrap();
    assert_eq!(stats, G02OutboxDispatchStats { claimed: 1, acknowledged: 1, retry_scheduled: 0 });
}

#[test]
fn postgres_g02_outbox_dispatch_schedules_retry_after_sink_failure() {
    struct FailedSink;
    impl G02AuthorityEventSink for FailedSink {
        fn deliver(&self, _event: &G02AuthorityOutboxEvent) -> Result<String, G02OutboxError> {
            Err(G02OutboxError::Unavailable)
        }
    }
    let Some(url) = test_url() else { return };
    let _guard = PG_TEST_LOCK.lock().unwrap();
    let _db = admin(&url);
    let mut cleanup = Client::connect(&url, NoTls).unwrap();
    cleanup.execute("DELETE FROM g02_authority_outbox WHERE delivered_at IS NULL", &[]).unwrap();
    let signer = SigningKey::from_bytes(&[89u8; 32]);
    let auth = verifier(&url, &signer, "owner-key");
    let signed = command(
        &signer,
        "owner-key",
        &unique("outbox-retry"),
        G02SecurityAction::SetTenantMembership {
            subject: unique("retry-subject"),
            tenant_id: unique("retry-tenant"),
            active: true,
            version: 1,
            reason: "retry test".into(),
        },
    );
    auth.apply_security_command(&signed, 1_200).unwrap();
    let worker = PostgresG02AuthorityOutboxWorker::from_client_for_test(
        Client::connect(&url, NoTls).unwrap(),
    );
    let stats = worker.dispatch_once(
        "retry-worker",
        "55555555-5555-4555-8555-555555555555",
        1,
        30,
        60,
        &FailedSink,
    ).unwrap();
    assert_eq!(stats, G02OutboxDispatchStats { claimed: 1, acknowledged: 0, retry_scheduled: 1 });
    let mut db = Client::connect(&url, NoTls).unwrap();
    let row = db.query_one(
        "SELECT delivered_at IS NULL,last_error_code,lease_token IS NULL
         FROM g02_authority_outbox WHERE command_id=$1",
        &[&signed.payload.command_id],
    ).unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, String>(1), "sink_delivery_failed");
    assert!(row.get::<_, bool>(2));
}
