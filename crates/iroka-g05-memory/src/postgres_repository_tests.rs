use super::*;
use crate::{
    Classification, MemoryCandidate, MemoryClass, Provenance, ProvenanceKind, Purpose,
    TrustedClock,
};
use postgres::NoTls;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Barrier,
};
use std::thread;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static POSTGRES_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn database_url() -> Option<String> {
    std::env::var("IROKA_TEST_DATABASE_URL").ok()
}

fn unique_id() -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    format!("pg-test-{t}-{n}")
}

fn admin(url: &str) -> Client {
    let mut client = Client::connect(url, NoTls).expect("PostgreSQL test connection");
    client
        .batch_execute(include_str!(
            "../migrations/postgres/0001_shared_g05_g11.sql"
        ))
        .expect("PostgreSQL migration");
    client
}

fn repository(url: &str) -> PostgresMemoryRepository {
    PostgresMemoryRepository {
        client: Arc::new(Mutex::new(
            Client::connect(url, NoTls).expect("repository connection"),
        )),
    }
}

fn worker(url: &str) -> PostgresG11OutboxWorker {
    PostgresG11OutboxWorker {
        client: Arc::new(Mutex::new(
            Client::connect(url, NoTls).expect("worker connection"),
        )),
    }
}

fn test_record(id: &str, state: LifecycleState, version: u64) -> MemoryRecord {
    let content = "postgres shared repository fixture".to_owned();
    let approved = matches!(state, LifecycleState::PendingAudit | LifecycleState::Active);
    MemoryRecord {
        candidate: MemoryCandidate {
            schema_id: crate::RECORD_SCHEMA_ID.into(),
            contract_version: crate::CONTRACT_VERSION.into(),
            memory_id: format!("memory:{id}"),
            tenant_ref: "tenant:postgres-tests".into(),
            subject_ref: "subject:postgres-tests".into(),
            actor_ref: "actor:postgres-tests".into(),
            memory_class: MemoryClass::Durable,
            content: content.clone(),
            content_sha256: crate::sha256_hex(content.as_bytes()),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            provenance: Provenance {
                kind: ProvenanceKind::OwnerApproved,
                source_refs: vec![],
                source_revision_refs: vec![],
                derived_from: vec![],
                recorded_by_ref: "actor:postgres-tests".into(),
                recorded_at: 10,
            },
            confidence_milli: None,
            created_at: 10,
            expires_at: None,
            retention_policy_ref: "retention:postgres-tests".into(),
            episodic_opt_in_ref: None,
            record_version: version,
        },
        lifecycle_state: state,
        approval_ref: approved.then(|| format!("approval:{id}")),
        approved_by_ref: approved.then(|| "reviewer:postgres-tests".into()),
        approved_at: approved.then_some(11),
        updated_at: 11,
    }
}

fn test_event(record: &MemoryRecord, event_type: &str, event_id: &str) -> AuditEvent {
    AuditEvent {
        event_id: event_id.into(),
        event_type: event_type.into(),
        memory_id: record.candidate.memory_id.clone(),
        tenant_ref: record.candidate.tenant_ref.clone(),
        actor_ref: "actor:postgres-tests".into(),
        purpose: record.candidate.purpose,
        record_version: record.candidate.record_version,
        outcome: "ok".into(),
        correlation_ref: format!("trace:{}", record.candidate.memory_id),
        occurred_at: 11,
        content_sha256: record.candidate.content_sha256.clone(),
    }
}

fn cleanup(client: &mut Client, ids: &[String]) {
    for id in ids {
        client
            .execute(
                "DELETE FROM g05_memory_g11_outbox WHERE memory_id=$1",
                &[id],
            )
            .expect("delete test outbox");
        client
            .execute("DELETE FROM g05_memory_records WHERE memory_id=$1", &[id])
            .expect("delete test record");
    }
}

struct CheckpointTestClock;
impl TrustedClock for CheckpointTestClock {
    fn now_unix_seconds(&self) -> Result<u64, G05Error> {
        Ok(1_800_000_000)
    }
}

struct CheckpointTestSigner(ed25519_dalek::SigningKey);
impl iroka_kernel::CheckpointSigner for CheckpointTestSigner {
    fn sign(
        &self,
        _key_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, iroka_kernel::CheckpointError> {
        use ed25519_dalek::Signer;
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

struct CheckpointTestPublisher(std::sync::atomic::AtomicU64);
impl iroka_kernel::ExternalCheckpointPublisher for CheckpointTestPublisher {
    fn publish(
        &self,
        checkpoint: &iroka_kernel::SignedCheckpoint,
    ) -> Result<iroka_kernel::ExternalPublicationReceipt, iroka_kernel::CheckpointError>
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(iroka_kernel::ExternalPublicationReceipt {
            provider: "test-checkpoint-log".into(),
            receipt_id: "receipt:g11:1".into(),
            checkpoint_digest: checkpoint.digest()?,
            published_at: checkpoint.payload.issued_at + 1,
            proof_ref: "proof:g11:1".into(),
        })
    }
}

struct CheckpointTestPublicationVerifier;
impl iroka_kernel::ExternalPublicationVerifier for CheckpointTestPublicationVerifier {
    fn verify(
        &self,
        digest: &str,
        receipt: &iroka_kernel::ExternalPublicationReceipt,
    ) -> Result<(), iroka_kernel::CheckpointError> {
        if receipt.provider == "test-checkpoint-log"
            && receipt.receipt_id == "receipt:g11:1"
            && receipt.checkpoint_digest == digest
            && receipt.proof_ref == "proof:g11:1"
        {
            Ok(())
        } else {
            Err(iroka_kernel::CheckpointError::InvalidPublicationReceipt)
        }
    }
}

#[test]
fn postgres_insert_is_atomic_and_survives_repository_restart() {
    let _test_guard = POSTGRES_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(url) = database_url() else { return };
    let mut admin = admin(&url);
    let suffix = unique_id();
    let first = test_record(&suffix, LifecycleState::PendingReview, 1);
    let first_event = test_event(
        &first,
        "memory.durable.proposed",
        &format!("event:{suffix}:first"),
    );
    let first_id = first.candidate.memory_id.clone();

    let mut repo = repository(&url);
    repo.insert_with_audit(first.clone(), first_event.clone())
        .unwrap();
    drop(repo);

    // A fresh connection models process restart and confirms committed data.
    let restarted = repository(&url);
    assert_eq!(
        restarted.get_content(&first_id).unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        restarted
            .get_metadata(&first_id)
            .unwrap()
            .unwrap()
            .record_version,
        1
    );

    // A duplicate event ID fails after the record INSERT; the enclosing
    // transaction must roll that record back as well.
    let second = test_record(
        &format!("{suffix}-rollback"),
        LifecycleState::PendingReview,
        1,
    );
    let second_id = second.candidate.memory_id.clone();
    let duplicate_event = test_event(&second, "memory.durable.proposed", &first_event.event_id);
    let mut writer = repository(&url);
    assert_eq!(
        writer.insert_with_audit(second, duplicate_event),
        Err(G05Error::AuditUnavailable)
    );
    assert_eq!(writer.get_metadata(&second_id).unwrap(), None);
    cleanup(&mut admin, &[first_id, second_id]);
}

#[test]
fn postgres_optimistic_cas_allows_only_one_concurrent_writer() {
    let _test_guard = POSTGRES_TEST_LOCK.lock().unwrap();
    let Some(url) = database_url() else { return };
    let mut admin = admin(&url);
    let suffix = unique_id();
    let initial = test_record(&suffix, LifecycleState::PendingReview, 1);
    let id = initial.candidate.memory_id.clone();
    let mut setup = repository(&url);
    setup
        .insert_with_audit(
            initial.clone(),
            test_event(
                &initial,
                "memory.durable.proposed",
                &format!("event:{suffix}:initial"),
            ),
        )
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for writer_number in 0..2 {
        let url = url.clone();
        let suffix = suffix.clone();
        let barrier = barrier.clone();
        let mut next = initial.clone();
        next.lifecycle_state = LifecycleState::PendingAudit;
        next.approval_ref = Some(format!("approval:{suffix}"));
        next.approved_by_ref = Some("reviewer:postgres-tests".into());
        next.approved_at = Some(12);
        next.updated_at = 12;
        next.candidate.record_version = 2;
        handles.push(thread::spawn(move || {
            let mut repo = repository(&url);
            let event = test_event(
                &next,
                "memory.durable.activation.pending",
                &format!("event:{suffix}:writer:{writer_number}"),
            );
            barrier.wait();
            repo.replace_with_audit(next, 1, event)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(G05Error::VersionConflict))
            .count(),
        1
    );
    assert_eq!(
        repository(&url)
            .get_metadata(&id)
            .unwrap()
            .unwrap()
            .record_version,
        2
    );
    cleanup(&mut admin, &[id]);
}

#[test]
fn postgres_g11_leases_are_exclusive_restart_recoverable_and_idempotent() {
    let _test_guard = POSTGRES_TEST_LOCK.lock().unwrap();
    let Some(url) = database_url() else { return };
    let mut admin = admin(&url);
    let suffix = unique_id();
    let record = test_record(&suffix, LifecycleState::PendingAudit, 1);
    let id = record.candidate.memory_id.clone();
    let event = test_event(
        &record,
        "memory.durable.activation.pending",
        &format!("event:{suffix}:lease"),
    );
    let mut repo = repository(&url);
    repo.insert_with_audit(record, event.clone()).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _worker_number in 0..2 {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            let worker = worker(&url);
            barrier.wait();
            worker.claim_batch(10, 30).unwrap()
        }));
    }
    let claims: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(claims.iter().map(Vec::len).sum::<usize>(), 1);
    assert_eq!(claims.iter().filter(|batch| batch.is_empty()).count(), 1);
    let first_claim = claims.into_iter().find(|batch| !batch.is_empty()).unwrap();

    // Force expiry through database time to model a crashed worker without
    // sleeping; a new process/connection must reclaim the event.
    admin
        .execute(
            "UPDATE g05_memory_g11_outbox
             SET lease_expires_at=clock_timestamp()-interval '1 second'
             WHERE event_id=$1",
            &[&event.event_id],
        )
        .unwrap();
    let restarted_worker = worker(&url);
    let recovered = restarted_worker.claim_batch(10, 30).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_ne!(recovered[0].lease_token, first_claim[0].lease_token);

    let stale_ack = G11Acknowledgment {
        event_id: event.event_id.clone(),
        payload_sha256: audit_event_sha256(&event),
        accepted_at: event.occurred_at,
    };
    assert_eq!(
        restarted_worker.acknowledge(&first_claim[0], &stale_ack),
        Err(G05Error::AuditUnavailable)
    );
    restarted_worker
        .acknowledge(&recovered[0], &stale_ack)
        .unwrap();
    restarted_worker
        .acknowledge(&recovered[0], &stale_ack)
        .unwrap();

    let delivered: bool = admin
        .query_one(
            "SELECT delivered_at IS NOT NULL FROM g05_memory_g11_outbox WHERE event_id=$1",
            &[&event.event_id],
        )
        .unwrap()
        .get(0);
    assert!(delivered);
    cleanup(&mut admin, &[id]);
}

#[test]
fn postgres_g11_retry_releases_lease_and_retains_event() {
    let _test_guard = POSTGRES_TEST_LOCK.lock().unwrap();
    let Some(url) = database_url() else { return };
    let mut admin = admin(&url);
    let suffix = unique_id();
    let record = test_record(&suffix, LifecycleState::PendingReview, 1);
    let id = record.candidate.memory_id.clone();
    let event = test_event(
        &record,
        "memory.durable.proposed",
        &format!("event:{suffix}:retry"),
    );
    let mut repo = repository(&url);
    repo.insert_with_audit(record, event.clone()).unwrap();

    let worker = worker(&url);
    let mut claim = worker.claim_batch(1, 30).unwrap().remove(0);
    for attempt in 1..=12 {
        worker
            .schedule_retry(&claim, "g11_temporarily_unavailable")
            .unwrap();
        if attempt < 12 {
            admin
                .execute(
                    "UPDATE g05_memory_g11_outbox SET next_attempt_at=clock_timestamp()
                     WHERE event_id=$1",
                    &[&event.event_id],
                )
                .unwrap();
            claim = worker.claim_batch(1, 30).unwrap().remove(0);
        }
    }
    let exhausted = worker.exhausted_events(10).unwrap();
    assert!(exhausted.iter().any(|(event_id, error)| {
        event_id == &event.event_id && error == "retry_exhausted:g11_temporarily_unavailable"
    }));
    let row = admin
        .query_one(
            "SELECT lease_token IS NULL,delivered_at IS NULL,last_error_code
             FROM g05_memory_g11_outbox WHERE event_id=$1",
            &[&event.event_id],
        )
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, bool>(1));
    assert_eq!(
        row.get::<_, String>(2),
        "retry_exhausted:g11_temporarily_unavailable"
    );
    cleanup(&mut admin, &[id]);
}

#[test]
fn postgres_g11_receipt_creation_is_idempotent_and_chain_verifiable_after_restart() {
    let _test_guard = POSTGRES_TEST_LOCK.lock().unwrap();
    let Some(url) = database_url() else { return };
    let mut admin = admin(&url);
    let suffix = unique_id();
    let record = test_record(&suffix, LifecycleState::PendingReview, 1);
    let event = test_event(
        &record,
        "memory.durable.proposed",
        &format!("event:{suffix}:g11-receipt"),
    );
    let memory_id = record.candidate.memory_id.clone();

    let sink = PostgresG11MemoryAdapter {
        client: Arc::new(Mutex::new(
            Client::connect(&url, NoTls).expect("G11 connection"),
        )),
    };
    let first = sink.append_memory_event(&event).unwrap();
    let duplicate = sink.append_memory_event(&event).unwrap();
    assert_eq!(first, duplicate);
    assert_eq!(sink.head().unwrap().0, 1);
    sink.verify_integrity().unwrap();
    drop(sink);

    let restarted = PostgresG11MemoryAdapter {
        client: Arc::new(Mutex::new(
            Client::connect(&url, NoTls).expect("restarted G11 connection"),
        )),
    };
    assert_eq!(restarted.head().unwrap().0, 1);
    restarted.verify_integrity().unwrap();

    let mut changed = event.clone();
    changed.outcome = "changed-payload".into();
    assert_eq!(
        restarted.append_memory_event(&changed),
        Err(G05Error::AuditUnavailable)
    );
    let receipt_count: i64 = admin
        .query_one(
            "SELECT count(*) FROM g11_memory_receipts WHERE event_id=$1",
            &[&event.event_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(receipt_count, 1);

    let checkpoint_signer =
        CheckpointTestSigner(ed25519_dalek::SigningKey::from_bytes(&[13_u8; 32]));
    let publisher = CheckpointTestPublisher(AtomicU64::new(0));
    let published = restarted
        .publish_checkpoint(
            "g11:memory",
            "g11-checkpoint-key-1",
            &CheckpointTestClock,
            &checkpoint_signer,
            &publisher,
        )
        .unwrap();
    let checkpoint_id = published.checkpoint.digest().unwrap();
    assert_eq!(published.checkpoint.payload.sequence, 1);
    assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    iroka_kernel::verify_published_checkpoint(
        &published,
        &checkpoint_signer.0.verifying_key(),
        "g11:memory",
        1,
        None,
        &CheckpointTestPublicationVerifier,
    )
    .unwrap();

    // Repeated publication at the same audit head returns the stored
    // envelope and does not create a second external publication.
    let repeated = restarted
        .publish_checkpoint(
            "g11:memory",
            "g11-checkpoint-key-1",
            &CheckpointTestClock,
            &checkpoint_signer,
            &publisher,
        )
        .unwrap();
    assert_eq!(repeated, published);
    assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    let loaded = restarted
        .load_published_checkpoint(&checkpoint_id)
        .unwrap()
        .unwrap();
    assert_eq!(loaded, published);
    iroka_kernel::verify_published_checkpoint(
        &loaded,
        &checkpoint_signer.0.verifying_key(),
        "g11:memory",
        1,
        None,
        &CheckpointTestPublicationVerifier,
    )
    .unwrap();
    cleanup(&mut admin, &[memory_id]);
}