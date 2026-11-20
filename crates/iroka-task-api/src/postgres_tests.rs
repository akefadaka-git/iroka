use super::*;
use postgres::NoTls;

fn task(task_id: &str, digest: &str) -> TaskRecord {
    TaskRecord {
        task_id: task_id.into(),
        tenant_ref: "tenant:pg-test".into(),
        principal_ref: "principal:pg-test".into(),
        capability_id: "iroka.answer".into(),
        capability_version: "1.0.0".into(),
        policy_version: "policy:pg-test".into(),
        idempotency_key: "idem:pg-test".into(),
        request_sha256: digest.into(),
        correlation_id: "trace:pg-test".into(),
        client_request_id: "client:pg-test".into(),
        state: TaskState::Accepted,
        task_version: 1,
        created_at: 100,
        updated_at: 100,
        expires_at: 1_000,
        result_ref: None,
        error_code: None,
    }
}

fn initial_event(task: &TaskRecord) -> TaskEvent {
    TaskEvent {
        task_id: task.task_id.clone(),
        sequence: 1,
        event_id: format!("{}:event:1", task.task_id),
        event_type: "task.accepted".into(),
        state: TaskState::Accepted,
        task_version: 1,
        actor_ref: task.principal_ref.clone(),
        occurred_at: 100,
        metadata: json!({"contract_version": TASK_CONTRACT_VERSION}),
    }
}

#[test]
fn postgres_idempotency_atomic_transitions_ordering_and_append_only() {
    let Ok(url) = std::env::var("IROKA_TEST_DATABASE_URL") else {
        eprintln!("skipping PostgreSQL integration test: IROKA_TEST_DATABASE_URL is unset");
        return;
    };
    let mut client = Client::connect(&url, NoTls).expect("connect to CI PostgreSQL");
    client.batch_execute(
        "DROP TABLE IF EXISTS iroka_task_events CASCADE;
         DROP TABLE IF EXISTS iroka_tasks CASCADE;
         DROP FUNCTION IF EXISTS iroka_reject_task_event_mutation();"
    ).expect("reset isolated test database");
    client.batch_execute(include_str!("../migrations/postgres/0001_task_lifecycle.sql"))
        .expect("apply task lifecycle migration");
    client.batch_execute(include_str!("../migrations/postgres/0002_task_worker_leases.sql"))
        .expect("apply worker lease migration");

    let repository = PostgresTaskRepository {
        client: Arc::new(Mutex::new(client)),
    };
    repository.verify_schema().expect("migration schema exists");

    // Same key + same request digest is a replay; same key + different digest conflicts.
    let original = task("task:pg-original", &"a".repeat(64));
    let (created, was_created) = repository.create(&original, &initial_event(&original))
        .expect("first submission");
    assert!(was_created);
    assert_eq!(created.task_id, original.task_id);

    let replay = task("task:pg-replay-id-must-not-win", &"a".repeat(64));
    let (replayed, was_created) = repository.create(&replay, &initial_event(&replay))
        .expect("idempotent replay");
    assert!(!was_created);
    assert_eq!(replayed.task_id, original.task_id);

    let conflict = task("task:pg-conflict", &"b".repeat(64));
    assert_eq!(
        repository.create(&conflict, &initial_event(&conflict)),
        Err(TaskApiError::Conflict)
    );

    // Force event append failure after the row update; the transaction must roll back both.
    {
        let mut db = repository.client.lock().unwrap();
        db.batch_execute(
            "CREATE FUNCTION reject_task_event_insert() RETURNS trigger
             LANGUAGE plpgsql AS $$ BEGIN
               IF NEW.sequence = 2 THEN RAISE EXCEPTION 'injected event failure'; END IF;
               RETURN NEW;
             END $$;
             CREATE TRIGGER reject_task_event_insert BEFORE INSERT ON iroka_task_events
             FOR EACH ROW EXECUTE FUNCTION reject_task_event_insert();"
        ).unwrap();
    }
    let queued = TaskTransition {
        task_id: original.task_id.clone(),
        expected_version: 1,
        next_state: TaskState::Queued,
        actor_ref: "worker:pg-test".into(),
        occurred_at: 110,
        metadata: json!({"worker_ref":"worker:pg-test"}),
        result_ref: None,
        error_code: None,
    };
    assert_eq!(repository.transition(queued), Err(TaskApiError::RepositoryUnavailable));
    let unchanged = repository.get(&original.task_id).unwrap().unwrap();
    assert_eq!(unchanged.state, TaskState::Accepted);
    assert_eq!(unchanged.task_version, 1);
    assert_eq!(repository.events(&original.task_id, 0, 20).unwrap().len(), 1);
    {
        let mut db = repository.client.lock().unwrap();
        db.batch_execute(
            "DROP TRIGGER reject_task_event_insert ON iroka_task_events;
             DROP FUNCTION reject_task_event_insert();"
        ).unwrap();
    }

    // Successful transitions append one event each with monotonically increasing sequence.
    let queued = TaskTransition {
        task_id: original.task_id.clone(), expected_version: 1,
        next_state: TaskState::Queued, actor_ref: "worker:pg-test".into(),
        occurred_at: 110, metadata: json!({"worker_ref":"worker:pg-test"}),
        result_ref: None, error_code: None,
    };
    repository.transition(queued).expect("accepted -> queued");
    let lease = repository.claim_next("worker:pg-test", 120, 30, 3)
        .expect("claim next queued task").expect("one queued task");
    assert_eq!(lease.task.state, TaskState::Running);
    assert_eq!(lease.attempt, 1);
    assert_eq!(lease.lease_expires_at, 150);
    let renewed = repository.renew_lease(&lease, 125, 30).expect("renew live lease");
    assert_eq!(renewed.lease_expires_at, 155);
    let mut forged = renewed.clone();
    forged.lease_token = "00000000-0000-0000-0000-000000000000".into();
    assert_eq!(repository.renew_lease(&forged, 126, 30), Err(TaskApiError::Conflict));
    let succeeded = TaskTransition {
        task_id: original.task_id.clone(), expected_version: 3,
        next_state: TaskState::Succeeded, actor_ref: "worker:pg-test".into(),
        occurred_at: 130, metadata: json!({"adapter_class":"test"}),
        result_ref: Some("result:pg-test".into()), error_code: None,
    };
    repository.complete_lease(&renewed, succeeded).expect("lease-guarded completion");

    let events = repository.events(&original.task_id, 0, 20).unwrap();
    assert_eq!(events.iter().map(|event| event.sequence).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    assert_eq!(events.iter().map(|event| event.state).collect::<Vec<_>>(),
        vec![TaskState::Accepted, TaskState::Queued, TaskState::Running, TaskState::Succeeded]);
    assert_eq!(events.iter().map(|event| event.task_version).collect::<Vec<_>>(), vec![1, 2, 3, 4]);

    // Running cancellation remains pending until the lease owner acknowledges it.
    let mut cancel_task = task("task:pg-cancel", &"c".repeat(64));
    cancel_task.idempotency_key = "idem:pg-cancel".into();
    repository.create(&cancel_task, &initial_event(&cancel_task)).expect("create cancellation task");
    repository.transition(TaskTransition {
        task_id: cancel_task.task_id.clone(), expected_version: 1,
        next_state: TaskState::Queued, actor_ref: "scheduler:pg-test".into(),
        occurred_at: 200, metadata: json!({"reason_code":"scheduled"}),
        result_ref: None, error_code: None,
    }).expect("queue cancellation task");
    let cancel_lease = repository.claim_next("worker:cancel", 210, 30, 3)
        .expect("claim cancellation task").expect("queued cancellation task");
    repository.transition(TaskTransition {
        task_id: cancel_task.task_id.clone(), expected_version: cancel_lease.task.task_version,
        next_state: TaskState::CancelRequested, actor_ref: "principal:pg-test".into(),
        occurred_at: 215, metadata: json!({"reason_code":"caller_cancelled"}),
        result_ref: None, error_code: None,
    }).expect("request cancellation while running");
    let cancelled = repository.acknowledge_cancel(
        &cancel_lease, 220, json!({"reason_code":"worker_cancel_acknowledged"})
    ).expect("worker acknowledges cancellation");
    assert_eq!(cancelled.state, TaskState::Cancelled);
    assert_eq!(repository.events(&cancel_task.task_id, 0, 20).unwrap().len(), 5);

    // Optimistic version check rejects stale writers without appending an event.
    let stale = TaskTransition {
        task_id: original.task_id.clone(), expected_version: 3,
        next_state: TaskState::Failed, actor_ref: "worker:pg-test".into(),
        occurred_at: 140, metadata: json!({"error_code":"stale"}),
        result_ref: None, error_code: Some("stale_writer".into()),
    };
    assert_eq!(repository.transition(stale), Err(TaskApiError::Conflict));
    assert_eq!(repository.events(&original.task_id, 0, 20).unwrap().len(), 4);

    // Database trigger rejects both UPDATE and DELETE of historical events.
    let mut db = repository.client.lock().unwrap();
    assert!(db.execute(
        "UPDATE iroka_task_events SET event_type='tampered' WHERE task_id=$1 AND sequence=1",
        &[&original.task_id]
    ).is_err());
    assert!(db.execute(
        "DELETE FROM iroka_task_events WHERE task_id=$1 AND sequence=1",
        &[&original.task_id]
    ).is_err());
    let count: i64 = db.query_one(
        "SELECT count(*) FROM iroka_task_events WHERE task_id=$1",
        &[&original.task_id]
    ).unwrap().get(0);
    assert_eq!(count, 4);
}
