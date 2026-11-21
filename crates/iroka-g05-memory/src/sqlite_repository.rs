//! Durable SQLite persistence for G05 memory records and the content-free G11 outbox.
use crate::{
    audit_event_sha256, AuditEvent, G05Error, G11Acknowledgment, G11OutboxRepository,
    LifecycleState, MemoryMetadata, MemoryRecord, MemoryRepository,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteMemoryRepository {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteMemoryRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, G05Error> {
        let connection = Connection::open(path).map_err(|_| G05Error::RepositoryUnavailable)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, G05Error> {
        let connection =
            Connection::open_in_memory().map_err(|_| G05Error::RepositoryUnavailable)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, G05Error> {
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS g05_memory_records(
                   memory_id TEXT PRIMARY KEY,
                   tenant_ref TEXT NOT NULL,
                   subject_ref TEXT NOT NULL,
                   memory_class TEXT NOT NULL,
                   content_sha256 TEXT NOT NULL,
                   purpose TEXT NOT NULL,
                   classification TEXT NOT NULL,
                   lifecycle_state TEXT NOT NULL,
                   expires_at INTEGER,
                   record_version INTEGER NOT NULL CHECK(record_version>0),
                   retention_policy_ref TEXT NOT NULL,
                   metadata_json TEXT NOT NULL,
                   record_json TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS g05_memory_tenant_subject
                   ON g05_memory_records(tenant_ref,subject_ref,lifecycle_state);
                 CREATE TABLE IF NOT EXISTS g05_memory_g11_outbox(
                   event_id TEXT PRIMARY KEY,
                   memory_id TEXT NOT NULL,
                   payload_sha256 TEXT NOT NULL,
                   payload_json TEXT NOT NULL,
                   occurred_at INTEGER NOT NULL,
                   delivered_at INTEGER,
                   acknowledgment_sha256 TEXT,
                   FOREIGN KEY(memory_id) REFERENCES g05_memory_records(memory_id)
                 );
                 CREATE INDEX IF NOT EXISTS g05_memory_outbox_pending
                   ON g05_memory_g11_outbox(delivered_at,occurred_at);",
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Return undelivered, content-free events in stable FIFO order.
    pub fn pending_g11_events(&self, limit: usize) -> Result<Vec<AuditEvent>, G05Error> {
        if limit == 0 || limit > 1_000 {
            return Err(G05Error::MalformedRecord);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT payload_json FROM g05_memory_g11_outbox
                 WHERE delivered_at IS NULL ORDER BY occurred_at,event_id LIMIT ?1",
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let rows = statement
            .query_map(params![limit as i64], |row| row.get::<_, String>(0))
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        rows.map(|row| {
            let json = row.map_err(|_| G05Error::RepositoryUnavailable)?;
            serde_json::from_str(&json).map_err(|_| G05Error::RepositoryUnavailable)
        })
        .collect()
    }

    /// Mark delivery only with the opaque acknowledgment produced by the
    /// trusted G11 adapter. Duplicate acknowledgments are idempotent.
    pub fn acknowledge_g11_event(
        &self,
        event: &AuditEvent,
        acknowledgment: &G11Acknowledgment,
    ) -> Result<(), G05Error> {
        if acknowledgment.event_id() != event.event_id
            || acknowledgment.payload_sha256() != audit_event_sha256(event)
            || acknowledgment.accepted_at() < event.occurred_at
        {
            return Err(G05Error::AuditUnavailable);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .unchecked_transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let stored: Option<(String, Option<i64>, Option<String>)> = tx
            .query_row(
                "SELECT payload_sha256,delivered_at,acknowledgment_sha256
                 FROM g05_memory_g11_outbox WHERE event_id=?1",
                params![event.event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let (digest, delivered_at, old_ack) = stored.ok_or(G05Error::RecordNotFound)?;
        if digest != audit_event_sha256(event) {
            return Err(G05Error::AuditUnavailable);
        }
        if let Some(old_ack) = old_ack {
            if old_ack != acknowledgment.payload_sha256() {
                return Err(G05Error::AuditUnavailable);
            }
            return Ok(());
        }
        if delivered_at.is_some() {
            return Err(G05Error::AuditUnavailable);
        }
        tx.execute(
            "UPDATE g05_memory_g11_outbox
             SET delivered_at=?2,acknowledgment_sha256=?3
             WHERE event_id=?1 AND delivered_at IS NULL",
            params![
                event.event_id,
                acknowledgment.accepted_at() as i64,
                acknowledgment.payload_sha256()
            ],
        )
        .map_err(|_| G05Error::RepositoryUnavailable)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }
}

fn metadata(record: &MemoryRecord) -> Result<MemoryMetadata, G05Error> {
    Ok(MemoryMetadata {
        memory_id: record.candidate.memory_id.clone(),
        tenant_ref: record.candidate.tenant_ref.clone(),
        subject_ref: record.candidate.subject_ref.clone(),
        memory_class: record.candidate.memory_class,
        content_sha256: record.candidate.content_sha256.clone(),
        purpose: record.candidate.purpose,
        classification: record.candidate.classification,
        lifecycle_state: record.lifecycle_state,
        expires_at: record.candidate.expires_at,
        record_version: record.candidate.record_version,
        retention_policy_ref: record.candidate.retention_policy_ref.clone(),
    })
}

fn persist_outbox(tx: &Transaction<'_>, event: &AuditEvent) -> Result<(), G05Error> {
    if event.event_id.trim().is_empty()
        || event.memory_id.trim().is_empty()
        || event.tenant_ref.trim().is_empty()
        || event.record_version == 0
    {
        return Err(G05Error::MalformedRecord);
    }
    let payload_json = serde_json::to_string(event).map_err(|_| G05Error::RepositoryUnavailable)?;
    let digest = audit_event_sha256(event);
    tx.execute(
        "INSERT INTO g05_memory_g11_outbox
         (event_id,memory_id,payload_sha256,payload_json,occurred_at)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            event.event_id,
            event.memory_id,
            digest,
            payload_json,
            event.occurred_at as i64
        ],
    )
    .map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            G05Error::AuditUnavailable
        } else {
            G05Error::RepositoryUnavailable
        }
    })?;
    Ok(())
}

impl G11OutboxRepository for SqliteMemoryRepository {
    fn pending_g11_events(&self, limit: usize) -> Result<Vec<AuditEvent>, G05Error> {
        SqliteMemoryRepository::pending_g11_events(self, limit)
    }

    fn acknowledge_g11_event(
        &self,
        event: &AuditEvent,
        acknowledgment: &G11Acknowledgment,
    ) -> Result<(), G05Error> {
        SqliteMemoryRepository::acknowledge_g11_event(self, event, acknowledgment)
    }
}

impl MemoryRepository for SqliteMemoryRepository {
    fn insert_with_audit(
        &mut self,
        record: MemoryRecord,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        if event.memory_id != record.candidate.memory_id
            || event.tenant_ref != record.candidate.tenant_ref
            || event.record_version != record.candidate.record_version
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        let metadata_json = serde_json::to_string(&metadata(&record)?)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let record_json =
            serde_json::to_string(&record).map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        tx.execute(
            "INSERT INTO g05_memory_records
             (memory_id,tenant_ref,subject_ref,memory_class,content_sha256,purpose,
              classification,lifecycle_state,expires_at,record_version,retention_policy_ref,
              metadata_json,record_json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.candidate.memory_id,
                record.candidate.tenant_ref,
                record.candidate.subject_ref,
                serde_json::to_string(&record.candidate.memory_class).unwrap(),
                record.candidate.content_sha256,
                serde_json::to_string(&record.candidate.purpose).unwrap(),
                serde_json::to_string(&record.candidate.classification).unwrap(),
                serde_json::to_string(&record.lifecycle_state).unwrap(),
                record.candidate.expires_at.map(|v| v as i64),
                record.candidate.record_version as i64,
                record.candidate.retention_policy_ref,
                metadata_json,
                record_json
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                G05Error::DuplicateRecord
            } else {
                G05Error::RepositoryUnavailable
            }
        })?;
        persist_outbox(&tx, &event)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    fn get_metadata(&self, memory_id: &str) -> Result<Option<MemoryMetadata>, G05Error> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let json: Option<String> = connection
            .query_row(
                "SELECT metadata_json FROM g05_memory_records WHERE memory_id=?1",
                params![memory_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        json.map(|value| serde_json::from_str(&value).map_err(|_| G05Error::RepositoryUnavailable))
            .transpose()
    }

    fn get_content(&self, memory_id: &str) -> Result<Option<MemoryRecord>, G05Error> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let json: Option<String> = connection
            .query_row(
                "SELECT record_json FROM g05_memory_records WHERE memory_id=?1",
                params![memory_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        json.map(|value| serde_json::from_str(&value).map_err(|_| G05Error::RepositoryUnavailable))
            .transpose()
    }

    fn replace_with_audit(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        if event.memory_id != record.candidate.memory_id
            || event.tenant_ref != record.candidate.tenant_ref
            || event.record_version != record.candidate.record_version
            || record.candidate.record_version != expected_version.saturating_add(1)
        {
            return Err(G05Error::VersionConflict);
        }
        let metadata_json = serde_json::to_string(&metadata(&record)?)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let record_json =
            serde_json::to_string(&record).map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let current_state: Option<String> = tx
            .query_row(
                "SELECT lifecycle_state FROM g05_memory_records WHERE memory_id=?1 AND record_version=?2",
                params![record.candidate.memory_id,expected_version as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let current_state = current_state.ok_or(G05Error::VersionConflict)?;
        let current_state: LifecycleState =
            serde_json::from_str(&current_state).map_err(|_| G05Error::RepositoryUnavailable)?;
        if current_state == LifecycleState::PendingAudit
            && record.lifecycle_state == LifecycleState::Active
        {
            return Err(G05Error::InvalidLifecycleTransition);
        }
        let updated = tx
            .execute(
                "UPDATE g05_memory_records SET lifecycle_state=?3,record_version=?4,
             content_sha256=?5,purpose=?6,classification=?7,expires_at=?8,
             metadata_json=?9,record_json=?10
             WHERE memory_id=?1 AND record_version=?2",
                params![
                    record.candidate.memory_id,
                    expected_version as i64,
                    serde_json::to_string(&record.lifecycle_state).unwrap(),
                    record.candidate.record_version as i64,
                    record.candidate.content_sha256,
                    serde_json::to_string(&record.candidate.purpose).unwrap(),
                    serde_json::to_string(&record.candidate.classification).unwrap(),
                    record.candidate.expires_at.map(|v| v as i64),
                    metadata_json,
                    record_json
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if updated != 1 {
            return Err(G05Error::VersionConflict);
        }
        persist_outbox(&tx, &event)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    fn finalize_pending_activation(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        if record.lifecycle_state != LifecycleState::Active
            || record.candidate.memory_class != crate::MemoryClass::Durable
            || event.event_type != "memory.durable.activated"
        {
            return Err(G05Error::InvalidLifecycleTransition);
        }
        if record.candidate.record_version != expected_version
            || event.record_version != expected_version
        {
            return Err(G05Error::VersionConflict);
        }
        if event.memory_id != record.candidate.memory_id
            || event.tenant_ref != record.candidate.tenant_ref
            || event.content_sha256 != record.candidate.content_sha256
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        let approval_ref = record
            .approval_ref
            .as_deref()
            .ok_or(G05Error::DurableApprovalRequired)?;
        let pending_event_id = format!(
            "g05:durable-activation:{}:{}:{}",
            record.candidate.memory_id, expected_version, approval_ref
        );
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let current_state: Option<String> = tx
            .query_row(
                "SELECT lifecycle_state FROM g05_memory_records
                 WHERE memory_id=?1 AND record_version=?2",
                params![record.candidate.memory_id, expected_version as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let current_state = current_state.ok_or(G05Error::VersionConflict)?;
        let current_state: LifecycleState =
            serde_json::from_str(&current_state).map_err(|_| G05Error::RepositoryUnavailable)?;
        if current_state != LifecycleState::PendingAudit {
            return Err(G05Error::VersionConflict);
        }
        let receipt_row: Option<(String, String, Option<i64>, Option<String>)> = tx
            .query_row(
                "SELECT payload_json,payload_sha256,delivered_at,acknowledgment_sha256
                 FROM g05_memory_g11_outbox WHERE event_id=?1",
                params![pending_event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let (pending_json, pending_digest, delivered_at, acknowledgment_digest) =
            receipt_row.ok_or(G05Error::AuditUnavailable)?;
        let pending_event: AuditEvent =
            serde_json::from_str(&pending_json).map_err(|_| G05Error::RepositoryUnavailable)?;
        if pending_event.event_type != "memory.durable.activation.pending"
            || pending_event.memory_id != record.candidate.memory_id
            || pending_event.tenant_ref != record.candidate.tenant_ref
            || pending_event.record_version != expected_version
            || pending_event.content_sha256 != record.candidate.content_sha256
            || pending_digest != audit_event_sha256(&pending_event)
            || delivered_at.is_none()
            || acknowledgment_digest.as_deref() != Some(pending_digest.as_str())
            || delivered_at.is_some_and(|time| time < pending_event.occurred_at as i64)
        {
            return Err(G05Error::AuditUnavailable);
        }
        let metadata_json = serde_json::to_string(&metadata(&record)?)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let record_json =
            serde_json::to_string(&record).map_err(|_| G05Error::RepositoryUnavailable)?;
        let updated = tx
            .execute(
                "UPDATE g05_memory_records SET lifecycle_state=?3,metadata_json=?4,record_json=?5
             WHERE memory_id=?1 AND record_version=?2 AND lifecycle_state=?6",
                params![
                    record.candidate.memory_id,
                    expected_version as i64,
                    serde_json::to_string(&LifecycleState::Active).unwrap(),
                    metadata_json,
                    record_json,
                    serde_json::to_string(&LifecycleState::PendingAudit).unwrap()
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if updated != 1 {
            return Err(G05Error::VersionConflict);
        }
        persist_outbox(&tx, &event)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit_event_sha256, AuditEvent, MemoryClass, Purpose};

    fn record(state: LifecycleState, version: u64) -> MemoryRecord {
        let content = "sqlite repository fixture".to_owned();
        MemoryRecord {
            candidate: crate::MemoryCandidate {
                schema_id: crate::RECORD_SCHEMA_ID.into(),
                contract_version: crate::CONTRACT_VERSION.into(),
                memory_id: "memory:sqlite".into(),
                tenant_ref: "tenant:sqlite".into(),
                subject_ref: "subject:sqlite".into(),
                actor_ref: "actor:sqlite".into(),
                memory_class: MemoryClass::Durable,
                content_sha256: crate::sha256_hex(content.as_bytes()),
                content,
                purpose: Purpose::TaskContinuity,
                classification: crate::Classification::Internal,
                provenance: crate::Provenance {
                    kind: crate::ProvenanceKind::OwnerApproved,
                    source_refs: vec![],
                    source_revision_refs: vec![],
                    derived_from: vec![],
                    recorded_by_ref: "actor:sqlite".into(),
                    recorded_at: 10,
                },
                confidence_milli: None,
                created_at: 10,
                expires_at: None,
                retention_policy_ref: "retention:sqlite".into(),
                episodic_opt_in_ref: None,
                record_version: version,
            },
            lifecycle_state: state,
            approval_ref: if state == LifecycleState::PendingAudit
                || state == LifecycleState::Active
            {
                Some("approval:sqlite".into())
            } else {
                None
            },
            approved_by_ref: if state == LifecycleState::PendingAudit
                || state == LifecycleState::Active
            {
                Some("reviewer:sqlite".into())
            } else {
                None
            },
            approved_at: if state == LifecycleState::PendingAudit || state == LifecycleState::Active
            {
                Some(11)
            } else {
                None
            },
            updated_at: 11,
        }
    }

    fn event(record: &MemoryRecord, event_type: &str) -> AuditEvent {
        AuditEvent {
            event_id: format!("event:{}:{}", record.candidate.memory_id, event_type),
            event_type: event_type.into(),
            memory_id: record.candidate.memory_id.clone(),
            tenant_ref: record.candidate.tenant_ref.clone(),
            actor_ref: "actor:sqlite".into(),
            purpose: record.candidate.purpose,
            record_version: record.candidate.record_version,
            outcome: "ok".into(),
            correlation_ref: "trace:sqlite".into(),
            occurred_at: 11,
            content_sha256: record.candidate.content_sha256.clone(),
        }
    }

    #[test]
    fn insert_metadata_and_content_are_separated_and_outbox_is_content_free() {
        let mut repository = SqliteMemoryRepository::open_in_memory().unwrap();
        let record = record(LifecycleState::PendingAudit, 1);
        let event = event(&record, "memory.durable.activation.pending");
        repository
            .insert_with_audit(record.clone(), event.clone())
            .unwrap();
        let metadata = repository.get_metadata("memory:sqlite").unwrap().unwrap();
        assert_eq!(metadata.lifecycle_state, LifecycleState::PendingAudit);
        assert_eq!(
            repository.get_content("memory:sqlite").unwrap(),
            Some(record)
        );
        let pending = repository.pending_g11_events(10).unwrap();
        assert_eq!(pending, vec![event]);
        let encoded = serde_json::to_string(&pending[0]).unwrap();
        assert!(!encoded.contains("sqlite repository fixture"));
    }

    #[test]
    fn replace_requires_exact_version_and_is_atomic_with_outbox() {
        let mut repository = SqliteMemoryRepository::open_in_memory().unwrap();
        let original = record(LifecycleState::PendingReview, 1);
        repository
            .insert_with_audit(
                original.clone(),
                event(&original, "memory.durable.proposed"),
            )
            .unwrap();
        let mut updated = original.clone();
        updated.lifecycle_state = LifecycleState::PendingAudit;
        updated.candidate.record_version = 2;
        let update_event = event(&updated, "memory.durable.activation.pending");
        assert_eq!(
            repository.replace_with_audit(updated.clone(), 1, update_event.clone()),
            Ok(())
        );
        assert_eq!(
            repository.replace_with_audit(updated, 1, update_event),
            Err(G05Error::VersionConflict)
        );
        assert_eq!(repository.pending_g11_events(10).unwrap().len(), 2);
    }

    #[test]
    fn active_transition_requires_pending_audit_and_exact_cas() {
        let mut repository = SqliteMemoryRepository::open_in_memory().unwrap();
        let pending = record(LifecycleState::PendingAudit, 2);
        let pending_event = crate::durable_activation_audit_event(&pending).unwrap();
        repository
            .insert_with_audit(pending.clone(), pending_event.clone())
            .unwrap();
        let mut active = pending.clone();
        active.lifecycle_state = LifecycleState::Active;
        let activation_event = event(&active, "memory.durable.activated");
        assert_eq!(
            repository.finalize_pending_activation(active.clone(), 2, activation_event.clone()),
            Err(G05Error::AuditUnavailable)
        );
        let acknowledgment = G11Acknowledgment {
            event_id: pending_event.event_id.clone(),
            payload_sha256: audit_event_sha256(&pending_event),
            accepted_at: pending_event.occurred_at,
        };
        repository
            .acknowledge_g11_event(&pending_event, &acknowledgment)
            .unwrap();
        assert_eq!(
            repository.finalize_pending_activation(active.clone(), 1, activation_event.clone()),
            Err(G05Error::VersionConflict)
        );
        assert_eq!(
            repository.finalize_pending_activation(active, 2, activation_event),
            Ok(())
        );
        assert_eq!(
            repository
                .get_metadata("memory:sqlite")
                .unwrap()
                .unwrap()
                .lifecycle_state,
            LifecycleState::Active
        );
    }

    #[test]
    fn outbox_delivery_retries_without_losing_or_mutating_event() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct RetryG11 {
            fail_once: AtomicBool,
        }
        impl crate::G11MemoryAuditAuthority for RetryG11 {
            fn append_memory_event(
                &self,
                event: &AuditEvent,
            ) -> Result<G11Acknowledgment, G05Error> {
                if self.fail_once.swap(false, Ordering::SeqCst) {
                    return Err(G05Error::AuditUnavailable);
                }
                Ok(G11Acknowledgment {
                    event_id: event.event_id.clone(),
                    payload_sha256: audit_event_sha256(event),
                    accepted_at: event.occurred_at,
                })
            }
        }

        let mut repository = SqliteMemoryRepository::open_in_memory().unwrap();
        let pending = record(LifecycleState::PendingAudit, 2);
        let event = event(&pending, "memory.durable.activation.pending");
        repository
            .insert_with_audit(pending, event.clone())
            .unwrap();
        let sink = RetryG11 {
            fail_once: AtomicBool::new(true),
        };

        assert_eq!(
            crate::dispatch_g11_outbox(&repository, &sink, 10),
            Err(G05Error::AuditUnavailable)
        );
        assert_eq!(
            repository.pending_g11_events(10).unwrap(),
            vec![event.clone()]
        );
        let acknowledgments = crate::dispatch_g11_outbox(&repository, &sink, 10).unwrap();
        assert_eq!(acknowledgments.len(), 1);
        assert_eq!(acknowledgments[0].event_id(), event.event_id);
        assert!(repository.pending_g11_events(10).unwrap().is_empty());
    }

    #[test]
    fn durable_activation_runs_through_g11_receipt_and_final_repository_cas() {
        let mut repository = SqliteMemoryRepository::open_in_memory().unwrap();
        let pending = record(LifecycleState::PendingAudit, 2);
        let pending_event = crate::durable_activation_audit_event(&pending).unwrap();
        repository
            .insert_with_audit(pending.clone(), pending_event.clone())
            .unwrap();

        let g11_sink =
            std::sync::Arc::new(iroka_kernel::SqliteAuditSink::open_in_memory().unwrap());
        let g11 = crate::KernelSqliteG11MemoryAdapter::new(g11_sink.clone());
        let acknowledgments = crate::dispatch_g11_outbox(&repository, &g11, 10).unwrap();
        let acknowledgment = acknowledgments
            .iter()
            .find(|item| item.event_id() == pending_event.event_id)
            .unwrap();

        crate::commit_durable_activation(
            &mut repository,
            &pending,
            acknowledgment,
            pending.candidate.record_version,
            acknowledgment.accepted_at(),
        )
        .unwrap();

        assert_eq!(
            repository
                .get_metadata("memory:sqlite")
                .unwrap()
                .unwrap()
                .lifecycle_state,
            LifecycleState::Active
        );
        assert_eq!(repository.pending_g11_events(10).unwrap().len(), 1);
        assert_eq!(g11_sink.verify_integrity(), Ok(()));
    }

    #[test]
    fn g11_acknowledgment_must_match_exact_event_and_is_idempotent() {
        let repository = SqliteMemoryRepository::open_in_memory().unwrap();
        let pending = record(LifecycleState::PendingAudit, 2);
        let event = event(&pending, "memory.durable.activation.pending");
        let mut writer = repository.clone();
        writer.insert_with_audit(pending, event.clone()).unwrap();
        let acknowledgment = G11Acknowledgment {
            event_id: event.event_id.clone(),
            payload_sha256: audit_event_sha256(&event),
            accepted_at: event.occurred_at,
        };
        repository
            .acknowledge_g11_event(&event, &acknowledgment)
            .unwrap();
        repository
            .acknowledge_g11_event(&event, &acknowledgment)
            .unwrap();
        assert!(repository.pending_g11_events(10).unwrap().is_empty());
    }
}
