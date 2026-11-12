//! Transactional SQLite adapter for the G05 memory repository.
//!
//! This is a single-node persistence adapter. Multi-node deployments must use
//! a separately reviewed shared transactional database implementation.
//! Content is stored as serialized record data; encryption-at-rest and key
//! management remain deployment responsibilities and are not implied here.
use crate::{
    audit_event_sha256, AuditEvent, Classification, G05Error, LifecycleState, MemoryClass,
    MemoryMetadata, MemoryRecord, MemoryRepository, Purpose,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
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
                   classification TEXT NOT NULL,
                   purpose TEXT NOT NULL,
                   content_sha256 TEXT NOT NULL,
                   lifecycle_state TEXT NOT NULL,
                   expires_at INTEGER,
                   record_version INTEGER NOT NULL CHECK(record_version>0),
                   retention_policy_ref TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS g05_memory_tenant_subject
                   ON g05_memory_records(tenant_ref,subject_ref,lifecycle_state);
                 CREATE TABLE IF NOT EXISTS g05_memory_audit_outbox(
                   event_id TEXT PRIMARY KEY,
                   payload_sha256 TEXT NOT NULL,
                   event_json TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   delivery_state TEXT NOT NULL DEFAULT 'pending'
                     CHECK(delivery_state IN ('pending','delivered')),
                   delivered_at INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS g05_memory_outbox_pending
                   ON g05_memory_audit_outbox(delivery_state,created_at);",
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Read the next bounded batch of content-free G11 outbox events.
    /// Delivery/lease/acknowledgment is owned by the G11 adapter, not this
    /// repository. Events remain pending until an explicit durable receipt.
    pub fn pending_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, G05Error> {
        if limit == 0 || limit > 500 {
            return Err(G05Error::MalformedRecord);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT event_json FROM g05_memory_audit_outbox
                 WHERE delivery_state='pending' ORDER BY created_at,event_id LIMIT ?1",
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let rows = statement
            .query_map([i64::try_from(limit).map_err(|_| G05Error::MalformedRecord)?], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut events = Vec::new();
        for row in rows {
            let json = row.map_err(|_| G05Error::RepositoryUnavailable)?;
            events.push(
                serde_json::from_str(&json).map_err(|_| G05Error::RepositoryUnavailable)?,
            );
        }
        Ok(events)
    }

    /// Mark an outbox event delivered only after the trusted G11 adapter has
    /// validated its durable acknowledgment. This records delivery state; it
    /// does not mint or construct a G11Acknowledgment.
    pub fn mark_audit_event_delivered(
        &self,
        event_id: &str,
        payload_sha256: &str,
        delivered_at: u64,
    ) -> Result<(), G05Error> {
        if event_id.trim().is_empty()
            || payload_sha256.len() != 64
            || !payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(G05Error::MalformedRecord);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let changed = connection
            .execute(
                "UPDATE g05_memory_audit_outbox
                 SET delivery_state='delivered',delivered_at=?1
                 WHERE event_id=?2 AND payload_sha256=?3",
                params![to_i64(delivered_at)?, event_id, payload_sha256],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::AuditUnavailable);
        }
        Ok(())
    }
}

impl MemoryRepository for SqliteMemoryRepository {
    fn insert_with_audit(
        &mut self,
        record: MemoryRecord,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        validate_event_binding(&record, &event)?;
        let record_json =
            serde_json::to_string(&record).map_err(|_| G05Error::RepositoryUnavailable)?;
        let event_json =
            serde_json::to_string(&event).map_err(|_| G05Error::RepositoryUnavailable)?;
        let digest = audit_event_sha256(&event);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        tx.execute(
            "INSERT INTO g05_memory_records
             (memory_id,tenant_ref,subject_ref,memory_class,classification,purpose,
              content_sha256,lifecycle_state,expires_at,record_version,retention_policy_ref,
              record_json,created_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                record.candidate.memory_id,
                record.candidate.tenant_ref,
                record.candidate.subject_ref,
                json_key(record.candidate.memory_class)?,
                json_key(record.candidate.classification)?,
                json_key(record.candidate.purpose)?,
                record.candidate.content_sha256,
                json_key(record.lifecycle_state)?,
                record.candidate.expires_at.map(to_i64).transpose()?,
                to_i64(record.candidate.record_version)?,
                record.candidate.retention_policy_ref,
                record_json,
                to_i64(record.candidate.created_at)?,
                to_i64(record.updated_at)?,
            ],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(ref code, _)
                if code.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                G05Error::DuplicateRecord
            }
            _ => G05Error::RepositoryUnavailable,
        })?;
        enqueue_event(&tx, &event, &event_json, &digest)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    fn get_metadata(&self, memory_id: &str) -> Result<Option<MemoryMetadata>, G05Error> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row: Option<(String,String,String,String,String,String,String,String,Option<i64>,i64,String)> =
            connection
                .query_row(
                    "SELECT memory_id,tenant_ref,subject_ref,memory_class,classification,purpose,
                            content_sha256,lifecycle_state,expires_at,record_version,retention_policy_ref
                     FROM g05_memory_records WHERE memory_id=?1",
                    [memory_id],
                    |r| Ok((
                        r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,
                        r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?
                    )),
                )
                .optional()
                .map_err(|_| G05Error::RepositoryUnavailable)?;
        row.map(|r| {
            Ok(MemoryMetadata {
                memory_id: r.0,
                tenant_ref: r.1,
                subject_ref: r.2,
                memory_class: parse_key(&r.3)?,
                classification: parse_key(&r.4)?,
                purpose: parse_key(&r.5)?,
                content_sha256: r.6,
                lifecycle_state: parse_key(&r.7)?,
                expires_at: r.8.map(from_i64).transpose()?,
                record_version: from_i64(r.9)?,
                retention_policy_ref: r.10,
            })
        })
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
                [memory_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|_| G05Error::RepositoryUnavailable)
        })
        .transpose()
    }

    fn replace_with_audit(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        validate_event_binding(&record, &event)?;
        if record.lifecycle_state == LifecycleState::Active
            && record.candidate.memory_class == MemoryClass::Durable
        {
            return Err(G05Error::InvalidLifecycleTransition);
        }
        let record_json =
            serde_json::to_string(&record).map_err(|_| G05Error::RepositoryUnavailable)?;
        let event_json =
            serde_json::to_string(&event).map_err(|_| G05Error::RepositoryUnavailable)?;
        let digest = audit_event_sha256(&event);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let changed = tx
            .execute(
                "UPDATE g05_memory_records
                 SET tenant_ref=?1,subject_ref=?2,memory_class=?3,classification=?4,purpose=?5,
                     content_sha256=?6,lifecycle_state=?7,expires_at=?8,record_version=?9,
                     retention_policy_ref=?10,record_json=?11,updated_at=?12
                 WHERE memory_id=?13 AND tenant_ref=?14 AND record_version=?15",
                params![
                    record.candidate.tenant_ref,
                    record.candidate.subject_ref,
                    json_key(record.candidate.memory_class)?,
                    json_key(record.candidate.classification)?,
                    json_key(record.candidate.purpose)?,
                    record.candidate.content_sha256,
                    json_key(record.lifecycle_state)?,
                    record.candidate.expires_at.map(to_i64).transpose()?,
                    to_i64(record.candidate.record_version)?,
                    record.candidate.retention_policy_ref,
                    record_json,
                    to_i64(record.updated_at)?,
                    record.candidate.memory_id,
                    record.candidate.tenant_ref,
                    to_i64(expected_version)?,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::VersionConflict);
        }
        enqueue_event(&tx, &event, &event_json, &digest)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    fn finalize_pending_activation(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        if record.lifecycle_state != LifecycleState::Active
            || record.candidate.memory_class != MemoryClass::Durable
            || record.candidate.record_version != expected_version
            || event.event_type != "memory.durable.activated"
            || event.memory_id != record.candidate.memory_id
            || event.tenant_ref != record.candidate.tenant_ref
            || event.record_version != expected_version
            || event.content_sha256 != record.candidate.content_sha256
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        let record_json =
            serde_json::to_string(&record).map_err(|_| G05Error::RepositoryUnavailable)?;
        let event_json =
            serde_json::to_string(&event).map_err(|_| G05Error::RepositoryUnavailable)?;
        let digest = audit_event_sha256(&event);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let current_state: Option<String> = tx
            .query_row(
                "SELECT lifecycle_state FROM g05_memory_records
                 WHERE memory_id=?1 AND tenant_ref=?2 AND record_version=?3",
                params![
                    record.candidate.memory_id,
                    record.candidate.tenant_ref,
                    to_i64(expected_version)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if current_state.as_deref() != Some("\"pending_audit\"") {
            return Err(G05Error::VersionConflict);
        }
        let changed = tx
            .execute(
                "UPDATE g05_memory_records SET lifecycle_state=?1,record_json=?2,updated_at=?3
                 WHERE memory_id=?4 AND tenant_ref=?5 AND record_version=?6
                   AND lifecycle_state=?7",
                params![
                    json_key(record.lifecycle_state)?,
                    record_json,
                    to_i64(record.updated_at)?,
                    record.candidate.memory_id,
                    record.candidate.tenant_ref,
                    to_i64(expected_version)?,
                    "\"pending_audit\""
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::VersionConflict);
        }
        enqueue_event(&tx, &event, &event_json, &digest)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }
}

fn validate_event_binding(record: &MemoryRecord, event: &AuditEvent) -> Result<(), G05Error> {
    if event.event_id.trim().is_empty()
        || event.memory_id != record.candidate.memory_id
        || event.tenant_ref != record.candidate.tenant_ref
        || event.record_version != record.candidate.record_version
        || event.content_sha256 != record.candidate.content_sha256
    {
        return Err(G05Error::ApprovalBindingMismatch);
    }
    Ok(())
}

fn enqueue_event(
    tx: &Transaction<'_>,
    event: &AuditEvent,
    event_json: &str,
    digest: &str,
) -> Result<(), G05Error> {
    let existing: Option<String> = tx
        .query_row(
            "SELECT payload_sha256 FROM g05_memory_audit_outbox WHERE event_id=?1",
            [&event.event_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| G05Error::RepositoryUnavailable)?;
    if let Some(existing_digest) = existing {
        return if existing_digest == digest {
            Ok(())
        } else {
            Err(G05Error::AuditUnavailable)
        };
    }
    tx.execute(
        "INSERT INTO g05_memory_audit_outbox(event_id,payload_sha256,event_json,created_at)
         VALUES(?1,?2,?3,?4)",
        params![event.event_id, digest, event_json, to_i64(event.occurred_at)?],
    )
    .map_err(|_| G05Error::RepositoryUnavailable)?;
    Ok(())
}

fn json_key<T: serde::Serialize>(value: T) -> Result<String, G05Error> {
    serde_json::to_string(&value).map_err(|_| G05Error::RepositoryUnavailable)
}
fn parse_key<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, G05Error> {
    serde_json::from_str(value).map_err(|_| G05Error::RepositoryUnavailable)
}
fn to_i64(value: u64) -> Result<i64, G05Error> {
    i64::try_from(value).map_err(|_| G05Error::MalformedRecord)
}
fn from_i64(value: i64) -> Result<u64, G05Error> {
    u64::try_from(value).map_err(|_| G05Error::RepositoryUnavailable)
}
