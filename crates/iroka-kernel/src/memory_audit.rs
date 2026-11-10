//! G11 versioned, content-free memory lifecycle assurance events.
//!
//! This stream is deliberately separate from decision AuditEvent. It has its
//! own schema version, idempotency key, append-only table and hash chain.
//! Payloads contain opaque references and lifecycle metadata only; memory
//! content, excerpts, prompts, embeddings, credentials and secrets are absent.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

pub const MEMORY_EVENT_SCHEMA_ID: &str = "iroka.g11.memory-lifecycle-event";
pub const MEMORY_EVENT_SCHEMA_VERSION: u16 = 1;
const ZERO_HASH: [u8; 32] = [0; 32];
const MAX_FIELD_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleEvent {
    pub schema_id: String,
    pub schema_version: u16,
    pub event_id: String,
    pub event_type: String,
    pub aggregate_ref: String,
    pub tenant_ref: String,
    pub actor_ref: String,
    pub purpose: String,
    pub record_version: u64,
    pub outcome: String,
    pub correlation_ref: String,
    pub occurred_at: u64,
}

impl MemoryLifecycleEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: impl Into<String>,
        event_type: impl Into<String>,
        aggregate_ref: impl Into<String>,
        tenant_ref: impl Into<String>,
        actor_ref: impl Into<String>,
        purpose: impl Into<String>,
        record_version: u64,
        outcome: impl Into<String>,
        correlation_ref: impl Into<String>,
        occurred_at: u64,
    ) -> Self {
        Self {
            schema_id: MEMORY_EVENT_SCHEMA_ID.to_owned(),
            schema_version: MEMORY_EVENT_SCHEMA_VERSION,
            event_id: event_id.into(),
            event_type: event_type.into(),
            aggregate_ref: aggregate_ref.into(),
            tenant_ref: tenant_ref.into(),
            actor_ref: actor_ref.into(),
            purpose: purpose.into(),
            record_version,
            outcome: outcome.into(),
            correlation_ref: correlation_ref.into(),
            occurred_at,
        }
    }

    fn validate(&self) -> Result<(), MemoryAuditError> {
        if self.schema_id != MEMORY_EVENT_SCHEMA_ID
            || self.schema_version != MEMORY_EVENT_SCHEMA_VERSION
            || self.record_version == 0
            || [
                &self.event_id,
                &self.event_type,
                &self.aggregate_ref,
                &self.tenant_ref,
                &self.actor_ref,
                &self.purpose,
                &self.outcome,
                &self.correlation_ref,
            ]
            .iter()
            .any(|field| field.trim().is_empty() || field.len() > MAX_FIELD_BYTES)
        {
            return Err(MemoryAuditError::Rejected);
        }
        if self.event_type.len() > 128
            || !self.event_type.starts_with("memory.")
            || self.event_id.len() > 256
        {
            return Err(MemoryAuditError::Rejected);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAuditError {
    Unavailable,
    IntegrityFailure,
    Rejected,
    EventIdCollision,
}

/// G11-owned append interface. Repeated identical event IDs are idempotent;
/// reusing an ID for different content is rejected.
pub trait MemoryLifecycleAuditSink: Send + Sync {
    fn append_memory_event(&self, event: &MemoryLifecycleEvent) -> Result<(), MemoryAuditError>;
}

pub struct SqliteMemoryLifecycleAuditStore {
    connection: Mutex<Connection>,
}

impl SqliteMemoryLifecycleAuditStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MemoryAuditError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::fs::{symlink_metadata, OpenOptions};
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            match symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink()
                    || metadata.permissions().mode() & 0o077 != 0 =>
                    return Err(MemoryAuditError::Unavailable),
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    OpenOptions::new().write(true).create_new(true).mode(0o600)
                        .open(path).map_err(|_| MemoryAuditError::Unavailable)?;
                }
                Err(_) => return Err(MemoryAuditError::Unavailable),
            }
        }
        let connection = Connection::open(path).map_err(|_| MemoryAuditError::Unavailable)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, MemoryAuditError> {
        let connection = Connection::open_in_memory().map_err(|_| MemoryAuditError::Unavailable)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, MemoryAuditError> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| MemoryAuditError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS g11_memory_lifecycle_events(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_id TEXT NOT NULL UNIQUE,
                   schema_version INTEGER NOT NULL,
                   payload BLOB NOT NULL,
                   previous_hash BLOB NOT NULL CHECK(length(previous_hash)=32),
                   event_hash BLOB NOT NULL CHECK(length(event_hash)=32)
                 );
                 CREATE TRIGGER IF NOT EXISTS g11_memory_events_no_update
                   BEFORE UPDATE ON g11_memory_lifecycle_events
                   BEGIN SELECT RAISE(ABORT,'append-only memory audit'); END;
                 CREATE TRIGGER IF NOT EXISTS g11_memory_events_no_delete
                   BEFORE DELETE ON g11_memory_lifecycle_events
                   BEGIN SELECT RAISE(ABORT,'append-only memory audit'); END;",
            )
            .map_err(|_| MemoryAuditError::Unavailable)?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.verify_integrity()?;
        Ok(store)
    }

    pub fn verify_integrity(&self) -> Result<(), MemoryAuditError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| MemoryAuditError::Unavailable)?;
        verify_connection(&connection)
    }
}

impl MemoryLifecycleAuditSink for SqliteMemoryLifecycleAuditStore {
    fn append_memory_event(&self, event: &MemoryLifecycleEvent) -> Result<(), MemoryAuditError> {
        event.validate()?;
        let payload = serde_json::to_vec(event).map_err(|_| MemoryAuditError::Rejected)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| MemoryAuditError::Unavailable)?;
        verify_connection(&connection)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| MemoryAuditError::Unavailable)?;

        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT payload FROM g11_memory_lifecycle_events WHERE event_id=?1",
                [&event.event_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| MemoryAuditError::Unavailable)?;
        if let Some(existing_payload) = existing {
            if existing_payload == payload {
                tx.commit().map_err(|_| MemoryAuditError::Unavailable)?;
                return Ok(());
            }
            return Err(MemoryAuditError::EventIdCollision);
        }

        let previous: Vec<u8> = tx
            .query_row(
                "SELECT event_hash FROM g11_memory_lifecycle_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| MemoryAuditError::Unavailable)?
            .unwrap_or_else(|| ZERO_HASH.to_vec());
        if previous.len() != 32 {
            return Err(MemoryAuditError::IntegrityFailure);
        }
        let digest = hash_event(&previous, &payload);
        tx.execute(
            "INSERT INTO g11_memory_lifecycle_events
             (event_id,schema_version,payload,previous_hash,event_hash)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                event.event_id,
                i64::from(event.schema_version),
                payload,
                previous,
                digest.as_slice()
            ],
        )
        .map_err(|_| MemoryAuditError::Unavailable)?;
        tx.commit().map_err(|_| MemoryAuditError::Unavailable)
    }
}

fn hash_event(previous: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"IROKA:G11:MEMORY-LIFECYCLE:V1\0");
    hasher.update(previous);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> MemoryLifecycleEvent {
        MemoryLifecycleEvent::new(
            "event:memory-created:1",
            "memory.created",
            "memory:opaque-1",
            "tenant:opaque-1",
            "principal:opaque-1",
            "TASK_CONTINUITY",
            1,
            "accepted",
            "trace:opaque-1",
            100,
        )
    }

    #[test]
    fn appends_versioned_content_free_event_and_verifies_chain() {
        let store = SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let event = event();
        store.append_memory_event(&event).unwrap();
        store.verify_integrity().unwrap();
        let payload = serde_json::to_string(&event).unwrap();
        for forbidden in ["content", "excerpt", "prompt", "embedding", "credential", "secret"] {
            assert!(!payload.contains(forbidden));
        }
        assert_eq!(event.schema_version, 1);
    }

    #[test]
    fn identical_retry_is_idempotent() {
        let store = SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let event = event();
        store.append_memory_event(&event).unwrap();
        store.append_memory_event(&event).unwrap();
        store.verify_integrity().unwrap();
        let connection = store.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM g11_memory_lifecycle_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn event_id_collision_with_different_payload_is_rejected() {
        let store = SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let first = event();
        store.append_memory_event(&first).unwrap();
        let mut conflicting = first;
        conflicting.outcome = "rejected".into();
        assert_eq!(
            store.append_memory_event(&conflicting),
            Err(MemoryAuditError::EventIdCollision)
        );
    }

    #[test]
    fn rejects_unknown_schema_and_malformed_event() {
        let store = SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let mut unknown = event();
        unknown.schema_version = 2;
        assert_eq!(
            store.append_memory_event(&unknown),
            Err(MemoryAuditError::Rejected)
        );
        let mut malformed = event();
        malformed.event_type = "decision.allow".into();
        assert_eq!(
            store.append_memory_event(&malformed),
            Err(MemoryAuditError::Rejected)
        );
    }

    #[test]
    fn rejects_missing_and_oversized_opaque_references() {
        let store = SqliteMemoryLifecycleAuditStore::open_in_memory().unwrap();
        let mut missing = event();
        missing.actor_ref.clear();
        assert_eq!(
            store.append_memory_event(&missing),
            Err(MemoryAuditError::Rejected)
        );
        let mut oversized = event();
        oversized.aggregate_ref = "x".repeat(MAX_FIELD_BYTES + 1);
        assert_eq!(
            store.append_memory_event(&oversized),
            Err(MemoryAuditError::Rejected)
        );
    }
}

fn verify_connection(connection: &Connection) -> Result<(), MemoryAuditError> {
    let mut statement = connection
        .prepare("SELECT payload,previous_hash,event_hash FROM g11_memory_lifecycle_events ORDER BY sequence")
        .map_err(|_| MemoryAuditError::Unavailable)?;
    let rows = statement
        .query_map([], |row| Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        )))
        .map_err(|_| MemoryAuditError::Unavailable)?;
    let mut expected_previous = ZERO_HASH.to_vec();
    for row in rows {
        let (payload, previous, event_hash) = row.map_err(|_| MemoryAuditError::Unavailable)?;
        if previous != expected_previous || event_hash.len() != 32 {
            return Err(MemoryAuditError::IntegrityFailure);
        }
        let calculated = hash_event(&previous, &payload);
        if calculated.as_slice() != event_hash.as_slice() {
            return Err(MemoryAuditError::IntegrityFailure);
        }
        expected_previous = event_hash;
    }
    Ok(())
}
