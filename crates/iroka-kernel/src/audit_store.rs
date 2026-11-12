//! G11 append-only SQLite audit adapter with a SHA-256 event chain.
//! Hash chains detect local edits; production must externally anchor signed checkpoints.

use crate::{AuditError, AuditEvent, AuditSink, DecisionCode};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex, time::Duration};

const ZERO: [u8; 32] = [0; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStoreError {
    Unavailable,
    IntegrityFailure,
    Rejected,
}

/// Opaque G11 durable-acceptance receipt. Only SqliteAuditSink can construct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAuditReceipt {
    event_id: String,
    payload_sha256: String,
    accepted_at: u64,
}

impl MemoryAuditReceipt {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    pub fn accepted_at(&self) -> u64 {
        self.accepted_at
    }
}

pub struct SqliteAuditSink {
    connection: Mutex<Connection>,
}

impl SqliteAuditSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditStoreError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::{
                fs::{symlink_metadata, OpenOptions},
                os::unix::fs::{OpenOptionsExt, PermissionsExt},
            };
            match symlink_metadata(path) {
                Ok(m) if m.file_type().is_symlink() || m.permissions().mode() & 0o077 != 0 => {
                    return Err(AuditStoreError::Unavailable)
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .map_err(|_| AuditStoreError::Unavailable)?;
                }
                Err(_) => return Err(AuditStoreError::Unavailable),
            }
        }
        let c = Connection::open(path).map_err(|_| AuditStoreError::Unavailable)?;
        Self::from_connection(c)
    }

    pub fn open_in_memory() -> Result<Self, AuditStoreError> {
        Self::from_connection(
            Connection::open_in_memory().map_err(|_| AuditStoreError::Unavailable)?,
        )
    }

    fn from_connection(c: Connection) -> Result<Self, AuditStoreError> {
        c.busy_timeout(Duration::from_secs(5))
            .map_err(|_| AuditStoreError::Unavailable)?;
        c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS audit_events(
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
            correlation_id TEXT NOT NULL, subject TEXT NOT NULL, capability TEXT NOT NULL,
            resource TEXT NOT NULL, policy_version TEXT NOT NULL,
            decision TEXT NOT NULL CHECK(decision IN ('ALLOW','DENY','REQUIRE_APPROVAL','ESCALATE')),
            occurred_at INTEGER NOT NULL, previous_hash BLOB NOT NULL CHECK(length(previous_hash)=32),
            event_hash BLOB NOT NULL CHECK(length(event_hash)=32));
          CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
          CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
          CREATE TABLE IF NOT EXISTS audit_memory_receipts(
            event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
            payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
            accepted_at INTEGER NOT NULL,
            audit_sequence INTEGER NOT NULL UNIQUE,
            event_hash BLOB NOT NULL CHECK(length(event_hash)=32));
          CREATE TRIGGER IF NOT EXISTS audit_memory_receipts_no_update
            BEFORE UPDATE ON audit_memory_receipts
            BEGIN SELECT RAISE(ABORT,'append-only audit receipt'); END;
          CREATE TRIGGER IF NOT EXISTS audit_memory_receipts_no_delete
            BEFORE DELETE ON audit_memory_receipts
            BEGIN SELECT RAISE(ABORT,'append-only audit receipt'); END;")
            .map_err(|_| AuditStoreError::Unavailable)?;
        let sink = Self {
            connection: Mutex::new(c),
        };
        sink.verify_integrity()?;
        Ok(sink)
    }

    pub fn append_event(&self, e: &AuditEvent) -> Result<(), AuditStoreError> {
        let fields = [
            e.event_id(),
            e.correlation_id(),
            e.subject(),
            e.capability(),
            e.resource(),
            e.policy_version(),
        ];
        if fields.iter().any(|v| v.trim().is_empty() || v.len() > 4096) || e.event_id().len() > 256
        {
            return Err(AuditStoreError::Rejected);
        }
        let at = i64::try_from(e.occurred_at()).map_err(|_| AuditStoreError::Rejected)?;
        let decision = decision_name(e.decision());
        let mut c = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuditStoreError::Unavailable)?;
        let previous: Vec<u8> = tx
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| AuditStoreError::Unavailable)?
            .unwrap_or_else(|| ZERO.to_vec());
        if previous.len() != 32 {
            return Err(AuditStoreError::IntegrityFailure);
        }
        let digest = hash_event(
            &previous,
            e.event_id(),
            e.correlation_id(),
            e.subject(),
            e.capability(),
            e.resource(),
            e.policy_version(),
            decision,
            at,
        );
        tx.execute(
            "INSERT INTO audit_events(event_id,correlation_id,subject,capability,resource,
          policy_version,decision,occurred_at,previous_hash,event_hash)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                e.event_id(),
                e.correlation_id(),
                e.subject(),
                e.capability(),
                e.resource(),
                e.policy_version(),
                decision,
                at,
                previous,
                digest.as_slice()
            ],
        )
        .map_err(|err| {
            if err.to_string().contains("UNIQUE constraint failed") {
                AuditStoreError::Rejected
            } else {
                AuditStoreError::Unavailable
            }
        })?;
        tx.commit().map_err(|_| AuditStoreError::Unavailable)
    }

    /// Append or confirm an exact content-free G05 lifecycle event and
    /// return an opaque receipt. Duplicate IDs are idempotent only when the
    /// original G05 payload digest and mapped audit fields match exactly.
    #[allow(clippy::too_many_arguments)]
    pub fn append_memory_receipt(
        &self,
        event_id: &str,
        correlation_id: &str,
        subject: &str,
        capability: &str,
        resource: &str,
        policy_version: &str,
        occurred_at: u64,
        payload_sha256: &str,
    ) -> Result<MemoryAuditReceipt, AuditStoreError> {
        let fields = [event_id, correlation_id, subject, capability, resource, policy_version];
        if fields.iter().any(|value| value.trim().is_empty() || value.len() > 4096)
            || event_id.len() > 256
            || payload_sha256.len() != 64
            || !payload_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(AuditStoreError::Rejected);
        }
        let event = AuditEvent::new(
            event_id,
            correlation_id,
            subject,
            capability,
            resource,
            policy_version,
            DecisionCode::Allow,
            occurred_at,
        );
        let accepted_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AuditStoreError::Unavailable)?
            .as_secs();
        let accepted_at_i64 = i64::try_from(accepted_at).map_err(|_| AuditStoreError::Rejected)?;
        let occurred_at_i64 = i64::try_from(occurred_at).map_err(|_| AuditStoreError::Rejected)?;
        if accepted_at_i64 < occurred_at_i64 {
            return Err(AuditStoreError::Rejected);
        }
        let mut connection = self.connection.lock().map_err(|_| AuditStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuditStoreError::Unavailable)?;

        let existing: Option<(String, i64, i64, Vec<u8>)> = tx
            .query_row(
                "SELECT payload_sha256,accepted_at,audit_sequence,event_hash
                 FROM audit_memory_receipts WHERE event_id=?1",
                params![event_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            )
            .optional()
            .map_err(|_| AuditStoreError::Unavailable)?;
        if let Some((stored_payload, stored_at, sequence, stored_hash)) = existing {
            if stored_payload != payload_sha256 {
                return Err(AuditStoreError::Rejected);
            }
            let stored_event: Option<(String,String,String,String,String,String,String,i64,Vec<u8>)> =
                tx.query_row(
                    "SELECT correlation_id,subject,capability,resource,policy_version,decision,event_id,
                            occurred_at,event_hash
                     FROM audit_events WHERE sequence=?1",
                    params![sequence],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,
                              row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
                )
                .optional()
                .map_err(|_| AuditStoreError::Unavailable)?;
            let Some((trace, stored_subject, cap, res, policy, decision, id, at, hash)) = stored_event else {
                return Err(AuditStoreError::IntegrityFailure);
            };
            if trace != correlation_id || stored_subject != subject || cap != capability
                || res != resource || policy != policy_version || decision != "ALLOW"
                || id != event_id || at != occurred_at_i64 || hash != stored_hash
            {
                return Err(AuditStoreError::IntegrityFailure);
            }
            tx.commit().map_err(|_| AuditStoreError::Unavailable)?;
            return Ok(MemoryAuditReceipt {
                event_id: event_id.to_owned(),
                payload_sha256: stored_payload,
                accepted_at: u64::try_from(stored_at).map_err(|_| AuditStoreError::IntegrityFailure)?,
            });
        }

        let previous: Vec<u8> = tx
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| AuditStoreError::Unavailable)?
            .unwrap_or_else(|| ZERO.to_vec());
        if previous.len() != 32 {
            return Err(AuditStoreError::IntegrityFailure);
        }
        let digest = hash_event(
            &previous,
            event_id,
            correlation_id,
            subject,
            capability,
            resource,
            policy_version,
            "ALLOW",
            occurred_at_i64,
        );
        tx.execute(
            "INSERT INTO audit_events(event_id,correlation_id,subject,capability,resource,
             policy_version,decision,occurred_at,previous_hash,event_hash)
             VALUES(?1,?2,?3,?4,?5,?6,'ALLOW',?7,?8,?9)",
            params![event_id,correlation_id,subject,capability,resource,policy_version,
                    occurred_at_i64,previous,digest.as_slice()],
        )
        .map_err(|_| AuditStoreError::Rejected)?;
        let sequence = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO audit_memory_receipts(event_id,payload_sha256,accepted_at,audit_sequence,event_hash)
             VALUES(?1,?2,?3,?4,?5)",
            params![event_id,payload_sha256,accepted_at_i64,sequence,digest.as_slice()],
        )
        .map_err(|_| AuditStoreError::Unavailable)?;
        tx.commit().map_err(|_| AuditStoreError::Unavailable)?;
        Ok(MemoryAuditReceipt {
            event_id: event_id.to_owned(),
            payload_sha256: payload_sha256.to_owned(),
            accepted_at,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), AuditStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        let mut s = c.prepare("SELECT event_id,correlation_id,subject,capability,resource,
          policy_version,decision,occurred_at,previous_hash,event_hash FROM audit_events ORDER BY sequence")
          .map_err(|_| AuditStoreError::Unavailable)?;
        let mut rows = s.query([]).map_err(|_| AuditStoreError::Unavailable)?;
        let mut previous = ZERO.to_vec();
        while let Some(r) = rows.next().map_err(|_| AuditStoreError::Unavailable)? {
            let id: String = r.get(0).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let trace: String = r.get(1).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let subject: String = r.get(2).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let capability: String = r.get(3).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let resource: String = r.get(4).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let policy: String = r.get(5).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let decision: String = r.get(6).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let at: i64 = r.get(7).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let prev: Vec<u8> = r.get(8).map_err(|_| AuditStoreError::IntegrityFailure)?;
            let stored: Vec<u8> = r.get(9).map_err(|_| AuditStoreError::IntegrityFailure)?;
            if prev != previous || prev.len() != 32 {
                return Err(AuditStoreError::IntegrityFailure);
            }
            let expected = hash_event(
                &prev,
                &id,
                &trace,
                &subject,
                &capability,
                &resource,
                &policy,
                &decision,
                at,
            );
            if stored.as_slice() != expected.as_slice() {
                return Err(AuditStoreError::IntegrityFailure);
            }
            previous = stored;
        }
        let receipt_count: i64 = c
            .query_row("SELECT COUNT(*) FROM audit_memory_receipts", [], |row| row.get(0))
            .map_err(|_| AuditStoreError::IntegrityFailure)?;
        let valid_receipt_count: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM audit_memory_receipts r
                 JOIN audit_events e ON e.event_id=r.event_id
                   AND e.sequence=r.audit_sequence AND e.event_hash=r.event_hash
                 WHERE length(r.payload_sha256)=64
                   AND r.accepted_at>=e.occurred_at",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuditStoreError::IntegrityFailure)?;
        if receipt_count != valid_receipt_count {
            return Err(AuditStoreError::IntegrityFailure);
        }
        Ok(())
    }

    pub fn head(&self) -> Result<(u64, [u8; 32]), AuditStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        let row: Option<(i64, Vec<u8>)> = c
            .query_row(
                "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| AuditStoreError::Unavailable)?;
        match row {
            None => Ok((0, ZERO)),
            Some((n, h)) => Ok((
                u64::try_from(n).map_err(|_| AuditStoreError::IntegrityFailure)?,
                h.try_into()
                    .map_err(|_| AuditStoreError::IntegrityFailure)?,
            )),
        }
    }
}

impl AuditSink for SqliteAuditSink {
    fn append(&self, e: &AuditEvent) -> Result<(), AuditError> {
        self.append_event(e).map_err(|e| match e {
            AuditStoreError::Unavailable => AuditError::Unavailable,
            AuditStoreError::IntegrityFailure => AuditError::IntegrityFailure,
            AuditStoreError::Rejected => AuditError::Rejected,
        })
    }
}

fn decision_name(d: DecisionCode) -> &'static str {
    match d {
        DecisionCode::Allow => "ALLOW",
        DecisionCode::Deny => "DENY",
        DecisionCode::RequireApproval => "REQUIRE_APPROVAL",
        DecisionCode::Escalate => "ESCALATE",
    }
}
fn field(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_be_bytes());
    h.update(b);
}
#[allow(clippy::too_many_arguments)]
fn hash_event(
    prev: &[u8],
    id: &str,
    trace: &str,
    subject: &str,
    cap: &str,
    res: &str,
    policy: &str,
    decision: &str,
    at: i64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"IROKA:G11:AUDIT-EVENT:V1\0");
    for v in [
        prev,
        id.as_bytes(),
        trace.as_bytes(),
        subject.as_bytes(),
        cap.as_bytes(),
        res.as_bytes(),
        policy.as_bytes(),
        decision.as_bytes(),
        at.to_be_bytes().as_slice(),
    ] {
        field(&mut h, v);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(id: &str) -> AuditEvent {
        AuditEvent::new(
            id,
            "trace:1",
            "principal:1",
            "workspace.read",
            "workspace:1",
            "policy-v1",
            DecisionCode::Allow,
            1_800_000_000,
        )
    }
    #[test]
    fn appends_and_verifies_chain() {
        let s = SqliteAuditSink::open_in_memory().unwrap();
        s.append_event(&event("event:1")).unwrap();
        s.append_event(&event("event:2")).unwrap();
        assert_eq!(s.head().unwrap().0, 2);
        assert_eq!(s.verify_integrity(), Ok(()));
    }
    #[test]
    fn rejects_duplicate_event_ids() {
        let s = SqliteAuditSink::open_in_memory().unwrap();
        s.append_event(&event("event:1")).unwrap();
        assert_eq!(
            s.append_event(&event("event:1")),
            Err(AuditStoreError::Rejected)
        );
    }
    #[test]
    fn detects_modified_rows() {
        let s = SqliteAuditSink::open_in_memory().unwrap();
        s.append_event(&event("event:1")).unwrap();
        {
            let c = s.connection.lock().unwrap();
            c.execute_batch(
            "DROP TRIGGER audit_no_update; UPDATE audit_events SET subject='tampered' WHERE sequence=1").unwrap();
        }
        assert_eq!(s.verify_integrity(), Err(AuditStoreError::IntegrityFailure));
    }
    #[test]
    fn detects_deleted_rows() {
        let s = SqliteAuditSink::open_in_memory().unwrap();
        s.append_event(&event("event:1")).unwrap();
        s.append_event(&event("event:2")).unwrap();
        {
            let c = s.connection.lock().unwrap();
            c.execute_batch(
                "DROP TRIGGER audit_no_delete; DELETE FROM audit_events WHERE sequence=1",
            )
            .unwrap();
        }
        assert_eq!(s.verify_integrity(), Err(AuditStoreError::IntegrityFailure));
    }
    #[test]
    fn persists_and_verifies_after_reopen() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("iroka-audit-{}-{nonce}.sqlite", std::process::id()));

        {
            let sink = SqliteAuditSink::open(&path).unwrap();
            sink.append_event(&event("event:durable")).unwrap();
            assert_eq!(sink.head().unwrap().0, 1);
        }

        {
            let sink = SqliteAuditSink::open(&path).unwrap();
            assert_eq!(sink.head().unwrap().0, 1);
            assert_eq!(sink.verify_integrity(), Ok(()));
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
