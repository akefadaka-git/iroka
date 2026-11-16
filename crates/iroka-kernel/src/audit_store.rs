//! G11 append-only SQLite audit adapter with a SHA-256 event chain.
//! Hash chains detect local edits; production must externally anchor signed checkpoints.

use crate::{AuditError, AuditEvent, AuditSink, DecisionCode};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex, time::Duration};

const ZERO: [u8; 32] = [0; 32];

type StoredCheckpointEvidence = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);
type SerializedCheckpointEvidence = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStoreError {
    Unavailable,
    IntegrityFailure,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAuditHead {
    pub sequence: u64,
    pub digest: [u8; 32],
    pub prefix_digest: Option<[u8; 32]>,
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
          CREATE TABLE IF NOT EXISTS external_checkpoint_evidence(
            stream_id TEXT NOT NULL,
            checkpoint_sequence INTEGER NOT NULL CHECK(checkpoint_sequence > 0),
            event_sequence INTEGER NOT NULL CHECK(event_sequence > 0),
            checkpoint_digest BLOB NOT NULL CHECK(length(checkpoint_digest)=32),
            checkpoint_json BLOB NOT NULL,
            receipts_json BLOB NOT NULL,
            receipt_count INTEGER NOT NULL CHECK(receipt_count > 0),
            required_quorum INTEGER NOT NULL CHECK(required_quorum > 0),
            persisted_at INTEGER NOT NULL,
            PRIMARY KEY(stream_id, checkpoint_sequence),
            UNIQUE(stream_id, event_sequence));
          CREATE TRIGGER IF NOT EXISTS checkpoint_evidence_no_update
            BEFORE UPDATE ON external_checkpoint_evidence
            BEGIN SELECT RAISE(ABORT,'append-only checkpoint evidence'); END;
          CREATE TRIGGER IF NOT EXISTS checkpoint_evidence_no_delete
            BEFORE DELETE ON external_checkpoint_evidence
            BEGIN SELECT RAISE(ABORT,'append-only checkpoint evidence'); END;")
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

    pub fn verify_integrity(&self) -> Result<(), AuditStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        verify_chain_and_prefix(&connection, None).map(|_| ())
    }

    /// Verify the complete local chain and read its terminal sequence/digest
    /// under one SQLite read snapshot. Checkpoint creation must use this method
    /// rather than separate verify_integrity()/head() calls.
    pub fn verified_head(&self) -> Result<(u64, [u8; 32]), AuditStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| AuditStoreError::Unavailable)?;
        let verified = verify_chain_and_prefix(&transaction, None)?;
        transaction
            .commit()
            .map_err(|_| AuditStoreError::Unavailable)?;
        Ok((verified.sequence, verified.digest))
    }

    /// Verify the chain and return its terminal head plus the digest at an
    /// earlier sequence, all from the same SQLite read snapshot. The prefix
    /// digest lets reconciliation detect a fork before the latest local event.
    pub fn verified_head_and_prefix(
        &self,
        prefix_sequence: u64,
    ) -> Result<VerifiedAuditHead, AuditStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| AuditStoreError::Unavailable)?;
        let result = verify_chain_and_prefix(&transaction, Some(prefix_sequence))?;
        transaction
            .commit()
            .map_err(|_| AuditStoreError::Unavailable)?;
        Ok(result)
    }

    /// Persist already signature- and quorum-verified checkpoint evidence only
    /// when its event-head digest matches the verified local audit prefix.
    pub fn persist_checkpoint_evidence(
        &self,
        evidence: &crate::VerifiedCheckpointEvidence,
        persisted_at: u64,
    ) -> Result<(), AuditStoreError> {
        let checkpoint = evidence.checkpoint();
        let payload = &checkpoint.payload;
        let required_quorum = evidence.required_quorum();
        let receipt_count = evidence.receipts().len();
        if payload.stream_id.trim().is_empty()
            || payload.checkpoint_sequence == 0
            || payload.event_sequence == 0
            || required_quorum == 0
            || receipt_count < required_quorum
        {
            return Err(AuditStoreError::Rejected);
        }
        let checkpoint_sequence =
            i64::try_from(payload.checkpoint_sequence).map_err(|_| AuditStoreError::Rejected)?;
        let event_sequence =
            i64::try_from(payload.event_sequence).map_err(|_| AuditStoreError::Rejected)?;
        let receipt_count = i64::try_from(receipt_count).map_err(|_| AuditStoreError::Rejected)?;
        let required_quorum =
            i64::try_from(required_quorum).map_err(|_| AuditStoreError::Rejected)?;
        let persisted_at = i64::try_from(persisted_at).map_err(|_| AuditStoreError::Rejected)?;
        let expected_event_head = parse_sha256_hex(&payload.event_head_sha256)?;
        let checkpoint_digest = checkpoint.digest().map_err(|_| AuditStoreError::Rejected)?;
        let checkpoint_value =
            serde_json::to_value(checkpoint).map_err(|_| AuditStoreError::Rejected)?;
        let checkpoint_json =
            crate::canonical_json(&checkpoint_value).map_err(|_| AuditStoreError::Rejected)?;
        let receipts_value =
            serde_json::to_value(evidence.receipts()).map_err(|_| AuditStoreError::Rejected)?;
        let receipts_json =
            crate::canonical_json(&receipts_value).map_err(|_| AuditStoreError::Rejected)?;

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuditStoreError::Unavailable)?;
        let local = verify_chain_and_prefix(&transaction, Some(payload.event_sequence))?;
        if local.sequence < payload.event_sequence
            || local.prefix_digest != Some(expected_event_head)
        {
            return Err(AuditStoreError::IntegrityFailure);
        }

        let changed = transaction
            .execute(
                "INSERT OR IGNORE INTO external_checkpoint_evidence(
                    stream_id, checkpoint_sequence, event_sequence, checkpoint_digest,
                    checkpoint_json, receipts_json, receipt_count, required_quorum, persisted_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    payload.stream_id,
                    checkpoint_sequence,
                    event_sequence,
                    checkpoint_digest.as_slice(),
                    checkpoint_json,
                    receipts_json,
                    receipt_count,
                    required_quorum,
                    persisted_at
                ],
            )
            .map_err(|_| AuditStoreError::Unavailable)?;
        if changed == 0 {
            let existing: Option<StoredCheckpointEvidence> = transaction
                .query_row(
                    "SELECT checkpoint_digest, checkpoint_json, receipts_json, receipt_count, required_quorum
                     FROM external_checkpoint_evidence
                     WHERE stream_id=?1 AND checkpoint_sequence=?2",
                    params![payload.stream_id, checkpoint_sequence],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| AuditStoreError::Unavailable)?;
            let Some((digest, checkpoint_bytes, receipt_bytes, stored_count, stored_quorum)) =
                existing
            else {
                return Err(AuditStoreError::Rejected);
            };
            if digest.as_slice() != checkpoint_digest.as_slice()
                || checkpoint_bytes != checkpoint_json
                || receipt_bytes != receipts_json
                || stored_count != receipt_count
                || stored_quorum != required_quorum
            {
                return Err(AuditStoreError::Rejected);
            }
        }
        transaction
            .commit()
            .map_err(|_| AuditStoreError::Unavailable)
    }

    /// Return canonical serialized checkpoint and receipt evidence for recovery.
    /// Callers must re-parse and re-verify signatures/quorum before trusting it.
    pub fn latest_checkpoint_evidence_bytes(
        &self,
        stream_id: &str,
    ) -> Result<Option<SerializedCheckpointEvidence>, AuditStoreError> {
        if stream_id.trim().is_empty() {
            return Err(AuditStoreError::Rejected);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuditStoreError::Unavailable)?;
        connection
            .query_row(
                "SELECT checkpoint_json, receipts_json
                 FROM external_checkpoint_evidence
                 WHERE stream_id=?1 ORDER BY checkpoint_sequence DESC LIMIT 1",
                [stream_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| AuditStoreError::Unavailable)
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

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], AuditStoreError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuditStoreError::Rejected);
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| AuditStoreError::Rejected)?;
        digest[index] = u8::from_str_radix(text, 16).map_err(|_| AuditStoreError::Rejected)?;
    }
    Ok(digest)
}

fn verify_chain_and_prefix(
    connection: &Connection,
    target_sequence: Option<u64>,
) -> Result<VerifiedAuditHead, AuditStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence,event_id,correlation_id,subject,capability,resource,
             policy_version,decision,occurred_at,previous_hash,event_hash
             FROM audit_events ORDER BY sequence",
        )
        .map_err(|_| AuditStoreError::Unavailable)?;
    let mut rows = statement
        .query([])
        .map_err(|_| AuditStoreError::Unavailable)?;
    let mut previous = ZERO.to_vec();
    let mut last_sequence = 0_u64;
    let mut prefix_hash = (target_sequence == Some(0)).then_some(ZERO);
    while let Some(row) = rows.next().map_err(|_| AuditStoreError::Unavailable)? {
        let sequence: i64 = row.get(0).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let sequence = u64::try_from(sequence).map_err(|_| AuditStoreError::IntegrityFailure)?;
        if sequence <= last_sequence {
            return Err(AuditStoreError::IntegrityFailure);
        }
        let id: String = row.get(1).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let trace: String = row.get(2).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let subject: String = row.get(3).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let capability: String = row.get(4).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let resource: String = row.get(5).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let policy: String = row.get(6).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let decision: String = row.get(7).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let occurred_at: i64 = row.get(8).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let stored_previous: Vec<u8> = row.get(9).map_err(|_| AuditStoreError::IntegrityFailure)?;
        let stored_hash: Vec<u8> = row.get(10).map_err(|_| AuditStoreError::IntegrityFailure)?;
        if stored_previous != previous || stored_previous.len() != 32 {
            return Err(AuditStoreError::IntegrityFailure);
        }
        let expected = hash_event(
            &stored_previous,
            &id,
            &trace,
            &subject,
            &capability,
            &resource,
            &policy,
            &decision,
            occurred_at,
        );
        if stored_hash.as_slice() != expected.as_slice() {
            return Err(AuditStoreError::IntegrityFailure);
        }
        let digest: [u8; 32] = stored_hash
            .as_slice()
            .try_into()
            .map_err(|_| AuditStoreError::IntegrityFailure)?;
        if target_sequence == Some(sequence) {
            prefix_hash = Some(digest);
        }
        previous = stored_hash;
        last_sequence = sequence;
    }
    let digest = previous
        .try_into()
        .map_err(|_| AuditStoreError::IntegrityFailure)?;
    Ok(VerifiedAuditHead {
        sequence: last_sequence,
        digest,
        prefix_digest: prefix_hash,
    })
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
    fn verified_head_checks_chain_and_returns_snapshot_head() {
        let s = SqliteAuditSink::open_in_memory().unwrap();
        s.append_event(&event("event:verified-head")).unwrap();
        assert_eq!(s.verified_head(), s.head());

        {
            let c = s.connection.lock().unwrap();
            c.execute_batch(
                "DROP TRIGGER audit_no_update;
                 UPDATE audit_events SET subject='tampered' WHERE sequence=1",
            )
            .unwrap();
        }
        assert_eq!(s.verified_head(), Err(AuditStoreError::IntegrityFailure));
    }

    #[test]
    fn verified_head_and_prefix_are_from_one_integrity_checked_snapshot() {
        let s = SqliteAuditSink::open_in_memory().unwrap();
        s.append_event(&event("event:prefix")).unwrap();
        let expected_prefix = s.verified_head().unwrap().1;
        s.append_event(&event("event:tail")).unwrap();
        let verified = s.verified_head_and_prefix(1).unwrap();
        assert_eq!(verified.sequence, 2);
        assert_eq!(verified.digest, s.head().unwrap().1);
        assert_eq!(verified.prefix_digest, Some(expected_prefix));
        let beyond = s.verified_head_and_prefix(3).unwrap();
        assert_eq!(beyond.sequence, 2);
        assert_eq!(beyond.digest, verified.digest);
        assert_eq!(beyond.prefix_digest, None);
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
