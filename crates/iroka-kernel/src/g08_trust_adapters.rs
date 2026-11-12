//! Durable G08 trust adapters.
//!
//! SQLite adapters are safe for multiple processes sharing one database file,
//! but not for hostile snapshot rollback or independent multi-node databases.
//! A restored database requires an external monotonic anchor before production use.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{
    TrustedClock, TrustedTimeError, WorkerKey, WorkerReplayError, WorkerReplayGuard,
    WorkerRevocationChecker, WorkerRevocationError,
};

const MAX_TIME_ATTESTATION_TTL: u64 = 30;
const MAX_REGISTRY_TTL: u64 = 86_400;

fn open_db(path: &Path) -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(10))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(connection)
}

/// Cross-process replay guard. Every consume uses BEGIN IMMEDIATE and a
/// monotonic conditional UPSERT; all verifier processes must share this file.
pub struct SqliteWorkerReplayGuard {
    path: PathBuf,
}

impl SqliteWorkerReplayGuard {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WorkerReplayError> {
        let path = path.as_ref().to_path_buf();
        let connection = open_db(&path).map_err(|_| WorkerReplayError::Unavailable)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS g08_worker_sequences(
               worker_id TEXT NOT NULL, key_id TEXT NOT NULL,
               last_sequence INTEGER NOT NULL CHECK(last_sequence > 0),
               PRIMARY KEY(worker_id,key_id)
             );",
            )
            .map_err(|_| WorkerReplayError::Unavailable)?;
        Ok(Self { path })
    }
}

impl WorkerReplayGuard for SqliteWorkerReplayGuard {
    fn consume_sequence(
        &self,
        worker_id: &str,
        key_id: &str,
        sequence: u64,
    ) -> Result<(), WorkerReplayError> {
        if worker_id.trim().is_empty() || key_id.trim().is_empty() || sequence == 0 {
            return Err(WorkerReplayError::Replay);
        }
        let sequence = i64::try_from(sequence).map_err(|_| WorkerReplayError::Replay)?;
        let mut connection = open_db(&self.path).map_err(|_| WorkerReplayError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| WorkerReplayError::Unavailable)?;
        let changed = transaction
            .execute(
                "INSERT INTO g08_worker_sequences(worker_id,key_id,last_sequence)
             VALUES(?1,?2,?3)
             ON CONFLICT(worker_id,key_id) DO UPDATE SET last_sequence=excluded.last_sequence
             WHERE g08_worker_sequences.last_sequence < excluded.last_sequence",
                params![worker_id, key_id, sequence],
            )
            .map_err(|_| WorkerReplayError::Unavailable)?;
        if changed != 1 {
            return Err(WorkerReplayError::Replay);
        }
        transaction
            .commit()
            .map_err(|_| WorkerReplayError::Unavailable)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeAttestationPayload {
    pub source_id: String,
    pub key_id: String,
    pub sequence: u64,
    pub unix_seconds: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedTimeAttestation {
    pub payload: TimeAttestationPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TimeAuthorityKey {
    pub source_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

struct ClockAnchor {
    unix_seconds: u64,
    expires_at: u64,
    monotonic: Instant,
}

/// Quorum clock with signed source attestations and a persistent high-water
/// mark. A fresh quorum is mandatory after every process start. Instant is
/// used only to advance a fresh attestation within the current process.
pub struct SqliteQuorumTrustedClock {
    path: PathBuf,
    keys: HashMap<(String, String), TimeAuthorityKey>,
    quorum: usize,
    max_skew_seconds: u64,
    anchor: Mutex<Option<ClockAnchor>>,
}

impl SqliteQuorumTrustedClock {
    pub fn open(
        path: impl AsRef<Path>,
        keys: Vec<TimeAuthorityKey>,
        quorum: usize,
        max_skew_seconds: u64,
    ) -> Result<Self, TrustedTimeError> {
        if keys.is_empty() || quorum == 0 || quorum > keys.len() || max_skew_seconds > 10 {
            return Err(TrustedTimeError::Invalid);
        }
        let mut indexed = HashMap::new();
        for key in keys {
            if key.source_id.trim().is_empty()
                || key.key_id.trim().is_empty()
                || key.not_before >= key.not_after
                || VerifyingKey::from_bytes(&key.public_key).is_err()
                || indexed
                    .insert((key.source_id.clone(), key.key_id.clone()), key)
                    .is_some()
            {
                return Err(TrustedTimeError::Invalid);
            }
        }
        let path = path.as_ref().to_path_buf();
        let connection = open_db(&path).map_err(|_| TrustedTimeError::Unavailable)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS g08_clock_state(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               high_water INTEGER NOT NULL CHECK(high_water > 0)
             );
             CREATE TABLE IF NOT EXISTS g08_clock_sources(
               source_id TEXT PRIMARY KEY, last_sequence INTEGER NOT NULL CHECK(last_sequence > 0)
             );",
            )
            .map_err(|_| TrustedTimeError::Unavailable)?;
        Ok(Self {
            path,
            keys: indexed,
            quorum,
            max_skew_seconds,
            anchor: Mutex::new(None),
        })
    }

    /// Verify a distinct-source quorum, then atomically persist both source
    /// sequence high-water marks and the global nondecreasing time watermark.
    pub fn observe(&self, attestations: &[SignedTimeAttestation]) -> Result<u64, TrustedTimeError> {
        if attestations.len() < self.quorum {
            return Err(TrustedTimeError::Unavailable);
        }
        let mut seen = HashSet::new();
        let mut valid = Vec::new();
        for item in attestations {
            let p = &item.payload;
            if p.source_id.trim().is_empty()
                || p.key_id.trim().is_empty()
                || p.sequence == 0
                || p.unix_seconds == 0
                || p.expires_at <= p.unix_seconds
                || p.expires_at - p.unix_seconds > MAX_TIME_ATTESTATION_TTL
                || !seen.insert(p.source_id.clone())
            {
                return Err(TrustedTimeError::Invalid);
            }
            let key = self
                .keys
                .get(&(p.source_id.clone(), p.key_id.clone()))
                .ok_or(TrustedTimeError::Invalid)?;
            if p.unix_seconds < key.not_before || p.unix_seconds >= key.not_after {
                return Err(TrustedTimeError::Invalid);
            }
            let verifying =
                VerifyingKey::from_bytes(&key.public_key).map_err(|_| TrustedTimeError::Invalid)?;
            let signature =
                Signature::from_slice(&item.signature).map_err(|_| TrustedTimeError::Invalid)?;
            let bytes = serde_jcs::to_vec(p).map_err(|_| TrustedTimeError::Invalid)?;
            verifying
                .verify(&bytes, &signature)
                .map_err(|_| TrustedTimeError::Invalid)?;
            valid.push((
                p.source_id.clone(),
                p.sequence,
                p.unix_seconds,
                p.expires_at,
            ));
        }
        if valid.len() < self.quorum {
            return Err(TrustedTimeError::Unavailable);
        }
        valid.sort_by_key(|v| v.2);
        let low = valid.first().ok_or(TrustedTimeError::Invalid)?.2;
        let high = valid.last().ok_or(TrustedTimeError::Invalid)?.2;
        if high.saturating_sub(low) > self.max_skew_seconds {
            return Err(TrustedTimeError::Invalid);
        }
        let candidate = valid[(valid.len() - 1) / 2].2;
        let expires_at = valid
            .iter()
            .map(|v| v.3)
            .min()
            .ok_or(TrustedTimeError::Invalid)?;
        let mut connection = open_db(&self.path).map_err(|_| TrustedTimeError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TrustedTimeError::Unavailable)?;
        let previous: Option<i64> = transaction
            .query_row(
                "SELECT high_water FROM g08_clock_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| TrustedTimeError::Unavailable)?;
        if previous.is_some_and(|v| i64::try_from(candidate).map_or(true, |n| n < v)) {
            return Err(TrustedTimeError::Invalid);
        }
        for (source, sequence, _, _) in &valid {
            let sequence = i64::try_from(*sequence).map_err(|_| TrustedTimeError::Invalid)?;
            let changed = transaction
                .execute(
                    "INSERT INTO g08_clock_sources(source_id,last_sequence) VALUES(?1,?2)
                 ON CONFLICT(source_id) DO UPDATE SET last_sequence=excluded.last_sequence
                 WHERE g08_clock_sources.last_sequence < excluded.last_sequence",
                    params![source, sequence],
                )
                .map_err(|_| TrustedTimeError::Unavailable)?;
            if changed != 1 {
                return Err(TrustedTimeError::Invalid);
            }
        }
        let candidate_i64 = i64::try_from(candidate).map_err(|_| TrustedTimeError::Invalid)?;
        transaction
            .execute(
                "INSERT INTO g08_clock_state(singleton,high_water) VALUES(1,?1)
             ON CONFLICT(singleton) DO UPDATE SET high_water=excluded.high_water",
                params![candidate_i64],
            )
            .map_err(|_| TrustedTimeError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| TrustedTimeError::Unavailable)?;
        let mut anchor = self
            .anchor
            .lock()
            .map_err(|_| TrustedTimeError::Unavailable)?;
        *anchor = Some(ClockAnchor {
            unix_seconds: candidate,
            expires_at,
            monotonic: Instant::now(),
        });
        Ok(candidate)
    }
}

impl TrustedClock for SqliteQuorumTrustedClock {
    fn now_unix_seconds(&self) -> Result<u64, TrustedTimeError> {
        let anchor = self
            .anchor
            .lock()
            .map_err(|_| TrustedTimeError::Unavailable)?;
        let value = anchor.as_ref().ok_or(TrustedTimeError::Unavailable)?;
        let elapsed = value.monotonic.elapsed().as_secs();
        let now = value
            .unix_seconds
            .checked_add(elapsed)
            .ok_or(TrustedTimeError::Invalid)?;
        if now >= value.expires_at {
            return Err(TrustedTimeError::Unavailable);
        }
        Ok(now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerRegistryEntry {
    pub worker_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub worker_revoked: bool,
    pub key_revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerRegistryPayload {
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub entries: Vec<WorkerRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkerRegistryBundle {
    pub root_key_id: String,
    pub payload: WorkerRegistryPayload,
    pub signature: Vec<u8>,
}

pub struct SqliteWorkerRegistry {
    path: PathBuf,
    root_key_id: String,
    root: VerifyingKey,
    clock: Arc<dyn TrustedClock>,
}

impl SqliteWorkerRegistry {
    pub fn open(
        path: impl AsRef<Path>,
        root_key_id: impl Into<String>,
        root_public_key: [u8; 32],
        clock: Arc<dyn TrustedClock>,
    ) -> Result<Self, WorkerRevocationError> {
        let root = VerifyingKey::from_bytes(&root_public_key)
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let path = path.as_ref().to_path_buf();
        let connection = open_db(&path).map_err(|_| WorkerRevocationError::Unavailable)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS g08_worker_registry_meta(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               version INTEGER NOT NULL, expires_at INTEGER NOT NULL, digest BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS g08_worker_registry_keys(
               worker_id TEXT NOT NULL, key_id TEXT NOT NULL, public_key BLOB NOT NULL CHECK(length(public_key)=32),
               not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
               worker_revoked INTEGER NOT NULL CHECK(worker_revoked IN (0,1)),
               key_revoked INTEGER NOT NULL CHECK(key_revoked IN (0,1)),
               PRIMARY KEY(worker_id,key_id)
             );"
        ).map_err(|_|WorkerRevocationError::Unavailable)?;
        Ok(Self {
            path,
            root_key_id: root_key_id.into(),
            root,
            clock,
        })
    }

    /// Install a complete Owner-root-signed registry snapshot. The signed
    /// version is monotonic and replacement is atomic with its digest.
    pub fn install(
        &self,
        bundle: &SignedWorkerRegistryBundle,
    ) -> Result<(), WorkerRevocationError> {
        let now = self
            .clock
            .now_unix_seconds()
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let p = &bundle.payload;
        if bundle.root_key_id != self.root_key_id
            || p.version == 0
            || p.entries.is_empty()
            || p.issued_at > now
            || p.expires_at <= now
            || p.expires_at <= p.issued_at
            || p.expires_at - p.issued_at > MAX_REGISTRY_TTL
        {
            return Err(WorkerRevocationError::Unavailable);
        }
        if p.entries.windows(2).any(|w| {
            (w[0].worker_id.as_str(), w[0].key_id.as_str())
                >= (w[1].worker_id.as_str(), w[1].key_id.as_str())        }) {
            return Err(WorkerRevocationError::Unavailable);
        }
        for entry in &p.entries {
            if entry.worker_id.trim().is_empty()
                || entry.key_id.trim().is_empty()
                || entry.not_before >= entry.not_after
                || entry.not_after > p.expires_at
                || VerifyingKey::from_bytes(&entry.public_key).is_err()
            {
                return Err(WorkerRevocationError::Unavailable);
            }
        }
        #[derive(Serialize)]
        struct RegistrySigningPayload<'a> {
            root_key_id: &'a str,
            payload: &'a WorkerRegistryPayload,
        }
        let signed_payload = RegistrySigningPayload {
            root_key_id: &bundle.root_key_id,
            payload: p,
        };
        let bytes =
            serde_jcs::to_vec(&signed_payload).map_err(|_| WorkerRevocationError::Unavailable)?;
        let signature = Signature::from_slice(&bundle.signature)
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        self.root
            .verify_strict(&bytes, &signature)
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let mut connection = open_db(&self.path).map_err(|_| WorkerRevocationError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT version FROM g08_worker_registry_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let version = i64::try_from(p.version).map_err(|_| WorkerRevocationError::Unavailable)?;
        if current.is_some_and(|v| version <= v) {
            return Err(WorkerRevocationError::Unavailable);
        }
        transaction
            .execute("DELETE FROM g08_worker_registry_keys", [])
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        for e in &p.entries {
            transaction
                .execute(
                    "INSERT INTO g08_worker_registry_keys VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        e.worker_id,
                        e.key_id,
                        e.public_key.as_slice(),
                        i64::try_from(e.not_before)
                            .map_err(|_| WorkerRevocationError::Unavailable)?,
                        i64::try_from(e.not_after)
                            .map_err(|_| WorkerRevocationError::Unavailable)?,
                        e.worker_revoked,
                        e.key_revoked
                    ],
                )
                .map_err(|_| WorkerRevocationError::Unavailable)?;
        }
        transaction.execute(
            "INSERT INTO g08_worker_registry_meta(singleton,version,expires_at,digest) VALUES(1,?1,?2,?3)
             ON CONFLICT(singleton) DO UPDATE SET version=excluded.version,expires_at=excluded.expires_at,digest=excluded.digest",
            params![version,i64::try_from(p.expires_at).map_err(|_|WorkerRevocationError::Unavailable)?,digest.as_slice()],
        ).map_err(|_|WorkerRevocationError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| WorkerRevocationError::Unavailable)
    }

    pub fn trust_snapshot(&self) -> Result<Vec<WorkerKey>, WorkerRevocationError> {
        let now = self
            .clock
            .now_unix_seconds()
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let connection = open_db(&self.path).map_err(|_| WorkerRevocationError::Unavailable)?;
        let expiry: i64 = connection
            .query_row(
                "SELECT expires_at FROM g08_worker_registry_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        if i64::try_from(now).map_err(|_| WorkerRevocationError::Unavailable)? >= expiry {
            return Err(WorkerRevocationError::Unavailable);
        }
        let mut statement = connection.prepare(
            "SELECT worker_id,key_id,public_key,not_before,not_after FROM g08_worker_registry_keys
             WHERE worker_revoked=0 AND key_revoked=0
               AND not_before<=?1 AND not_after>?1 ORDER BY worker_id,key_id"
        ).map_err(|_|WorkerRevocationError::Unavailable)?;
        let rows = statement
            .query_map(
                [i64::try_from(now).map_err(|_| WorkerRevocationError::Unavailable)?],
                |r| {
                    Ok(WorkerKey {
                        worker_id: r.get(0)?,
                        key_id: r.get(1)?,
                        public_key: r
                            .get::<_, Vec<u8>>(2)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        not_before: u64::try_from(r.get::<_, i64>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        not_after: u64::try_from(r.get::<_, i64>(4)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row.map_err(|_| WorkerRevocationError::Unavailable)?);
        }
        if values.is_empty() {
            return Err(WorkerRevocationError::Unavailable);
        }
        Ok(values)
    }

    fn status(&self, worker_id: &str, key_id: Option<&str>) -> Result<bool, WorkerRevocationError> {
        let now = self
            .clock
            .now_unix_seconds()
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        let connection = open_db(&self.path).map_err(|_| WorkerRevocationError::Unavailable)?;
        let expiry: i64 = connection
            .query_row(
                "SELECT expires_at FROM g08_worker_registry_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| WorkerRevocationError::Unavailable)?;
        if i64::try_from(now).map_err(|_| WorkerRevocationError::Unavailable)? >= expiry {
            return Err(WorkerRevocationError::Unavailable);
        }
        match key_id {
            Some(key) => connection.query_row(
                "SELECT worker_revoked OR key_revoked FROM g08_worker_registry_keys WHERE worker_id=?1 AND key_id=?2",
                params![worker_id,key],|r|r.get(0))
                .optional().map_err(|_|WorkerRevocationError::Unavailable)?
                .ok_or(WorkerRevocationError::Unavailable),
            None => {
                let revoked: Option<bool> = connection.query_row(
                    "SELECT MAX(worker_revoked) FROM g08_worker_registry_keys WHERE worker_id=?1",
                    params![worker_id],|r|r.get(0))
                    .map_err(|_|WorkerRevocationError::Unavailable)?;
                revoked.ok_or(WorkerRevocationError::Unavailable)
            }
        }
    }
}

impl WorkerRevocationChecker for SqliteWorkerRegistry {
    fn worker_revoked(&self, worker_id: &str) -> Result<bool, WorkerRevocationError> {
        self.status(worker_id, None)
    }
    fn key_revoked(&self, worker_id: &str, key_id: &str) -> Result<bool, WorkerRevocationError> {
        self.status(worker_id, Some(key_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn db_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "iroka-g08-{label}-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    #[test]
    fn replay_guard_survives_restart_and_rejects_old_sequence() {
        let path = db_path("replay-restart");
        {
            let guard = SqliteWorkerReplayGuard::open(&path).unwrap();
            guard.consume_sequence("worker-a", "key-a", 7).unwrap();
        }
        let guard = SqliteWorkerReplayGuard::open(&path).unwrap();
        assert_eq!(
            guard.consume_sequence("worker-a", "key-a", 7),
            Err(WorkerReplayError::Replay)
        );
        guard.consume_sequence("worker-a", "key-a", 8).unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn replay_guard_serializes_competing_process_style_connections() {
        let path = db_path("replay-race");
        let barrier = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let guard = SqliteWorkerReplayGuard::open(path).unwrap();
                barrier.wait();
                guard.consume_sequence("worker-race", "key-race", 42)
            }));
        }
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(WorkerReplayError::Replay))
                .count(),
            7
        );
        let _ = std::fs::remove_file(path);
    }

    struct TestClock(u64);
    impl TrustedClock for TestClock {
        fn now_unix_seconds(&self) -> Result<u64, TrustedTimeError> {
            Ok(self.0)
        }
    }

    fn signed_time(
        signing: &SigningKey,
        source_id: &str,
        sequence: u64,
        unix_seconds: u64,
    ) -> SignedTimeAttestation {
        let payload = TimeAttestationPayload {
            source_id: source_id.to_owned(),
            key_id: "clock-key".to_owned(),
            sequence,
            unix_seconds,
            expires_at: unix_seconds + 20,
        };
        let bytes = serde_jcs::to_vec(&payload).unwrap();
        SignedTimeAttestation {
            payload,
            signature: signing.sign(&bytes).to_bytes().to_vec(),
        }
    }

    #[test]
    fn trusted_clock_requires_fresh_quorum_after_restart_and_rejects_rollback() {
        let path = db_path("clock-restart");
        let signing = SigningKey::from_bytes(&[31u8; 32]);
        let authority = TimeAuthorityKey {
            source_id: "clock-a".into(),
            key_id: "clock-key".into(),
            public_key: signing.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 2_000,
        };
        {
            let clock =
                SqliteQuorumTrustedClock::open(&path, vec![authority.clone()], 1, 0).unwrap();
            assert_eq!(clock.now_unix_seconds(), Err(TrustedTimeError::Unavailable));
            assert_eq!(
                clock.observe(&[signed_time(&signing, "clock-a", 1, 1_000)]),
                Ok(1_000)
            );
            assert_eq!(clock.now_unix_seconds(), Ok(1_000));
            assert_eq!(
                clock.observe(&[signed_time(&signing, "clock-a", 1, 999)]),
                Err(TrustedTimeError::Invalid)
            );
        }
        let clock = SqliteQuorumTrustedClock::open(&path, vec![authority], 1, 0).unwrap();
        assert_eq!(clock.now_unix_seconds(), Err(TrustedTimeError::Unavailable));
        assert_eq!(
            clock.observe(&[signed_time(&signing, "clock-a", 2, 1_001)]),
            Ok(1_001)
        );
        assert_eq!(clock.now_unix_seconds(), Ok(1_001));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn trusted_clock_rejects_duplicate_sources_and_bad_signatures() {
        let path = db_path("clock-invalid");
        let a = SigningKey::from_bytes(&[32u8; 32]);
        let b = SigningKey::from_bytes(&[33u8; 32]);
        let keys = vec![
            TimeAuthorityKey {
                source_id: "clock-a".into(),
                key_id: "clock-key".into(),
                public_key: a.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 2_000,
            },
            TimeAuthorityKey {
                source_id: "clock-b".into(),
                key_id: "clock-key".into(),
                public_key: b.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 2_000,
            },
        ];
        let clock = SqliteQuorumTrustedClock::open(&path, keys, 2, 2).unwrap();
        let duplicate = [
            signed_time(&a, "clock-a", 1, 1_000),
            signed_time(&a, "clock-a", 2, 1_000),
        ];
        assert_eq!(clock.observe(&duplicate), Err(TrustedTimeError::Invalid));
        let mut invalid = signed_time(&b, "clock-b", 1, 1_001);
        invalid.signature[0] ^= 1;
        assert_eq!(
            clock.observe(&[signed_time(&a, "clock-a", 1, 1_000), invalid]),
            Err(TrustedTimeError::Invalid)
        );
        let _ = std::fs::remove_file(path);
    }

    #[derive(Serialize)]
    struct RegistrySigningPayload<'a> {
        root_key_id: &'a str,
        payload: &'a WorkerRegistryPayload,
    }

    fn signed_registry(
        root: &SigningKey,
        version: u64,
        revoked: bool,
    ) -> SignedWorkerRegistryBundle {
        let worker = SigningKey::from_bytes(&[44u8; 32]);
        let payload = WorkerRegistryPayload {
            version,
            issued_at: 1_000,
            expires_at: 1_100,
            entries: vec![WorkerRegistryEntry {
                worker_id: "worker-a".into(),
                key_id: "worker-key".into(),
                public_key: worker.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 1_090,
                worker_revoked: revoked,
                key_revoked: false,
            }],
        };
        let envelope = RegistrySigningPayload {
            root_key_id: "owner-root-v1",
            payload: &payload,
        };
        let bytes = serde_jcs::to_vec(&envelope).unwrap();
        SignedWorkerRegistryBundle {
            root_key_id: "owner-root-v1".into(),
            payload,
            signature: root.sign(&bytes).to_bytes().to_vec(),
        }
    }

    #[test]
    fn worker_registry_installs_signed_versions_and_enforces_revocation() {
        let path = db_path("registry");
        let root = SigningKey::from_bytes(&[55u8; 32]);
        let registry = SqliteWorkerRegistry::open(
            &path,
            "owner-root-v1",
            root.verifying_key().to_bytes(),
            Arc::new(TestClock(1_010)),
        )
        .unwrap();
        registry.install(&signed_registry(&root, 1, false)).unwrap();
        assert_eq!(registry.worker_revoked("worker-a"), Ok(false));
        assert_eq!(registry.key_revoked("worker-a", "worker-key"), Ok(false));
        assert_eq!(registry.trust_snapshot().unwrap().len(), 1);
        assert!(registry.install(&signed_registry(&root, 1, true)).is_err());
        registry.install(&signed_registry(&root, 2, true)).unwrap();
        assert_eq!(registry.worker_revoked("worker-a"), Ok(true));
        assert_eq!(registry.key_revoked("worker-a", "worker-key"), Ok(true));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn worker_registry_rejects_forged_bundle_and_unknown_worker() {
        let path = db_path("registry-forged");
        let root = SigningKey::from_bytes(&[56u8; 32]);
        let registry = SqliteWorkerRegistry::open(
            &path,
            "owner-root-v1",
            root.verifying_key().to_bytes(),
            Arc::new(TestClock(1_010)),
        )
        .unwrap();
        let mut forged = signed_registry(&root, 1, false);
        forged.payload.entries[0].worker_id = "worker-forged".into();
        assert!(registry.install(&forged).is_err());
        assert_eq!(
            registry.worker_revoked("unknown"),
            Err(WorkerRevocationError::Unavailable)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn replay_guard_failed_insert_does_not_advance_sequence() {
        let path = db_path("replay-insert-rollback");
        let guard = SqliteWorkerReplayGuard::open(&path).unwrap();
        let connection = open_db(&path).unwrap();
        connection.execute_batch("CREATE TRIGGER reject_replay_insert BEFORE INSERT ON g08_worker_sequences BEGIN SELECT RAISE(ABORT,'injected insert failure'); END;").unwrap();
        assert_eq!(guard.consume_sequence("worker-failure", "key-failure", 1), Err(WorkerReplayError::Unavailable));
        connection.execute_batch("DROP TRIGGER reject_replay_insert;").unwrap();
        guard.consume_sequence("worker-failure", "key-failure", 1).unwrap();
        assert_eq!(guard.consume_sequence("worker-failure", "key-failure", 1), Err(WorkerReplayError::Replay));
        drop(connection);
        drop(guard);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn worker_registry_failed_snapshot_install_rolls_back_old_snapshot() {
        let path = db_path("registry-rollback");
        let root = SigningKey::from_bytes(&[57u8; 32]);
        let registry = SqliteWorkerRegistry::open(&path, "owner-root-v1", root.verifying_key().to_bytes(), Arc::new(TestClock(1_010))).unwrap();
        registry.install(&signed_registry(&root, 1, false)).unwrap();
        let connection = open_db(&path).unwrap();
        connection.execute_batch("CREATE TRIGGER reject_registry_insert BEFORE INSERT ON g08_worker_registry_keys BEGIN SELECT RAISE(ABORT,'injected registry insert failure'); END;").unwrap();
        assert!(registry.install(&signed_registry(&root, 2, true)).is_err());
        connection.execute_batch("DROP TRIGGER reject_registry_insert;").unwrap();
        assert_eq!(registry.worker_revoked("worker-a"), Ok(false));
        assert_eq!(registry.trust_snapshot().unwrap().len(), 1);
        registry.install(&signed_registry(&root, 2, true)).unwrap();
        assert_eq!(registry.worker_revoked("worker-a"), Ok(true));
        drop(connection);
        drop(registry);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_guard_subprocess_race_restart_and_revocation() {
        use std::process::Command;
        use std::time::Duration;
        if let Ok(mode) = std::env::var("IROKA_G08_SUBPROCESS_MODE") {
            let path = PathBuf::from(std::env::var_os("IROKA_G08_SUBPROCESS_DB").unwrap());
            let marker = PathBuf::from(std::env::var_os("IROKA_G08_SUBPROCESS_MARKER").unwrap());
            match mode.as_str() {
                "consume" => {
                    thread::sleep(Duration::from_millis(200));
                    let guard = SqliteWorkerReplayGuard::open(path).unwrap();
                    let outcome = match guard.consume_sequence("worker-process", "key-process", 42) {
                        Ok(()) => "accepted",
                        Err(WorkerReplayError::Replay) => "replayed",
                        Err(error) => panic!("unexpected subprocess replay error: {error:?}"),
                    };
                    std::fs::write(marker, outcome).unwrap();
                }
                "revocation" => {
                    let root = SigningKey::from_bytes(&[55u8; 32]);
                    let registry = SqliteWorkerRegistry::open(&path, "owner-root-v1", root.verifying_key().to_bytes(), Arc::new(TestClock(1_010))).unwrap();
                    std::fs::write(marker, registry.worker_revoked("worker-a").unwrap().to_string()).unwrap();
                }
                _ => panic!("unknown subprocess mode"),
            }
            return;
        }
        let path = db_path("replay-subprocess");
        let exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        let mut markers = Vec::new();
        for index in 0..2 {
            let marker = path.with_extension(format!("child-{index}.result"));
            let child = Command::new(&exe)
                .args(["--exact", "g08_trust_adapters::tests::replay_guard_subprocess_race_restart_and_revocation", "--nocapture"])
                .env("IROKA_G08_SUBPROCESS_MODE", "consume")
                .env("IROKA_G08_SUBPROCESS_DB", &path)
                .env("IROKA_G08_SUBPROCESS_MARKER", &marker)
                .spawn().unwrap();
            children.push(child);
            markers.push(marker);
        }
        for child in children { assert!(child.wait_with_output().unwrap().status.success()); }
        let outcomes: Vec<String> = markers.iter().map(|p| std::fs::read_to_string(p).unwrap()).collect();
        assert_eq!(outcomes.iter().filter(|v| v.as_str() == "accepted").count(), 1);
        assert_eq!(outcomes.iter().filter(|v| v.as_str() == "replayed").count(), 1);
        let guard = SqliteWorkerReplayGuard::open(&path).unwrap();
        assert_eq!(guard.consume_sequence("worker-process", "key-process", 42), Err(WorkerReplayError::Replay));
        drop(guard);
        for marker in markers { let _ = std::fs::remove_file(marker); }
        let _ = std::fs::remove_file(&path);

        let registry_path = db_path("registry-subprocess-revocation");
        let root = SigningKey::from_bytes(&[55u8; 32]);
        let registry = SqliteWorkerRegistry::open(&registry_path, "owner-root-v1", root.verifying_key().to_bytes(), Arc::new(TestClock(1_010))).unwrap();
        registry.install(&signed_registry(&root, 1, false)).unwrap();
        registry.install(&signed_registry(&root, 2, true)).unwrap();
        let marker = registry_path.with_extension("revocation.result");
        let child = Command::new(exe)
            .args(["--exact", "g08_trust_adapters::tests::replay_guard_subprocess_race_restart_and_revocation", "--nocapture"])
            .env("IROKA_G08_SUBPROCESS_MODE", "revocation")
            .env("IROKA_G08_SUBPROCESS_DB", &registry_path)
            .env("IROKA_G08_SUBPROCESS_MARKER", &marker)
            .spawn().unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "true");
        drop(registry);
        let _ = std::fs::remove_file(marker);
        let _ = std::fs::remove_file(registry_path);
    }
}
