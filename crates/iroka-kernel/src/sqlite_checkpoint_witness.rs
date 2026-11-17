//! Durable SQLite reference backend for an independently operated G11 witness.
//!
//! This adapter provides transactional, append-only checkpoint acceptance and
//! signed receipts. It is not itself an independent operator or a network API;
//! each operator must run and administer its own isolated instance and keys.
use crate::{
    CheckpointError, CheckpointSigner, CheckpointWitness, SignedCheckpoint, WitnessReceipt,
    WitnessReceiptPayload,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const RECEIPT_DOMAIN_VERSION: u32 = 1;
const RECEIPT_PROTOCOL: &str = "iroka.g11.witness-receipt";
const SIGNATURE_ALGORITHM: &str = "Ed25519";

/// A durable witness ledger. Use one database and one signing identity per operator.
pub struct SqliteCheckpointWitness {
    connection: Mutex<Connection>,
    witness_id: String,
    signer: Arc<dyn CheckpointSigner>,
    trusted_checkpoint_signers: BTreeMap<String, VerifyingKey>,
}

impl SqliteCheckpointWitness {
    /// Open or create a witness ledger. The parent directory and database file
    /// permissions are the operator's responsibility and must be protected.
    pub fn open(
        path: impl AsRef<Path>,
        witness_id: impl Into<String>,
        signer: Arc<dyn CheckpointSigner>,
        witness_verifying_key: VerifyingKey,
        trusted_checkpoint_signers: BTreeMap<String, VerifyingKey>,
    ) -> Result<Self, CheckpointError> {
        let witness_id = witness_id.into();
        if witness_id.trim().is_empty()
            || signer.key_id().trim().is_empty()
            || trusted_checkpoint_signers.is_empty()
            || trusted_checkpoint_signers.contains_key(signer.key_id())
            || trusted_checkpoint_signers
                .values()
                .any(|key| key.as_bytes() == witness_verifying_key.as_bytes())
        {
            return Err(CheckpointError::Malformed);
        }
        let mut challenge = b"IROKA:G11:WITNESS-KEY-CHECK:V1\0".to_vec();
        challenge.extend_from_slice(witness_id.as_bytes());
        challenge.extend_from_slice(signer.key_id().as_bytes());
        let signature = signer.sign(&challenge)?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| CheckpointError::InvalidSignature)?;
        witness_verifying_key
            .verify(&challenge, &signature)
            .map_err(|_| CheckpointError::InvalidSignature)?;
        let witness_key_fingerprint = hex(&Sha256::digest(witness_verifying_key.as_bytes()));

        let path = path.as_ref();
        prepare_database_file(path)?;
        let mut connection =
            Connection::open(path).map_err(|_| CheckpointError::WitnessUnavailable)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;
                 CREATE TABLE IF NOT EXISTS g11_witness_identity (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    witness_id TEXT NOT NULL UNIQUE,
                    witness_key_id TEXT NOT NULL UNIQUE,
                    witness_key_fingerprint TEXT NOT NULL
                 );
                 CREATE TRIGGER IF NOT EXISTS g11_witness_identity_no_update
                 BEFORE UPDATE ON g11_witness_identity
                 BEGIN SELECT RAISE(ABORT, 'G11 witness identity is immutable'); END;
                 CREATE TRIGGER IF NOT EXISTS g11_witness_identity_no_delete
                 BEFORE DELETE ON g11_witness_identity
                 BEGIN SELECT RAISE(ABORT, 'G11 witness identity is immutable'); END;
                 CREATE TABLE IF NOT EXISTS g11_witness_checkpoint_receipts (
                    stream_id TEXT NOT NULL,
                    checkpoint_sequence INTEGER NOT NULL CHECK(checkpoint_sequence > 0),
                    event_sequence INTEGER NOT NULL CHECK(event_sequence > 0),
                    checkpoint_digest_sha256 TEXT NOT NULL,
                    checkpoint_envelope BLOB NOT NULL,
                    witness_receipt BLOB NOT NULL,
                    accepted_at INTEGER NOT NULL CHECK(accepted_at > 0),
                    PRIMARY KEY(stream_id, checkpoint_sequence),
                    UNIQUE(stream_id, checkpoint_digest_sha256)
                 );
                 CREATE TRIGGER IF NOT EXISTS g11_witness_no_update
                 BEFORE UPDATE ON g11_witness_checkpoint_receipts
                 BEGIN SELECT RAISE(ABORT, 'G11 witness ledger is append-only'); END;
                 CREATE TRIGGER IF NOT EXISTS g11_witness_no_delete
                 BEFORE DELETE ON g11_witness_checkpoint_receipts
                 BEGIN SELECT RAISE(ABORT, 'G11 witness ledger is append-only'); END;",
            )
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        let identity = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        identity
            .execute(
                "INSERT OR IGNORE INTO g11_witness_identity
                 (singleton, witness_id, witness_key_id, witness_key_fingerprint)
                 VALUES (1, ?1, ?2, ?3)",
                params![witness_id, signer.key_id(), witness_key_fingerprint],
            )
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        let stored_identity = identity
            .query_row(
                "SELECT witness_id, witness_key_id, witness_key_fingerprint
                 FROM g11_witness_identity WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        if stored_identity.0 != witness_id
            || stored_identity.1 != signer.key_id()
            || stored_identity.2 != witness_key_fingerprint
        {
            return Err(CheckpointError::Malformed);
        }
        identity
            .commit()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;

        Ok(Self {
            connection: Mutex::new(connection),
            witness_id,
            signer,
            trusted_checkpoint_signers,
        })
    }

    fn make_receipt(
        &self,
        checkpoint: &SignedCheckpoint,
        accepted_at: u64,
    ) -> Result<WitnessReceipt, CheckpointError> {
        let payload = WitnessReceiptPayload {
            protocol: RECEIPT_PROTOCOL.into(),
            version: RECEIPT_DOMAIN_VERSION,
            witness_id: self.witness_id.clone(),
            witness_key_id: self.signer.key_id().into(),
            stream_id: checkpoint.payload.stream_id.clone(),
            checkpoint_sequence: checkpoint.payload.checkpoint_sequence,
            checkpoint_digest_sha256: hex(&checkpoint.digest()?),
            previous_checkpoint_digest_sha256: checkpoint
                .payload
                .previous_checkpoint_sha256
                .clone(),
            accepted_at,
            algorithm: SIGNATURE_ALGORITHM.into(),
        };
        let signature = self
            .signer
            .sign(&WitnessReceipt::signing_bytes(&payload)?)?;
        Ok(WitnessReceipt { payload, signature })
    }
}

impl CheckpointWitness for SqliteCheckpointWitness {
    fn publish(&self, checkpoint: &SignedCheckpoint) -> Result<WitnessReceipt, CheckpointError> {
        checkpoint.verify(&self.trusted_checkpoint_signers)?;
        let digest = hex(&checkpoint.digest()?);
        let envelope = serde_json::to_vec(checkpoint).map_err(|_| CheckpointError::Malformed)?;
        let sequence = i64::try_from(checkpoint.payload.checkpoint_sequence)
            .map_err(|_| CheckpointError::Malformed)?;
        let event_sequence = i64::try_from(checkpoint.payload.event_sequence)
            .map_err(|_| CheckpointError::Malformed)?;
        let accepted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CheckpointError::WitnessUnavailable)?
            .as_secs();
        let accepted_at_i64 =
            i64::try_from(accepted_at).map_err(|_| CheckpointError::WitnessUnavailable)?;

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CheckpointError::WitnessUnavailable)?;

        let previous = transaction
            .query_row(
                "SELECT checkpoint_sequence, event_sequence, checkpoint_digest_sha256,
                        checkpoint_envelope, witness_receipt
                 FROM g11_witness_checkpoint_receipts
                 WHERE stream_id = ?1
                 ORDER BY checkpoint_sequence DESC LIMIT 1",
                params![checkpoint.payload.stream_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;

        if let Some((
            previous_sequence,
            previous_event,
            previous_digest,
            previous_envelope,
            previous_receipt,
        )) = previous
        {
            if sequence == previous_sequence
                && digest == previous_digest
                && envelope == previous_envelope
            {
                let receipt = serde_json::from_slice(&previous_receipt)
                    .map_err(|_| CheckpointError::WitnessUnavailable)?;
                transaction
                    .commit()
                    .map_err(|_| CheckpointError::WitnessUnavailable)?;
                return Ok(receipt);
            }
            let expected_sequence = previous_sequence
                .checked_add(1)
                .ok_or(CheckpointError::SequenceConflict)?;
            if sequence <= previous_sequence {
                return Err(CheckpointError::SequenceConflict);
            }
            if sequence != expected_sequence {
                return Err(CheckpointError::SequenceGap);
            }
            if event_sequence <= previous_event {
                return Err(CheckpointError::SequenceRegression);
            }
            if checkpoint.payload.previous_checkpoint_sha256.as_deref()
                != Some(previous_digest.as_str())
            {
                return Err(CheckpointError::PredecessorMismatch);
            }
        } else if sequence != 1 || checkpoint.payload.previous_checkpoint_sha256.is_some() {
            return Err(CheckpointError::PredecessorMismatch);
        }

        let receipt = self.make_receipt(checkpoint, accepted_at)?;
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|_| CheckpointError::Malformed)?;
        transaction
            .execute(
                "INSERT INTO g11_witness_checkpoint_receipts
                 (stream_id, checkpoint_sequence, event_sequence, checkpoint_digest_sha256,
                  checkpoint_envelope, witness_receipt, accepted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    checkpoint.payload.stream_id,
                    sequence,
                    event_sequence,
                    digest,
                    envelope,
                    receipt_bytes,
                    accepted_at_i64
                ],
            )
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        transaction
            .commit()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        Ok(receipt)
    }

    fn latest(
        &self,
        stream_id: &str,
    ) -> Result<Option<(SignedCheckpoint, WitnessReceipt)>, CheckpointError> {
        if stream_id.trim().is_empty() {
            return Err(CheckpointError::Malformed);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        let stored = connection
            .query_row(
                "SELECT checkpoint_envelope, witness_receipt
                 FROM g11_witness_checkpoint_receipts
                 WHERE stream_id = ?1
                 ORDER BY checkpoint_sequence DESC LIMIT 1",
                params![stream_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        stored
            .map(|(checkpoint, receipt)| {
                let checkpoint = serde_json::from_slice(&checkpoint)
                    .map_err(|_| CheckpointError::WitnessUnavailable)?;
                let receipt = serde_json::from_slice(&receipt)
                    .map_err(|_| CheckpointError::WitnessUnavailable)?;
                Ok((checkpoint, receipt))
            })
            .transpose()
    }
}

#[cfg(unix)]
fn prepare_database_file(path: &Path) -> Result<(), CheckpointError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(CheckpointError::Malformed);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| CheckpointError::WitnessUnavailable)?;
            drop(file);
        }
        Err(_) => return Err(CheckpointError::WitnessUnavailable),
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_database_file(_path: &Path) -> Result<(), CheckpointError> {
    // Platform-specific ACL verification is required before using this backend.
    Err(CheckpointError::Malformed)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(H[(byte >> 4) as usize] as char);
        out.push(H[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_checkpoint, CheckpointSigner};
    use ed25519_dalek::{Signer, SigningKey};

    struct TestSigner {
        id: String,
        key: SigningKey,
    }

    impl CheckpointSigner for TestSigner {
        fn key_id(&self) -> &str {
            &self.id
        }

        fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, CheckpointError> {
            Ok(self.key.sign(bytes).to_bytes().to_vec())
        }
    }

    fn path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "iroka-g11-{label}-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    fn fixture() -> (
        Arc<TestSigner>,
        Arc<TestSigner>,
        BTreeMap<String, VerifyingKey>,
    ) {
        let checkpoint_signer = Arc::new(TestSigner {
            id: "checkpoint-root:test".into(),
            key: SigningKey::from_bytes(&[41; 32]),
        });
        let witness_signer = Arc::new(TestSigner {
            id: "witness-key:test".into(),
            key: SigningKey::from_bytes(&[92; 32]),
        });
        let roots = BTreeMap::from([(
            checkpoint_signer.id.clone(),
            checkpoint_signer.key.verifying_key(),
        )]);
        (checkpoint_signer, witness_signer, roots)
    }

    fn checkpoint(
        signer: &dyn CheckpointSigner,
        sequence: u64,
        event_sequence: u64,
        previous: Option<String>,
    ) -> SignedCheckpoint {
        create_checkpoint(
            signer,
            "audit-stream:durable-test",
            sequence,
            event_sequence,
            [sequence as u8 + 1; 32],
            previous,
            1_900 + sequence,
        )
        .unwrap()
    }

    #[test]
    fn durable_witness_persists_receipt_across_reopen_and_exact_retry() {
        let path = path("reopen");
        let (signer, witness_signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-a",
            witness_signer.clone(),
            witness_signer.key.verifying_key(),
            roots.clone(),
        )
        .unwrap();
        let first = checkpoint(signer.as_ref(), 1, 10, None);
        let receipt = witness.publish(&first).unwrap();
        assert_eq!(witness.publish(&first).unwrap(), receipt);
        drop(witness);

        let reopened = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-a",
            witness_signer.clone(),
            witness_signer.key.verifying_key(),
            roots.clone(),
        )
        .unwrap();
        let (stored, stored_receipt) = reopened
            .latest("audit-stream:durable-test")
            .unwrap()
            .unwrap();
        assert_eq!(stored, first);
        assert_eq!(stored_receipt, receipt);
        stored_receipt
            .verify(
                &stored,
                &roots,
                &BTreeMap::from([(
                    witness_signer.id.clone(),
                    witness_signer.key.verifying_key(),
                )]),
            )
            .unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn durable_witness_rejects_sequence_gaps_regressions_and_wrong_predecessors() {
        let path = path("monotonic");
        let (signer, witness_signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-b",
            witness_signer.clone(),
            witness_signer.key.verifying_key(),
            roots,
        )
        .unwrap();
        let first = checkpoint(signer.as_ref(), 1, 10, None);
        witness.publish(&first).unwrap();
        let gap = checkpoint(signer.as_ref(), 3, 12, Some(hex(&first.digest().unwrap())));
        assert_eq!(witness.publish(&gap), Err(CheckpointError::SequenceGap));
        let regression = checkpoint(signer.as_ref(), 2, 10, Some(hex(&first.digest().unwrap())));
        assert_eq!(
            witness.publish(&regression),
            Err(CheckpointError::SequenceRegression)
        );
        let wrong = checkpoint(signer.as_ref(), 2, 11, Some("00".repeat(32)));
        assert_eq!(
            witness.publish(&wrong),
            Err(CheckpointError::PredecessorMismatch)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[cfg(unix)]
    #[test]
    fn durable_witness_enforces_private_database_file_and_rejects_symlinks() {
        use std::os::unix::fs::PermissionsExt;

        let db_path = path("permissions");
        let (checkpoint_signer, witness_signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &db_path,
            "witness:permissions",
            witness_signer.clone(),
            witness_signer.key.verifying_key(),
            roots,
        )
        .unwrap();
        let mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(witness);

        let target = path("symlink-target");
        let link = path("symlink-link");
        std::fs::write(&target, b"not a witness database").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            prepare_database_file(&link),
            Err(CheckpointError::Malformed)
        );

        let reused_checkpoint_key = SqliteCheckpointWitness::open(
            &db_path,
            "witness:bad-key-reuse",
            checkpoint_signer.clone(),
            checkpoint_signer.key.verifying_key(),
            BTreeMap::from([(
                checkpoint_signer.id.clone(),
                checkpoint_signer.key.verifying_key(),
            )]),
        );
        assert!(matches!(reused_checkpoint_key, Err(CheckpointError::Malformed)));

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("sqlite-shm"));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn durable_witness_binds_database_to_one_identity_and_signing_key() {
        let path = path("identity");
        let (_signer, witness_signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-a",
            witness_signer.clone(),
            witness_signer.key.verifying_key(),
            roots.clone(),
        )
        .unwrap();
        drop(witness);

        let other_signer = Arc::new(TestSigner {
            id: "witness-key:operator-b".into(),
            key: SigningKey::from_bytes(&[42; 32]),
        });
        assert!(matches!(
            SqliteCheckpointWitness::open(
                &path,
                "witness:operator-b",
                other_signer.clone(),
                other_signer.key.verifying_key(),
                roots,
            ),
            Err(CheckpointError::Malformed)
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn durable_witness_rejects_conflicting_same_sequence_and_keeps_original() {
        let path = path("conflict");
        let (signer, witness_signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-c",
            witness_signer.clone(),
            witness_signer.key.verifying_key(),
            roots,
        )
        .unwrap();
        let first = checkpoint(signer.as_ref(), 1, 10, None);
        witness.publish(&first).unwrap();
        let conflicting = create_checkpoint(
            signer.as_ref(),
            "audit-stream:durable-test",
            1,
            10,
            [99; 32],
            None,
            1_901,
        )
        .unwrap();
        assert_eq!(
            witness.publish(&conflicting),
            Err(CheckpointError::SequenceConflict)
        );
        assert_eq!(
            witness
                .latest("audit-stream:durable-test")
                .unwrap()
                .unwrap()
                .0,
            first
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
