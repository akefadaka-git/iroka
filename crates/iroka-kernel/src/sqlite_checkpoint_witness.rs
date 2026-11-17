//! Durable SQLite reference backend for an independently operated G11 witness.
//!
//! This adapter provides transactional, append-only checkpoint acceptance and
//! signed receipts. It is not itself an independent operator or a network API;
//! each operator must run and administer its own isolated instance and keys.
use crate::{CheckpointError, CheckpointSigner, CheckpointWitness, SignedCheckpoint, WitnessReceipt, WitnessReceiptPayload};
use ed25519_dalek::VerifyingKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
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
        trusted_checkpoint_signers: BTreeMap<String, VerifyingKey>,
    ) -> Result<Self, CheckpointError> {
        let witness_id = witness_id.into();
        if witness_id.trim().is_empty()
            || signer.key_id().trim().is_empty()
            || trusted_checkpoint_signers.is_empty()
        {
            return Err(CheckpointError::Malformed);
        }
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

        if let Some((previous_sequence, previous_event, previous_digest, previous_envelope, previous_receipt)) = previous {
            if sequence == previous_sequence
                && digest == previous_digest
                && envelope == previous_envelope
            {
                let receipt = serde_json::from_slice(&previous_receipt)
                    .map_err(|_| CheckpointError::WitnessUnavailable)?;
                transaction.commit().map_err(|_| CheckpointError::WitnessUnavailable)?;
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
        let receipt_bytes =
            serde_json::to_vec(&receipt).map_err(|_| CheckpointError::Malformed)?;
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
        transaction.commit().map_err(|_| CheckpointError::WitnessUnavailable)?;
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

    fn fixture() -> (Arc<TestSigner>, BTreeMap<String, VerifyingKey>) {
        let signer = Arc::new(TestSigner {
            id: "checkpoint-root:test".into(),
            key: SigningKey::from_bytes(&[41; 32]),
        });
        let roots = BTreeMap::from([(signer.id.clone(), signer.key.verifying_key())]);
        (signer, roots)
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
        let (signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-a",
            signer.clone(),
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
            signer,
            roots,
        )
        .unwrap();
        let (stored, stored_receipt) = reopened
            .latest("audit-stream:durable-test")
            .unwrap()
            .unwrap();
        assert_eq!(stored, first);
        assert_eq!(stored_receipt, receipt);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn durable_witness_rejects_sequence_gaps_regressions_and_wrong_predecessors() {
        let path = path("monotonic");
        let (signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-b",
            signer.clone(),
            roots,
        )
        .unwrap();
        let first = checkpoint(signer.as_ref(), 1, 10, None);
        witness.publish(&first).unwrap();
        let gap = checkpoint(
            signer.as_ref(),
            3,
            12,
            Some(hex(&first.digest().unwrap())),
        );
        assert_eq!(witness.publish(&gap), Err(CheckpointError::SequenceGap));
        let regression = checkpoint(
            signer.as_ref(),
            2,
            10,
            Some(hex(&first.digest().unwrap())),
        );
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

    #[test]
    fn durable_witness_rejects_conflicting_same_sequence_and_keeps_original() {
        let path = path("conflict");
        let (signer, roots) = fixture();
        let witness = SqliteCheckpointWitness::open(
            &path,
            "witness:operator-c",
            signer.clone(),
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
            witness.latest("audit-stream:durable-test").unwrap().unwrap().0,
            first
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
