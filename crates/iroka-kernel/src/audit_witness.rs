//! Witness acceptance state machine and in-memory test ledger.
//! MemoryWitnessLedger is NOT an independent production witness: it is a deterministic
//! adapter for protocol tests. Production must implement durable storage and separate custody.

use crate::audit_checkpoint::CheckpointPayload;
use crate::audit_signer::{CheckpointSignatureVerifier, SignedCheckpoint, SignerError};
#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex, time::Duration};
#[cfg(test)]
use std::{collections::BTreeMap};

const RECEIPT_DOMAIN: &[u8] = b"IROKA:G11:AUDIT-WITNESS-RECEIPT:V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    InvalidCheckpoint,
    InvalidSignature,
    SequenceConflict,
    CheckpointGap,
    PreviousDigestMismatch,
    Equivocation,
    StorageUnavailable,
    SigningUnavailable,
    ClockAnomaly,
    WrongStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessReceipt {
    pub witness_id: String,
    pub stream_id: String,
    pub checkpoint_number: u64,
    pub checkpoint_digest: [u8; 32],
    pub last_sequence: u64,
    pub head_event_hash: [u8; 32],
    pub previous_checkpoint_digest: [u8; 32],
    pub previous_receipt_digest: [u8; 32],
    pub witnessed_at: u64,
    pub log_index: u64,
    pub signing_key_id: String,
    pub signature: [u8; 64],
}

impl WitnessReceipt {
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"IROKA:G11:WITNESS-RECEIPT-DIGEST:V1\0");
        h.update(self.signing_bytes());
        h.update(self.signature);
        h.finalize().into()
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(RECEIPT_DOMAIN);
        put(&mut out, self.witness_id.as_bytes());
        put(&mut out, self.stream_id.as_bytes());
        out.extend_from_slice(&self.checkpoint_number.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_digest);
        out.extend_from_slice(&self.last_sequence.to_be_bytes());
        out.extend_from_slice(&self.head_event_hash);
        out.extend_from_slice(&self.previous_checkpoint_digest);
        out.extend_from_slice(&self.previous_receipt_digest);
        out.extend_from_slice(&self.witnessed_at.to_be_bytes());
        out.extend_from_slice(&self.log_index.to_be_bytes());
        put(&mut out, self.signing_key_id.as_bytes());
        out
    }
}

fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

pub trait WitnessReceiptSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign_receipt(&self, receipt: &WitnessReceipt) -> Result<[u8; 64], WitnessError>;
}

/// Local witness receipt signer for tests only; production keys must be independently held.
#[cfg(test)]
pub struct LocalWitnessTestSigner {
    key_id: String,
    key: SigningKey,
}
#[cfg(test)]
impl LocalWitnessTestSigner {
    pub fn from_test_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn key_for_test(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}
#[cfg(test)]
impl WitnessReceiptSigner for LocalWitnessTestSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign_receipt(&self, receipt: &WitnessReceipt) -> Result<[u8; 64], WitnessError> {
        if receipt.signing_key_id != self.key_id {
            return Err(WitnessError::SigningUnavailable);
        }
        Ok(self.key.sign(&receipt.signing_bytes()).to_bytes())
    }
}

pub trait WitnessLedger: Send + Sync {
    fn accept(
        &self,
        signed: &SignedCheckpoint,
        verifier: &dyn CheckpointSignatureVerifier,
        witnessed_at: u64,
    ) -> Result<WitnessReceipt, WitnessError>;
    fn head(&self, stream_id: &str) -> Result<Option<WitnessReceipt>, WitnessError>;
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryWitnessLedger {
    witness_id: String,
    signer: Option<Box<dyn WitnessReceiptSigner>>,
    streams: Mutex<BTreeMap<String, Vec<WitnessReceipt>>>,
}

#[cfg(test)]
impl MemoryWitnessLedger {
    pub fn new(witness_id: impl Into<String>, signer: Box<dyn WitnessReceiptSigner>) -> Self {
        Self {
            witness_id: witness_id.into(),
            signer: Some(signer),
            streams: Mutex::new(BTreeMap::new()),
        }
    }
}

#[cfg(test)]
impl WitnessLedger for MemoryWitnessLedger {
    fn accept(
        &self,
        signed: &SignedCheckpoint,
        verifier: &dyn CheckpointSignatureVerifier,
        witnessed_at: u64,
    ) -> Result<WitnessReceipt, WitnessError> {
        verifier.verify_checkpoint(signed).map_err(|e| match e {
            SignerError::InvalidSignature | SignerError::UnknownKey => {
                WitnessError::InvalidSignature
            }
            _ => WitnessError::InvalidCheckpoint,
        })?;
        let payload: &CheckpointPayload = &signed.payload;
        payload
            .validate()
            .map_err(|_| WitnessError::InvalidCheckpoint)?;
        let digest = payload
            .digest()
            .map_err(|_| WitnessError::InvalidCheckpoint)?;
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| WitnessError::StorageUnavailable)?;
        let history = streams.entry(payload.stream_id.clone()).or_default();

        if let Some(existing) = history
            .iter()
            .find(|r| r.checkpoint_number == payload.checkpoint_number)
        {
            if existing.checkpoint_digest == digest {
                return Ok(existing.clone());
            }
            return Err(WitnessError::Equivocation);
        }
        let (expected_number, expected_previous, previous_sequence) = match history.last() {
            None => (1, [0; 32], 0),
            Some(last) => (
                last.checkpoint_number.checked_add(1).ok_or(WitnessError::CheckpointGap)?,
                last.checkpoint_digest,
                last.last_sequence,
            ),
        };
        if payload.checkpoint_number != expected_number {
            return Err(WitnessError::CheckpointGap);
        }
        if payload.previous_checkpoint_digest != expected_previous {
            return Err(WitnessError::PreviousDigestMismatch);
        }
        if payload.last_sequence <= previous_sequence {
            return Err(WitnessError::SequenceConflict);
        }
        if history
            .last()
            .map(|last| witnessed_at < last.witnessed_at)
            .unwrap_or(false)
        {
            return Err(WitnessError::ClockAnomaly);
        }

        let signer = self
            .signer
            .as_ref()
            .ok_or(WitnessError::SigningUnavailable)?;
        let mut receipt = WitnessReceipt {
            witness_id: self.witness_id.clone(),
            stream_id: payload.stream_id.clone(),
            checkpoint_number: payload.checkpoint_number,
            checkpoint_digest: digest,
            last_sequence: payload.last_sequence,
            head_event_hash: payload.head_event_hash,
            previous_checkpoint_digest: payload.previous_checkpoint_digest,
            previous_receipt_digest: history
                .last()
                .map(WitnessReceipt::digest)
                .unwrap_or([0; 32]),
            witnessed_at,
            log_index: u64::try_from(history.len())
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(WitnessError::CheckpointGap)?,
            signing_key_id: signer.key_id().to_string(),
            signature: [0; 64],
        };
        receipt.signature = signer.sign_receipt(&receipt)?;
        history.push(receipt.clone());
        Ok(receipt)
    }

    fn head(&self, stream_id: &str) -> Result<Option<WitnessReceipt>, WitnessError> {
        let streams = self
            .streams
            .lock()
            .map_err(|_| WitnessError::StorageUnavailable)?;
        Ok(streams.get(stream_id).and_then(|v| v.last()).cloned())
    }
}

type ReceiptRow = (
    String,
    String,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    String,
    Vec<u8>,
);

fn decode_receipt(row: ReceiptRow) -> Result<WitnessReceipt, WitnessError> {
    let fixed32 = |v: Vec<u8>| -> Result<[u8; 32], WitnessError> {
        v.try_into().map_err(|_| WitnessError::StorageUnavailable)
    };
    let signature: [u8; 64] = row
        .11
        .try_into()
        .map_err(|_| WitnessError::StorageUnavailable)?;
    Ok(WitnessReceipt {
        witness_id: row.0,
        stream_id: row.1,
        checkpoint_number: u64::try_from(row.2).map_err(|_| WitnessError::StorageUnavailable)?,
        checkpoint_digest: fixed32(row.3)?,
        last_sequence: u64::try_from(row.4).map_err(|_| WitnessError::StorageUnavailable)?,
        head_event_hash: fixed32(row.5)?,
        previous_checkpoint_digest: fixed32(row.6)?,
        previous_receipt_digest: fixed32(row.7)?,
        witnessed_at: u64::try_from(row.8).map_err(|_| WitnessError::StorageUnavailable)?,
        log_index: u64::try_from(row.9).map_err(|_| WitnessError::StorageUnavailable)?,
        signing_key_id: row.10,
        signature,
    })
}

fn read_receipt(row: &Row<'_>) -> rusqlite::Result<ReceiptRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    ))
}

/// Durable witness ledger adapter. It is independent only when deployed with
/// separate administration, storage, credentials, backups and receipt-key custody.
pub struct SqliteWitnessLedger {
    witness_id: String,
    stream_id: String,
    signer: Box<dyn WitnessReceiptSigner>,
    connection: Mutex<Connection>,
}

impl SqliteWitnessLedger {
    pub fn open(
        path: impl AsRef<Path>,
        witness_id: impl Into<String>,
        stream_id: impl Into<String>,
        signer: Box<dyn WitnessReceiptSigner>,
    ) -> Result<Self, WitnessError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::{
                fs::{symlink_metadata, OpenOptions},
                os::unix::fs::{OpenOptionsExt, PermissionsExt},
            };
            match symlink_metadata(path) {
                Ok(m) if m.file_type().is_symlink() || m.permissions().mode() & 0o077 != 0 => {
                    return Err(WitnessError::StorageUnavailable);
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .map_err(|_| WitnessError::StorageUnavailable)?;
                }
                Err(_) => return Err(WitnessError::StorageUnavailable),
            }
        }
        let connection = Connection::open(path).map_err(|_| WitnessError::StorageUnavailable)?;
        Self::from_connection(connection, witness_id.into(), stream_id.into(), signer)
    }

    fn from_connection(
        connection: Connection,
        witness_id: String,
        stream_id: String,
        signer: Box<dyn WitnessReceiptSigner>,
    ) -> Result<Self, WitnessError> {
        if witness_id.trim().is_empty()
            || stream_id.trim().is_empty()
            || signer.key_id().trim().is_empty()
        {
            return Err(WitnessError::InvalidCheckpoint);
        }
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| WitnessError::StorageUnavailable)?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS witness_receipts(
               witness_id TEXT NOT NULL, stream_id TEXT NOT NULL,
               checkpoint_number INTEGER NOT NULL, checkpoint_digest BLOB NOT NULL CHECK(length(checkpoint_digest)=32),
               last_sequence INTEGER NOT NULL, head_event_hash BLOB NOT NULL CHECK(length(head_event_hash)=32),
               previous_checkpoint_digest BLOB NOT NULL CHECK(length(previous_checkpoint_digest)=32),
               previous_receipt_digest BLOB NOT NULL CHECK(length(previous_receipt_digest)=32),
               witnessed_at INTEGER NOT NULL, log_index INTEGER NOT NULL,
               signing_key_id TEXT NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
               PRIMARY KEY(stream_id, checkpoint_number), UNIQUE(stream_id, log_index));
             CREATE TRIGGER IF NOT EXISTS witness_no_update BEFORE UPDATE ON witness_receipts
               BEGIN SELECT RAISE(ABORT,'append-only witness ledger'); END;
             CREATE TRIGGER IF NOT EXISTS witness_no_delete BEFORE DELETE ON witness_receipts
               BEGIN SELECT RAISE(ABORT,'append-only witness ledger'); END;"
        ).map_err(|_| WitnessError::StorageUnavailable)?;
        let conflicting_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM witness_receipts
                 WHERE witness_id != ?1 OR stream_id != ?2",
                params![witness_id, stream_id],
                |row| row.get(0),
            )
            .map_err(|_| WitnessError::StorageUnavailable)?;
        if conflicting_rows != 0 {
            return Err(WitnessError::InvalidCheckpoint);
        }
        Ok(Self {
            witness_id,
            stream_id,
            signer,
            connection: Mutex::new(connection),
        })
    }

    fn select_receipt(
        connection: &Connection,
        sql: &str,
        stream_id: &str,
        checkpoint_number: Option<i64>,
    ) -> Result<Option<WitnessReceipt>, WitnessError> {
        let mut statement = connection
            .prepare(sql)
            .map_err(|_| WitnessError::StorageUnavailable)?;
        let raw = match checkpoint_number {
            Some(number) => statement
                .query_row(params![stream_id, number], read_receipt)
                .optional(),
            None => statement
                .query_row(params![stream_id], read_receipt)
                .optional(),
        }
        .map_err(|_| WitnessError::StorageUnavailable)?;
        raw.map(decode_receipt).transpose()
    }
}

impl WitnessLedger for SqliteWitnessLedger {
    fn accept(
        &self,
        signed: &SignedCheckpoint,
        verifier: &dyn CheckpointSignatureVerifier,
        witnessed_at: u64,
    ) -> Result<WitnessReceipt, WitnessError> {
        verifier
            .verify_checkpoint(signed)
            .map_err(|_| WitnessError::InvalidSignature)?;
        let payload = &signed.payload;
        payload
            .validate()
            .map_err(|_| WitnessError::InvalidCheckpoint)?;
        if payload.stream_id != self.stream_id {
            return Err(WitnessError::WrongStream);
        }
        let digest = payload
            .digest()
            .map_err(|_| WitnessError::InvalidCheckpoint)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| WitnessError::StorageUnavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| WitnessError::StorageUnavailable)?;
        let number = i64::try_from(payload.checkpoint_number)
            .map_err(|_| WitnessError::InvalidCheckpoint)?;
        let existing = Self::select_receipt(
            &tx,
            "SELECT witness_id,stream_id,checkpoint_number,checkpoint_digest,last_sequence,
             head_event_hash,previous_checkpoint_digest,previous_receipt_digest,witnessed_at,
             log_index,signing_key_id,signature FROM witness_receipts
             WHERE stream_id=?1 AND checkpoint_number=?2",
            &payload.stream_id,
            Some(number),
        )?;
        if let Some(receipt) = existing {
            if receipt.checkpoint_digest == digest {
                return Ok(receipt);
            }
            return Err(WitnessError::Equivocation);
        }
        let previous = Self::select_receipt(
            &tx,
            "SELECT witness_id,stream_id,checkpoint_number,checkpoint_digest,last_sequence,
             head_event_hash,previous_checkpoint_digest,previous_receipt_digest,witnessed_at,
             log_index,signing_key_id,signature FROM witness_receipts
             WHERE stream_id=?1 ORDER BY log_index DESC LIMIT 1",
            &payload.stream_id,
            None,
        )?;
        let (
            expected_number,
            previous_digest,
            previous_sequence,
            previous_receipt_digest,
            previous_time,
            next_index,
        ) = match previous {
            None => (1, [0; 32], 0, [0; 32], 0, 1),
            Some(last) => (
                last.checkpoint_number.checked_add(1).ok_or(WitnessError::CheckpointGap)?,
                last.checkpoint_digest,
                last.last_sequence,
                last.digest(),
                last.witnessed_at,
                last.log_index.checked_add(1).ok_or(WitnessError::CheckpointGap)?,
            ),
        };
        if payload.checkpoint_number != expected_number {
            return Err(WitnessError::CheckpointGap);
        }
        if payload.previous_checkpoint_digest != previous_digest {
            return Err(WitnessError::PreviousDigestMismatch);
        }
        if payload.last_sequence <= previous_sequence {
            return Err(WitnessError::SequenceConflict);
        }
        if witnessed_at < previous_time {
            return Err(WitnessError::ClockAnomaly);
        }
        let mut receipt = WitnessReceipt {
            witness_id: self.witness_id.clone(),
            stream_id: payload.stream_id.clone(),
            checkpoint_number: payload.checkpoint_number,
            checkpoint_digest: digest,
            last_sequence: payload.last_sequence,
            head_event_hash: payload.head_event_hash,
            previous_checkpoint_digest: payload.previous_checkpoint_digest,
            previous_receipt_digest,
            witnessed_at,
            log_index: next_index,
            signing_key_id: self.signer.key_id().to_string(),
            signature: [0; 64],
        };
        receipt.signature = self.signer.sign_receipt(&receipt)?;
        tx.execute(
            "INSERT INTO witness_receipts(witness_id,stream_id,checkpoint_number,checkpoint_digest,
             last_sequence,head_event_hash,previous_checkpoint_digest,previous_receipt_digest,
             witnessed_at,log_index,signing_key_id,signature)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                receipt.witness_id,
                receipt.stream_id,
                number,
                receipt.checkpoint_digest.as_slice(),
                i64::try_from(receipt.last_sequence)
                    .map_err(|_| WitnessError::InvalidCheckpoint)?,
                receipt.head_event_hash.as_slice(),
                receipt.previous_checkpoint_digest.as_slice(),
                receipt.previous_receipt_digest.as_slice(),
                i64::try_from(receipt.witnessed_at).map_err(|_| WitnessError::InvalidCheckpoint)?,
                i64::try_from(receipt.log_index).map_err(|_| WitnessError::InvalidCheckpoint)?,
                receipt.signing_key_id,
                receipt.signature.as_slice()
            ],
        )
        .map_err(|_| WitnessError::StorageUnavailable)?;
        tx.commit().map_err(|_| WitnessError::StorageUnavailable)?;
        Ok(receipt)
    }

    fn head(&self, stream_id: &str) -> Result<Option<WitnessReceipt>, WitnessError> {
        if stream_id != self.stream_id {
            return Err(WitnessError::WrongStream);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| WitnessError::StorageUnavailable)?;
        Self::select_receipt(
            &connection,
            "SELECT witness_id,stream_id,checkpoint_number,checkpoint_digest,last_sequence,
             head_event_hash,previous_checkpoint_digest,previous_receipt_digest,witnessed_at,
             log_index,signing_key_id,signature FROM witness_receipts
             WHERE stream_id=?1 ORDER BY log_index DESC LIMIT 1",
            stream_id,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_digest_uses_the_canonical_nul_terminated_domain() {
        let receipt = WitnessReceipt {
            witness_id: "witness-1".into(),
            stream_id: "stream-1".into(),
            checkpoint_number: 1,
            checkpoint_digest: [1; 32],
            last_sequence: 7,
            head_event_hash: [2; 32],
            previous_checkpoint_digest: [0; 32],
            previous_receipt_digest: [0; 32],
            witnessed_at: 100,
            log_index: 1,
            signing_key_id: "wkey-1".into(),
            signature: [3; 64],
        };
        assert_eq!(
            receipt.digest(),
            [
                0x69, 0x35, 0x03, 0xa7, 0x7b, 0xce, 0xc3, 0xcb,
                0x6d, 0xd6, 0xa4, 0xe4, 0xed, 0x89, 0x6b, 0x4b,
                0xda, 0x76, 0xeb, 0xa3, 0x8f, 0x6a, 0xc7, 0x00,
                0xca, 0x77, 0xa4, 0xb1, 0xdb, 0xe9, 0xf1, 0x69,
            ]
        );
    }
    use crate::audit_checkpoint::{AuditHead, CheckpointBuilder, V1_CHAIN_FORMAT};
    use crate::audit_signer::{
        CheckpointSigner, Ed25519CheckpointVerifier, LocalEd25519TestSigner,
    };

    #[test]
    fn witness_accepts_once_and_returns_same_receipt_for_retry() {
        let signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let verifier =
            Ed25519CheckpointVerifier::new(vec![("cp-key".into(), signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:one", "cp-key");
        let head = AuditHead {
            first_sequence: 1,
            last_sequence: 2,
            event_count: 2,
            head_event_hash: [2; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let cp = signer
            .sign_checkpoint(&builder.initial_v1_anchor(&head, 10).unwrap())
            .unwrap();
        let ledger = MemoryWitnessLedger::new(
            "witness-a",
            Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [3; 32])),
        );
        let first = ledger.accept(&cp, &verifier, 11).unwrap();
        let retry = ledger.accept(&cp, &verifier, 12).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.log_index, 1);
    }

    #[test]
    fn witness_rejects_conflicting_checkpoint_at_same_position() {
        let signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let verifier =
            Ed25519CheckpointVerifier::new(vec![("cp-key".into(), signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:one", "cp-key");
        let mk = |hash| {
            let head = AuditHead {
                first_sequence: 1,
                last_sequence: 2,
                event_count: 2,
                head_event_hash: [hash; 32],
                chain_format: V1_CHAIN_FORMAT.into(),
            };
            signer
                .sign_checkpoint(&builder.initial_v1_anchor(&head, 10).unwrap())
                .unwrap()
        };
        let ledger = MemoryWitnessLedger::new(
            "witness-a",
            Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [3; 32])),
        );
        ledger.accept(&mk(2), &verifier, 11).unwrap();
        assert_eq!(
            ledger.accept(&mk(4), &verifier, 12),
            Err(WitnessError::Equivocation)
        );
    }
    #[test]
    fn sqlite_witness_ledger_is_bound_to_one_provisioned_stream() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iroka-witness-stream-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let signer = LocalEd25519TestSigner::from_test_seed("cp-key", [21; 32]);
        let verifier =
            Ed25519CheckpointVerifier::new(vec![("cp-key".into(), signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:other", "cp-key");
        let head = AuditHead {
            first_sequence: 1,
            last_sequence: 1,
            event_count: 1,
            head_event_hash: [22; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let signed = signer
            .sign_checkpoint(&builder.initial_v1_anchor(&head, 10).unwrap())
            .unwrap();
        let ledger = SqliteWitnessLedger::open(
            &path,
            "witness-bound",
            "stream:provisioned",
            Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [23; 32])),
        )
        .unwrap();
        assert_eq!(
            ledger.accept(&signed, &verifier, 11),
            Err(WitnessError::WrongStream)
        );
        assert_eq!(
            ledger.head("stream:other"),
            Err(WitnessError::WrongStream)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn sqlite_witness_ledger_survives_reopen_and_replays_same_receipt() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iroka-witness-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let checkpoint_signer = LocalEd25519TestSigner::from_test_seed("cp-key", [11; 32]);
        let verifier = Ed25519CheckpointVerifier::new(vec![(
            "cp-key".into(),
            checkpoint_signer.verifying_key(),
        )]);
        let builder = CheckpointBuilder::new("stream:durable", "cp-key");
        let head = AuditHead {
            first_sequence: 1,
            last_sequence: 1,
            event_count: 1,
            head_event_hash: [6; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let signed = checkpoint_signer
            .sign_checkpoint(&builder.initial_v1_anchor(&head, 10).unwrap())
            .unwrap();

        let first = {
            let ledger = SqliteWitnessLedger::open(
                &path,
                "witness-durable",
                "stream:durable",
                Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [12; 32])),
            )
            .unwrap();
            ledger.accept(&signed, &verifier, 11).unwrap()
        };
        {
            let ledger = SqliteWitnessLedger::open(
                &path,
                "witness-durable",
                "stream:durable",
                Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [12; 32])),
            )
            .unwrap();
            assert_eq!(ledger.accept(&signed, &verifier, 12), Ok(first.clone()));
            assert_eq!(ledger.head("stream:durable").unwrap(), Some(first));
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
