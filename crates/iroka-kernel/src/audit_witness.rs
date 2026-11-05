//! Witness acceptance state machine and in-memory test ledger.
//! MemoryWitnessLedger is NOT an independent production witness: it is a deterministic
//! adapter for protocol tests. Production must implement durable storage and separate custody.

use crate::audit_checkpoint::CheckpointPayload;
use crate::audit_signer::{CheckpointSignatureVerifier, SignedCheckpoint, SignerError};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};

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
    pub witnessed_at: u64,
    pub log_index: u64,
    pub signing_key_id: String,
    pub signature: [u8; 64],
}

impl WitnessReceipt {
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
pub struct LocalWitnessTestSigner {
    key_id: String,
    key: SigningKey,
}
impl LocalWitnessTestSigner {
    pub fn from_test_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self { key_id: key_id.into(), key: SigningKey::from_bytes(&seed) }
    }
}
impl WitnessReceiptSigner for LocalWitnessTestSigner {
    fn key_id(&self) -> &str { &self.key_id }
    fn sign_receipt(&self, receipt: &WitnessReceipt) -> Result<[u8; 64], WitnessError> {
        if receipt.signing_key_id != self.key_id { return Err(WitnessError::SigningUnavailable); }
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

#[derive(Default)]
pub struct MemoryWitnessLedger {
    witness_id: String,
    signer: Option<Box<dyn WitnessReceiptSigner>>,
    streams: Mutex<BTreeMap<String, Vec<WitnessReceipt>>>,
}

impl MemoryWitnessLedger {
    pub fn new(witness_id: impl Into<String>, signer: Box<dyn WitnessReceiptSigner>) -> Self {
        Self { witness_id: witness_id.into(), signer: Some(signer), streams: Mutex::new(BTreeMap::new()) }
    }
}

impl WitnessLedger for MemoryWitnessLedger {
    fn accept(
        &self,
        signed: &SignedCheckpoint,
        verifier: &dyn CheckpointSignatureVerifier,
        witnessed_at: u64,
    ) -> Result<WitnessReceipt, WitnessError> {
        verifier.verify_checkpoint(signed).map_err(|e| match e {
            SignerError::InvalidSignature | SignerError::UnknownKey => WitnessError::InvalidSignature,
            _ => WitnessError::InvalidCheckpoint,
        })?;
        let payload: &CheckpointPayload = &signed.payload;
        payload.validate().map_err(|_| WitnessError::InvalidCheckpoint)?;
        let digest = payload.digest().map_err(|_| WitnessError::InvalidCheckpoint)?;
        let mut streams = self.streams.lock().map_err(|_| WitnessError::StorageUnavailable)?;
        let history = streams.entry(payload.stream_id.clone()).or_default();

        if let Some(existing) = history.iter().find(|r| r.checkpoint_number == payload.checkpoint_number) {
            if existing.checkpoint_digest == digest { return Ok(existing.clone()); }
            return Err(WitnessError::Equivocation);
        }
        let (expected_number, expected_previous, previous_sequence) = match history.last() {
            None => (1, [0; 32], 0),
            Some(last) => (last.checkpoint_number + 1, last.checkpoint_digest, last.last_sequence),
        };
        if payload.checkpoint_number != expected_number { return Err(WitnessError::CheckpointGap); }
        if payload.previous_checkpoint_digest != expected_previous { return Err(WitnessError::PreviousDigestMismatch); }
        if payload.last_sequence <= previous_sequence { return Err(WitnessError::SequenceConflict); }

        let signer = self.signer.as_ref().ok_or(WitnessError::SigningUnavailable)?;
        let mut receipt = WitnessReceipt {
            witness_id: self.witness_id.clone(),
            stream_id: payload.stream_id.clone(),
            checkpoint_number: payload.checkpoint_number,
            checkpoint_digest: digest,
            last_sequence: payload.last_sequence,
            head_event_hash: payload.head_event_hash,
            previous_checkpoint_digest: payload.previous_checkpoint_digest,
            witnessed_at,
            log_index: history.len() as u64 + 1,
            signing_key_id: signer.key_id().to_string(),
            signature: [0; 64],
        };
        receipt.signature = signer.sign_receipt(&receipt)?;
        history.push(receipt.clone());
        Ok(receipt)
    }

    fn head(&self, stream_id: &str) -> Result<Option<WitnessReceipt>, WitnessError> {
        let streams = self.streams.lock().map_err(|_| WitnessError::StorageUnavailable)?;
        Ok(streams.get(stream_id).and_then(|v| v.last()).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_checkpoint::{AuditHead, CheckpointBuilder, V1_CHAIN_FORMAT};
    use crate::audit_signer::{CheckpointSigner, Ed25519CheckpointVerifier, LocalEd25519TestSigner};

    #[test]
    fn witness_accepts_once_and_returns_same_receipt_for_retry() {
        let signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let verifier = Ed25519CheckpointVerifier::new(vec![("cp-key".into(), signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:one", "cp-key");
        let head = AuditHead { first_sequence: 1, last_sequence: 2, event_count: 2,
            head_event_hash: [2; 32], chain_format: V1_CHAIN_FORMAT.into() };
        let cp = signer.sign_checkpoint(&builder.initial_v1_anchor(&head, 10).unwrap()).unwrap();
        let ledger = MemoryWitnessLedger::new("witness-a", Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [3; 32])));
        let first = ledger.accept(&cp, &verifier, 11).unwrap();
        let retry = ledger.accept(&cp, &verifier, 12).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.log_index, 1);
    }

    #[test]
    fn witness_rejects_conflicting_checkpoint_at_same_position() {
        let signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let verifier = Ed25519CheckpointVerifier::new(vec![("cp-key".into(), signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:one", "cp-key");
        let mk = |hash| {
            let head = AuditHead { first_sequence: 1, last_sequence: 2, event_count: 2,
                head_event_hash: [hash; 32], chain_format: V1_CHAIN_FORMAT.into() };
            signer.sign_checkpoint(&builder.initial_v1_anchor(&head, 10).unwrap()).unwrap()
        };
        let ledger = MemoryWitnessLedger::new("witness-a", Box::new(LocalWitnessTestSigner::from_test_seed("w-key", [3; 32])));
        ledger.accept(&mk(2), &verifier, 11).unwrap();
        assert_eq!(ledger.accept(&mk(4), &verifier, 12), Err(WitnessError::Equivocation));
    }
}
