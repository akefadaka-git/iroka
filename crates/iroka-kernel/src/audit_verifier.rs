//! Offline checkpoint, receipt-quorum and local rollback verification.

use crate::audit_checkpoint::{AuditHead, CheckpointPayload};
use crate::audit_signer::{CheckpointSignatureVerifier, SignedCheckpoint, SignerError};
use crate::audit_witness::WitnessReceipt;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidCheckpoint,
    InvalidCheckpointSignature,
    InvalidReceiptSignature,
    WrongStream,
    ReceiptCheckpointMismatch,
    DuplicateWitness,
    InsufficientQuorum,
    RollbackOrTampering,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalReconciliation {
    MatchesCheckpoint,
    LocalAheadOfCheckpoint,
}

pub struct WitnessReceiptVerifier {
    trusted_keys: Vec<(String, VerifyingKey)>,
}

impl WitnessReceiptVerifier {
    pub fn new(trusted_keys: Vec<(String, VerifyingKey)>) -> Self { Self { trusted_keys } }

    pub fn verify(&self, receipt: &WitnessReceipt) -> Result<(), VerificationError> {
        let key = self.trusted_keys.iter()
            .find(|(id, _)| id == &receipt.signing_key_id)
            .map(|(_, key)| key)
            .ok_or(VerificationError::InvalidReceiptSignature)?;
        key.verify(&receipt.signing_bytes(), &Signature::from_bytes(&receipt.signature))
            .map_err(|_| VerificationError::InvalidReceiptSignature)
    }
}

pub fn verify_checkpoint_and_quorum(
    signed: &SignedCheckpoint,
    checkpoint_verifier: &dyn CheckpointSignatureVerifier,
    receipts: &[WitnessReceipt],
    receipt_verifier: &WitnessReceiptVerifier,
    required_quorum: usize,
) -> Result<(), VerificationError> {
    let payload: &CheckpointPayload = &signed.payload;
    payload.validate().map_err(|_| VerificationError::InvalidCheckpoint)?;
    checkpoint_verifier.verify_checkpoint(signed).map_err(|e| match e {
        SignerError::InvalidSignature | SignerError::UnknownKey => VerificationError::InvalidCheckpointSignature,
        _ => VerificationError::InvalidCheckpoint,
    })?;
    if required_quorum == 0 { return Err(VerificationError::InsufficientQuorum); }
    let digest = payload.digest().map_err(|_| VerificationError::InvalidCheckpoint)?;
    let mut witnesses = BTreeSet::new();
    for receipt in receipts {
        receipt_verifier.verify(receipt)?;
        if receipt.stream_id != payload.stream_id { return Err(VerificationError::WrongStream); }
        if receipt.checkpoint_number != payload.checkpoint_number
            || receipt.checkpoint_digest != digest
            || receipt.last_sequence != payload.last_sequence
            || receipt.head_event_hash != payload.head_event_hash
            || receipt.previous_checkpoint_digest != payload.previous_checkpoint_digest
        {
            return Err(VerificationError::ReceiptCheckpointMismatch);
        }
        if !witnesses.insert(receipt.witness_id.clone()) {
            return Err(VerificationError::DuplicateWitness);
        }
    }
    if witnesses.len() < required_quorum { return Err(VerificationError::InsufficientQuorum); }
    Ok(())
}

pub fn reconcile_local_head(
    local: &AuditHead,
    accepted: &CheckpointPayload,
) -> Result<LocalReconciliation, VerificationError> {
    if local.last_sequence < accepted.last_sequence {
        return Err(VerificationError::RollbackOrTampering);
    }
    if local.last_sequence == accepted.last_sequence {
        if local.head_event_hash != accepted.head_event_hash {
            return Err(VerificationError::RollbackOrTampering);
        }
        return Ok(LocalReconciliation::MatchesCheckpoint);
    }
    Ok(LocalReconciliation::LocalAheadOfCheckpoint)
}

/// Verifies a single witness's exported receipt history from its genesis receipt.
pub fn verify_receipt_chain(
    receipts: &[WitnessReceipt],
    verifier: &WitnessReceiptVerifier,
) -> Result<(), VerificationError> {
    let Some(first) = receipts.first() else { return Ok(()); };
    let witness_id = first.witness_id.as_str();
    let mut previous_digest = [0; 32];
    let mut expected_index = 1u64;
    for receipt in receipts {
        verifier.verify(receipt)?;
        if receipt.witness_id != witness_id || receipt.log_index != expected_index
            || receipt.previous_receipt_digest != previous_digest
        {
            return Err(VerificationError::ReceiptCheckpointMismatch);
        }
        previous_digest = receipt.digest();
        expected_index = expected_index.checked_add(1)
            .ok_or(VerificationError::ReceiptCheckpointMismatch)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_checkpoint::{CheckpointBuilder, V1_CHAIN_FORMAT};
    use crate::audit_signer::{CheckpointSigner, Ed25519CheckpointVerifier, LocalEd25519TestSigner};
    use crate::audit_witness::{LocalWitnessTestSigner, MemoryWitnessLedger, WitnessLedger};

    #[test]
    fn two_distinct_signed_witness_receipts_satisfy_quorum() {
        let checkpoint_signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let cp_verifier = Ed25519CheckpointVerifier::new(vec![("cp-key".into(), checkpoint_signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:q", "cp-key");
        let head = AuditHead { first_sequence: 1, last_sequence: 1, event_count: 1,
            head_event_hash: [8; 32], chain_format: V1_CHAIN_FORMAT.into() };
        let signed = checkpoint_signer.sign_checkpoint(&builder.initial_v1_anchor(&head, 1).unwrap()).unwrap();
        let w1 = LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]);
        let w2 = LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32]);
        let ledger1 = MemoryWitnessLedger::new("w1", Box::new(w1));
        let ledger2 = MemoryWitnessLedger::new("w2", Box::new(w2));
        let r1 = ledger1.accept(&signed, &cp_verifier, 2).unwrap();
        let r2 = ledger2.accept(&signed, &cp_verifier, 2).unwrap();
        let receipt_verifier = WitnessReceiptVerifier::new(vec![
            ("w1-key".into(), LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]).key_for_test()),
            ("w2-key".into(), LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32]).key_for_test()),
        ]);
        assert_eq!(verify_checkpoint_and_quorum(&signed, &cp_verifier, &[r1, r2], &receipt_verifier, 2), Ok(()));
    }

    #[test]
    fn detects_local_rollback_below_external_high_water_mark() {
        let builder = CheckpointBuilder::new("stream:q", "cp-key");
        let cp = builder.initial_v1_anchor(&AuditHead { first_sequence: 1, last_sequence: 5,
            event_count: 5, head_event_hash: [8; 32], chain_format: V1_CHAIN_FORMAT.into() }, 1).unwrap();
        let local = AuditHead { first_sequence: 1, last_sequence: 4, event_count: 4,
            head_event_hash: [7; 32], chain_format: V1_CHAIN_FORMAT.into() };
        assert_eq!(reconcile_local_head(&local, &cp), Err(VerificationError::RollbackOrTampering));
    }
}
