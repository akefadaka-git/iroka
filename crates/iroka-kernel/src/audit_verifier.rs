//! Offline checkpoint, receipt-quorum and local rollback verification.

use crate::audit_checkpoint::{AuditHead, CheckpointPayload};
use crate::audit_signer::{CheckpointSignatureVerifier, SignedCheckpoint, SignerError};
use crate::audit_witness::WitnessReceipt;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
    trusted_keys: Vec<(String, String, VerifyingKey)>,
}

impl WitnessReceiptVerifier {
    pub fn new(trusted_keys: Vec<(String, String, VerifyingKey)>) -> Self {
        Self { trusted_keys }
    }

    pub fn verify(&self, receipt: &WitnessReceipt) -> Result<(), VerificationError> {
        let key = self
            .trusted_keys
            .iter()
            .find(|(id, witness_id, _)| {
                id == &receipt.signing_key_id && witness_id == &receipt.witness_id
            })
            .map(|(_, _, key)| key)
            .ok_or(VerificationError::InvalidReceiptSignature)?;
        key.verify(
            &receipt.signing_bytes(),
            &Signature::from_bytes(&receipt.signature),
        )
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
    payload
        .validate()
        .map_err(|_| VerificationError::InvalidCheckpoint)?;
    checkpoint_verifier
        .verify_checkpoint(signed)
        .map_err(|e| match e {
            SignerError::InvalidSignature | SignerError::UnknownKey => {
                VerificationError::InvalidCheckpointSignature
            }
            _ => VerificationError::InvalidCheckpoint,
        })?;
    if required_quorum == 0 {
        return Err(VerificationError::InsufficientQuorum);
    }
    let digest = payload
        .digest()
        .map_err(|_| VerificationError::InvalidCheckpoint)?;
    let mut witnesses = BTreeSet::new();
    for receipt in receipts {
        receipt_verifier.verify(receipt)?;
        if receipt.stream_id != payload.stream_id {
            return Err(VerificationError::WrongStream);
        }
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
    if witnesses.len() < required_quorum {
        return Err(VerificationError::InsufficientQuorum);
    }
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
    let Some(first) = receipts.first() else {
        return Ok(());
    };
    let witness_id = first.witness_id.as_str();
    let stream_id = first.stream_id.as_str();
    let mut previous_receipt_digest = [0; 32];
    let mut previous_checkpoint_digest = [0; 32];
    let mut previous_sequence = 0u64;
    let mut previous_checkpoint_number = 0u64;
    let mut previous_witnessed_at = 0u64;
    for (offset, receipt) in receipts.iter().enumerate() {
        verifier.verify(receipt)?;
        let expected_index = u64::try_from(offset + 1)
            .map_err(|_| VerificationError::ReceiptCheckpointMismatch)?;
        let expected_checkpoint = previous_checkpoint_number.checked_add(1)
            .ok_or(VerificationError::ReceiptCheckpointMismatch)?;
        if receipt.witness_id != witness_id || receipt.stream_id != stream_id
            || receipt.log_index != expected_index
            || receipt.checkpoint_number != expected_checkpoint
            || receipt.previous_receipt_digest != previous_receipt_digest
            || receipt.previous_checkpoint_digest != previous_checkpoint_digest
            || receipt.last_sequence <= previous_sequence
            || receipt.witnessed_at < previous_witnessed_at
        {
            return Err(VerificationError::ReceiptCheckpointMismatch);
        }
        previous_receipt_digest = receipt.digest();
        previous_checkpoint_digest = receipt.checkpoint_digest;
        previous_sequence = receipt.last_sequence;
        previous_checkpoint_number = receipt.checkpoint_number;
        previous_witnessed_at = receipt.witnessed_at;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_checkpoint::{CheckpointBuilder, V1_CHAIN_FORMAT};
    use crate::audit_signer::{
        CheckpointSigner, Ed25519CheckpointVerifier, LocalEd25519TestSigner,
    };
    use crate::audit_witness::{LocalWitnessTestSigner, MemoryWitnessLedger, WitnessLedger};

    #[test]
    fn two_distinct_signed_witness_receipts_satisfy_quorum() {
        let checkpoint_signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let cp_verifier = Ed25519CheckpointVerifier::new(vec![(
            "cp-key".into(),
            checkpoint_signer.verifying_key(),
        )]);
        let builder = CheckpointBuilder::new("stream:q", "cp-key");
        let head = AuditHead {
            first_sequence: 1,
            last_sequence: 1,
            event_count: 1,
            head_event_hash: [8; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let signed = checkpoint_signer
            .sign_checkpoint(&builder.initial_v1_anchor(&head, 1).unwrap())
            .unwrap();
        let w1 = LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]);
        let w2 = LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32]);
        let ledger1 = MemoryWitnessLedger::new("w1", Box::new(w1));
        let ledger2 = MemoryWitnessLedger::new("w2", Box::new(w2));
        let r1 = ledger1.accept(&signed, &cp_verifier, 2).unwrap();
        let r2 = ledger2.accept(&signed, &cp_verifier, 2).unwrap();
        let receipt_verifier = WitnessReceiptVerifier::new(vec![
            (
                "w1-key".into(), "w1".into(),
                LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]).key_for_test(),
            ),
            (
                "w2-key".into(), "w2".into(),
                LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32]).key_for_test(),
            ),
        ]);
        assert_eq!(
            verify_checkpoint_and_quorum(&signed, &cp_verifier, &[r1, r2], &receipt_verifier, 2),
            Ok(())
        );
    }

    #[test]
    fn verifies_receipt_chain_across_checkpoint_advances() {
        let cp_signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let cp_verifier =
            Ed25519CheckpointVerifier::new(vec![("cp-key".into(), cp_signer.verifying_key())]);
        let builder = CheckpointBuilder::new("stream:chain", "cp-key");
        let h1 = AuditHead {
            first_sequence: 1,
            last_sequence: 1,
            event_count: 1,
            head_event_hash: [1; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let p1 = builder.initial_v1_anchor(&h1, 10).unwrap();
        let signed1 = cp_signer.sign_checkpoint(&p1).unwrap();
        let h2 = AuditHead {
            first_sequence: 1,
            last_sequence: 2,
            event_count: 2,
            head_event_hash: [2; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let p2 = builder.next(&h2, &p1, 20).unwrap();
        let signed2 = cp_signer.sign_checkpoint(&p2).unwrap();

        let witness_signer = LocalWitnessTestSigner::from_test_seed("w-key", [8; 32]);
        let witness_key = witness_signer.key_for_test();
        let ledger = MemoryWitnessLedger::new("witness-1", Box::new(witness_signer));
        let r1 = ledger.accept(&signed1, &cp_verifier, 11).unwrap();
        let r2 = ledger.accept(&signed2, &cp_verifier, 21).unwrap();
        let receipt_verifier = WitnessReceiptVerifier::new(vec![(
            "w-key".into(),
            "witness-1".into(),
            witness_key,
        )]);
        assert_eq!(verify_receipt_chain(&[r1.clone(), r2.clone()], &receipt_verifier), Ok(()));
        use crate::audit_witness::WitnessReceiptSigner;
        let progression_signer = LocalWitnessTestSigner::from_test_seed("w-key", [8; 32]);
        let mut skipped = r2;
        skipped.checkpoint_number = 3;
        skipped.signature = progression_signer.sign_receipt(&skipped).unwrap();
        assert_eq!(
            verify_receipt_chain(&[r1, skipped], &receipt_verifier),
            Err(VerificationError::ReceiptCheckpointMismatch)
        );
    }

    #[test]
    fn rejects_a_valid_signature_from_a_key_bound_to_another_witness() {
        use crate::audit_witness::WitnessReceiptSigner;
        let signer = LocalWitnessTestSigner::from_test_seed("shared-key", [9; 32]);
        let verifier = WitnessReceiptVerifier::new(vec![("shared-key".into(), "authorized-witness".into(), signer.key_for_test())]);
        let mut receipt = WitnessReceipt {
            witness_id: "forged-witness".into(), stream_id: "stream:x".into(),
            checkpoint_number: 1, checkpoint_digest: [1; 32], last_sequence: 1,
            head_event_hash: [2; 32], previous_checkpoint_digest: [0; 32],
            previous_receipt_digest: [0; 32], witnessed_at: 1, log_index: 1,
            signing_key_id: "shared-key".into(), signature: [0; 64],
        };
        receipt.signature = signer.sign_receipt(&receipt).unwrap();
        assert_eq!(verifier.verify(&receipt), Err(VerificationError::InvalidReceiptSignature));
    }

    #[test]
    fn detects_local_rollback_below_external_high_water_mark() {
        let builder = CheckpointBuilder::new("stream:q", "cp-key");
        let cp = builder
            .initial_v1_anchor(
                &AuditHead {
                    first_sequence: 1,
                    last_sequence: 5,
                    event_count: 5,
                    head_event_hash: [8; 32],
                    chain_format: V1_CHAIN_FORMAT.into(),
                },
                1,
            )
            .unwrap();
        let local = AuditHead {
            first_sequence: 1,
            last_sequence: 4,
            event_count: 4,
            head_event_hash: [7; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        assert_eq!(
            reconcile_local_head(&local, &cp),
            Err(VerificationError::RollbackOrTampering)
        );
    }
}
