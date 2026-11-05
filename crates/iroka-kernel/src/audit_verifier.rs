//! Offline checkpoint, receipt-quorum and local rollback verification.

use crate::audit_checkpoint::{AuditHead, CheckpointPayload};
use crate::audit_signer::{CheckpointSignatureVerifier, SignedCheckpoint, SignerError};
use crate::audit_witness::WitnessReceipt;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::BTreeSet;

/// The Owner-approved roster has exactly three independently administered witnesses.
pub const AUTHORIZED_WITNESS_COUNT: usize = 3;
/// OD01 requires two distinct authorized witnesses for an accepted checkpoint.
pub const REQUIRED_WITNESS_QUORUM: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidCheckpoint,
    InvalidCheckpointSignature,
    InvalidReceiptSignature,
    InvalidWitnessRoster,
    WitnessRosterUnprovisioned,
    WitnessRosterExpired,
    WitnessRosterScopeMismatch,
    UnauthorizedWitness,
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

/// One explicit binding between a provisioned witness identity, its key identifier,
/// and the public key authorized to sign receipts for that identity.
pub struct AuthorizedWitness {
    pub witness_id: String,
    pub signing_key_id: String,
    pub verifying_key: VerifyingKey,
}

pub struct WitnessReceiptVerifier {
    roster: Vec<AuthorizedWitness>,
}

impl WitnessReceiptVerifier {
    /// Construct the fixed Owner-approved 3-witness roster.
    ///
    /// Rejects incomplete/oversized rosters, blank identifiers, duplicate witness IDs,
    /// duplicate key IDs, and key reuse under multiple identities or key IDs.
    pub(crate) fn new(roster: Vec<AuthorizedWitness>) -> Result<Self, VerificationError> {
        if roster.len() != AUTHORIZED_WITNESS_COUNT {
            return Err(VerificationError::InvalidWitnessRoster);
        }
        let mut witness_ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for entry in &roster {
            if entry.witness_id.trim().is_empty()
                || entry.signing_key_id.trim().is_empty()
                || !witness_ids.insert(entry.witness_id.as_str())
                || !key_ids.insert(entry.signing_key_id.as_str())
                || !public_keys.insert(entry.verifying_key.to_bytes())
            {
                return Err(VerificationError::InvalidWitnessRoster);
            }
        }
        Ok(Self { roster })
    }

    /// A valid signature is insufficient unless both the witness ID and key ID
    /// match the same provisioned roster entry.
    pub fn verify(&self, receipt: &WitnessReceipt) -> Result<(), VerificationError> {
        let entry = self
            .roster
            .iter()
            .find(|entry| entry.witness_id == receipt.witness_id)
            .ok_or(VerificationError::UnauthorizedWitness)?;
        if entry.signing_key_id != receipt.signing_key_id {
            return Err(VerificationError::UnauthorizedWitness);
        }
        entry
            .verifying_key
            .verify(
                &receipt.signing_bytes(),
                &Signature::from_bytes(&receipt.signature),
            )
            .map_err(|_| VerificationError::InvalidReceiptSignature)
    }
}

/// Runtime trust state for the independent witness roster.
/// Production callers can only construct the unprovisioned state until a separately
/// reviewed Owner-authorized roster activation path is implemented.
pub struct WitnessRosterState {
    verifier: Option<WitnessReceiptVerifier>,
    stream_id: Option<String>,
    version: Option<u64>,
    expires_at: Option<u64>,
}

impl WitnessRosterState {
    pub fn unprovisioned() -> Self {
        Self { verifier: None, stream_id: None, version: None, expires_at: None }
    }

    /// Version of the currently activated Owner-signed roster, if provisioned.
    pub fn version(&self) -> Option<u64> {
        self.version
    }

    /// Stream authorized by the activated roster, if provisioned.
    pub fn authorized_stream(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    fn verifier_at(&self, now: u64) -> Result<&WitnessReceiptVerifier, VerificationError> {
        if self.expires_at.is_some_and(|expires_at| now >= expires_at) {
            return Err(VerificationError::WitnessRosterExpired);
        }
        self.verifier.as_ref().ok_or(VerificationError::WitnessRosterUnprovisioned)
    }

    fn validate_stream(&self, stream_id: &str) -> Result<(), VerificationError> {
        if self.stream_id.as_deref().is_some_and(|authorized| authorized != stream_id) {
            return Err(VerificationError::WitnessRosterScopeMismatch);
        }
        Ok(())
    }

    pub(crate) fn provisioned_from_manifest(
        verifier: WitnessReceiptVerifier, stream_id: String, version: u64, expires_at: u64,
    ) -> Self {
        Self { verifier: Some(verifier), stream_id: Some(stream_id), version: Some(version), expires_at: Some(expires_at) }
    }

    #[cfg(test)]
    fn provisioned_for_test(verifier: WitnessReceiptVerifier) -> Self {
        Self { verifier: Some(verifier), stream_id: None, version: None, expires_at: None }
    }
}

/// Verifies a checkpoint against the fixed Owner-approved 2-of-3 witness roster.
/// Missing Owner authorization is an explicit fail-closed state.
pub fn verify_checkpoint_and_quorum(
    signed: &SignedCheckpoint,
    checkpoint_verifier: &dyn CheckpointSignatureVerifier,
    receipts: &[WitnessReceipt],
    roster_state: &WitnessRosterState,
    now: u64,
) -> Result<(), VerificationError> {
    let payload: &CheckpointPayload = &signed.payload;
    let receipt_verifier = roster_state.verifier_at(now)?;
    roster_state.validate_stream(&payload.stream_id)?;
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
        if !witnesses.insert(receipt.witness_id.as_str()) {
            return Err(VerificationError::DuplicateWitness);
        }
    }
    if witnesses.len() < REQUIRED_WITNESS_QUORUM {
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
    roster_state: &WitnessRosterState,
    now: u64,
) -> Result<(), VerificationError> {
    let verifier = roster_state.verifier_at(now)?;
    let Some(first) = receipts.first() else {
        return Ok(());
    };
    roster_state.validate_stream(&first.stream_id)?;
    let witness_id = first.witness_id.as_str();
    let stream_id = first.stream_id.as_str();
    let mut previous_digest = [0; 32];
    let mut expected_index = 1u64;
    for receipt in receipts {
        verifier.verify(receipt)?;
        if receipt.witness_id != witness_id
            || receipt.stream_id != stream_id
            || receipt.log_index != expected_index
            || receipt.previous_receipt_digest != previous_digest
        {
            return Err(VerificationError::ReceiptCheckpointMismatch);
        }
        previous_digest = receipt.digest();
        expected_index = expected_index
            .checked_add(1)
            .ok_or(VerificationError::ReceiptCheckpointMismatch)?;
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
    use crate::audit_witness::{LocalWitnessTestSigner, MemoryWitnessLedger, WitnessLedger, WitnessReceiptSigner};

    fn roster() -> WitnessRosterState {
        let w1 = LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]);
        let w2 = LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32]);
        let w3 = LocalWitnessTestSigner::from_test_seed("w3-key", [4; 32]);
        WitnessRosterState::provisioned_for_test(WitnessReceiptVerifier::new(vec![
            AuthorizedWitness {
                witness_id: "w1".into(),
                signing_key_id: "w1-key".into(),
                verifying_key: w1.key_for_test(),
            },
            AuthorizedWitness {
                witness_id: "w2".into(),
                signing_key_id: "w2-key".into(),
                verifying_key: w2.key_for_test(),
            },
            AuthorizedWitness {
                witness_id: "w3".into(),
                signing_key_id: "w3-key".into(),
                verifying_key: w3.key_for_test(),
            },
        ]).unwrap())
    }

    #[test]
    fn unprovisioned_roster_has_no_verification_authority() {
        let state = WitnessRosterState::unprovisioned();
        assert!(matches!(state.verifier(), Err(VerificationError::WitnessRosterUnprovisioned)));
    }

    #[test]
    fn checkpoint_verification_fails_closed_when_roster_is_unprovisioned() {
        let checkpoint_signer = LocalEd25519TestSigner::from_test_seed("cp-key", [1; 32]);
        let checkpoint_verifier = Ed25519CheckpointVerifier::new(vec![(
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
        assert_eq!(
            verify_checkpoint_and_quorum(
                &signed,
                &checkpoint_verifier,
                &[],
                &WitnessRosterState::unprovisioned(),
                1,
            ),
            Err(VerificationError::WitnessRosterUnprovisioned)
        );
    }

    #[test]
    fn two_distinct_authorized_witness_receipts_satisfy_fixed_quorum() {
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
        let ledger1 = MemoryWitnessLedger::new(
            "w1",
            Box::new(LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32])),
        );
        let ledger2 = MemoryWitnessLedger::new(
            "w2",
            Box::new(LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32])),
        );
        let r1 = ledger1.accept(&signed, &cp_verifier, 2).unwrap();
        let r2 = ledger2.accept(&signed, &cp_verifier, 2).unwrap();
        assert_eq!(
            verify_checkpoint_and_quorum(&signed, &cp_verifier, &[r1, r2], &roster(), 3),
            Ok(())
        );
    }

    #[test]
    fn one_receipt_cannot_satisfy_fixed_two_of_three_quorum() {
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
        let ledger = MemoryWitnessLedger::new(
            "w1",
            Box::new(LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32])),
        );
        let receipt = ledger.accept(&signed, &cp_verifier, 2).unwrap();
        assert_eq!(
            verify_checkpoint_and_quorum(&signed, &cp_verifier, &[receipt], &roster(), 3),
            Err(VerificationError::InsufficientQuorum)
        );
    }

    #[test]
    fn receipt_key_cannot_be_relabelled_as_another_authorized_witness() {
        let signer = LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]);
        let key = signer.key_for_test();
        let roster = WitnessReceiptVerifier::new(vec![
            AuthorizedWitness {
                witness_id: "w1".into(),
                signing_key_id: "w1-key".into(),
                verifying_key: key,
            },
            AuthorizedWitness {
                witness_id: "w2".into(),
                signing_key_id: "w2-key".into(),
                verifying_key: LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32])
                    .key_for_test(),
            },
            AuthorizedWitness {
                witness_id: "w3".into(),
                signing_key_id: "w3-key".into(),
                verifying_key: LocalWitnessTestSigner::from_test_seed("w3-key", [4; 32])
                    .key_for_test(),
            },
        ]).unwrap();
        let mut receipt = WitnessReceipt {
            witness_id: "w2".into(),
            stream_id: "stream:q".into(),
            checkpoint_number: 1,
            checkpoint_digest: [5; 32],
            last_sequence: 1,
            head_event_hash: [8; 32],
            previous_checkpoint_digest: [0; 32],
            previous_receipt_digest: [0; 32],
            witnessed_at: 2,
            log_index: 1,
            signing_key_id: "w1-key".into(),
            signature: [0; 64],
        };
        receipt.signature = signer.sign_receipt(&receipt).unwrap();
        assert_eq!(roster.verify(&receipt), Err(VerificationError::UnauthorizedWitness));
    }

    #[test]
    fn roster_rejects_reused_public_key_even_with_distinct_ids() {
        let reused = LocalWitnessTestSigner::from_test_seed("shared-key", [9; 32]);
        let result = WitnessReceiptVerifier::new(vec![
            AuthorizedWitness { witness_id: "w1".into(), signing_key_id: "k1".into(), verifying_key: reused.key_for_test() },
            AuthorizedWitness { witness_id: "w2".into(), signing_key_id: "k2".into(), verifying_key: reused.key_for_test() },
            AuthorizedWitness {
                witness_id: "w3".into(),
                signing_key_id: "k3".into(),
                verifying_key: LocalWitnessTestSigner::from_test_seed("k3", [4; 32])
                    .key_for_test(),
            },
        ]);
        assert!(matches!(result, Err(VerificationError::InvalidWitnessRoster)));
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

        let witness_signer = LocalWitnessTestSigner::from_test_seed("w1-key", [2; 32]);
        let witness_key = witness_signer.key_for_test();
        let ledger = MemoryWitnessLedger::new("w1", Box::new(witness_signer));
        let r1 = ledger.accept(&signed1, &cp_verifier, 11).unwrap();
        let r2 = ledger.accept(&signed2, &cp_verifier, 21).unwrap();
        let receipt_verifier = WitnessRosterState::provisioned_for_test(WitnessReceiptVerifier::new(vec![
            AuthorizedWitness {
                witness_id: "w1".into(),
                signing_key_id: "w1-key".into(),
                verifying_key: witness_key,
            },
            AuthorizedWitness {
                witness_id: "w2".into(),
                signing_key_id: "w2-key".into(),
                verifying_key: LocalWitnessTestSigner::from_test_seed("w2-key", [3; 32]).key_for_test(),
            },
            AuthorizedWitness {
                witness_id: "w3".into(),
                signing_key_id: "w3-key".into(),
                verifying_key: LocalWitnessTestSigner::from_test_seed("w3-key", [4; 32]).key_for_test(),
            },
        ]).unwrap());
        assert_eq!(verify_receipt_chain(&[r1, r2], &receipt_verifier, 30), Ok(()));
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
