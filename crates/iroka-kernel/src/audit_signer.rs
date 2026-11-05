//! Provider-neutral checkpoint signing boundary.
//! The included Ed25519 key wrapper is for deterministic tests and local development only.
//! Production adapters must call a separately administered HSM/KMS/offline signer.

use crate::audit_checkpoint::{CheckpointError, CheckpointPayload};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

const SIGNING_DOMAIN: &[u8] = b"IROKA:G11:AUDIT-CHECKPOINT-SIGNATURE:V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    InvalidPayload,
    KeyUnavailable,
    SigningFailed,
    InvalidSignature,
    UnknownKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub payload: CheckpointPayload,
    pub signature: [u8; 64],
}

pub trait CheckpointSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign_checkpoint(&self, payload: &CheckpointPayload) -> Result<SignedCheckpoint, SignerError>;
}

pub trait CheckpointSignatureVerifier: Send + Sync {
    fn verify_checkpoint(&self, signed: &SignedCheckpoint) -> Result<(), SignerError>;
}

/// Local key implementation intended for tests. Do not construct from production application config.
pub struct LocalEd25519TestSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl LocalEd25519TestSigner {
    pub fn from_test_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self { key_id: key_id.into(), signing_key: SigningKey::from_bytes(&seed) }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl CheckpointSigner for LocalEd25519TestSigner {
    fn key_id(&self) -> &str { &self.key_id }

    fn sign_checkpoint(&self, payload: &CheckpointPayload) -> Result<SignedCheckpoint, SignerError> {
        if payload.signing_key_id != self.key_id {
            return Err(SignerError::UnknownKey);
        }
        let canonical = payload.canonical_cbor().map_err(|_: CheckpointError| SignerError::InvalidPayload)?;
        let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        message.extend_from_slice(SIGNING_DOMAIN);
        message.extend_from_slice(&canonical);
        let signature = self.signing_key.sign(&message).to_bytes();
        Ok(SignedCheckpoint { payload: payload.clone(), signature })
    }
}

pub struct Ed25519CheckpointVerifier {
    trusted_keys: Vec<(String, VerifyingKey)>,
}

impl Ed25519CheckpointVerifier {
    pub fn new(trusted_keys: Vec<(String, VerifyingKey)>) -> Self {
        Self { trusted_keys }
    }
}

impl CheckpointSignatureVerifier for Ed25519CheckpointVerifier {
    fn verify_checkpoint(&self, signed: &SignedCheckpoint) -> Result<(), SignerError> {
        let key = self.trusted_keys.iter()
            .find(|(id, _)| id == &signed.payload.signing_key_id)
            .map(|(_, key)| key)
            .ok_or(SignerError::UnknownKey)?;
        let canonical = signed.payload.canonical_cbor().map_err(|_: CheckpointError| SignerError::InvalidPayload)?;
        let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        message.extend_from_slice(SIGNING_DOMAIN);
        message.extend_from_slice(&canonical);
        let signature = Signature::from_bytes(&signed.signature);
        key.verify(&message, &signature).map_err(|_| SignerError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_checkpoint::{AuditHead, CheckpointBuilder, V1_CHAIN_FORMAT};

    #[test]
    fn signature_is_bound_to_canonical_payload_and_key_id() {
        let signer = LocalEd25519TestSigner::from_test_seed("test-key", [9; 32]);
        let builder = CheckpointBuilder::new("stream:test", "test-key");
        let head = AuditHead { first_sequence: 1, last_sequence: 1, event_count: 1,
            head_event_hash: [3; 32], chain_format: V1_CHAIN_FORMAT.into() };
        let payload = builder.initial_v1_anchor(&head, 100).unwrap();
        let signed = signer.sign_checkpoint(&payload).unwrap();
        let verifier = Ed25519CheckpointVerifier::new(vec![("test-key".into(), signer.verifying_key())]);
        assert_eq!(verifier.verify_checkpoint(&signed), Ok(()));
        let mut altered = signed.clone();
        altered.payload.created_at += 1;
        assert_eq!(verifier.verify_checkpoint(&altered), Err(SignerError::InvalidSignature));
    }

    #[test]
    fn signer_refuses_payload_for_another_key() {
        let signer = LocalEd25519TestSigner::from_test_seed("key-a", [4; 32]);
        let builder = CheckpointBuilder::new("stream:test", "key-b");
        let head = AuditHead { first_sequence: 1, last_sequence: 1, event_count: 1,
            head_event_hash: [3; 32], chain_format: V1_CHAIN_FORMAT.into() };
        let payload = builder.initial_v1_anchor(&head, 100).unwrap();
        assert_eq!(signer.sign_checkpoint(&payload), Err(SignerError::UnknownKey));
    }
}
