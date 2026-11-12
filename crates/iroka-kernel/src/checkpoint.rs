//! Signed G11 checkpoint envelopes and independent external-publication verification.
//! Private signing keys remain behind a signer port (HSM/KMS in production);
//! publication evidence is verified separately from the database copy.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const G11_CHECKPOINT_SCHEMA_ID: &str = "iroka.g11.signed-checkpoint.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointError {
    Malformed,
    SigningUnavailable,
    PublicationUnavailable,
    UnknownSigner,
    InvalidSignature,
    InvalidPublicationReceipt,
    StreamMismatch,
    SequenceMismatch,
    PreviousCheckpointMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPayload {
    pub schema_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
    pub audit_head_digest: String,
    pub issued_at: u64,
    pub signer_key_id: String,
}

impl CheckpointPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        self.validate()?;
        let canonical = serde_jcs::to_vec(self).map_err(|_| CheckpointError::Malformed)?;
        let mut bytes = b"IROKA:G11:SIGNED_CHECKPOINT:V1\0".to_vec();
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.schema_id != G11_CHECKPOINT_SCHEMA_ID
            || self.stream_id.trim().is_empty()
            || self.stream_id.len() > 256
            || self.sequence == 0
            || self.signer_key_id.trim().is_empty()
            || self.signer_key_id.len() > 256
            || !valid_digest(&self.audit_head_digest)
            || self
                .previous_checkpoint_digest
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
        {
            return Err(CheckpointError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub payload: CheckpointPayload,
    pub signature: Vec<u8>,
}

impl SignedCheckpoint {
    pub fn digest(&self) -> Result<String, CheckpointError> {
        let mut bytes = self.payload.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalPublicationReceipt {
    pub provider: String,
    pub receipt_id: String,
    pub checkpoint_digest: String,
    pub published_at: u64,
    pub proof_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublishedCheckpoint {
    pub checkpoint: SignedCheckpoint,
    pub publication: ExternalPublicationReceipt,
}

pub trait CheckpointSigner: Send + Sync {
    /// Delegate to an HSM/KMS or another protected signing service.
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, CheckpointError>;
}

pub trait ExternalCheckpointPublisher: Send + Sync {
    /// Publish the signed envelope to an independently administered anchor.
    fn publish(
        &self,
        checkpoint: &SignedCheckpoint,
    ) -> Result<ExternalPublicationReceipt, CheckpointError>;
}

pub trait ExternalPublicationVerifier: Send + Sync {
    /// Verify provider authenticity and inclusion/receipt evidence independently.
    fn verify(
        &self,
        checkpoint_digest: &str,
        receipt: &ExternalPublicationReceipt,
    ) -> Result<(), CheckpointError>;
}

/// Create a signed checkpoint and publish it externally. A successful return
/// means the publisher supplied a receipt bound to this exact signed digest.
pub fn sign_and_publish_checkpoint<S, P>(
    payload: CheckpointPayload,
    signer: &S,
    publisher: &P,
) -> Result<PublishedCheckpoint, CheckpointError>
where
    S: CheckpointSigner,
    P: ExternalCheckpointPublisher,
{
    let message = payload.signing_bytes()?;
    let signature = signer.sign(&payload.signer_key_id, &message)?;
    if signature.len() != 64 {
        return Err(CheckpointError::SigningUnavailable);
    }
    let checkpoint = SignedCheckpoint { payload, signature };
    let digest = checkpoint.digest()?;
    let publication = publisher.publish(&checkpoint)?;
    if publication.provider.trim().is_empty()
        || publication.receipt_id.trim().is_empty()
        || publication.proof_ref.trim().is_empty()
        || publication.checkpoint_digest != digest
        || publication.published_at < checkpoint.payload.issued_at
    {
        return Err(CheckpointError::InvalidPublicationReceipt);
    }
    Ok(PublishedCheckpoint {
        checkpoint,
        publication,
    })
}

/// Independent verification requires a separately provisioned signer trust key
/// and a provider-specific verifier; a database row is never publication proof.
pub fn verify_published_checkpoint<V>(
    published: &PublishedCheckpoint,
    trusted_signer_key: &VerifyingKey,
    expected_stream_id: &str,
    expected_sequence: u64,
    expected_previous_digest: Option<&str>,
    publication_verifier: &V,
) -> Result<(), CheckpointError>
where
    V: ExternalPublicationVerifier,
{
    let payload = &published.checkpoint.payload;
    let message = payload.signing_bytes()?;
    let signature = Signature::from_slice(&published.checkpoint.signature)
        .map_err(|_| CheckpointError::InvalidSignature)?;
    trusted_signer_key
        .verify(&message, &signature)
        .map_err(|_| CheckpointError::InvalidSignature)?;

    if payload.stream_id != expected_stream_id {
        return Err(CheckpointError::StreamMismatch);
    }
    if payload.sequence != expected_sequence {
        return Err(CheckpointError::SequenceMismatch);
    }
    if payload.previous_checkpoint_digest.as_deref() != expected_previous_digest {
        return Err(CheckpointError::PreviousCheckpointMismatch);
    }
    let digest = published.checkpoint.digest()?;
    if published.publication.checkpoint_digest != digest
        || published.publication.published_at < payload.issued_at
        || published.publication.provider.trim().is_empty()
        || published.publication.receipt_id.trim().is_empty()
        || published.publication.proof_ref.trim().is_empty()
    {
        return Err(CheckpointError::InvalidPublicationReceipt);
    }
    publication_verifier.verify(&digest, &published.publication)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct LocalSigner(SigningKey);
    impl CheckpointSigner for LocalSigner {
        fn sign(&self, _key_id: &str, message: &[u8]) -> Result<Vec<u8>, CheckpointError> {
            Ok(self.0.sign(message).to_bytes().to_vec())
        }
    }

    struct TestPublisher;
    impl ExternalCheckpointPublisher for TestPublisher {
        fn publish(
            &self,
            checkpoint: &SignedCheckpoint,
        ) -> Result<ExternalPublicationReceipt, CheckpointError> {
            Ok(ExternalPublicationReceipt {
                provider: "test-transparency-log".into(),
                receipt_id: "receipt:checkpoint:1".into(),
                checkpoint_digest: checkpoint.digest()?,
                published_at: checkpoint.payload.issued_at + 1,
                proof_ref: "proof:checkpoint:1".into(),
            })
        }
    }

    struct TestPublicationVerifier;
    impl ExternalPublicationVerifier for TestPublicationVerifier {
        fn verify(
            &self,
            digest: &str,
            receipt: &ExternalPublicationReceipt,
        ) -> Result<(), CheckpointError> {
            if receipt.provider == "test-transparency-log"
                && receipt.receipt_id == "receipt:checkpoint:1"
                && receipt.checkpoint_digest == digest
                && receipt.proof_ref == "proof:checkpoint:1"
            {
                Ok(())
            } else {
                Err(CheckpointError::InvalidPublicationReceipt)
            }
        }
    }

    #[test]
    fn signed_checkpoint_requires_signature_and_external_receipt() {
        let signer = LocalSigner(SigningKey::from_bytes(&[7_u8; 32]));
        let payload = CheckpointPayload {
            schema_id: G11_CHECKPOINT_SCHEMA_ID.into(),
            stream_id: "g11:memory".into(),
            sequence: 42,
            previous_checkpoint_digest: Some("a".repeat(64)),
            audit_head_digest: "b".repeat(64),
            issued_at: 1_800_000_000,
            signer_key_id: "g11-checkpoint-key-1".into(),
        };
        let published = sign_and_publish_checkpoint(payload, &signer, &TestPublisher).unwrap();
        verify_published_checkpoint(
            &published,
            &signer.0.verifying_key(),
            "g11:memory",
            42,
            Some(&"a".repeat(64)),
            &TestPublicationVerifier,
        )
        .unwrap();
        assert_eq!(
            verify_published_checkpoint(
                &published,
                &signer.0.verifying_key(),
                "g11:memory",
                43,
                Some(&"a".repeat(64)),
                &TestPublicationVerifier,
            ),
            Err(CheckpointError::SequenceMismatch)
        );
    }

    #[test]
    fn checkpoint_rejects_forged_external_receipt() {
        let signer = LocalSigner(SigningKey::from_bytes(&[9_u8; 32]));
        let payload = CheckpointPayload {
            schema_id: CHECKPOINT_SCHEMA.into(),
            stream_id: "g11:memory".into(),
            sequence: 1,
            previous_checkpoint_digest: None,
            audit_head_digest: "c".repeat(64),
            issued_at: 1_800_000_000,
            signer_key_id: "g11-checkpoint-key-1".into(),
        };
        let mut published = sign_and_publish_checkpoint(payload, &signer, &TestPublisher).unwrap();
        published.publication.proof_ref = "forged".into();
        assert_eq!(
            verify_published_checkpoint(
                &published,
                &signer.0.verifying_key(),
                "g11:memory",
                1,
                None,
                &TestPublicationVerifier,
            ),
            Err(CheckpointError::InvalidPublicationReceipt)
        );
    }
}
