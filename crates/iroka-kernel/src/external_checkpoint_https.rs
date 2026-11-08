//! Production HTTPS/mTLS adapter for independently operated checkpoint witnesses.
//!
//! The adapter speaks the IROKA witness HTTP contract documented alongside A4-03.
//! It does not create or own signer keys. Each instance must be configured with a
//! distinct operator endpoint, client identity and witness trust root.
use crate::{CheckpointError, CheckpointWitness, SignedCheckpoint, WitnessReceipt};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

const MAX_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone)]
pub struct HttpsWitnessConfig {
    /// HTTPS origin plus optional deployment prefix, e.g. https://witness.example/v1-root.
    pub endpoint: String,
    pub witness_id: String,
    pub witness_key_id: String,
    /// Dedicated mTLS client identity issued to this IROKA deployment.
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
    /// CA bundle used to authenticate the witness server TLS certificate.
    pub trusted_ca_bundle: PathBuf,
    /// Checkpoint signer trust roots; provisioned from Owner-governed configuration.
    pub checkpoint_signer_roots: BTreeMap<String, VerifyingKey>,
    /// Expected Ed25519 public key for this witness identity.
    pub witness_trust_root: VerifyingKey,
}

pub struct HttpsCheckpointWitness {
    config: HttpsWitnessConfig,
}

impl HttpsCheckpointWitness {
    pub fn new(config: HttpsWitnessConfig) -> Result<Self, CheckpointError> {
        validate_endpoint(&config.endpoint)?;
        if config.witness_id.trim().is_empty()
            || config.witness_key_id.trim().is_empty()
            || config.checkpoint_signer_roots.is_empty()
            || !config.client_certificate.is_file()
            || !config.client_private_key.is_file()
            || !config.trusted_ca_bundle.is_file()
        {
            return Err(CheckpointError::Malformed);
        }
        Ok(Self { config })
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        idempotency: Option<&str>,
    ) -> Result<Vec<u8>, CheckpointError> {
        let mut command = Command::new("curl");
        command
            .arg("--disable")
            .arg("--silent")
            .arg("--show-error")
            .arg("--fail")
            .arg("--max-time")
            .arg("20")
            .arg("--connect-timeout")
            .arg("5")
            .arg("--max-filesize")
            .arg(MAX_RESPONSE_BYTES.to_string())
            .arg("--proto")
            .arg("=https")
            .arg("--tlsv1.2")
            .arg("--cert")
            .arg(&self.config.client_certificate)
            .arg("--key")
            .arg(&self.config.client_private_key)
            .arg("--cacert")
            .arg(&self.config.trusted_ca_bundle)
            .arg("--request")
            .arg(method)
            .arg("--header")
            .arg("Accept: application/json")
            .arg("--header")
            .arg("Content-Type: application/json");
        if let Some(key) = idempotency {
            command
                .arg("--header")
                .arg(format!("Idempotency-Key: {key}"));
        }
        if body.is_some() {
            command.arg("--data-binary").arg("@-");
        }
        let mut child = command
            .arg("--url")
            .arg(url)
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        if let Some(bytes) = body {
            let write_result = child
                .stdin
                .take()
                .ok_or(CheckpointError::WitnessUnavailable)?
                .write_all(bytes);
            if write_result.is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CheckpointError::WitnessUnavailable);
            }
        }
        // Read at most limit + 1 bytes before allocating further memory. Checking
        // after wait_with_output() would buffer an untrusted response without a
        // hard client-side bound (notably for chunked/unknown-length responses).
        let mut stdout = child
            .stdout
            .take()
            .ok_or(CheckpointError::WitnessUnavailable)?;
        let mut response = Vec::with_capacity(MAX_RESPONSE_BYTES.min(8192));
        if stdout
            .by_ref()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CheckpointError::WitnessUnavailable);
        }
        drop(stdout);
        let status = child
            .wait()
            .map_err(|_| CheckpointError::WitnessUnavailable)?;
        if !status.success() || response.len() > MAX_RESPONSE_BYTES {
            return Err(CheckpointError::WitnessUnavailable);
        }
        Ok(response)
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "{}/{}",
            self.config.endpoint.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
    }

    fn verify_receipt(
        &self,
        checkpoint: &SignedCheckpoint,
        receipt: &WitnessReceipt,
    ) -> Result<(), CheckpointError> {
        if receipt.payload.witness_id != self.config.witness_id
            || receipt.payload.witness_key_id != self.config.witness_key_id
        {
            return Err(CheckpointError::WitnessIdentityMismatch);
        }
        receipt.verify(
            checkpoint,
            &BTreeMap::from([(
                self.config.witness_key_id.clone(),
                self.config.witness_trust_root,
            )]),
        )
    }
}

impl CheckpointWitness for HttpsCheckpointWitness {
    fn publish(&self, checkpoint: &SignedCheckpoint) -> Result<WitnessReceipt, CheckpointError> {
        checkpoint.verify(&self.config.checkpoint_signer_roots)?;
        let digest = checkpoint.digest().map(hex_digest)?;
        let body = serde_json::to_vec(checkpoint).map_err(|_| CheckpointError::Malformed)?;
        let bytes = self.request(
            "POST",
            &self.url("v1/checkpoints"),
            Some(&body),
            Some(&digest),
        )?;
        let receipt: WitnessReceipt =
            serde_json::from_slice(&bytes).map_err(|_| CheckpointError::InvalidWitnessResponse)?;
        self.verify_receipt(checkpoint, &receipt)?;
        Ok(receipt)
    }

    fn latest(
        &self,
        stream_id: &str,
    ) -> Result<Option<(SignedCheckpoint, WitnessReceipt)>, CheckpointError> {
        if stream_id.trim().is_empty() {
            return Err(CheckpointError::Malformed);
        }
        let path = format!("v1/streams/{}/latest", percent_encode(stream_id.as_bytes()));
        let bytes = self.request("GET", &self.url(&path), None, None)?;
        let response: LatestResponse =
            serde_json::from_slice(&bytes).map_err(|_| CheckpointError::InvalidWitnessResponse)?;
        match (response.checkpoint, response.receipt) {
            (None, None) => Ok(None),
            (Some(checkpoint), Some(receipt)) => {
                if checkpoint.payload.stream_id != stream_id {
                    return Err(CheckpointError::InvalidWitnessResponse);
                }
                checkpoint.verify(&self.config.checkpoint_signer_roots)?;
                self.verify_receipt(&checkpoint, &receipt)?;
                Ok(Some((checkpoint, receipt)))
            }
            _ => Err(CheckpointError::InvalidWitnessResponse),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LatestResponse {
    checkpoint: Option<SignedCheckpoint>,
    receipt: Option<WitnessReceipt>,
}

/// Publish to separately administered adapters and require verified distinct-identity quorum.
/// A successful receipt is retained even if another endpoint is unavailable; failure is closed
/// unless the verified receipt count reaches the configured threshold.
pub fn publish_witness_quorum(
    checkpoint: &SignedCheckpoint,
    witnesses: &[&dyn CheckpointWitness],
    trusted_witnesses: &BTreeMap<String, VerifyingKey>,
    required: usize,
) -> Result<Vec<WitnessReceipt>, CheckpointError> {
    if required == 0 || required > witnesses.len() {
        return Err(CheckpointError::Malformed);
    }
    let mut receipts = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        if let Ok(receipt) = witness.publish(checkpoint) {
            receipts.push(receipt);
        }
    }
    crate::verify_witness_quorum(checkpoint, &receipts, trusted_witnesses, required)?;
    Ok(receipts)
}

fn validate_endpoint(endpoint: &str) -> Result<(), CheckpointError> {
    let Some(authority) = endpoint.strip_prefix("https://") else {
        return Err(CheckpointError::InvalidWitnessEndpoint);
    };
    let host = authority.split('/').next().unwrap_or_default();
    if host.is_empty()
        || host.contains('@')
        || endpoint.contains('?')
        || endpoint.contains('#')
        || endpoint
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(CheckpointError::InvalidWitnessEndpoint);
    }
    Ok(())
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_checkpoint, CheckpointSigner, WitnessReceiptPayload};
    use ed25519_dalek::{Signer, SigningKey};

    struct TestCheckpointSigner(SigningKey);

    impl CheckpointSigner for TestCheckpointSigner {
        fn key_id(&self) -> &str {
            "checkpoint:test"
        }

        fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, CheckpointError> {
            Ok(self.0.sign(bytes).to_bytes().to_vec())
        }
    }

    struct StaticWitness {
        id: String,
        key_id: String,
        key: SigningKey,
    }

    impl CheckpointWitness for StaticWitness {
        fn publish(
            &self,
            checkpoint: &SignedCheckpoint,
        ) -> Result<WitnessReceipt, CheckpointError> {
            let payload = WitnessReceiptPayload {
                protocol: "iroka.g11.witness-receipt".into(),
                version: 1,
                witness_id: self.id.clone(),
                witness_key_id: self.key_id.clone(),
                stream_id: checkpoint.payload.stream_id.clone(),
                checkpoint_sequence: checkpoint.payload.checkpoint_sequence,
                checkpoint_digest_sha256: hex_digest(checkpoint.digest()?),
                previous_checkpoint_digest_sha256: checkpoint
                    .payload
                    .previous_checkpoint_sha256
                    .clone(),
                accepted_at: checkpoint.payload.issued_at,
                algorithm: "Ed25519".into(),
            };
            let signature = self
                .key
                .sign(&WitnessReceipt::signing_bytes(&payload)?)
                .to_bytes()
                .to_vec();
            Ok(WitnessReceipt { payload, signature })
        }

        fn latest(
            &self,
            _stream_id: &str,
        ) -> Result<Option<(SignedCheckpoint, WitnessReceipt)>, CheckpointError> {
            Ok(None)
        }
    }

    #[test]
    fn quorum_publisher_requires_two_distinct_verified_remote_identities() {
        let checkpoint_signer = TestCheckpointSigner(SigningKey::from_bytes(&[41; 32]));
        let checkpoint = create_checkpoint(
            &checkpoint_signer,
            "audit-stream:remote-quorum",
            1,
            1,
            [7; 32],
            None,
            2_000,
        )
        .unwrap();
        let first = StaticWitness {
            id: "operator:one".into(),
            key_id: "witness-key:one".into(),
            key: SigningKey::from_bytes(&[51; 32]),
        };
        let second = StaticWitness {
            id: "operator:two".into(),
            key_id: "witness-key:two".into(),
            key: SigningKey::from_bytes(&[52; 32]),
        };
        let roots = BTreeMap::from([
            (first.key_id.clone(), first.key.verifying_key()),
            (second.key_id.clone(), second.key.verifying_key()),
        ]);
        let receipts = publish_witness_quorum(&checkpoint, &[&first, &second], &roots, 2).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            publish_witness_quorum(&checkpoint, &[&first, &second], &roots, 3),
            Err(CheckpointError::Malformed),
        );
    }

    #[test]
    fn endpoint_requires_https_and_rejects_credentials_and_fragments() {
        assert!(validate_endpoint("https://witness.example").is_ok());
        assert!(validate_endpoint("http://witness.example").is_err());
        assert!(validate_endpoint("https://user@witness.example").is_err());
        assert!(validate_endpoint("https://witness.example/path?token=x").is_err());
        assert!(validate_endpoint("https://witness.example/#fragment").is_err());
    }

    #[test]
    fn stream_path_encoding_prevents_path_injection() {
        assert_eq!(percent_encode(b"a/b c"), "a%2Fb%20c");
    }
}
