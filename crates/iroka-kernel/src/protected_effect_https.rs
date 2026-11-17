//! HTTPS/mTLS client adapter for a separately operated G09 protected-effect executor.
//!
//! This adapter provides the transport boundary only. The remote executor must
//! implement the durable nonce/idempotency and signed-result contract; a live
//! business system and its credentials are provisioned separately by the Owner.
use crate::{
    EffectExecutionError, ExecutionResultPayload, ProtectedEffectExecutor,
    ProtectedEffectRequest, SignedExecutionResult,
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MAX_REQUEST_BYTES: usize = 1_048_576;
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const STATUS_MARKER: &[u8] = b"\nIROKA_HTTP_STATUS:";

#[derive(Clone)]
pub struct HttpsProtectedEffectExecutorConfig {
    /// HTTPS origin plus optional deployment prefix.
    pub endpoint: String,
    /// Executor identity expected by the kernel and signed result.
    pub executor_subject: String,
    /// Dedicated mTLS client certificate and private key.
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
    /// CA bundle used to authenticate the executor server.
    pub trusted_ca_bundle: PathBuf,
}

pub struct HttpsProtectedEffectExecutor {
    config: HttpsProtectedEffectExecutorConfig,
}

impl HttpsProtectedEffectExecutor {
    pub fn new(
        config: HttpsProtectedEffectExecutorConfig,
    ) -> Result<Self, EffectExecutionError> {
        validate_endpoint(&config.endpoint)?;
        if config.executor_subject.trim().is_empty()
            || config.executor_subject.len() > 256
            || !regular_file_without_symlink(&config.client_certificate)
            || !private_key_is_secure(&config.client_private_key)
            || !regular_file_without_symlink(&config.trusted_ca_bundle)
        {
            return Err(EffectExecutionError::Unavailable);
        }
        Ok(Self { config })
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        nonce: &str,
        operation_digest: Option<&str>,
    ) -> Result<(u16, Vec<u8>), EffectExecutionError> {
        let mut command = Command::new("curl");
        command
            .arg("--disable")
            .arg("--noproxy")
            .arg("*")
            .arg("--silent")
            .arg("--show-error")
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
            .arg("Content-Type: application/json")
            .arg("--header")
            .arg(format!("Idempotency-Key: {nonce}"));
        if let Some(digest) = operation_digest {
            command
                .arg("--header")
                .arg(format!("IROKA-Operation-Digest: {digest}"));
        }
        command
            .arg("--header")
            .arg("IROKA-Protocol-Version: 1")
            .arg("--write-out")
            .arg("\\nIROKA_HTTP_STATUS:%{http_code}");
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
            .map_err(|_| EffectExecutionError::Unavailable)?;

        if let Some(bytes) = body {
            let write_result = child
                .stdin
                .take()
                .ok_or(EffectExecutionError::Unavailable)?
                .write_all(bytes);
            if write_result.is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EffectExecutionError::OutcomeUnknown);
            }
        }

        let mut stdout = child
            .stdout
            .take()
            .ok_or(EffectExecutionError::Unavailable)?;
        let maximum = MAX_RESPONSE_BYTES + STATUS_MARKER.len() + 3;
        let mut response = Vec::with_capacity(maximum.min(8192));
        if stdout
            .by_ref()
            .take((maximum + 1) as u64)
            .read_to_end(&mut response)
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(EffectExecutionError::OutcomeUnknown);
        }
        drop(stdout);
        let status = child
            .wait()
            .map_err(|_| EffectExecutionError::OutcomeUnknown)?;
        if !status.success() || response.len() > maximum {
            return Err(EffectExecutionError::OutcomeUnknown);
        }

        let marker_index = response
            .windows(STATUS_MARKER.len())
            .rposition(|window| window == STATUS_MARKER)
            .ok_or(EffectExecutionError::OutcomeUnknown)?;
        let status_bytes = &response[marker_index + STATUS_MARKER.len()..];
        if status_bytes.len() != 3 || !status_bytes.iter().all(u8::is_ascii_digit) {
            return Err(EffectExecutionError::OutcomeUnknown);
        }
        let http_status = std::str::from_utf8(status_bytes)
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(EffectExecutionError::OutcomeUnknown)?;
        let body = response[..marker_index].to_vec();
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(EffectExecutionError::OutcomeUnknown);
        }
        Ok((http_status, body))
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "{}/{}",
            self.config.endpoint.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
    }

    fn decode_result(
        &self,
        body: &[u8],
        expected_nonce: &str,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<SignedExecutionResult, EffectExecutionError> {
        let result: SignedExecutionResult =
            serde_json::from_slice(body).map_err(|_| EffectExecutionError::OutcomeUnknown)?;
        let payload: &ExecutionResultPayload = &result.payload;
        if payload.protocol != "iroka.g09.execution-result"
            || payload.version != 1
            || payload.nonce != expected_nonce
            || payload.executor_subject != self.config.executor_subject
            || expected_digest.is_some_and(|digest| payload.operation_digest != digest)
            || payload.executor_key_id.trim().is_empty()
        {
            return Err(EffectExecutionError::OutcomeUnknown);
        }
        Ok(result)
    }
}

impl ProtectedEffectExecutor for HttpsProtectedEffectExecutor {
    fn execute(
        &self,
        effect: &ProtectedEffectRequest,
        nonce: &str,
        operation_digest: [u8; 32],
    ) -> Result<SignedExecutionResult, EffectExecutionError> {
        if effect.executor_subject() != self.config.executor_subject
            || !valid_nonce(nonce)
        {
            return Err(EffectExecutionError::RejectedBeforeEffect);
        }
        let digest = hex_digest(&operation_digest);
        let body = serde_json::to_vec(&serde_json::json!({
            "protocol": "iroka.g09.protected-effect-request",
            "version": 1,
            "nonce": nonce,
            "operation_digest": digest,
            "executor_subject": effect.executor_subject(),
            "capability": effect.capability(),
            "resource": effect.resource(),
            "effect_type": effect.effect_type(),
            "risk_class": effect.risk_class(),
            "operation": effect.operation(),
        }))
        .map_err(|_| EffectExecutionError::RejectedBeforeEffect)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(EffectExecutionError::RejectedBeforeEffect);
        }

        let (status, response) = self.request(
            "POST",
            &self.url("v1/protected-effects"),
            Some(&body),
            nonce,
            Some(&digest),
        )?;
        match status {
            200 | 201 => self.decode_result(&response, nonce, Some(operation_digest)),
            400 | 401 | 403 | 404 | 409 | 422 => {
                // The remote contract defines these 4xx statuses as rejected
                // before any business side effect is initiated.
                Err(EffectExecutionError::RejectedBeforeEffect)
            }
            _ => Err(EffectExecutionError::OutcomeUnknown),
        }
    }

    fn lookup(
        &self,
        nonce: &str,
    ) -> Result<Option<SignedExecutionResult>, EffectExecutionError> {
        if !valid_nonce(nonce) {
            return Err(EffectExecutionError::Unavailable);
        }
        let path = format!("v1/protected-effects/{}", percent_encode(nonce.as_bytes()));
        let (status, response) = self.request(
            "GET",
            &self.url(&path),
            None,
            nonce,
            None,
        )?;
        match status {
            200 => self
                .decode_result(&response, nonce, None)
                .map(Some),
            404 => Ok(None),
            _ => Err(EffectExecutionError::Unavailable),
        }
    }
}

fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= 256
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:".contains(&byte))
}

fn validate_endpoint(endpoint: &str) -> Result<(), EffectExecutionError> {
    let Some(authority) = endpoint.strip_prefix("https://") else {
        return Err(EffectExecutionError::Unavailable);
    };
    let host = authority.split('/').next().unwrap_or_default();
    if host.is_empty()
        || host.contains('@')
        || endpoint.contains('?')
        || endpoint.contains('#')
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(EffectExecutionError::Unavailable);
    }
    Ok(())
}

fn regular_file_without_symlink(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.is_file() && !metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn private_key_is_secure(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_key_is_secure(_path: &Path) -> bool {
    // Platform-specific ACL verification is required before production use.
    false
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            output.push(*byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g09_executor_endpoint_requires_https_and_rejects_ambiguous_authorities() {
        assert!(validate_endpoint("https://executor.example").is_ok());
        assert!(validate_endpoint("https://executor.example/api/v1").is_ok());
        for invalid in [
            "http://executor.example",
            "https://",
            "https://user:pass@executor.example",
            "https://executor.example?token=x",
            "https://executor.example#fragment",
            "https://executor.example/path with space",
        ] {
            assert!(validate_endpoint(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn g09_executor_nonce_is_header_and_path_safe() {
        assert!(valid_nonce("approval-123:abc_9"));
        assert!(!valid_nonce(""));
        assert!(!valid_nonce("bad nonce"));
        assert!(!valid_nonce("bad\\r\\nHeader: injected"));
        assert!(!valid_nonce(&"x".repeat(257)));
        assert_eq!(percent_encode(b"nonce/with space"), "nonce%2Fwith%20space");
    }

    #[test]
    fn g09_executor_operation_digest_is_lowercase_hex() {
        assert_eq!(hex_digest(&[0xab; 32]), "ab".repeat(32));
    }

    #[cfg(unix)]
    #[test]
    fn g09_executor_private_key_requires_owner_only_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iroka-g09-executor-key-{}-{nonce}",
            std::process::id()
        ));
        std::fs::write(&path, b"synthetic-key-material").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_key_is_secure(&path));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!private_key_is_secure(&path));
        std::fs::remove_file(&path).unwrap();
    }
}
