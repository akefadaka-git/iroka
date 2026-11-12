//! HTTPS adapters for the frozen external checkpoint witness/retention protocol.
//! Provider receipts are not trusted here: callers must pass them through the
//! offline Ed25519 quorum verifier before considering a checkpoint anchored.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use native_tls::TlsConnector;
use serde::de::DeserializeOwned;
use serde::Serialize;

use iroka_kernel::{
    CheckpointPackage, CheckpointQuorumError, CheckpointWitnessProvider,
    ImmutableRetentionProvider, RetentionReceipt, WitnessReceipt,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BYTES: usize = 64 * 1_024;
const MAX_RESPONSE_BYTES: usize = 16 * 1_024;
const MAX_RESPONSE_HEADERS: usize = 32;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1_024;

struct HttpsJsonEndpoint {
    host: String,
    port: u16,
    host_header: String,
    path: String,
    bearer_token: String,
}

impl HttpsJsonEndpoint {
    fn new(url: &str, bearer_token: &str) -> Result<Self, CheckpointQuorumError> {
        let rest = url.strip_prefix("https://")
            .ok_or(CheckpointQuorumError::InvalidPolicy)?;
        if rest.contains('@') || rest.contains('?') || rest.contains('#')
            || bearer_token.trim().is_empty()
            || bearer_token.len() > 4_096
            || bearer_token.bytes().any(|b| !b.is_ascii_graphic())
        {
            return Err(CheckpointQuorumError::InvalidPolicy);
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() || path.contains('\r') || path.contains('\n') {
            return Err(CheckpointQuorumError::InvalidPolicy);
        }
        let (host, port) = if authority.starts_with('[') {
            let end = authority.find(']').ok_or(CheckpointQuorumError::InvalidPolicy)?;
            let host = &authority[1..end];
            let suffix = &authority[end + 1..];
            let port = if suffix.is_empty() {
                443
            } else {
                suffix.strip_prefix(':')
                    .ok_or(CheckpointQuorumError::InvalidPolicy)?
                    .parse::<u16>()
                    .map_err(|_| CheckpointQuorumError::InvalidPolicy)?
            };
            (host, port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.contains(':') {
                return Err(CheckpointQuorumError::InvalidPolicy);
            }
            (host, port.parse::<u16>().map_err(|_| CheckpointQuorumError::InvalidPolicy)?)
        } else {
            (authority, 443)
        };
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || host.bytes().any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':'))
        {
            return Err(CheckpointQuorumError::InvalidPolicy);
        }
        let path = if path.is_empty() { "/".to_owned() } else { format!("/{path}") };
        if path.len() > 2_048 || path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(CheckpointQuorumError::InvalidPolicy);
        }
        let host_header = if port == 443 {
            authority.to_owned()
        } else {
            format!("{authority}")
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            host_header,
            path,
            bearer_token: bearer_token.to_owned(),
        })
    }

    fn post_json<T: Serialize, R: DeserializeOwned>(&self, body: &T) -> Result<R, CheckpointQuorumError> {
        let request_body = serde_json::to_vec(body)
            .map_err(|_| CheckpointQuorumError::Malformed)?;
        if request_body.is_empty() || request_body.len() > MAX_REQUEST_BYTES {
            return Err(CheckpointQuorumError::Malformed);
        }
        let addresses = (self.host.as_str(), self.port).to_socket_addrs()
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        let mut stream = None;
        for address in addresses {
            if let Ok(connection) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                stream = Some(connection);
                break;
            }
        }
        let mut stream = stream.ok_or(CheckpointQuorumError::ProviderUnavailable)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        stream.set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        let tls = TlsConnector::new().map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        let mut tls_stream = tls.connect(&self.host, stream)
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host_header,
            self.bearer_token,
            request_body.len(),
        );
        tls_stream.write_all(request.as_bytes())
            .and_then(|_| tls_stream.write_all(&request_body))
            .and_then(|_| tls_stream.flush())
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;

        let mut reader = BufReader::new(tls_stream);
        let status_line = read_crlf_line(&mut reader, 4_096)?;
        let mut status_parts = status_line.split_whitespace();
        let version = status_parts.next().ok_or(CheckpointQuorumError::ProviderUnavailable)?;
        let status = status_parts.next().and_then(|s| s.parse::<u16>().ok())
            .ok_or(CheckpointQuorumError::ProviderUnavailable)?;
        if version != "HTTP/1.1" || (status != 200 && status != 201) {
            // Redirects are deliberately not followed: credentials and signed
            // evidence must never be forwarded to an unconfigured origin.
            return Err(CheckpointQuorumError::ProviderUnavailable);
        }
        let mut headers = std::collections::HashMap::new();
        let mut total = status_line.len();
        let mut terminated = false;
        for _ in 0..MAX_RESPONSE_HEADERS {
            let line = read_crlf_line(&mut reader, 4_096)?;
            total = total.saturating_add(line.len());
            if total > MAX_RESPONSE_HEADER_BYTES {
                return Err(CheckpointQuorumError::ProviderUnavailable);
            }
            if line.is_empty() {
                terminated = true;
                break;
            }
            let (name, value) = line.split_once(':')
                .ok_or(CheckpointQuorumError::ProviderUnavailable)?;
            let name = name.to_ascii_lowercase();
            if headers.insert(name, value.trim().to_owned()).is_some() {
                return Err(CheckpointQuorumError::ProviderUnavailable);
            }
        }
        if !terminated || headers.contains_key("transfer-encoding")
            || !headers.get("content-type").map_or(false, |v|
                v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(CheckpointQuorumError::ProviderUnavailable);
        }
        let length = headers.get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0 && *n <= MAX_RESPONSE_BYTES)
            .ok_or(CheckpointQuorumError::ProviderUnavailable)?;
        let mut response_body = vec![0; length];
        reader.read_exact(&mut response_body)
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        serde_json::from_slice(&response_body)
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)
    }
}

fn read_crlf_line(reader: &mut impl BufRead, limit: usize) -> Result<String, CheckpointQuorumError> {
    let mut bytes = Vec::new();
    let mut saw_cr = false;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)
            .map_err(|_| CheckpointQuorumError::ProviderUnavailable)?;
        if byte[0] == b'\n' {
            if !saw_cr {
                return Err(CheckpointQuorumError::ProviderUnavailable);
            }
            break;
        }
        if saw_cr {
            return Err(CheckpointQuorumError::ProviderUnavailable);
        }
        if byte[0] == b'\r' {
            saw_cr = true;
            continue;
        }
        if bytes.len() >= limit {
            return Err(CheckpointQuorumError::ProviderUnavailable);
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).map_err(|_| CheckpointQuorumError::ProviderUnavailable)
}

pub struct HttpsCheckpointWitnessProvider {
    endpoint: HttpsJsonEndpoint,
}

impl HttpsCheckpointWitnessProvider {
    pub fn new(url: &str, bearer_token: &str) -> Result<Self, CheckpointQuorumError> {
        Ok(Self { endpoint: HttpsJsonEndpoint::new(url, bearer_token)? })
    }
}

impl CheckpointWitnessProvider for HttpsCheckpointWitnessProvider {
    fn attest(&self, package: &CheckpointPackage) -> Result<WitnessReceipt, CheckpointQuorumError> {
        self.endpoint.post_json(package)
    }
}

pub struct HttpsImmutableRetentionProvider {
    endpoint: HttpsJsonEndpoint,
}

impl HttpsImmutableRetentionProvider {
    pub fn new(url: &str, bearer_token: &str) -> Result<Self, CheckpointQuorumError> {
        Ok(Self { endpoint: HttpsJsonEndpoint::new(url, bearer_token)? })
    }
}

#[derive(Serialize)]
struct RetentionRequest<'a> {
    package: &'a CheckpointPackage,
    witness_receipts: &'a [WitnessReceipt],
}

impl ImmutableRetentionProvider for HttpsImmutableRetentionProvider {
    fn retain(
        &self,
        package: &CheckpointPackage,
        witness_receipts: &[WitnessReceipt],
    ) -> Result<RetentionReceipt, CheckpointQuorumError> {
        self.endpoint.post_json(&RetentionRequest { package, witness_receipts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_provider_endpoints_reject_plaintext_and_credential_forwarding_tricks() {
        assert!(HttpsJsonEndpoint::new("http://witness.example/v1/attest", "secret").is_err());
        assert!(HttpsJsonEndpoint::new("https://user@witness.example/v1/attest", "secret").is_err());
        assert!(HttpsJsonEndpoint::new("https://witness.example/v1/attest?next=other", "secret").is_err());
        assert!(HttpsJsonEndpoint::new("https://witness.example/v1/attest", "bad\r\nHost:evil").is_err());
    }

    #[test]
    fn https_provider_endpoint_parses_default_and_explicit_ports() {
        let default = HttpsJsonEndpoint::new("https://witness.example/v1/attest", "secret").unwrap();
        assert_eq!(default.host, "witness.example");
        assert_eq!(default.port, 443);
        assert_eq!(default.path, "/v1/attest");
        let explicit = HttpsJsonEndpoint::new("https://witness.example:9443/v1/attest", "secret").unwrap();
        assert_eq!(explicit.port, 9443);
    }
}
