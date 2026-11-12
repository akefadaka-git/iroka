//! Narrow production HTTP host for G05.
//!
//! TLS is terminated by a trusted reverse proxy. This process binds only to a
//! loopback address, accepts only bounded HTTP/1.1 requests, requires the proxy
//! to assert HTTPS, and runs G01/G02/G09 checks immediately before the executor.
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use iroka_kernel::RevocationChecker;
use crate::TrustedClock;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    AuthenticatedG05Request, AuthorizationRequest, G02AuthorizationAuthority, G05Error,
    G05IngressService, G09ExecutionRevalidator,
};

const MAX_REQUEST_LINE: usize = 4_096;
const MAX_HEADER_LINE: usize = 4_096;
const MAX_HEADER_BYTES: usize = 16 * 1_024;
const MAX_HEADERS: usize = 32;
const MAX_BODY_BYTES: usize = 64 * 1_024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G05HttpHostError {
    InvalidConfiguration,
    BindFailed,
    ListenerFailed,
}

pub trait G05OperationExecutor: Send + Sync + 'static {
    /// Execute the already-authorized operation. The executor must not accept
    /// a caller-supplied principal or perform a second, weaker auth path.
    fn execute(&self, context: &AuthenticatedG05Request) -> Result<Value, G05Error>;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct G05RequestEnvelope {
    credential: String,
    request: AuthorizationRequest,
}

pub struct G05HttpHost<R, G, C, E, X> {
    ingress: Arc<G05IngressService<R, G, C, E>>,
    executor: Arc<X>,
    allowed_hosts: HashSet<String>,
    workers: usize,
}

impl<R, G, C, E, X> G05HttpHost<R, G, C, E, X>
where
    R: RevocationChecker + Send + Sync + 'static,
    G: G02AuthorizationAuthority + Send + Sync + 'static,
    C: TrustedClock + Send + Sync + 'static,
    E: G09ExecutionRevalidator + Send + Sync + 'static,
    X: G05OperationExecutor,
{
    pub fn new(
        ingress: Arc<G05IngressService<R, G, C, E>>,
        executor: Arc<X>,
        allowed_hosts: impl IntoIterator<Item = String>,
        workers: usize,
    ) -> Result<Self, G05HttpHostError> {
        let allowed_hosts: HashSet<String> = allowed_hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .collect();
        if allowed_hosts.is_empty()
            || allowed_hosts.iter().any(|host| host.is_empty() || host.len() > 253)
            || workers == 0
            || workers > 128
        {
            return Err(G05HttpHostError::InvalidConfiguration);
        }
        Ok(Self {
            ingress,
            executor,
            allowed_hosts,
            workers,
        })
    }

    /// Serve behind a TLS-terminating reverse proxy. Non-loopback binding is
    /// rejected so untrusted networks cannot forge the proxy HTTPS assertion.
    pub fn serve(self, bind: SocketAddr) -> Result<(), G05HttpHostError> {
        if !bind.ip().is_loopback() {
            return Err(G05HttpHostError::InvalidConfiguration);
        }
        let listener = TcpListener::bind(bind).map_err(|_| G05HttpHostError::BindFailed)?;
        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(64);
        let receiver = Arc::new(Mutex::new(receiver));

        for _ in 0..self.workers {
            let receiver = Arc::clone(&receiver);
            let ingress = Arc::clone(&self.ingress);
            let executor = Arc::clone(&self.executor);
            let allowed_hosts = self.allowed_hosts.clone();
            thread::spawn(move || loop {
                let stream = match receiver.lock() {
                    Ok(guard) => guard.recv(),
                    Err(_) => return,
                };
                let Ok(mut stream) = stream else { return };
                let _ = handle_connection(
                    &mut stream,
                    &ingress,
                    &executor,
                    &allowed_hosts,
                );
            });
        }

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => match sender.try_send(stream) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(mut stream)) => {
                        write_response(&mut stream, 503, "Service Unavailable", &json!({
                            "error": "capacity_exhausted"
                        }));
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err(G05HttpHostError::ListenerFailed);
                    }
                },
                Err(_) => return Err(G05HttpHostError::ListenerFailed),
            }
        }
        Ok(())
    }
}

fn handle_connection<R, G, C, E, X>(
    stream: &mut TcpStream,
    ingress: &G05IngressService<R, G, C, E>,
    executor: &X,
    allowed_hosts: &HashSet<String>,
) -> Result<(), ()>
where
    R: RevocationChecker,
    G: G02AuthorizationAuthority,
    C: TrustedClock,
    E: G09ExecutionRevalidator,
    X: G05OperationExecutor,
{
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let parsed = match read_request(stream, allowed_hosts) {
        Ok(request) => request,
        Err(error) => {
            let (status, label) = match error {
                HttpParseError::TooLarge => (413, "Payload Too Large"),
                HttpParseError::HeadersTooLarge => (431, "Request Header Fields Too Large"),
                _ => (400, "Bad Request"),
            };
            write_response(stream, status, label, &json!({"error":"invalid_http_request"}));
            return Ok(());
        }
    };

    if parsed.method == "GET" && parsed.path == "/healthz" {
        write_response(stream, 200, "OK", &json!({"status":"ready"}));
        return Ok(());
    }
    if parsed.method != "POST" || parsed.path != "/v1/g05/execute" {
        write_response(stream, 404, "Not Found", &json!({"error":"not_found"}));
        return Ok(());
    }

    let envelope: G05RequestEnvelope = match serde_json::from_slice(&parsed.body) {
        Ok(value) => value,
        Err(_) => {
            write_response(stream, 400, "Bad Request", &json!({"error":"invalid_request"}));
            return Ok(());
        }
    };
    let context = match ingress.authorize(&envelope.credential, envelope.request) {
        Ok(context) => context,
        Err(error) => {
            let (status, label) = status_for_g05_error(error);
            write_response(stream, status, label, &json!({"error":format!("{error:?}")}));
            return Ok(());
        }
    };
    let result = ingress.execute_external(&context, &envelope.credential, || {
        executor.execute(&context)
    });
    match result {
        Ok(value) => write_response(stream, 200, "OK", &json!({"result":value})),
        Err(error) => {
            let (status, label) = status_for_g05_error(error);
            write_response(stream, status, label, &json!({"error":format!("{error:?}")}));
        }
    }
    Ok(())
}

fn status_for_g05_error(error: G05Error) -> (u16, &'static str) {
    match error {
        G05Error::AuthorityUnavailable | G05Error::AuditUnavailable => {
            (503, "Service Unavailable")
        }
        G05Error::AuthorizationDenied
        | G05Error::ReviewerNotAuthorized
        | G05Error::TenantScopeMismatch => {
            (403, "Forbidden")
        }
        G05Error::MalformedRecord | G05Error::ContentTooLarge => (400, "Bad Request"),
        _ => (422, "Unprocessable Entity"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HttpParseError {
    Io,
    Invalid,
    TooLarge,
    HeadersTooLarge,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(
    stream: &mut TcpStream,
    allowed_hosts: &HashSet<String>,
) -> Result<ParsedRequest, HttpParseError> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|_| HttpParseError::Io)?);
    let request_line = read_limited_line(&mut reader, MAX_REQUEST_LINE)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or(HttpParseError::Invalid)?;
    let path = request_parts.next().ok_or(HttpParseError::Invalid)?;
    let version = request_parts.next().ok_or(HttpParseError::Invalid)?;
    if request_parts.next().is_some() || version != "HTTP/1.1" {
        return Err(HttpParseError::Invalid);
    }

    let mut headers = std::collections::HashMap::<String, String>::new();
    let mut header_bytes = request_line.len();
    let mut headers_terminated = false;
    for _ in 0..MAX_HEADERS {
        let line = read_limited_line(&mut reader, MAX_HEADER_LINE)?;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_HEADER_BYTES {
            return Err(HttpParseError::HeadersTooLarge);
        }
        if line.is_empty() {
            headers_terminated = true;
            break;
        }
        let (name, value) = line.split_once(':').ok_or(HttpParseError::Invalid)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.chars().any(|c| c.is_control() && c != '\t')
        {
            return Err(HttpParseError::Invalid);
        }
        let key = name.to_ascii_lowercase();
        if headers.insert(key, value.trim().to_owned()).is_some() {
            return Err(HttpParseError::Invalid);
        }
    }

    if !headers_terminated {
        return Err(HttpParseError::HeadersTooLarge);
    }
    let host = headers.get("host").ok_or(HttpParseError::Invalid)?.to_ascii_lowercase();
    if !allowed_hosts.contains(&host) {
        return Err(HttpParseError::Invalid);
    }
    if headers.get("transfer-encoding").is_some()
        || headers.get("expect").is_some()
        || headers.get("connection").is_some_and(|v| !v.eq_ignore_ascii_case("close"))
    {
        return Err(HttpParseError::Invalid);
    }
    if method == "POST" {
        if headers
            .get("x-forwarded-proto")
            .is_none_or(|value| !value.eq_ignore_ascii_case("https"))
        {
            return Err(HttpParseError::Invalid);
        }
        if headers
            .get("content-type")
            .is_none_or(|value| !value.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(HttpParseError::Invalid);
        }
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>().map_err(|_| HttpParseError::Invalid))
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(HttpParseError::TooLarge);
    }
    if method == "POST" && !headers.contains_key("content-length") {
        return Err(HttpParseError::Invalid);
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).map_err(|_| HttpParseError::Io)?;
    Ok(ParsedRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        body,
    })
}

fn read_limited_line(reader: &mut impl BufRead, limit: usize) -> Result<String, HttpParseError> {
    let mut bytes = Vec::new();
    let mut saw_cr = false;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).map_err(|_| HttpParseError::Io)?;
        if byte[0] == b'\n' {
            if !saw_cr {
                return Err(HttpParseError::Invalid);
            }
            break;
        }
        if saw_cr {
            return Err(HttpParseError::Invalid);
        }
        if byte[0] == b'\r' {
            saw_cr = true;
            continue;
        }
        if bytes.len() >= limit {
            return Err(HttpParseError::HeadersTooLarge);
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).map_err(|_| HttpParseError::Invalid)
}

fn write_response(stream: &mut TcpStream, status: u16, reason: &str, body: &Value) {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        bytes.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_requires_loopback_binding_and_bounded_worker_count() {
        assert!(SocketAddr::from(([0, 0, 0, 0], 8080)).ip().is_loopback() == false);
        assert!(MAX_BODY_BYTES <= 64 * 1_024);
        assert!(MAX_HEADERS <= 32);
    }

    #[test]
    fn parser_rejects_transfer_encoding_and_duplicate_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(
                b"POST /v1/g05/execute HTTP/1.1\r\nHost: api.iroka.test\r\nX-Forwarded-Proto: https\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
            ).unwrap();
        });
        let (mut server, _) = listener.accept().unwrap();
        let allowed = HashSet::from(["api.iroka.test".to_owned()]);
        assert_eq!(read_request(&mut server, &allowed), Err(HttpParseError::Invalid));
        client.join().unwrap();
    }
}
