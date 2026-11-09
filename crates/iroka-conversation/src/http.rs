//! Same-origin HTTP transport for the CIW answer-only vertical slice.
//!
//! The transport never constructs a principal. It verifies the compact G01
//! credential from a Secure, HttpOnly cookie, then delegates session,
//! membership and Kernel authorization checks to ConversationService.
//! This deliberately small HTTP/1.1 adapter is intended to sit behind a TLS
//! reverse proxy; it does not terminate TLS itself.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use iroka_kernel::{Ed25519CredentialVerifier, RevocationChecker};
use serde_json::{json, Value};

use crate::{
    AnswerGenerator, Cancellation, ConversationError, ConversationService, KernelAuthorization,
    SessionGuard, StreamEvent, TenantMembership,
};

const MAX_HEADER_BYTES: usize = 24 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024;
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct GenerationState {
    events: Mutex<Vec<StreamEvent>>,
    ready: Condvar,
    done: std::sync::atomic::AtomicBool,
    cancellation: Cancellation,
    created_at: u64,
}
impl GenerationState {
    fn publish(&self, event: StreamEvent) -> Result<(), ConversationError> {
        let terminal = matches!(
            &event,
            StreamEvent::Completed { .. }
                | StreamEvent::Cancelled { .. }
                | StreamEvent::Failed { .. }
        );
        let mut events = self
            .events
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        events.push(event);
        if terminal {
            self.done.store(true, Ordering::Release);
        }
        self.ready.notify_all();
        Ok(())
    }
    fn cancel(&self) {
        self.cancellation.cancel();
    }
}

#[derive(Default)]
struct GenerationHub {
    states: Mutex<HashMap<String, Arc<GenerationState>>>,
}
impl GenerationHub {
    fn insert(&self, id: &str, created_at: u64) -> Result<Arc<GenerationState>, HttpError> {
        let state = Arc::new(GenerationState {
            events: Mutex::new(Vec::new()),
            ready: Condvar::new(),
            done: std::sync::atomic::AtomicBool::new(false),
            cancellation: Cancellation::new(),
            created_at,
        });
        let mut states = self.states.lock().map_err(|_| HttpError::Storage)?;
        if states.len() >= 512 {
            let oldest_completed = states
                .iter()
                .filter(|(_, item)| item.done.load(Ordering::Acquire))
                .min_by_key(|(_, item)| item.created_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest_completed {
                states.remove(&oldest);
            } else {
                return Err(HttpError::Conflict);
            }
        }
        states.insert(id.to_owned(), Arc::clone(&state));
        Ok(state)
    }
    fn get(&self, id: &str) -> Option<Arc<GenerationState>> {
        self.states.lock().ok()?.get(id).cloned()
    }
    fn cancel(&self, id: &str) -> bool {
        if let Some(state) = self.get(id) {
            if state.done.load(Ordering::Acquire) {
                return false;
            }
            state.cancel();
            true
        } else {
            false
        }
    }
}

pub struct G01CookieAuthenticator<R: RevocationChecker> {
    verifier: Ed25519CredentialVerifier<R>,
    audience: String,
}
impl<R: RevocationChecker> G01CookieAuthenticator<R> {
    pub fn new(
        verifier: Ed25519CredentialVerifier<R>,
        audience: impl Into<String>,
    ) -> Result<Self, HttpError> {
        let audience = audience.into();
        if audience.trim().is_empty() {
            return Err(HttpError::Configuration);
        }
        Ok(Self { verifier, audience })
    }

    fn authenticate(
        &self,
        headers: &[(String, String)],
        now: u64,
    ) -> Result<(iroka_kernel::VerifiedPrincipal, String), HttpError> {
        let cookie = header(headers, "cookie").ok_or(HttpError::Unauthenticated)?;
        let credential =
            cookie_value(cookie, "__Host-iroka_credential").ok_or(HttpError::Unauthenticated)?;
        let session =
            cookie_value(cookie, "__Host-iroka_session").ok_or(HttpError::Unauthenticated)?;
        if credential.len() > 16 * 1024 || session.is_empty() || session.len() > 256 {
            return Err(HttpError::Unauthenticated);
        }
        let principal = self
            .verifier
            .authenticate(credential, &self.audience, now)
            .map_err(|_| HttpError::Unauthenticated)?;
        Ok((principal, session.to_owned()))
    }
}

pub struct HttpServer<T, S, A, G, R>
where
    T: TenantMembership + 'static,
    S: SessionGuard + 'static,
    A: KernelAuthorization + Send + Sync + 'static,
    G: AnswerGenerator + 'static,
    R: RevocationChecker + 'static,
{
    service: Arc<ConversationService<T, S, A, G>>,
    authenticator: Arc<G01CookieAuthenticator<R>>,
    generations: Arc<GenerationHub>,
}
impl<T, S, A, G, R> HttpServer<T, S, A, G, R>
where
    T: TenantMembership + 'static,
    S: SessionGuard + 'static,
    A: KernelAuthorization + Send + Sync + 'static,
    G: AnswerGenerator + 'static,
    R: RevocationChecker + 'static,
{
    pub fn new(
        service: Arc<ConversationService<T, S, A, G>>,
        authenticator: Arc<G01CookieAuthenticator<R>>,
    ) -> Self {
        Self {
            service,
            authenticator,
            generations: Arc::new(GenerationHub::default()),
        }
    }

    /// Bind only to an explicitly supplied address. Production deployment must
    /// place this listener behind a TLS proxy and must not expose it publicly.
    pub fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let service = self.service;
        let authenticator = self.authenticator;
        let generations = self.generations;
        for stream in listener.incoming() {
            let stream = stream?;
            let service = Arc::clone(&service);
            let authenticator = Arc::clone(&authenticator);
            let generations = Arc::clone(&generations);
            thread::spawn(move || {
                let _ = handle_connection(stream, service, authenticator, generations);
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    BadRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    TooLarge,
    UnsupportedMedia,
    Storage,
    Configuration,
}
impl HttpError {
    fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::TooLarge => 413,
            Self::UnsupportedMedia => 415,
            Self::Storage | Self::Configuration => 503,
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "BAD_REQUEST",
            Self::Unauthenticated => "AUTH_REQUIRED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::TooLarge => "REQUEST_TOO_LARGE",
            Self::UnsupportedMedia => "UNSUPPORTED_MEDIA_TYPE",
            Self::Storage => "STORAGE_UNAVAILABLE",
            Self::Configuration => "SERVICE_UNAVAILABLE",
        }
    }
}
impl From<ConversationError> for HttpError {
    fn from(error: ConversationError) -> Self {
        match error {
            ConversationError::InvalidInput => Self::BadRequest,
            ConversationError::TenantUnavailable
            | ConversationError::MembershipDenied
            | ConversationError::SessionInvalid
            | ConversationError::AuthorizationDenied => Self::Forbidden,
            ConversationError::NotFound => Self::NotFound,
            ConversationError::Conflict => Self::Conflict,
            ConversationError::StorageUnavailable => Self::Storage,
            ConversationError::BudgetExceeded
            | ConversationError::GenerationFailed
            | ConversationError::Cancelled => Self::Conflict,
        }
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn correlation() -> String {
    format!(
        "http-{}-{}",
        now(),
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}
fn cookie_value<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    cookie
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then_some(value)
        })
        .next()
}
fn read_request(stream: &mut TcpStream) -> Result<Request, HttpError> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|_| HttpError::BadRequest)?;
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let boundary = loop {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(HttpError::TooLarge);
        }
        let n = stream.read(&mut chunk).map_err(|_| HttpError::BadRequest)?;
        if n == 0 {
            return Err(HttpError::BadRequest);
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..boundary]).map_err(|_| HttpError::BadRequest)?;
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or(HttpError::BadRequest)?
        .split_whitespace();
    let method = request_line.next().ok_or(HttpError::BadRequest)?.to_owned();
    let target = request_line.next().ok_or(HttpError::BadRequest)?;
    if request_line.next() != Some("HTTP/1.1")
        || !target.starts_with('/')
        || target.starts_with("//")
    {
        return Err(HttpError::BadRequest);
    }
    let mut target_parts = target.splitn(2, '?');
    let path = target_parts.next().unwrap_or("/").to_owned();
    let query = target_parts.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or(HttpError::BadRequest)?;
        if key.trim().is_empty() {
            return Err(HttpError::BadRequest);
        }
        headers.push((key.trim().to_owned(), value.trim().to_owned()));
    }
    if header(&headers, "transfer-encoding").is_some() {
        return Err(HttpError::BadRequest);
    }
    let length = header(&headers, "content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| HttpError::BadRequest)?;
    if length > MAX_BODY_BYTES {
        return Err(HttpError::TooLarge);
    }
    let start = boundary + 4;
    let mut body = bytes[start..].to_vec();
    if body.len() > length {
        body.truncate(length);
    }
    while body.len() < length {
        let remaining = length - body.len();
        let read_len = remaining.min(chunk.len());
        let n = stream
            .read(&mut chunk[..read_len])
            .map_err(|_| HttpError::BadRequest)?;
        if n == 0 {
            return Err(HttpError::BadRequest);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}
fn write_json(stream: &mut TcpStream, status: u16, body: Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":{\"code\":\"INTERNAL\"}}".to_vec());
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Service Unavailable",
    };
    write!(stream, "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n", bytes.len())?;
    stream.write_all(&bytes)?;
    stream.flush()
}
fn fail(stream: &mut TcpStream, error: HttpError) -> std::io::Result<()> {
    write_json(
        stream,
        error.status(),
        json!({"error":{"code":error.code()}}),
    )
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':')
}
fn body_json(request: &Request) -> Result<Value, HttpError> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    let content_type = header(&request.headers, "content-type").unwrap_or("");
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        return Err(HttpError::UnsupportedMedia);
    }
    serde_json::from_slice(&request.body).map_err(|_| HttpError::BadRequest)
}
fn enforce_same_origin(request: &Request) -> Result<(), HttpError> {
    let origin = header(&request.headers, "origin").ok_or(HttpError::Forbidden)?;
    let host = header(&request.headers, "host").ok_or(HttpError::Forbidden)?;
    let (_, authority) = origin.split_once("://").ok_or(HttpError::Forbidden)?;
    if authority.contains('/') || authority.contains('@') || !authority.eq_ignore_ascii_case(host) {
        return Err(HttpError::Forbidden);
    }
    Ok(())
}
fn handle_connection<T, S, A, G, R>(
    mut stream: TcpStream,
    service: Arc<ConversationService<T, S, A, G>>,
    authenticator: Arc<G01CookieAuthenticator<R>>,
    generations: Arc<GenerationHub>,
) -> std::io::Result<()>
where
    T: TenantMembership + 'static,
    S: SessionGuard + 'static,
    A: KernelAuthorization + Send + Sync + 'static,
    G: AnswerGenerator + 'static,
    R: RevocationChecker + 'static,
{
    let request = match read_request(&mut stream) {
        Ok(r) => r,
        Err(e) => return fail(&mut stream, e),
    };
    if request.method != "GET" && request.method != "POST" {
        return fail(&mut stream, HttpError::BadRequest);
    }
    if request.method == "POST" {
        if let Err(e) = enforce_same_origin(&request) {
            return fail(&mut stream, e);
        }
    }
    let now = now();
    let (principal, session) = match authenticator.authenticate(&request.headers, now) {
        Ok(value) => value,
        Err(error) => return fail(&mut stream, error),
    };
    let correlation_id = correlation();
    if request.method == "POST"
        && request.path.starts_with("/api/v1/conversations/")
        && request.path.ends_with("/turns")
    {
        return start_generation(
            &mut stream,
            service,
            principal,
            session,
            &request,
            &correlation_id,
            now,
            &generations,
        );
    }
    if request.method == "GET" && request.path.starts_with("/api/v1/generations/") {
        return write_sse(
            &mut stream,
            &service,
            &principal,
            &session,
            &request,
            &correlation_id,
            now,
            &generations,
        );
    }
    let result = route(
        &request,
        &service,
        &principal,
        &session,
        &correlation_id,
        now,
        &generations,
    );
    match result {
        Ok((status, body)) => write_json(&mut stream, status, body),
        Err(error) => fail(&mut stream, error),
    }
}

fn route<T, S, A, G>(
    request: &Request,
    service: &ConversationService<T, S, A, G>,
    principal: &iroka_kernel::VerifiedPrincipal,
    session: &str,
    correlation_id: &str,
    now: u64,
    generations: &GenerationHub,
) -> Result<(u16, Value), HttpError>
where
    T: TenantMembership,
    S: SessionGuard,
    A: KernelAuthorization,
    G: AnswerGenerator,
{
    let parts: Vec<&str> = request.path.trim_matches('/').split('/').collect();
    if request.path == "/api/v1/conversations" && request.method == "GET" {
        let items = service
            .list(principal, session, correlation_id, now)
            .map_err(HttpError::from)?;
        return Ok((
            200,
            json!({"conversations": items.iter().map(|c| json!({"id":c.id,"title":c.id,"locale":match c.locale { crate::Locale::Amharic => "am", crate::Locale::English => "en" }})).collect::<Vec<_>>()}),
        ));
    }
    if request.path == "/api/v1/conversations" && request.method == "POST" {
        let body = body_json(request)?;
        let locale = body.get("locale").and_then(Value::as_str);
        let id = format!(
            "c-{}-{}",
            now,
            REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let c = service
            .create(principal, session, &id, locale, correlation_id, now)
            .map_err(HttpError::from)?;
        return Ok((
            201,
            json!({"conversation":{"id":c.id,"locale":match c.locale { crate::Locale::Amharic => "am", crate::Locale::English => "en" }}}),
        ));
    }
    if parts.len() == 5
        && parts[0] == "api"
        && parts[1] == "v1"
        && parts[2] == "conversations"
        && parts[4] == "messages"
        && request.method == "GET"
    {
        let id = parts[3];
        if !valid_id(id) {
            return Err(HttpError::BadRequest);
        }
        let turns = service
            .read(principal, session, id, correlation_id, now)
            .map_err(HttpError::from)?;
        return Ok((
            200,
            json!({"messages":turns.iter().map(|t| json!({"id":t.id,"role":t.role,"text":t.content,"state":t.state,"created_at":t.created_at})).collect::<Vec<_>>()}),
        ));
    }
    if parts.len() == 7
        && parts[0] == "api"
        && parts[1] == "v1"
        && parts[2] == "conversations"
        && parts[4] == "turns"
        && parts[6] == "cancel"
        && request.method == "POST"
    {
        let conversation_id = parts[3];
        let turn_id = parts[5];
        if !valid_id(conversation_id) || !valid_id(turn_id) {
            return Err(HttpError::BadRequest);
        }
        let _ = body_json(request)?;
        let active_generation = generations.cancel(turn_id);
        match service.cancel_turn(
            principal,
            session,
            conversation_id,
            turn_id,
            correlation_id,
            now,
        ) {
            Ok(()) => {}
            Err(ConversationError::Conflict) if active_generation => {}
            Err(error) => return Err(HttpError::from(error)),
        }
        return Ok((200, json!({"cancelled":true})));
    }
    Err(HttpError::NotFound)
}

#[allow(clippy::too_many_arguments)]
fn start_generation<T, S, A, G>(
    stream: &mut TcpStream,
    service: Arc<ConversationService<T, S, A, G>>,
    principal: iroka_kernel::VerifiedPrincipal,
    session: String,
    request: &Request,
    correlation_id: &str,
    now: u64,
    generations: &GenerationHub,
) -> std::io::Result<()>
where
    T: TenantMembership + 'static,
    S: SessionGuard + 'static,
    A: KernelAuthorization + Send + Sync + 'static,
    G: AnswerGenerator + 'static,
{
    let parts: Vec<&str> = request.path.trim_matches('/').split('/').collect();
    if parts.len() != 5
        || parts[0] != "api"
        || parts[1] != "v1"
        || parts[2] != "conversations"
        || parts[4] != "turns"
        || !valid_id(parts[3])
    {
        return fail(stream, HttpError::NotFound);
    }
    let body = match body_json(request) {
        Ok(value) => value,
        Err(error) => return fail(stream, error),
    };
    let prompt = match body.pointer("/input/text").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() && value.len() <= 16 * 1024 => value.to_owned(),
        _ => return fail(stream, HttpError::BadRequest),
    };
    let locale = body
        .get("locale")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let idempotency = match header(&request.headers, "idempotency-key") {
        Some(value) if valid_id(value) => value.to_owned(),
        _ => return fail(stream, HttpError::BadRequest),
    };
    let conversation_id = parts[3].to_owned();
    let turn_id = format!(
        "t-{}-{}",
        now,
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let assistant_id = format!("{turn_id}:assistant");
    let state = match generations.insert(&assistant_id, now) {
        Ok(value) => value,
        Err(error) => return fail(stream, error),
    };
    let service = Arc::clone(&service);
    let session_for_worker = session.clone();
    let correlation_for_worker = correlation_id.to_owned();
    let assistant_id_for_worker = assistant_id.clone();
    let conversation_id_for_worker = conversation_id.clone();
    thread::spawn(move || {
        let state_for_events = Arc::clone(&state);
        let result = service.submit_streaming(
            &principal,
            &session_for_worker,
            &conversation_id_for_worker,
            &turn_id,
            &idempotency,
            &prompt,
            locale.as_deref(),
            &correlation_for_worker,
            now,
            &state.cancellation,
            &mut |event| state_for_events.publish(event),
        );
        if let Err(error) = result {
            let event = if error == ConversationError::Cancelled {
                StreamEvent::Cancelled {
                    turn_id: assistant_id_for_worker.clone(),
                    sequence: 0,
                }
            } else {
                StreamEvent::Failed {
                    turn_id: assistant_id_for_worker.clone(),
                    sequence: 0,
                }
            };
            let _ = state.publish(event);
        }
    });
    write_json(
        stream,
        202,
        json!({
            "turn":{"id":assistant_id},
            "events_url":format!("/api/v1/generations/{assistant_id}/events?conversation_id={conversation_id}")
        }),
    )
}

fn sse_event(event: &StreamEvent) -> Value {
    match event {
        StreamEvent::Accepted { turn_id, sequence } => {
            json!({"type":"generation.accepted","payload":{"turn_id":turn_id,"sequence":sequence}})
        }
        StreamEvent::Delta {
            turn_id,
            sequence,
            text,
        } => {
            json!({"type":"message.delta","payload":{"turn_id":turn_id,"sequence":sequence,"text":text}})
        }
        StreamEvent::Completed { turn_id, sequence } => {
            json!({"type":"generation.completed","payload":{"turn_id":turn_id,"sequence":sequence}})
        }
        StreamEvent::Cancelled { turn_id, sequence } => {
            json!({"type":"generation.interrupted","payload":{"turn_id":turn_id,"sequence":sequence}})
        }
        StreamEvent::Failed { turn_id, sequence } => {
            json!({"type":"generation.failed","payload":{"turn_id":turn_id,"sequence":sequence}})
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_sse<T, S, A, G>(
    stream: &mut TcpStream,
    service: &ConversationService<T, S, A, G>,
    principal: &iroka_kernel::VerifiedPrincipal,
    session: &str,
    request: &Request,
    correlation_id: &str,
    now: u64,
    generations: &GenerationHub,
) -> std::io::Result<()>
where
    T: TenantMembership,
    S: SessionGuard,
    A: KernelAuthorization,
    G: AnswerGenerator,
{
    let parts: Vec<&str> = request.path.trim_matches('/').split('/').collect();
    if parts.len() != 5
        || parts[0] != "api"
        || parts[1] != "v1"
        || parts[2] != "generations"
        || parts[4] != "events"
        || !valid_id(parts[3])
    {
        return fail(stream, HttpError::NotFound);
    }
    let conversation_id = request.query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "conversation_id").then_some(value)
    });
    let Some(conversation_id) = conversation_id.filter(|v| valid_id(v)) else {
        return fail(stream, HttpError::BadRequest);
    };
    let turns = match service.read(principal, session, conversation_id, correlation_id, now) {
        Ok(value) => value,
        Err(error) => return fail(stream, HttpError::from(error)),
    };
    if !turns
        .iter()
        .any(|turn| turn.id == parts[3] && turn.role == "assistant")
    {
        return fail(stream, HttpError::NotFound);
    }
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-store, no-transform\r\nX-Content-Type-Options: nosniff\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n")?;
    if let Some(state) = generations.get(parts[3]) {
        let mut index = 0usize;
        loop {
            let mut events = match state.events.lock() {
                Ok(value) => value,
                Err(_) => return Ok(()),
            };
            let mut heartbeat = false;
            while index >= events.len() && !state.done.load(Ordering::Acquire) {
                let waited = state
                    .ready
                    .wait_timeout(events, std::time::Duration::from_secs(15));
                match waited {
                    Ok((guard, timeout)) => {
                        events = guard;
                        if timeout.timed_out() && index >= events.len() {
                            heartbeat = true;
                            break;
                        }
                    }
                    Err(_) => return Ok(()),
                }
            }
            if heartbeat {
                drop(events);
                stream.write_all(b": keep-alive\n\n")?;
                continue;
            }
            let batch = events[index..].to_vec();
            index += batch.len();
            let caught_up = index == events.len();
            let done = state.done.load(Ordering::Acquire);
            drop(events);
            for event in &batch {
                writeln!(stream, "data: {}\n", sse_event(event))?;
            }
            stream.flush()?;
            if done && caught_up {
                break;
            }
        }
    } else if let Some(turn) = turns.iter().find(|turn| turn.id == parts[3]) {
        if turn.state == "completed" {
            writeln!(
                stream,
                "data: {}\n",
                json!({"type":"message.delta","payload":{"text":turn.content}})
            )?;
            writeln!(
                stream,
                "data: {}\n",
                json!({"type":"generation.completed","payload":{"turn_id":turn.id}})
            )?;
        } else if turn.state == "cancelled" {
            writeln!(
                stream,
                "data: {}\n",
                json!({"type":"generation.interrupted","payload":{"turn_id":turn.id}})
            )?;
        } else {
            writeln!(
                stream,
                "data: {}\n",
                json!({"type":"generation.failed","payload":{"turn_id":turn.id}})
            )?;
        }
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parser_requires_exact_cookie_name() {
        assert_eq!(
            cookie_value(
                "x=1; __Host-iroka_session=session-1; y=2",
                "__Host-iroka_session"
            ),
            Some("session-1")
        );
        assert_eq!(
            cookie_value("not__Host-iroka_session=bad", "__Host-iroka_session"),
            None
        );
    }
    #[test]
    fn identifiers_reject_path_separators_and_control_characters() {
        assert!(valid_id("conversation_123:assistant"));
        assert!(!valid_id("../admin"));
        assert!(!valid_id("a/b"));
        assert!(!valid_id(""));
    }
    #[test]
    fn generation_hub_publishes_terminal_state_and_propagates_cancel() {
        let hub = GenerationHub::default();
        let state = hub.insert("turn-1", 10).unwrap();
        state
            .publish(StreamEvent::Accepted {
                turn_id: "turn-1".into(),
                sequence: 1,
            })
            .unwrap();
        assert!(!state.done.load(Ordering::Acquire));
        assert!(hub.cancel("turn-1"));
        assert!(state.cancellation.is_cancelled());
        state
            .publish(StreamEvent::Cancelled {
                turn_id: "turn-1".into(),
                sequence: 2,
            })
            .unwrap();
        assert!(state.done.load(Ordering::Acquire));
        assert!(!hub.cancel("turn-1"));
    }

    #[test]
    fn sse_delta_preserves_utf8_payload_and_event_type() {
        let value = sse_event(&StreamEvent::Delta {
            turn_id: "turn-1:assistant".into(),
            sequence: 2,
            text: "ሰላም".into(),
        });
        assert_eq!(value["type"], "message.delta");
        assert_eq!(value["payload"]["text"], "ሰላም");
    }
}
