//! Private, bounded TALORA task-service core for IROKA.
//!
//! This is a transport-neutral service boundary. A trusted HTTP adapter must
//! terminate TLS, authenticate the workload, and expose only private routes.
//! No Android endpoint, remote provider, durable task store, or persistent
//! project memory is implemented in this A3 slice. Request text is processed
//! in memory only and is not included in stored task results.

use iroka_kernel::{
    evaluate as evaluate_policy, AuthorizationRequest, Decision, DecisionCode, Policy, RiskLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const API_PREFIX: &str = "/api/v1";
pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_OBJECTIVE_BYTES: usize = 4_096;
pub const MAX_OUTPUT_BYTES: usize = 16_384;
pub const MAX_TASKS_IN_MEMORY: usize = 128;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MAX_REFERENCE_BYTES: usize = 256;
pub const MAX_TASK_TTL_SECONDS: u64 = 300;
pub const MAX_INPUT_REFERENCES: usize = 16;
pub const CONTRACT_VERSION: &str = "1.0.0";
pub const TASK_SCHEMA_ID: &str = "iroka.talora.task.v1";
pub const RESULT_SCHEMA_ID: &str = "iroka.talora.result.v1";
pub const TALORA_POLICY_VERSION: &str = "talora-dev-policy-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterClass {
    FakeLocal,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    InvalidRequest(&'static str),
    Unauthorized,
    Forbidden,
    PayloadTooLarge,
    Conflict,
    CapacityExhausted,
    RemoteProviderDisabled,
    AdapterFailure,
    SerializationFailure,
    NotFound,
    Internal,
}

impl ApiError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::PayloadTooLarge => 413,
            Self::Conflict => 409,
            Self::CapacityExhausted => 429,
            Self::RemoteProviderDisabled => 503,
            Self::AdapterFailure | Self::SerializationFailure | Self::Internal => 500,
            Self::NotFound => 404,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    subject: String,
    audience: String,
    tenant_ref: String,
    workspace_refs: Vec<String>,
    project_refs: Vec<String>,
    scopes: Vec<String>,
}

impl AuthenticatedCaller {
    /// Only trusted authentication code may construct this from verified claims.
    pub fn from_verified_claims(
        subject: impl Into<String>,
        audience: impl Into<String>,
        tenant_ref: impl Into<String>,
        workspace_refs: Vec<String>,
        project_refs: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<Self, ApiError> {
        let caller = Self {
            subject: subject.into(),
            audience: audience.into(),
            tenant_ref: tenant_ref.into(),
            workspace_refs,
            project_refs,
            scopes,
        };
        if caller.subject.trim().is_empty()
            || caller.audience.trim().is_empty()
            || caller.tenant_ref.trim().is_empty()
        {
            return Err(ApiError::Unauthorized);
        }
        Ok(caller)
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }

    fn permits(&self, scope: &str, workspace_ref: &str, project_ref: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
            && self.workspace_refs.iter().any(|r| r == workspace_ref)
            && self.project_refs.iter().any(|r| r == project_ref)
    }
}

/// Implementations must verify signature, issuer, audience, expiry, revocation,
/// workload identity and credential rotation before returning a caller.
pub trait WorkloadAuthenticator: Send + Sync {
    fn authenticate(
        &self,
        bearer_credential: &str,
        now_unix_seconds: u64,
    ) -> Result<AuthenticatedCaller, ApiError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputReference {
    pub source_ref: String,
    pub classification: String,
    pub purpose: String,
    pub revision_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskConstraints {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub deadline_unix_seconds: u64,
    pub max_iterations: u32,
    pub allow_remote_provider: bool,
    pub allow_persistent_memory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub contract_version: String,
    pub task_schema_id: String,
    pub client_request_id: String,
    pub correlation_id: String,
    pub idempotency_key: String,
    pub tenant_ref: String,
    pub workspace_ref: String,
    pub project_ref: String,
    pub capability_id: String,
    pub capability_version: String,
    pub task_class: String,
    pub objective: String,
    pub locale: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub consent_ref: String,
    pub authorization_ref: String,
    pub policy_ref: String,
    pub output_schema_id: String,
    pub input_refs: Vec<InputReference>,
    pub required_evidence: Vec<String>,
    pub constraints: TaskConstraints,
    pub document_ref: Option<String>,
    pub document_revision: Option<String>,
    pub calendar: Option<String>,
    #[serde(default)]
    pub input_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub adapter_class: String,
    pub paid_provider_calls: u32,
    pub estimated_cost_etb_micros: u64,
    pub actual_cost_etb_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskResponse {
    pub task_schema_id: String,
    pub result_schema_id: String,
    pub task_id: String,
    pub client_request_id: String,
    pub correlation_id: String,
    pub contract_version: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: String,
    pub principal_ref: String,
    pub tenant_ref: String,
    pub workspace_ref: String,
    pub project_ref: String,
    pub capability_id: String,
    pub capability_version: String,
    pub policy_version: String,
    pub consent_ref: String,
    pub authorization_ref: String,
    pub policy_ref: String,
    pub output_schema_id: String,
    pub document_ref: Option<String>,
    pub document_revision: Option<String>,
    pub calendar: Option<String>,
    pub input_source_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub assumptions: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub verification_status: String,
    pub locale: String,
    pub result_payload: Value,
    pub usage: Usage,
    pub persistence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub capability_id: String,
    pub capability_version: String,
    pub availability: String,
    pub provider_class: String,
    pub supported_locales: Vec<String>,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub persistent_memory: bool,
}

pub trait ModelAdapter: Send + Sync {
    fn class(&self) -> AdapterClass;
    fn execute(&self, request: &TaskRequest) -> Result<Value, ApiError>;
}

/// Deterministic development/test adapter. It performs no generative inference
/// and neither echoes nor retains the supplied creative text.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicFakeAdapter;

impl ModelAdapter for DeterministicFakeAdapter {
    fn class(&self) -> AdapterClass {
        AdapterClass::FakeLocal
    }

    fn execute(&self, request: &TaskRequest) -> Result<Value, ApiError> {
        Ok(json!({
            "mode": "FAKE_LOCAL",
            "inference_performed": false,
            "message": "Deterministic fake adapter completed; no generative inference was performed.",
            "capability_id": request.capability_id,
            "locale": request.locale,
            "input_sha256": sha256_hex(request.input_text.as_bytes()),
            "suggestions": []
        }))
    }
}

#[derive(Default)]
struct TaskStore {
    by_idempotency: HashMap<(String, String), (String, TaskResponse)>,
    by_task_id: HashMap<String, TaskResponse>,
}

/// Bounded process-local task service. No task or creative content is written to disk.
pub struct TaskService {
    authenticator: Arc<dyn WorkloadAuthenticator>,
    adapter: Arc<dyn ModelAdapter>,
    store: Mutex<TaskStore>,
}

impl TaskService {
    pub fn new(
        authenticator: Arc<dyn WorkloadAuthenticator>,
        adapter: Arc<dyn ModelAdapter>,
    ) -> Result<Self, ApiError> {
        if adapter.class() != AdapterClass::FakeLocal {
            return Err(ApiError::RemoteProviderDisabled);
        }
        Ok(Self {
            authenticator,
            adapter,
            store: Mutex::new(TaskStore::default()),
        })
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            capability_id: "talora.dev.fake.v1".into(),
            capability_version: "1.0.0".into(),
            availability: "development_only".into(),
            provider_class: "FAKE_LOCAL".into(),
            supported_locales: vec!["am-ET".into(), "en".into()],
            max_input_bytes: MAX_INPUT_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
            persistent_memory: false,
        }]
    }

    pub fn submit_with_credential(
        &self,
        bearer_credential: &str,
        now_unix_seconds: u64,
        request: TaskRequest,
    ) -> Result<TaskResponse, ApiError> {
        let caller = self
            .authenticator
            .authenticate(bearer_credential, now_unix_seconds)?;
        self.submit_authenticated(&caller, request, now_unix_seconds)
    }

    /// Called only by a trusted transport adapter after authenticating the workload.
    pub fn submit_authenticated(
        &self,
        caller: &AuthenticatedCaller,
        request: TaskRequest,
        now_unix_seconds: u64,
    ) -> Result<TaskResponse, ApiError> {
        if caller.audience != "iroka-talora-api" {
            return Err(ApiError::Unauthorized);
        }
        validate_request(caller, &request, now_unix_seconds)?;
        let serialized =
            serde_json::to_vec(&request).map_err(|_| ApiError::SerializationFailure)?;
        let request_digest = sha256_hex(&serialized);
        let key = (caller.tenant_ref.clone(), request.idempotency_key.clone());

        // The fake adapter is bounded and synchronous; holding the lock makes
        // idempotency atomic for concurrent duplicate submissions.
        let mut store = self.store.lock().map_err(|_| ApiError::Internal)?;
        if let Some((existing_digest, response)) = store.by_idempotency.get(&key) {
            return if existing_digest == &request_digest {
                Ok(response.clone())
            } else {
                Err(ApiError::Conflict)
            };
        }
        if store.by_task_id.len() >= MAX_TASKS_IN_MEMORY {
            return Err(ApiError::CapacityExhausted);
        }

        let task_id = format!(
            "task_{}",
            &sha256_hex(format!("{}:{}", caller.tenant_ref, request.idempotency_key).as_bytes())
                [..32]
        );
        let result_payload = self.adapter.execute(&request)?;
        let output_bytes = serde_json::to_vec(&result_payload)
            .map_err(|_| ApiError::SerializationFailure)?
            .len();
        if output_bytes > request.constraints.max_output_bytes || output_bytes > MAX_OUTPUT_BYTES {
            return Err(ApiError::PayloadTooLarge);
        }

        let response = TaskResponse {
            task_schema_id: TASK_SCHEMA_ID.into(),
            result_schema_id: RESULT_SCHEMA_ID.into(),
            task_id: task_id.clone(),
            client_request_id: request.client_request_id.clone(),
            correlation_id: request.correlation_id.clone(),
            contract_version: CONTRACT_VERSION.into(),
            created_at: request.created_at,
            expires_at: request.expires_at,
            state: "completed".into(),
            principal_ref: caller.subject.clone(),
            tenant_ref: caller.tenant_ref.clone(),
            workspace_ref: request.workspace_ref.clone(),
            project_ref: request.project_ref.clone(),
            capability_id: request.capability_id.clone(),
            capability_version: request.capability_version.clone(),
            policy_version: TALORA_POLICY_VERSION.into(),
            consent_ref: request.consent_ref.clone(),
            authorization_ref: request.authorization_ref.clone(),
            policy_ref: request.policy_ref.clone(),
            output_schema_id: request.output_schema_id.clone(),
            document_ref: request.document_ref.clone(),
            document_revision: request.document_revision.clone(),
            calendar: request.calendar.clone(),
            input_source_refs: request
                .input_refs
                .iter()
                .map(|input| input.source_ref.clone())
                .collect(),
            evidence_refs: Vec::new(),
            assumptions: vec![
                "Deterministic fake adapter; no generative inference performed.".into(),
            ],
            unresolved_questions: Vec::new(),
            verification_status: "not_ai_validated_fake_adapter".into(),
            locale: request.locale.clone(),
            result_payload,
            usage: Usage {
                input_bytes: request.input_text.len(),
                output_bytes,
                adapter_class: "FAKE_LOCAL".into(),
                paid_provider_calls: 0,
                estimated_cost_etb_micros: 0,
                actual_cost_etb_micros: 0,
            },
            persistence: "process_memory_only_ephemeral".into(),
        };
        store
            .by_idempotency
            .insert(key, (request_digest, response.clone()));
        store.by_task_id.insert(task_id, response.clone());
        Ok(response)
    }

    pub fn get_task(
        &self,
        caller: &AuthenticatedCaller,
        task_id: &str,
    ) -> Result<TaskResponse, ApiError> {
        if caller.audience != "iroka-talora-api" {
            return Err(ApiError::Unauthorized);
        }
        if !caller.scopes.iter().any(|s| s == "talora.tasks.read") {
            return Err(ApiError::Forbidden);
        }
        let store = self.store.lock().map_err(|_| ApiError::Internal)?;
        let response = store.by_task_id.get(task_id).ok_or(ApiError::NotFound)?;
        if response.tenant_ref != caller.tenant_ref
            || !caller.permits(
                "talora.tasks.read",
                &response.workspace_ref,
                &response.project_ref,
            )
        {
            return Err(ApiError::Forbidden);
        }
        Ok(response.clone())
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Execute the private HTTP route contract without owning a network listener.
/// The hosting adapter remains responsible for TLS, loopback binding,
/// trusted-proxy configuration, request deadlines and connection limits.
pub fn route_http(
    service: &TaskService,
    request: HttpRequest,
    now_unix_seconds: u64,
) -> HttpResponse {
    if request.method == "GET" && request.path == "/api/v1/health/live" {
        return json_response(200, json!({"status":"live"}));
    }
    if request.method == "GET" && request.path == "/api/v1/health/ready" {
        return json_response(200, json!({"status":"ready","profile":"development_only"}));
    }

    let bearer = match header(&request.headers, "authorization")
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, credential)| {
            scheme.eq_ignore_ascii_case("bearer") && !credential.trim().is_empty()
        })
        .map(|(_, credential)| credential)
    {
        Some(value) => value,
        None => return error_response(ApiError::Unauthorized),
    };

    if request.method == "GET" && request.path == "/api/v1/capabilities" {
        let caller = match service.authenticator.authenticate(bearer, now_unix_seconds) {
            Ok(caller) => caller,
            Err(error) => return error_response(error),
        };
        if caller.audience != "iroka-talora-api" {
            return error_response(ApiError::Unauthorized);
        }
        if !caller
            .scopes
            .iter()
            .any(|scope| scope == "talora.capabilities.read")
        {
            return error_response(ApiError::Forbidden);
        }
        return json_response(
            200,
            json!({
                "contract_version": CONTRACT_VERSION,
                "capabilities": service.capabilities()
            }),
        );
    }

    if request.method == "POST" && request.path == "/api/v1/tasks" {
        if request.body.len() > MAX_INPUT_BYTES + 16_384 {
            return error_response(ApiError::PayloadTooLarge);
        }
        if !header(&request.headers, "content-type")
            .map(|value| value.to_ascii_lowercase().starts_with("application/json"))
            .unwrap_or(false)
        {
            return error_response(ApiError::InvalidRequest(
                "content_type_must_be_application_json",
            ));
        }
        let task: TaskRequest = match serde_json::from_slice(&request.body) {
            Ok(task) => task,
            Err(_) => return error_response(ApiError::InvalidRequest("invalid_task_json")),
        };
        return match service.submit_with_credential(bearer, now_unix_seconds, task) {
            Ok(result) => {
                let task_id = result.task_id.clone();
                json_response(
                    202,
                    json!({
                        "task_id": task_id,
                        "state": result.state,
                        "status_url": format!("/api/v1/tasks/{task_id}"),
                        "events_url": format!("/api/v1/tasks/{task_id}/events"),
                        "result": result
                    }),
                )
            }
            Err(error) => error_response(error),
        };
    }

    if request.method == "GET"
        && request.path.starts_with("/api/v1/tasks/")
        && request.path.ends_with("/events")
    {
        let task_id = request
            .path
            .strip_prefix("/api/v1/tasks/")
            .and_then(|value| value.strip_suffix("/events"))
            .unwrap_or("");
        if task_id.is_empty() || task_id.contains('/') {
            return error_response(ApiError::NotFound);
        }
        let caller = match service.authenticator.authenticate(bearer, now_unix_seconds) {
            Ok(caller) => caller,
            Err(error) => return error_response(error),
        };
        return match service.get_task(&caller, task_id) {
            Ok(result) => {
                let payload = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
                let mut headers = HashMap::new();
                headers.insert("content-type".into(), "text/event-stream".into());
                headers.insert("cache-control".into(), "no-store".into());
                HttpResponse {
                    status: 200,
                    headers,
                    body: format!("event: completed\ndata: {payload}\n\n").into_bytes(),
                }
            }
            Err(error) => error_response(error),
        };
    }

    if request.method == "POST"
        && request.path.starts_with("/api/v1/tasks/")
        && request.path.ends_with("/cancel")
    {
        let task_id = request
            .path
            .strip_prefix("/api/v1/tasks/")
            .and_then(|value| value.strip_suffix("/cancel"))
            .unwrap_or("");
        if task_id.is_empty() || task_id.contains('/') {
            return error_response(ApiError::NotFound);
        }
        let caller = match service.authenticator.authenticate(bearer, now_unix_seconds) {
            Ok(caller) => caller,
            Err(error) => return error_response(error),
        };
        return match service.get_task(&caller, task_id) {
            Ok(_) => error_response(ApiError::Conflict),
            Err(error) => error_response(error),
        };
    }

    if request.method == "GET" && request.path.starts_with("/api/v1/tasks/") {
        let task_id = &request.path["/api/v1/tasks/".len()..];
        if task_id.is_empty() || task_id.contains('/') {
            return error_response(ApiError::NotFound);
        }
        let caller = match service.authenticator.authenticate(bearer, now_unix_seconds) {
            Ok(caller) => caller,
            Err(error) => return error_response(error),
        };
        return match service.get_task(&caller, task_id) {
            Ok(result) => json_response(200, serde_json::to_value(result).unwrap_or(Value::Null)),
            Err(error) => error_response(error),
        };
    }

    error_response(ApiError::NotFound)
}

fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn json_response(status: u16, value: Value) -> HttpResponse {
    let body = serde_json::to_vec(&value)
        .unwrap_or_else(|_| b"{\"error\":\"serialization_failure\"}".to_vec());
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".into(),
        "application/json; charset=utf-8".into(),
    );
    headers.insert("cache-control".into(), "no-store".into());
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn error_response(error: ApiError) -> HttpResponse {
    let code = match error {
        ApiError::InvalidRequest(_) => "invalid_request",
        ApiError::Unauthorized => "unauthorized",
        ApiError::Forbidden => "forbidden",
        ApiError::PayloadTooLarge => "payload_too_large",
        ApiError::Conflict => "idempotency_conflict",
        ApiError::CapacityExhausted => "capacity_exhausted",
        ApiError::RemoteProviderDisabled => "remote_provider_disabled",
        ApiError::AdapterFailure => "adapter_failure",
        ApiError::SerializationFailure => "serialization_failure",
        ApiError::NotFound => "not_found",
        ApiError::Internal => "internal_error",
    };
    json_response(error.http_status(), json!({"error":code}))
}

fn validate_request(
    caller: &AuthenticatedCaller,
    request: &TaskRequest,
    now_unix_seconds: u64,
) -> Result<(), ApiError> {
    for (value, name) in [
        (&request.client_request_id, "client_request_id"),
        (&request.correlation_id, "correlation_id"),
        (&request.idempotency_key, "idempotency_key"),
        (&request.tenant_ref, "tenant_ref"),
        (&request.workspace_ref, "workspace_ref"),
        (&request.project_ref, "project_ref"),
        (&request.capability_id, "capability_id"),
        (&request.capability_version, "capability_version"),
        (&request.task_class, "task_class"),
        (&request.objective, "objective"),
        (&request.locale, "locale"),
        (&request.consent_ref, "consent_ref"),
        (&request.authorization_ref, "authorization_ref"),
        (&request.policy_ref, "policy_ref"),
        (&request.output_schema_id, "output_schema_id"),
    ] {
        if value.trim().is_empty() {
            return Err(ApiError::InvalidRequest(name));
        }
    }
    if request.contract_version != CONTRACT_VERSION || request.task_schema_id != TASK_SCHEMA_ID {
        return Err(ApiError::InvalidRequest("unsupported_contract_or_schema"));
    }
    if request.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || request.client_request_id.len() > MAX_REFERENCE_BYTES
        || request.correlation_id.len() > MAX_REFERENCE_BYTES
        || request.tenant_ref.len() > MAX_REFERENCE_BYTES
        || request.workspace_ref.len() > MAX_REFERENCE_BYTES
        || request.project_ref.len() > MAX_REFERENCE_BYTES
        || request.capability_id.len() > MAX_REFERENCE_BYTES
        || request.capability_version.len() > MAX_REFERENCE_BYTES
        || request.task_class.len() > MAX_REFERENCE_BYTES
        || request.locale.len() > 32
        || request.consent_ref.len() > MAX_REFERENCE_BYTES
        || request.authorization_ref.len() > MAX_REFERENCE_BYTES
        || request.policy_ref.len() > MAX_REFERENCE_BYTES
        || request.output_schema_id.len() > MAX_REFERENCE_BYTES
        || request
            .document_ref
            .as_ref()
            .is_some_and(|value| value.len() > MAX_REFERENCE_BYTES)
        || request
            .document_revision
            .as_ref()
            .is_some_and(|value| value.len() > MAX_REFERENCE_BYTES)
        || request
            .calendar
            .as_ref()
            .is_some_and(|value| value.len() > 32)
    {
        return Err(ApiError::PayloadTooLarge);
    }
    if request.objective.len() > MAX_OBJECTIVE_BYTES || request.input_text.len() > MAX_INPUT_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    if request.created_at > now_unix_seconds
        || request.expires_at <= now_unix_seconds
        || request.expires_at <= request.created_at
        || request.expires_at - request.created_at > MAX_TASK_TTL_SECONDS
        || request.constraints.deadline_unix_seconds <= now_unix_seconds
        || request.constraints.deadline_unix_seconds > request.expires_at
    {
        return Err(ApiError::InvalidRequest("invalid_task_expiry_or_deadline"));
    }
    if request.constraints.max_input_bytes > MAX_INPUT_BYTES
        || request.constraints.max_input_bytes < request.input_text.len()
        || request.constraints.max_output_bytes == 0
        || request.constraints.max_output_bytes > MAX_OUTPUT_BYTES
        || request.constraints.max_iterations != 1
    {
        return Err(ApiError::PayloadTooLarge);
    }
    if request.constraints.allow_remote_provider || request.constraints.allow_persistent_memory {
        return Err(ApiError::Forbidden);
    }
    if request.policy_ref != TALORA_POLICY_VERSION || request.output_schema_id != RESULT_SCHEMA_ID {
        return Err(ApiError::InvalidRequest("policy_or_output_schema_mismatch"));
    }
    if request.input_refs.is_empty() || request.input_refs.len() > MAX_INPUT_REFERENCES {
        return Err(ApiError::InvalidRequest(
            "input_references_required_or_excessive",
        ));
    }
    for input in &request.input_refs {
        if input.source_ref.trim().is_empty()
            || input.purpose.trim().is_empty()
            || input.source_ref.len() > MAX_REFERENCE_BYTES
            || input.purpose.len() > MAX_REFERENCE_BYTES
            || input.classification != "synthetic"
            || input.revision_digest.len() != 64
            || !input
                .revision_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ApiError::Forbidden);
        }
    }
    if request.required_evidence.len() > 32 {
        return Err(ApiError::PayloadTooLarge);
    }
    if !request.required_evidence.is_empty() {
        return Err(ApiError::InvalidRequest(
            "fake_adapter_cannot_satisfy_required_evidence",
        ));
    }
    if request.document_ref.is_some() != request.document_revision.is_some()
        || request
            .document_ref
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || request
            .document_revision
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
    {
        return Err(ApiError::InvalidRequest(
            "document_reference_revision_mismatch",
        ));
    }
    if request.tenant_ref != caller.tenant_ref {
        return Err(ApiError::Forbidden);
    }
    if !caller.permits(
        "talora.tasks.submit",
        &request.workspace_ref,
        &request.project_ref,
    ) {
        return Err(ApiError::Forbidden);
    }
    if request.capability_id != "talora.dev.fake.v1" || request.capability_version != "1.0.0" {
        return Err(ApiError::InvalidRequest("capability_unavailable"));
    }
    if request.locale != "am-ET" && request.locale != "en" {
        return Err(ApiError::InvalidRequest("locale_not_supported"));
    }
    if evaluate_capability_policy(caller, request).code() != DecisionCode::Allow {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn evaluate_capability_policy(caller: &AuthenticatedCaller, request: &TaskRequest) -> Decision {
    let policy = Policy::new(
        TALORA_POLICY_VERSION,
        vec!["talora.dev.fake.v1".into()],
        Vec::new(),
        RiskLevel::Low,
    );
    let authorization = AuthorizationRequest::new(
        caller.subject(),
        request.capability_id.clone(),
        request.project_ref.clone(),
        RiskLevel::Low,
    );
    evaluate_policy(&authorization, &policy, false)
}

fn sha256_hex(bytes: &[u8]) -> String {
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

    struct TestAuthenticator;
    impl WorkloadAuthenticator for TestAuthenticator {
        fn authenticate(
            &self,
            credential: &str,
            _now: u64,
        ) -> Result<AuthenticatedCaller, ApiError> {
            if credential != "test-only-token" {
                return Err(ApiError::Unauthorized);
            }
            AuthenticatedCaller::from_verified_claims(
                "service:talora-test",
                "iroka-talora-api",
                "tenant:test",
                vec!["workspace:test".into()],
                vec!["project:test".into()],
                vec![
                    "talora.tasks.submit".into(),
                    "talora.tasks.read".into(),
                    "talora.capabilities.read".into(),
                ],
            )
        }
    }

    fn request() -> TaskRequest {
        TaskRequest {
            contract_version: CONTRACT_VERSION.into(),
            task_schema_id: TASK_SCHEMA_ID.into(),
            client_request_id: "client-1".into(),
            correlation_id: "corr-1".into(),
            idempotency_key: "idem-1".into(),
            tenant_ref: "tenant:test".into(),
            workspace_ref: "workspace:test".into(),
            project_ref: "project:test".into(),
            capability_id: "talora.dev.fake.v1".into(),
            capability_version: "1.0.0".into(),
            task_class: "development".into(),
            objective: "Check a sample script".into(),
            locale: "am-ET".into(),
            created_at: 1,
            expires_at: 100,
            consent_ref: "consent:test".into(),
            authorization_ref: "authorization:test".into(),
            policy_ref: TALORA_POLICY_VERSION.into(),
            output_schema_id: RESULT_SCHEMA_ID.into(),
            input_refs: vec![InputReference {
                source_ref: "synthetic:script-1".into(),
                classification: "synthetic".into(),
                purpose: "development-test".into(),
                revision_digest: "a".repeat(64),
            }],
            required_evidence: Vec::new(),
            constraints: TaskConstraints {
                max_input_bytes: MAX_INPUT_BYTES,
                max_output_bytes: MAX_OUTPUT_BYTES,
                deadline_unix_seconds: 90,
                max_iterations: 1,
                allow_remote_provider: false,
                allow_persistent_memory: false,
            },
            document_ref: Some("document:test".into()),
            document_revision: Some("revision:1".into()),
            calendar: Some("ethiopian".into()),
            input_text: "sample creative text".into(),
        }
    }

    fn service() -> TaskService {
        TaskService::new(
            Arc::new(TestAuthenticator),
            Arc::new(DeterministicFakeAdapter),
        )
        .unwrap()
    }

    #[test]
    fn only_fake_local_is_advertised_and_memory_is_disabled() {
        let capability = &service().capabilities()[0];
        assert_eq!(capability.provider_class, "FAKE_LOCAL");
        assert!(!capability.persistent_memory);
    }

    #[test]
    fn invalid_workload_credentials_are_rejected() {
        assert_eq!(
            service().submit_with_credential("bad-token", 1, request()),
            Err(ApiError::Unauthorized)
        );
    }

    #[test]
    fn fake_execution_is_explicit_and_has_zero_paid_calls() {
        let result = service()
            .submit_with_credential("test-only-token", 1, request())
            .unwrap();
        assert_eq!(result.state, "completed");
        assert_eq!(result.usage.paid_provider_calls, 0);
        assert_eq!(result.usage.adapter_class, "FAKE_LOCAL");
        assert_eq!(result.result_payload["inference_performed"], false);
        assert_eq!(result.persistence, "process_memory_only_ephemeral");
    }

    #[test]
    fn idempotent_replay_returns_the_original_result() {
        let service = service();
        let first = service
            .submit_with_credential("test-only-token", 1, request())
            .unwrap();
        let replay = service
            .submit_with_credential("test-only-token", 2, request())
            .unwrap();
        assert_eq!(first, replay);
    }

    #[test]
    fn changed_payload_with_same_idempotency_key_conflicts() {
        let service = service();
        service
            .submit_with_credential("test-only-token", 1, request())
            .unwrap();
        let mut changed = request();
        changed.objective = "Different objective".into();
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, changed),
            Err(ApiError::Conflict)
        );
    }

    #[test]
    fn cross_tenant_and_unscoped_projects_are_denied() {
        let service = service();
        let mut changed = request();
        changed.tenant_ref = "tenant:other".into();
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, changed),
            Err(ApiError::Forbidden)
        );
        let mut changed = request();
        changed.project_ref = "project:other".into();
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, changed),
            Err(ApiError::Forbidden)
        );
    }

    #[test]
    fn oversized_input_and_unsupported_locale_are_rejected() {
        let service = service();
        let mut oversized = request();
        oversized.input_text = "x".repeat(MAX_INPUT_BYTES + 1);
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, oversized),
            Err(ApiError::PayloadTooLarge)
        );
        let mut unsupported = request();
        unsupported.locale = "xx".into();
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, unsupported),
            Err(ApiError::InvalidRequest("locale_not_supported"))
        );
    }

    #[test]
    fn private_http_routes_require_auth_and_disable_caching() {
        let service = service();
        let live = route_http(
            &service,
            HttpRequest {
                method: "GET".into(),
                path: "/api/v1/health/live".into(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
            1,
        );
        assert_eq!(live.status, 200);
        assert_eq!(
            live.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );

        let denied = route_http(
            &service,
            HttpRequest {
                method: "GET".into(),
                path: "/api/v1/capabilities".into(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
            1,
        );
        assert_eq!(denied.status, 401);
    }

    #[test]
    fn private_http_task_route_uses_authenticated_service() {
        let service = service();
        let body = serde_json::to_vec(&request()).unwrap();
        let response = route_http(
            &service,
            HttpRequest {
                method: "POST".into(),
                path: "/api/v1/tasks".into(),
                headers: HashMap::from([
                    ("authorization".into(), "Bearer test-only-token".into()),
                    ("content-type".into(), "application/json".into()),
                ]),
                body,
            },
            1,
        );
        assert_eq!(response.status, 202);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("FAKE_LOCAL"));
        assert!(body.contains("status_url"));
    }

    #[test]
    fn rejects_expired_tasks_and_production_data_classification() {
        let service = service();
        let mut expired = request();
        expired.expires_at = 1;
        assert_eq!(
            service.submit_with_credential("test-only-token", 2, expired),
            Err(ApiError::InvalidRequest("invalid_task_expiry_or_deadline"))
        );

        let mut production = request();
        production.input_refs[0].classification = "private".into();
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, production),
            Err(ApiError::Forbidden)
        );
    }

    #[test]
    fn rejects_remote_provider_persistence_and_unverifiable_evidence_requests() {
        let service = service();
        let mut remote = request();
        remote.constraints.allow_remote_provider = true;
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, remote),
            Err(ApiError::Forbidden)
        );

        let mut persistent = request();
        persistent.constraints.allow_persistent_memory = true;
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, persistent),
            Err(ApiError::Forbidden)
        );

        let mut evidence = request();
        evidence.required_evidence.push("source-proof".into());
        assert_eq!(
            service.submit_with_credential("test-only-token", 1, evidence),
            Err(ApiError::InvalidRequest(
                "fake_adapter_cannot_satisfy_required_evidence"
            ))
        );
    }

    #[test]
    fn private_http_routes_support_capabilities_status_events_and_cancel() {
        let service = service();
        let capability_response = route_http(
            &service,
            HttpRequest {
                method: "GET".into(),
                path: "/api/v1/capabilities".into(),
                headers: HashMap::from([("Authorization".into(), "bEaReR test-only-token".into())]),
                body: Vec::new(),
            },
            1,
        );
        assert_eq!(capability_response.status, 200);

        let submitted = route_http(
            &service,
            HttpRequest {
                method: "POST".into(),
                path: "/api/v1/tasks".into(),
                headers: HashMap::from([
                    ("Authorization".into(), "Bearer test-only-token".into()),
                    (
                        "Content-Type".into(),
                        "application/json; charset=utf-8".into(),
                    ),
                ]),
                body: serde_json::to_vec(&request()).unwrap(),
            },
            1,
        );
        assert_eq!(submitted.status, 202);
        let submission: Value = serde_json::from_slice(&submitted.body).unwrap();
        let task_id = submission["task_id"].as_str().unwrap();

        let status = route_http(
            &service,
            HttpRequest {
                method: "GET".into(),
                path: format!("/api/v1/tasks/{task_id}"),
                headers: HashMap::from([("Authorization".into(), "Bearer test-only-token".into())]),
                body: Vec::new(),
            },
            1,
        );
        assert_eq!(status.status, 200);

        let events = route_http(
            &service,
            HttpRequest {
                method: "GET".into(),
                path: format!("/api/v1/tasks/{task_id}/events"),
                headers: HashMap::from([("Authorization".into(), "Bearer test-only-token".into())]),
                body: Vec::new(),
            },
            1,
        );
        assert_eq!(events.status, 200);
        assert!(String::from_utf8(events.body)
            .unwrap()
            .contains("event: completed\n"));

        let cancelled = route_http(
            &service,
            HttpRequest {
                method: "POST".into(),
                path: format!("/api/v1/tasks/{task_id}/cancel"),
                headers: HashMap::from([("Authorization".into(), "Bearer test-only-token".into())]),
                body: Vec::new(),
            },
            1,
        );
        assert_eq!(cancelled.status, 409);
    }

    #[test]
    fn task_reads_are_scoped_to_authorized_project() {
        let service = service();
        let result = service
            .submit_with_credential("test-only-token", 1, request())
            .unwrap();
        let caller = TestAuthenticator
            .authenticate("test-only-token", 1)
            .unwrap();
        assert_eq!(service.get_task(&caller, &result.task_id), Ok(result));
    }
}
