//! Private, bounded TALORA task-service core for IROKA.
//!
//! This is a transport-neutral service boundary. A trusted HTTP adapter must
//! terminate TLS, authenticate the workload, and expose only private routes.
//! No Android endpoint, remote provider, durable task store, or persistent
//! project memory is implemented in this A3 slice. Request text is processed
//! in memory only and is not included in stored task results.

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
pub const CONTRACT_VERSION: &str = "1.0.0";
pub const TASK_SCHEMA_ID: &str = "iroka.talora.task.v1";
pub const RESULT_SCHEMA_ID: &str = "iroka.talora.result.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterClass { FakeLocal, Remote }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    InvalidRequest(&'static str), Unauthorized, Forbidden, PayloadTooLarge,
    Conflict, CapacityExhausted, RemoteProviderDisabled, AdapterFailure,
    SerializationFailure, NotFound, Internal,
}

impl ApiError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) => 400, Self::Unauthorized => 401,
            Self::Forbidden => 403, Self::PayloadTooLarge => 413,
            Self::Conflict => 409, Self::CapacityExhausted => 429,
            Self::RemoteProviderDisabled => 503,
            Self::AdapterFailure | Self::SerializationFailure | Self::Internal => 500,
            Self::NotFound => 404,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    subject: String, audience: String, tenant_ref: String,
    workspace_refs: Vec<String>, project_refs: Vec<String>, scopes: Vec<String>,
}

impl AuthenticatedCaller {
    /// Only trusted authentication code may construct this from verified claims.
    pub fn from_verified_claims(
        subject: impl Into<String>, audience: impl Into<String>, tenant_ref: impl Into<String>,
        workspace_refs: Vec<String>, project_refs: Vec<String>, scopes: Vec<String>,
    ) -> Result<Self, ApiError> {
        let caller = Self {
            subject: subject.into(), audience: audience.into(), tenant_ref: tenant_ref.into(),
            workspace_refs, project_refs, scopes,
        };
        if caller.subject.trim().is_empty() || caller.audience.trim().is_empty()
            || caller.tenant_ref.trim().is_empty() { return Err(ApiError::Unauthorized); }
        Ok(caller)
    }

    pub fn subject(&self) -> &str { &self.subject }

    fn permits(&self, scope: &str, workspace_ref: &str, project_ref: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
            && self.workspace_refs.iter().any(|r| r == workspace_ref)
            && self.project_refs.iter().any(|r| r == project_ref)
    }
}

/// Implementations must verify signature, issuer, audience, expiry, revocation,
/// workload identity and credential rotation before returning a caller.
pub trait WorkloadAuthenticator: Send + Sync {
    fn authenticate(&self, bearer_credential: &str, now_unix_seconds: u64)
        -> Result<AuthenticatedCaller, ApiError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub contract_version: String, pub task_schema_id: String,
    pub client_request_id: String, pub correlation_id: String, pub idempotency_key: String,
    pub tenant_ref: String, pub workspace_ref: String, pub project_ref: String,
    pub capability_id: String, pub capability_version: String, pub task_class: String,
    pub objective: String, pub locale: String,
    #[serde(default)]
    pub input_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    pub input_bytes: usize, pub output_bytes: usize, pub adapter_class: String,
    pub paid_provider_calls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskResponse {
    pub task_schema_id: String, pub result_schema_id: String, pub task_id: String,
    pub client_request_id: String, pub correlation_id: String, pub contract_version: String,
    pub state: String, pub principal_ref: String, pub tenant_ref: String,
    pub workspace_ref: String, pub project_ref: String, pub capability_id: String,
    pub capability_version: String, pub locale: String, pub result_payload: Value,
    pub usage: Usage, pub persistence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub capability_id: String, pub capability_version: String, pub availability: String,
    pub provider_class: String, pub supported_locales: Vec<String>,
    pub max_input_bytes: usize, pub max_output_bytes: usize, pub persistent_memory: bool,
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
    fn class(&self) -> AdapterClass { AdapterClass::FakeLocal }

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
    pub fn new(authenticator: Arc<dyn WorkloadAuthenticator>,
        adapter: Arc<dyn ModelAdapter>) -> Result<Self, ApiError> {
        if adapter.class() != AdapterClass::FakeLocal {
            return Err(ApiError::RemoteProviderDisabled);
        }
        Ok(Self { authenticator, adapter, store: Mutex::new(TaskStore::default()) })
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            capability_id: "talora.dev.fake.v1".into(), capability_version: "1.0.0".into(),
            availability: "development_only".into(), provider_class: "FAKE_LOCAL".into(),
            supported_locales: vec!["am-ET".into(), "en".into()],
            max_input_bytes: MAX_INPUT_BYTES, max_output_bytes: MAX_OUTPUT_BYTES,
            persistent_memory: false,
        }]
    }

    pub fn submit_with_credential(&self, bearer_credential: &str, now_unix_seconds: u64,
        request: TaskRequest) -> Result<TaskResponse, ApiError> {
        let caller = self.authenticator.authenticate(bearer_credential, now_unix_seconds)?;
        self.submit_authenticated(&caller, request)
    }

    /// Called only by a trusted transport adapter after authenticating the workload.
    pub fn submit_authenticated(&self, caller: &AuthenticatedCaller,
        request: TaskRequest) -> Result<TaskResponse, ApiError> {
        validate_request(caller, &request)?;
        let serialized = serde_json::to_vec(&request).map_err(|_| ApiError::SerializationFailure)?;
        let request_digest = sha256_hex(&serialized);
        let key = (caller.tenant_ref.clone(), request.idempotency_key.clone());

        // The fake adapter is bounded and synchronous; holding the lock makes
        // idempotency atomic for concurrent duplicate submissions.
        let mut store = self.store.lock().map_err(|_| ApiError::Internal)?;
        if let Some((existing_digest, response)) = store.by_idempotency.get(&key) {
            return if existing_digest == &request_digest {
                Ok(response.clone())
            } else { Err(ApiError::Conflict) };
        }
        if store.by_task_id.len() >= MAX_TASKS_IN_MEMORY {
            return Err(ApiError::CapacityExhausted);
        }

        let task_id = format!("task_{}",
            &sha256_hex(format!("{}:{}", caller.tenant_ref, request.idempotency_key).as_bytes())[..32]);
        let result_payload = self.adapter.execute(&request)?;
        let output_bytes = serde_json::to_vec(&result_payload)
            .map_err(|_| ApiError::SerializationFailure)?.len();
        if output_bytes > MAX_OUTPUT_BYTES { return Err(ApiError::PayloadTooLarge); }

        let response = TaskResponse {
            task_schema_id: TASK_SCHEMA_ID.into(), result_schema_id: RESULT_SCHEMA_ID.into(),
            task_id: task_id.clone(), client_request_id: request.client_request_id.clone(),
            correlation_id: request.correlation_id.clone(), contract_version: CONTRACT_VERSION.into(),
            state: "completed".into(), principal_ref: caller.subject.clone(),
            tenant_ref: caller.tenant_ref.clone(), workspace_ref: request.workspace_ref.clone(),
            project_ref: request.project_ref.clone(), capability_id: request.capability_id.clone(),
            capability_version: request.capability_version.clone(), locale: request.locale.clone(),
            result_payload,
            usage: Usage { input_bytes: request.input_text.len(), output_bytes,
                adapter_class: "FAKE_LOCAL".into(), paid_provider_calls: 0 },
            persistence: "process_memory_only_ephemeral".into(),
        };
        store.by_idempotency.insert(key, (request_digest, response.clone()));
        store.by_task_id.insert(task_id, response.clone());
        Ok(response)
    }

    pub fn get_task(&self, caller: &AuthenticatedCaller, task_id: &str)
        -> Result<TaskResponse, ApiError> {
        if !caller.scopes.iter().any(|s| s == "talora.tasks.read") {
            return Err(ApiError::Forbidden);
        }
        let store = self.store.lock().map_err(|_| ApiError::Internal)?;
        let response = store.by_task_id.get(task_id).ok_or(ApiError::NotFound)?;
        if response.tenant_ref != caller.tenant_ref
            || !caller.permits("talora.tasks.read", &response.workspace_ref, &response.project_ref) {
            return Err(ApiError::Forbidden);
        }
        Ok(response.clone())
    }
}

fn validate_request(caller: &AuthenticatedCaller, request: &TaskRequest) -> Result<(), ApiError> {
    for (value, name) in [
        (&request.client_request_id, "client_request_id"),
        (&request.correlation_id, "correlation_id"),
        (&request.idempotency_key, "idempotency_key"), (&request.tenant_ref, "tenant_ref"),
        (&request.workspace_ref, "workspace_ref"), (&request.project_ref, "project_ref"),
        (&request.capability_id, "capability_id"), (&request.capability_version, "capability_version"),
        (&request.task_class, "task_class"), (&request.objective, "objective"),
        (&request.locale, "locale"),
    ] {
        if value.trim().is_empty() { return Err(ApiError::InvalidRequest(name)); }
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
        || request.task_class.len() > MAX_REFERENCE_BYTES || request.locale.len() > 32 {
        return Err(ApiError::PayloadTooLarge);
    }
    if request.objective.len() > MAX_OBJECTIVE_BYTES || request.input_text.len() > MAX_INPUT_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    if request.tenant_ref != caller.tenant_ref { return Err(ApiError::Forbidden); }
    if !caller.permits("talora.tasks.submit", &request.workspace_ref, &request.project_ref) {
        return Err(ApiError::Forbidden);
    }
    if request.capability_id != "talora.dev.fake.v1" || request.capability_version != "1.0.0" {
        return Err(ApiError::InvalidRequest("capability_unavailable"));
    }
    if request.locale != "am-ET" && request.locale != "en" {
        return Err(ApiError::InvalidRequest("locale_not_supported"));
    }
    Ok(())
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
        fn authenticate(&self, credential: &str, _now: u64)
            -> Result<AuthenticatedCaller, ApiError> {
            if credential != "test-only-token" { return Err(ApiError::Unauthorized); }
            AuthenticatedCaller::from_verified_claims("service:talora-test", "iroka-talora-api",
                "tenant:test", vec!["workspace:test".into()], vec!["project:test".into()],
                vec!["talora.tasks.submit".into(), "talora.tasks.read".into()])
        }
    }

    fn request() -> TaskRequest {
        TaskRequest {
            contract_version: CONTRACT_VERSION.into(), task_schema_id: TASK_SCHEMA_ID.into(),
            client_request_id: "client-1".into(), correlation_id: "corr-1".into(),
            idempotency_key: "idem-1".into(), tenant_ref: "tenant:test".into(),
            workspace_ref: "workspace:test".into(), project_ref: "project:test".into(),
            capability_id: "talora.dev.fake.v1".into(), capability_version: "1.0.0".into(),
            task_class: "development".into(), objective: "Check a sample script".into(),
            locale: "am-ET".into(), input_text: "sample creative text".into(),
        }
    }

    fn service() -> TaskService {
        TaskService::new(Arc::new(TestAuthenticator), Arc::new(DeterministicFakeAdapter)).unwrap()
    }

    #[test]
    fn only_fake_local_is_advertised_and_memory_is_disabled() {
        let capability = &service().capabilities()[0];
        assert_eq!(capability.provider_class, "FAKE_LOCAL");
        assert!(!capability.persistent_memory);
    }

    #[test]
    fn invalid_workload_credentials_are_rejected() {
        assert_eq!(service().submit_with_credential("bad-token", 1, request()),
            Err(ApiError::Unauthorized));
    }

    #[test]
    fn fake_execution_is_explicit_and_has_zero_paid_calls() {
        let result = service().submit_with_credential("test-only-token", 1, request()).unwrap();
        assert_eq!(result.state, "completed");
        assert_eq!(result.usage.paid_provider_calls, 0);
        assert_eq!(result.usage.adapter_class, "FAKE_LOCAL");
        assert_eq!(result.result_payload["inference_performed"], false);
        assert_eq!(result.persistence, "process_memory_only_ephemeral");
    }

    #[test]
    fn idempotent_replay_returns_the_original_result() {
        let service = service();
        let first = service.submit_with_credential("test-only-token", 1, request()).unwrap();
        let replay = service.submit_with_credential("test-only-token", 2, request()).unwrap();
        assert_eq!(first, replay);
    }

    #[test]
    fn changed_payload_with_same_idempotency_key_conflicts() {
        let service = service();
        service.submit_with_credential("test-only-token", 1, request()).unwrap();
        let mut changed = request();
        changed.objective = "Different objective".into();
        assert_eq!(service.submit_with_credential("test-only-token", 1, changed),
            Err(ApiError::Conflict));
    }

    #[test]
    fn cross_tenant_and_unscoped_projects_are_denied() {
        let service = service();
        let mut changed = request();
        changed.tenant_ref = "tenant:other".into();
        assert_eq!(service.submit_with_credential("test-only-token", 1, changed),
            Err(ApiError::Forbidden));
        let mut changed = request();
        changed.project_ref = "project:other".into();
        assert_eq!(service.submit_with_credential("test-only-token", 1, changed),
            Err(ApiError::Forbidden));
    }

    #[test]
    fn oversized_input_and_unsupported_locale_are_rejected() {
        let service = service();
        let mut oversized = request();
        oversized.input_text = "x".repeat(MAX_INPUT_BYTES + 1);
        assert_eq!(service.submit_with_credential("test-only-token", 1, oversized),
            Err(ApiError::PayloadTooLarge));
        let mut unsupported = request();
        unsupported.locale = "xx".into();
        assert_eq!(service.submit_with_credential("test-only-token", 1, unsupported),
            Err(ApiError::InvalidRequest("locale_not_supported")));
    }

    #[test]
    fn task_reads_are_scoped_to_authorized_project() {
        let service = service();
        let result = service.submit_with_credential("test-only-token", 1, request()).unwrap();
        let caller = TestAuthenticator.authenticate("test-only-token", 1).unwrap();
        assert_eq!(service.get_task(&caller, &result.task_id), Ok(result));
    }
}
