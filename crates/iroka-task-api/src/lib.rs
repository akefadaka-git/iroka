//! First-party task lifecycle service.
//! Task records persist only operational metadata and digests. Inputs, prompts,
//! outputs and credentials are never written by this crate.
use iroka_kernel::VerifiedPrincipal;
use native_tls::TlsConnector;
use postgres::{Client, Row};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

pub const TASK_CONTRACT_VERSION: &str = "1.0.0";
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MAX_TASK_REF_BYTES: usize = 256;
pub const MAX_EVENT_PAGE: usize = 100;
pub const MAX_TASK_TTL_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskApiError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    CapacityUnavailable,
    AuthorityUnavailable,
    RepositoryUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Accepted,
    Queued,
    Running,
    AwaitingAuthorization,
    Succeeded,
    Failed,
    CancelRequested,
    Cancelled,
    Expired,
}

impl TaskState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::AwaitingAuthorization => "awaiting_authorization",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::CancelRequested => "cancel_requested",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, TaskApiError> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "awaiting_authorization" => Ok(Self::AwaitingAuthorization),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancel_requested" => Ok(Self::CancelRequested),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            _ => Err(TaskApiError::RepositoryUnavailable),
        }
    }

    fn permits(self, next: Self) -> bool {
        use TaskState as S;
        matches!(
            (self, next),
            (S::Accepted, S::Queued)
                | (S::Accepted, S::AwaitingAuthorization)
                | (S::Accepted, S::Failed)
                | (S::Accepted, S::Cancelled)
                | (S::Queued, S::Running)
                | (S::Queued, S::CancelRequested)
                | (S::Queued, S::Cancelled)
                | (S::Queued, S::Failed)
                | (S::Queued, S::Expired)
                | (S::Running, S::AwaitingAuthorization)
                | (S::Running, S::Succeeded)
                | (S::Running, S::Failed)
                | (S::Running, S::CancelRequested)
                | (S::AwaitingAuthorization, S::Queued)
                | (S::AwaitingAuthorization, S::Failed)
                | (S::AwaitingAuthorization, S::Cancelled)
                | (S::AwaitingAuthorization, S::Expired)
                | (S::CancelRequested, S::Cancelled)
        )
    }

    fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskSubmission {
    pub tenant_selector: String,
    pub idempotency_key: String,
    pub client_request_id: String,
    pub correlation_id: String,
    pub capability_id: String,
    pub capability_version: String,
    pub expires_at: u64,
    /// Opaque source references only. No prompt or document body is accepted.
    pub input_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task_id: String,
    pub tenant_ref: String,
    pub principal_ref: String,
    pub capability_id: String,
    pub capability_version: String,
    pub policy_version: String,
    pub idempotency_key: String,
    pub request_sha256: String,
    pub correlation_id: String,
    pub client_request_id: String,
    pub state: TaskState,
    pub task_version: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub result_ref: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEvent {
    pub task_id: String,
    pub sequence: u64,
    pub event_id: String,
    pub event_type: String,
    pub state: TaskState,
    pub task_version: u64,
    pub actor_ref: String,
    pub occurred_at: u64,
    /// Content-free, allowlisted operational metadata.
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorization {
    pub tenant_ref: String,
    pub policy_version: String,
}

pub trait TaskAuthorizer: Send + Sync {
    /// Must derive tenant membership and capability permission from current
    /// G02/G09 server-side authority. The tenant selector is untrusted input.
    fn authorize_submit(
        &self,
        principal: &VerifiedPrincipal,
        request: &TaskSubmission,
        now: u64,
    ) -> Result<TaskAuthorization, TaskApiError>;

    fn authorize_read(
        &self,
        principal: &VerifiedPrincipal,
        task: &TaskRecord,
        now: u64,
    ) -> Result<(), TaskApiError>;

    fn authorize_cancel(
        &self,
        principal: &VerifiedPrincipal,
        task: &TaskRecord,
        now: u64,
    ) -> Result<(), TaskApiError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskTransition {
    pub task_id: String,
    pub expected_version: u64,
    pub next_state: TaskState,
    pub actor_ref: String,
    pub occurred_at: u64,
    pub metadata: Value,
    pub result_ref: Option<String>,
    pub error_code: Option<String>,
}

pub trait TaskRepository: Send + Sync {
    fn create(&self, task: &TaskRecord, initial_event: &TaskEvent)
        -> Result<(TaskRecord, bool), TaskApiError>;
    fn get(&self, task_id: &str) -> Result<Option<TaskRecord>, TaskApiError>;
    fn transition(&self, change: TaskTransition) -> Result<TaskRecord, TaskApiError>;
    fn events(
        &self,
        task_id: &str,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<TaskEvent>, TaskApiError>;
}

pub struct TaskService<R, A> {
    repository: R,
    authorizer: A,
}

impl<R: TaskRepository, A: TaskAuthorizer> TaskService<R, A> {
    pub fn new(repository: R, authorizer: A) -> Self {
        Self { repository, authorizer }
    }

    pub fn submit(
        &self,
        principal: &VerifiedPrincipal,
        request: TaskSubmission,
        now: u64,
    ) -> Result<(TaskRecord, bool), TaskApiError> {
        validate_submission(&request, now)?;
        let authorization = self.authorizer.authorize_submit(principal, &request, now)?;
        if authorization.tenant_ref.trim().is_empty()
            || authorization.policy_version.trim().is_empty()
            || authorization.tenant_ref != request.tenant_selector
        {
            return Err(TaskApiError::Forbidden);
        }
        let request_sha256 = request_digest(&request)?;
        let task_id = digest_hex(
            format!("{}:{}:{}", authorization.tenant_ref, principal.subject(), request.idempotency_key)
                .as_bytes(),
        );
        let task = TaskRecord {
            task_id: format!("task_{}", &task_id[..32]),
            tenant_ref: authorization.tenant_ref,
            principal_ref: principal.subject().to_owned(),
            capability_id: request.capability_id,
            capability_version: request.capability_version,
            policy_version: authorization.policy_version,
            idempotency_key: request.idempotency_key,
            request_sha256,
            correlation_id: request.correlation_id,
            client_request_id: request.client_request_id,
            state: TaskState::Accepted,
            task_version: 1,
            created_at: now,
            updated_at: now,
            expires_at: request.expires_at,
            result_ref: None,
            error_code: None,
        };
        let event = TaskEvent {
            task_id: task.task_id.clone(),
            sequence: 1,
            event_id: format!("{}:event:1", task.task_id),
            event_type: "task.accepted".into(),
            state: TaskState::Accepted,
            task_version: 1,
            actor_ref: principal.subject().to_owned(),
            occurred_at: now,
            metadata: json!({"contract_version": TASK_CONTRACT_VERSION}),
        };
        self.repository.create(&task, &event)
    }

    pub fn get(
        &self,
        principal: &VerifiedPrincipal,
        task_id: &str,
        now: u64,
    ) -> Result<TaskRecord, TaskApiError> {
        let task = self.repository.get(task_id)?.ok_or(TaskApiError::NotFound)?;
        self.authorizer.authorize_read(principal, &task, now)?;
        Ok(task)
    }

    pub fn events(
        &self,
        principal: &VerifiedPrincipal,
        task_id: &str,
        after_sequence: u64,
        limit: usize,
        now: u64,
    ) -> Result<Vec<TaskEvent>, TaskApiError> {
        if limit == 0 || limit > MAX_EVENT_PAGE {
            return Err(TaskApiError::InvalidRequest);
        }
        let task = self.repository.get(task_id)?.ok_or(TaskApiError::NotFound)?;
        self.authorizer.authorize_read(principal, &task, now)?;
        self.repository.events(task_id, after_sequence, limit)
    }

    pub fn cancel(
        &self,
        principal: &VerifiedPrincipal,
        task_id: &str,
        now: u64,
    ) -> Result<TaskRecord, TaskApiError> {
        let task = self.repository.get(task_id)?.ok_or(TaskApiError::NotFound)?;
        self.authorizer.authorize_cancel(principal, &task, now)?;
        let next = match task.state {
            TaskState::Accepted | TaskState::Queued | TaskState::AwaitingAuthorization => {
                TaskState::Cancelled
            }
            TaskState::Running => TaskState::CancelRequested,
            state if state.terminal() || state == TaskState::CancelRequested => {
                return Err(TaskApiError::Conflict);
            }
            _ => return Err(TaskApiError::Conflict),
        };
        self.repository.transition(TaskTransition {
            task_id: task_id.to_owned(),
            expected_version: task.task_version,
            next_state: next,
            actor_ref: principal.subject().to_owned(),
            occurred_at: now,
            metadata: json!({"reason_code":"caller_cancelled"}),
            result_ref: None,
            error_code: None,
        })
    }
}

fn validate_submission(request: &TaskSubmission, now: u64) -> Result<(), TaskApiError> {
    for value in [
        request.tenant_selector.as_str(),
        request.idempotency_key.as_str(),
        request.client_request_id.as_str(),
        request.correlation_id.as_str(),
        request.capability_id.as_str(),
        request.capability_version.as_str(),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(TaskApiError::InvalidRequest);
        }
    }
    if request.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || request.tenant_selector.len() > MAX_TASK_REF_BYTES
        || request.client_request_id.len() > MAX_TASK_REF_BYTES
        || request.correlation_id.len() > MAX_TASK_REF_BYTES
        || request.capability_id.len() > MAX_TASK_REF_BYTES
        || request.capability_version.len() > MAX_TASK_REF_BYTES
        || request.expires_at <= now
        || request.expires_at - now > MAX_TASK_TTL_SECONDS
        || request.input_refs.len() > 16
        || request.input_refs.iter().any(|value| {
            value.trim().is_empty()
                || value.len() > MAX_TASK_REF_BYTES
                || value.chars().any(char::is_control)
        })
    {
        return Err(TaskApiError::InvalidRequest);
    }
    Ok(())
}

fn request_digest(request: &TaskSubmission) -> Result<String, TaskApiError> {
    let bytes = serde_json::to_vec(request).map_err(|_| TaskApiError::InvalidRequest)?;
    Ok(digest_hex(&bytes))
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone)]
pub struct PostgresTaskRepository {
    client: Arc<Mutex<Client>>,
}

impl PostgresTaskRepository {
    pub fn connect(connection_string: &str) -> Result<Self, TaskApiError> {
        if !connection_string.contains("sslmode=verify-full") {
            return Err(TaskApiError::RepositoryUnavailable);
        }
        let tls = TlsConnector::builder().build()
            .map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| TaskApiError::RepositoryUnavailable)?;
        Ok(Self { client: Arc::new(Mutex::new(client)) })
    }

    pub fn verify_schema(&self) -> Result<(), TaskApiError> {
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let row = client.query_one(
            "SELECT to_regclass('public.iroka_tasks') IS NOT NULL
                AND to_regclass('public.iroka_task_events') IS NOT NULL",
            &[],
        ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
        if row.get::<_, bool>(0) { Ok(()) } else { Err(TaskApiError::RepositoryUnavailable) }
    }
}

fn task_from_row(row: &Row) -> Result<TaskRecord, TaskApiError> {
    let version: i64 = row.get("task_version");
    let created: i64 = row.get("created_at");
    let updated: i64 = row.get("updated_at");
    let expires: i64 = row.get("expires_at");
    Ok(TaskRecord {
        task_id: row.get("task_id"),
        tenant_ref: row.get("tenant_ref"),
        principal_ref: row.get("principal_ref"),
        capability_id: row.get("capability_id"),
        capability_version: row.get("capability_version"),
        policy_version: row.get("policy_version"),
        idempotency_key: row.get("idempotency_key"),
        request_sha256: row.get("request_sha256"),
        correlation_id: row.get("correlation_id"),
        client_request_id: row.get("client_request_id"),
        state: TaskState::parse(&row.get::<_, String>("state"))?,
        task_version: u64::try_from(version).map_err(|_| TaskApiError::RepositoryUnavailable)?,
        created_at: u64::try_from(created).map_err(|_| TaskApiError::RepositoryUnavailable)?,
        updated_at: u64::try_from(updated).map_err(|_| TaskApiError::RepositoryUnavailable)?,
        expires_at: u64::try_from(expires).map_err(|_| TaskApiError::RepositoryUnavailable)?,
        result_ref: row.get("result_ref"),
        error_code: row.get("error_code"),
    })
}

const TASK_COLUMNS: &str = "task_id,tenant_ref,principal_ref,capability_id,capability_version,
    policy_version,idempotency_key,request_sha256,correlation_id,client_request_id,state,
    task_version,created_at,updated_at,expires_at,result_ref,error_code";

fn valid_event_metadata(metadata: &Value) -> bool {
    let Some(object) = metadata.as_object() else { return false };
    if metadata.to_string().len() > 4096 { return false; }
    object.iter().all(|(key, value)| {
        matches!(key.as_str(),
            "reason_code" | "error_code" | "retryable" | "adapter_class" |
            "worker_ref" | "attempt" | "contract_version"
        ) && match value {
            Value::String(text) => !text.is_empty() && text.len() <= 256
                && !text.chars().any(char::is_control),
            Value::Bool(_) | Value::Number(_) => true,
            _ => false,
        }
    })
}

impl TaskRepository for PostgresTaskRepository {
    fn create(&self, task: &TaskRecord, initial_event: &TaskEvent)
        -> Result<(TaskRecord, bool), TaskApiError> {
        if initial_event.task_id != task.task_id
            || initial_event.sequence != 1
            || initial_event.task_version != 1
            || initial_event.state != task.state
            || initial_event.actor_ref != task.principal_ref
            || !valid_event_metadata(&initial_event.metadata)
        {
            return Err(TaskApiError::InvalidRequest);
        }
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let mut tx = client.transaction().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let inserted = tx.query_opt(
            "INSERT INTO iroka_tasks
             (task_id,tenant_ref,principal_ref,capability_id,capability_version,policy_version,
              idempotency_key,request_sha256,correlation_id,client_request_id,state,task_version,
              created_at,updated_at,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (tenant_ref,principal_ref,idempotency_key) DO NOTHING
             RETURNING task_id",
            &[&task.task_id,&task.tenant_ref,&task.principal_ref,&task.capability_id,
              &task.capability_version,&task.policy_version,&task.idempotency_key,
              &task.request_sha256,&task.correlation_id,&task.client_request_id,
              &task.state.as_str(),&(task.task_version as i64),&(task.created_at as i64),
              &(task.updated_at as i64),&(task.expires_at as i64)],
        ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
        if inserted.is_some() {
            let metadata = initial_event.metadata.clone();
            tx.execute(
                "INSERT INTO iroka_task_events
                 (task_id,sequence,event_id,event_type,task_state,task_version,actor_ref,occurred_at,metadata_json)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                &[&initial_event.task_id,&(initial_event.sequence as i64),&initial_event.event_id,
                  &initial_event.event_type,&initial_event.state.as_str(),
                  &(initial_event.task_version as i64),&initial_event.actor_ref,
                  &(initial_event.occurred_at as i64),&metadata],
            ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
            tx.commit().map_err(|_| TaskApiError::RepositoryUnavailable)?;
            return Ok((task.clone(), true));
        }
        let sql = format!("SELECT {TASK_COLUMNS} FROM iroka_tasks
            WHERE tenant_ref=$1 AND principal_ref=$2 AND idempotency_key=$3");
        let existing = tx.query_opt(&sql,&[&task.tenant_ref,&task.principal_ref,&task.idempotency_key])
            .map_err(|_| TaskApiError::RepositoryUnavailable)?
            .ok_or(TaskApiError::RepositoryUnavailable)?;
        let existing = task_from_row(&existing)?;
        if existing.request_sha256 != task.request_sha256 {
            return Err(TaskApiError::Conflict);
        }
        tx.commit().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        Ok((existing, false))
    }

    fn get(&self, task_id: &str) -> Result<Option<TaskRecord>, TaskApiError> {
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let sql = format!("SELECT {TASK_COLUMNS} FROM iroka_tasks WHERE task_id=$1");
        client.query_opt(&sql,&[&task_id]).map_err(|_| TaskApiError::RepositoryUnavailable)?
            .map(|row| task_from_row(&row)).transpose()
    }

    fn transition(&self, change: TaskTransition) -> Result<TaskRecord, TaskApiError> {
        if !valid_event_metadata(&change.metadata)
            || change.actor_ref.trim().is_empty()
            || change.actor_ref.len() > MAX_TASK_REF_BYTES
            || change.actor_ref.chars().any(char::is_control)
            || change.result_ref.as_ref().is_some_and(|value| value.trim().is_empty()
                || value.len() > MAX_TASK_REF_BYTES || value.chars().any(char::is_control))
            || change.error_code.as_ref().is_some_and(|value| value.trim().is_empty()
                || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
            || (change.next_state == TaskState::Succeeded && change.result_ref.is_none())
            || (change.next_state == TaskState::Failed && change.error_code.is_none())
            || (change.next_state != TaskState::Succeeded && change.result_ref.is_some())
            || (change.next_state != TaskState::Failed && change.error_code.is_some())
        {
            return Err(TaskApiError::InvalidRequest);
        }
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let mut tx = client.transaction().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let sql = format!("SELECT {TASK_COLUMNS} FROM iroka_tasks WHERE task_id=$1 FOR UPDATE");
        let row = tx.query_opt(&sql,&[&change.task_id]).map_err(|_| TaskApiError::RepositoryUnavailable)?
            .ok_or(TaskApiError::NotFound)?;
        let current = task_from_row(&row)?;
        if current.task_version != change.expected_version
            || !current.state.permits(change.next_state)
            || change.occurred_at < current.updated_at
            || change.occurred_at > current.expires_at
        {
            return Err(TaskApiError::Conflict);
        }
        let next_version = current.task_version.checked_add(1).ok_or(TaskApiError::Conflict)?;
        let changed = tx.execute(
            "UPDATE iroka_tasks SET state=$2,task_version=$3,updated_at=$4,
                result_ref=COALESCE($5,result_ref),error_code=COALESCE($6,error_code)
             WHERE task_id=$1 AND task_version=$7",
            &[&change.task_id,&change.next_state.as_str(),&(next_version as i64),
              &(change.occurred_at as i64),&change.result_ref,&change.error_code,
              &(change.expected_version as i64)],
        ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
        if changed != 1 { return Err(TaskApiError::Conflict); }
        let event_type = format!("task.{}", change.next_state.as_str());
        let event_id = format!("{}:event:{next_version}", change.task_id);
        tx.execute(
            "INSERT INTO iroka_task_events
             (task_id,sequence,event_id,event_type,task_state,task_version,actor_ref,occurred_at,metadata_json)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[&change.task_id,&(next_version as i64),&event_id,&event_type,
              &change.next_state.as_str(),&(next_version as i64),&change.actor_ref,
              &(change.occurred_at as i64),&change.metadata],
        ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let updated = tx.query_one(&sql.replace(" FOR UPDATE",""),&[&change.task_id])
            .map_err(|_| TaskApiError::RepositoryUnavailable)?;
        tx.commit().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        task_from_row(&updated)
    }

    fn events(&self, task_id: &str, after_sequence: u64, limit: usize)
        -> Result<Vec<TaskEvent>, TaskApiError> {
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let rows = client.query(
            "SELECT task_id,sequence,event_id,event_type,task_state,task_version,
                actor_ref,occurred_at,metadata_json
             FROM iroka_task_events WHERE task_id=$1 AND sequence>$2
             ORDER BY sequence ASC LIMIT $3",
            &[&task_id,&(after_sequence as i64),&(limit as i64)],
        ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
        rows.iter().map(|row| {
            let sequence: i64 = row.get("sequence");
            let version: i64 = row.get("task_version");
            let occurred: i64 = row.get("occurred_at");
            Ok(TaskEvent {
                task_id: row.get("task_id"),
                sequence: u64::try_from(sequence).map_err(|_| TaskApiError::RepositoryUnavailable)?,
                event_id: row.get("event_id"),
                event_type: row.get("event_type"),
                state: TaskState::parse(&row.get::<_, String>("task_state"))?,
                task_version: u64::try_from(version).map_err(|_| TaskApiError::RepositoryUnavailable)?,
                actor_ref: row.get("actor_ref"),
                occurred_at: u64::try_from(occurred).map_err(|_| TaskApiError::RepositoryUnavailable)?,
                metadata: row.get("metadata_json"),
            })
        }).collect()
    }
}

#[derive(Debug, Clone)]
pub struct TaskHttpRequest {
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHttpResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Authenticated transport-neutral routes. The caller MUST obtain principal
/// from G01 verification (for example G05IngressService::authenticate_http);
/// this function never trusts identity, tenant, role or permission fields in
/// the request body or headers.
pub fn route_authenticated<R: TaskRepository, A: TaskAuthorizer>(
    service: &TaskService<R, A>,
    principal: Option<&VerifiedPrincipal>,
    request: TaskHttpRequest,
    now: u64,
) -> TaskHttpResponse {
    let Some(principal) = principal else {
        return error_response(401, "authentication_required");
    };
    let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
    if request.method == "POST" && path == "/api/v1/tasks" {
        if !header_is_json(&request.headers) {
            return error_response(415, "application_json_required");
        }
        let submission: TaskSubmission = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(_) => return error_response(400, "invalid_task_request"),
        };
        return match service.submit(principal, submission, now) {
            Ok((task, created)) => json_response(202, json!({
                "task_id": task.task_id,
                "state": task.state,
                "task_version": task.task_version,
                "created": created,
                "status_url": format!("/api/v1/tasks/{}", task.task_id),
                "events_url": format!("/api/v1/tasks/{}/events", task.task_id)
            })),
            Err(error) => task_error_response(error),
        };
    }

    let Some(rest) = path.strip_prefix("/api/v1/tasks/") else {
        return error_response(404, "not_found");
    };
    if let Some(task_id) = rest.strip_suffix("/events") {
        if request.method != "GET" || task_id.is_empty() || task_id.contains('/') {
            return error_response(404, "not_found");
        }
        let after = query_value(query, "after").unwrap_or("0").parse::<u64>();
        let limit = query_value(query, "limit").unwrap_or("50").parse::<usize>();
        let (Ok(after), Ok(limit)) = (after, limit) else {
            return error_response(400, "invalid_event_cursor");
        };
        return match service.events(principal, task_id, after, limit, now) {
            Ok(events) => {
                let next = events.last().map_or(after, |event| event.sequence);
                json_response(200, json!({
                    "task_id": task_id,
                    "events": events,
                    "next_after_sequence": next,
                    "has_more": events.len() == limit
                }))
            }
            Err(error) => task_error_response(error),
        };
    }
    if let Some(task_id) = rest.strip_suffix("/cancel") {
        if request.method != "POST" || task_id.is_empty() || task_id.contains('/') {
            return error_response(404, "not_found");
        }
        return match service.cancel(principal, task_id, now) {
            Ok(task) => json_response(202, json!({
                "task_id": task.task_id,
                "state": task.state,
                "task_version": task.task_version
            })),
            Err(error) => task_error_response(error),
        };
    }
    if request.method == "GET" && !rest.is_empty() && !rest.contains('/') {
        return match service.get(principal, rest, now) {
            Ok(task) => json_response(200, json!({"task":task})),
            Err(error) => task_error_response(error),
        };
    }
    error_response(404, "not_found")
}

fn header_is_json(headers: &std::collections::HashMap<String, String>) -> bool {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, value)| value.split(';').next().unwrap_or("").trim()
            .eq_ignore_ascii_case("application/json"))
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').filter_map(|part| part.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
}

fn json_response(status: u16, body: Value) -> TaskHttpResponse {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    TaskHttpResponse {
        status,
        headers: std::collections::HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("cache-control".into(), "no-store".into()),
            ("x-content-type-options".into(), "nosniff".into()),
        ]),
        body: bytes,
    }
}

fn error_response(status: u16, code: &str) -> TaskHttpResponse {
    json_response(status, json!({"error":{"code":code}}))
}

fn task_error_response(error: TaskApiError) -> TaskHttpResponse {
    let (status, code) = match error {
        TaskApiError::InvalidRequest => (400, "invalid_request"),
        TaskApiError::Unauthorized => (401, "unauthorized"),
        TaskApiError::Forbidden => (403, "forbidden"),
        TaskApiError::NotFound => (404, "not_found"),
        TaskApiError::Conflict => (409, "conflict"),
        TaskApiError::CapacityUnavailable => (503, "capacity_unavailable"),
        TaskApiError::AuthorityUnavailable => (503, "authority_unavailable"),
        TaskApiError::RepositoryUnavailable => (503, "repository_unavailable"),
    };
    error_response(status, code)
}

/// G01-wired route entry point. The bearer token is verified by the existing
/// first-party ingress before the task service sees a principal. The injected
/// TaskAuthorizer remains responsible for current G02 and G09 decisions.
pub fn route_with_g01<R, G, C, E, T, A>(
    ingress: &iroka_g05_memory::G05IngressService<R, G, C, E>,
    service: &TaskService<T, A>,
    request: TaskHttpRequest,
    now: u64,
) -> TaskHttpResponse
where
    R: iroka_kernel::RevocationChecker,
    G: iroka_g05_memory::G02AuthorizationAuthority,
    C: iroka_g05_memory::TrustedClock,
    E: iroka_g05_memory::G09ExecutionRevalidator,
    T: TaskRepository,
    A: TaskAuthorizer,
{
    let authorization = request.headers.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str());
    match ingress.authenticate_http(authorization) {
        Ok(principal) => route_authenticated(service, Some(&principal), request, now),
        Err(iroka_g05_memory::G05Error::AuthenticationRequired
            | iroka_g05_memory::G05Error::AuthenticationInvalid) =>
            error_response(401, "authentication_invalid"),
        Err(iroka_g05_memory::G05Error::AuthorityUnavailable
            | iroka_g05_memory::G05Error::RepositoryUnavailable) =>
            error_response(503, "authentication_authority_unavailable"),
        Err(_) => error_response(403, "authentication_denied"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_machine_rejects_terminal_and_skipped_transitions() {
        assert!(TaskState::Accepted.permits(TaskState::Queued));
        assert!(TaskState::Running.permits(TaskState::Succeeded));
        assert!(TaskState::Running.permits(TaskState::CancelRequested));
        assert!(TaskState::CancelRequested.permits(TaskState::Cancelled));
        assert!(!TaskState::Accepted.permits(TaskState::Succeeded));
        assert!(!TaskState::Succeeded.permits(TaskState::Queued));
        assert!(!TaskState::Cancelled.permits(TaskState::Running));
    }

    #[test]
    fn task_submission_bounds_and_expiry_are_enforced() {
        let request = TaskSubmission {
            tenant_selector: "tenant:1".into(),
            idempotency_key: "idem:1".into(),
            client_request_id: "client:1".into(),
            correlation_id: "trace:1".into(),
            capability_id: "iroka.answer".into(),
            capability_version: "1.0".into(),
            expires_at: 100,
            input_refs: vec!["document:1@rev:1".into()],
        };
        assert_eq!(validate_submission(&request, 50), Ok(()));
        assert_eq!(validate_submission(&request, 100), Err(TaskApiError::InvalidRequest));
        let mut invalid = request;
        invalid.idempotency_key = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        assert_eq!(validate_submission(&invalid, 50), Err(TaskApiError::InvalidRequest));
    }

    #[test]
    fn task_request_digest_is_stable_and_changes_with_request() {
        let request = TaskSubmission {
            tenant_selector: "tenant:1".into(),
            idempotency_key: "idem:1".into(),
            client_request_id: "client:1".into(),
            correlation_id: "trace:1".into(),
            capability_id: "iroka.answer".into(),
            capability_version: "1.0".into(),
            expires_at: 100,
            input_refs: vec!["document:1@rev:1".into()],
        };
        let first = request_digest(&request).unwrap();
        assert_eq!(first, request_digest(&request).unwrap());
        let mut changed = request;
        changed.input_refs.push("document:2@rev:1".into());
        assert_ne!(first, request_digest(&changed).unwrap());
    }
}

#[cfg(test)]
mod postgres_tests;

mod authority;
pub use authority::{G02G09TaskAuthorizer, TaskCapabilityGrant};
