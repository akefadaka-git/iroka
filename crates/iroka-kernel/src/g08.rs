//! G08 coordinator-only workflow persistence.
//!
//! This first A3 slice persists tenant-scoped workflow creation and idempotency.
//! It does not claim task execution, worker leases, retries, or distributed
//! durability. Tenant authority is supplied by a trusted G01 adapter; callers
//! cannot construct TenantScope directly.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::{
    Ed25519WorkerAuthenticator, RetryFailureClass, RetryPolicy, RetryPolicyError, RetrySchedule,
    SignedWorkerProof, TrustedClock, VerifiedPrincipal, WorkerAuthError, WorkerOperationScope,
    WorkerReplayGuard, WorkerRevocationChecker,
};

const MAX_FIELD_LEN: usize = 256;
const MAX_PAYLOAD_DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G08Error {
    InvalidInput,
    TenantAuthorityUnavailable,
    TenantAuthorityRejected,
    StoreUnavailable,
    IdempotencyConflict,
    IntegrityFailure,
    TrustedTimeUnavailable,
    WorkerAuthenticationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    subject: String,
    tenant_id: String,
    membership_version: u64,
    resolved_at: u64,
}

impl TenantScope {
    // Reserved for the in-crate G01 membership adapter; intentionally not public.
    #[allow(dead_code)]
    pub(crate) fn from_verified_membership(
        subject: String,
        tenant_id: String,
        membership_version: u64,
        resolved_at: u64,
    ) -> Result<Self, G08Error> {
        if subject.trim().is_empty()
            || tenant_id.trim().is_empty()
            || subject.len() > MAX_FIELD_LEN
            || tenant_id.len() > MAX_FIELD_LEN
            || membership_version == 0
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        Ok(Self {
            subject,
            tenant_id,
            membership_version,
            resolved_at,
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn membership_version(&self) -> u64 {
        self.membership_version
    }

    pub fn resolved_at(&self) -> u64 {
        self.resolved_at
    }
}

/// Trusted G01 adapter contract. Implementations must resolve the selector
/// against current issuer-verified identity and authoritative tenant membership.
/// The selector is never itself proof of membership. Fail closed on stale,
/// revoked, unavailable, or inconsistent membership evidence.
pub trait TenantAuthority {
    fn resolve_tenant(
        &self,
        principal: &VerifiedPrincipal,
        tenant_selector: &str,
        now: u64,
    ) -> Result<TenantScope, G08Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkflow {
    pub tenant_selector: String,
    pub workflow_type: String,
    pub contract_version: String,
    pub idempotency_key: String,
    pub input_digest: [u8; 32],
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowReceipt {
    pub workflow_id: String,
    pub tenant_id: String,
    pub workflow_type: String,
    pub contract_version: String,
    pub state: WorkflowState,
    pub version: u64,
    pub created_at: u64,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowState {
    Draft,
}

impl WorkflowState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
        }
    }
}

struct ExistingWorkflowRecord {
    workflow_id: String,
    owner_subject: String,
    request_digest: Vec<u8>,
    contract_version: String,
    state: String,
    version: i64,
    created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    pub task_key: String,
    pub task_type: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Blocked,
    Ready,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl TaskState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "BLOCKED",
            Self::Ready => "READY",
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTransitionRequest {
    pub tenant_selector: String,
    pub task_id: String,
    pub expected_version: u64,
    pub next_state: TaskState,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskReceipt {
    pub task_id: String,
    pub workflow_id: String,
    pub task_key: String,
    pub state: TaskState,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskClaimRequest {
    pub tenant_selector: String,
    pub worker_id: String,
    /// Must be generated from a cryptographically secure RNG by the worker.
    pub claim_nonce: [u8; 32],
    pub lease_seconds: u64,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTaskClaimRequest {
    pub tenant_selector: String,
    pub lease_seconds: u64,
    pub proof: SignedWorkerProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTaskLeaseRenewalRequest {
    pub tenant_selector: String,
    pub task_id: String,
    pub lease_token: String,
    pub expected_lease_version: u64,
    pub lease_seconds: u64,
    pub proof: SignedWorkerProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTaskLeaseCompletionRequest {
    pub tenant_selector: String,
    pub task_id: String,
    pub lease_token: String,
    pub expected_lease_version: u64,
    pub expected_task_version: u64,
    pub next_state: TaskState,
    pub proof: SignedWorkerProof,
}

fn map_worker_auth_error(error: WorkerAuthError) -> G08Error {
    match error {
        WorkerAuthError::ClockUnavailable | WorkerAuthError::InvalidClock => {
            G08Error::TrustedTimeUnavailable
        }
        _ => G08Error::WorkerAuthenticationFailed,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLeaseReceipt {
    pub task: TaskReceipt,
    pub worker_id: String,
    /// Bearer capability; keep secret and rotate on every renewal.
    pub lease_token: String,
    pub lease_version: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLeaseRenewalRequest {
    pub tenant_selector: String,
    pub task_id: String,
    pub worker_id: String,
    pub lease_token: String,
    pub expected_lease_version: u64,
    pub lease_seconds: u64,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLeaseCompletionRequest {
    pub tenant_selector: String,
    pub task_id: String,
    pub worker_id: String,
    pub lease_token: String,
    pub expected_lease_version: u64,
    pub expected_task_version: u64,
    pub next_state: TaskState,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRetryRequest {
    pub tenant_selector: String,
    pub task_id: String,
    pub failure: RetryFailureClass,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowCancellationRequest {
    pub tenant_selector: String,
    pub workflow_id: String,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowCancellationReceipt {
    pub workflow_id: String,
    pub cancelled_tasks: u64,
    pub idempotent_replay: bool,
}

pub struct SqliteWorkflowStore {
    connection: Mutex<Connection>,
}

impl SqliteWorkflowStore {
    /// Opens a local SQLite database. This adapter is single-node only.
    /// It is not a distributed queue or multi-node durability implementation.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, G08Error> {
        let connection = Connection::open(path).map_err(|_| G08Error::StoreUnavailable)?;
        Self::from_connection(connection)
    }

    /// In-memory adapter for deterministic contract tests only.
    pub fn open_in_memory() -> Result<Self, G08Error> {
        let connection = Connection::open_in_memory().map_err(|_| G08Error::StoreUnavailable)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, G08Error> {
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| G08Error::StoreUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS g08_workflows (
                   workflow_id TEXT PRIMARY KEY,
                   tenant_id TEXT NOT NULL,
                   owner_subject TEXT NOT NULL,
                   membership_version INTEGER NOT NULL CHECK(membership_version > 0),
                   workflow_type TEXT NOT NULL,
                   contract_version TEXT NOT NULL,
                   idempotency_key TEXT NOT NULL,
                   request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
                   state TEXT NOT NULL CHECK(state IN ('DRAFT')),
                   version INTEGER NOT NULL CHECK(version=1),
                   created_at INTEGER NOT NULL,
                   UNIQUE(tenant_id, workflow_type, idempotency_key)
                 );
                 CREATE TABLE IF NOT EXISTS g08_workflow_events (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_id TEXT NOT NULL UNIQUE,
                   workflow_id TEXT NOT NULL REFERENCES g08_workflows(workflow_id),
                   tenant_id TEXT NOT NULL,
                   actor_subject TEXT NOT NULL,
                   event_type TEXT NOT NULL CHECK(event_type='WORKFLOW_CREATED'),
                   from_version INTEGER NOT NULL CHECK(from_version=0),
                   to_version INTEGER NOT NULL CHECK(to_version=1),
                   occurred_at INTEGER NOT NULL,
                   payload_digest BLOB NOT NULL CHECK(length(payload_digest)=32)
                 );
                 CREATE TABLE IF NOT EXISTS g08_task_graphs (
                   workflow_id TEXT PRIMARY KEY REFERENCES g08_workflows(workflow_id),
                   graph_digest BLOB NOT NULL CHECK(length(graph_digest)=32),
                   created_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS g08_tasks (
                   task_id TEXT PRIMARY KEY,
                   workflow_id TEXT NOT NULL REFERENCES g08_workflows(workflow_id),
                   tenant_id TEXT NOT NULL,
                   task_key TEXT NOT NULL,
                   task_type TEXT NOT NULL,
                   state TEXT NOT NULL CHECK(state IN ('BLOCKED','READY','RUNNING','SUCCEEDED','FAILED','CANCELLED')),
                   version INTEGER NOT NULL CHECK(version >= 1),
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL,
                   UNIQUE(workflow_id, task_key)
                 );
                 CREATE TABLE IF NOT EXISTS g08_task_dependencies (
                   workflow_id TEXT NOT NULL,
                   task_key TEXT NOT NULL,
                   depends_on_task_key TEXT NOT NULL,
                   PRIMARY KEY(workflow_id, task_key, depends_on_task_key),
                   FOREIGN KEY(workflow_id, task_key) REFERENCES g08_tasks(workflow_id, task_key),
                   FOREIGN KEY(workflow_id, depends_on_task_key) REFERENCES g08_tasks(workflow_id, task_key),
                   CHECK(task_key <> depends_on_task_key)
                 );
                 CREATE TABLE IF NOT EXISTS g08_task_events (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_id TEXT NOT NULL UNIQUE,
                   task_id TEXT NOT NULL REFERENCES g08_tasks(task_id),
                   workflow_id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   actor_subject TEXT NOT NULL,
                   event_type TEXT NOT NULL,
                   from_state TEXT NOT NULL,
                   to_state TEXT NOT NULL,
                   from_version INTEGER NOT NULL,
                   to_version INTEGER NOT NULL,
                   occurred_at INTEGER NOT NULL
                 );

                 CREATE TABLE IF NOT EXISTS g08_task_leases (
                   task_id TEXT PRIMARY KEY REFERENCES g08_tasks(task_id),
                   worker_id TEXT NOT NULL,
                   token_digest BLOB NOT NULL CHECK(length(token_digest)=32),
                   lease_version INTEGER NOT NULL CHECK(lease_version > 0),
                   claimed_at INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL CHECK(expires_at > claimed_at)
                 );
                 CREATE TABLE IF NOT EXISTS g08_task_retry_state (
                   task_id TEXT PRIMARY KEY REFERENCES g08_tasks(task_id),
                   attempts_completed INTEGER NOT NULL DEFAULT 0 CHECK(attempts_completed >= 0),
                   not_before INTEGER,
                   last_failure TEXT
                 );
                 CREATE TABLE IF NOT EXISTS g08_workflow_cancellations (
                   workflow_id TEXT PRIMARY KEY REFERENCES g08_workflows(workflow_id),
                   tenant_id TEXT NOT NULL,
                   actor_subject TEXT NOT NULL,
                   cancelled_at INTEGER NOT NULL
                 );
                 CREATE TRIGGER IF NOT EXISTS g08_workflow_cancellations_no_update
                   BEFORE UPDATE ON g08_workflow_cancellations
                   BEGIN SELECT RAISE(ABORT,'immutable G08 cancellation record'); END;
                 CREATE TRIGGER IF NOT EXISTS g08_workflow_cancellations_no_delete
                   BEFORE DELETE ON g08_workflow_cancellations
                   BEGIN SELECT RAISE(ABORT,'immutable G08 cancellation record'); END;
                 CREATE TRIGGER IF NOT EXISTS g08_task_events_no_update
                   BEFORE UPDATE ON g08_task_events
                   BEGIN SELECT RAISE(ABORT,'append-only G08 task events'); END;
                 CREATE TRIGGER IF NOT EXISTS g08_task_events_no_delete
                   BEFORE DELETE ON g08_task_events
                   BEGIN SELECT RAISE(ABORT,'append-only G08 task events'); END;
                 CREATE TRIGGER IF NOT EXISTS g08_events_no_update
                   BEFORE UPDATE ON g08_workflow_events
                   BEGIN SELECT RAISE(ABORT,'append-only G08 events'); END;
                 CREATE TRIGGER IF NOT EXISTS g08_events_no_delete
                   BEFORE DELETE ON g08_workflow_events
                   BEGIN SELECT RAISE(ABORT,'append-only G08 events'); END;",
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn create_workflow<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &CreateWorkflow,
    ) -> Result<WorkflowReceipt, G08Error> {
        validate_request(request)?;
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }

        let digest = request_digest(request);
        let workflow_id = format!("wf_{}", hex_digest(&digest[..16]));
        let event_id = format!("g08_create_{}", hex_digest(&digest));
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;

        let existing: Option<ExistingWorkflowRecord> = transaction
            .query_row(
                "SELECT workflow_id, owner_subject, request_digest, contract_version, state, version, created_at
                 FROM g08_workflows
                 WHERE tenant_id=?1 AND workflow_type=?2 AND idempotency_key=?3",
                params![
                    scope.tenant_id(),
                    request.workflow_type,
                    request.idempotency_key
                ],
                |row| {
                    Ok(ExistingWorkflowRecord {
                        workflow_id: row.get(0)?,
                        owner_subject: row.get(1)?,
                        request_digest: row.get(2)?,
                        contract_version: row.get(3)?,
                        state: row.get(4)?,
                        version: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;

        if let Some(existing) = existing {
            // Idempotency receipts are owner-bound; another tenant member must not
            // learn or reuse a workflow created by a different subject.
            if existing.owner_subject != scope.subject() {
                return Err(G08Error::TenantAuthorityRejected);
            }
            if existing.request_digest.as_slice() != digest {
                return Err(G08Error::IdempotencyConflict);
            }
            if existing.contract_version != request.contract_version
                || existing.state != WorkflowState::Draft.as_str()
            {
                return Err(G08Error::IntegrityFailure);
            }
            transaction
                .commit()
                .map_err(|_| G08Error::StoreUnavailable)?;
            return Ok(WorkflowReceipt {
                workflow_id: existing.workflow_id,
                tenant_id: scope.tenant_id().to_owned(),
                workflow_type: request.workflow_type.clone(),
                contract_version: existing.contract_version,
                state: WorkflowState::Draft,
                version: u64::try_from(existing.version).map_err(|_| G08Error::IntegrityFailure)?,
                created_at: u64::try_from(existing.created_at)
                    .map_err(|_| G08Error::IntegrityFailure)?,
                idempotent_replay: true,
            });
        }

        let created_at = i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?;
        let membership_version = i64::try_from(scope.membership_version())
            .map_err(|_| G08Error::TenantAuthorityRejected)?;
        transaction
            .execute(
                "INSERT INTO g08_workflows(
                   workflow_id, tenant_id, owner_subject, membership_version,
                   workflow_type, contract_version, idempotency_key, request_digest,
                   state, version, created_at
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'DRAFT',1,?9)",
                params![
                    workflow_id,
                    scope.tenant_id(),
                    scope.subject(),
                    membership_version,
                    request.workflow_type,
                    request.contract_version,
                    request.idempotency_key,
                    digest.as_slice(),
                    created_at
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        transaction
            .execute(
                "INSERT INTO g08_workflow_events(
                   event_id, workflow_id, tenant_id, actor_subject, event_type,
                   from_version, to_version, occurred_at, payload_digest
                 ) VALUES(?1,?2,?3,?4,'WORKFLOW_CREATED',0,1,?5,?6)",
                params![
                    event_id,
                    workflow_id,
                    scope.tenant_id(),
                    scope.subject(),
                    created_at,
                    digest.as_slice()
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;

        Ok(WorkflowReceipt {
            workflow_id,
            tenant_id: scope.tenant_id().to_owned(),
            workflow_type: request.workflow_type.clone(),
            contract_version: request.contract_version.clone(),
            state: WorkflowState::Draft,
            version: 1,
            created_at: request.now,
            idempotent_replay: false,
        })
    }

    /// Atomically persists a validated acyclic task graph for an existing workflow.
    /// The workflow creator is the only actor admitted until delegated authority is integrated.
    pub fn create_task_graph<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        tenant_selector: &str,
        workflow_id: &str,
        tasks: &[TaskSpec],
        now: u64,
    ) -> Result<Vec<TaskReceipt>, G08Error> {
        if workflow_id.trim().is_empty() || now == 0 || tasks.is_empty() || tasks.len() > 256 {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, tenant_selector, now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != tenant_selector
            || scope.resolved_at() > now
            || now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let graph_digest = validate_and_digest_graph(tasks)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let owner: Option<String> = transaction
            .query_row(
                "SELECT owner_subject FROM g08_workflows WHERE workflow_id=?1 AND tenant_id=?2",
                params![workflow_id, scope.tenant_id()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        if owner.as_deref() != Some(scope.subject()) {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let cancelled: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM g08_workflow_cancellations WHERE workflow_id=?1)",
                params![workflow_id],
                |row| row.get(0),
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if cancelled {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT graph_digest FROM g08_task_graphs WHERE workflow_id=?1",
                params![workflow_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        if let Some(existing_digest) = existing {
            if existing_digest.as_slice() != graph_digest {
                return Err(G08Error::IdempotencyConflict);
            }
            let mut statement = transaction
                .prepare(
                    "SELECT task_id, workflow_id, task_key, state, version FROM g08_tasks
                 WHERE workflow_id=?1 ORDER BY task_key",
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            let rows = statement
                .query_map(params![workflow_id], |row| {
                    let state: String = row.get(3)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        state,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .map_err(|_| G08Error::StoreUnavailable)?;
            let mut receipts = Vec::new();
            for row in rows {
                let (task_id, workflow_id, task_key, state, version) =
                    row.map_err(|_| G08Error::StoreUnavailable)?;
                receipts.push(TaskReceipt {
                    task_id,
                    workflow_id,
                    task_key,
                    state: parse_task_state(&state)?,
                    version: u64::try_from(version).map_err(|_| G08Error::IntegrityFailure)?,
                });
            }
            drop(statement);
            transaction
                .commit()
                .map_err(|_| G08Error::StoreUnavailable)?;
            return Ok(receipts);
        }
        transaction
            .execute(
                "INSERT INTO g08_task_graphs(workflow_id, graph_digest, created_at) VALUES(?1,?2,?3)",
                params![
                    workflow_id,
                    graph_digest.as_slice(),
                    i64::try_from(now).map_err(|_| G08Error::InvalidInput)?
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        let mut receipts = Vec::with_capacity(tasks.len());
        for task in tasks {
            let task_id = task_id(workflow_id, &task.task_key);
            let state = if task.depends_on.is_empty() {
                TaskState::Ready
            } else {
                TaskState::Blocked
            };
            transaction
                .execute(
                    "INSERT INTO g08_tasks(task_id, workflow_id, tenant_id, task_key, task_type,
                 state, version, created_at, updated_at) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?7)",
                    params![
                        task_id,
                        workflow_id,
                        scope.tenant_id(),
                        task.task_key,
                        task.task_type,
                        state.as_str(),
                        i64::try_from(now).map_err(|_| G08Error::InvalidInput)?
                    ],
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            transaction
                .execute(
                    "INSERT INTO g08_task_retry_state(task_id,attempts_completed) VALUES(?1,0)",
                    params![task_id],
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            receipts.push(TaskReceipt {
                task_id,
                workflow_id: workflow_id.to_owned(),
                task_key: task.task_key.clone(),
                state,
                version: 1,
            });
        }
        for task in tasks {
            for dependency in &task.depends_on {
                transaction
                    .execute(
                        "INSERT INTO g08_task_dependencies(workflow_id, task_key, depends_on_task_key)
                     VALUES(?1,?2,?3)",
                        params![workflow_id, task.task_key, dependency],
                    )
                    .map_err(|_| G08Error::IntegrityFailure)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        receipts.sort_by(|a, b| a.task_key.cmp(&b.task_key));
        Ok(receipts)
    }

    /// Applies a version-checked task transition and records it atomically.
    /// Only the workflow creator is admitted until G02 delegation is wired in.
    pub fn transition_task<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &TaskTransitionRequest,
    ) -> Result<TaskReceipt, G08Error> {
        if request.task_id.trim().is_empty() || request.expected_version == 0 || request.now == 0 {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let current: Option<(String, String, String, i64)> = transaction
            .query_row(
                "SELECT t.workflow_id, t.task_key, t.state, t.version
             FROM g08_tasks t JOIN g08_workflows w ON w.workflow_id=t.workflow_id
             WHERE t.task_id=?1 AND t.tenant_id=?2 AND w.owner_subject=?3",
                params![&request.task_id, scope.tenant_id(), scope.subject()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let (workflow_id, task_key, current_state_text, current_version) =
            current.ok_or(G08Error::TenantAuthorityRejected)?;
        let current_state = parse_task_state(&current_state_text)?;
        if current_state == TaskState::Running {
            let active_lease: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM g08_task_leases WHERE task_id=?1 AND expires_at>?2)",
                params![request.task_id, i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?],
                |row| row.get(0),
            ).map_err(|_| G08Error::StoreUnavailable)?;
            if active_lease {
                return Err(G08Error::TenantAuthorityRejected);
            }
        }
        let expected =
            i64::try_from(request.expected_version).map_err(|_| G08Error::InvalidInput)?;
        if current_version != expected || !valid_task_transition(current_state, request.next_state)
        {
            return Err(G08Error::IntegrityFailure);
        }
        let next_version = current_version
            .checked_add(1)
            .ok_or(G08Error::IntegrityFailure)?;
        let changed = transaction
            .execute(
                "UPDATE g08_tasks SET state=?1, version=?2, updated_at=?3
             WHERE task_id=?4 AND version=?5 AND state=?6",
                params![
                    request.next_state.as_str(),
                    next_version,
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                    &request.task_id,
                    expected,
                    current_state.as_str()
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if changed != 1 {
            return Err(G08Error::IntegrityFailure);
        }
        let event_id = format!(
            "g08_task_evt_{}",
            hex_digest(&Sha256::digest(
                format!("{}:{next_version}:{}", request.task_id, request.now).as_bytes()
            ))
        );
        transaction
            .execute(
                "INSERT INTO g08_task_events(event_id, task_id, workflow_id, tenant_id,
             actor_subject, event_type, from_state, to_state, from_version, to_version, occurred_at)
             VALUES(?1,?2,?3,?4,?5,'TASK_STATE_CHANGED',?6,?7,?8,?9,?10)",
                params![
                    event_id,
                    &request.task_id,
                    workflow_id,
                    scope.tenant_id(),
                    scope.subject(),
                    current_state.as_str(),
                    request.next_state.as_str(),
                    current_version,
                    next_version,
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if request.next_state == TaskState::Succeeded {
            let newly_ready = {
                let mut statement = transaction
                    .prepare(
                        "SELECT t.task_id, t.task_key, t.version
                         FROM g08_tasks t
                         WHERE t.workflow_id=?1 AND t.state='BLOCKED'
                           AND EXISTS (
                             SELECT 1 FROM g08_task_dependencies d
                             WHERE d.workflow_id=t.workflow_id AND d.task_key=t.task_key
                           )
                           AND NOT EXISTS (
                             SELECT 1 FROM g08_task_dependencies d
                             JOIN g08_tasks dep
                               ON dep.workflow_id=d.workflow_id
                              AND dep.task_key=d.depends_on_task_key
                             WHERE d.workflow_id=t.workflow_id
                               AND d.task_key=t.task_key
                               AND dep.state<>'SUCCEEDED'
                           )
                         ORDER BY t.task_key",
                    )
                    .map_err(|_| G08Error::StoreUnavailable)?;
                let rows = statement
                    .query_map(params![workflow_id], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .map_err(|_| G08Error::StoreUnavailable)?;
                let mut selected = Vec::new();
                for row in rows {
                    selected.push(row.map_err(|_| G08Error::StoreUnavailable)?);
                }
                selected
            };
            for (ready_task_id, ready_task_key, ready_version) in newly_ready {
                let next_ready_version = ready_version
                    .checked_add(1)
                    .ok_or(G08Error::IntegrityFailure)?;
                let changed = transaction
                    .execute(
                        "UPDATE g08_tasks SET state='READY', version=?1, updated_at=?2
                         WHERE task_id=?3 AND state='BLOCKED' AND version=?4",
                        params![
                            next_ready_version,
                            i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                            ready_task_id,
                            ready_version
                        ],
                    )
                    .map_err(|_| G08Error::StoreUnavailable)?;
                if changed != 1 {
                    return Err(G08Error::IntegrityFailure);
                }
                let ready_event_id = format!(
                    "g08_task_evt_{}",
                    hex_digest(&Sha256::digest(
                        format!(
                            "{ready_task_id}:{next_ready_version}:{}:unblocked",
                            request.now
                        )
                        .as_bytes()
                    ))
                );
                transaction
                    .execute(
                        "INSERT INTO g08_task_events(
                           event_id, task_id, workflow_id, tenant_id, actor_subject,
                           event_type, from_state, to_state, from_version, to_version, occurred_at
                         ) VALUES(?1,?2,?3,?4,?5,'TASK_UNBLOCKED','BLOCKED','READY',?6,?7,?8)",
                        params![
                            ready_event_id,
                            ready_task_id,
                            workflow_id,
                            scope.tenant_id(),
                            scope.subject(),
                            ready_version,
                            next_ready_version,
                            i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
                        ],
                    )
                    .map_err(|_| G08Error::StoreUnavailable)?;
                let _ = ready_task_key;
            }
        }
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(TaskReceipt {
            task_id: request.task_id.clone(),
            workflow_id,
            task_key,
            state: request.next_state,
            version: u64::try_from(next_version).map_err(|_| G08Error::IntegrityFailure)?,
        })
    }

    /// Secure worker claim entry point. Time is obtained from the trusted clock,
    /// and worker_id is derived only from a verified, scope-bound Ed25519 proof.
    pub fn claim_next_task_authenticated<A, R, G>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        authenticator: &Ed25519WorkerAuthenticator<R, G>,
        clock: &dyn TrustedClock,
        request: &AuthenticatedTaskClaimRequest,
    ) -> Result<Option<TaskLeaseReceipt>, G08Error>
    where
        A: TenantAuthority,
        R: WorkerRevocationChecker,
        G: WorkerReplayGuard,
    {
        let scope = WorkerOperationScope::new("task.claim", request.tenant_selector.clone(), None)
            .map_err(|_| G08Error::WorkerAuthenticationFailed)?;
        let worker = authenticator
            .authenticate(&request.proof, &scope, clock)
            .map_err(map_worker_auth_error)?;
        let internal = TaskClaimRequest {
            tenant_selector: request.tenant_selector.clone(),
            worker_id: worker.worker_id().to_owned(),
            claim_nonce: worker.request_nonce(),
            lease_seconds: request.lease_seconds,
            now: worker.authenticated_at(),
        };
        self.claim_next_task(authority, principal, &internal)
    }

    /// Secure lease renewal. The proof is bound to task.lease.renew and task_id.
    pub fn renew_task_lease_authenticated<A, R, G>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        authenticator: &Ed25519WorkerAuthenticator<R, G>,
        clock: &dyn TrustedClock,
        request: &AuthenticatedTaskLeaseRenewalRequest,
    ) -> Result<TaskLeaseReceipt, G08Error>
    where
        A: TenantAuthority,
        R: WorkerRevocationChecker,
        G: WorkerReplayGuard,
    {
        let scope = WorkerOperationScope::new(
            "task.lease.renew",
            request.tenant_selector.clone(),
            Some(request.task_id.clone()),
        )
        .map_err(|_| G08Error::WorkerAuthenticationFailed)?;
        let worker = authenticator
            .authenticate(&request.proof, &scope, clock)
            .map_err(map_worker_auth_error)?;
        let internal = TaskLeaseRenewalRequest {
            tenant_selector: request.tenant_selector.clone(),
            task_id: request.task_id.clone(),
            worker_id: worker.worker_id().to_owned(),
            lease_token: request.lease_token.clone(),
            expected_lease_version: request.expected_lease_version,
            lease_seconds: request.lease_seconds,
            now: worker.authenticated_at(),
        };
        self.renew_task_lease(authority, principal, &internal)
    }

    /// Secure lease completion. The proof is bound to task.lease.complete and task_id.
    pub fn complete_task_lease_authenticated<A, R, G>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        authenticator: &Ed25519WorkerAuthenticator<R, G>,
        clock: &dyn TrustedClock,
        request: &AuthenticatedTaskLeaseCompletionRequest,
    ) -> Result<TaskReceipt, G08Error>
    where
        A: TenantAuthority,
        R: WorkerRevocationChecker,
        G: WorkerReplayGuard,
    {
        let scope = WorkerOperationScope::new(
            "task.lease.complete",
            request.tenant_selector.clone(),
            Some(request.task_id.clone()),
        )
        .map_err(|_| G08Error::WorkerAuthenticationFailed)?;
        let worker = authenticator
            .authenticate(&request.proof, &scope, clock)
            .map_err(map_worker_auth_error)?;
        let internal = TaskLeaseCompletionRequest {
            tenant_selector: request.tenant_selector.clone(),
            task_id: request.task_id.clone(),
            worker_id: worker.worker_id().to_owned(),
            lease_token: request.lease_token.clone(),
            expected_lease_version: request.expected_lease_version,
            expected_task_version: request.expected_task_version,
            next_state: request.next_state,
            now: worker.authenticated_at(),
        };
        self.complete_task_lease(authority, principal, &internal)
    }

    /// Claims the oldest eligible task for this workflow owner. Expired leases are
    /// atomically fenced by rotating the lease version and token. This SQLite
    /// implementation is single-node; worker identity must be authenticated by a
    /// future G01/G02-bound worker adapter before production use.
    pub(crate) fn claim_next_task<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &TaskClaimRequest,
    ) -> Result<Option<TaskLeaseReceipt>, G08Error> {
        if request.worker_id.trim().is_empty()
            || request.worker_id.len() > MAX_FIELD_LEN
            || request.now == 0
            || !(1..=300).contains(&request.lease_seconds)
            || request.claim_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let expires_at = request
            .now
            .checked_add(request.lease_seconds)
            .ok_or(G08Error::InvalidInput)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let candidate: Option<(String, String, String, String, i64, Option<i64>)> = transaction
            .query_row(
                "SELECT t.task_id,t.workflow_id,t.task_key,t.state,t.version,l.lease_version
             FROM g08_tasks t
             JOIN g08_workflows w ON w.workflow_id=t.workflow_id
             LEFT JOIN g08_task_leases l ON l.task_id=t.task_id
             LEFT JOIN g08_task_retry_state r ON r.task_id=t.task_id
             WHERE t.tenant_id=?1 AND w.owner_subject=?2
               AND NOT EXISTS (SELECT 1 FROM g08_workflow_cancellations c WHERE c.workflow_id=t.workflow_id)
               AND (t.state='READY'
                    OR (t.state='RUNNING' AND l.expires_at<=?3)
                    OR (t.state='FAILED' AND r.not_before IS NOT NULL AND r.not_before<=?3))
             ORDER BY t.created_at,t.task_key LIMIT 1",
                params![
                    scope.tenant_id(),
                    scope.subject(),
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let Some((
            task_id_value,
            workflow_id,
            task_key,
            state_text,
            task_version,
            prior_lease_version,
        )) = candidate
        else {
            transaction
                .commit()
                .map_err(|_| G08Error::StoreUnavailable)?;
            return Ok(None);
        };
        let prior_state = parse_task_state(&state_text)?;
        if !matches!(
            prior_state,
            TaskState::Ready | TaskState::Running | TaskState::Failed
        ) {
            return Err(G08Error::IntegrityFailure);
        }
        let next_task_version = task_version
            .checked_add(1)
            .ok_or(G08Error::IntegrityFailure)?;
        let lease_version = prior_lease_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(G08Error::IntegrityFailure)?;
        let token = derive_lease_token(
            &task_id_value,
            &request.worker_id,
            &request.claim_nonce,
            request.now,
            lease_version,
        );
        let token_digest = Sha256::digest(token.as_bytes());
        let now_i64 = i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?;
        let expires_i64 = i64::try_from(expires_at).map_err(|_| G08Error::InvalidInput)?;
        let next_state = TaskState::Running;
        let changed = transaction
            .execute(
                "UPDATE g08_tasks SET state='RUNNING',version=?1,updated_at=?2
             WHERE task_id=?3 AND version=?4 AND state=?5",
                params![
                    next_task_version,
                    now_i64,
                    task_id_value,
                    task_version,
                    prior_state.as_str()
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if changed != 1 {
            return Err(G08Error::IntegrityFailure);
        }
        let event_kind = match prior_state {
            TaskState::Ready => "TASK_CLAIMED",
            TaskState::Running => "TASK_LEASE_RECLAIMED",
            TaskState::Failed => "TASK_RETRY_CLAIMED",
            _ => return Err(G08Error::IntegrityFailure),
        };
        let event_id = format!(
            "g08_lease_evt_{}",
            hex_digest(&Sha256::digest(
                format!(
                    "{task_id_value}:{next_task_version}:{}:{event_kind}",
                    request.now
                )
                .as_bytes()
            ))
        );
        transaction.execute(
            "INSERT INTO g08_task_events(event_id,task_id,workflow_id,tenant_id,actor_subject,event_type,
             from_state,to_state,from_version,to_version,occurred_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,'RUNNING',?8,?9,?10)",
            params![event_id,task_id_value,workflow_id,scope.tenant_id(),scope.subject(),event_kind,
                prior_state.as_str(),task_version,next_task_version,now_i64]
        ).map_err(|_| G08Error::StoreUnavailable)?;
        transaction.execute(
            "INSERT INTO g08_task_leases(task_id,worker_id,token_digest,lease_version,claimed_at,expires_at)
             VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(task_id) DO UPDATE SET worker_id=excluded.worker_id,
             token_digest=excluded.token_digest,lease_version=excluded.lease_version,
             claimed_at=excluded.claimed_at,expires_at=excluded.expires_at",
            params![task_id_value,request.worker_id,token_digest.as_slice(),lease_version,now_i64,expires_i64]
        ).map_err(|_| G08Error::StoreUnavailable)?;
        transaction
            .execute(
                "INSERT INTO g08_task_retry_state(task_id,attempts_completed) VALUES(?1,1)
             ON CONFLICT(task_id) DO UPDATE SET
               attempts_completed=attempts_completed+1,not_before=NULL,last_failure=NULL",
                params![task_id_value],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(Some(TaskLeaseReceipt {
            task: TaskReceipt {
                task_id: task_id_value,
                workflow_id,
                task_key,
                state: next_state,
                version: u64::try_from(next_task_version)
                    .map_err(|_| G08Error::IntegrityFailure)?,
            },
            worker_id: request.worker_id.clone(),
            lease_token: token,
            lease_version: u64::try_from(lease_version).map_err(|_| G08Error::IntegrityFailure)?,
            expires_at,
        }))
    }

    /// Renews an active lease with token rotation. Expired or superseded tokens
    /// cannot renew; callers must claim again after expiry.
    pub(crate) fn renew_task_lease<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &TaskLeaseRenewalRequest,
    ) -> Result<TaskLeaseReceipt, G08Error> {
        if request.task_id.trim().is_empty()
            || request.worker_id.trim().is_empty()
            || request.lease_token.is_empty()
            || request.expected_lease_version == 0
            || request.now == 0
            || !(1..=300).contains(&request.lease_seconds)
        {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let expires_at = request
            .now
            .checked_add(request.lease_seconds)
            .ok_or(G08Error::InvalidInput)?;
        let token_digest = Sha256::digest(request.lease_token.as_bytes());
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let row: Option<(String, String, String, i64, i64, i64)> = transaction
            .query_row(
                "SELECT t.workflow_id,t.task_key,t.state,t.version,l.lease_version,l.expires_at
             FROM g08_tasks t JOIN g08_workflows w ON w.workflow_id=t.workflow_id
             JOIN g08_task_leases l ON l.task_id=t.task_id
             WHERE t.task_id=?1 AND t.tenant_id=?2 AND w.owner_subject=?3
               AND l.worker_id=?4 AND l.token_digest=?5",
                params![
                    request.task_id,
                    scope.tenant_id(),
                    scope.subject(),
                    request.worker_id,
                    token_digest.as_slice()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let (workflow_id, task_key, state_text, task_version, lease_version, old_expiry) =
            row.ok_or(G08Error::TenantAuthorityRejected)?;
        if state_text != "RUNNING"
            || lease_version
                != i64::try_from(request.expected_lease_version)
                    .map_err(|_| G08Error::InvalidInput)?
            || old_expiry <= i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let next_lease_version = lease_version
            .checked_add(1)
            .ok_or(G08Error::IntegrityFailure)?;
        let next_token = derive_rotated_lease_token(
            &request.lease_token,
            &request.task_id,
            request.now,
            next_lease_version,
        );
        let next_digest = Sha256::digest(next_token.as_bytes());
        transaction.execute(
            "UPDATE g08_task_leases SET token_digest=?1,lease_version=?2,claimed_at=?3,expires_at=?4
             WHERE task_id=?5 AND lease_version=?6",
            params![next_digest.as_slice(),next_lease_version,i64::try_from(request.now).map_err(|_|G08Error::InvalidInput)?,
                i64::try_from(expires_at).map_err(|_|G08Error::InvalidInput)?,request.task_id,lease_version]
        ).map_err(|_|G08Error::StoreUnavailable)?;
        let event_id = format!(
            "g08_lease_evt_{}",
            hex_digest(&Sha256::digest(
                format!(
                    "{}:{}:{}:renew",
                    request.task_id, next_lease_version, request.now
                )
                .as_bytes()
            ))
        );
        transaction.execute(
            "INSERT INTO g08_task_events(event_id,task_id,workflow_id,tenant_id,actor_subject,event_type,
             from_state,to_state,from_version,to_version,occurred_at)
             VALUES(?1,?2,?3,?4,?5,'TASK_LEASE_RENEWED','RUNNING','RUNNING',?6,?6,?7)",
            params![event_id,request.task_id,workflow_id,scope.tenant_id(),scope.subject(),task_version,
                i64::try_from(request.now).map_err(|_|G08Error::InvalidInput)?]
        ).map_err(|_|G08Error::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(TaskLeaseReceipt {
            task: TaskReceipt {
                task_id: request.task_id.clone(),
                workflow_id,
                task_key,
                state: TaskState::Running,
                version: u64::try_from(task_version).map_err(|_| G08Error::IntegrityFailure)?,
            },
            worker_id: request.worker_id.clone(),
            lease_token: next_token,
            lease_version: u64::try_from(next_lease_version)
                .map_err(|_| G08Error::IntegrityFailure)?,
            expires_at,
        })
    }

    /// Completes a task only with its current, unexpired lease capability.
    /// Successful completion atomically unlocks newly-satisfied dependents.
    pub(crate) fn complete_task_lease<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &TaskLeaseCompletionRequest,
    ) -> Result<TaskReceipt, G08Error> {
        if request.task_id.trim().is_empty()
            || request.worker_id.trim().is_empty()
            || request.lease_token.is_empty()
            || request.expected_lease_version == 0
            || request.expected_task_version == 0
            || request.now == 0
            || !matches!(request.next_state, TaskState::Succeeded | TaskState::Failed)
        {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let token_digest = Sha256::digest(request.lease_token.as_bytes());
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let row: Option<(String, String, String, i64, i64, i64)> = transaction
            .query_row(
                "SELECT t.workflow_id,t.task_key,t.state,t.version,l.lease_version,l.expires_at
             FROM g08_tasks t JOIN g08_workflows w ON w.workflow_id=t.workflow_id
             JOIN g08_task_leases l ON l.task_id=t.task_id
             WHERE t.task_id=?1 AND t.tenant_id=?2 AND w.owner_subject=?3
               AND l.worker_id=?4 AND l.token_digest=?5",
                params![
                    request.task_id,
                    scope.tenant_id(),
                    scope.subject(),
                    request.worker_id,
                    token_digest.as_slice()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let (workflow_id, task_key, state_text, task_version, lease_version, expires_at) =
            row.ok_or(G08Error::TenantAuthorityRejected)?;
        if state_text != "RUNNING"
            || task_version
                != i64::try_from(request.expected_task_version)
                    .map_err(|_| G08Error::InvalidInput)?
            || lease_version
                != i64::try_from(request.expected_lease_version)
                    .map_err(|_| G08Error::InvalidInput)?
            || expires_at <= i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let next_version = task_version
            .checked_add(1)
            .ok_or(G08Error::IntegrityFailure)?;
        let changed = transaction
            .execute(
                "UPDATE g08_tasks SET state=?1,version=?2,updated_at=?3
             WHERE task_id=?4 AND state='RUNNING' AND version=?5",
                params![
                    request.next_state.as_str(),
                    next_version,
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                    request.task_id,
                    task_version
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if changed != 1 {
            return Err(G08Error::IntegrityFailure);
        }
        let event_id = format!(
            "g08_lease_evt_{}",
            hex_digest(&Sha256::digest(
                format!(
                    "{}:{}:{}:complete",
                    request.task_id, next_version, request.now
                )
                .as_bytes()
            ))
        );
        transaction.execute(
            "INSERT INTO g08_task_events(event_id,task_id,workflow_id,tenant_id,actor_subject,event_type,
             from_state,to_state,from_version,to_version,occurred_at)
             VALUES(?1,?2,?3,?4,?5,'TASK_LEASE_COMPLETED','RUNNING',?6,?7,?8,?9)",
            params![event_id,request.task_id,workflow_id,scope.tenant_id(),scope.subject(),
                request.next_state.as_str(),task_version,next_version,
                i64::try_from(request.now).map_err(|_|G08Error::InvalidInput)?]
        ).map_err(|_|G08Error::StoreUnavailable)?;
        // Retain the expired lease row as a monotonic fencing epoch. The
        // token is unusable after expiry, while the next claim increments its
        // version instead of resetting to one.
        transaction
            .execute(
                "UPDATE g08_task_leases SET expires_at=?1 WHERE task_id=?2 AND lease_version=?3",
                params![
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                    request.task_id,
                    lease_version
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if request.next_state == TaskState::Succeeded {
            let ready_tasks = {
                let mut statement = transaction
                    .prepare(
                        "SELECT t.task_id,t.version FROM g08_tasks t
                     WHERE t.workflow_id=?1 AND t.state='BLOCKED'
                       AND EXISTS (SELECT 1 FROM g08_task_dependencies d
                         WHERE d.workflow_id=t.workflow_id AND d.task_key=t.task_key)
                       AND NOT EXISTS (SELECT 1 FROM g08_task_dependencies d
                         JOIN g08_tasks dep ON dep.workflow_id=d.workflow_id
                           AND dep.task_key=d.depends_on_task_key
                         WHERE d.workflow_id=t.workflow_id AND d.task_key=t.task_key
                           AND dep.state<>'SUCCEEDED') ORDER BY t.task_key",
                    )
                    .map_err(|_| G08Error::StoreUnavailable)?;
                let rows = statement
                    .query_map(params![workflow_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                    .map_err(|_| G08Error::StoreUnavailable)?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row.map_err(|_| G08Error::StoreUnavailable)?);
                }
                values
            };
            for (dependent_id, dependent_version) in ready_tasks {
                let next_dependent_version = dependent_version
                    .checked_add(1)
                    .ok_or(G08Error::IntegrityFailure)?;
                let changed = transaction
                    .execute(
                        "UPDATE g08_tasks SET state='READY',version=?1,updated_at=?2
                     WHERE task_id=?3 AND state='BLOCKED' AND version=?4",
                        params![
                            next_dependent_version,
                            i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                            dependent_id,
                            dependent_version
                        ],
                    )
                    .map_err(|_| G08Error::StoreUnavailable)?;
                if changed != 1 {
                    return Err(G08Error::IntegrityFailure);
                }
                let unblock_event = format!(
                    "g08_lease_evt_{}",
                    hex_digest(&Sha256::digest(
                        format!(
                            "{dependent_id}:{next_dependent_version}:{}:unblocked",
                            request.now
                        )
                        .as_bytes()
                    ))
                );
                transaction.execute(
                    "INSERT INTO g08_task_events(event_id,task_id,workflow_id,tenant_id,actor_subject,
                     event_type,from_state,to_state,from_version,to_version,occurred_at)
                     VALUES(?1,?2,?3,?4,?5,'TASK_UNBLOCKED','BLOCKED','READY',?6,?7,?8)",
                    params![unblock_event,dependent_id,workflow_id,scope.tenant_id(),scope.subject(),
                        dependent_version,next_dependent_version,
                        i64::try_from(request.now).map_err(|_|G08Error::InvalidInput)?]
                ).map_err(|_|G08Error::StoreUnavailable)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(TaskReceipt {
            task_id: request.task_id.clone(),
            workflow_id,
            task_key,
            state: request.next_state,
            version: u64::try_from(next_version).map_err(|_| G08Error::IntegrityFailure)?,
        })
    }

    /// Persists a retry decision after a worker reports a failed attempt.
    /// The task remains FAILED until its persisted not-before time is reached.
    pub fn schedule_task_retry<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &TaskRetryRequest,
        policy: RetryPolicy,
    ) -> Result<Option<RetrySchedule>, G08Error> {
        if request.task_id.trim().is_empty() || request.now == 0 {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let row: Option<(String, i64)> = transaction
            .query_row(
                "SELECT t.state,r.attempts_completed
                 FROM g08_tasks t
                 JOIN g08_workflows w ON w.workflow_id=t.workflow_id
                 JOIN g08_task_retry_state r ON r.task_id=t.task_id
                 WHERE t.task_id=?1 AND t.tenant_id=?2 AND w.owner_subject=?3
                   AND NOT EXISTS (SELECT 1 FROM g08_workflow_cancellations c WHERE c.workflow_id=t.workflow_id)",
                params![request.task_id, scope.tenant_id(), scope.subject()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let (state, attempts) = row.ok_or(G08Error::TenantAuthorityRejected)?;
        if state != "FAILED" || attempts <= 0 {
            return Err(G08Error::IntegrityFailure);
        }
        let attempts = u32::try_from(attempts).map_err(|_| G08Error::IntegrityFailure)?;
        let schedule = policy
            .schedule_after_failure(request.failure, attempts, request.now)
            .map_err(|error| match error {
                RetryPolicyError::TimestampOverflow => G08Error::InvalidInput,
                RetryPolicyError::InvalidConfiguration | RetryPolicyError::InvalidAttemptCount => {
                    G08Error::IntegrityFailure
                }
            })?;
        let not_before = schedule
            .map(|value| i64::try_from(value.not_before).map_err(|_| G08Error::InvalidInput))
            .transpose()?;
        let failure_name = retry_failure_name(request.failure);
        transaction
            .execute(
                "UPDATE g08_task_retry_state SET not_before=?1,last_failure=?2 WHERE task_id=?3",
                params![not_before, failure_name, request.task_id],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        let task: (String, String, i64) = transaction
            .query_row(
                "SELECT workflow_id,task_key,version FROM g08_tasks WHERE task_id=?1",
                params![request.task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        let event_type = if schedule.is_some() {
            "TASK_RETRY_SCHEDULED"
        } else {
            "TASK_RETRY_EXHAUSTED"
        };
        let event_id = format!(
            "g08_retry_evt_{}",
            hex_digest(&Sha256::digest(
                format!(
                    "{}:{}:{}:{}",
                    request.task_id, attempts, request.now, event_type
                )
                .as_bytes()
            ))
        );
        transaction
            .execute(
                "INSERT INTO g08_task_events(event_id,task_id,workflow_id,tenant_id,actor_subject,
                 event_type,from_state,to_state,from_version,to_version,occurred_at)
                 VALUES(?1,?2,?3,?4,?5,?6,'FAILED','FAILED',?7,?7,?8)",
                params![
                    event_id,
                    request.task_id,
                    task.0,
                    scope.tenant_id(),
                    scope.subject(),
                    event_type,
                    task.2,
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(schedule)
    }

    /// Cancels all nonterminal tasks and invalidates every active lease in one
    /// transaction. A durable immutable cancellation marker fences later claims.
    pub fn cancel_workflow<A: TenantAuthority>(
        &self,
        authority: &A,
        principal: &VerifiedPrincipal,
        request: &WorkflowCancellationRequest,
    ) -> Result<WorkflowCancellationReceipt, G08Error> {
        if request.workflow_id.trim().is_empty() || request.now == 0 {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(principal, &request.tenant_selector, request.now)?;
        if scope.subject() != principal.subject()
            || scope.tenant_id() != request.tenant_selector
            || scope.resolved_at() > request.now
            || request.now.saturating_sub(scope.resolved_at()) > 30
        {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G08Error::StoreUnavailable)?;
        let owner: Option<String> = transaction
            .query_row(
                "SELECT owner_subject FROM g08_workflows WHERE workflow_id=?1 AND tenant_id=?2",
                params![request.workflow_id, scope.tenant_id()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| G08Error::StoreUnavailable)?;
        if owner.as_deref() != Some(scope.subject()) {
            return Err(G08Error::TenantAuthorityRejected);
        }
        let existing: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM g08_workflow_cancellations WHERE workflow_id=?1)",
                params![request.workflow_id],
                |row| row.get(0),
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        if existing {
            let count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM g08_task_events WHERE workflow_id=?1 AND event_type='TASK_CANCELLED'",
                    params![request.workflow_id],
                    |row| row.get(0),
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            transaction
                .commit()
                .map_err(|_| G08Error::StoreUnavailable)?;
            return Ok(WorkflowCancellationReceipt {
                workflow_id: request.workflow_id.clone(),
                cancelled_tasks: u64::try_from(count).map_err(|_| G08Error::IntegrityFailure)?,
                idempotent_replay: true,
            });
        }
        transaction
            .execute(
                "INSERT INTO g08_workflow_cancellations(workflow_id,tenant_id,actor_subject,cancelled_at)
                 VALUES(?1,?2,?3,?4)",
                params![
                    request.workflow_id,
                    scope.tenant_id(),
                    scope.subject(),
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
                ],
            )
            .map_err(|_| G08Error::StoreUnavailable)?;
        let active = {
            let mut statement = transaction
                .prepare(
                    "SELECT task_id,state,version FROM g08_tasks
                     WHERE workflow_id=?1 AND state IN ('BLOCKED','READY','RUNNING','FAILED')
                     ORDER BY task_id",
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            let rows = statement
                .query_map(params![request.workflow_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|_| G08Error::StoreUnavailable)?;
            let mut values = Vec::new();
            for row in rows {
                values.push(row.map_err(|_| G08Error::StoreUnavailable)?);
            }
            values
        };
        for (task_id_value, state_text, version) in &active {
            let state = parse_task_state(state_text)?;
            let next_version = version.checked_add(1).ok_or(G08Error::IntegrityFailure)?;
            let changed = transaction
                .execute(
                    "UPDATE g08_tasks SET state='CANCELLED',version=?1,updated_at=?2
                     WHERE task_id=?3 AND state=?4 AND version=?5",
                    params![
                        next_version,
                        i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                        task_id_value,
                        state.as_str(),
                        version
                    ],
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            if changed != 1 {
                return Err(G08Error::IntegrityFailure);
            }
            transaction
                .execute(
                    "DELETE FROM g08_task_leases WHERE task_id=?1",
                    params![task_id_value],
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
            let event_id = format!(
                "g08_cancel_evt_{}",
                hex_digest(&Sha256::digest(
                    format!("{}:{}:{}", task_id_value, next_version, request.now).as_bytes()
                ))
            );
            transaction
                .execute(
                    "INSERT INTO g08_task_events(event_id,task_id,workflow_id,tenant_id,actor_subject,
                     event_type,from_state,to_state,from_version,to_version,occurred_at)
                     VALUES(?1,?2,?3,?4,?5,'TASK_CANCELLED',?6,'CANCELLED',?7,?8,?9)",
                    params![
                        event_id,
                        task_id_value,
                        request.workflow_id,
                        scope.tenant_id(),
                        scope.subject(),
                        state.as_str(),
                        version,
                        next_version,
                        i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
                    ],
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| G08Error::StoreUnavailable)?;
        Ok(WorkflowCancellationReceipt {
            workflow_id: request.workflow_id.clone(),
            cancelled_tasks: u64::try_from(active.len()).map_err(|_| G08Error::IntegrityFailure)?,
            idempotent_replay: false,
        })
    }

    pub fn workflow_count(&self) -> Result<u64, G08Error> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM g08_workflows", [], |row| row.get(0))
            .map_err(|_| G08Error::StoreUnavailable)?;
        u64::try_from(count).map_err(|_| G08Error::IntegrityFailure)
    }

    pub fn event_count(&self) -> Result<u64, G08Error> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| G08Error::StoreUnavailable)?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM g08_workflow_events", [], |row| {
                row.get(0)
            })
            .map_err(|_| G08Error::StoreUnavailable)?;
        u64::try_from(count).map_err(|_| G08Error::IntegrityFailure)
    }
}

fn derive_lease_token(
    task_id: &str,
    worker_id: &str,
    nonce: &[u8; 32],
    now: u64,
    lease_version: i64,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"IROKA:G08:LEASE:CLAIM:V1\\0");
    hash.update(task_id.as_bytes());
    hash.update([0]);
    hash.update(worker_id.as_bytes());
    hash.update([0]);
    hash.update(nonce);
    hash.update(now.to_be_bytes());
    hash.update(lease_version.to_be_bytes());
    hex_digest(&hash.finalize())
}

fn derive_rotated_lease_token(
    old_token: &str,
    task_id: &str,
    now: u64,
    lease_version: i64,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"IROKA:G08:LEASE:RENEW:V1\\0");
    hash.update(old_token.as_bytes());
    hash.update(task_id.as_bytes());
    hash.update(now.to_be_bytes());
    hash.update(lease_version.to_be_bytes());
    hex_digest(&hash.finalize())
}

fn retry_failure_name(failure: RetryFailureClass) -> &'static str {
    match failure {
        RetryFailureClass::TransientStore => "TRANSIENT_STORE",
        RetryFailureClass::WorkerUnavailable => "WORKER_UNAVAILABLE",
        RetryFailureClass::LeaseExpired => "LEASE_EXPIRED",
        RetryFailureClass::InvalidInput => "INVALID_INPUT",
        RetryFailureClass::AuthorityRejected => "AUTHORITY_REJECTED",
        RetryFailureClass::IntegrityFailure => "INTEGRITY_FAILURE",
        RetryFailureClass::Cancelled => "CANCELLED",
    }
}

fn parse_task_state(value: &str) -> Result<TaskState, G08Error> {
    match value {
        "BLOCKED" => Ok(TaskState::Blocked),
        "READY" => Ok(TaskState::Ready),
        "RUNNING" => Ok(TaskState::Running),
        "SUCCEEDED" => Ok(TaskState::Succeeded),
        "FAILED" => Ok(TaskState::Failed),
        "CANCELLED" => Ok(TaskState::Cancelled),
        _ => Err(G08Error::IntegrityFailure),
    }
}

fn valid_task_transition(from: TaskState, to: TaskState) -> bool {
    matches!(
        (from, to),
        (TaskState::Ready, TaskState::Running)
            | (TaskState::Ready, TaskState::Cancelled)
            | (TaskState::Running, TaskState::Succeeded)
            | (TaskState::Running, TaskState::Failed)
            | (TaskState::Running, TaskState::Cancelled)
    )
}

fn task_id(workflow_id: &str, task_key: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"IROKA:G08:TASK:V1\0");
    hash.update(workflow_id.as_bytes());
    hash.update([0]);
    hash.update(task_key.as_bytes());
    format!("task_{}", hex_digest(&hash.finalize()))
}

fn validate_and_digest_graph(tasks: &[TaskSpec]) -> Result<[u8; 32], G08Error> {
    use std::collections::{BTreeMap, BTreeSet};
    if tasks.is_empty() || tasks.len() > 256 {
        return Err(G08Error::InvalidInput);
    }
    let mut by_key = BTreeMap::new();
    for task in tasks {
        if task.task_key.trim().is_empty()
            || task.task_type.trim().is_empty()
            || task.task_key.len() > MAX_FIELD_LEN
            || task.task_type.len() > MAX_FIELD_LEN
            || by_key.insert(task.task_key.as_str(), task).is_some()
        {
            return Err(G08Error::InvalidInput);
        }
    }
    for task in tasks {
        let mut seen = BTreeSet::new();
        for dependency in &task.depends_on {
            if dependency == &task.task_key
                || !by_key.contains_key(dependency.as_str())
                || !seen.insert(dependency)
            {
                return Err(G08Error::InvalidInput);
            }
        }
    }
    let mut indegree: BTreeMap<&str, usize> = tasks
        .iter()
        .map(|task| (task.task_key.as_str(), task.depends_on.len()))
        .collect();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for task in tasks {
        for dependency in &task.depends_on {
            dependents
                .entry(dependency.as_str())
                .or_default()
                .push(task.task_key.as_str());
        }
    }
    let mut ready: Vec<&str> = indegree
        .iter()
        .filter_map(|(key, degree)| (*degree == 0).then_some(*key))
        .collect();
    let mut visited = 0usize;
    while let Some(key) = ready.pop() {
        visited += 1;
        if let Some(children) = dependents.get(key) {
            for child in children {
                let degree = indegree.get_mut(child).ok_or(G08Error::IntegrityFailure)?;
                *degree -= 1;
                if *degree == 0 {
                    ready.push(child);
                }
            }
        }
    }
    if visited != tasks.len() {
        return Err(G08Error::InvalidInput);
    }
    let mut ordered: Vec<&TaskSpec> = tasks.iter().collect();
    ordered.sort_by(|a, b| a.task_key.cmp(&b.task_key));
    let mut hash = Sha256::new();
    hash.update(b"IROKA:G08:TASK-GRAPH:V1\0");
    for task in ordered {
        hash.update((task.task_key.len() as u64).to_be_bytes());
        hash.update(task.task_key.as_bytes());
        hash.update((task.task_type.len() as u64).to_be_bytes());
        hash.update(task.task_type.as_bytes());
        let mut dependencies = task.depends_on.clone();
        dependencies.sort();
        for dependency in dependencies {
            hash.update((dependency.len() as u64).to_be_bytes());
            hash.update(dependency.as_bytes());
        }
    }
    Ok(hash.finalize().into())
}

fn validate_request(request: &CreateWorkflow) -> Result<(), G08Error> {
    for value in [
        request.tenant_selector.as_str(),
        request.workflow_type.as_str(),
        request.contract_version.as_str(),
        request.idempotency_key.as_str(),
    ] {
        if value.trim().is_empty() || value.len() > MAX_FIELD_LEN {
            return Err(G08Error::InvalidInput);
        }
    }
    if request.input_digest.len() != MAX_PAYLOAD_DIGEST_LEN || request.now == 0 {
        return Err(G08Error::InvalidInput);
    }
    Ok(())
}

fn request_digest(request: &CreateWorkflow) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"IROKA:G08:WORKFLOW-CREATE:V1\0");
    for field in [
        request.tenant_selector.as_bytes(),
        request.workflow_type.as_bytes(),
        request.contract_version.as_bytes(),
        request.idempotency_key.as_bytes(),
        request.input_digest.as_slice(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAuthority {
        tenant_id: String,
        resolved_at: u64,
    }

    impl TenantAuthority for TestAuthority {
        fn resolve_tenant(
            &self,
            principal: &VerifiedPrincipal,
            tenant_selector: &str,
            _now: u64,
        ) -> Result<TenantScope, G08Error> {
            if tenant_selector != self.tenant_id {
                return Err(G08Error::TenantAuthorityRejected);
            }
            TenantScope::from_verified_membership(
                principal.subject().to_owned(),
                self.tenant_id.clone(),
                7,
                self.resolved_at,
            )
        }
    }

    fn principal() -> VerifiedPrincipal {
        VerifiedPrincipal::from_verified_credential(
            "principal:test".into(),
            "issuer:test".into(),
            "credential:test".into(),
        )
    }

    fn request() -> CreateWorkflow {
        CreateWorkflow {
            tenant_selector: "tenant:test".into(),
            workflow_type: "report.generate".into(),
            contract_version: "1.0.0".into(),
            idempotency_key: "idem:test:1".into(),
            input_digest: [9; 32],
            now: 1_800_000_000,
        }
    }

    #[test]
    fn creates_workflow_and_event_atomically() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let receipt = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        assert_eq!(receipt.state, WorkflowState::Draft);
        assert_eq!(receipt.version, 1);
        assert!(!receipt.idempotent_replay);
        assert_eq!(store.workflow_count().unwrap(), 1);
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn identical_idempotent_request_returns_original_workflow() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let first = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let second = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        assert_eq!(first.workflow_id, second.workflow_id);
        assert!(second.idempotent_replay);
        assert_eq!(store.workflow_count().unwrap(), 1);
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn same_tenant_different_subject_cannot_replay_workflow_receipt() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();

        let other = VerifiedPrincipal::from_verified_credential(
            "principal:other".into(),
            "issuer:test".into(),
            "credential:other".into(),
        );
        assert_eq!(
            store.create_workflow(&authority, &other, &request()),
            Err(G08Error::TenantAuthorityRejected)
        );
        assert_eq!(store.workflow_count().unwrap(), 1);
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn idempotency_key_with_different_payload_is_rejected() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let mut conflicting = request();
        conflicting.input_digest = [8; 32];
        assert_eq!(
            store.create_workflow(&authority, &principal(), &conflicting),
            Err(G08Error::IdempotencyConflict)
        );
        assert_eq!(store.workflow_count().unwrap(), 1);
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn stale_membership_evidence_fails_closed() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000 - 31,
        };
        assert_eq!(
            store.create_workflow(&authority, &principal(), &request()),
            Err(G08Error::TenantAuthorityRejected)
        );
        assert_eq!(store.workflow_count().unwrap(), 0);
    }

    #[test]
    fn caller_cannot_select_another_tenant_without_membership_resolution() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:owned".into(),
            resolved_at: 1_800_000_000,
        };
        assert_eq!(
            store.create_workflow(&authority, &principal(), &request()),
            Err(G08Error::TenantAuthorityRejected)
        );
        assert_eq!(store.workflow_count().unwrap(), 0);
    }

    #[test]
    fn persisted_retry_waits_until_due_and_stops_at_attempt_budget() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let created = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &[TaskSpec {
                    task_key: "retry-me".into(),
                    task_type: "compute".into(),
                    depends_on: vec![],
                }],
                1_800_000_000,
            )
            .unwrap();
        let policy = RetryPolicy::new(3, 5, 10).unwrap();
        let first = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-a".into(),
                    claim_nonce: [31; 32],
                    lease_seconds: 10,
                    now: 1_800_000_001,
                },
            )
            .unwrap()
            .unwrap();
        store
            .complete_task_lease(
                &authority,
                &principal(),
                &TaskLeaseCompletionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: first.task.task_id.clone(),
                    worker_id: "worker-a".into(),
                    lease_token: first.lease_token,
                    expected_lease_version: 1,
                    expected_task_version: first.task.version,
                    next_state: TaskState::Failed,
                    now: 1_800_000_002,
                },
            )
            .unwrap();
        let first_schedule = store
            .schedule_task_retry(
                &authority,
                &principal(),
                &TaskRetryRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: created[0].task_id.clone(),
                    failure: RetryFailureClass::WorkerUnavailable,
                    now: 1_800_000_002,
                },
                policy,
            )
            .unwrap()
            .unwrap();
        assert_eq!(first_schedule.not_before, 1_800_000_007);
        assert!(store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-b".into(),
                    claim_nonce: [32; 32],
                    lease_seconds: 10,
                    now: 1_800_000_006,
                },
            )
            .unwrap()
            .is_none());
        let second = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-b".into(),
                    claim_nonce: [33; 32],
                    lease_seconds: 10,
                    now: 1_800_000_007,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(second.task.state, TaskState::Running);
        store
            .complete_task_lease(
                &authority,
                &principal(),
                &TaskLeaseCompletionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: second.task.task_id.clone(),
                    worker_id: "worker-b".into(),
                    lease_token: second.lease_token,
                    expected_lease_version: 2,
                    expected_task_version: second.task.version,
                    next_state: TaskState::Failed,
                    now: 1_800_000_008,
                },
            )
            .unwrap();
        let second_schedule = store
            .schedule_task_retry(
                &authority,
                &principal(),
                &TaskRetryRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: created[0].task_id.clone(),
                    failure: RetryFailureClass::TransientStore,
                    now: 1_800_000_008,
                },
                policy,
            )
            .unwrap()
            .unwrap();
        assert_eq!(second_schedule.not_before, 1_800_000_018);
        let third = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-c".into(),
                    claim_nonce: [34; 32],
                    lease_seconds: 10,
                    now: 1_800_000_018,
                },
            )
            .unwrap()
            .unwrap();
        store
            .complete_task_lease(
                &authority,
                &principal(),
                &TaskLeaseCompletionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: third.task.task_id.clone(),
                    worker_id: "worker-c".into(),
                    lease_token: third.lease_token,
                    expected_lease_version: 3,
                    expected_task_version: third.task.version,
                    next_state: TaskState::Failed,
                    now: 1_800_000_019,
                },
            )
            .unwrap();
        assert_eq!(
            store
                .schedule_task_retry(
                    &authority,
                    &principal(),
                    &TaskRetryRequest {
                        tenant_selector: "tenant:test".into(),
                        task_id: created[0].task_id.clone(),
                        failure: RetryFailureClass::WorkerUnavailable,
                        now: 1_800_000_019,
                    },
                    policy,
                )
                .unwrap(),
            None
        );
        assert!(store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-d".into(),
                    claim_nonce: [35; 32],
                    lease_seconds: 10,
                    now: 1_800_000_020,
                },
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn workflow_cancellation_atomically_cancels_tasks_and_invalidates_leases() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let created = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &[
                    TaskSpec {
                        task_key: "active".into(),
                        task_type: "compute".into(),
                        depends_on: vec![],
                    },
                    TaskSpec {
                        task_key: "blocked".into(),
                        task_type: "transform".into(),
                        depends_on: vec!["active".into()],
                    },
                ],
                1_800_000_000,
            )
            .unwrap();
        let lease = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-a".into(),
                    claim_nonce: [41; 32],
                    lease_seconds: 60,
                    now: 1_800_000_001,
                },
            )
            .unwrap()
            .unwrap();
        let request = WorkflowCancellationRequest {
            tenant_selector: "tenant:test".into(),
            workflow_id: workflow.workflow_id.clone(),
            now: 1_800_000_002,
        };
        let cancelled = store
            .cancel_workflow(&authority, &principal(), &request)
            .unwrap();
        assert_eq!(cancelled.cancelled_tasks, 2);
        assert!(!cancelled.idempotent_replay);
        let replay = store
            .cancel_workflow(&authority, &principal(), &request)
            .unwrap();
        assert_eq!(replay.cancelled_tasks, 2);
        assert!(replay.idempotent_replay);
        assert!(store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-b".into(),
                    claim_nonce: [42; 32],
                    lease_seconds: 10,
                    now: 1_800_000_003,
                },
            )
            .unwrap()
            .is_none());
        let connection = store.connection.lock().unwrap();
        let cancelled_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM g08_tasks WHERE workflow_id=?1 AND state='CANCELLED'",
                params![workflow.workflow_id],
                |row| row.get(0),
            )
            .unwrap();
        let lease_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM g08_task_leases WHERE task_id=?1",
                params![lease.task.task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cancelled_count, 2);
        assert_eq!(lease_count, 0);
        assert_eq!(created.len(), 2);
    }

    #[test]
    fn sqlite_restart_recovers_workflow_and_monotonic_lease_epoch() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iroka-g08-recovery-{}-{unique}.sqlite",
            std::process::id()
        ));
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow_id;
        let task_id_value;
        {
            let store = SqliteWorkflowStore::open(&path).unwrap();
            let workflow = store
                .create_workflow(&authority, &principal(), &request())
                .unwrap();
            workflow_id = workflow.workflow_id;
            let tasks = store
                .create_task_graph(
                    &authority,
                    &principal(),
                    "tenant:test",
                    &workflow_id,
                    &[TaskSpec {
                        task_key: "recoverable".into(),
                        task_type: "compute".into(),
                        depends_on: vec![],
                    }],
                    1_800_000_000,
                )
                .unwrap();
            task_id_value = tasks[0].task_id.clone();
            let first = store
                .claim_next_task(
                    &authority,
                    &principal(),
                    &TaskClaimRequest {
                        tenant_selector: "tenant:test".into(),
                        worker_id: "worker-before-restart".into(),
                        claim_nonce: [51; 32],
                        lease_seconds: 5,
                        now: 1_800_000_001,
                    },
                )
                .unwrap()
                .unwrap();
            assert_eq!(first.lease_version, 1);
        }

        {
            let store = SqliteWorkflowStore::open(&path).unwrap();
            assert_eq!(store.workflow_count().unwrap(), 1);
            assert_eq!(store.event_count().unwrap(), 1);
            assert!(store
                .claim_next_task(
                    &authority,
                    &principal(),
                    &TaskClaimRequest {
                        tenant_selector: "tenant:test".into(),
                        worker_id: "worker-after-restart-early".into(),
                        claim_nonce: [52; 32],
                        lease_seconds: 5,
                        now: 1_800_000_002,
                    },
                )
                .unwrap()
                .is_none());
            let recovered = store
                .claim_next_task(
                    &authority,
                    &principal(),
                    &TaskClaimRequest {
                        tenant_selector: "tenant:test".into(),
                        worker_id: "worker-after-restart".into(),
                        claim_nonce: [53; 32],
                        lease_seconds: 5,
                        now: 1_800_000_006,
                    },
                )
                .unwrap()
                .unwrap();
            assert_eq!(recovered.task.task_id, task_id_value);
            assert_eq!(recovered.lease_version, 2);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
        assert!(!workflow_id.is_empty());
    }

    #[test]
    fn concurrent_workers_cannot_claim_the_same_ready_task() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(SqliteWorkflowStore::open_in_memory().unwrap());
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &[TaskSpec {
                    task_key: "single-winner".into(),
                    task_type: "compute".into(),
                    depends_on: vec![],
                }],
                1_800_000_000,
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for (worker, nonce) in [("worker-a", 61_u8), ("worker-b", 62_u8)] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let worker = worker.to_owned();
            handles.push(std::thread::spawn(move || {
                let authority = TestAuthority {
                    tenant_id: "tenant:test".into(),
                    resolved_at: 1_800_000_000,
                };
                let worker_principal = principal();
                barrier.wait();
                store
                    .claim_next_task(
                        &authority,
                        &worker_principal,
                        &TaskClaimRequest {
                            tenant_selector: "tenant:test".into(),
                            worker_id: worker,
                            claim_nonce: [nonce; 32],
                            lease_seconds: 30,
                            now: 1_800_000_001,
                        },
                    )
                    .unwrap()
                    .is_some()
            }));
        }
        barrier.wait();
        let winners = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }

    #[test]
    fn task_claim_is_atomic_and_expired_lease_is_fenced_on_reclaim() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let tasks = [TaskSpec {
            task_key: "first".into(),
            task_type: "compute".into(),
            depends_on: vec![],
        }];
        let created = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &tasks,
                1_800_000_000,
            )
            .unwrap();
        let first = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-a".into(),
                    claim_nonce: [1; 32],
                    lease_seconds: 10,
                    now: 1_800_000_001,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.task.task_id, created[0].task_id);
        assert_eq!(first.task.state, TaskState::Running);
        assert!(store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-b".into(),
                    claim_nonce: [2; 32],
                    lease_seconds: 10,
                    now: 1_800_000_002
                }
            )
            .unwrap()
            .is_none());
        let reclaimed = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-b".into(),
                    claim_nonce: [3; 32],
                    lease_seconds: 10,
                    now: 1_800_000_012,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(reclaimed.lease_version, 2);
        assert_ne!(first.lease_token, reclaimed.lease_token);
        let connection = store.connection.lock().unwrap();
        let events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM g08_task_events WHERE event_type='TASK_LEASE_RECLAIMED'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(events, 1);
    }

    #[test]
    fn lease_renewal_rotates_token_and_rejects_old_token() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &[TaskSpec {
                    task_key: "first".into(),
                    task_type: "compute".into(),
                    depends_on: vec![],
                }],
                1_800_000_000,
            )
            .unwrap();
        let claim = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-a".into(),
                    claim_nonce: [4; 32],
                    lease_seconds: 10,
                    now: 1_800_000_001,
                },
            )
            .unwrap()
            .unwrap();
        let renewed = store
            .renew_task_lease(
                &authority,
                &principal(),
                &TaskLeaseRenewalRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: claim.task.task_id.clone(),
                    worker_id: "worker-a".into(),
                    lease_token: claim.lease_token.clone(),
                    expected_lease_version: 1,
                    lease_seconds: 20,
                    now: 1_800_000_005,
                },
            )
            .unwrap();
        assert_eq!(renewed.lease_version, 2);
        assert_ne!(renewed.lease_token, claim.lease_token);
        assert_eq!(
            store.renew_task_lease(
                &authority,
                &principal(),
                &TaskLeaseRenewalRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: claim.task.task_id,
                    worker_id: "worker-a".into(),
                    lease_token: claim.lease_token,
                    expected_lease_version: 1,
                    lease_seconds: 20,
                    now: 1_800_000_006
                }
            ),
            Err(G08Error::TenantAuthorityRejected)
        );
    }

    #[test]
    fn leased_completion_requires_current_token_and_unblocks_dependents() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let tasks = [
            TaskSpec {
                task_key: "source".into(),
                task_type: "source".into(),
                depends_on: vec![],
            },
            TaskSpec {
                task_key: "next".into(),
                task_type: "transform".into(),
                depends_on: vec!["source".into()],
            },
        ];
        let created = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &tasks,
                1_800_000_000,
            )
            .unwrap();
        let claim = store
            .claim_next_task(
                &authority,
                &principal(),
                &TaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    worker_id: "worker-a".into(),
                    claim_nonce: [8; 32],
                    lease_seconds: 30,
                    now: 1_800_000_001,
                },
            )
            .unwrap()
            .unwrap();
        let completed = store
            .complete_task_lease(
                &authority,
                &principal(),
                &TaskLeaseCompletionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: claim.task.task_id.clone(),
                    worker_id: "worker-a".into(),
                    lease_token: claim.lease_token,
                    expected_lease_version: 1,
                    expected_task_version: claim.task.version,
                    next_state: TaskState::Succeeded,
                    now: 1_800_000_002,
                },
            )
            .unwrap();
        assert_eq!(completed.state, TaskState::Succeeded);
        let connection = store.connection.lock().unwrap();
        let state: String = connection
            .query_row(
                "SELECT state FROM g08_tasks WHERE task_id=?1",
                params![
                    created
                        .iter()
                        .find(|task| task.task_key == "next")
                        .unwrap()
                        .task_id
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "READY");
    }

    #[test]
    fn task_graph_rejects_cycles_missing_dependencies_and_duplicate_keys() {
        let cycle = [
            TaskSpec {
                task_key: "a".into(),
                task_type: "compute".into(),
                depends_on: vec!["b".into()],
            },
            TaskSpec {
                task_key: "b".into(),
                task_type: "compute".into(),
                depends_on: vec!["a".into()],
            },
        ];
        assert_eq!(
            validate_and_digest_graph(&cycle),
            Err(G08Error::InvalidInput)
        );

        let missing = [TaskSpec {
            task_key: "a".into(),
            task_type: "compute".into(),
            depends_on: vec!["unknown".into()],
        }];
        assert_eq!(
            validate_and_digest_graph(&missing),
            Err(G08Error::InvalidInput)
        );

        let duplicate = [
            TaskSpec {
                task_key: "a".into(),
                task_type: "compute".into(),
                depends_on: vec![],
            },
            TaskSpec {
                task_key: "a".into(),
                task_type: "compute".into(),
                depends_on: vec![],
            },
        ];
        assert_eq!(
            validate_and_digest_graph(&duplicate),
            Err(G08Error::InvalidInput)
        );
    }

    #[test]
    fn task_graph_digest_is_independent_of_input_order() {
        let first = [
            TaskSpec {
                task_key: "a".into(),
                task_type: "source".into(),
                depends_on: vec![],
            },
            TaskSpec {
                task_key: "b".into(),
                task_type: "transform".into(),
                depends_on: vec!["a".into()],
            },
        ];
        let second = [
            TaskSpec {
                task_key: "b".into(),
                task_type: "transform".into(),
                depends_on: vec!["a".into()],
            },
            TaskSpec {
                task_key: "a".into(),
                task_type: "source".into(),
                depends_on: vec![],
            },
        ];
        assert_eq!(
            validate_and_digest_graph(&first).unwrap(),
            validate_and_digest_graph(&second).unwrap()
        );
    }

    #[test]
    fn task_graph_is_idempotent_and_dependency_unlock_is_audited() {
        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let tasks = [
            TaskSpec {
                task_key: "source".into(),
                task_type: "source.fetch".into(),
                depends_on: vec![],
            },
            TaskSpec {
                task_key: "transform".into(),
                task_type: "data.transform".into(),
                depends_on: vec!["source".into()],
            },
        ];
        let created = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &tasks,
                1_800_000_000,
            )
            .unwrap();
        assert_eq!(created.len(), 2);
        assert_eq!(
            created
                .iter()
                .find(|task| task.task_key == "source")
                .unwrap()
                .state,
            TaskState::Ready
        );
        assert_eq!(
            created
                .iter()
                .find(|task| task.task_key == "transform")
                .unwrap()
                .state,
            TaskState::Blocked
        );
        let replay = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &tasks,
                1_800_000_001,
            )
            .unwrap();
        assert_eq!(created, replay);

        let source = created
            .iter()
            .find(|task| task.task_key == "source")
            .unwrap();
        store
            .transition_task(
                &authority,
                &principal(),
                &TaskTransitionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: source.task_id.clone(),
                    expected_version: 1,
                    next_state: TaskState::Running,
                    now: 1_800_000_002,
                },
            )
            .unwrap();
        store
            .transition_task(
                &authority,
                &principal(),
                &TaskTransitionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: source.task_id.clone(),
                    expected_version: 2,
                    next_state: TaskState::Succeeded,
                    now: 1_800_000_003,
                },
            )
            .unwrap();

        let connection = store.connection.lock().unwrap();
        let (state, version): (String, i64) = connection
            .query_row(
                "SELECT state, version FROM g08_tasks WHERE workflow_id=?1 AND task_key='transform'",
                params![workflow.workflow_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "READY");
        assert_eq!(version, 2);
        let unblock_events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM g08_task_events WHERE event_type='TASK_UNBLOCKED'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unblock_events, 1);
    }

    struct TestWorkerClock(u64);
    impl TrustedClock for TestWorkerClock {
        fn now_unix_seconds(&self) -> Result<u64, crate::TrustedTimeError> {
            Ok(self.0)
        }
    }

    #[derive(Default)]
    struct TestWorkerReplayGuard(
        std::sync::Mutex<std::collections::HashMap<(String, String), u64>>,
    );
    impl crate::WorkerReplayGuard for TestWorkerReplayGuard {
        fn consume_sequence(
            &self,
            worker_id: &str,
            key_id: &str,
            sequence: u64,
        ) -> Result<(), crate::WorkerReplayError> {
            let mut sequences = self
                .0
                .lock()
                .map_err(|_| crate::WorkerReplayError::Unavailable)?;
            let key = (worker_id.to_owned(), key_id.to_owned());
            if sequences
                .get(&key)
                .is_some_and(|previous| sequence <= *previous)
            {
                return Err(crate::WorkerReplayError::Replay);
            }
            sequences.insert(key, sequence);
            Ok(())
        }
    }

    struct TestWorkerRevocations;
    impl crate::WorkerRevocationChecker for TestWorkerRevocations {
        fn worker_revoked(&self, _: &str) -> Result<bool, crate::WorkerRevocationError> {
            Ok(false)
        }

        fn key_revoked(&self, _: &str, _: &str) -> Result<bool, crate::WorkerRevocationError> {
            Ok(false)
        }
    }

    fn signed_worker_proof(
        signer: &ed25519_dalek::SigningKey,
        operation: &str,
        resource_id: Option<String>,
        sequence: u64,
        now: u64,
        request_nonce: [u8; 32],
    ) -> crate::SignedWorkerProof {
        use ed25519_dalek::Signer;

        let payload = crate::WorkerProofPayload {
            worker_id: "worker:alpha".into(),
            key_id: "worker-key:alpha:v1".into(),
            audience: crate::G08_WORKER_AUDIENCE.into(),
            operation: operation.into(),
            tenant_selector: "tenant:test".into(),
            resource_id,
            sequence,
            request_nonce,
            issued_at: now,
            expires_at: now + 20,
        };
        let bytes = serde_jcs::to_vec(&payload).unwrap();
        crate::SignedWorkerProof {
            payload,
            signature: signer.sign(&bytes).to_bytes().to_vec(),
        }
    }

    #[test]
    fn authenticated_worker_claim_renewal_and_completion_use_trusted_time() {
        use ed25519_dalek::SigningKey;

        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        let created = store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &[TaskSpec {
                    task_key: "signed-worker-task".into(),
                    task_type: "compute".into(),
                    depends_on: vec![],
                }],
                1_800_000_000,
            )
            .unwrap();

        let signer = SigningKey::from_bytes(&[101u8; 32]);
        let trust = crate::WorkerTrustStore::new(vec![crate::WorkerKey {
            worker_id: "worker:alpha".into(),
            key_id: "worker-key:alpha:v1".into(),
            public_key: signer.verifying_key().to_bytes(),
            not_before: 1_799_999_000,
            not_after: 1_800_010_000,
        }])
        .unwrap();
        let authenticator = crate::Ed25519WorkerAuthenticator::new(
            trust,
            TestWorkerRevocations,
            TestWorkerReplayGuard::default(),
        );

        let claim_time = 1_800_000_001;
        let claim = store
            .claim_next_task_authenticated(
                &authority,
                &principal(),
                &authenticator,
                &TestWorkerClock(claim_time),
                &AuthenticatedTaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    lease_seconds: 30,
                    proof: signed_worker_proof(&signer, "task.claim", None, 1, claim_time, [1; 32]),
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(claim.task.task_id, created[0].task_id);
        assert_eq!(claim.worker_id, "worker:alpha");
        assert_eq!(claim.lease_version, 1);

        let renewal_time = claim_time + 1;
        let renewed = store
            .renew_task_lease_authenticated(
                &authority,
                &principal(),
                &authenticator,
                &TestWorkerClock(renewal_time),
                &AuthenticatedTaskLeaseRenewalRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: claim.task.task_id.clone(),
                    lease_token: claim.lease_token,
                    expected_lease_version: 1,
                    lease_seconds: 30,
                    proof: signed_worker_proof(
                        &signer,
                        "task.lease.renew",
                        Some(claim.task.task_id.clone()),
                        2,
                        renewal_time,
                        [2; 32],
                    ),
                },
            )
            .unwrap();
        assert_eq!(renewed.worker_id, "worker:alpha");
        assert_eq!(renewed.lease_version, 2);

        let completion_time = renewal_time + 1;
        let completed = store
            .complete_task_lease_authenticated(
                &authority,
                &principal(),
                &authenticator,
                &TestWorkerClock(completion_time),
                &AuthenticatedTaskLeaseCompletionRequest {
                    tenant_selector: "tenant:test".into(),
                    task_id: renewed.task.task_id.clone(),
                    lease_token: renewed.lease_token,
                    expected_lease_version: renewed.lease_version,
                    expected_task_version: renewed.task.version,
                    next_state: TaskState::Succeeded,
                    proof: signed_worker_proof(
                        &signer,
                        "task.lease.complete",
                        Some(renewed.task.task_id.clone()),
                        3,
                        completion_time,
                        [3; 32],
                    ),
                },
            )
            .unwrap();
        assert_eq!(completed.state, TaskState::Succeeded);
    }

    #[test]
    fn authenticated_worker_claim_rejects_scope_substitution_before_claiming() {
        use ed25519_dalek::SigningKey;

        let store = SqliteWorkflowStore::open_in_memory().unwrap();
        let authority = TestAuthority {
            tenant_id: "tenant:test".into(),
            resolved_at: 1_800_000_000,
        };
        let workflow = store
            .create_workflow(&authority, &principal(), &request())
            .unwrap();
        store
            .create_task_graph(
                &authority,
                &principal(),
                "tenant:test",
                &workflow.workflow_id,
                &[TaskSpec {
                    task_key: "must-remain-ready".into(),
                    task_type: "compute".into(),
                    depends_on: vec![],
                }],
                1_800_000_000,
            )
            .unwrap();

        let signer = SigningKey::from_bytes(&[102u8; 32]);
        let trust = crate::WorkerTrustStore::new(vec![crate::WorkerKey {
            worker_id: "worker:alpha".into(),
            key_id: "worker-key:alpha:v1".into(),
            public_key: signer.verifying_key().to_bytes(),
            not_before: 1_799_999_000,
            not_after: 1_800_010_000,
        }])
        .unwrap();
        let authenticator = crate::Ed25519WorkerAuthenticator::new(
            trust,
            TestWorkerRevocations,
            TestWorkerReplayGuard::default(),
        );
        let mut invalid =
            signed_worker_proof(&signer, "task.claim", None, 1, 1_800_000_001, [4; 32]);
        invalid.payload.tenant_selector = "tenant:other".into();

        assert_eq!(
            store.claim_next_task_authenticated(
                &authority,
                &principal(),
                &authenticator,
                &TestWorkerClock(1_800_000_001),
                &AuthenticatedTaskClaimRequest {
                    tenant_selector: "tenant:test".into(),
                    lease_seconds: 30,
                    proof: invalid,
                },
            ),
            Err(G08Error::WorkerAuthenticationFailed)
        );
        let connection = store.connection.lock().unwrap();
        let state: String = connection
            .query_row(
                "SELECT state FROM g08_tasks WHERE workflow_id=?1",
                params![workflow.workflow_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "READY");
    }
}
