//! G08 coordinator-only workflow persistence.
//!
//! This first A3 slice persists tenant-scoped workflow creation and idempotency.
//! It does not claim task execution, worker leases, retries, or distributed
//! durability. Tenant authority is supplied by a trusted G01 adapter; callers
//! cannot construct TenantScope directly.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::VerifiedPrincipal;

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
                    i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?
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
        if request.task_id.trim().is_empty()
            || request.expected_version == 0
            || request.now == 0
        {
            return Err(G08Error::InvalidInput);
        }
        let scope = authority.resolve_tenant(
            principal,
            &request.tenant_selector,
            request.now,
        )?;
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
        let expected = i64::try_from(request.expected_version).map_err(|_| G08Error::InvalidInput)?;
        if current_version != expected || !valid_task_transition(current_state, request.next_state) {
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
            transaction
                .execute(
                    "UPDATE g08_tasks SET state='READY', version=version+1, updated_at=?1
                 WHERE workflow_id=?2 AND state='BLOCKED'
                 AND task_key IN (SELECT task_key FROM g08_task_dependencies
                                  WHERE workflow_id=?2)
                 AND NOT EXISTS (
                   SELECT 1 FROM g08_task_dependencies d JOIN g08_tasks dep
                     ON dep.workflow_id=d.workflow_id AND dep.task_key=d.depends_on_task_key
                   WHERE d.workflow_id=g08_tasks.workflow_id
                     AND d.task_key=g08_tasks.task_key AND dep.state<>'SUCCEEDED'
                 )",
                    params![
                        i64::try_from(request.now).map_err(|_| G08Error::InvalidInput)?,
                        workflow_id
                    ],
                )
                .map_err(|_| G08Error::StoreUnavailable)?;
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
}
