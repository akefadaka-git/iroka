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

        let existing: Option<(String, Vec<u8>, String, String, i64, i64)> = transaction
            .query_row(
                "SELECT workflow_id, request_digest, contract_version, state, version, created_at
                 FROM g08_workflows
                 WHERE tenant_id=?1 AND workflow_type=?2 AND idempotency_key=?3",
                params![
                    scope.tenant_id(),
                    request.workflow_type,
                    request.idempotency_key
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

        if let Some((id, prior_digest, contract, state, version, created_at)) = existing {
            if prior_digest.as_slice() != digest {
                return Err(G08Error::IdempotencyConflict);
            }
            if contract != request.contract_version || state != WorkflowState::Draft.as_str() {
                return Err(G08Error::IntegrityFailure);
            }
            transaction
                .commit()
                .map_err(|_| G08Error::StoreUnavailable)?;
            return Ok(WorkflowReceipt {
                workflow_id: id,
                tenant_id: scope.tenant_id().to_owned(),
                workflow_type: request.workflow_type.clone(),
                contract_version: contract,
                state: WorkflowState::Draft,
                version: u64::try_from(version).map_err(|_| G08Error::IntegrityFailure)?,
                created_at: u64::try_from(created_at).map_err(|_| G08Error::IntegrityFailure)?,
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
